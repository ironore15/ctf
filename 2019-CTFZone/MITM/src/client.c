#include "MessageAuth.h"
#include "DHE_mpz.h"
#include "AESCTR.h"
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <stdint.h>
#include <sys/socket.h> 
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>

#define PORT 8888
#define DIGITAL_SIGNATURE_LENGTH 512
#define KEY_FILE "key_client.txt"

int32_t create_connection_client();
void *socket_thread(void *arg);
int8_t secure_connection(int32_t sock, uint8_t *secret_key_AES, uint8_t *nonce);
RSA_key *RSA_server_private_key_init();
int8_t send_client_hello(int32_t sock);
int8_t check_server_hello(unsigned char *message, uint16_t full_message_length, mpz_t p, mpz_t g, mpz_t A, RSA_key *key);
int8_t send_public_key_with_nonce(int32_t sock, mpz_t private_key, mpz_t p, mpz_t g, uint8_t *nonce);
unsigned char *get_bignum_to_str(mpz_t number);
int8_t create_encryption_key_for_AES(mpz_t private_key, mpz_t B, mpz_t p, uint8_t *secret_key_AES);
unsigned char *receive_data_from_socket(int32_t sock, uint16_t *data_size);
int8_t send_error_message(int32_t sock, unsigned char *message);
int8_t check_input_and_copy_str_to_bignum(unsigned char *data, mpz_t q, uint16_t *position, uint16_t position_offset, unsigned char *pattern, uint16_t full_data_length);
int8_t get_hash_data(unsigned char *message, mpz_t hash, uint16_t length);
int8_t check_hash(unsigned char *full_message, uint16_t full_message_length, mpz_t signature, RSA_key *key);
int8_t nonce_generation(uint8_t *nonce);
unsigned char *bytes_to_hex(uint8_t *bytes, uint8_t length);

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void main() { 
    sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
    create_connection_client();
} 

int32_t create_connection_client(){
    int32_t socket_server, socket_new;
    struct sockaddr_in addr_server;
    struct sockaddr_storage server_storage;
    socklen_t addr_size; 
    pthread_t tid[1025] = {0};
    uint16_t i = 0;
    
    socket_server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (socket_server == -1) { 
        printf("ERROR: Socket creation failed with errno %d..\n", errno); 
        return 0; 
    } 
    else
        printf("SUCCESS: Socket successfully created...\n"); 
    setsockopt(socket_server, SOL_SOCKET, SO_REUSEADDR, 0, 0);
    setsockopt(socket_server, SOL_SOCKET, SO_REUSEPORT, 0, 0);
    memset(&addr_server, 0, sizeof(addr_server));
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(PORT);
    addr_server.sin_addr.s_addr = htonl(INADDR_ANY);
    memset(addr_server.sin_zero, '\0', sizeof addr_server.sin_zero);
    if ((bind(socket_server, (struct sockaddr*) &addr_server, sizeof(addr_server))) != 0) {
        printf("ERROR: Bind failed with errno %d..\n", errno); 
        return 0; 
    } 
    else
        printf("SUCCESS: Socket successfully binded...\n"); 
   
    if ((listen(socket_server, 100)) != 0) { 
        printf("ERROR: Listen failed with errno %d..\n", errno); 
        return 0; 
    } 
    else
        printf("SUCCESS: Waiting for connection...\n"); 
    while(1)
    {
        addr_size = sizeof(server_storage);
        socket_new = accept(socket_server, (struct sockaddr *) &server_storage, &addr_size);
        if (socket_new <= 0 || pthread_create(&tid[i++], NULL, socket_thread, &socket_new) != 0)
            printf("Pthread_create was failed..\n");
        if (i >= 1024) {
            sleep(5);
            i = 0;
            while(i < 1024) {
                printf("Cancel thread..\n");
                pthread_cancel(tid[i++]);
            }
            i = 0;
        }
    }
    printf("Normal exit...\n");
    return 0;
}

void *socket_thread(void *arg) {
    uint8_t nonce[17] = {0};
    uint8_t secret_key_AES[33] = {0};
    int32_t connection = *((int *)arg);
    if (connection) {
        secure_connection(connection, secret_key_AES, nonce);
        shutdown(connection, SHUT_RDWR);
        close(connection);
        printf("Thread exit..\n");
        pthread_exit(NULL);
    }
    else {
        printf("Connection was failed, thread exit..\n");
        pthread_exit(NULL);
    }
}

int8_t secure_connection(int32_t sock, uint8_t *secret_key_AES, uint8_t *nonce) {
    RSA_key *key_RSA;
    mpz_t p, g, A, client_private_key;
    unsigned char *data;    
    uint16_t data_size;
    printf("Creating secure connection. This might take a while...\n");
    send_client_hello(sock);
    printf("Client hello was sent...\n");
    data = receive_data_from_socket(sock, &data_size);
    if (data == NULL) {
        printf("Server hello not received\n");
        send_error_message(sock, "Oops, connection has been terminated by the client..\n");
        return 0;
    }
    printf("Server hello was received..\n");
    pthread_mutex_lock(&lock);
    key_RSA = RSA_server_private_key_init();
    pthread_mutex_unlock(&lock);
    if (key_RSA == NULL) {
        free(data);
        send_error_message(sock, "Oops, connection has been terminated by the client..\n");
        return 0; 
    }
    mpz_init(p);
    mpz_init(g);
    mpz_init(A);
    if (!check_server_hello(data, data_size, p, g, A, key_RSA)) {
            mpz_clear(p);
            mpz_clear(g);
            mpz_clear(A);
            free(data);
            free(key_RSA);
            printf("Server hello error..\n");
            send_error_message(sock, "Oops, connection has been terminated by the client..\n");
            return 0; 
    }
    free(data);
    printf("Server hello was checked..\n");
    mpz_init(client_private_key);
    if (!send_public_key_with_nonce(sock, client_private_key, p, g, nonce)) {
        mpz_clear(p);
        mpz_clear(g);
        mpz_clear(A);
        mpz_clear(client_private_key);
        free(key_RSA);
        printf("Nonce was not sent..\n");
        send_error_message(sock, "Oops, connection has been terminated by the client..\n");
        return 0;
    }
    printf("Nonce was sent..\n");
    mpz_clear(p);
    mpz_clear(g);
    mpz_clear(A);
    mpz_clear(client_private_key);
    free(key_RSA);
    return 1;
}

RSA_key *RSA_server_private_key_init() {
    RSA_key *key;
    FILE *fp;
    unsigned char e[7] = {"\x00"};
    unsigned char n[516] = {"\x00"};
    fp = fopen(KEY_FILE, "r");
    if (fp == NULL){
        printf("Could not open server key file..\n");
        return NULL;
    }
    fgets(e, 7, fp);
    fgets(n, 516, fp);
    fclose(fp);
    key = RSA_key_init(e, n);
    return key;
}

int8_t send_client_hello(int32_t sock) {
    unsigned char message[37] = "ClientHello:SHA_AES_CTR_RSA_DHE_2048\n";
    uint16_t length = 37;
    if ((send(sock, &length, sizeof(uint16_t), 0) == -1) || (send(sock, message, length, 0) == -1)) {
        return 0;
    }
    return 1; 
}

int8_t check_server_hello(unsigned char *message, uint16_t full_message_length, mpz_t p, mpz_t g, mpz_t A, RSA_key *key) {
    mpz_t signature;
    uint16_t position = 0, data_length = 0;
    uint8_t ok = 1;
    ok &= check_input_and_copy_str_to_bignum(message, p, &position, 14, "ServerHello:p=", full_message_length);
    ok &= check_input_and_copy_str_to_bignum(message, g, &position, 3, "|g=", full_message_length);
    ok &= check_input_and_copy_str_to_bignum(message, A, &position, 3, "|A=", full_message_length);
    data_length = position;
    mpz_init(signature);
    ok &= check_input_and_copy_str_to_bignum(message, signature, &position, 3, "|s=", full_message_length); 
    if (!ok || !check_hash(message, data_length, signature, key)) {
        mpz_clear(signature);
        return 0;
    }
    mpz_clear(signature);
    return 1;
}

int8_t send_public_key_with_nonce(int32_t sock, mpz_t private_key, mpz_t p, mpz_t g, uint8_t *nonce) {
    mpz_t public_key;
    uint16_t message_length = 0;
    unsigned char *client_message, *buffer;
    mpz_init(public_key);
    DHE_generate_private_and_public_key(private_key, public_key, p, g); 
    message_length = 46 + mpz_sizeinbase(public_key, 16);
    client_message = malloc(message_length);
    if (client_message == NULL) {
        mpz_clear(public_key);
        return 0;
    }
    memset(client_message, 0, message_length);
    strncat(client_message, "OK:B=", 5);
    buffer = get_bignum_to_str(public_key);
    if (buffer == NULL) {
        mpz_clear(public_key);
        free(client_message);
        return 0;
    }
    strncat(client_message, buffer, mpz_sizeinbase(public_key, 16));
    free(buffer);
    strncat(client_message, "|nonce=", 7);
    nonce_generation(nonce);
    buffer = bytes_to_hex(nonce, 16);
    if (buffer == NULL) {
        mpz_clear(public_key);
        free(client_message);
        return 0;
    }
    memcpy(client_message + 12 + mpz_sizeinbase(public_key, 16), buffer, 32);
    free(buffer);
    strncat(client_message, "|\n", 2);
    if (send(sock, &message_length, sizeof(uint16_t), 0) == -1 || send(sock, client_message, message_length, 0) == -1) {
        mpz_clear(public_key);    
        free(client_message);
        return 0;
    }
    mpz_clear(public_key);    
    free(client_message);
    return 1;
}

unsigned char *get_bignum_to_str(mpz_t number) {
    unsigned char *buffer;
    buffer = malloc(mpz_sizeinbase(number, 16) + 1);
    if (buffer == NULL) {
        return NULL;
    }
    memset(buffer, 0, mpz_sizeinbase(number, 16) + 1);
    mpz_get_str(buffer, 16, number);
    return buffer;
}

unsigned char *receive_data_from_socket(int32_t sock, uint16_t *data_size) {
    unsigned char *byte;
    unsigned char *message;
    uint16_t num_bytes = 0, rec = 0;
    fd_set Sockets;
    struct timeval tv;
    int32_t retval = 0;
    FD_ZERO(&Sockets);
    FD_SET(sock, &Sockets);
    tv.tv_sec = 180;
    tv.tv_usec = 0;
    retval = select(sock + 1, &Sockets, NULL, NULL, &tv);
    if (retval == -1) {
        printf("Select error.\n");
        return NULL;
    }
    else if (retval) {
        printf("Data is available now.\n");
        byte = (unsigned char *) data_size;
        while (num_bytes < 2) {
            if (recv(sock, byte + num_bytes, 1, 0) <= 0) {
                break;
            }
            num_bytes++;
        }
        if (*data_size <= 0 || *data_size > 2500) {
            return NULL;
        }
        retval = select(sock + 1, &Sockets, NULL, NULL, &tv);
        if (retval == -1) {
            printf("Select error.\n");
            return NULL;
        }
        else if (retval) {
            printf("Data is available now.\n");
            message = malloc(*data_size + 1);
            if (message == NULL) {
                return NULL;
            }
            memset(message, 0, *data_size + 1);
            num_bytes = 0;
            tv.tv_sec = 1;
            while (num_bytes < *data_size) {
                retval = select(sock + 1, &Sockets, NULL, NULL, &tv);
                if (retval == -1) {
                    printf("Select error.\n");
                    return NULL;
                }
                else if (retval) {
                    rec = recv(sock, message + num_bytes, *data_size - num_bytes, 0);
                }
                else {
                    break;
                }
                if (rec <= 0) {
                    free(message);
                    return NULL;
                }
                num_bytes += rec;
            }
            if (num_bytes != *data_size) {
                printf("Invalid data..\n");
                free(message);
                return NULL;
            }
            retval = select(sock + 1, &Sockets, NULL, NULL, &tv);
            if (retval == -1) {
                printf("Select error.\n");
                return NULL;
            }
            else if (retval) {
                printf("Extra data is available now.\n");
                free(message);
                return NULL;
            }
            return message;
        }
        else {
            printf("No data within 3 minutes.\n");
            return NULL;
        }
    }
    else {
        printf("No data within 3 minutes.\n");
        return NULL;
    }
}


int8_t send_error_message(int32_t sock, unsigned char *message) {
    uint16_t message_length = 0;
    int32_t retval = 0, error = 0;
    socklen_t len = sizeof(error);
    message_length = strlen(message);
    retval = getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
    if (retval || error) {
        printf("Sending of error message was failed..\n");
        return 0;
    }
    if (send(sock, &message_length, sizeof(uint16_t), 0) == -1 || send(sock, message, message_length, 0) == -1) {
        printf("Error message not sent\n");
        return 0;
    }
    printf("Error message sent\n");
    return 1;
}

int8_t check_input_and_copy_str_to_bignum(unsigned char *data, mpz_t q, uint16_t *position, uint16_t position_offset, unsigned char *pattern, uint16_t full_data_length) {
    unsigned char *buffer;
    uint16_t num_bytes = 0;
    if (memcmp(data + *position, pattern, position_offset) != 0) {
        return 0;
    }
    *position += position_offset;
    if (*position >= full_data_length) {
        return 0;
    }
    while (data[*position] != 124 && *position < full_data_length) {
        if ((data[*position] > 47 && data[*position] < 58) || (data[*position] > 96 && data[*position] < 103)) {
            *position = *position + 1;
            num_bytes++;
        }
        else {
            return 0;
        }
    }
    buffer = malloc(num_bytes + 1);
    if (buffer == NULL) {
        return 0;
    }
    memset(buffer, 0, num_bytes + 1);
    memcpy(buffer, &data[*position - num_bytes], num_bytes);
    mpz_set_str(q, buffer, 16);
    free(buffer);
    return 1;
}

int8_t get_hash_data(unsigned char *message, mpz_t hash, uint16_t length) {
    unsigned char *hash_plain;
    hash_plain = malloc(SHA256_BLOCK_SIZE + 1);
    if (hash_plain == NULL) {
        return 0;
    }
    else {
        memset(hash_plain, 0, SHA256_BLOCK_SIZE + 1);
        SHA256_get_hash_message(message, hash_plain, length);
        SHA256_copy_hash_in_mpz(hash, hash_plain);
    }
    free(hash_plain);
    return 1;
}

int8_t check_hash(unsigned char *full_message, uint16_t full_message_length, mpz_t signature, RSA_key *key) {
    mpz_t hash_plain, hash_decrypted;
    unsigned char *data;
    mpz_init(hash_plain);
    mpz_init(hash_decrypted);
    data = malloc(full_message_length + 1);
    if (data == NULL) {
        mpz_clear(hash_plain);
        mpz_clear(hash_decrypted);
        return 0;
    }
    memset(data, 0, full_message_length + 1);
    memcpy(data, full_message, full_message_length);
    if (!get_hash_data(data, hash_plain, full_message_length)) {
        mpz_clear(hash_plain);
        mpz_clear(hash_decrypted);
        free(data);
        return 0;
    }
    RSA_encrypt_decrypt_hash(key, signature);
    if (mpz_cmp(hash_plain, signature) == 0) {
        mpz_clear(hash_plain);
        mpz_clear(hash_decrypted);
        free(data);
        return 1;
    }
    else {
        mpz_clear(hash_plain);
        mpz_clear(hash_decrypted);
        free(data);
        return 0;
    }
}

int8_t nonce_generation(uint8_t *nonce) {
    srand(time(NULL));
    for (int8_t i = 0; i < 15; i++) {
        nonce[i] = rand() % 255 + 1;
    }
    nonce[15] = 0x00;
    return 1;
}

unsigned char *bytes_to_hex(uint8_t *bytes, uint8_t length) {
    unsigned char chr[3] = {0};
    unsigned char *hex;
    hex = malloc(2 * length + 1);
    if (hex == NULL) {
        return NULL;
    }
    memset(hex, 0, 2 * length + 1);
    for (int8_t i = 0; i < length; i++) {
        if (bytes[i] == 0) {
            memcpy(hex + 2 * i, "00", 2);
            } 
        else {
            sprintf(chr, "%x", bytes[i]);
            if (chr[1] == 0) {
                chr[1] = chr[0];
                chr[0] = '0';
            }
            memcpy(hex + 2 * i, chr, 2);
        }
    }
    return hex;
}
