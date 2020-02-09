#include "DHE_mpz.h"
#include "MessageAuth.h"
#include "AESCTR.h"
#include <gmp.h>
#include <stdlib.h> 
#include <stdio.h> 
#include <string.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <sys/socket.h> 
#include <sys/types.h> 
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
#include <signal.h>

#define PORT 8889
#define DIGITAL_SIGNATURE_LENGTH 512
#define KEY_FILE "key_server.txt"

int32_t create_connection_server();
void *socket_thread(void *arg);
int8_t secure_connection(int32_t sock, uint8_t *secret_key_AES, uint8_t *nonce);
RSA_key *RSA_server_private_key_init();
unsigned char *get_bignum_to_str(mpz_t number);
int8_t check_client_hello(unsigned char *client_message, uint16_t data_size, int32_t *key_length);
int8_t send_server_hello(int32_t sock, mpz_t private_key, mpz_t p, mpz_t g, uint32_t key_length, RSA_key *key_RSA);
int8_t check_param_nonce(unsigned char* message, uint16_t full_message_length, mpz_t B, uint8_t *nonce);
int8_t create_encryption_key_for_AES(mpz_t private_key, mpz_t B, mpz_t p, uint8_t *secret_key_AES);
int8_t encrypt_and_send(int32_t sock, uint8_t *nonce, uint8_t *secret_key);
unsigned char *receive_data_from_socket(int32_t sock, uint16_t *data_size);
int8_t send_error_message(int32_t sock, unsigned char *message);
int8_t check_input_and_copy_str_to_bignum(unsigned char *data, mpz_t q, uint16_t *position, uint16_t position_offset, unsigned char *pattern, uint16_t full_data_length);
int8_t get_digital_data_signature(unsigned char *message, mpz_t digital_signature, RSA_key *key_RSA, uint16_t message_length);
int8_t get_hash_data(unsigned char *message, mpz_t hash, uint16_t message_length);
int8_t check_hash(unsigned char *parameters, uint16_t parameters_size, mpz_t signature, RSA_key *key);
int8_t hex_to_bytes(uint8_t *nonce, unsigned char *nonce_hex);
unsigned char *bytes_to_hex(uint8_t *bytes, uint8_t length);

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void main() {
    sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
    create_connection_server();
} 

int32_t create_connection_server(){
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
        if (socket_new <= 0 || pthread_create(&tid[i++], NULL, socket_thread, &socket_new) != 0) {
            printf("Pthread_create failed..\n");
        }
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
        if (secure_connection(connection, secret_key_AES, nonce)) {
            pthread_mutex_lock(&lock);
            encrypt_and_send(connection, nonce, secret_key_AES);
            pthread_mutex_unlock(&lock);
        }
        shutdown(connection, SHUT_RDWR);
        close(connection);
        printf("Thread exit..\n");
        pthread_exit(NULL);
    }
    else {
        printf("Connection failed, thread exit..\n");
        pthread_exit(NULL);
    }
}

int8_t secure_connection(int32_t sock, uint8_t *secret_key_AES, uint8_t *nonce) {
    RSA_key *key_RSA;
    mpz_t p, g, B, server_private_key;
    int32_t key_length = 0;
    unsigned char *data;
    uint16_t data_size;
    printf("Creating secure connection. This might take a while...\n");
    data = receive_data_from_socket(sock, &data_size);
    if (data == NULL) {
        send_error_message(sock, "Oops, connection has been terminated by the server..\n");
        printf("Client hello was not received..\n");
        return 0;
    }
    printf("Client hello was received..\n");
    if (!check_client_hello(data, data_size, &key_length)) {   
        free(data);
        send_error_message(sock, "Oops, connection has been terminated by the server..\n");
        printf("Client hello error..\n");
        return 0;
    }
    free(data);
    printf("Client hello was checked..\n");
    mpz_init(p);
    mpz_init(g);
    mpz_init(server_private_key);
    pthread_mutex_lock(&lock);
    key_RSA = RSA_server_private_key_init();
    if (key_RSA == NULL) {
        mpz_clear(p);
        mpz_clear(g);
        mpz_clear(server_private_key);
        send_error_message(sock, "Oops, connection has been terminated by the server..\n");
        return 0; 
    }
    pthread_mutex_unlock(&lock);
    printf("Key created..\n");
    if (!send_server_hello(sock, server_private_key, p, g, key_length, key_RSA)) {
        mpz_clear(p);
        mpz_clear(g);
        mpz_clear(server_private_key);
        free(key_RSA);
        printf("Server hello was not sent..\n");
        send_error_message(sock, "Oops, connection has been terminated by the server..\n");
        return 0;
    }
    printf("Server hello was sent..\n");
    data = receive_data_from_socket(sock, &data_size);
    if (data == NULL) {
        mpz_clear(p);
        mpz_clear(g);
        mpz_clear(server_private_key);
        free(key_RSA);
        printf("Nonce was not received..\n");
        send_error_message(sock, "Oops, connection has been terminated by the server..\n");
        return 0;
    }
    printf("Nonce was received..\n");
    mpz_init(B);
    if (!check_param_nonce(data, data_size, B, nonce)) {
        mpz_clear(p); 
        mpz_clear(g);
        mpz_clear(server_private_key);
        mpz_clear(B);
        free(data);
        free(key_RSA);
        printf("Nonce error..\n");
        send_error_message(sock, "Oops, connection has been terminated by the server..\n");
        return 0;      
    }
    free(data);
    if (!create_encryption_key_for_AES(server_private_key, B, p, secret_key_AES)) {
        mpz_clear(p); 
        mpz_clear(g);
        mpz_clear(server_private_key);
        mpz_clear(B);
        free(key_RSA);
        printf("Encryption key was not created..\n");
        send_error_message(sock, "Oops, connection has been terminated by the server..\n");
        return 0;         
    }
    printf("Encryption key was created..\n");
    mpz_clear(p);
    mpz_clear(g);
    mpz_clear(B);
    mpz_clear(server_private_key);
    free(key_RSA);
    printf("Secure connection is establish..\n");
    return 1;
}

RSA_key *RSA_server_private_key_init() {
    RSA_key *key;
    FILE *fp;
    unsigned char d[514] = {"\x00"}; 
    unsigned char n[516] = {"\x00"};
    fp = fopen(KEY_FILE, "r");
    if (fp == NULL){
        printf("Could not open client key file..\n");
        return NULL;
    }
    fgets(d, 514, fp);
    fgets(n, 516, fp);
    fclose(fp);
    key = RSA_key_init(d, n);
    return key;
}

int8_t check_client_hello(unsigned char *client_message, uint16_t message_length, int32_t *key_length) {
    unsigned char *buffer;
    if (message_length < 33) {
        return 0;   
    }
    else if (client_message[32] < 48 || client_message[32] > 57) {
        return 0;
    }
    else {
        buffer = malloc(message_length - 31);
        if (buffer == NULL) {
            return 0;
        }
        memset(buffer, 0, message_length - 31);
        for(uint16_t i = 32; i < message_length; i++) {
            if (client_message[i] > 47 && client_message[i] < 58) {
                buffer[i-32] = client_message[i];
            } else {
                break;
            }
        }
        *key_length = atoi(buffer);
        if (*key_length < 2048) {
            free(buffer);
            return 0;
        }
        else {
            free(buffer);
            return 1;
        }
    }
}

int8_t send_server_hello(int32_t sock, mpz_t private_key, mpz_t p, mpz_t g, uint32_t key_length, RSA_key *key_RSA) {
    mpz_t public_key, digital_signature;
    uint16_t message_length = 0;
    unsigned char signature_str[513] = {0};
    unsigned char *server_message, *buffer;
    if (!DHE_generate_parameters(p, g, key_length)) {
        return 0;
    }
    mpz_init(public_key);
    DHE_generate_private_and_public_key(private_key, public_key, p, g); 
    message_length = 540 + mpz_sizeinbase(p, 16) + mpz_sizeinbase(g, 16) + mpz_sizeinbase(public_key, 16); 
    server_message = malloc(message_length);
    if (server_message == NULL) {
        mpz_clear(public_key);
        return 0;
    }
    memset(server_message, 0, message_length);
    strncpy(server_message, "ServerHello:p=", 14);
    buffer = get_bignum_to_str(p);
    if (buffer == NULL) {
        mpz_clear(public_key);
        free(server_message);
        return 0;
    }
    strncat(server_message, buffer, mpz_sizeinbase(p, 16));
    free(buffer);
    strncat(server_message, "|g=", 3);
    buffer = get_bignum_to_str(g);
    if (buffer == NULL) {
        mpz_clear(public_key);
        free(server_message);
        return 0;
    }
    strncat(server_message, buffer, mpz_sizeinbase(g, 16));
    free(buffer);
    strncat(server_message, "|A=", 3);
    buffer = get_bignum_to_str(public_key);
    if (buffer == NULL) {
        mpz_clear(public_key);
        free(server_message);
        return 0;
    }
    strncat(server_message, buffer, mpz_sizeinbase(public_key, 16));
    free(buffer);
    mpz_init(digital_signature);
    if (!get_digital_data_signature(server_message, digital_signature, key_RSA, message_length - 520)) {
        mpz_clear(public_key);
        free(server_message);
        return 0;
    }
    mpz_get_str(signature_str, 16, digital_signature);
    strncat(server_message, "|s=", 3);
    strncat(server_message, signature_str, DIGITAL_SIGNATURE_LENGTH);
    strncat(server_message, "|\n", 2);
    if (send(sock, &message_length, sizeof(uint16_t), 0) == -1 || send(sock, server_message, message_length, 0) == -1) {
        mpz_clear(public_key);
        mpz_clear(digital_signature);
        free(server_message);
        return 0;
    }
    mpz_clear(public_key);
    mpz_clear(digital_signature);
    free(server_message);
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

int8_t check_param_nonce(unsigned char* message, uint16_t full_message_length, mpz_t B, uint8_t *nonce) {
    uint16_t position = 0, data_length = 0, i = 0;
    unsigned char nonce_hex[33] = {"\x00"};
    uint8_t ok = 1;
    ok &= check_input_and_copy_str_to_bignum(message, B, &position, 5, "OK:B=", full_message_length);
    if (strncmp(message + position + 1, "nonce=", 6) != 0) {
        return 0;
    }
    position += 7;
    if ((full_message_length - position < 32) || (message[position + 32] != 124)) {
        return 0;
    }
    memcpy(nonce_hex, &message[position], 32);
    ok &= hex_to_bytes(nonce, nonce_hex);
    if (!ok) {
        return 0;
    }
    return 1;
}

int8_t create_encryption_key_for_AES(mpz_t private_key, mpz_t B, mpz_t p, uint8_t *secret_key_AES) {
    unsigned char *key;
    DHE_generate_symmetric_key(B, B, private_key, p);
    key = malloc(mpz_sizeinbase(B, 16) + 1);
    if (key == NULL) {
        return 0;
    }
    memset(key, mpz_sizeinbase(B, 16) + 1, 0);
    mpz_get_str(key, 16, B);
    SHA256_get_hash_message(key, secret_key_AES, mpz_sizeinbase(B, 16));
    free(key);
    return 1;
}

int8_t encrypt_and_send(int32_t sock, uint8_t *nonce, uint8_t *secret_key) {
    FILE *fp;
    unsigned char flag[75] = {0};
    unsigned char *flag_hex;
    uint16_t length = 148;
    fp = fopen("secret.txt", "r");
    if (fp == NULL){
        printf("Could not open the file..\n");
        return 0;
    }
    fgets(flag, 75, fp);
    fclose(fp);
    AES_init_nonce_and_crypt(secret_key, nonce, flag, 74);
    flag_hex = bytes_to_hex(flag, 74);
    if (flag_hex == NULL) {
        return 0;
    }
    if (send(sock, &length, sizeof(uint16_t), 0) == -1 || send(sock, flag_hex, length, 0) == -1) {
        free(flag_hex);
        return 0;
    }
    free(flag_hex);
    return 1;
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

int8_t get_digital_data_signature(unsigned char *message, mpz_t digital_signature, RSA_key *key_RSA, uint16_t message_length) {
    if (!get_hash_data(message, digital_signature, message_length)) {
        return 0;
    }
    RSA_encrypt_decrypt_hash(key_RSA, digital_signature);
    return 1;
}

int8_t get_hash_data(unsigned char *message, mpz_t hash, uint16_t message_length) {
    unsigned char *hash_plain;
    hash_plain = malloc(SHA256_BLOCK_SIZE + 1);
    if (hash_plain == NULL) {
        return 0;
    }
    else {
        memset(hash_plain, 0, SHA256_BLOCK_SIZE + 1);
        SHA256_get_hash_message(message, hash_plain, message_length);
        SHA256_copy_hash_in_mpz(hash, hash_plain);
    }
    free(hash_plain);
    return 1;
}

int8_t hex_to_bytes(uint8_t *nonce, unsigned char *nonce_hex) {
    uint8_t byte = 0;
    for(int8_t i = 0; i < 32; i += 2) {
        if (!(nonce_hex[i] > 47 && nonce_hex[i] < 58) && !(nonce_hex[i] > 96 && nonce_hex[i] < 103)) {
            return 0;
        }
        if (nonce_hex[i] > 47 && nonce_hex[i] < 58) {
            byte = byte + 16 * (nonce_hex[i] - 48);
        }
        else if (nonce_hex[i] > 96 && nonce_hex[i] < 103) {
            byte = byte + 16 * (nonce_hex[i] - 87);
        }
        if (nonce_hex[i + 1] > 47 && nonce_hex[i + 1] < 58) {
            byte = byte + nonce_hex[i + 1] - 48;
        }
        else if (nonce_hex[i + 1] > 96 && nonce_hex[i + 1] < 103) {
            byte = byte + nonce_hex[i + 1] - 87;
        }
        nonce[i / 2] = byte;
        byte = 0;
    }
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
