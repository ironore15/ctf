(echo "98416"; echo "50") | gdb ./pro -ex "set print elements 0" -ex "b *0x555555554000 + 0x8E2" -ex "r" -ex "x/s 0x555555554000 + 0x201100" | grep "BambooFox"
