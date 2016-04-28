# goAES
AES encryption in golang
AES-256-CBC

Usage:
# ./goAES -pass Password111111111111111111111111 -text HelloWorld
LBxWeil1bM1LbC/cmM9SfomBwlCK2jph07khOpvOqbw=

# ./goAES -pass Password111111111111111111111111 -cipher LBxWeil1bM1LbC/cmM9SfomBwlCK2jph07khOpvOqbw=
HelloWorld

Since the passphrase is 32 bytes, that is the blocksize. AES with a 32 byte block size is AES-256.
