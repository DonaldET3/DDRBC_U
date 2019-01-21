# DDRBC_U
Data Dependent Rotation Block Cipher for Unix

**This program will be rewritten soon. The new program will not be complatible with this one.**

This program encrypts and decrypts files. The password and nonce are input through standard input. Two filenames are specified on the command line. The first is the input file and the second is the output file.

The password is not translated to a common encoding before being used as the key, so the text encoding used by the encrypting computer and the decrypting computer must be the same. It is recommended that the system locale be set to one that uses UTF-8 for maximum portability. GNU/Linux is set to UTF-8 by default. FreeBSD is set to ASCII by default, which works with UTF-8 if you use an American keyboard.

By default, the program is in encryption mode. For decryption mode, mention the -d option.

RB1 is based on concepts from RC5 and RC6. The number after the dash specifies how many bits per word the program uses. Programs with different word lengths can be made to work with blocks of the same size by changing the number of words used, but they will still generate completely different results.

The block cipher mode of operation used is actually two-fold. First the data is encrypted with CTR mode, then it is encrypted with ECB mode. The encryption with ECB means that the nonce for CTR does not necessarily need to be changed for every message, though you should change it anyway.

options <br />
h: output help and exit <br />
d: decryption mode <br />
r: number of rounds to encrypt file data <br />
x: password and nonce input are interpreted as hexadecimal <br />
b: number of words per block <br />

The number of rounds and words per block do not need to be provided when decrypting a file.

You should enter information you can't remember to be used as the nonce. Pressing random keys on your keyboard should work fine. :)

The password and nonce are repeated to you through standard output to ensure the text encoding was understood correctly.

When decrypting, the file is not checked for errors. A hash should be computed seperately to verify the integrity of the data.


FILE FORMAT

all nubmers are word-sized, big-endian, binary

null-terminated program name string <br />
file version number <br />
number of rounds <br />
words per block <br />
nonce block <br />
password check <br />
encrypted data <br />
