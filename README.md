# DDRBC_U
Data Dependent Rotation Block Cipher for Unix

You should review the source code of this program before using it with important files or a system that contains important files. You take all responsibility for what happens when you use this program.

This program encrypts and decrypts files. The password and nonce are input through standard input. Two filenames are specified on the command line. The first is the input file and the second is the output file.

The password is not translated to a common encoding before being used as the key, so the text encoding used by the encrypting computer and the decrypting computer must be the same. It is recommended that the system locale be set to one that uses UTF-8 for maximum portability. GNU/Linux is set to UTF-8 by default. FreeBSD is set to ASCII by default, which works with UTF-8 if you use an American keyboard.

By default, the program is in encryption mode. For decryption mode, mention the -d option.

RB1 is based on concepts from RC5 and RC6. The number after the dash specifies how many bits per word the program uses. Programs with different word lengths can be made to work with blocks of the same size by changing the number of words used, but they will still generate completely different results.

The block cipher mode of operation used is actually two-fold. First the data is encrypted with CTR mode, then it is encrypted with ECB mode. The encryption with ECB means that the nonce for CTR does not necessarily need to be changed for every message, though you should change it anyway.

### options  
h: output help and exit  
d: decryption mode  
r: number of rounds to encrypt file data  
x: password and nonce input are interpreted as hexadecimal  
b: number of words per block  

The number of rounds and words per block do not need to be provided when decrypting a file.

You should enter information you can't remember to be used as the nonce. Pressing random keys on your keyboard should work fine. :)

The password and nonce are repeated to you through standard output to ensure the text encoding was understood correctly.

When decrypting, the file is not checked for errors. A hash should be computed seperately to verify the integrity of the data.


_______

## CIPHER DESCRIPTION

R = number of rounds  
WPB = words per block  

All array indicies are modulo the number of elements.  


### initialization words (in hexadecimal)

The initialization value is found by setting the most significant bit, then alternating each bit below that between 0 and 1.  
The addend is found by first finding the smallest number of bits that can be used to make a number that when incremented results in a progression that is not shorter than the word size, then aligning the large end of the progression with the least significant bit of the word and counting backwardto fill the more significant bits. For example, in the case of an 8-bit word, you would take a 2-bit number, set the least significant bits or the word to "11", and count backward, filling the next two more significant bits with "10", then "01", and finally "00" for the most significant bits. This results in an addend of 1B. For a 16-bit word would would need to use a 3-bit progression because the 2-bit progression was exhausted after 8 bits. For a 32-bit word you have to use a 4-bit progression, and you can use a 4-bit progression with a 64-bit word too because it takes 64 bits to exhaust the 4-bit progression.

8-bit  
initialization value: AA  
addend: 1B  

16-bit  
initialization value: AAAA  
addend: 3977  

32-bit  
initialization value: AAAAAAAA  
addend: 89ABCDEF  

64-bit  
initialization value: AAAAAAAAAAAAAAAA  
addend: 0123456789ABCDEF  


### generate key schedule

create array KHB of the smallest power of two number of words that is at least WPB * (R + 1)

Load key bytes into words in array KHB. (big endian style)

process KHB  

`A = initialization value`  
`for i = 0 to ((number of words in KHB) * R) - 1 do`  
&emsp;`KHB[i + 1] = ((KHB[i + 1] XOR KHB[i]) <<< KHB[i]) + A`  
&emsp;`A += addend`

array S = the first WPB * R words of KHB  
array D = the next WPB words of KHB


### RB2 encryption
whiten the first word  
encrypt every word starting with the second word and moving forward  
after R rounds, finish by encrypting the first word  
whiten every word except the first word

`B[0] += D[0]`  
`for i = 0 to (WPB * R) - 1 do`  
&emsp;`B[i + 1] = ((B[i + 1] XOR B[i]) <<< B[i]) + S[i]`  
`for i = 1 to WPB - 1 do`  
&emsp;`B[i] += D[i]`


### RB2 decryption
subtract whitening from every word except the first word  
decrypt every word starting with the first word and moving backward  
after R rounds, finish by decrypting the second word  
subtract whitening from the first word  

`for i = WPB - 1 to 1 do`  
&emsp;`B[i] -= D[i]`  
`for i = (WPB * R) - 1 to 0 do`  
&emsp;`B[i + 1] = ((B[i + 1] - S[i]) >>> B[i]) XOR B[i]`  
`B[0] -= D[0]`


_______

## FILE FORMAT

all nubmers are word-sized, big-endian, binary

null-terminated program name string  
file version number  
number of rounds  
words per block  
nonce block  
password check  
encrypted data  
