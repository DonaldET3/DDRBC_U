# Opal Block Cipher 1

**You should review the source code of this program before using it with important files or a system that contains important files. You take all responsibility for what happens when you use this program. If you do decide to use this program, save a copy of the source code; the code in this repository may be replaced by an entirely incompatible program at any time.**

This program encrypts and decrypts files. The password and nonce are input through standard input.

The password is not translated to a common encoding before being used as the key, so the text encoding used by the encrypting computer and the decrypting computer must be the same. It is recommended that the system locale be set to one that uses UTF-8 for maximum portability. GNU/Linux is set to UTF-8 by default. FreeBSD is set to ASCII by default, which works with UTF-8 if you use an American keyboard.

By default, the program is in encryption mode. For decryption mode, mention the -d option.

The number in the program name after the dash specifies how many bits per word the program uses. Programs with different word lengths can be made to work with blocks of the same size by changing the number of words used, but they will still generate completely different results.

### options  
h: output help and exit  
d: decryption mode  
e: re-encryption mode  
x: password and nonce input are interpreted as hexadecimal  
r: number of rounds to encrypt file data (default: 12)  
b: number of words per block (default: 4)  

The input and output file names are prompted for. In decryption mode, the file is checked for a file name before prompting for an output file name.

The number of rounds and words per block do not need to be provided when decrypting a file.

You should enter information you can't remember to be used as the nonce. Pressing random keys on your keyboard should work quite well.

The data is not checked for errors. A hash should be computed seperately to verify the integrity of the data.

### minimum reccomended number of rounds for each block size with 64-bit words
2 words: 33 rounds  
4 words: 12 rounds  
8 words: 6 rounds  
16 words: 4 rounds  
32 words: 3 rounds  
33 words and up: 2 rounds  


_______

## CIPHER DESCRIPTION

Multi-byte words are interpreted as big-endian.

### constants (in hexadecimal)

The constant value is found by first finding the smallest number of bits that can be used to make a number that, when incremented, results in a progression that is not shorter than the word size, then aligning the large end of the progression with the least significant bit of the word and counting backward to fill the more significant bits. For example, in the case of an 8-bit word, you would take a 2-bit number, set the least significant bits or the word to "11", and count backward, filling the next two more significant bits with "10", then "01", and finally "00" for the most significant bits. This results in an addend of 1B. For a 16-bit word would would need to use a 3-bit progression because the 2-bit progression was exhausted after 8 bits. For a 32-bit word you have to use a 4-bit progression, and you can use a 4-bit progression with a 64-bit word too because it takes 64 bits to exhaust the 4-bit progression.

8-bit: 1B  
16-bit: 3977  
32-bit: 89ABCDEF  
64-bit: 0123456789ABCDEF  


### generate key block
For each block of key bytes, XOR the bytes into the key block, then mix the block. At the end of the key byte string, a singe set bit is appended, followed by a series of clear bits to fill the last block.


### OBC1 encryption
N = nonce  
P = plaintext block  
C = ciphertext block  
B = block being processed  
K = key block  
S = counter stream block  

The nonce is incremented for each block.

> #### for each block
> S = K XOR N  
> mix(S)  
> B = P XOR S  
> mix(B)  
> C = B XOR K  
> increment N  

### decryption
> #### for each block
> B = C XOR K  
> unmix(B)  
> S = K XOR N  
> mix(S)  
> P = B XOR S  
> increment N  


### mix
R = number of rounds  
WPB = words per block  
A = constant  

    for i = 0 to R - 1 do  
     for j = 1 to WPB - 1 do  
      B[j] XOR= (B[j - 1] << 1) XOR B[j - 1] XOR (B[j - 1] >> 1) XOR A  
     for j = WPB - 2 to 0 do  
      B[j] XOR= (B[j + 1] << 1) XOR B[j + 1] XOR (B[j + 1] >> 1) XOR A  


### unmix
    for i = 0 to R - 1 do  
     for j = 0 to WPB - 2 do  
      B[j] XOR= (B[j + 1] << 1) XOR B[j + 1] XOR (B[j + 1] >> 1) XOR A  
     for j = WPB - 1 to 1 do  
      B[j] XOR= (B[j - 1] << 1) XOR B[j - 1] XOR (B[j - 1] >> 1) XOR A  


_______

## FILE FORMAT

all binary numbers are big-endian

### file layout
null-terminated magic string  
file version byte  
number of rounds (hexadecimal string)  
words per block (hexadecimal string)  
nonce block  
password check block  
encrypted file name (null-terminated)  
encrypted data  

To generate the password check: mix the key 4 times, then XOR the key with the mixed key.

The data starts just after the next block boundary after the file name.
