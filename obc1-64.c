/* Opal Block Cipher 1
 * 64-bit
 * for Unix
 * 
 * partly inspired by TEA
 * similar to a "single-key Even-Mansour scheme"
 */


/* pieces section */

#include <errno.h>
/* errno
 */

#include <stdio.h>
/* fputs()
 * printf()
 * fprintf()
 * sscanf()
 * getchar()
 * getc()
 * putc()
 * getline()
 * getdelim()
 * fwrite()
 * fopen()
 * fclose()
 * FILE
 * NULL
 * EOF
 */

#include <stdlib.h>
/* malloc()
 * calloc()
 * realloc()
 * free()
 * exit()
 * NULL
 * EXIT_SUCCESS
 * EXIT_FAILURE
 */

#include <string.h>
/* strtok()
 * strerror_l()
 */

#include <stdint.h>
/* uint8_t
 * uint64_t
 * uintmax_t
 */

#include <stdbool.h>
/* bool
 * true
 * false
 */

#include <locale.h>
/* uselocale()
 */

#include <unistd.h>
/* getopt()
 * access()
 * F_OK
 */


/* definitions section */

/* OBC1-64 */
uint8_t magic[] = {0x4F, 0x42, 0x43, 0x31, 0x2D, 0x36, 0x34, 0x00};

/* program options */
struct options {
 /* number of rounds */
 uintmax_t rounds;
 /* words per block */
 uintmax_t wpb;
 /* hexadecimal input? */
 bool hex_in;
};

/* cipher parameters */
struct cipher_params {
 /* number of rounds */
 uintmax_t rounds;
 /* words per block */
 uintmax_t wpb;
 /* nonce block */
 uint64_t *nonce;
 /* key block */
 uint64_t *key;
};

/* text input buffer */
char *i_buf;
/* buffer size */
size_t ib_s;


/* functions section */

/* print error message and quit */
void fail(char *message)
{
 /* print error message */
 fputs(message, stderr);
 /* elaborate on the error if possible */
 if(errno) fprintf(stderr, ": %s", strerror_l(errno, uselocale((locale_t)0)));
 putc('\n', stderr);
 exit(EXIT_FAILURE);
}

/* "failed to" <error message> and quit */
void failed(char *message)
{
 /* prepend "failed to" to the error message */
 fputs("failed to ", stderr);
 fail(message);
}

/* print help */
void help()
{
 char message[] = "Opal Block Cipher 1\n"
 "64-bit\n\n"
 "options\n"
 "h: output help and exit\n"
 "d: decryption mode\n"
 "e: re-encryption mode\n"
 "r: number of rounds to encrypt file data (default: 12)\n"
 "x: password and nonce input are interpreted as hexadecimal\n"
 "b: number of words per block; must be at least 2 (default: 4)\n\n"
 "By default, the program is in encryption mode.\n";
 fputs(message, stderr);
}

/* bad command line value */
void invalid(char c)
{
 fprintf(stderr, "value supplied to -%c is invalid\n", c);
 exit(EXIT_FAILURE);
}

/* allocate space and put an input line in it */
char *input_line()
{
 size_t space = 0;
 char *line = NULL;

 if(getline(&line, &space, stdin) == -1) failed("read input line");
 strtok(line, "\n");
 return line;
}

/* write hexadecimal number */
void write_number(uintmax_t x, FILE *fp)
{
 if(fprintf(fp, "%jX", x) < 0) failed("write number value");
 if(putc('\0', fp) == EOF) failed("write number terminator");
 return;
}

/* read hexadecimal number */
uintmax_t read_number(FILE *fp)
{
 uintmax_t x;
 if(getdelim(&i_buf, &ib_s, '\0', fp) == -1) failed("read number");
 if(sscanf(i_buf, "%jx", &x) != 1) failed("comprehend number");
 return x;
}

/* read bit-endian word */
uint64_t read_word(FILE *fp)
{
 int i, c;
 uint64_t x = 0;

 for(i = 7; i >= 0; i--)
 {
  if((c = getc(fp)) == EOF) failed("read word");
  x |= ((uint64_t)c) << (i * 8);
 }

 return x;
}

/* write a block of big-endian words */
void write_block(uint64_t *x, uintmax_t n, FILE *fp)
{
 uintmax_t i;
 int j;

 for(i = 0; i < n; i++)
  for(j = 7; j >= 0; j--)
   if(putc(0xFF & (x[i] >> (j * 8)), fp) == EOF)
    failed("write block");

 return;
}

/* write a partial block of plaintext bytes */
void write_last_block(uint64_t *x, uintmax_t n, FILE *fp)
{
 uintmax_t i, end;

 /* find the last byte in the block */
 for(end = (n * 8) - 1; end > 0; end--)
  if((x[end / 8] >> ((7 - (end % 8)) * 8)) & 0xFF)
   break;

 /* write the bytes that contain data */
 for(i = 0; i < end; i++)
  if(putc((x[i / 8] >> ((7 - (i % 8)) * 8)) & 0xFF, fp) == EOF)
   failed("write last block");

 return;
}

/* read a block of big-endian words */
bool read_block(uint64_t *x, uintmax_t n, FILE *fp)
{
 uintmax_t i;
 int j, c;

 /* clear block */
 for(i = 0; i < n; i++) x[i] = 0;

 /* for each word */
 for(i = 0; i < n; i++)
  /* for each byte */
  for(j = 7; j >= 0; j--)
  {
   /* if end of file, terminate data with a single set bit */
   if((c = getc(fp)) == EOF)
   {
    x[i] |= ((uint64_t)0x80) << (j * 8);
    return false;
   }
   /* add byte to the word */
   x[i] |= ((uint64_t)c) << (j * 8);
  }

 return true;
}

/* OBC1 block permutation */
void mix(uint64_t *b, uintmax_t rounds, uintmax_t wpb)
{
 uintmax_t i, j, end;
 const uint64_t a = 0x0123456789ABCDEF;

 end = wpb - 1;

 for(i = 0; i < rounds; i++)
 {
  /* permute each word with the word before it */
  for(j = 0; j < end; j++) b[j + 1] ^= (b[j] << 1) ^ b[j] ^ (b[j] >> 1) ^ a;
  /* permute each word with the word after it */
  for(j = end; j > 0; j--) b[j - 1] ^= (b[j] << 1) ^ b[j] ^ (b[j] >> 1) ^ a;
 }

 return;
}

/* OBC1 block permutation inverse */
void unmix(uint64_t *b, uintmax_t rounds, uintmax_t wpb)
{
 uintmax_t i, j, end;
 const uint64_t a = 0x0123456789ABCDEF;
 const uintmax_t n = ((uintmax_t)0) - 1;

 end = wpb - 2;

 for(i = 0; i < rounds; i++)
 {
  /* permute each word with the word after it */
  for(j = 1; j < wpb; j++) b[j - 1] ^= (b[j] << 1) ^ b[j] ^ (b[j] >> 1) ^ a;
  /* permute each word with the word before it */
  for(j = end; j != n; j--) b[j + 1] ^= (b[j] << 1) ^ b[j] ^ (b[j] >> 1) ^ a;
 }

 return;
}

void encrypt_block(uint64_t *block, uint64_t *key_stream, struct cipher_params *params)
{
 uintmax_t i;

 /* nonce and pre-whitening */
 for(i = 0; i < params->wpb; i++) key_stream[i] = params->key[i] ^ params->nonce[i];
 /* generate key stream (CTR mix) */
 mix(key_stream, params->rounds, params->wpb);
 /* apply key stream to plaintext */
 for(i = 0; i < params->wpb; i++) block[i] ^= key_stream[i];
 /* ECB mix */
 mix(block, params->rounds, params->wpb);
 /* post-whitening */
 for(i = 0; i < params->wpb; i++) block[i] ^= params->key[i];

 /* increment nonce */
 for(i = params->wpb - 1; (!(++params->nonce[i])) && (i > 0); i--);

 return;
}

void decrypt_block(uint64_t *block, uint64_t *key_stream, struct cipher_params *params)
{
 uintmax_t i;

 /* undo post-whitening */
 for(i = 0; i < params->wpb; i++) block[i] ^= params->key[i];
 /* ECB unmix */
 unmix(block, params->rounds, params->wpb);
 /* nonce and pre-whitening */
 for(i = 0; i < params->wpb; i++) key_stream[i] = params->key[i] ^ params->nonce[i];
 /* generate key stream (CTR mix) */
 mix(key_stream, params->rounds, params->wpb);
 /* apply key stream to get plaintext */
 for(i = 0; i < params->wpb; i++) block[i] ^= key_stream[i];

 /* increment nonce */
 for(i = params->wpb - 1; (!(++params->nonce[i])) && (i > 0); i--);

 return;
}

/* convert hexadecimal digit to binary quartet */
int hex_quartet(int c)
{
 switch(c)
 {
  case '0': return 0x0;
  case '1': return 0x1;
  case '2': return 0x2;
  case '3': return 0x3;
  case '4': return 0x4;
  case '5': return 0x5;
  case '6': return 0x6;
  case '7': return 0x7;
  case '8': return 0x8;
  case '9': return 0x9;
  case 'A': return 0xA;
  case 'B': return 0xB;
  case 'C': return 0xC;
  case 'D': return 0xD;
  case 'E': return 0xE;
  case 'F': return 0xF;
  case 'a': return 0xA;
  case 'b': return 0xB;
  case 'c': return 0xC;
  case 'd': return 0xD;
  case 'e': return 0xE;
  case 'f': return 0xF;
  default: fail("not a hexadecimal number");
 }

 /* This is just to quiet Clang. */
 return 0;
}

void write_header(FILE *out_file, struct cipher_params *params)
{
 uintmax_t i;
 uint64_t *block;

 /* write magic */
 if(fwrite(magic, 1, 8, out_file) != 8) failed("write magic");

 /* write file version number */
 putc(1, out_file);

 /* write number of rounds */
 write_number(params->rounds, out_file);

 /* write number of words per block */
 write_number(params->wpb, out_file);

 /* write nonce */
 write_block(params->nonce, params->wpb, out_file);

 /* generate password check */
 if((block = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate pw check block");
 for(i = 0; i < params->wpb; i++) block[i] = params->key[i];
 mix(block, params->rounds * 4, params->wpb);
 for(i = 0; i < params->wpb; i++) block[i] ^= params->key[i];
 /* write password check */
 write_block(block, params->wpb, out_file);
 free(block);

 return;
}

void read_header(FILE *in_file, struct cipher_params *params)
{
 uintmax_t i;
 uint64_t *block;

 /* verify magic */
 for(i = 0; i < 8; i++)
  if(magic[i] != getc(in_file))
   fail("incompatible file");

 /* read file version number */
 if(1 != getc(in_file)) fail("incompatible version");

 /* read number of rounds */
 params->rounds = read_number(in_file);

 /* read number of words per block */
 params->wpb = read_number(in_file);

 /* check values */
 if(params->rounds < 1) fail("invalid value in file for rounds");
 if(params->wpb < 2) fail("invalid value in file for words per block");

 /* read nonce */
 if((params->nonce = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate nonce block");
 if(!read_block(params->nonce, params->wpb, in_file)) failed("read nonce");

 return;
}

/* check password */
void check_pw(FILE *in_file, struct cipher_params *params)
{
 uintmax_t i;
 uint64_t *block;

 /* generate check */
 if((block = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate pw check block");
 for(i = 0; i < params->wpb; i++) block[i] = params->key[i];
 mix(block, params->rounds * 4, params->wpb);
 for(i = 0; i < params->wpb; i++) block[i] ^= params->key[i];

 /* compare check */
 for(i = 0; i < params->wpb; i++)
  if(block[i] != read_word(in_file))
   fail("password does not match");

 free(block);

 return;
}

/* generate block from string */
uint64_t *gen_block(char *string, struct options *opts)
{
 uintmax_t i, length;
 uint64_t *block;

 length = opts->wpb * sizeof(uint64_t);
 if((block = calloc(opts->wpb, sizeof(uint64_t))) == NULL) failed("allocate block space");

 /* interpret as hexadecimal digits */
 if(opts->hex_in)
 {
  length *= 2;

  /* process blocks */
  while(true)
  {
   /* XOR in a block */
   for(i = 0; i < length; i++)
   {
    /* if end of string */
    if(string[i] == '\0')
    {
     block[i / 16] ^= ((uint64_t)0x8) << ((15 - (i % 16)) * 4);
     mix(block, opts->rounds, opts->wpb);
     return block;
    }
    block[i / 16] ^= ((uint64_t)hex_quartet(string[i])) << ((15 - (i % 16)) * 4);
   }
   mix(block, opts->rounds, opts->wpb);
   string += length;
  }
 }
 /* interpret as a string */
 else
 {
  /* process blocks */
  while(true)
  {
   /* XOR in a block */
   for(i = 0; i < length; i++)
   {
    /* if end of string */
    if(string[i] == '\0')
    {
     block[i / 8] ^= ((uint64_t)0x80) << ((7 - (i % 8)) * 8);
     mix(block, opts->rounds, opts->wpb);
     return block;
    }
    block[i / 8] ^= ((uint64_t)string[i]) << ((7 - (i % 8)) * 8);
   }
   mix(block, opts->rounds, opts->wpb);
   string += length;
  }
 }
}

void encrypt_string(char *string, FILE *out_file, struct cipher_params *params)
{
 uintmax_t i, length;
 uint64_t *block, *space;

 length = params->wpb * sizeof(uint64_t);
 if((block = malloc(length)) == NULL) failed("allocate block space");
 if((space = malloc(length)) == NULL) failed("allocate space block");

 while(true)
 {
  /* clear block */
  for(i = 0; i < params->wpb; i++) block[i] = 0;

  /* for each byte */
  for(i = 0; i < length; i++)
  {
   /* if end of string */
   if(string[i] == '\0')
   {
    encrypt_block(block, space, params);
    write_block(block, params->wpb, out_file);
    free(block); free(space);
    return;
   }
   /* add byte to block */
   block[i / 8] |= ((uint64_t)string[i]) << ((7 - (i % 8)) * 8);
  }
  encrypt_block(block, space, params);
  write_block(block, params->wpb, out_file);
  /* move on to next block of bytes */
  string += length;
 }
}

char *decrypt_string(FILE *in_file, struct cipher_params *params)
{
 uintmax_t i, block_size, string_size, base = 0;
 uint64_t *block, *space;
 char *string;

 block_size = params->wpb * sizeof(uint64_t);
 if((block = malloc(block_size)) == NULL) failed("allocate block space");
 if((space = malloc(block_size)) == NULL) failed("allocate space block");
 if((string = malloc(string_size = block_size)) == NULL) failed("allocate string space");

 while(true)
 {
  /* read and decrypt block */
  if(!read_block(block, params->wpb, in_file)) failed("read encrypted string");
  decrypt_block(block, space, params);

  /* for each byte */
  for(i = 0; i < block_size; i++)
   if((string[base + i] = (block[i / 8] >> ((7 - (i % 8)) * 8)) & 0xFF) == 0)
   {
    free(block); free(space);
    return string;
   }

  /* increase string space */
  if((string = realloc(string, string_size += block_size)) == NULL) failed("allocate string space");
  base += block_size;
 }
}

void encrypt_stream(FILE *in_file, FILE *out_file, struct cipher_params *params)
{
 uint64_t *block, *space;

 if((block = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate block space");
 if((space = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate space block");

 /* encrypt blocks */
 while(read_block(block, params->wpb, in_file))
 {
  encrypt_block(block, space, params);
  write_block(block, params->wpb, out_file);
 }

 /* encrypt last block */
 encrypt_block(block, space, params);
 write_block(block, params->wpb, out_file);

 free(block);
 free(space);

 return;
}

void decrypt_stream(FILE *in_file, FILE *out_file, struct cipher_params *params)
{
 uintmax_t i;
 uint64_t *block, *space, *next;

 if((block = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate block space");
 if((space = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate space block");
 if((next = malloc(params->wpb * sizeof(uint64_t))) == NULL) failed("allocate block space");

 /* read first block */
 if(!read_block(block, params->wpb, in_file)) failed("read encrypted data");

 /* decrypt blocks */
 while(read_block(next, params->wpb, in_file))
 {
  decrypt_block(block, space, params);
  write_block(block, params->wpb, out_file);
  for(i = 0; i < params->wpb; i++) block[i] = next[i];
 }

 /* decrypt last block */
 decrypt_block(block, space, params);
 write_last_block(block, params->wpb, out_file);

 free(block);
 free(space);
 free(next);

 return;
}

void reencrypt_stream(FILE *in_file, FILE *out_file, struct cipher_params *old_params, struct cipher_params *new_params)
{
 uintmax_t i, j = 0, end;
 uint64_t *in_block, *in_space, *in_next, *out_block, *out_space;

 if((in_block = malloc(old_params->wpb * sizeof(uint64_t))) == NULL) failed("allocate block space");
 if((in_space = malloc(old_params->wpb * sizeof(uint64_t))) == NULL) failed("allocate space block");
 if((in_next = malloc(old_params->wpb * sizeof(uint64_t))) == NULL) failed("allocate block space");
 if((out_block = malloc(new_params->wpb * sizeof(uint64_t))) == NULL) failed("allocate block space");
 if((out_space = malloc(new_params->wpb * sizeof(uint64_t))) == NULL) failed("allocate space block");

 /* read first block */
 if(!read_block(in_block, old_params->wpb, in_file)) failed("read encrypted data");

 while(read_block(in_next, old_params->wpb, in_file))
 {
  /* decrypt input blocks */
  decrypt_block(in_block, in_space, old_params);

  /* for each word in each input block... */
  for(i = 0; i < old_params->wpb; i++)
  {
   /* encrypt and write output block if full */
   if(j == new_params->wpb)
   {
    encrypt_block(out_block, out_space, new_params);
    write_block(out_block, new_params->wpb, out_file);
    j = 0;
   }
   /* copy plaintext word */
   out_block[j++] = in_block[i];
  }
  /* copy next block */
  for(i = 0; i < old_params->wpb; i++) in_block[i] = in_next[i];
 }

 /* decrypt last input block */
 decrypt_block(in_block, in_space, old_params);
 /* find last data word */
 for(end = old_params->wpb - 1; end > 0; end--) if(in_block[end]) break;

 /* for each remaining word */
 for(i = 0; i <= end; i++)
 {
  /* encrypt and write output block if full */
  if(j == new_params->wpb)
  {
   encrypt_block(out_block, out_space, new_params);
   write_block(out_block, new_params->wpb, out_file);
   j = 0;
  }
  /* copy plaintext word */
  out_block[j++] = in_block[i];
 }

 /* zero the rest of the last output block */
 for(; j < new_params->wpb; j++) out_block[j] = 0;
 /* encrypt and write last output block */
 encrypt_block(out_block, out_space, new_params);
 write_block(out_block, new_params->wpb, out_file);

 free(in_block);
 free(in_space);
 free(in_next);
 free(out_block);
 free(out_space);

 return;
}

void encrypt_file(struct options *opts)
{
 char *in_name, *out_name, *key_string, *nonce_string;
 FILE *in_file, *out_file;
 struct cipher_params params;

 params.rounds = opts->rounds;
 params.wpb = opts->wpb;

 /* open input file */
 fputs("file to encrypt: ", stdout);
 in_name = input_line();
 if((in_file = fopen(in_name, "rb")) == NULL) fail(in_name);

 /* open output file */
 fputs("encrypted file name: ", stdout);
 out_name = input_line();
 if((out_file = fopen(out_name, "wb")) == NULL) fail(out_name);

 /* get password */
 fputs("password: ", stdout);
 key_string = input_line();
 params.key = gen_block(key_string, opts);

 /* get nonce */
 fputs("nonce: ", stdout);
 nonce_string = input_line();
 params.nonce = gen_block(nonce_string, opts);

 /* write file header */
 write_header(out_file, &params);

 /* write encrypted string */
 encrypt_string(in_name, out_file, &params);

 /* encrypt data */
 puts("encrypting data...");
 encrypt_stream(in_file, out_file, &params);
 puts("done");

 /* free space */
 free(in_name);
 free(out_name);
 free(key_string);
 free(nonce_string);
 free(params.key);
 free(params.nonce);

 /* close files */
 fclose(in_file);
 fclose(out_file);

 return;
}

void decrypt_file(struct options *opts)
{
 char *in_name, *out_name, *key_string;
 FILE *in_file, *out_file;
 struct cipher_params params;

 /* open input file */
 fputs("encrypted file name: ", stdout);
 in_name = input_line();
 if((in_file = fopen(in_name, "rb")) == NULL) fail(in_name);

 /* read file header */
 read_header(in_file, &params);
 opts->rounds = params.rounds;
 opts->wpb = params.wpb;

 /* get password */
 fputs("password: ", stdout);
 key_string = input_line();
 params.key = gen_block(key_string, opts);

 /* check password */
 check_pw(in_file, &params);

 /* read encrypted string */
 out_name = decrypt_string(in_file, &params);

 if(out_name[0])
 {
  printf("real file name: \"%s\"\n", out_name);

  /* see whether file already exists */
  if(access(out_name, F_OK) == 0)
  {
   puts("A file with this name already exists.");
   free(out_name);
   fputs("decrypted file name: ", stdout);
   out_name = input_line();
  }
  errno = 0;
 }
 /* if there is no file name */
 else
 {
  puts("no stored file name");
  free(out_name);
  fputs("decrypted file name: ", stdout);
  out_name = input_line();
 }

 /* open output file */
 if((out_file = fopen(out_name, "wb")) == NULL) fail(out_name);

 /* decrypt data */
 puts("decrypting data...");
 decrypt_stream(in_file, out_file, &params);
 puts("done");

 /* free space */
 free(in_name);
 free(out_name);
 free(key_string);
 free(params.key);
 free(params.nonce);

 /* close files */
 fclose(in_file);
 fclose(out_file);

 return;
}

void reencrypt_file(struct options *opts)
{
 char *in_name, *out_name, *real_name, *old_key_str, *new_key_str, *new_nonce_str;
 FILE *in_file, *out_file;
 struct cipher_params old_params, new_params;

 new_params.rounds = opts->rounds;
 new_params.wpb = opts->wpb;

 /* open input file */
 fputs("old file name: ", stdout);
 in_name = input_line();
 if((in_file = fopen(in_name, "rb")) == NULL) fail(in_name);

 /* read file header */
 read_header(in_file, &old_params);
 opts->rounds = old_params.rounds;
 opts->wpb = old_params.wpb;

 /* get old password */
 fputs("old password: ", stdout);
 old_key_str = input_line();
 old_params.key = gen_block(old_key_str, opts);

 /* check password */
 check_pw(in_file, &old_params);

 /* read real file name string */
 real_name = decrypt_string(in_file, &old_params);

 /* open output file */
 fputs("new file name: ", stdout);
 out_name = input_line();
 if((out_file = fopen(out_name, "wb")) == NULL) fail(out_name);

 /* get new password */
 fputs("new password: ", stdout);
 new_key_str = input_line();
 opts->rounds = new_params.rounds;
 opts->wpb = new_params.wpb;
 new_params.key = gen_block(new_key_str, opts);

 /* get nonce */
 fputs("nonce: ", stdout);
 new_nonce_str = input_line();
 new_params.nonce = gen_block(new_nonce_str, opts);

 /* write file header */
 write_header(out_file, &new_params);

 /* write encrypted string */
 encrypt_string(real_name, out_file, &new_params);

 /* re-encrypt data */
 puts("re-encrypting data...");
 reencrypt_stream(in_file, out_file, &old_params, &new_params);
 puts("done");

 /* free space */
 free(in_name);
 free(out_name);
 free(real_name);
 free(old_key_str);
 free(new_key_str);
 free(new_nonce_str);
 free(old_params.key);
 free(old_params.nonce);
 free(new_params.key);
 free(new_params.nonce);

 /* close files */
 fclose(in_file);
 fclose(out_file);

 return;
}

int main(int argc, char **argv)
{
 int c, mode = 1;
 struct options opts;
 extern char *optarg;
 extern int opterr, optind, optopt;

 /* the errno symbol is defined in errno.h */
 errno = 0;

 /* initialize global variables */
 i_buf = NULL;
 ib_s = 0;

 /* prepare default settings */
 opts.rounds = 12;
 opts.wpb = 4;
 opts.hex_in = false;

 /* parse command line */
 while((c = getopt(argc, argv, "hder:xb:")) != -1)
  switch(c)
  {
   case 'h': help(); exit(EXIT_SUCCESS);
   case 'd': mode = -1; break;
   case 'e': mode = 2; break;
   case 'r': if(sscanf(optarg, "%ju", &opts.rounds) != 1) invalid(c); break;
   case 'x': opts.hex_in = true; break;
   case 'b': if(sscanf(optarg, "%ju", &opts.wpb) != 1) invalid(c); break;
   case '?': exit(EXIT_FAILURE);
  }

 /* check values */
 if(opts.rounds < 1) fail("\"r\" must be at least 1");
 if(opts.wpb < 2) fail("\"b\" must be at least 2");

 /* process file */
 if(mode == 1) encrypt_file(&opts);
 else if(mode == -1) decrypt_file(&opts);
 else if(mode == 2) reencrypt_file(&opts);
 else return EXIT_FAILURE;

 free(i_buf);

 return EXIT_SUCCESS;
}
