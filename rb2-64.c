/* Data Dependent Rotation Block Cipher 2
 * 64-bit
 * for Unix
 * 
 * based on concepts from RC5 and RC6
 */


/* pieces section */

#include <stdio.h>
/* fputs()
 * printf()
 * scanf()
 * getchar()
 * getc()
 * putc()
 * fopen()
 * fclose()
 * perror()
 * FILE
 * NULL
 * EOF
 */

#include <stdlib.h>
/* malloc()
 * calloc()
 * realloc()
 * free()
 * NULL
 * EXIT_SUCCESS
 * EXIT_FAILURE
 */

#include <stdint.h>
/* uint8_t
 * uint64_t
 */

#include <stdbool.h>
/* bool
 * true
 * false
 */

#include <unistd.h>
/* getopt()
 */


/* definitions section */

/* RB2-64 */
uint8_t magic[] = {0x52, 0x42, 0x32, 0x2D, 0x36, 0x34, 0x00};

struct options {
 unsigned r;
 unsigned wpb;
 bool hexin;
 uint64_t *n;
 uint64_t *d;
 uint64_t *s;
};


/* functions section */

void fail(char *message)
{
 fprintf(stderr, "%s\n", message);
 exit(EXIT_FAILURE);
}

void error(char *message)
{
 perror(message);
 exit(EXIT_FAILURE);
}

void help()
{
 char message[] = "Data Dependent Rotation Block Cipher 2\n"
 "64-bit\n\n"
 "options\n"
 "h: output help and exit\n"
 "d: decryption mode\n"
 "r: number of rounds to encrypt file data\n"
 "x: password and nonce input are interpreted as hexadecimal\n"
 "b: number of words per block; must be a power of two, at least 2\n\n"
 "After the letter options, the input file must be specified,\nthen the output file.\n";
 fputs(message, stderr);
}

void invalid(char c)
{
 fprintf(stderr, "argument supplied to -%c is invalid\n", c);
 exit(EXIT_FAILURE);
}

/* binary logarithm floor for unsigned integers */
unsigned log2_floor(unsigned x)
{
 unsigned y = 0;

 while(x >>= 1) y++;

 return y;
}

/* binary logarithm ceiling for unsigned integers */
unsigned log2_ceil(unsigned x)
{
 unsigned y;

 y = log2_floor(x);
 if((1 << y) != x) y++;

 return y;
}

/* rotate left */
uint64_t rot_l(uint64_t x, uint64_t n)
{
 n &= 0x3F;
 return (x << n) | (x >> (64 - n));
}

/* rotate right */
uint64_t rot_r(uint64_t x, uint64_t n)
{
 n &= 0x3F;
 return (x >> n) | (x << (64 - n));
}

/* read word byte */
int rwb(uint64_t w, int i)
{
 return (w >> ((7 - i) * 8)) & 0xFF;
}

/* write word byte */
uint64_t wwb(uint64_t w, int i, int b)
{
 w &= (((uint64_t)0) - 1) ^ ((uint64_t)0xFF) << ((7 - i) * 8);
 return w | ((((uint64_t)b) & 0xFF) << ((7 - i) * 8));
}

void write_word(uint64_t x, FILE *fp)
{
 int i;

 for(i = 7; i >= 0; i--)
  if(putc(0xFF & (x >> (i * 8)), fp) == EOF)
   error("write word");

 return;
}

uint64_t read_word(FILE *fp)
{
 int i, c;
 uint64_t x = 0;

 for(i = 7; i >= 0; i--)
 {
  if((c = getc(fp)) == EOF)
   error("read word");
  x |= ((uint64_t)c) << (i * 8);
 }

 return x;
}

void encrypt(uint64_t *b, struct options *opts)
{
 int i, end;
 unsigned m;

 m = opts->wpb - 1;
 end = opts->wpb * opts->r;

 b[0] += opts->d[0];
 for(i = 0; i < end; i++)
  b[(i + 1) & m] = rot_l(b[(i + 1) & m] ^ b[i & m], b[i & m]) + opts->s[i];
 for(i = 1; i < opts->wpb; i++)
  b[i] += opts->d[i];

 return;
}

void decrypt(uint64_t *b, struct options *opts)
{
 int i, end;
 unsigned m;

 m = opts->wpb - 1;
 end = opts->wpb * opts->r;

 for(i = opts->wpb - 1; i > 0; i--)
  b[i] -= opts->d[i];
 for(i = end - 1; i >= 0; i--)
  b[(i + 1) & m] = rot_r(b[(i + 1) & m] - opts->s[i], b[i & m]) ^ b[i & m];
 b[0] -= opts->d[0];

 return;
}

void hash_key(uint64_t *b, unsigned hbwn, struct options *opts)
{
 int i, end;
 unsigned m;
 uint64_t a = 0xAAAAAAAAAAAAAAAA;

 m = hbwn - 1;
 end = hbwn * opts->r;

 for(i = 0; i < end; i++)
 {
  b[(i + 1) & m] = rot_l(b[(i + 1) & m] ^ b[i & m], b[i & m]) + a;
  a += 0x0123456789ABCDEF;
 }

 return;
}

void get_text(uint64_t *b, unsigned hbwn)
{
 int i = 0, c, hbbn;

 hbbn = hbwn * 8;

 c = getchar();
 while((c != EOF) && (c != '\0') && (c != '\n'))
 {
  b[i / 8] = wwb(b[i / 8], i % 8, c + rwb(b[i / 8], i % 8));
  i = (i + 1) % hbbn;
  c = getchar();
 }

 return;
}

/* comprehend hexadecimal digit */
int chd(int c)
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
}

/* get hexadecimal byte */
int get_hb()
{
 int c, b;

 c = getchar();
 if((c == EOF) || (c == '\0') || (c == '\n'))
  return 0x200;
 b = chd(c) << 4;

 c = getchar();
 if((c == EOF) || (c == '\0') || (c == '\n'))
  return 0x100 | b;
 return b | chd(c);
}

void get_hex(uint64_t *b, unsigned hbwn)
{
 int i = 0, c, hbbn;

 hbbn = hbwn * 8;

 c = get_hb();
 while(c != 0x200)
 {
  b[i / 8] = wwb(b[i / 8], i % 8, c + rwb(b[i / 8], i % 8));
  i = (i + 1) % hbbn;
  if((c & 0xF00) == 0x100) break;
  c = get_hb();
 }

 return;
}

void write_header(FILE *outf, struct options *opts)
{
 int i;
 uint64_t *b;

 /* write magic */
 if(fwrite(magic, 1, 7, outf) != 7)
  error("write magic");

 /* write file version number */
 write_word(1, outf);

 /* write number of rounds */
 write_word((uint64_t)opts->r, outf);

 /* write number of words per block */
 write_word((uint64_t)opts->wpb, outf);

 /* write nonce */
 for(i = 0; i < opts->wpb; i++)
  write_word(opts->n[i], outf);

 /* generate password check */
 b = calloc((size_t)opts->wpb, 8);
 encrypt(b, opts);
 /* write password check */
 write_word(b[0], outf);
 free(b);

 return;
}

void read_header(FILE *inf, struct options *opts)
{
 int i;

 /* verify magic */
 for(i = 0; i < 7; i++)
  if(magic[i] != getc(inf))
   fail("incompatible file");

 /* read file version number */
 if(1 != read_word(inf))
  fail("incompatible version");

 /* read number of rounds */
 opts->r = read_word(inf);

 /* read number of words per block */
 opts->wpb = read_word(inf);

 /* read nonce */
 opts->n = calloc((size_t)opts->wpb, 8);
 for(i = 0; i < opts->wpb; i++)
  opts->n[i] = read_word(inf);

 return;
}

/* check password */
void check_pw(FILE *inf, struct options *opts)
{
 uint64_t *b;

 b = calloc((size_t)opts->wpb, 8);
 encrypt(b, opts);
 if(b[0] != read_word(inf))
  fail("password does not match");
 free(b);

 return;
}

void e_stream(FILE *inf, FILE *outf, struct options *opts)
{
 int i, c;
 unsigned opb;
 uint64_t *b, *ks;

 opb = opts->wpb * 8;

 b = malloc((size_t)opb);
 ks = malloc((size_t)opb);

 while(true)
 {
  /* clear block */
  for(i = 0; i < opts->wpb; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < opb; i++)
  {
   if((c = getc(inf)) == EOF)
    break;
   b[i / 8] |= ((uint64_t)c) << ((7 - (i & 7)) * 8);
  }

  /* mark end */
  if(i < opb)
   b[i / 8] |= ((uint64_t)0x80) << ((7 - (i & 7)) * 8);

  /* CTR encryption */
  for(i = 0; i < opts->wpb; i++)
   ks[i] = opts->n[i];
  encrypt(ks, opts);
  for(i = 0; i < opts->wpb; i++)
   b[i] ^= ks[i];
  /* ECB encryption */
  encrypt(b, opts);

  /* write block */
  for(i = 0; i < opts->wpb; i++)
   write_word(b[i], outf);

  if(c == EOF)
  {
   free(b);
   free(ks);
   return;
  }

  /* increment counter */
  for(i = opts->wpb - 1; (!(++opts->n[i])) && (i > 0); i--);
 }
}

void d_stream(FILE *inf, FILE *outf, struct options *opts)
{
 int i, c, end = 0;
 unsigned opb;
 uint64_t *b, *ks;

 opb = opts->wpb * 8;

 b = malloc((size_t)opb);
 ks = malloc((size_t)opb);

 if((c = getc(inf)) == EOF)
  fail("bad file");
 while(true)
 {
  /* clear block */
  for(i = 0; i < opts->wpb; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < opb; i++)
  {
   b[i / 8] |= ((uint64_t)c) << ((7 - (i & 7)) * 8);
   if((c = getc(inf)) == EOF)
    break;
  }
  if(i < (opb - 1))
   fail("last block incomplete");

  /* detect last block */
  if(i == (opb - 1))
   end = 1;

  /* ECB decryption */
  decrypt(b, opts);
  /* CTR decryption */
  for(i = 0; i < opts->wpb; i++)
   ks[i] = opts->n[i];
  encrypt(ks, opts);
  for(i = 0; i < opts->wpb; i++)
   b[i] ^= ks[i];

  /* write last block */
  if(end)
  {
   end = opb - 1;
   while((end > 0) && ((0xFF & (b[end / 8] >> ((7 - (end & 7)) * 8))) == 0))
    end--;

   for(i = 0; i < end; i++)
    if(putc(0xFF & (b[i / 8] >> ((7 - (i & 7)) * 8)), outf) == EOF)
     error("read_oef write block");

   free(b);
   free(ks);
   return;
  }

  /* write block */
  for(i = 0; i < opts->wpb; i++)
   write_word(b[i], outf);

  /* increment counter */
  for(i = opts->wpb - 1; (!(++opts->n[i])) && (i > 0); i--);
 }
}

void e_file(struct options *opts, char *inn, char *outn)
{
 unsigned hbwn;
 uint64_t *khb, *nhb;
 FILE *inf, *outf;

 /* open files */
 if((inf = fopen(inn, "rb")) == NULL) error(inn);
 if((outf = fopen(outn, "wb")) == NULL) error(outn);

 /* create hash blocks */
 hbwn = 1 << log2_ceil(opts->wpb * (opts->r + 1));
 khb = calloc((size_t)hbwn, 8);
 nhb = calloc((size_t)hbwn, 8);
 opts->n = calloc((size_t)opts->wpb, 8);

 /* get key */
 fputs("password: ", stdout);
 if(opts->hexin) 
  get_hex(khb, hbwn);
 else
  get_text(khb, hbwn);

 /* get nonce */
 fputs("nonce: ", stdout);
 if(opts->hexin) 
  get_hex(nhb, hbwn);
 else
  get_text(nhb, hbwn);

 /* generate nonce */
 hash_key(nhb, hbwn, opts);
 opts->s = nhb;
 opts->d = nhb + (opts->wpb * opts->r);
 encrypt(opts->n, opts);

 /* generate key schedule */
 hash_key(khb, hbwn, opts);
 opts->s = khb;
 opts->d = khb + (opts->wpb * opts->r);

 /* write file header */
 write_header(outf, opts);

 /* encrypt file */
 e_stream(inf, outf, opts);

 /* free allocated space */
 free(khb);
 free(nhb);
 free(opts->n);

 /* close files */
 fclose(inf);
 fclose(outf);

 return;
}

void d_file(struct options *opts, char *inn, char *outn)
{
 unsigned hbwn;
 uint64_t *khb;
 FILE *inf, *outf;

 /* open files */
 if((inf = fopen(inn, "rb")) == NULL) error(inn);
 if((outf = fopen(outn, "wb")) == NULL) error(outn);

 /* read file header */
 read_header(inf, opts);

 /* create hash blocks */
 hbwn = 1 << log2_ceil(opts->wpb * (opts->r + 1));
 khb = calloc((size_t)hbwn, 8);

 /* get key */
 fputs("password: ", stdout);
 if(opts->hexin) 
  get_hex(khb, hbwn);
 else
  get_text(khb, hbwn);

 /* generate key schedule */
 hash_key(khb, hbwn, opts);
 opts->s = khb;
 opts->d = khb + (opts->wpb * opts->r);

 /* check password */
 check_pw(inf, opts);

 /* decrypt file */
 d_stream(inf, outf, opts);

 /* free allocated space */
 free(khb);
 free(opts->n);

 /* close files */
 fclose(inf);
 fclose(outf);

 return;
}

int main(int argc, char **argv)
{
 int c, mode = 1;
 struct options opts;
 extern char *optarg;
 extern int opterr, optind, optopt;

 /* prepare default settings */
 opts.r = 20;
 opts.wpb = 4;
 opts.hexin = false;

 /* parse command line */
 while((c = getopt(argc, argv, "hdr:xb:")) != -1)
  switch(c)
  {
   case 'h': help(); exit(EXIT_SUCCESS);
   case 'd': mode = -1; break;
   case 'r': if(sscanf(optarg, "%u", &opts.r) != 1) invalid(c); break;
   case 'x': opts.hexin = true; break;
   case 'b': if(sscanf(optarg, "%u", &opts.wpb) != 1) invalid(c); break;
   case '?': exit(EXIT_FAILURE);
  }

 /* check values */
 if(opts.r < 1) fail("\"r\" must be at least 1");

 if(opts.wpb < 2) fail("\"b\" must be at least 2");
 if((1 << log2_floor(opts.wpb)) != opts.wpb) fail("\"b\" must be a power of two");

 if(argv[optind] == NULL) fail("missing input filename");
 if(argv[optind + 1] == NULL) fail("missing output filename");

 /* process file */
 if(mode == 1) e_file(&opts, argv[optind], argv[optind + 1]);
 else if(mode == -1) d_file(&opts, argv[optind], argv[optind + 1]);
 else return EXIT_FAILURE;

 return EXIT_SUCCESS;
}
