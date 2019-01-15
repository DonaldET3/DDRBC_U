/* Data Dependent Rotation Block Cipher 1
 * 16-bit
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
 * uint16_t
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

uint8_t magic[] = {0x52, 0x42, 0x31, 0x2D, 0x31, 0x36, 0x00};

struct cipher_settings {
 unsigned r;
 unsigned wpb;
 uint16_t *n;
 uint16_t *ds;
};


/* functions section */

void help()
{
 char message[] = "Data Dependent Rotation Block Cipher 1\n"
 "16-bit\n\n"
 "options\n"
 "h: output help and exit\n"
 "d: decryption mode\n"
 "r: number of rounds to encrypt file data\n"
 "x: password and nonce input are interpreted as hexadecimal\n"
 "b: number of words per block; must be a power of two, at least 2\n";
 fputs(message, stderr);
 return;
}

void fail()
{
 perror(NULL);
 exit(EXIT_FAILURE);
}

void invalid(char c)
{
 fprintf(stderr, "argument supplied to -%c is invalid\n", c);
 exit(EXIT_FAILURE);
}

unsigned bin_log(unsigned x)
{
 unsigned y = 0;

 while(x >>= 1)
  y++;
 return y;
}

/* rotate left */
uint16_t rot_l(uint16_t x, uint16_t n)
{
 n &= 0xF;
 return (x << n) | (x >> (16 - n));
}

/* rotate right */
uint16_t rot_r(uint16_t x, uint16_t n)
{
 n &= 0xF;
 return (x >> n) | (x << (16 - n));
}

void encrypt(uint16_t *b, uint16_t *s, unsigned r, unsigned wpb)
{
 int i, end;
 unsigned m;

 m = wpb - 1;
 end = wpb * r;

 b[2 & m] += s[0];
 for(i = 1; i <= end; i++)
  b[i & m] = rot_l(b[i & m] ^ b[(i + 1) & m], b[(i + 1) & m]) + s[i];
 b[1] += s[i];

 return;
}

void decrypt(uint16_t *b, uint16_t *s, unsigned r, unsigned wpb)
{
 int i, end;
 unsigned m;

 m = wpb - 1;
 end = wpb * r;

 b[1] -= s[end + 1];
 for(i = end; i > 0; i--)
  b[i & m] = rot_r(b[i & m] - s[i], b[(i + 1) & m]) ^ b[(i + 1) & m];
 b[2 & m] -= s[0];

 return;
}

uint8_t *get_text(unsigned *length)
{
 int c;
 unsigned i, end = 255;
 uint8_t *data;

 if((data = malloc(256)) == NULL)
 {
  perror("get_text malloc");
  exit(EXIT_FAILURE);
 }

 for(i = 0; c = getchar(); i++)
 {
  if((c == '\n') || (c == EOF))
   break;
  if(i == end)
   if((data = realloc(data, end += 256)) == NULL)
   {
    perror("get_text realloc");
    exit(EXIT_FAILURE);
   }
  data[i] = c;
 }

 data[i] = '\0';
 *length = i;

 return data;
}

uint8_t *get_hex(unsigned *length)
{
 int c;
 unsigned i, end = 255, b;
 char input[3];
 uint8_t *data;

 input[2] = '\0';
 if((data = malloc(256)) == NULL)
 {
  perror("get_hex malloc");
  exit(EXIT_FAILURE);
 }

 for(i = 0; c = getchar(); i++)
 {
  if((c == '\n') || (c == EOF))
   break;
  if((i >> 1) == end)
   if((data = realloc(data, end += 256)) == NULL)
   {
    perror("get_hex realloc");
    exit(EXIT_FAILURE);
   }
  input[i & 1] = c;
  if(i & 1)
  {
   if(sscanf(input, "%x", &b) != 1)
   {
    fputs("not a valid hexadecimal number\n", stderr);
    exit(EXIT_FAILURE);
   }
   data[i >> 1] = b;
  }
 }

 if(i & 1)
 {
  input[1] = '0';
  if(sscanf(input, "%x", &b) != 1)
  {
   fputs("not a valid hexadecimal number\n", stderr);
   exit(EXIT_FAILURE);
  }
  data[i >> 1] = b;
 }

 *length = (i >> 1) + (i & 1);

 return data;
}

void write_oef(FILE *inf, FILE *outf, uint16_t *ds, uint16_t *ns, unsigned r, unsigned wpb)
{
 int c, i;
 unsigned opb;
 uint8_t rseed[] = {0x6E, 0x6F, 0x6E, 0x63, 0x65, 0x31}, *seed;
 uint16_t *n, *b, *st;

 opb = 2 * wpb;

 if((n = calloc(wpb, 2)) == NULL) fail();
 if((b = calloc(wpb, 2)) == NULL) fail();
 if((st = calloc(wpb, 2)) == NULL) fail();
 if((seed = calloc(opb, 1)) == NULL) fail();

 /* write magic */
 if(fwrite(magic, 1, 7, outf) != 7)
 {
  perror("write magic");
  exit(EXIT_FAILURE);
 }

 /* write file version number */
 for(i = 1; i >= 0; i--)
  if(putc(0xFF & (1 >> (i * 8)), outf) == EOF)
  {
   perror("write version");
   exit(EXIT_FAILURE);
  }

 /* write number of rounds */
 for(i = 1; i >= 0; i--)
  if(putc(0xFF & (r >> (i * 8)), outf) == EOF)
  {
   perror("write rounds");
   exit(EXIT_FAILURE);
  }

 /* write number of words per block */
 for(i = 1; i >= 0; i--)
  if(putc(0xFF & (wpb >> (i * 8)), outf) == EOF)
  {
   perror("write rounds");
   exit(EXIT_FAILURE);
  }

 /* prepare nonce */
 for(i = 0; i < 6; i++)
  seed[i % opb] += rseed[i];
 for(i = 0; i < opb; i++)
  n[i / 2] |= seed[i] << ((1 - (i & 1)) * 8);
 /* generate nonce */
 encrypt(n, ns, r, wpb);

 /* write nonce */
 for(i = 0; i < opb; i++)
  if(putc(0xFF & (n[i / 2] >> ((1 - (i & 1)) * 8)), outf) == EOF)
  {
   perror("write nonce");
   exit(EXIT_FAILURE);
  }

 /* generate password check */
 encrypt(b, ds, r, wpb);
 /* write password check */
 for(i = 1; i >= 0; i--)
  if(putc(0xFF & (b[0] >> (i * 8)), outf) == EOF)
  {
   perror("write password check");
   exit(EXIT_FAILURE);
  }

 while(true)
 {
  /* clear block */
  for(i = 0; i < wpb; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < opb; i++)
  {
   if((c = getc(inf)) == EOF)
    break;
   b[i / 2] |= c << ((1 - (i & 1)) * 8);
  }

  /* mark end */
  if(i < opb)
   b[i / 2] |= 0x80 << ((1 - (i & 1)) * 8);

  /* CTR encryption */
  for(i = 0; i < wpb; i++)
   st[i] = n[i];
  encrypt(st, ds, r, wpb);
  for(i = 0; i < wpb; i++)
   b[i] ^= st[i];
  /* ECB encryption */
  encrypt(b, ds, r, wpb);

  /* write block */
  for(i = 0; i < opb; i++)
   if(putc(0xFF & (b[i / 2] >> ((1 - (i & 1)) * 8)), outf) == EOF)
   {
    perror("write_oef write block");
    exit(EXIT_FAILURE);
   }

  if(c == EOF)
  {
   free(n);
   free(b);
   free(st);
   free(seed);
   return;
  }

  /* increment counter */
  for(i = wpb - 1; (!(++n[i])) && (i > 0); i--);
 }
}

void read_oeh(FILE *inf, struct cipher_settings *cs)
{
 int i, c;
 unsigned opb;

 /* verify magic */
 for(i = 0; (c = getc(inf)) && (i < 7); i++)
 {
  if(c == EOF)
   break;
  if(magic[i] != c)
  {
   fputs("incompatible file\n", stderr);
   exit(EXIT_FAILURE);
  }
 }

 /* read file version number */
 for(i = 1; i >= 0; i--)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  if((1 >> (i * 8)) != c)
  {
   fputs("incompatible version\n", stderr);
   exit(EXIT_FAILURE);
  }
 }

 cs->r = 0;
 /* read number of rounds */
 for(i = 1; i >= 0; i--)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  cs->r |= c << (i * 8);
 }

 cs->wpb = 0;
 /* read number of words per block */
 for(i = 1; i >= 0; i--)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  cs->wpb |= c << (i * 8);
 }

 opb = cs->wpb * 2;

 if((cs->n = calloc(cs->wpb, 2)) == NULL) fail();

 /* read nonce */
 for(i = 0; i < opb; i++)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  cs->n[i / 2] |= c << ((1 - (i & 1)) * 8);
 }
}

void read_oef(FILE *inf, FILE *outf, struct cipher_settings *cs)
{
 int i, c, end = 0;
 unsigned r, wpb, opb;
 uint16_t *n, *b, *st, *ds;

 r = cs->r;
 wpb = cs->wpb;
 opb = wpb * 2;
 n = cs->n;
 ds = cs->ds;

 if((b = calloc(wpb, 2)) == NULL) fail();
 if((st = calloc(wpb, 2)) == NULL) fail();

 /* generate password check */
 encrypt(b, ds, r, wpb);
 /* check password */
 for(i = 1; i >= 0; i--)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  if(c != (0xFF & (b[0] >> (i * 8))))
  {
   fputs("password does not match\n", stderr);
   exit(EXIT_FAILURE);
  }
 }

 if((c = getc(inf)) == EOF)
 {
  fputs("bad file\n", stderr);
  exit(EXIT_FAILURE);
 }
 while(true)
 {
  /* clear block */
  for(i = 0; i < wpb; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < opb; i++)
  {
   b[i / 2] |= c << ((1 - (i & 1)) * 8);
   if((c = getc(inf)) == EOF)
    break;
  }
  if(i < (opb - 1))
  {
   fputs("last block incomplete\n", stderr);
   exit(EXIT_FAILURE);
  }

  /* detect last block */
  if(i == (opb - 1))
   end = 1;

  /* ECB decryption */
  decrypt(b, ds, r, wpb);
  /* CTR decryption */
  for(i = 0; i < wpb; i++)
   st[i] = n[i];
  encrypt(st, ds, r, wpb);
  for(i = 0; i < wpb; i++)
   b[i] ^= st[i];

  /* write last block */
  if(end)
  {
   end = opb - 1;
   while((end > 0) && ((0xFF & (b[end / 2] >> ((1 - (end & 1)) * 8))) == 0))
    end--;

   for(i = 0; i < end; i++)
    if(putc(0xFF & (b[i / 2] >> ((1 - (i & 1)) * 8)), outf) == EOF)
    {
     perror("read_oef write block");
     exit(EXIT_FAILURE);
    }

   free(b);
   free(st);
   return;
  }

  /* write block */
  for(i = 0; i < opb; i++)
   putc(0xFF & (b[i / 2] >> ((1 - (i & 1)) * 8)), outf);

  /* increment counter */
  for(i = wpb - 1; (!(++n[i])) && (i > 0); i--);
 }
}

uint16_t *key_sched(uint8_t *kb, unsigned kbl, unsigned r, unsigned wpb)
{
 unsigned ind, kwl, sl, end;
 uint16_t *kw, *s, a, b, i, j;

 /* find key word length */
 kwl = (kbl / 2) + (kbl & 1) + (kbl == 0);
 if((kw = calloc(kwl, 2)) == NULL)
 {
  perror("key word calloc");
  exit(EXIT_FAILURE);
 }
 kw[0] = 0;
 /* convert key bytes to words */
 for(ind = 0; ind < kbl; ind++)
  kw[ind / 2] |= (kb[ind] << ((1 - (ind & 1)) * 8));

 /* schedule length */
 sl = (wpb * r) + 2;
 if((s = malloc(sl * 2)) == NULL)
 {
  perror("schedule malloc");
  exit(EXIT_FAILURE);
 }

 /* initialize schedule */
 s[0] = 0xAAAA;
 for(ind = 1; ind < sl; ind++)
  s[ind] = s[ind - 1] + 0x3977;

 a = b = i = j = 0;
 if(kwl > sl)
  end = 3 * kwl;
 else
  end = 3 * sl;
 for(ind = 1; ind <= end; ind++)
 {
  /* A = S[i] = (S[i] + A + B) <<< 3 */
  a = s[i] = rot_l(s[i] + a + b, 3);
  /* B = L[j] = (L[j] + A + B) <<< (A + B) */
  b = kw[j] = rot_l(kw[j] + a + b, a + b);
  /* i = (i + 1) mod (2r + 4) */
  i = (i + 1) % sl;
  /* j = (j + 1) mod c */
  j = (j + 1) % kwl;
 }

 free(kw);

 return s;
}

int main(int argc, char **argv)
{
 int mode = 1, c;
 unsigned i, r = 20, wpb = 4, pbl, nbl;
 uint8_t *pb, *nb;
 uint16_t *dsw, *nsw;
 bool hexin = false;
 extern char *optarg;
 extern int opterr, optind, optopt;
 struct cipher_settings cs;
 FILE *inf, *outf;

 while((c = getopt(argc, argv, "hdr:xb:")) != -1)
  switch(c)
  {
   case 'h': help(); exit(EXIT_SUCCESS);
   case 'd': mode = -1; break;
   case 'r': if(sscanf(optarg, "%u", &r) != 1) invalid(c); break;
   case 'x': hexin = true; break;
   case 'b': if(sscanf(optarg, "%u", &wpb) != 1) invalid(c); break;
   case '?': exit(EXIT_FAILURE);
  }

 if(wpb < 2)
 {
  fputs("\"b\" must be at least 2\n", stderr);
  exit(EXIT_FAILURE);
 }
 if((1 << bin_log(wpb)) != wpb)
 {
  fputs("\"b\" must be a power of two\n", stderr);
  exit(EXIT_FAILURE);
 }

 if(argv[optind] == NULL)
 {
  fputs("missing input filename\n", stderr);
  exit(EXIT_FAILURE);
 }
 if(argv[optind + 1] == NULL)
 {
  fputs("missing output filename\n", stderr);
  exit(EXIT_FAILURE);
 }

 if((inf = fopen(argv[optind], "rb")) == NULL)
 {
  perror(argv[optind]);
  exit(EXIT_FAILURE);
 }
 if((outf = fopen(argv[optind + 1], "wb")) == NULL)
 {
  perror(argv[optind + 1]);
  exit(EXIT_FAILURE);
 }

 fputs("password: ", stdout);
 if(hexin)
 {
  pb = get_hex(&pbl);
  fputs("using password: ", stdout);
  for(i = 0; i < pbl; i++)
   printf("%02X", pb[i]);
 }
 else
 {
  pb = get_text(&pbl);
  fputs("using password: ", stdout);
  for(i = 0; i < pbl; i++)
   putchar(pb[i]);
 }
 putchar('\n');

 if(mode == 1)
 {
  fputs("nonce: ", stdout);
  if(hexin)
  {
   nb = get_hex(&nbl);
   fputs("using nonce: ", stdout);
   for(i = 0; i < nbl; i++)
    printf("%02X", nb[i]);
  }
  else
  {
   nb = get_text(&nbl);
   fputs("using nonce: ", stdout);
   for(i = 0; i < nbl; i++)
    putchar(nb[i]);
  }
  putchar('\n');
  cs.r = r; cs.wpb = wpb;
  dsw = key_sched(pb, pbl, r, wpb);
  free(pb);
  nsw = key_sched(nb, nbl, r, wpb);
  free(nb);
  fputs("working...\n", stdout);
  write_oef(inf, outf, dsw, nsw, r, wpb);
  free(nsw);
 }
 else if(mode == -1)
 {
  read_oeh(inf, &cs);
  cs.ds = dsw = key_sched(pb, pbl, cs.r, cs.wpb);
  free(pb);
  fputs("working...\n", stdout);
  read_oef(inf, outf, &cs);
 }

 free(dsw);

 fclose(inf);
 fclose(outf);

 return EXIT_SUCCESS;
}
