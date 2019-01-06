/* Data Dependent Rotation Block Cipher 1
 * 2-word, 8-bit
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

uint8_t magic[] = {0x52, 0x42, 0x31, 0x2D, 0x32, 0x2D, 0x38, 0x00};


/* functions section */

void help()
{
 char message[] = "Data Dependent Rotation Block Cipher 1\n"
 "2-word, 8-bit\n\n"
 "options\n"
 "h: output help and exit\n"
 "d: decryption mode\n"
 "r: number of rounds to encrypt file data\n"
 "x: password and nonce input are interpreted as hexadecimal\n";
 fputs(message, stderr);
 return;
}

void invalid(char c)
{
 fprintf(stderr, "argument supplied to -%c is invalid\n", c);
 exit(EXIT_FAILURE);
}

/* rotate left */
uint8_t rot_l(uint8_t x, uint8_t n)
{
 n &= 7;
 return (x << n) | (x >> (8 - n));
}

/* rotate right */
uint8_t rot_r(uint8_t x, uint8_t n)
{
 n &= 7;
 return (x >> n) | (x << (8 - n));
}

void encrypt(uint8_t *b, uint8_t *s, unsigned r)
{
 int i, end;

 end = 2 * r;

 b[0] += s[0];
 for(i = 1; i <= end; i++)
  b[i & 1] = rot_l(b[i & 1] ^ b[(i + 1) & 1], b[(i + 1) & 1]) + s[i];
 b[1] += s[i];

 return;
}

void decrypt(uint8_t *b, uint8_t *s, unsigned r)
{
 int i, end;

 end = 2 * r;

 b[1] -= s[end + 1];
 for(i = end; i > 0; i--)
  b[i & 1] = rot_r(b[i & 1] - s[i], b[(i + 1) & 1]) ^ b[(i + 1) & 1];
 b[0] -= s[0];

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

void write_oef(FILE *inf, FILE *outf, uint8_t *ds, uint8_t *ns, unsigned r)
{
 int c, i;
 uint8_t seed[] = {0x41, 0x03};
 uint8_t n[2], b[2], st[2];

 /* write magic */
 if(fwrite(magic, 1, 8, outf) != 8)
 {
  perror("write magic");
  exit(EXIT_FAILURE);
 }

 /* write file version number */
 if(putc(1, outf) == EOF)
 {
  perror("write version");
  exit(EXIT_FAILURE);
 }

 /* write number of rounds */
 if(putc(0xFF & r, outf) == EOF)
 {
  perror("write rounds");
  exit(EXIT_FAILURE);
 }

 /* clear nonce */
 for(i = 0; i < 2; i++)
  n[i] = 0;
 /* prepare nonce */
 for(i = 0; i < 2; i++)
  n[i] = seed[i];
 /* generate nonce */
 encrypt(n, ns, r);

 /* write nonce */
 for(i = 0; i < 2; i++)
  if(putc(n[i], outf) == EOF)
  {
   perror("write nonce");
   exit(EXIT_FAILURE);
  }

 for(i = 0; i < 2; i++)
  b[i] = 0;
 /* generate password check */
 encrypt(b, ds, r);
 /* write password check */
 if(putc(b[0], outf) == EOF)
 {
  perror("write password check");
  exit(EXIT_FAILURE);
 }

 while(true)
 {
  /* clear block */
  for(i = 0; i < 2; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < 2; i++)
  {
   if((c = getc(inf)) == EOF)
    break;
   b[i] = c;
  }

  /* mark end */
  if(i < 2)
   b[i] = 0x80;

  /* CTR encryption */
  for(i = 0; i < 2; i++)
   st[i] = n[i];
  encrypt(st, ds, r);
  for(i = 0; i < 2; i++)
   b[i] ^= st[i];
  /* ECB encryption */
  encrypt(b, ds, r);

  /* write block */
  for(i = 0; i < 2; i++)
   if(putc(b[i], outf) == EOF)
   {
    perror("write_oef write block");
    exit(EXIT_FAILURE);
   }

  if(c == EOF)
   return;

  /* increment counter */
  if(!(++n[1]))
   ++n[0];
 }
}

void read_oef(FILE *inf, FILE *outf, uint8_t *ds)
{
 int i, c, end = 0;
 unsigned r = 0;
 uint8_t n[2], b[2], st[2];

 /* verify magic */
 for(i = 0; (c = getc(inf)) && (i < 8); i++)
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
 if((c = getc(inf)) == EOF)
 {
  fputs("bad file\n", stderr);
  exit(EXIT_FAILURE);
 }
 if(1 != c)
 {
  fputs("incompatible version\n", stderr);
  exit(EXIT_FAILURE);
 }

 /* read number of rounds */
 if((c = getc(inf)) == EOF)
 {
  fputs("bad file\n", stderr);
  exit(EXIT_FAILURE);
 }
 r = c;

 for(i = 0; i < 2; i++)
  n[i] = 0;
 /* read nonce */
 for(i = 0; i < 2; i++)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  n[i] = c;
 }

 for(i = 0; i < 2; i++)
  b[i] = 0;
 /* generate password check */
 encrypt(b, ds, r);
 /* check password */
 if((c = getc(inf)) == EOF)
 {
  fputs("bad file\n", stderr);
  exit(EXIT_FAILURE);
 }
 if(c != b[0])
 {
  fputs("password does not match\n", stderr);
  exit(EXIT_FAILURE);
 }

 if((c = getc(inf)) == EOF)
 {
  fputs("bad file\n", stderr);
  exit(EXIT_FAILURE);
 }
 while(true)
 {
  /* clear block */
  for(i = 0; i < 2; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < 2; i++)
  {
   b[i] = c;
   if((c = getc(inf)) == EOF)
    break;
  }
  if(i < 1)
  {
   fputs("last block incomplete\n", stderr);
   exit(EXIT_FAILURE);
  }

  /* detect last block */
  if(i == 1)
   end = 1;

  /* ECB decryption */
  decrypt(b, ds, r);
  /* CTR decryption */
  for(i = 0; i < 2; i++)
   st[i] = n[i];
  encrypt(st, ds, r);
  for(i = 0; i < 2; i++)
   b[i] ^= st[i];

  /* write last block */
  if(end)
  {
   end = 1;
   while((end > 0) && (b[end] == 0))
    end--;

   for(i = 0; i < end; i++)
    if(putc(b[i], outf) == EOF)
    {
     perror("read_oef write block");
     exit(EXIT_FAILURE);
    }

   return;
  }

  /* write block */
  for(i = 0; i < 2; i++)
   putc(b[i], outf);

  /* increment counter */
  if(!(++n[1]))
   ++n[0];
 }
}

uint8_t *key_sched(uint8_t *kb, unsigned kbl, unsigned r)
{
 unsigned ind, kwl, sl, end;
 uint8_t *kw, *s, a, b, i, j;

 /* find key word length */
 kwl = kbl + (kbl == 0);
 if((kw = calloc(kwl, 1)) == NULL)
 {
  perror("key word calloc");
  exit(EXIT_FAILURE);
 }
 kw[0] = 0;
 /* convert key bytes to words */
 for(ind = 0; ind < kbl; ind++)
  kw[ind] = kb[ind];

 /* schedule length */
 sl = (2 * r) + 2;
 if((s = malloc(sl)) == NULL)
 {
  perror("schedule malloc");
  exit(EXIT_FAILURE);
 }

 /* initialize schedule */
 s[0] = 0xBE;
 for(ind = 1; ind < sl; ind++)
  s[ind] = s[ind - 1] + 0xB3;

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
 unsigned i, r = 20, pbl, nbl;
 uint8_t *pb, *nb;
 uint8_t *dsw, *nsw;
 bool hexin = false;
 extern char *optarg;
 extern int opterr, optind, optopt;
 FILE *inf, *outf;

 while((c = getopt(argc, argv, "hdr:x")) != -1)
  switch(c)
  {
   case 'h': help(); exit(EXIT_SUCCESS);
   case 'd': mode = -1; break;
   case 'r': if(sscanf(optarg, "%u", &r) != 1) invalid(c); break;
   case 'x': hexin = true; break;
   case '?': exit(EXIT_FAILURE);
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
 dsw = key_sched(pb, pbl, r);
 free(pb);

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
  nsw = key_sched(nb, nbl, r);
  free(nb);
  fputs("working...\n", stdout);
  write_oef(inf, outf, dsw, nsw, r);
  free(nsw);
 }
 else if(mode == -1)
 {
  fputs("working...\n", stdout);
  read_oef(inf, outf, dsw);
 }

 free(dsw);

 fclose(inf);
 fclose(outf);

 return EXIT_SUCCESS;
}
