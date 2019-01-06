/* Data Dependent Rotation Block Cipher 1
 * 8-word, 32-bit
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
 * uint32_t
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

uint8_t magic[] = {0x52, 0x42, 0x31, 0x2D, 0x38, 0x2D, 0x33, 0x32, 0x00};


/* functions section */

void help()
{
 char message[] = "Data Dependent Rotation Block Cipher 1\n"
 "8-word, 32-bit\n\n"
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
uint32_t rot_l(uint32_t x, uint32_t n)
{
 n &= 0x1F;
 return (x << n) | (x >> (32 - n));
}

/* rotate right */
uint32_t rot_r(uint32_t x, uint32_t n)
{
 n &= 0x1F;
 return (x >> n) | (x << (32 - n));
}

void encrypt(uint32_t *b, uint32_t *s, unsigned r)
{
 int i, end;

 end = 8 * r;

 b[2] += s[0];
 for(i = 1; i <= end; i++)
  b[i & 7] = rot_l(b[i & 7] ^ b[(i + 1) & 7], b[(i + 1) & 7]) + s[i];
 b[1] += s[i];

 return;
}

void decrypt(uint32_t *b, uint32_t *s, unsigned r)
{
 int i, end;

 end = 8 * r;

 b[1] -= s[end + 1];
 for(i = end; i > 0; i--)
  b[i & 7] = rot_r(b[i & 7] - s[i], b[(i + 1) & 7]) ^ b[(i + 1) & 7];
 b[2] -= s[0];

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

void write_oef(FILE *inf, FILE *outf, uint32_t *ds, uint32_t *ns, unsigned r)
{
 int c, i;
 uint8_t seed[] = {0x6E, 0x6F, 0x6E, 0x63, 0x65, 0x31};
 uint32_t n[8], b[8], st[8];

 /* write magic */
 if(fwrite(magic, 1, 9, outf) != 9)
 {
  perror("write magic");
  exit(EXIT_FAILURE);
 }

 /* write file version number */
 for(i = 3; i >= 0; i--)
  if(putc(0xFF & ((unsigned)1 >> (i * 8)), outf) == EOF)
  {
   perror("write version");
   exit(EXIT_FAILURE);
  }

 /* write number of rounds */
 for(i = 3; i >= 0; i--)
  if(putc(0xFF & (r >> (i * 8)), outf) == EOF)
  {
   perror("write rounds");
   exit(EXIT_FAILURE);
  }

 /* clear nonce */
 for(i = 0; i < 8; i++)
  n[i] = 0;
 /* prepare nonce */
 for(i = 0; i < 6; i++)
  n[i / 4] |= (uint32_t)seed[i] << ((3 - (i & 3)) * 8);
 /* generate nonce */
 encrypt(n, ns, r);

 /* write nonce */
 for(i = 0; i < 32; i++)
  if(putc(0xFF & (n[i / 4] >> ((3 - (i & 3)) * 8)), outf) == EOF)
  {
   perror("write nonce");
   exit(EXIT_FAILURE);
  }

 for(i = 0; i < 8; i++)
  b[i] = 0;
 /* generate password check */
 encrypt(b, ds, r);
 /* write password check */
 for(i = 3; i >= 0; i--)
  if(putc(0xFF & (b[0] >> (i * 8)), outf) == EOF)
  {
   perror("write password check");
   exit(EXIT_FAILURE);
  }

 while(true)
 {
  /* clear block */
  for(i = 0; i < 8; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < 32; i++)
  {
   if((c = getc(inf)) == EOF)
    break;
   b[i / 4] |= c << ((3 - (i & 3)) * 8);
  }

  /* mark end */
  if(i < 32)
   b[i / 4] |= 0x80 << ((3 - (i & 3)) * 8);

  /* CTR encryption */
  for(i = 0; i < 8; i++)
   st[i] = n[i];
  encrypt(st, ds, r);
  for(i = 0; i < 8; i++)
   b[i] ^= st[i];
  /* ECB encryption */
  encrypt(b, ds, r);

  /* write block */
  for(i = 0; i < 32; i++)
   if(putc(0xFF & (b[i / 4] >> ((3 - (i & 3)) * 8)), outf) == EOF)
   {
    perror("write_oef write block");
    exit(EXIT_FAILURE);
   }

  if(c == EOF)
   return;

  /* increment counter */
  if(!(++n[7]))
   if(!(++n[6]))
    if(!(++n[5]))
     if(!(++n[4]))
      if(!(++n[3]))
       if(!(++n[2]))
        if(!(++n[1]))
         ++n[0];
 }
}

void read_oef(FILE *inf, FILE *outf, uint32_t *ds)
{
 int i, c, end = 0;
 unsigned r = 0;
 uint32_t n[8], b[8], st[8];

 /* verify magic */
 for(i = 0; (c = getc(inf)) && (i < 9); i++)
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
 for(i = 3; i >= 0; i--)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  if(((unsigned)1 >> (i * 8)) != c)
  {
   fputs("incompatible version\n", stderr);
   exit(EXIT_FAILURE);
  }
 }

 /* read number of rounds */
 for(i = 3; i >= 0; i--)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  r |= c << (i * 8);
 }

 for(i = 0; i < 8; i++)
  n[i] = 0;
 /* read nonce */
 for(i = 0; i < 32; i++)
 {
  if((c = getc(inf)) == EOF)
  {
   fputs("bad file\n", stderr);
   exit(EXIT_FAILURE);
  }
  n[i / 4] |= c << ((3 - (i & 3)) * 8);
 }

 for(i = 0; i < 8; i++)
  b[i] = 0;
 /* generate password check */
 encrypt(b, ds, r);
 /* check password */
 for(i = 3; i >= 0; i--)
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
  for(i = 0; i < 8; i++)
   b[i] = 0;
  /* read block */
  for(i = 0; i < 32; i++)
  {
   b[i / 4] |= c << ((3 - (i & 3)) * 8);
   if((c = getc(inf)) == EOF)
    break;
  }
  if(i < 31)
  {
   fputs("last block incomplete\n", stderr);
   exit(EXIT_FAILURE);
  }

  /* detect last block */
  if(i == 31)
   end = 1;

  /* ECB decryption */
  decrypt(b, ds, r);
  /* CTR decryption */
  for(i = 0; i < 8; i++)
   st[i] = n[i];
  encrypt(st, ds, r);
  for(i = 0; i < 8; i++)
   b[i] ^= st[i];

  /* write last block */
  if(end)
  {
   end = 31;
   while((end > 0) && ((0xFF & (b[end / 4] >> ((3 - (end & 3)) * 8))) == 0))
    end--;

   for(i = 0; i < end; i++)
    if(putc(0xFF & (b[i / 4] >> ((3 - (i & 3)) * 8)), outf) == EOF)
    {
     perror("read_oef write block");
     exit(EXIT_FAILURE);
    }

   return;
  }

  /* write block */
  for(i = 0; i < 32; i++)
   putc(0xFF & (b[i / 4] >> ((3 - (i & 3)) * 8)), outf);

  /* increment counter */
  if(!(++n[7]))
   if(!(++n[6]))
    if(!(++n[5]))
     if(!(++n[4]))
      if(!(++n[3]))
       if(!(++n[2]))
        if(!(++n[1]))
         ++n[0];
 }
}

uint32_t *key_sched(uint8_t *kb, unsigned kbl, unsigned r)
{
 unsigned ind, kwl, sl, end;
 uint32_t *kw, *s, a, b, i, j;

 /* find key word length */
 kwl = (kbl / 4) + ((kbl & 3) != 0) + (kbl == 0);
 if((kw = calloc(kwl, 4)) == NULL)
 {
  perror("key word calloc");
  exit(EXIT_FAILURE);
 }
 kw[0] = 0;
 /* convert key bytes to words */
 for(ind = 0; ind < kbl; ind++)
  kw[ind / 4] |= (((uint32_t)kb[ind]) << ((3 - (ind & 3)) * 8));

 /* schedule length */
 sl = (8 * r) + 2;
 if((s = malloc(sl * 4)) == NULL)
 {
  perror("schedule malloc");
  exit(EXIT_FAILURE);
 }

 /* initialize schedule */
 s[0] = 0xBFD1A2A8;
 for(ind = 1; ind < sl; ind++)
  s[ind] = s[ind - 1] + 0xA87A036D;

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
 uint32_t *dsw, *nsw;
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
