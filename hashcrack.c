/*

  Brute force hash cracker using a dictionary.
  
  Yaspr - 2019

  To be optimized (Reorganize, Vectorize, ...)

  TODO:
  
         Bufferize IO for VERY large dictionaries
	 
*/
#include <math.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

//MD5, SHA1, SHA224, SHA256, SHA512 implementations
#include "yhash/hash.h"

//Hash algorithm constants definitions. i.e. MD5_H_SIZE, SHA1_H_SIZE, ...
#include "yhash/common.h"

//
#define MAX_LEN    32
#define MAX_WORDS  70000000

//
#define MD5_MODE      0
#define SHA1_MODE     1
#define SHA224_MODE   2
#define SHA256_MODE   3
#define SHA512_MODE   4

//
#define DIFF(a, b) ((a) > (b)) ? ((a) - (b)) : ((b) - (a))

//
typedef char          i8;
typedef unsigned char u8;

typedef short          i16;
typedef unsigned short u16;

typedef int           i32;
typedef unsigned      u32;

typedef long long          i64;
typedef unsigned long long u64;

//Dictionary (Words, Number of Words)
typedef struct dict_s { u8 **wl; u64 nb_w; } dict_t;

//Thread task: Thread ID, words list, number of words, word pointer, hash length
typedef struct thread_task_s {

  pthread_t tid;
  u8 **wl;
  u64 nb_w;
  u8 *w;
  u64 hash_len;
  u8 *in_hash;
  void (*hf)(const u8 *, const u64, u8 *);

} thread_task_t;

//
u8 logo[] =
  "             __            \n" 
  "|_| _  _ |_ /   __ _  _ |  \n" 
  "| |(_|_> | |\\__ | (_|(_ |<\n";

//Timing before and after
struct timespec ts_a, ts_b;

//Allocate memory for a dictionary 
dict_t *alloc_dict(u64 max_w, u64 max_l)
{
  dict_t *d = malloc(sizeof(dict_t));

  //Allocate memory for the words list
  d->wl = malloc(sizeof(u8 *) * max_w);

  for (u64 i = 0; i < max_w; i++)
    d->wl[i] = malloc(max_l + 1);
  
  return d;
}

//Load a given dictionary from disk to memory (serial I/O)
dict_t *load_dict_file(u8 *d_fname)
{
  FILE *fp = fopen(d_fname, "rb");
  
  //
  if (fp)
    {
      u64 i = 0;
      dict_t *d = alloc_dict(MAX_WORDS, MAX_LEN);
      
      while (i < MAX_WORDS && fscanf(fp, "%s\n", d->wl[i]) != EOF)
	i++;

      d->nb_w = i;
      
      fclose(fp);

      return d;
    }
  else
    return NULL;
}

//Sequencial
u8 *hashcrack_s(u8 *d_fname, u8 *in_hash, void hf(const u8 *, const u64, u8 *), u64 hash_len)
{
  u64 pos;
  u8 found = 0;
  u8 *w = NULL;
  
  //Temporary hash
  u8 *hash = malloc(hash_len);

  //Load a dictionary
  dict_t *d = load_dict_file(d_fname);
  
  //Get clock before
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts_b);
  
  //Crack
  for (pos = 0; !found && pos < d->nb_w; pos++)
    {
      //Generate a hash for the current dictionary word 
      hf(d->wl[pos], strlen(d->wl[pos]), hash);

      //Compare current hash to target hash 
      found = !strncmp(hash, in_hash, hash_len);
    }

  //Get clock after
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts_a);
  
  //
  free(hash);
  
  //Return word if found
  if (found)
    w = d->wl[pos - 1];
  
  return w;
}

//Thread main function  
void *_hc_(void *arg)
{
  u64 pos;
  u8 found = 0;
  thread_task_t *p = (thread_task_t *)arg;

  //Temporary hash
  u8 *hash = malloc(p->hash_len);
  
  //
  for (pos = 0; !found && pos < p->nb_w; pos++)
    {
      //Generate a hash for the current dictionary word 
      p->hf(p->wl[pos], strlen(p->wl[pos]), hash);
      
      //Compare current hash to target hash 
      found = !strncmp(hash, p->in_hash, p->hash_len);
    }

  free(hash);

  if (found)
    p->w = p->wl[pos - 1];
  else
    p->w = NULL;
}

//Parallel
u8 *hashcrack_p(u8 *d_fname, u8 *in_hash, void hf(const u8 *, const u64, u8 *), u64 hash_len, u64 nt)
{
  u8 *w = NULL;
  
  //Load a dictionary
  dict_t *d = load_dict_file(d_fname);

  //
  u64 nb_w_div_nt = (d->nb_w / nt);
  u64 nb_w_mod_nt = (d->nb_w % nt);
  thread_task_t *tt = malloc(sizeof(thread_task_t) * nt);
  
  //Get clock before
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts_b);
  
  //
  for (u64 i = 0; i < nt; i++)
    {
      tt[i].wl = &d->wl[i * nb_w_div_nt];
      tt[i].nb_w = nb_w_div_nt + ((i == (nt - 1)) ? nb_w_mod_nt : 0);
      tt[i].w = NULL;
      tt[i].hash_len = hash_len;
      tt[i].hf = hf;
      tt[i].in_hash = in_hash;
      
      pthread_create(&tt[i].tid, NULL, _hc_, &tt[i]);
    }

  for (u64 i = 0; i < nt; i++)
    {
      pthread_join(tt[i].tid, NULL);

      if (tt[i].w)
	w = tt[i].w;
    }
  
  //Get clock after
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts_a);
  
  return w;
}

//Convert a string to a hash (could do better!) 
void cvt_str2hash(u8 *str, u8 *hash, u64 str_len)
{
  u8 b;
  static u8 cvt_tab[6] = { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
  
  for (u64 i = 0, j = 0; i < str_len; i += 2, j++)
    {
      b = 0x00;

      //High 4 bits
      if (str[i] >= '0' && str[i] <= '9')
	b = (str[i] - '0') << 4;
      else
	if (str[i] >= 'A' && str[i] <= 'F')
	  b = cvt_tab[str[i] - 'A'] << 4;
	else
	  if (str[i] >= 'a' && str[i] <= 'f')
	    b = cvt_tab[str[i] - 'a'] << 4;

      //Low 4 bits
      if (str[i + 1] >= '0' && str[i + 1] <= '9')
	b |= (str[i + 1] - '0') & 0x0F;
      else
	if (str[i + 1] >= 'A' && str[i + 1] <= 'F')
	  b |= cvt_tab[str[i + 1] - 'A'] & 0x0F;
	else
	  if (str[i + 1] >= 'a' && str[i + 1] <= 'f')
	    b |= cvt_tab[str[i + 1] - 'a'] & 0x0F;

      //Store byte
      hash[j] = b;
    }
}

//
void print_hash(u8 *hash, u64 hash_len)
{
  
  for (u64 i = 0; i < hash_len; i++)
    printf("%02x", hash[i]);
  
  printf("\n");
}
//
int main(int argc, char **argv)
{
  //
  puts(logo);

  //
  if (argc < 5)
    return printf("Usage: %s [-algorithm] [dictionary file path] [hash to crack] [number of threads]\n"
		  "\n\tHashing algorithms: md5, sha1, sha224, sha256, sha512\n\n", argv[0]), 2;
  
  //
  u64 nt = atoll(argv[4]);
  
  //
  u8 *in_hash;
  u8 *out_word;
  u64 hash_len;
  void (*hf)(const u8 *, const u64, u8 *);
  
  //
  if (!strncmp(argv[1], "-md5", 4))
    {
      hash_len = MD5_H_SIZE;
      hf = md5hash;
    }
  else
    if (!strncmp(argv[1], "-sha1", 5))
      {
	hash_len = SHA1_H_SIZE;
	hf = sha1hash;
      }
    else
      if (!strncmp(argv[1], "-sha224", 7))
	{
	  hash_len = SHA224_H_SIZE;
	  hf = sha224hash;
	}
      else
	if (!strncmp(argv[1], "-sha256", 7))
	  {
	    hash_len = SHA256_H_SIZE;
	    hf = sha256hash;
	  }
  	else
	  if (!strncmp(argv[1], "-sha512", 7))
	    {
	      hash_len = SHA512_H_SIZE;
	      hf = sha512hash;
	    }
	  else
	    return printf("Error: wrong algorithm. Possible values: -md5, -sha1, -sha224n -sha256, -sha512\n"), 3;
  
  //
  in_hash = malloc(hash_len);
  
  //Convert in_hash from string to hash XX XX XX ...
  cvt_str2hash(argv[3], in_hash, (hash_len << 1));
  
  printf("Target hash: "); print_hash(in_hash, hash_len);

  //
  if (nt == 1)
    {
      //Sequential
      out_word = hashcrack_s(argv[2], in_hash, hf, hash_len);
    }
  else
    {
      //Parallel
      out_word = hashcrack_p(argv[2], in_hash, hf, hash_len, nt);
    }

  //
  if (out_word)
    {
      //Set green color
      printf("\033[0;32m");

      printf("\n!! CRACKED !! ");

      //Reset color
      printf("\033[0m");
      printf("String found: %s\n", out_word);
    }
  else
    {
      //Red color
      printf("\033[0;31m");

      printf("\n!! FAILED !! ");

      //Reset color
      printf("\033[0m");
      printf("No string found. Try a different dictionary\n");
    }

  //
  printf("\nLookup time: %llu  s\n", (u64)DIFF(ts_a.tv_sec, ts_b.tv_sec));
  
  //
  free(in_hash);
  
  return 0;
}
