//
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>

//
#include "types.h"

//
#include "yhash/yhash.h"

//
typedef struct dictionary_s {

  //List of passwords
  ascii **list;

  //Number of entries
  u64 n;

  //
  u64 max_n;

  //
  u64 size;
  
} dictionary_t;

//
typedef struct thread_task_s {

  //Pointer to the thread block of the dictionary
  ascii **list;

  //Number of passwords in the block
  u64 n;
  
  //Thread ID
  pthread_t tid;

  //The hash to crack
  u8 *target_hash;

  //The hash length
  u64 hash_len;
  
  //The hash function
  void (*hash_function)(const u8 *, const u64, u8 *);

  //
  u8 found;
  
  //The password (if found)
  ascii *password;

} thread_task_t;

//
ascii yhashcrack_logo[] =

  "        _    _           _      _____                _     \n"
  "       | |  | |         | |    / ____|              | |    \n"
  "  _   _| |__| | __ _ ___| |__ | |     _ __ __ _  ___| | __ \n"
  " | | | |  __  |/ _` / __| '_ \\| |    | '__/ _` |/ __| |/ / \n"
  " | |_| | |  | | (_| \\__ | | | | |____| | | (_| | (__|   <  \n"
  "  \\__, |_|  |_|\\__,_|___|_| |_|\\_____|_|  \\__,_|\\___|_|\\_\\ \n"
  "   __/ |                                                   \n"
  "  |___/                                                    \n";

//
dictionary_t *create_dictionary(u64 max_n, u64 max_len)
{
  dictionary_t *d = malloc(sizeof(dictionary_t));
  
  if (!d)
    return printf("Error: cannot allocate dictionary\n"), NULL;
  
  d->list = malloc(sizeof(ascii *) * max_n);
  
  if (!d->list)
    return printf("Error: cannot allocate dictionary list\n"), NULL;
  
  d->n     = 0;
  d->max_n = max_n;
  d->size  = 0;
  
  for (u64 i = 0; i < max_n; i++)
    {
      d->list[i] = malloc(sizeof(ascii) * max_len);

      if (!d->list[i])
	{
	  printf("Error: cannot allocate password entry '%llu' in dictionary\n", i);
	  exit(7);
	}
    }
  
  return d;
}

//
void destroy_dictionary(dictionary_t *d)
{
  if (d)
    {
      for (u64 i = 0; i < d->max_n; i++)
	free(d->list[i]);
      
      free(d->list);
      
      d->n     = 0;
      d->max_n = 0;
      d->size  = 0;
    }
  else
    printf("Error: dictionary pointer is NULL\n"), exit(5);
}

//
ascii load_dictionary(FILE *fp, dictionary_t *d)
{
  u64 i = 0;
  ascii done = 1;
  
  if (fp)
    {
      while (i < d->max_n && done != EOF)
	{
	  done = fscanf(fp, "%s\n", d->list[i]);

	  d->size += strlen(d->list[i]);
	  
	  i++;
	}
      
      d->n = i;
    }
  
  return (done == EOF) ? 0 : 1;
}

//Convert a string to a hash 
void cvt_str2hash(ascii *str, u8 *hash, u64 str_len)
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
void print_hash(const u8 *hash, u64 hash_len)
{
  for (u64 i = 0; i < hash_len; i++)
    printf("%02x", hash[i]);
  
  printf("\n");
}

//
u8 compare(const u8 *hash1, const u8 *hash2, u64 hash_len)
{
  u64 d = 0;

  for (u64 i = 0; i < hash_len; i++)
    d += (hash1[i] ^ hash2[i]);
  
  return (d) ? 0 : 1;
}

//Currently unused!
u8 lookup_hash_sequential(dictionary_t *d, u8 *target_hash, void (*hash_function)(const u8 *, const u64, u8 *), const u64 hash_len, ascii **password)
{
  u8 found = 0;
  u8 hash[hash_len];
  
  for (u64 i = 0; i < d->n; i++)
    {
      hash_function((u8 *)d->list[i], strlen(d->list[i]), hash);

      found = compare(target_hash, hash, hash_len);
      
      if (found)
	{
	  (*password) = d->list[i];
	  break;
	}
    }
  
  return found;
}

//
void *thread_task(void *arg)
{
  thread_task_t *tt = (thread_task_t *)arg;

  u8 found = 0;
  ascii **list = tt->list;
  u8 *target_hash = tt->target_hash;
  u64 hash_len = tt->hash_len;
  u8 hash[hash_len];
  
  void (*hash_function)(const u8 *, const u64, u8 *) = tt->hash_function;
  
  for (u64 i = 0; i < tt->n; i++)
    {
      hash_function((u8 *)list[i], strlen(list[i]), hash);
      
      found = compare(target_hash, hash, hash_len);
      
      if (found)
	{
	  tt->found = 1;
	  tt->password = list[i];
	  break;
	}
    }

  if (!found)
    tt->password = NULL;

  return NULL;
}

//
u8 lookup_hash_parallel(u64 nt, dictionary_t *d, u8 *target_hash, void (*hash_function)(const u8 *, const u64, u8 *), const u64 hash_len, ascii **password)
{
  u8 found = 0;
  u64 thread_n = d->n / nt;
  u64 thread_m = d->n % nt;
  thread_task_t *tt = malloc(sizeof(thread_task_t) * nt);
  
  if (!tt)
    {
      printf("Error: cannot allocate memory for threads\n");
      exit(6);
    }

  for (u64 i = 0; i < nt; i++)
    {
      tt[i].n = (thread_n + ((i == nt - 1) ? thread_m : 0));
      tt[i].list = &d->list[i * thread_n];
      tt[i].hash_function = hash_function;
      tt[i].target_hash = target_hash;
      tt[i].hash_len = hash_len;
      tt[i].found = 0;
      tt[i].password = NULL;

      pthread_create(&tt[i].tid, NULL, thread_task, &tt[i]);
    }

  for (u64 i = 0; i < nt; i++)
    {
      pthread_join(tt[i].tid, NULL);
      
      if (tt[i].found)
	{
	  (*password) = tt[i].password;
	  found = 1;
	}
    }

  free(tt);
  
  return found;
}

//
int main(int argc, char **argv)
{
  //Print logo
  printf("%s\n", yhashcrack_logo);

  //Handle command line parameters
  if (argc < 4)
    return printf("Usage: %s [hashing algorithm] [number of threads] [dictionary path] [hash]\n", argv[0]), 1;

  //Set hash length and hash function pointer
  u64 hash_len = 0;
  void (*hash_function)(const u8 *, const u64, u8 *) = NULL;;
  
  if (!strcmp(argv[1], "md5"))
    {
      hash_len = MD5_HASH_SIZE;
      hash_function = md5hash;
    }
  else
    if (!strcmp(argv[1], "sha1"))
      {
	hash_len = SHA1_HASH_SIZE;
	hash_function = sha1hash;
      }
    else
      if (!strcmp(argv[1], "sha224"))
	{
	  hash_len = SHA224_HASH_SIZE;
	  hash_function = sha224hash;
	}
      else
	if (!strcmp(argv[1], "sha256"))
	  {
	    hash_len = SHA256_HASH_SIZE;
	    hash_function = sha256hash;
	  }
	else
	  if (!strcmp(argv[1], "sha512"))
	    {
	      hash_len = SHA512_HASH_SIZE;
	      hash_function = sha512hash;
	    }
	  else
	    {
	      printf("Error: unknown hashing algorithm '%s'\n", argv[1]);
	      exit(8);
	    }
  
  //Get number of threads
  u64 nt = atoll(argv[2]);
  
  if (nt < 1)
    return printf("Error: invalid number of threads '%llu'\n", nt), 4;

  //Printing info
  printf("Number of threads   : %llu\n"
	 "Hashing algorithm   : %s\n"
	 "Dictionary file     : %s\n"
	 "Target hash         : %s\n", nt, argv[1], argv[3], argv[4]);

  //Get file size
  u64 size = 0;
  struct stat sb;
  u64 dictionary_size = 0;
  
  if (stat(argv[3], &sb) < 0)
    return printf("Error: cannot open file '%s'\n", argv[3]), 3;
  
  dictionary_size = sb.st_size;

  //Open dictionary file
  FILE *fp = fopen(argv[3], "rb");
  
  if (!fp)
    return printf("Error: cannot open file '%s'\n", argv[3]), 3;

  u8 found = 0;
  u64 rounds = 1;
  ascii *password = NULL;
  u8 target_hash[hash_len];
  struct timespec lu_after, lu_before;
  struct timespec all_after, all_before;
  
  //Convert parameter hash (string) into number form
  cvt_str2hash(argv[4], target_hash, strlen(argv[4]));
  
  dictionary_t *d = create_dictionary(100000000, 32);
  
  if (!d)
    return printf("Error: cannot create dictionary\n"), 4;
  
  printf("Dictionary file size: %llu MiB; %llu GiB\n\n", dictionary_size >> 20, dictionary_size >> 30);

  clock_gettime(CLOCK_MONOTONIC_RAW, &all_before);
  
  while (load_dictionary(fp, d) != EOF)
    {
      clock_gettime(CLOCK_MONOTONIC_RAW, &lu_before);
      
      found = lookup_hash_parallel(nt, d, target_hash, hash_function, hash_len, &password);
      
      clock_gettime(CLOCK_MONOTONIC_RAW, &lu_after);
      
      f64 lu_elapsed = (f64)(lu_after.tv_sec - lu_before.tv_sec);

      size += d->size;
      
      printf("[%llu] Tested %llu passwords  (%llu MiB) in %.2lf seconds\n", rounds, d->n * rounds, d->size >> 20, lu_elapsed);

      d->size = 0;
      
      if (found)
	break;
      
      rounds++;
    }

  clock_gettime(CLOCK_MONOTONIC_RAW, &all_after);
  
  if (found)
    printf("\n### Cracked!! Found password: '%s'\n\n", password);
  else
    printf("\n### Sorry! No password matched the given hash\n\n");

  f64 all_elapsed = (f64)(all_after.tv_sec - all_before.tv_sec);

  printf("Total cracking run time: %.3lf seconds, number of rounds: %llu, searched memory: ", all_elapsed, rounds);

  if ((size >> 20) > 1024)
    printf("%llu GiB\n", size >> 30);
  else
    printf("%llu MiB\n", size >> 20);
  
  destroy_dictionary(d);
  free(d);

  fclose(fp);
  
  return 0;
}
