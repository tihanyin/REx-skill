/*
 *  REx@Skill  ·  argvfuzz.c
 *
 *  Fuzzing a program that parses argv is otherwise impossible with a stock
 *  AFL++: `-- prog @@` fuzzes a FILENAME, and stdin mode feeds a channel the
 *  program never reads. Both return a confident zero-crash result.
 *
 *  AFL++ solves this with utils/argv_fuzzing/argvfuzz.so -- which most
 *  distributions, nixpkgs included, do not build or ship. fuzz_target.sh
 *  compiles this file on demand when it cannot find one:
 *
 *      cc -shared -fPIC -nostdlib -o argvfuzz.so argvfuzz.c
 *      AFL_PRELOAD=./argvfuzz.so afl-fuzz -Q -i seeds -o out -- ./target
 *
 *  It interposes __libc_start_main, reads the fuzzer's input from stdin and
 *  hands it to the program as argv. NUL separates arguments, so a seed with no
 *  NUL in it becomes a single argv[1] -- which is what the probe battery emits.
 *  argv[0] is preserved: programs branch on it, and rewriting it changes the
 *  behaviour under test.
 *
 *  Author :  Norbert Tihanyi   ·   x.com/@TihanyiNorbert
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>

#define MAX_LEN 100000
#define MAX_ARG 1024

static char *fuzz_argv[MAX_ARG];
static char  fuzz_buf[MAX_LEN + 2];

typedef int (*main_fn)(int, char **, char **);
static main_fn real_main;

static int fuzz_main(int argc, char **argv, char **envp) {
  ssize_t n = read(0, fuzz_buf, MAX_LEN);
  if (n < 0) n = 0;
  fuzz_buf[n] = 0;
  fuzz_buf[n + 1] = 0;

  int c = 0;
  fuzz_argv[c++] = argc > 0 ? argv[0] : (char *)"";

  char *p = fuzz_buf;
  while (p < fuzz_buf + n && c < MAX_ARG - 1) {
    fuzz_argv[c++] = p;
    p += strlen(p) + 1;
  }
  fuzz_argv[c] = NULL;
  return real_main(c, fuzz_argv, envp);
}

int __libc_start_main(main_fn m, int argc, char **argv, void (*init)(void),
                      void (*fini)(void), void (*rtld_fini)(void),
                      void *stack_end) {
  real_main = m;
  int (*orig)(main_fn, int, char **, void (*)(void), void (*)(void),
              void (*)(void), void *) =
      dlsym(RTLD_NEXT, "__libc_start_main");
  return orig(fuzz_main, argc, argv, init, fini, rtld_fini, stack_end);
}
