
#include <execinfo.h>
#include <signal.h>
#define PACKAGE 1
#define PACKAGE_VERSION 1
#include <bfd.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// code from http://en.wikibooks.org/wiki/Linux_Applications_Debugging_Techniques/The_call_stack

void resolve(const void *address) {
    static bfd* abfd = 0;
    static asymbol **syms = 0;
    static asection *text = 0;
    if (!abfd) {
	  char ename[1024];
	  int l = readlink("/proc/self/exe",ename,sizeof(ename));
	  if (l == -1) {
	    perror("failed to find executable\n");
	    return;
	  }
	  ename[l] = 0;
 
	  bfd_init();
 
	  abfd = bfd_openr(ename, 0);
	  if (!abfd) {
	      perror("bfd_openr failed: ");
	      return;
	  }
 
	  /* oddly, this is required for it to work... */
	  bfd_check_format(abfd,bfd_object);
 
	  unsigned storage_needed = bfd_get_symtab_upper_bound(abfd);
	  syms = (asymbol **) malloc(storage_needed);
	  bfd_canonicalize_symtab(abfd, syms);
 
	  text = bfd_get_section_by_name(abfd, ".text");
    }
 
    long offset = ((long)address) - text->vma;
    if (offset > 0) {
	const char *file;
	const char *func;
	unsigned line;
	if (bfd_find_nearest_line(abfd, text, syms, offset, &file, &func, &line) && file)
	    printf("file: %s, line: %u, func %s\n",file,line,func);
    }
}

void show_stackframe() {
  void *trace[16];
  char **messages = nullptr;

  int trace_size = backtrace(trace, 16);
  messages = backtrace_symbols(trace, trace_size);
  printf("[bt] Execution path:\n");
  for (int i = 0; i < 16; ++i){
      resolve(trace[i]); 
  }
  free(messages);
}

void  handler(int param) {
    show_stackframe();
}

struct Setup {
    Setup( ){
	signal( SIGUSR1, handler );
	signal( SIGABRT, handler );
    }
};
volatile Setup s;

