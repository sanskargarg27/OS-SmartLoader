#include "loader.h"

#define PAGE_SIZE 4096

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;

int total_page_faults = 0;
int total_page_allocatins = 0;
int total_internal_fragmentaton = 0;

off_t e_phoff;
size_t e_phentsize;
uint16_t e_phnum;
uint32_t e_entry;

/*
 * release memory and other cleanups
 */
void loader_cleanup() {
  if (phdr){
    free(phdr);
    phdr = NULL;
  }
  if (ehdr){
    free(ehdr);
    ehdr= NULL;
  }
  close(fd);
}

/*
 * Load and run the ELF executable file
 */

void load_and_run_elf(char** exe) {
  ehdr = malloc(sizeof(Elf32_Ehdr));
  if (ehdr == NULL) {
    perror("malloc");
    return;
  }
  phdr = malloc(sizeof(Elf32_Phdr));
  if (phdr == NULL) {
    perror("malloc");
    return;
  }
  
  fd = open(exe[1], O_RDONLY);
  if (fd < 0) {
    perror("open");
    return;
  }

  // 1. Load entire binary content into the memory from the ELF file.
  if (read(fd, ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
    perror("read");
    return;
  }

  e_phoff = ehdr->e_phoff;
  e_phentsize = ehdr->e_phentsize;
  e_phnum = ehdr->e_phnum;
  e_entry = ehdr->e_entry;

  // lseek(fd, e_phoff, SEEK_SET);

  // 5. Typecast the address to that of function pointer matching "_start" method in fib.c.
  // int (*_start)(void) = (int (*)(void))((char *)virtual_mem + (e_entry - phdr->p_vaddr));
  int (*_start)(void) = (int (*)(void))(e_entry);
  
  // 6. Call the "_start" method and print the value returned from the "_start"
  int result = _start();
  printf("User _start return value = %d\n",result);
}

// Helper function to convert ELF `p_flags` to `mmap` protection flags
// int get_protection(uint32_t p_flags) {
//     int prot = 0;
//     if (p_flags & PF_R) prot |= PROT_READ;
//     if (p_flags & PF_W) prot |= PROT_WRITE;
//     if (p_flags & PF_X) prot |= PROT_EXEC;
//     return prot;
// }

void segmentation_fault_signal_handler(int sig, siginfo_t* sig_info, void *context) {

  void *fault_addr = (void*)((uintptr_t)sig_info->si_addr);
  total_page_faults++;
  
  void *aligned_fault_addr = (void *)((uintptr_t)fault_addr & ~(PAGE_SIZE-1));

  for (int i = 0; i < e_phnum; i++) {
    lseek(fd, e_phoff + i * e_phentsize, SEEK_SET);

    Elf32_Phdr tem;
    if (read(fd, &tem, sizeof(Elf32_Phdr)) != sizeof(Elf32_Phdr)) {
      perror("read");
      return;
    }
    void *start_address = (void *)tem.p_vaddr;
    void *end_address = (void *)(tem.p_vaddr + tem.p_memsz);

    if (tem.p_type == PT_LOAD && fault_addr >= start_address && fault_addr < end_address) {
      // int prot = get_protection(tem.p_flags);
      void *mapped_addr = mmap(aligned_fault_addr, PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
      if (mapped_addr == MAP_FAILED) {
        perror("mmap (due)");
        return;
      }
      total_page_allocatins++;

      size_t offset_within_segment = (uintptr_t)fault_addr - (uintptr_t)tem.p_vaddr;
      size_t page_offset = offset_within_segment & ~(PAGE_SIZE - 1);
      size_t bytes_to_read = PAGE_SIZE;
      
      if (page_offset + bytes_to_read > tem.p_memsz) {
        bytes_to_read = tem.p_memsz - page_offset;
      }

      // Read segment content into mapped memory
      lseek(fd, tem.p_offset + page_offset, SEEK_SET);
      ssize_t bytes_read = read(fd, mapped_addr, bytes_to_read);
      if (bytes_read == -1) {
        perror("read3");
        exit(1);
      }

      total_internal_fragmentaton += (PAGE_SIZE - bytes_read);
      return;
    }
  }
}

int main(int argc, char** argv) {
  // 1. carry out necessary checks on the input ELF file
  if(argc != 2) {
    printf("Usage: %s <ELF Executable> \n",argv[0]);
    exit(1);
  }

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = segmentation_fault_signal_handler;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGSEGV, &sa, NULL) == -1) {
    perror("sigaction failed");
    exit(1);
  }
  // 2. passing it to the loader for carrying out the loading/execution
  load_and_run_elf(argv);
  // 3. invoke the cleanup routine inside the loader  

  printf("Total page faults: %d\n", total_page_faults);
  printf("Total page allocations: %d\n", total_page_allocatins);
  printf("Total internal fragmentation: %d bytes\n", total_internal_fragmentaton);

  loader_cleanup();
  return 0;
}