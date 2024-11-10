#include "loader.h"

#define PAGE_SIZE 4096;

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;
void *virtual_mem;

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
  if (virtual_mem){
    if (munmap(virtual_mem, phdr->p_memsz) == -1) {
          perror("munmap");
          return;
    }
    virtual_mem = NULL;
  }
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

  lseek(fd, e_phoff, SEEK_SET);

  // 2. Iterate through the PHDR table and find the section of PT_LOAD 
  //    type that contains the address of the entrypoint method in fib.c
  // for(int i = 0; i < e_phnum; i++){
  //   Elf32_Phdr tem;
  //   if (read(fd, &tem, sizeof(Elf32_Phdr)) != sizeof(Elf32_Phdr)) {
  //       perror("read");
  //       return;
  //   }


  //   if (tem.p_type == 1){
  //     uint32_t seg_start = tem.p_vaddr;
  //     uint32_t seg_end = tem.p_vaddr + tem.p_memsz;
  //     if (e_entry >= seg_start && e_entry <= seg_end){
  //       memcpy(phdr, &tem, sizeof(Elf32_Phdr));
  //     }
  //   } 
  // }

  // // 3. Allocate memory of the size "p_memsz" using mmap function 
  // //    and then copy the segment content
  // virtual_mem = mmap(NULL, phdr->p_memsz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
  // if (virtual_mem == MAP_FAILED) {
  //       perror("mmap");
  //       return;
  // }
  // lseek(fd, phdr->p_offset, SEEK_SET);

  // if (read(fd, virtual_mem, phdr->p_memsz) != phdr->p_memsz) {
  //       perror("read");
  //       return;
  // }
  
  // 4. Navigate to the entrypoint address into the segment loaded in the memory in above step
  // 5. Typecast the address to that of function pointer matching "_start" method in fib.c.
  // int (*_start)(void) = (int (*)(void))((char *)virtual_mem + (e_entry - phdr->p_vaddr));
  int (*_start)(void) = (int (*)(void)(e_entry));
  
  // 6. Call the "_start" method and print the value returned from the "_start"
  int result = _start();
  printf("User _start return value = %d\n",result);
}

// Helper function to convert ELF `p_flags` to `mmap` protection flags
int get_protection(uint32_t p_flags) {
    int prot = 0;
    if (p_flags & PF_R) prot |= PROT_READ;
    if (p_flags & PF_W) prot |= PROT_WRITE;
    if (p_flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

void segmentation_fault_signal_handler(int sig, siginfo_t* sig_info, void *context) {
  total_page_faults++;
  void *fault_addr = sig_info->si_addr;

  for (int i = 0; i < e_phnum; i++) {
    Elf32_Phdr tem;
    if (read(fd, &tem, sizeof(Elf32_Phdr)) != sizeof(Elf32_Phdr)) {
      perror("read");
      return;
    }

    if (fault_addr >= tem.p_vaddr && fault_addr <= (tem.p_vaddr + tem.p_memsz)) {
      int prot = get_protection(tem.p_flags);
      void *mapped_addr = mmap(fault_addr, PAGE_SIZE, prot, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
      if (mapped_addr == MAP_FAILED) {
        perror("mmap (due)");
        return;
      }
      total_page_allocatins++;
      size_t offset_within_segment = (uintptr_t)fault_addr - (uintptr_t)tem.p_memsz;
      ssize_t bytes_to_read = (offset_within_segment + PAGE_SIZE <= tem.p_memsz) ? PAGE_SIZE ? tem.p_memsz - offset_within_segment;

      lseek(fd, tem.p_offset + offset_within_segment, SEEK_SET);
      if (read(fd, mapped_addr, bytes_to_read) != bytes_to_read) {
        perror("read");
        return;
      }

      total_internal_fragmentaton += (PAGE_SIZE - bytes_to_read);
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

  printf("%d\n%d\n%d\n", total_page_faults, total_page_allocatins, total_internal_fragmentaton);
  loader_cleanup();
  return 0;
}