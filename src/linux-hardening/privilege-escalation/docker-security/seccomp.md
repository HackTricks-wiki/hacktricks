# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**Seccomp**，即安全计算模式，是**Linux内核的一个安全特性，用于过滤系统调用**。它将进程限制在一组有限的系统调用中（`exit()`、`sigreturn()`、`read()`和`write()`，仅适用于已打开的文件描述符）。如果进程尝试调用其他任何内容，内核将使用SIGKILL或SIGSYS终止该进程。该机制并不虚拟化资源，而是将进程与资源隔离。

激活seccomp有两种方法：通过`prctl(2)`系统调用与`PR_SET_SECCOMP`，或者对于3.17及以上版本的Linux内核，使用`seccomp(2)`系统调用。通过写入`/proc/self/seccomp`来启用seccomp的旧方法已被弃用，取而代之的是`prctl()`。

一个增强功能，**seccomp-bpf**，增加了使用可自定义策略过滤系统调用的能力，使用伯克利数据包过滤器（BPF）规则。该扩展被OpenSSH、vsftpd以及Chrome OS和Linux上的Chrome/Chromium浏览器等软件利用，以实现灵活高效的系统调用过滤，提供了对现在不再支持的Linux systrace的替代方案。

### **原始/严格模式**

在此模式下，Seccomp **仅允许系统调用** `exit()`、`sigreturn()`、`read()`和`write()`，仅适用于已打开的文件描述符。如果进行任何其他系统调用，进程将被SIGKILL终止。
```c:seccomp_strict.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
### Seccomp-bpf

此模式允许**使用可配置策略过滤系统调用**，该策略使用伯克利数据包过滤器规则实现。
```c:seccomp_bpf.c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## Seccomp in Docker

**Seccomp-bpf** 被 **Docker** 支持，以有效限制来自容器的 **syscalls**，从而减少攻击面。您可以在 [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) 找到 **默认** 被 **阻止的 syscalls**，而 **默认 seccomp 配置文件** 可以在这里找到 [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)。\
您可以使用以下命令运行具有 **不同 seccomp** 策略的 docker 容器：
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
如果你想例如**禁止**一个容器执行某些**syscall**，像`uname`，你可以从[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)下载默认配置文件，然后**从列表中移除`uname`字符串**。\
如果你想确保**某个二进制文件在docker容器内无法工作**，你可以使用strace列出该二进制文件使用的syscalls，然后禁止它们。\
在以下示例中，发现了`uname`的**syscalls**：
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> 如果您仅仅是使用 **Docker 启动一个应用程序**，您可以使用 **`strace`** 对其进行 **分析**，并 **仅允许** 它所需的系统调用

### 示例 Seccomp 策略

[Example from here](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

为了说明 Seccomp 功能，让我们创建一个 Seccomp 配置文件，禁用“chmod”系统调用，如下所示。
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
在上述配置中，我们将默认操作设置为“允许”，并创建了一个黑名单以禁用“chmod”。为了更安全，我们可以将默认操作设置为丢弃，并创建一个白名单以选择性地启用系统调用。\
以下输出显示“chmod”调用返回错误，因为它在seccomp配置中被禁用。
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
以下输出显示了“docker inspect”显示的配置文件：
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
