# Seccomp

## Basic Information

**Seccomp** or Secure Computing mode is a feature of Linux kernel which can act as **syscall filter**.  
Seccomp has 2 modes.

### **Original/Strict Mode**

In this mode ****Seccomp **only allow the syscalls**  `exit()`, `sigreturn()`, `read()` and `write()` to already-open file descriptors. If any other syscall is made, the process is killed using SIGKILL

{% code title="seccomp\_strict.c" %}
```c
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
{% endcode %}

### Seccomp-bpf

This mode allows f**iltering of system calls using a configurable policy** implemented using Berkeley Packet Filter rules.

{% code title="seccomp\_bpf.c" %}
```c
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
{% endcode %}

## Seccomp in Docker

**Seccomp-bpf** is supported by **Docker** to restrict the **syscalls** from the containers effectively decreasing the surface area. You can find the **syscalls blocked** by **default** in [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) and the **default seccomp profile** can be found here [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).  
You can run a docker container with a **different seccomp** policy with:

```bash
docker run --rm \
             -it \
             --security-opt seccomp=/path/to/seccomp/profile.json \
             hello-world
```

If you want for example to **forbid** a container of executing some **syscall** like `uname` you could download the default profile from [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) and just **remove the `uname` string from the list**.  
If you wan to make sure that **some binary doesn't work inside a a docker container** you could use strace to list the syscalls the binary is using and then forbid them.  
In the following example the **syscalls** of `uname` are discovered:

```bash
ocker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```

