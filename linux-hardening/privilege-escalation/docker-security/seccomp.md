# Seccomp

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

**Seccomp** or Secure Computing mode, in summary, is a feature of Linux kernel which can act as **syscall filter**.\
Seccomp has 2 modes.

**seccomp** (short for **secure computing mode**) is a computer security facility in the **Linux** **kernel**. seccomp allows a process to make a one-way transition into a "secure" state where **it cannot make any system calls except** `exit()`, `sigreturn()`, `read()` and `write()` to **already-open** file descriptors. Should it attempt any other system calls, the **kernel** will **terminate** the **process** with SIGKILL or SIGSYS. In this sense, it does not virtualize the system's resources but isolates the process from them entirely.

seccomp mode is **enabled via the `prctl(2)` system call** using the `PR_SET_SECCOMP` argument, or (since Linux kernel 3.17) via the `seccomp(2)` system call. seccomp mode used to be enabled by writing to a file, `/proc/self/seccomp`, but this method was removed in favor of `prctl()`. In some kernel versions, seccomp disables the `RDTSC` x86 instruction, which returns the number of elapsed processor cycles since power-on, used for high-precision timing.

**seccomp-bpf** is an extension to seccomp that allows **filtering of system calls using a configurable policy** implemented using Berkeley Packet Filter rules. It is used by OpenSSH and vsftpd as well as the Google Chrome/Chromium web browsers on Chrome OS and Linux. (In this regard seccomp-bpf achieves similar functionality, but with more flexibility and higher performance, to the older systrace—which seems to be no longer supported for Linux.)

### **Original/Strict Mode**

In this mode Seccomp **only allow the syscalls** `exit()`, `sigreturn()`, `read()` and `write()` to already-open file descriptors. If any other syscall is made, the process is killed using SIGKILL

{% code title="seccomp_strict.c" %}
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

{% code title="seccomp_bpf.c" %}
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

**Seccomp-bpf** is supported by **Docker** to restrict the **syscalls** from the containers effectively decreasing the surface area. You can find the **syscalls blocked** by **default** in [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) and the **default seccomp profile** can be found here [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
You can run a docker container with a **different seccomp** policy with:

```bash
docker run --rm \
             -it \
             --security-opt seccomp=/path/to/seccomp/profile.json \
             hello-world
```

If you want for example to **forbid** a container of executing some **syscall** like `uname` you could download the default profile from [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) and just **remove the `uname` string from the list**.\
If you want to make sure that **some binary doesn't work inside a a docker container** you could use strace to list the syscalls the binary is using and then forbid them.\
In the following example the **syscalls** of `uname` are discovered:

```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```

{% hint style="info" %}
If you are using **Docker just to launch an application**, you can **profile** it with **`strace`** and **just allow the syscalls** it needs
{% endhint %}

### Example Seccomp policy

To illustrate Seccomp feature, let’s create a Seccomp profile disabling “chmod” system call as below.

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

In the above profile, we have set default action to “allow” and created a black list to disable “chmod”. To be more secure, we can set default action to drop and create a white list to selectively enable system calls.\
Following output shows the “chmod” call returning error because its disabled in the seccomp profile

```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```

Following output shows the “docker inspect” displaying the profile:

```json
           "SecurityOpt": [
                "seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
            ],
```

### Deactivate it in Docker

Launch a container with the flag: **`--security-opt seccomp=unconfined`**

As of Kubernetes 1.19, **seccomp is enabled by default for all Pods**. However, the default seccomp profile applied to the Pods is the "**RuntimeDefault**" profile, which is **provided by the container runtime** (e.g., Docker, containerd). The "RuntimeDefault" profile allows most system calls while blocking a few that are considered dangerous or not generally required by containers.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
