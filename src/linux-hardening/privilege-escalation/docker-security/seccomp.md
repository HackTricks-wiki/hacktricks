# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**Seccomp**, inamaanisha Hali ya Usalama wa Kompyuta, ni kipengele cha usalama cha **kernel ya Linux kilichoundwa kuchuja wito wa mfumo**. Inapunguza michakato kwa seti ndogo ya wito wa mfumo (`exit()`, `sigreturn()`, `read()`, na `write()` kwa viashiria vya faili vilivyo wazi tayari). Ikiwa mchakato unajaribu kuita chochote kingine, unauawa na kernel kwa kutumia SIGKILL au SIGSYS. Mekanism hii haisimami rasilimali lakini inatenga mchakato kutoka kwao.

Kuna njia mbili za kuanzisha seccomp: kupitia wito wa mfumo `prctl(2)` na `PR_SET_SECCOMP`, au kwa kernel za Linux 3.17 na juu, wito wa mfumo `seccomp(2)`. Njia ya zamani ya kuwezesha seccomp kwa kuandika kwenye `/proc/self/seccomp` imeondolewa kwa ajili ya `prctl()`.

Uboreshaji, **seccomp-bpf**, unongeza uwezo wa kuchuja wito wa mfumo kwa sera inayoweza kubadilishwa, kwa kutumia sheria za Berkeley Packet Filter (BPF). Kupanua hii inatumika na programu kama OpenSSH, vsftpd, na vivinjari vya Chrome/Chromium kwenye Chrome OS na Linux kwa kuchuja syscall kwa njia rahisi na yenye ufanisi, ikitoa mbadala kwa systrace ambayo sasa haisaidiwi kwa Linux.

### **Original/Strict Mode**

Katika hali hii Seccomp **inaruhusu tu wito wa mfumo** `exit()`, `sigreturn()`, `read()` na `write()` kwa viashiria vya faili vilivyo wazi tayari. Ikiwa wito mwingine wowote wa mfumo unafanywa, mchakato unauawa kwa kutumia SIGKILL.
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

Hali hii inaruhusu **kuchuja wito za mfumo kwa kutumia sera inayoweza kubadilishwa** inayotekelezwa kwa kutumia sheria za Berkeley Packet Filter.
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
## Seccomp katika Docker

**Seccomp-bpf** inasaidiwa na **Docker** kupunguza **syscalls** kutoka kwa kontena kwa ufanisi na kupunguza eneo la hatari. Unaweza kupata **syscalls zilizozuiwa** kwa **default** katika [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) na **profaili ya seccomp ya default** inaweza kupatikana hapa [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Unaweza kuendesha kontena la docker na sera ya **seccomp** tofauti kwa:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Ikiwa unataka kwa mfano **kuzuia** kontena kutekeleza **syscall** kama `uname` unaweza kupakua profaili ya kawaida kutoka [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) na tu **ondoa mfuatano wa `uname` kutoka kwenye orodha**.\
Ikiwa unataka kuhakikisha kwamba **binafsi fulani haifanyi kazi ndani ya kontena la docker** unaweza kutumia strace kuorodhesha syscalls ambazo binafsi inatumia na kisha kuzikataa.\
Katika mfano ufuatao **syscalls** za `uname` zinagunduliwa:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> Ikiwa unatumia **Docker kuzindua programu tu**, unaweza **kuunda profaili** yake kwa **`strace`** na **kuruhusu tu syscalls** inazohitaji

### Mfano wa sera ya Seccomp

[Mfano kutoka hapa](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Ili kuonyesha kipengele cha Seccomp, hebu tuunde profaili ya Seccomp inayozuia wito wa mfumo wa “chmod” kama ilivyo hapa chini.
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
Katika wasifu hapo juu, tumepanga hatua ya default kuwa "kuruhusu" na kuunda orodha ya mblack ili kuzima "chmod". Ili kuwa salama zaidi, tunaweza kuweka hatua ya default kuwa kuacha na kuunda orodha ya nyeupe ili kuwezesha simu za mfumo kwa kuchagua.\
Matokeo yafuatayo yanaonyesha wito wa "chmod" ukirudisha kosa kwa sababu umezimwa katika wasifu wa seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Ifuatayo ni matokeo yanayoonyesha “docker inspect” ikionyesha wasifu:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
