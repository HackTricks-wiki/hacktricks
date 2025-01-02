# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

**Seccomp**, che sta per Secure Computing mode, è una funzionalità di sicurezza del **kernel Linux progettata per filtrare le chiamate di sistema**. Limita i processi a un insieme ristretto di chiamate di sistema (`exit()`, `sigreturn()`, `read()` e `write()` per i descrittori di file già aperti). Se un processo tenta di chiamare qualsiasi altra cosa, viene terminato dal kernel utilizzando SIGKILL o SIGSYS. Questo meccanismo non virtualizza le risorse ma isola il processo da esse.

Ci sono due modi per attivare seccomp: attraverso la chiamata di sistema `prctl(2)` con `PR_SET_SECCOMP`, o per i kernel Linux 3.17 e superiori, la chiamata di sistema `seccomp(2)`. Il metodo più vecchio di abilitare seccomp scrivendo in `/proc/self/seccomp` è stato deprecato a favore di `prctl()`.

Un miglioramento, **seccomp-bpf**, aggiunge la capacità di filtrare le chiamate di sistema con una politica personalizzabile, utilizzando regole Berkeley Packet Filter (BPF). Questa estensione è sfruttata da software come OpenSSH, vsftpd e i browser Chrome/Chromium su Chrome OS e Linux per un filtraggio delle syscall flessibile ed efficiente, offrendo un'alternativa a systrace ora non supportato per Linux.

### **Modalità Originale/Stratta**

In questa modalità Seccomp **consente solo le syscall** `exit()`, `sigreturn()`, `read()` e `write()` per i descrittori di file già aperti. Se viene effettuata qualsiasi altra syscall, il processo viene terminato utilizzando SIGKILL.
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

Questa modalità consente **il filtraggio delle chiamate di sistema utilizzando una politica configurabile** implementata tramite regole di Berkeley Packet Filter.
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

**Seccomp-bpf** è supportato da **Docker** per limitare le **syscalls** dai container, riducendo efficacemente la superficie di attacco. Puoi trovare le **syscalls bloccate** per **default** in [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) e il **profilo seccomp di default** può essere trovato qui [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Puoi eseguire un container docker con una **politica seccomp** **diversa** con:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Se vuoi, ad esempio, **vietare** a un container di eseguire alcune **syscall** come `uname`, puoi scaricare il profilo predefinito da [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) e semplicemente **rimuovere la stringa `uname` dalla lista**.\
Se vuoi assicurarti che **alcun binario non funzioni all'interno di un container docker**, puoi usare strace per elencare le syscall che il binario sta utilizzando e poi vietarle.\
Nell'esempio seguente vengono scoperte le **syscall** di `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> Se stai usando **Docker solo per avviare un'applicazione**, puoi **profilare** con **`strace`** e **consentire solo le syscalls** di cui ha bisogno

### Esempio di politica Seccomp

[Esempio da qui](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Per illustrare la funzionalità Seccomp, creiamo un profilo Seccomp che disabilita la chiamata di sistema “chmod” come di seguito.
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
Nel profilo sopra, abbiamo impostato l'azione predefinita su "allow" e creato una lista nera per disabilitare "chmod". Per essere più sicuri, possiamo impostare l'azione predefinita su drop e creare una lista bianca per abilitare selettivamente le chiamate di sistema.\
L'output seguente mostra la chiamata "chmod" che restituisce un errore perché è disabilitata nel profilo seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
L'output seguente mostra il "docker inspect" che visualizza il profilo:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
