# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Grundinformationen

**Seccomp**, was für Secure Computing Mode steht, ist eine Sicherheitsfunktion des **Linux-Kernels, die dazu dient, Systemaufrufe zu filtern**. Es beschränkt Prozesse auf eine begrenzte Menge von Systemaufrufen (`exit()`, `sigreturn()`, `read()` und `write()` für bereits geöffnete Dateideskriptoren). Wenn ein Prozess versucht, etwas anderes aufzurufen, wird er vom Kernel mit SIGKILL oder SIGSYS beendet. Dieser Mechanismus virtualisiert keine Ressourcen, sondern isoliert den Prozess von ihnen.

Es gibt zwei Möglichkeiten, seccomp zu aktivieren: über den `prctl(2)` Systemaufruf mit `PR_SET_SECCOMP` oder für Linux-Kernel 3.17 und höher den `seccomp(2)` Systemaufruf. Die ältere Methode zur Aktivierung von seccomp durch Schreiben in `/proc/self/seccomp` wurde zugunsten von `prctl()` eingestellt.

Eine Erweiterung, **seccomp-bpf**, fügt die Fähigkeit hinzu, Systemaufrufe mit einer anpassbaren Richtlinie zu filtern, die Berkeley Packet Filter (BPF) Regeln verwendet. Diese Erweiterung wird von Software wie OpenSSH, vsftpd und den Chrome/Chromium-Browsern auf Chrome OS und Linux für flexibles und effizientes Syscall-Filtering genutzt und bietet eine Alternative zu dem mittlerweile nicht mehr unterstützten systrace für Linux.

### **Original/Strikter Modus**

In diesem Modus erlaubt Seccomp **nur die Syscalls** `exit()`, `sigreturn()`, `read()` und `write()` für bereits geöffnete Dateideskriptoren. Wenn ein anderer Syscall gemacht wird, wird der Prozess mit SIGKILL beendet.
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

Dieser Modus ermöglicht **die Filterung von Systemaufrufen mithilfe einer konfigurierbaren Richtlinie**, die mit Berkeley Packet Filter-Regeln implementiert ist.
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

**Seccomp-bpf** wird von **Docker** unterstützt, um die **syscalls** der Container einzuschränken und somit die Angriffsfläche effektiv zu verringern. Die **syscalls, die standardmäßig blockiert sind**, finden Sie unter [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) und das **Standard-Seccomp-Profil** finden Sie hier [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Sie können einen Docker-Container mit einer **anderen Seccomp**-Richtlinie ausführen mit:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Wenn Sie beispielsweise einen Container daran **hindern** möchten, einen bestimmten **syscall** wie `uname` auszuführen, könnten Sie das Standardprofil von [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) herunterladen und einfach den **`uname`-String aus der Liste entfernen**.\
Wenn Sie sicherstellen möchten, dass **einige Binärdateien nicht innerhalb eines Docker-Containers funktionieren**, könnten Sie strace verwenden, um die syscalls aufzulisten, die die Binärdatei verwendet, und diese dann verbieten.\
Im folgenden Beispiel werden die **syscalls** von `uname` entdeckt:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> Wenn Sie **Docker nur zum Starten einer Anwendung verwenden**, können Sie es mit **`strace`** **profilieren** und nur die Syscalls **erlauben**, die es benötigt.

### Beispiel Seccomp-Richtlinie

[Beispiel von hier](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Um die Seccomp-Funktion zu veranschaulichen, erstellen wir ein Seccomp-Profil, das den Systemaufruf „chmod“ wie unten gezeigt deaktiviert.
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
Im obigen Profil haben wir die Standardaktion auf "erlauben" gesetzt und eine schwarze Liste erstellt, um "chmod" zu deaktivieren. Um sicherer zu sein, können wir die Standardaktion auf "fallen lassen" setzen und eine weiße Liste erstellen, um Systemaufrufe selektiv zu aktivieren.\
Die folgende Ausgabe zeigt, dass der "chmod"-Aufruf einen Fehler zurückgibt, da er im seccomp-Profil deaktiviert ist.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Die folgende Ausgabe zeigt das „docker inspect“, das das Profil anzeigt:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
