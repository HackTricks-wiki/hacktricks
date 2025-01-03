# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**Seccomp**, czyli tryb bezpiecznego obliczania, to funkcja zabezpieczeń **jądra Linuxa zaprojektowana do filtrowania wywołań systemowych**. Ogranicza procesy do ograniczonego zestawu wywołań systemowych (`exit()`, `sigreturn()`, `read()` i `write()` dla już otwartych deskryptorów plików). Jeśli proces spróbuje wywołać cokolwiek innego, zostaje zakończony przez jądro za pomocą SIGKILL lub SIGSYS. Ten mechanizm nie wirtualizuje zasobów, ale izoluje proces od nich.

Istnieją dwa sposoby aktywacji seccomp: poprzez wywołanie systemowe `prctl(2)` z `PR_SET_SECCOMP`, lub dla jąder Linuxa 3.17 i nowszych, wywołanie systemowe `seccomp(2)`. Starsza metoda włączania seccomp poprzez zapis do `/proc/self/seccomp` została wycofana na rzecz `prctl()`.

Ulepszenie, **seccomp-bpf**, dodaje możliwość filtrowania wywołań systemowych z dostosowywaną polityką, wykorzystując zasady Berkeley Packet Filter (BPF). To rozszerzenie jest wykorzystywane przez oprogramowanie takie jak OpenSSH, vsftpd oraz przeglądarki Chrome/Chromium na Chrome OS i Linuxie do elastycznego i efektywnego filtrowania wywołań systemowych, oferując alternatywę dla teraz nieobsługiwanego systrace dla Linuxa.

### **Tryb oryginalny/ścisły**

W tym trybie Seccomp **pozwala tylko na wywołania systemowe** `exit()`, `sigreturn()`, `read()` i `write()` dla już otwartych deskryptorów plików. Jeśli zostanie wykonane jakiekolwiek inne wywołanie systemowe, proces zostaje zabity za pomocą SIGKILL.
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

Ten tryb pozwala na **filtrowanie wywołań systemowych za pomocą konfigurowalnej polityki** wdrożonej przy użyciu reguł Berkeley Packet Filter.
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
## Seccomp w Dockerze

**Seccomp-bpf** jest wspierany przez **Docker** w celu ograniczenia **syscalls** z kontenerów, skutecznie zmniejszając powierzchnię ataku. Możesz znaleźć **syscalls zablokowane** domyślnie w [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) a **domyślny profil seccomp** można znaleźć tutaj [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Możesz uruchomić kontener docker z **inną polityką seccomp** za pomocą:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Jeśli chcesz na przykład **zabronić** kontenerowi wykonywania niektórych **syscall** jak `uname`, możesz pobrać domyślny profil z [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) i po prostu **usunąć ciąg `uname` z listy**.\
Jeśli chcesz upewnić się, że **niektóre binarne pliki nie działają wewnątrz kontenera docker**, możesz użyć strace, aby wylistować syscalls, które używa binarny plik, a następnie je zabronić.\
W następującym przykładzie odkrywane są **syscall** `uname`:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> Jeśli używasz **Dockera tylko do uruchamiania aplikacji**, możesz **profilować** go za pomocą **`strace`** i **pozwolić tylko na te syscalls**, które są potrzebne

### Przykład polityki Seccomp

[Przykład stąd](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Aby zilustrować funkcję Seccomp, stwórzmy profil Seccomp, który wyłącza wywołanie systemowe „chmod”, jak poniżej.
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
W powyższym profilu ustawiliśmy domyślną akcję na „zezwól” i utworzyliśmy czarną listę, aby wyłączyć „chmod”. Aby być bardziej bezpiecznym, możemy ustawić domyślną akcję na odrzucenie i utworzyć białą listę, aby selektywnie włączyć wywołania systemowe.\
Poniższy wynik pokazuje, że wywołanie „chmod” zwraca błąd, ponieważ jest wyłączone w profilu seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
Poniższy wynik pokazuje „docker inspect” wyświetlający profil:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}
