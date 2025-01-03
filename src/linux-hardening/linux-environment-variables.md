# Linux-Umgebungsvariablen

{{#include ../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Sie können eine globale Variable für Ihre aktuelle Sitzung erstellen, indem Sie:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable wird von Ihren aktuellen Sitzungen und deren Kindprozessen zugänglich sein.

Sie können eine Variable **entfernen**, indem Sie:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Die **lokalen Variablen** können nur von der **aktuellen Shell/Skript** **zugegriffen** werden.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Aktuelle Variablen auflisten
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Gemeinsame Variablen

Von: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – der Bildschirm, der von **X** verwendet wird. Diese Variable ist normalerweise auf **:0.0** gesetzt, was den ersten Bildschirm auf dem aktuellen Computer bedeutet.
- **EDITOR** – der bevorzugte Texteditor des Benutzers.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen, die in der Verlaufdatei enthalten sind.
- **HISTSIZE** – Anzahl der Zeilen, die zur Verlaufdatei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
- **HOME** – Ihr Home-Verzeichnis.
- **HOSTNAME** – der Hostname des Computers.
- **LANG** – Ihre aktuelle Sprache.
- **MAIL** – der Speicherort des Mail-Spools des Benutzers. Normalerweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, in denen nach Handbuchseiten gesucht wird.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – die Standardaufforderung in bash.
- **PATH** – speichert den Pfad aller Verzeichnisse, die die Binärdateien enthalten, die Sie ausführen möchten, indem Sie nur den Namen der Datei angeben und nicht den relativen oder absoluten Pfad.
- **PWD** – das aktuelle Arbeitsverzeichnis.
- **SHELL** – der Pfad zur aktuellen Befehlszeile (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
- **TZ** – Ihre Zeitzone.
- **USER** – Ihr aktueller Benutzername.

## Interessante Variablen für das Hacking

### **HISTFILESIZE**

Ändern Sie **den Wert dieser Variable auf 0**, damit beim **Beenden Ihrer Sitzung** die **Verlaufdatei** (\~/.bash_history) **gelöscht wird**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändern Sie **den Wert dieser Variablen auf 0**, damit beim **Beenden Ihrer Sitzung** kein Befehl in die **Historie-Datei** (\~/.bash_history) aufgenommen wird.
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

Die Prozesse verwenden den hier deklarierten **Proxy**, um über **http oder https** eine Verbindung zum Internet herzustellen.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Ändern Sie, wie Ihre Eingabeaufforderung aussieht.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regulärer Benutzer:

![](<../images/image (740).png>)

Eins, zwei und drei Hintergrundjobs:

![](<../images/image (145).png>)

Ein Hintergrundjob, ein gestoppter und der letzte Befehl wurde nicht korrekt beendet:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
