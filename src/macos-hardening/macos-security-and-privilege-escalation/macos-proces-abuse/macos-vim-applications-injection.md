# macOS Vim/Neovim-Anwendungsinjektion

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Vims eigene Skriptsprache (Vimscript) kann **beliebige Ex-Befehle und Shell-Befehle beim Start** aus Umgebungsvariablen ausführen. Wenn ein Prozess mit höheren Privilegien (ein Wartungs-/Root-Workflow, ein `sudo vim …`, ein von einem anderen Tool gestarteter Editor, `crontab -e`, `visudo`, `git`/`less`, das einen Editor aufruft, …) Vim/Neovim mit einer vom Angreifer beeinflussten Umgebung startet, erhält der Angreifer Codeausführung in diesem Kontext.

## `VIMINIT`

Während der Initialisierung liest Vim die Ex-Befehle in **`VIMINIT`** und führt sie aus. Zu den Ex-Befehlen gehören `:!cmd` (führt einen Shell-Befehl aus) und `:call system(...)`; daher ermöglicht bereits eine einzelne Variable beliebige Codeausführung, bevor irgendeine Datei bearbeitet wird.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
Das im ersten Beispiel über stdin eingespeiste `:qa!` schließt den Editor erst, nachdem der Payload ausgeführt wurde; in einem realen Szenario kann das Opfer Vim ganz normal öffnen.

`VIMINIT` wird als **eine Ex-Befehlszeile** geparst. Eine Kette wird mit `|` (oder einem Literal-Newline) getrennt. Es hat Vorrang vor der vimrc des Benutzers und `EXINIT`, sodass ein Payload keine bösartige Konfigurationsdatei benötigt und vor der normalen Benutzerkonfiguration ausgeführt wird.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Wenn `VIMINIT` nicht gesetzt ist, greift Vim (und die `vi`-/`ex`-Kompatibilitäts-Binaries) auf **`EXINIT`** zurück, das auf dieselbe Weise ausgeführt wird. Es ist die klassische Variante aus der vi-Ära desselben Primitivs.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Unterdrückung des Starts und Ausnutzbarkeit

Dieses Primitive hängt von einem **normalen Start** ab. `vim -u NONE` / `nvim -u NONE` überspringen die Umgebungs-/Benutzerinitialisierung (und Plugins), während `-u <file>` stattdessen diese Datei verwendet. Vim `-es`/`-Es` und Neovim `-es`, `-Es` oder `-l` überspringen diese Initialisierungsschritte ebenfalls. Verwechsle `--headless` nicht mit einem sicheren Modus: Ein normaler headless-Start von Neovim verarbeitet `VIMINIT` weiterhin.<sup>[[1]](#references)[[2]](#references)</sup>

Überprüfe daher die vollständige Startkette: Die Variable muss den Wrapper, die `sudo`-Richtlinie, den Job Runner und die Editor-Auswahl überstehen, und der endgültige Befehl darf nicht `-u NONE`/`NORC` oder den Batch-Modus erzwingen. Ein zuverlässiger Payload kann sich mit `|qall!` selbst beenden, was auch das Testen von Wrappern erleichtert, die kein TTY bereitstellen.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking von Lua-Modulen im aktuellen Verzeichnis von Neovim

Ein separates Neovim-Injection-Primitive betrifft Builds, deren Lua-`package.path`/`package.cpath` weiterhin Vorlagen für das aktuelle Verzeichnis wie `./?.lua` oder `./?.so` enthalten. Neovim allein zu starten reicht nicht aus: Eine Konfiguration oder ein Plugin muss `require("name")` aufrufen, und kein früherer Loader darf diesen Namen zuvor auflösen. Ein häufiger Trigger ist eine **optionale Abhängigkeitsprüfung** wie `pcall(require, "optional_dep")`; wird `optional_dep.lua` in einem vom Angreifer kontrollierten Arbeitsverzeichnis platziert, wird die Datei ausgeführt, ohne das separate Feature für die lokale Konfiguration `'exrc'` zu aktivieren. Core-`vim.*`-Module und Module, die bereits auf `'runtimepath'` gefunden wurden, können im Allgemeinen nicht überschrieben werden. Ermittle daher die tatsächlich fehlenden/optionalen `require()`-Aufrufe, anstatt Namen zu erraten.<sup>[[3]](#references)</sup>

Das Folgende reproduziert das Loader-Primitive mit einer harmlosen Markierung:<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
Überprüfe den ausgeführten Build, statt dich nur auf eine Versionszeichenfolge zu verlassen:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream verfolgt die Entfernung des Fallbacks für das aktuelle Verzeichnis während des normalen Editorstarts, wobei das Verhalten von Lua-Skripten (`nvim -l`) beibehalten wird. Solange der installierte Build es noch bereitstellt, füge dies an den **Anfang** von `init.lua` ein (es entfernt absichtlich relative Lua/C-Modulvorlagen aus dem aktuellen Verzeichnis; wende es daher nicht auf Workflows an, die diese benötigen):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Hinweise und Einschränkungen

- **Neovim** berücksichtigt sowohl `VIMINIT` als auch den Fallback `EXINIT`, aber seine normale Benutzerkonfiguration befindet sich in `init.vim` oder `init.lua`.<sup>[[2]](#references)</sup>
- Der Pfad über die Umgebungsvariable benötigt keine beschreibbare Datei. Lokales rc- und Hijacking von Modulen im aktuellen Verzeichnis sind separate, dateibasierte Primitives.<sup>[[1]](#references)[[3]](#references)</sup>
- Die lokale Projektkonfiguration ist eine andere Angriffsfläche als Modelines. Wenn Vim mit aktiviertem `'exrc'` ausgeführt wird, wird eine lokale, einem anderen Benutzer gehörende vimrc/exrc-Datei mit `'secure'`-Einschränkungen ausgeführt. Beim Extrahieren eines Archivs gehört die platzierte Datei jedoch normalerweise dem Opfer, wodurch dieser eigentumsbasierte Schutz umgangen wird. Neovim sucht bei aktiviertem `'exrc'` außerdem nach `.nvim.lua`, `.nvimrc` oder `.exrc` — dieser Opt-in-Mechanismus darf nicht mit dem oben beschriebenen `require()`-Fallback für das aktuelle Verzeichnis verwechselt werden.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Variablen zur Auswahl des Editors bestimmen nur, welches Programm gestartet wird; sie garantieren nicht, dass `VIMINIT` den finalen Prozess erreicht. Untersuche die genaue Umgebung und die Argumente an der Vim/Neovim-exec-Grenze.<sup>[[1]](#references)[[2]](#references)</sup>

## Härtung

- Entferne die Variablen explizit vor privilegierten oder automatisierten Editorstarts: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` ist wichtig, wenn der Aufrufer jede Benutzer-Startup-Quelle ignorieren muss.<sup>[[1]](#references)[[2]](#references)</sup>
- Setze `EDITOR`/`VISUAL` auf vertrauenswürdige absolute Pfade, vermeide das Ausführen interaktiver Editoren als root mit einer geerbten Benutzerumgebung und stelle sicher, dass Wrapper `VIMINIT`/`EXINIT` nach der Bereinigung nicht wiederherstellen können.<sup>[[1]](#references)[[2]](#references)</sup>
- Aktualisiere bei Neovim auf einen Build, der Vorlagen für die Lua-/C-Suche im aktuellen Verzeichnis während des Editormodus entfernt, oder entferne sie vor dem Laden von Plugins. Prüfe den Plugin-Code auf optionale `pcall(require, ...)`-Aufrufe beim Öffnen nicht vertrauenswürdiger Repositories.<sup>[[3]](#references)</sup>
- Behandle die Kontrolle über die Editorumgebung, das Arbeitsverzeichnis oder die Startup-Konfiguration eines Ziels als potenzielles Code-Execution-Primitive im Sicherheitskontext des Editors.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim documentation — `starting.txt` (Initialisierung, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim documentation — Start und Initialisierung](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — Fallback für das aktuelle Verzeichnis in `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
