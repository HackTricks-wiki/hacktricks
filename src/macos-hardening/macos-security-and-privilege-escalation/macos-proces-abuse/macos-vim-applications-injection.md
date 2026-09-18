# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Vims eigene scripting language (Vimscript) kann beim Start **beliebige Ex-Befehle und shell commands** aus environment variables ausführen. Wenn ein Prozess mit höheren Privilegien (ein Wartungs-/root-Workflow, ein `sudo vim …`, ein von einem anderen Tool gestarteter Editor, `crontab -e`, `visudo`, `git`/`less`, die einen Editor aufrufen, …) Vim/Neovim mit einer vom Angreifer beeinflussten environment startet, erhält der Angreifer code execution in diesem Kontext.

## `VIMINIT`

Während der Initialisierung liest Vim die Ex-Befehle in **`VIMINIT`** und führt sie aus. Zu den Ex-Befehlen gehören `:!cmd` (führt einen shell command aus) und `:call system(...)`; daher ermöglicht bereits eine einzelne Variable beliebige code execution, bevor überhaupt eine Datei bearbeitet wurde.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
Das über `stdin` eingespeiste `:qa!` schließt den Editor erst, nachdem die Payload bereits ausgeführt wurde; in einem realen Szenario öffnet das Opfer Vim einfach normal.

## `EXINIT`

Wenn `VIMINIT` nicht gesetzt ist, greift Vim (sowie die Kompatibilitäts-Binaries `vi`/`ex`) auf **`EXINIT`** zurück, das auf dieselbe Weise ausgeführt wird. Dies ist die klassische Variante aus der vi-Ära desselben Primitives.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Hinweise und Einschränkungen

- **Neovim** berücksichtigt ebenfalls `VIMINIT` (diese Variable wird vor der benutzerspezifischen `init.vim`/`init.lua` geprüft).
- Der Batch-/Ex-Modus (`vim -es` / `vim -Es`) lädt `VIMINIT`/`EXINIT` **nicht**; die Variablen werden bei einem normalen (interaktiven) Start ausgeführt, was das häufige Opfer-Szenario darstellt.
- Verwandte dateibasierte Vektoren sind die verzeichnisbezogenen `exrc`/`.nvimrc`-„modeline“-/Local-RC-Funktionen und `-u <vimrc>`; der oben beschriebene Pfad über Umgebungsvariablen benötigt überhaupt keine beschreibbare Datei.

## Härtung

- Bereinige die Umgebung (entferne `VIMINIT`/`EXINIT`), bevor Editoren aus privilegierten oder automatisierten Kontexten gestartet werden, und bevorzuge `sudo -i`/`env -i`-Wrapper, die die Umgebung zurücksetzen.
- Setze `EDITOR`/`VISUAL` auf vertrauenswürdige absolute Pfade und vermeide es, Editoren als root mit einer geerbten Benutzerumgebung auszuführen.
- Behandle die Kontrolle über die Umgebung eines Ziels für jedes von ihm gestartete Vim/Neovim als gleichwertig mit Codeausführung.

## References

- [1] [Vim-Dokumentation — `starting.txt` (Initialisierung, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
