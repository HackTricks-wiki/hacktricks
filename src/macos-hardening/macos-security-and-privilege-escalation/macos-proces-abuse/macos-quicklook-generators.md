# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Quick Look es el framework de vista previa de archivos de macOS. Cuando un usuario selecciona un archivo en Finder, presiona Space, pasa el cursor sobre él o ve un directorio con miniaturas habilitadas, Quick Look carga automáticamente un plugin generador para parsear el archivo y renderizar una vista previa visual.

Quick Look generators son bundles (`.qlgenerator`) que se registran para Identificadores Uniformes de Tipo (UTIs) específicos. Cuando macOS necesita una vista previa para un archivo que coincide con ese UTI, carga el generator en un proceso auxiliar sandboxeado (`QuickLookSatellite` o `qlmanage`) y llama a su función generadora.

### Why This Matters for Security

> [!WARNING]
> Quick Look generators se activan con solo **seleccionar o visualizar un archivo** — no se requiere la acción de "Abrir". Esto los convierte en un poderoso vector de explotación **pasiva**: el usuario solo necesita navegar a un directorio que contenga un archivo malicioso.

**Attack surface:**
- Los generadores **parsean contenido de archivos arbitrarios** desde disco, descargas, adjuntos de email o recursos compartidos en red
- Un archivo manipulado puede explotar **vulnerabilidades de parsing** (buffer overflows, format strings, type confusion) en el código del generator
- El renderizado de la vista previa ocurre **automáticamente** — ver una carpeta Downloads donde aterrizó un archivo malicioso es suficiente
- Quick Look se ejecuta en un proceso auxiliar sandboxeado, pero se han demostrado sandbox escapes desde este contexto

## Architecture
```
User selects file in Finder
↓
Finder → QuickLookSatellite (sandboxed helper)
↓
Generator plugin loaded (.qlgenerator bundle)
↓
Plugin parses file content → Returns preview image/HTML
↓
Preview displayed to user
```
## Enumeración

### Listar Generadores Instalados
```bash
# List all Quick Look generators with their UTI registrations
qlmanage -m plugins 2>&1

# Find generator bundles on the system
find / -name "*.qlgenerator" -type d 2>/dev/null

# Common locations
ls /Library/QuickLook/
ls ~/Library/QuickLook/
ls /System/Library/QuickLook/

# Check a generator's Info.plist for UTI registrations
defaults read /path/to/Generator.qlgenerator/Contents/Info.plist 2>/dev/null
```
### Usando el Scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Escenarios de ataque

### Explotación basada en archivos

Un Quick Look generator de terceros que analiza formatos de archivo complejos (modelos 3D, datos científicos, formatos de archivo comprimidos) es un objetivo principal:
```bash
# 1. Identify a third-party generator and its UTI
qlmanage -m plugins 2>&1 | grep -v "com.apple" | head -20

# 2. Find what file types it handles
defaults read /Library/QuickLook/SomeGenerator.qlgenerator/Contents/Info.plist \
CFBundleDocumentTypes 2>/dev/null

# 3. Craft a malicious file matching that UTI
# (fuzzer output or hand-crafted malformed file)

# 4. Place the file where the user will preview it
cp malicious.xyz ~/Downloads/

# 5. When user opens Downloads in Finder → preview triggers → exploit fires
```
### Drive-By a través de Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Reemplazo de generadores de terceros

Si un bundle de generador de Quick Look está instalado en una **ubicación escribible por el usuario** (`~/Library/QuickLook/`), puede ser reemplazado:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Activar Quick Look de forma remota
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Consideraciones del sandbox

Quick Look generators se ejecutan dentro de un proceso auxiliar sandboxed. El perfil del sandbox limita:
- Acceso al sistema de archivos (principalmente solo lectura al archivo que se está previsualizando)
- Acceso a la red (restringido)
- IPC (mach-lookup limitado)

Sin embargo, el sandbox tiene vectores de escape conocidos:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVEs en el mundo real

| CVE | Descripción |
|---|---|
| CVE-2019-8741 | Corrupción de memoria en la vista previa de Quick Look mediante un archivo especialmente diseñado |
| CVE-2018-4293 | Escape del sandbox del generador de Quick Look |
| CVE-2020-9963 | Divulgación de información en el procesamiento de la vista previa de Quick Look |
| CVE-2021-30876 | Corrupción de memoria en la generación de miniaturas |

## Fuzzing de generadores de Quick Look
```bash
# Basic fuzzing approach for a Quick Look generator:

# 1. Identify the target generator and its file format
qlmanage -m plugins 2>&1 | grep "target-uti"

# 2. Collect seed corpus of valid files
find / -name "*.targetext" -size -1M 2>/dev/null | head -100

# 3. Mutate files and trigger preview
for f in /tmp/fuzz_corpus/*; do
# Mutate the file (using radamsa, honggfuzz, etc.)
radamsa "$f" > /tmp/fuzz_input.targetext

# Trigger Quick Look (with timeout to catch hangs)
timeout 5 qlmanage -t /tmp/fuzz_input.targetext 2>&1

# Check if QuickLookSatellite crashed
log show --last 5s --predicate 'process == "QuickLookSatellite" AND eventMessage CONTAINS "crash"' 2>/dev/null
done
```
## Referencias

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
