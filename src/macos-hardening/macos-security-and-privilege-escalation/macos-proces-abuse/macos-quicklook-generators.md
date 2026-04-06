# Geradores Quick Look no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

Quick Look é o **framework de visualização de arquivos** do macOS. Quando um usuário seleciona um arquivo no Finder, pressiona Space, passa o cursor sobre ele, ou visualiza um diretório com miniaturas habilitadas, o Quick Look **carrega automaticamente um plugin gerador** para analisar o arquivo e renderizar uma pré-visualização visual.

Quick Look generators são **bundles** (`.qlgenerator`) que se registram para **Uniform Type Identifiers (UTIs)** específicas. Quando o macOS precisa de uma pré-visualização para um arquivo que corresponda a esse UTI, ele carrega o generator em um processo auxiliar sandboxed (`QuickLookSatellite` ou `qlmanage`) e chama sua função do gerador.

### Por que isso importa para a segurança

> [!WARNING]
> Os Quick Look generators são acionados **apenas ao selecionar ou visualizar um arquivo** — nenhuma ação de "Open" é necessária. Isso os torna um poderoso **vetor de exploração passiva**: o usuário só precisa navegar até um diretório que contenha um arquivo malicioso.

**Superfície de ataque:**
- Geradores **analisam conteúdo de arquivo arbitrário** do disco, downloads, anexos de email ou compartilhamentos de rede
- Um arquivo especialmente criado pode explorar **vulnerabilidades de parsing** (buffer overflows, format strings, type confusion) no código do gerador
- A renderização da pré-visualização acontece **automaticamente** — visualizar a pasta Downloads onde um arquivo malicioso foi colocado é suficiente
- O Quick Look roda em um **auxiliar sandboxed**, mas escapes de sandbox desse contexto já foram demonstrados

## Arquitetura
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
## Enumeração

### Listar Geradores Instalados
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
### Usando o Scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Cenários de Ataque

### Exploração Baseada em Arquivos

Um Quick Look generator de terceiros que analisa formatos de arquivo complexos (modelos 3D, dados científicos, formatos de arquivamento) é um alvo principal:
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
### Drive-By via Downloads
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Substituição de gerador de terceiros

Se um Quick Look generator bundle estiver instalado em um **local gravável pelo usuário** (`~/Library/QuickLook/`), ele pode ser substituído:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Acionar o Quick Look remotamente
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Considerações sobre a sandbox

Os geradores do Quick Look são executados dentro de um processo auxiliar em sandbox. O perfil da sandbox limita:
- Acesso ao sistema de arquivos (principalmente somente leitura ao arquivo que está sendo pré-visualizado)
- Acesso à rede (restrito)
- IPC (mach-lookup limitado)

No entanto, a sandbox possui vetores de escape conhecidos:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVEs do mundo real

| CVE | Descrição |
|---|---|
| CVE-2019-8741 | Corrupção de memória no Quick Look preview via arquivo especialmente criado |
| CVE-2018-4293 | Quick Look generator sandbox escape |
| CVE-2020-9963 | Divulgação de informações no processamento do Quick Look preview |
| CVE-2021-30876 | Corrupção de memória na geração de miniaturas |

## Fuzzing Quick Look Generators
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
## Referências

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
