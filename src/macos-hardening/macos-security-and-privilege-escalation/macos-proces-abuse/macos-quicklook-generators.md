# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Quick Look est le framework d'aperçu de fichiers de macOS. Lorsque l'utilisateur sélectionne un fichier dans Finder, appuie sur Space, le survole, ou affiche un répertoire avec les vignettes activées, Quick Look charge automatiquement un plugin générateur pour analyser le fichier et afficher un aperçu visuel.

Quick Look generators sont des bundles (`.qlgenerator`) qui s'enregistrent pour des Uniform Type Identifiers (UTIs) spécifiques. Quand macOS a besoin d'un aperçu pour un fichier correspondant à cet UTI, il charge le generator dans un processus helper sandboxé (`QuickLookSatellite` ou `qlmanage`) et appelle sa fonction de génération.

### Pourquoi c'est important pour la sécurité

> [!WARNING]
> Quick Look generators sont déclenchés simplement en sélectionnant ou en affichant un fichier — aucune action "Ouvrir" n'est requise. Cela en fait un puissant vecteur d'exploitation passive : l'utilisateur a juste besoin de naviguer vers un répertoire contenant un fichier malveillant.

Surface d'attaque :
- Les générateurs analysent un contenu de fichier arbitraire provenant du disque, des downloads, des pièces jointes d'email ou des partages réseau
- Un fichier spécialement conçu peut exploiter des vulnérabilités de parsing (buffer overflows, format strings, type confusion) dans le code du générateur
- Le rendu de l'aperçu se produit automatiquement — afficher le dossier Downloads où un fichier malveillant a atterri suffit
- Quick Look s'exécute dans un helper sandboxé, mais des échappements de sandbox depuis ce contexte ont été démontrés

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
## Énumération

### Lister les Generators installés
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
### Utiliser le Scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Scénarios d'attaque

### Exploitation basée sur les fichiers

Un générateur Quick Look tiers qui analyse des formats de fichiers complexes (modèles 3D, données scientifiques, formats d'archive) est une cible de choix :
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
### Remplacement de générateurs tiers

Si un bundle de générateur Quick Look est installé dans un emplacement **modifiable par l'utilisateur** (`~/Library/QuickLook/`), il peut être remplacé :
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Déclencher Quick Look à distance
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Considérations sur le sandbox

Les Quick Look generators s'exécutent dans un helper process sandboxed. Le profil sandbox limite :
- Accès au système de fichiers (majoritairement en lecture seule pour le fichier en cours d'aperçu)
- Accès réseau (restreint)
- IPC (mach-lookup limité)

Cependant, le sandbox présente des escape vectors connus :
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVEs du monde réel

| CVE | Description |
|---|---|
| CVE-2019-8741 | Corruption de mémoire de l'aperçu Quick Look via un fichier spécialement conçu |
| CVE-2018-4293 | Évasion du sandbox du générateur Quick Look |
| CVE-2020-9963 | Divulgation d'informations lors du traitement de l'aperçu Quick Look |
| CVE-2021-30876 | Corruption de mémoire lors de la génération de vignettes |

## Fuzzing des générateurs Quick Look
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
## Références

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
