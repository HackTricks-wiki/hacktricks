# Générateurs Quick Look de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informations de base

Quick Look est le **framework de prévisualisation de fichiers** de macOS. Lorsqu’un utilisateur sélectionne un fichier dans Finder, appuie sur la barre d’espace, le survole ou consulte un répertoire avec les vignettes activées, Quick Look **charge automatiquement un plugin de générateur** pour analyser le fichier et afficher un aperçu visuel.<sup>[[1]](#references)</sup>

Les générateurs Quick Look sont des **bundles** (`.qlgenerator`) qui s’enregistrent pour des **Uniform Type Identifiers (UTIs)** spécifiques. Lorsque macOS a besoin d’un aperçu pour un fichier correspondant à cet UTI, il charge le générateur dans un processus auxiliaire sandboxé (`QuickLookSatellite` ou `qlmanage`) et appelle sa fonction de générateur.

### Pourquoi est-ce important pour la sécurité

> [!WARNING]
> Les générateurs Quick Look sont déclenchés par le fait de **sélectionner ou de consulter simplement un fichier** — aucune action « Open » n’est requise. Cela en fait un puissant **vecteur d’exploitation passive** : l’utilisateur doit simplement accéder à un répertoire contenant un fichier malveillant.

**Surface d’attaque :**
- Les générateurs **analysent le contenu de fichiers arbitraires** provenant du disque, de téléchargements, de pièces jointes d’e-mails ou de partages réseau
- Un fichier spécialement conçu peut exploiter des **vulnérabilités d’analyse** (dépassements de tampon, chaînes de format, confusion de types) dans le code du générateur
- Le rendu de l’aperçu s’effectue **automatiquement** — consulter un dossier Downloads dans lequel un fichier malveillant a été placé suffit
- Quick Look s’exécute dans un **helper sandboxé**, mais des sandbox escapes depuis ce contexte ont été démontrées

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

### Lister les générateurs installés
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
### Utilisation du Scanner
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## Scénarios d’attaque

### Exploitation basée sur les fichiers

Un Quick Look generator tiers qui analyse des formats de fichiers complexes (modèles 3D, données scientifiques, formats d’archives) constitue une cible de choix :
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
### Drive-By via les téléchargements
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Remplacement d’un Generator tiers

Si un bundle Quick Look generator est installé dans un **user-writable location** (`~/Library/QuickLook/`), il peut être remplacé :
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
## Considérations relatives au sandbox

Les générateurs Quick Look s’exécutent dans un processus auxiliaire sandboxé. Le profil sandbox limite :
- L’accès au système de fichiers (principalement en lecture seule pour le fichier prévisualisé)
- L’accès réseau (restreint)
- L’IPC (mach-lookup limité)

Cependant, le sandbox présente des vecteurs d’évasion connus :
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## CVE du monde réel<sup>[[2]](#references)</sup>

| CVE | Description |
|---|---|
| CVE-2019-8741 | Corruption de mémoire de l’aperçu Quick Look via un fichier conçu à cet effet |
| CVE-2018-4293 | Évasion du sandbox du générateur Quick Look |
| CVE-2020-9963 | Divulgation d’informations lors du traitement de l’aperçu Quick Look |
| CVE-2021-30876 | Corruption de mémoire lors de la génération des miniatures |

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
## References

- [1] [Apple Developer — Guide de programmation Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Mises à jour de sécurité Apple — CVE Quick Look](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
