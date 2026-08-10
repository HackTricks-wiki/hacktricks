# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Pregled

Mnogi archive formati (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada extraction utility slepo poštuje tu putanju, crafted filename koji sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće upisan izvan direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je poznata kao *Zip-Slip* ili **archive extraction path traversal**.<sup>[[6]](#references)</sup>

Posledice mogu biti od prepisivanja proizvoljnih fajlova do direktnog ostvarivanja **remote code execution (RCE)** ubacivanjem payloada na lokaciju sa **auto-run** funkcijom, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Attacker kreira archive u kojem jedno ili više zaglavlja fajlova sadrže:
* Relative traversal sekvence (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili crafted **symlinks** koji se razrešavaju izvan ciljnog direktorijuma (uobičajeno kod ZIP/TAR na *nix* sistemima).
2. Victim extractuje archive pomoću ranjivog tool-a koji veruje ugrađenoj putanji (ili prati symlinks), umesto da je sanitizuje ili prisili extraction ispod izabranog direktorijuma.
3. Fajl se upisuje na lokaciju pod kontrolom attackera i izvršava/učitava sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Čest .NET anti-pattern je kombinovanje predviđenog odredišta sa **user-controlled** `ZipArchiveEntry.FullName` vrednošću i extraction bez normalizacije putanje:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Ako `entry.FullName` počinje sa `..\\`, dolazi do traversal-a; ako je **absolute path**, leva komponenta se u potpunosti odbacuje, što kao extraction identity omogućava **arbitrary file write**.
- Proof-of-concept arhiva za upis u susedni `app` direktorijum koji nadgleda skener pokretan po rasporedu:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ubaci­vanje tog ZIP-a u nadzirani inbox rezultuje fajlom `C:\samples\app\0xdf.txt`, što dokazuje traversal izvan `C:\samples\queue\` i omogućava naknadne primitive (npr. DLL hijacks).

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows i njegove Windows RAR/UnRAR komponente nisu uspevale da validiraju nazive fajlova tokom ekstrakcije. Propust je koristio NTFS alternate data streams (ADS) za zaobilaženje izabrane putanje za ekstrakciju i upisivanje fajlova na nenamerne lokacije.<sup>[[5]](#references)</sup>
Maliciozni RAR archive koji sadrži unos kao što je:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
bi završio **izvan** izabranog izlaznog direktorijuma i unutar korisničke *Startup* fascikle. ESET je uočio da su se tamo raspakovali zlonamerni LNK fajlovi i izvršavali pri prijavljivanju korisnika, obezbeđujući persistence i put do RCE.<sup>[[5]](#references)</sup>

### Pravljenje PoC arhive (Linux/Mac)

Pošto CVE-2025-8088 koristi traversal putanju u ADS imenu, koristite namenski generator za pravljenje RAR-a, a zatim testirajte ekstrakciju samo u izolovanoj lab okolini sa ranjivom WinRAR verzijom.<sup>[[5]](#references)</sup>

### Uočena eksploatacija u stvarnom svetu

ESET je prijavio spear-phishing kampanje grupe RomCom (Storm-0978/UNC2596) koje su sadržale RAR arhive sa zloupotrebom CVE-2025-8088 za postavljanje prilagođenih backdoor-a i olakšavanje ransomware operacija.<sup>[[5]](#references)</sup>

## Noviji slučajevi (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Greška**: ZIP stavke koje su **symbolic linkovi** dereferencirane su tokom ekstrakcije, što je napadačima omogućavalo da izađu iz odredišnog direktorijuma i prepišu proizvoljne putanje. Interakcija korisnika svodi se samo na *otvaranje/ekstrakciju* arhive.<sup>[[1]](#references)</sup>
* **Pogođeno**: 7-Zip build-ovi pre verzije **25.00**. Greška u obradi symbolic linkova ispravljena je u verziji **25.00** (jul 2025) i novijim verzijama.<sup>[[1]](#references)[[10]](#references)</sup>
* **Putanja uticaja**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili lokacija koje pokreću servisi → kod se izvršava pri sledećem prijavljivanju ili ponovnom pokretanju servisa.
* **Brza postavka za proveru obrade symlink-ova (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Ova arhiva sadrži symlink stavku koja pokazuje izvan direktorijuma za ekstrakciju; koristite disposable odredište i proverite da extractor ne prati taj link. Test upisivanja kroz link takođe zahteva regular-file stavku ispod symlink-a.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Greška**: `archiver.Unarchive()` prati `../` i symlinkovane ZIP stavke, upisujući izvan `outputDir`.<sup>[[2]](#references)</sup>
* **Pogođeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada deprecated).
* **Ispravka**: Pređite na `mholt/archives` ≥ 0.1.0 ili implementirajte provere canonical putanje pre upisa.
* **Minimalna reprodukcija**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Saveti za detekciju

* **Statička inspekcija** – Izlistajte stavke arhive i označite svako ime koje sadrži `../`, `..\\`, *apsolutne putanje* (`/`, `C:`) ili stavke tipa *symlink* čije je odredište izvan direktorijuma za ekstrakciju.
* **Canonicalisation** – Obezbedite da `realpath(join(dest, name))` ostane unutar `realpath(dest)` (upoređujte komponente putanje, a ne samo sirovi string prefix). U suprotnom odbijte stavku.<sup>[[3]](#references)</sup>
* **Sandbox ekstrakcija** – Dekompresujte u disposable direktorijum koristeći extractor sa proverama putanja/symlink-ova (na primer, podrazumevane bezbedne provere alata bsdtar ili 7-Zip ≥ 25.00), a zatim proverite da rezultujuće putanje ostaju unutar direktorijuma.<sup>[[1]](#references)[[9]](#references)</sup>
* **Nadgledanje endpoint-a** – Upozorite na nove executable fajlove upisane u lokacije `Startup`/`Run`/`cron` ubrzo nakon što je arhiva otvorena pomoću WinRAR-a/7-Zip-a/itd.

## Ublažavanje i hardening

1. **Ažurirajte extractor** – WinRAR 7.13+ i 7-Zip 25.00+ sadrže ispravke za navedene probleme sa putanjama/symlink-ovima.<sup>[[1]](#references)[[5]](#references)</sup>
2. Kada je moguće, izvlačite arhive uz opciju „**Do not extract paths**“ / „**Ignore paths**“.
3. Na Unix sistemima smanjite privilegije i montirajte **chroot/namespace** pre ekstrakcije; na Windows-u koristite **AppContainer** ili sandbox.
4. Ako pišete prilagođeni kod, normalizujte putanju pomoću `realpath()`/`PathCanonicalize()` **pre** kreiranja/upisa i odbijte svaku stavku koja izlazi iz odredišta.

## Dodatni pogođeni / istorijski slučajevi

* 2018 – Opsežno *Zip-Slip* upozorenje kompanije Snyk koje je uticalo na mnoge Java/Go/JS biblioteke.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) traversal tokom TAR ekstrakcije u slug-ovima (ispravljeno u verziji v0.16.3).<sup>[[7]](#references)</sup>
* Svaka prilagođena logika ekstrakcije koja ne pozove `PathCanonicalize` / `realpath` pre upisa.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink traversal u ZIP-u (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Sprečavanje Zip Slip-a u .NET-u](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Ažurirajte WinRAR alate odmah: RomCom i drugi iskorišćavaju zero-day ranjivost (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Javno otkrivanje kritične ranjivosti za proizvoljno prepisivanje fajlova: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug ranjiv na Zip Slip napad (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metod Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar zastavice za bezbednu ekstrakciju](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Prijavljen Proof-of-Concept exploit za CVE-2025-11001 u 7-Zip-u](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
