# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi arhivski formati (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada alat za ekstrakciju slepo poštuje tu putanju, posebno ime datoteke koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće upisano izvan direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti poznata je kao *Zip-Slip* ili **path traversal pri ekstrakciji arhive**.<sup>[[6]](#references)</sup>

Posledice se kreću od prepisivanja proizvoljnih datoteka do direktnog postizanja **remote code execution (RCE)** ubacivanjem payload-a na lokaciju za **auto-run**, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu u kojoj jedno ili više zaglavlja datoteka sadrže:
* Relativne traversal sekvence (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili konstruisane **symlink-ove** koji se razrešavaju izvan ciljnog direktorijuma (uobičajeno kod ZIP/TAR arhiva na *nix* sistemima).
2. Žrtva izvlači arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlink-ove), umesto da je sanitizuje ili primora ekstrakciju unutar izabranog direktorijuma.
3. Datoteka se upisuje na lokaciju pod kontrolom napadača i izvršava/učitava sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Uobičajeni .NET anti-pattern je kombinovanje predviđenog odredišta sa `user-controlled` vrednošću `ZipArchiveEntry.FullName` i ekstrakcija bez normalizacije putanje:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Ako `entry.FullName` počinje sa `..\\`, omogućava traversal; ako je **absolute path**, komponenta sa leve strane se u potpunosti odbacuje, što kao identitet ekstrakcije dovodi do **arbitrary file write**.
- Proof-of-concept arhiva za upis u susedni `app` direktorijum koji nadgleda scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ubacinjem tog ZIP-a u nadzirani inbox dobija se `C:\samples\app\0xdf.txt`, čime se dokazuje traversal izvan `C:\samples\queue\` i omogućavaju naknadni primitives (npr. DLL hijacks).

## Napredni Archive-Breakout primitives

Posmatrajte extraction kao niz filesystem izmena, a ne kao nezavisne provere naziva fajlova. Entry koji je bezbedan prilikom parsiranja može postati nebezbedan nakon što prethodni member kreira ili zameni link; isti problem se pojavljuje kada extractor kešira direktorijum kao bezbedan, a zatim promeni njegov tip.<sup>[[11]](#references)</sup>

### Link pivots i kolizije entry-ja

* **Symlink write-through**: kreirajte `pivot -> /tmp`, a zatim extract-ujte regularni member kao `pivot/PWNED.txt`. Ako extractor prati prvi member prilikom materializacije drugog, upis izlazi iz dozvoljenog opsega bez `..` u drugom nazivu.
* **Directory-cache/TOCTOU collision**: generišite direktorijum `d/sub/`, zamenite `d/sub` symlink-om ka `/tmp`, a zatim generišite `d/sub/PWNED.txt`. Ovo cilja extractore koji jednom validiraju ili keširaju direktorijum i ne proveravaju ga ponovo pre završnog upisa.
* **Hardlink read/overwrite**: TAR i RAR mogu predstavljati hardlinkove. Hardlink ka postojećem host fajlu može otkriti njegov sadržaj ako kasnija komponenta posluži extract-ovani naziv; kolidirajući regularni entry umesto toga može prepisati povezani inode. Ovo je ograničeno pravilima istog filesystem-a i OS pravilima za dozvole hardlinkova.
* **Pre-existing ili cross-archive pivot**: pokušajte ponovo sa destinacijom koja nije prazna. Jedan archive može postaviti link, a kasniji extraction može pisati kroz njega čak i kada svaki archive prođe stateless proveru naziva u header-u.<sup>[[11]](#references)</sup>

### Kolizije ekvivalencije filesystem-a

Upoređujte nazive koristeći semantiku filesystem-a koji će ih primiti. Korisni differential slučajevi obuhvataju `LINK` naspram `link` na case-insensitive filesystem-ima, NFC naspram NFD Unicode zapisa, compatibility-equivalent nazive kao što su `ﬁle` naspram `file`, duplicate member-e koji menjaju putanju iz direktorijuma u symlink i backslash-ove koji se tumače kao separatori samo na Windows-u. Takođe testirajte ADS-bearing nazive na NTFS-u. Ovi slučajevi mogu dovesti do toga da validator vidi dve putanje, dok filesystem razrešava jednu.<sup>[[5]](#references)[[11]](#references)</sup>

Kompaktan corpus zato treba da testira uređene kombinacije **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mešane `/` i `\`, absolute/rooted nazive i compressed wrappers kao što je `.tar.gz`. Pokrenite ga samo u disposable VM/container-u i pratite i destinaciju i predviđenu canary putanju izvan nje.<sup>[[11]](#references)</sup>

ZIP-specific structural ambiguity može dovesti do toga da pre-scan i stvarni extractor vide različite entry nazive ili trees. Pogledajte [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), umesto da verujete izlazu samo jedne ZIP library.

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows i njegove Windows RAR/UnRAR komponente nisu uspevali da validiraju nazive fajlova tokom extraction-a. Flaw je koristio NTFS alternate data streams (ADS) za zaobilaženje izabrane extraction putanje i upis fajlova na nenamerne lokacije.<sup>[[5]](#references)</sup>
Malicious RAR archive koji sadrži entry kao što je:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
bi završio **izvan** izabranog izlaznog direktorijuma i unutar korisničkog foldera *Startup*. ESET je uočio da su se tamo raspakovali zlonamerni LNK fajlovi i izvršavali pri prijavljivanju korisnika, obezbeđujući persistence i putanju do RCE-a.<sup>[[5]](#references)</sup>

### Kreiranje PoC Archive-a (Linux/Mac)

Pošto CVE-2025-8088 koristi traversal putanju u ADS nazivu, koristite posebno napravljen generator za kreiranje RAR-a, a zatim testirajte extraction samo u izolovanoj labaratoriji sa ranjivom WinRAR verzijom.<sup>[[5]](#references)</sup>

### Uočena Eksploatacija u Wild-u

ESET je prijavio spear-phishing kampanje grupe RomCom (Storm-0978/UNC2596) koje su sadržale RAR archive-e koji zloupotrebljavaju CVE-2025-8088 za deploy prilagođenih backdoor-a i olakšavanje ransomware operacija.<sup>[[5]](#references)</sup>

## Noviji Slučajevi (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Greška**: ZIP entries koji su bili **symbolic links** dereferencirani su tokom extraction-a, što je napadačima omogućavalo da napuste odredišni direktorijum i prepišu proizvoljne putanje. Interakcija korisnika svodi se samo na *otvaranje/raspakivanje* archive-a.<sup>[[1]](#references)</sup>
* **Pogođeno**: 7-Zip build-ovi pre **25.00**. Greška u obradi symbolic-link-ova ispravljena je u verziji **25.00** (jul 2025) i novijim verzijama.<sup>[[1]](#references)[[10]](#references)</sup>
* **Putanja uticaja**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili lokacija koje pokreću servise → code se izvršava pri sledećem prijavljivanju ili restartovanju servisa.
* **Brzi fixture za obradu symlink-ova (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Ovaj archive sadrži symlink entry koji pokazuje izvan extraction direktorijuma; koristite disposable target i proverite da extractor ne prati symlink. Test prolaza upisa takođe zahteva regular-file entry ispod symlink-a.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Greška**: `archiver.Unarchive()` može da extract-uje ZIP symlink, a zatim da ga dereferencira kada kasniji regular member ima isto ime, pretvarajući naizgledni upis unutar root-a u upis izvan root-a.<sup>[[2]](#references)</sup>
* **Pogođeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada deprecated).<sup>[[2]](#references)</sup>
* **Ispravka**: Pređite na `mholt/archives` ≥ 0.1.0 ili odbijte linkove i ponovo razrešite svaku destination putanju neposredno pre njenog otvaranja.<sup>[[2]](#references)</sup>
* **Minimalni generator collision-a** (zatim pozovite `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython zaobilaženje filtriranog TAR extraction-a (CVE-2026-11940)

Čak su i `tarfile.extractall(filter="data")` i `filter="tar"` imali bypass-e zasnovane na redosledu linkova. U ovom slučaju, hardlink je referencirao symlink arhiviran na dubljoj putanji; fallback extraction je validirao relativni symlink na toj dubokoj lokaciji, ali ga je ponovo kreirao na plićoj lokaciji hardlink-a, gde je isti relativni target izašao iz dozvoljenog opsega. Ovo je koristan opšti test: učinite da se validation i materialisation ne slažu oko base direktorijuma ili konačnog tipa member-a.<sup>[[12]](#references)</sup>

### Node `tar` bekstvo hardlink target-a kroz lanac symlink-ova (GHSA-83g3-92jg-28cx)

Node.js `tar` package-ov `tar.extract()` prihvatao je hardlink čiji je target izgledao kao da se leksički nalazi unutar dozvoljenog opsega, ali se kroz dva ranija symlink-a razrešavao izvan extraction root-a. Napad funkcioniše sa podrazumevanim extraction opcijama: provere parent-a destination-a obuhvatale su ime hardlink-a unutar root-a, dok je hardlink target prosleđen filesystem-u bez razrešavanja kompletnog lanca radi provere pripadnosti. `tar` ≤ 7.5.7 je pogođen; verzija 7.5.8 ispravlja problem.<sup>[[13]](#references)</sup>

Važan test fixture je **uređeni odnos** između member-a, a ne ova konkretna imena:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Ako ekstrakcija uspe, `exfil` ostaje vidljiv unutar izlaznog stabla, ali deli inode sa izabranom spoljašnjom datotekom; njegovo čitanje izaziva leak te datoteke, a upis menja original. Ovaj bypass pokazuje zašto je nedovoljno proveravati samo konačnu putanju, uklanjati absolute prefikse ili blokirati `..` u hardlink header-u: ciljeve linkova treba validirati tek nakon primene celokupnog prethodno ekstrakovanog stanja filesystema.<sup>[[13]](#references)</sup>

## Saveti za detekciju

* **Statička inspekcija** – Izlistajte i nazive članova i ciljeve linkova. Označite `../`, `..\\`, absolute/rooted putanje, symlink-ove, hardlink-ove, special files, duplirane nazive, promene tipa i kolizije ekvivalentne po case/Unicode pravilima. Sačuvajte redosled stavki tokom pregleda jer exploit može zavisiti od ranijih članova.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # uređeni TAR članovi, tipovi i ciljevi linkova
7z l -slt suspect.7z          # tehnički metadata podaci, jedno polje po liniji
zipinfo -v suspect.zip        # ZIP metadata podaci centralnog direktorijuma i offset-i
```

* **Canonicalisation** – Uverite se da razrešeni parent zajedno sa konačnim basename-om ostaje unutar razrešenog odredišta (poredite komponente putanje, a ne sirovi string prefix). Ponovite proveru nakon svakog prethodnog člana; jednokratna provera `realpath(join(dest, name))` podložna je zameni linka i može neuspešno raditi za još-nekreirani leaf.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox ekstrakcija** – Dekomprimujte u nov, privremen direktorijum koristeći extractor sa proverama putanja/symlink-ova (na primer, podrazumevane bezbedne provere bsdtar-a ili 7-Zip ≥ 25.00), a zatim proverite da rezultujuće stablo ne sadrži outward linkove. Isolation mora sprečiti da već pokrenuti escape dosegne putanje hosta.<sup>[[1]](#references)[[9]](#references)</sup>
* **Naknadna čitanja su važna** – Preživeli symlink ili hardlink može postati primitive za arbitrary-file-read kada previewer, CDN, file browser ili package pipeline kasnije otvori ili posluži ekstrakovani naziv, čak i ako sama ekstrakcija nije kreirala nijednu spoljašnju datoteku.<sup>[[11]](#references)</sup>
* **Praćenje endpoint-a** – Generišite upozorenje na nove executable datoteke upisane na lokacije `Startup`/`Run`/`cron` ubrzo nakon što WinRAR/7-Zip/etc. otvori arhivu.

## Ublažavanje i hardening

1. **Ažurirajte extractor** – WinRAR 7.13+, 7-Zip 25.00+ i Node `tar` 7.5.8+ sadrže ispravke za navedene probleme sa path/symlink/link-target.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Kad god je moguće, ekstraktujte arhive sa opcijama “**Do not extract paths**” / “**Ignore paths**”. Za nepouzdan input odbijte symbolic links, hardlinks, devices i FIFO-ove, osim ako ih aplikacija izričito zahteva.<sup>[[9]](#references)[[11]](#references)</sup>
3. Ekstraktujte u **nov, prazan direktorijum**. Ne spajajte nepouzdane članove sa stablom koje sadrži putanje koje attacker može zameniti i ne koristite ponovo direktorijum koji je postavila ranija arhiva.<sup>[[11]](#references)</sup>
4. Na Unix-u smanjite privilegije i izolujte odredište u **chroot/mount namespace**; na Windows-u koristite **AppContainer** ili sandbox. Sam post-extraction scan nije dovoljan jer se escaped write dešava pre skeniranja.<sup>[[11]](#references)</sup>
5. U custom kodu primenite separator/case/Unicode pravila ciljnog OS-a i validirajte i član i cilj linka. Razrešite i otvorite odredište bez praćenja linkova; ne razdvajajte proveru containment-a od kasnije create/replace operacije. Validator mora koristiti potpuno isti base i link-emulation semantics kao write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Dodatni / istorijski pogođeni slučajevi

* 2018 – Massive *Zip-Slip* advisory kompanije Snyk koji je uticao na mnoge Java/Go/JS biblioteke.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal u slugovima (ispravljeno u v0.16.3).<sup>[[7]](#references)</sup>
* Bilo koja custom extraction logika koja validira header string-ove, ali ne i ciljeve linkova i konačnu filesystem putanju korišćenu za svaki upis.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Sprečavanje Zip Slip-a u .NET-u](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Ažurirajte WinRAR alate odmah: RomCom i drugi iskorišćavaju zero-day ranjivost (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Javno otkrivanje kritične ranjivosti za proizvoljno prepisivanje datoteka: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug ranjiv na Zip Slip napad (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bezbednosne zastavice za bsdtar ekstrakciju](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Prijavljen Proof-of-Concept exploit za CVE-2025-11001 u 7-Zip-u](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Zabava sa zip-slipovima, tar-slipovima, symlinkovima, hardlinkovima, kolizijama i drugim](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 bypass extraction filtera u tarfile-u](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar escape cilja hardlink-a kroz symlink lanac](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
