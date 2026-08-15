# Path Traversal pri ekstrakciji arhiva ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi formati arhiva (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada alat za ekstrakciju slepo poštuje tu putanju, izrađeno ime datoteke koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće zapisano izvan direktorijuma koji je korisnik izabrao.
Ova klasa ranjivosti je široko poznata kao *Zip-Slip* ili **path traversal pri ekstrakciji arhiva**.<sup>[[6]](#references)</sup>

Posledice se kreću od prepisivanja proizvoljnih datoteka do direktnog postizanja **remote code execution (RCE)** ubacivanjem payload-a na lokaciju koja se **auto-run** pokreće, kao što je Windows *Startup* folder.

## Osnovni uzrok

1. Napadač kreira arhivu u kojoj jedno ili više zaglavlja datoteka sadrže:
* Relativne traversal sekvence (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ili izrađene **symlink-ove** koji se razrešavaju izvan ciljnog direktorijuma (uobičajeno kod ZIP/TAR na *nix* sistemima).
2. Žrtva ekstraktuje arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlink-ove), umesto da je sanitizuje ili prisili ekstrakciju unutar izabranog direktorijuma.
3. Datoteka se zapisuje na lokaciju pod kontrolom napadača i izvršava/učitava sledeći put kada sistem ili korisnik pokrene tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Čest .NET anti-pattern je kombinovanje predviđenog odredišta sa **user-controlled** `ZipArchiveEntry.FullName` i ekstrakcija bez normalizacije putanje:<sup>[[4]](#references)[[8]](#references)</sup>
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
- Ako `entry.FullName` počinje sa `..\\`, dolazi do traversal-a; ako je **apsolutna putanja**, leva komponenta se u potpunosti odbacuje, što kao identitet ekstrakcije omogućava **arbitrary file write**.
- Proof-of-concept archive za upis u susedni `app` direktorijum koji nadgleda scheduled scanner:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Ubacinje tog ZIP-a u nadzirani inbox rezultuje fajlom `C:\samples\app\0xdf.txt`, čime se dokazuje traversal van `C:\samples\queue\` i omogućavaju naknadne primitive (npr. DLL hijacks).

## Advanced Archive-Breakout Primitives

Posmatrajte extraction kao niz filesystem mutacija, a ne kao nezavisne provere naziva fajlova. Entry koji je bezbedan prilikom parsiranja može postati nebezbedan nakon što prethodni member kreira ili zameni link; isti problem se javlja kada extractor kešira direktorijum kao bezbedan, a zatim mu se promeni tip.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: kreirajte `pivot -> /tmp`, zatim extractujte regularni member kao `pivot/PWNED.txt`. Ako extractor prati prvi member prilikom materializacije drugog, upis izlazi izvan predviđene lokacije bez `..` u drugom nazivu.
* **Directory-cache/TOCTOU collision**: emitujte direktorijum `d/sub/`, zamenite `d/sub` symlinkom ka `/tmp`, zatim emitujte `d/sub/PWNED.txt`. Ovo cilja extractore koji jednom validiraju ili keširaju direktorijum i ne proveravaju ga ponovo pre konačnog upisa.
* **Hardlink read/overwrite**: TAR i RAR mogu predstavljati hardlinkove. Hardlink ka postojećem host fajlu može otkriti njegov sadržaj ako kasnija komponenta posluži extractovani naziv; kolidirajući regularni entry umesto toga može prepisati povezani inode. Ovo je ograničeno pravilima istog filesystema i dozvolama OS-a za hardlinkove.
* **Pre-existing or cross-archive pivot**: ponovite pokušaj sa destinacijom koja nije prazna. Jedan archive može postaviti link, a kasnija extraction može pisati kroz njega čak i ako svaki archive prođe stateless proveru naziva u headeru.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

Upoređujte nazive koristeći semantiku filesystema koji će ih primiti. Korisni diferencijalni slučajevi uključuju `LINK` naspram `link` na case-insensitive filesystemima, NFC naspram NFD Unicode zapisa, compatibility-equivalent nazive kao što su `ﬁle` naspram `file`, duplicate membere koji menjaju putanju iz direktorijuma u symlink i backslash karaktere koji se tumače kao separatori samo na Windowsu. Takođe testirajte nazive koji sadrže ADS na NTFS-u. Ovi slučajevi mogu dovesti do toga da validator vidi dve putanje, dok filesystem razrešava jednu.<sup>[[5]](#references)[[11]](#references)</sup>

Kompaktan corpus zato treba da testira uređene kombinacije **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, mešane `/` i `\`, absolute/rooted nazive i compressed wrappers kao što je `.tar.gz`. Pokrenite ga samo u disposable VM/containeru i nadgledajte i destinaciju i predviđenu canary putanju izvan nje.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows i njegove Windows RAR/UnRAR komponente nisu uspevali da validiraju nazive fajlova tokom extraction-a. Propust je koristio NTFS alternate data streams (ADS) za zaobilaženje izabrane extraction putanje i upis fajlova na nenamerne lokacije.<sup>[[5]](#references)</sup>
Malicious RAR archive koji sadrži entry kao što je:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
završio bi **izvan** izabranog izlaznog direktorijuma i unutar korisnikovog *Startup* foldera. ESET je uočio da su se tamo raspakovali zlonamerni LNK fajlovi i izvršavali prilikom prijavljivanja korisnika, čime su obezbeđivali persistence i putanju do RCE.<sup>[[5]](#references)</sup>

### Kreiranje PoC Archive-a (Linux/Mac)

Pošto CVE-2025-8088 koristi traversal path u ADS imenu, koristite namenski generator za kreiranje RAR-a, a zatim testirajte ekstrakciju samo u izolovanoj lab environment sa ranjivom WinRAR verzijom.<sup>[[5]](#references)</sup>

### Uočena Eksploatacija u Wild-u

ESET je prijavio spear-phishing campaigns grupe RomCom (Storm-0978/UNC2596), koje su priloženim RAR arhivama zloupotrebljavale CVE-2025-8088 za deployment prilagođenih backdoor-a i olakšavanje ransomware operations.<sup>[[5]](#references)</sup>

## Noviji Slučajevi (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries koji su **symbolic links** dereferencirani su tokom ekstrakcije, što je attacker-ima omogućavalo da napuste destination directory i prepišu proizvoljne putanje. Interakcija korisnika svodi se na *otvaranje/raspakivanje* archive-a.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip builds pre **25.00**. Flaw u obradi symbolic link-ova ispravljen je u verziji **25.00** (jul 2025) i novijim verzijama.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili lokacija koje pokreću servise → code se izvršava pri sledećem prijavljivanju ili restartu servisa.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Ovaj archive sadrži symlink entry koji pokazuje izvan extraction directory-ja; koristite disposable target i proverite da extractor ne prati taj link. Test upisivanja kroz link takođe zahteva regular-file entry ispod symlink-a.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` može da ekstrahuje ZIP symlink, a zatim da ga dereferencira kada kasniji regular member ima isto ime, pretvarajući naizgled upis unutar root-a u upis izvan root-a.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada deprecated).<sup>[[2]](#references)</sup>
* **Fix**: Pređite na `mholt/archives` ≥ 0.1.0 ili odbijajte link-ove i ponovo rešavajte svaku destination putanju neposredno pre njenog otvaranja.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (zatim pozovite `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

Čak su i `tarfile.extractall(filter="data")` i `filter="tar"` imali bypass-e zasnovane na redosledu link-ova. U ovom slučaju, hardlink je referencirao symlink arhiviran na dubljoj putanji; fallback extraction je validirao relativni symlink na toj dubokoj lokaciji, ali ga je ponovo kreirao na plićoj lokaciji hardlink-a, gde je isti relativni target izlazio iz dozvoljenog opsega. Ovo je koristan opšti test: napravite da se validation i materialisation ne slažu oko base directory-ja ili konačnog member type-a.<sup>[[12]](#references)</sup>

## Saveti za Detekciju

* **Static inspection** – Izlistajte i member names i link targets. Označite `../`, `..\\`, absolute/rooted paths, symlink-ove, hardlink-ove, special files, duplicate names, type changes i collisions ekvivalentne u pogledu velikih/malih slova ili Unicode-a. Tokom pregleda sačuvajte redosled entry-ja, jer exploit može zavisiti od prethodnih member-a.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Obezbedite da resolved parent zajedno sa final basename-om ostane ispod resolved destination-a (upoređujte path components, a ne raw string prefix). Ponovite proveru nakon svakog prethodnog member-a; jednokratni `realpath(join(dest, name))` test je ranjiv na zamenu link-a i može da ne uspe za leaf koji još nije kreiran.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Dekompresujte u svež, disposable directory koristeći extractor sa path/symlink checks (na primer, podrazumevane secure checks u bsdtar-u ili 7-Zip ≥ 25.00), a zatim proverite da rezultujuće stablo ne sadrži link-ove ka spolja. Isolation mora sprečiti da već aktivirani escape dosegne host paths.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Preživeli symlink ili hardlink može postati primitive za čitanje proizvoljnog fajla kada previewer, CDN, file browser ili package pipeline kasnije otvori ili posluži extracted name, čak i ako sama ekstrakcija nije kreirala nijedan fajl izvan predviđenog direktorijuma.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – Upozorite na nove izvršne fajlove upisane u `Startup`/`Run`/`cron` lokacije ubrzo nakon što korisnik otvori archive u WinRAR-u/7-Zip-u/itd.

## Mitigacija i Hardening

1. **Ažurirajte extractor** – WinRAR 7.13+ i 7-Zip 25.00+ sadrže ispravke za navedene path/symlink probleme.<sup>[[1]](#references)[[5]](#references)</sup>
2. Kada je moguće, ekstrahujte arhive uz “**Do not extract paths**” / “**Ignore paths**”. Za nepouzdan input odbijte symbolic links, hardlinks, devices i FIFOs, osim ako ih aplikacija izričito zahteva.<sup>[[9]](#references)[[11]](#references)</sup>
3. Ekstrahujte u **novi prazan direktorijum**. Ne spajajte nepouzdane member-e sa stablom koje sadrži path-ove zamenljive od strane attacker-a i ne koristite ponovo direktorijum koji je prethodni archive već pripremio.<sup>[[11]](#references)</sup>
4. Na Unix-u smanjite privileges i izolujte destination u **chroot/mount namespace**; na Windows-u koristite **AppContainer** ili sandbox. Sam post-extraction scan nije dovoljan, jer se escaped write dešava pre scan-a.<sup>[[11]](#references)</sup>
5. U custom code-u primenite separator/case/Unicode rules ciljnog OS-a i validirajte i member i link target. Resolve-ujte i otvorite destination bez praćenja link-ova; nemojte odvajati containment check od kasnije create/replace operation. Validator mora koristiti potpuno isti base i link-emulation semantics kao write path.<sup>[[11]](#references)[[12]](#references)</sup>

## Dodatni / Istorijski Slučajevi

* 2018 – Opsežno *Zip-Slip* upozorenje kompanije Snyk koje je uticalo na mnoge Java/Go/JS biblioteke.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal u slug-ovima (ispravljeno u v0.16.3).<sup>[[7]](#references)</sup>
* Bilo koja custom extraction logic koja validira header strings, ali ne i link targets i final filesystem path korišćen za svaki write.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Sprečavanje Zip Slip-a u .NET-u](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Odmah ažurirajte WinRAR alate: RomCom i drugi iskorišćavaju zero-day ranjivost (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Javno objavljivanje kritične ranjivosti za proizvoljno prepisivanje fajlova: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug ranjiv na Zip Slip napad (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar zastavice za bezbednu ekstrakciju](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Prijavljen Proof-of-Concept exploit za CVE-2025-11001 u 7-Zip-u](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Zabava sa zip-slip, tar-slip, symlink, hardlink, collision tehnikama i drugim metodama](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – bypass extraction filter-a u tarfile-u za CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
