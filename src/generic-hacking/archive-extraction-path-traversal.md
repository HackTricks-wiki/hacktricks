# Path Traversal pri ekstrakciji arhive ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Pregled

Mnogi formati arhiva (ZIP, RAR, TAR, 7-ZIP itd.) omogućavaju da svaki unos sadrži sopstvenu **internu putanju**. Kada alat za ekstrakciju slepo poštuje tu putanju, posebno kreirano ime fajla koje sadrži `..` ili **apsolutnu putanju** (npr. `C:\Windows\System32\`) biće zapisano van direktorijuma koji je korisnik izabrao.  
Ova vrsta ranjivosti poznata je kao *Zip-Slip* ili **path traversal pri ekstrakciji arhive**.<sup>[[6]](#references)</sup>

Posledice mogu biti od prepisivanja proizvoljnih fajlova do direktnog postizanja **remote code execution (RCE)** ubacivanjem payload-a na lokaciju koja se **automatski pokreće**, poput Windows fascikle *Startup*.

## Osnovni uzrok

1. Napadač pravi arhivu u kojoj jedno ili više zaglavlja fajlova sadrži:
   * Relativne sekvence za traversal (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Apsolutne putanje (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Ili posebno kreirane **symlinks** koje vode van ciljnog direktorijuma (često u ZIP/TAR arhivama na *nix* sistemima). 
2. Žrtva izdvaja arhivu pomoću ranjivog alata koji veruje ugrađenoj putanji (ili prati symlinks), umesto da je sanitizuje ili ograniči ekstrakciju na izabrani direktorijum.
3. Fajl se zapisuje na lokaciju koju kontroliše napadač, a izvršava/učitava se sledeći put kada sistem ili korisnik aktivira tu putanju.

### .NET `Path.Combine` + `ZipArchive` traversal

Čest .NET anti-pattern je kombinovanje predviđenog odredišta sa **korisnički kontrolisanim** `ZipArchiveEntry.FullName` i izdvajanje bez normalizacije putanje:<sup>[[4]](#references)[[8]](#references)</sup>

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

- Ako `entry.FullName` počinje sa `..\\`, dolazi do path traversal-a; ako je **apsolutna putanja**, leva komponenta se u potpunosti odbacuje, pa identitet ekstrakcije omogućava **arbitrary file write**.
- Proof-of-concept arhiva za upis u susedni direktorijum `app`, koji nadgleda zakazani skener:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Ubacivanje tog ZIP-a u nadgledani prijemni direktorijum dovodi do kreiranja datoteke `C:\samples\app\0xdf.txt`, što dokazuje path traversal van direktorijuma `C:\samples\queue\` i omogućava naknadne primitive (npr. DLL hijacks).

### Korenski direktorijum ekstrakcije pod kontrolom korisnika

Testirajte i **direktorijum prosleđen ekstraktoru**, a ne samo nazive članova arhive. Aplikacija može da odredi taj direktorijum na osnovu naslova, naziva projekta ili drugog polja zahteva. Vrednost kao što je `../../../../app/module` može da pomeri korenski direktorijum ekstrakcije van direktorijuma za otpremanje pre nego što ekstraktor obradi bilo koji član arhive. U tom slučaju, čak i arhiva koja sadrži samo bezbedno ime `api.py` može da prepiše kod aplikacije.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Ovo je zasebna granica izolacije u odnosu na klasični Zip-Slip. Proverite i razrešeni korenski direktorijum za ekstrakciju i putanju svakog razrešenog člana. Provera korena može da koristi komponente putanje umesto prefiksa niske:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Za bezbedan test, otpremite ispravnu arhivu koja sadrži jednu canary datoteku i postavite sekvence za path traversal u svako polje koje može da određuje direktorijum za raspakivanje. Pratite i predviđeni direktorijum i privremenu spoljašnju putanju. Ako odredište može da dosegne uvezeni modul, njegovo prepisivanje može dovesti do izvršavanja koda kada se workers ponovo učitaju; HTTP 500 ili prekid veze tokom tog ponovnog učitavanja ne dokazuju da upis nije uspeo.<sup>[[14]](#references)[[15]](#references)</sup> Pogledajte i širu [metodologiju za otpremanje datoteka](../pentesting-web/file-upload/).

## Napredni primitivni načini zaobilaženja zaštite arhiva

Posmatrajte raspakivanje kao niz izmena sistema datoteka, a ne kao nezavisne provere imena datoteka. Stavka koja je bezbedna kada se parsira može postati nebezbedna nakon što prethodni član arhive napravi ili zameni link; isti problem se javlja kada alat za raspakivanje kešira direktorijum kao bezbedan, a kasnije mu promeni tip.<sup>[[11]](#references)</sup>

### Link pivot-i i kolizije stavki

* **Symlink write-through**: napravite `pivot -> /tmp`, a zatim raspakujte običnu stavku kao `pivot/PWNED.txt`. Ako alat za raspakivanje prati prvi član dok materijalizuje drugi, upis izlazi iz predviđenog direktorijuma iako drugo ime ne sadrži `..`.
* **Kolizija keša direktorijuma/TOCTOU**: dodajte direktorijum `d/sub/`, zamenite `d/sub` symlink-om ka `/tmp`, a zatim dodajte `d/sub/PWNED.txt`. Ovo cilja alate za raspakivanje koji jednom provere ili keširaju direktorijum, a ne proveravaju ga ponovo pre završnog upisa.
* **Čitanje/prepisivanje preko hardlink-a**: TAR i RAR mogu da sadrže hardlink-ove. Hardlink ka postojećoj datoteci na hostu može da otkrije njen sadržaj ako neka kasnija komponenta posluži izdvojeno ime; kolidirajuća obična stavka umesto toga može da prepiše povezani inode. Ovo je ograničeno pravilima istog sistema datoteka i dozvolama operativnog sistema za hardlink-ove.
* **Postojeći ili međuarhivski pivot**: ponovite test sa odredištem koje nije prazno. Jedna arhiva može da postavi link, a naknadno raspakivanje može da upiše podatke preko njega, čak i ako svaka arhiva prođe stateless proveru imena u zaglavlju.<sup>[[11]](#references)</sup>

### Kolizije ekvivalentности sistema datoteka

Uporedite imena prema pravilima sistema datoteka u koji će se raspakovati arhiva. Korisni diferencijalni primeri obuhvataju `LINK` naspram `link` na sistemima datoteka koji ne razlikuju velika i mala slova, NFC naspram NFD zapisa Unicode znakova, ekvivalentna imena prema kompatibilnosti kao što su `ﬁle` naspram `file`, duplirane stavke koje menjaju putanju iz direktorijuma u symlink i obrnute kose crte koje se tumače kao separatori samo u Windows-u. Testirajte i imena koja sadrže ADS na NTFS-u. Ovi slučajevi mogu navesti validator da vidi dve putanje, iako ih sistem datoteka razrešava kao jednu.<sup>[[5]](#references)[[11]](#references)</sup>

Zato kompaktan skup testova treba da obuhvati uređene kombinacije **direktorijum → symlink → podređena stavka**, **symlink → kolidirajuća obična datoteka**, **hardlink → kolidirajuća obična datoteka**, mešavinu `/` i `\`, apsolutna/ukorenjena imena i kompresovane omotače kao što je `.tar.gz`. Pokrećite testove samo u privremenoj VM/container instanci i pratite i odredište i predviđenu spoljašnju canary putanju.<sup>[[11]](#references)</sup>

Strukturne dvosmislenosti specifične za ZIP mogu dovesti do toga da pred-skeniranje i stvarni alat za raspakivanje vide različita imena stavki ili različita stabla. Pogledajte [Zabuna između parsera lokalnog zaglavlja i centralnog direktorijuma](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion), umesto da verujete izlazu samo jedne ZIP biblioteke.

## Primer iz stvarnog sveta – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR za Windows i njegove Windows RAR/UnRAR komponente nisu validirali imena datoteka tokom raspakivanja. Ranjivost je koristila alternativne tokove podataka (ADS) u NTFS-u da zaobiđe izabranu putanju za raspakivanje i upiše datoteke na neželjene lokacije.<sup>[[5]](#references)</sup>
Zlonamerna RAR arhiva koja sadrži stavku kao što je:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

završila bi **izvan** izabranog izlaznog direktorijuma, a unutar korisnikove fascikle *Startup*. ESET je primetio da su zlonamerni LNK fajlovi raspakovani tamo i pokretani pri prijavljivanju korisnika, čime su obezbeđivali persistence i put do RCE-a.<sup>[[5]](#references)</sup>

### Pravljenje PoC arhive (Linux/Mac)

Pošto CVE-2025-8088 koristi traversal putanju u ADS imenu, koristite namenski generator za kreiranje RAR-a, a zatim testirajte raspakivanje samo u izolovanom labu sa ranjivom verzijom WinRAR-a.<sup>[[5]](#references)</sup>

### Uočeni napadi u divljini

ESET je prijavio spear-phishing kampanje grupe RomCom (Storm-0978/UNC2596) koje su sadržale RAR arhive koje su zloupotrebljavale CVE-2025-8088 za isporuku prilagođenih backdoor-a i olakšavanje ransomware operacija.<sup>[[5]](#references)</sup>

## Noviji slučajevi (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Greška**: ZIP unosi koji su **simboličke veze** razrešavani su tokom raspakivanja, što je napadačima omogućavalo da izađu iz odredišnog direktorijuma i prepišu proizvoljne putanje. Interakcija korisnika svodi se na *otvaranje/raspakivanje* arhive.<sup>[[1]](#references)</sup>
* **Pogođene verzije**: 7-Zip verzije starije od **25.00**. Greška u obradi simboličkih veza ispravljena je u verziji **25.00** (jul 2025) i kasnijim verzijama.<sup>[[1]](#references)[[10]](#references)</sup>
* **Putanja do uticaja**: Prepisivanje lokacija `Start Menu/Programs/Startup` ili lokacija sa pokrenutim servisima → kod se izvršava pri sledećem prijavljivanju ili ponovnom pokretanju servisa.
* **Primer za brzo testiranje obrade symlink-ova (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Ova arhiva sadrži symlink stavku koja pokazuje izvan direktorijuma za raspakivanje; koristite odredište za jednokratnu upotrebu i proverite da li je raspakivač ne prati. Test upisa kroz symlink zahteva i stavku obične datoteke ispod symlinka.

### Go mholt/archiver `Unarchive()` sudar symlinkova (CVE-2025-3445)
* **Greška**: `archiver.Unarchive()` može da raspakuje ZIP symlink, a zatim da ga razreši kada naredni običan član arhive ima isto ime, pretvarajući naizgled upis unutar korena u upis izvan njega.<sup>[[2]](#references)</sup>
* **Pogođeno**: `github.com/mholt/archiver` ≤ 3.5.1 (projekat je sada zastareo).<sup>[[2]](#references)</sup>
* **Ispravka**: Pređite na `mholt/archives` ≥ 0.1.0 ili odbacujte linkove i ponovo razrešavajte svako odredište neposredno pre otvaranja.<sup>[[2]](#references)</sup>
* **Minimalni generator sudara** (zatim pozovite `archiver.Unarchive("exploit.zip", "/tmp/safe")`):<sup>[[2]](#references)</sup>
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

Čak su i `tarfile.extractall(filter="data")` i `filter="tar"` bili podložni zaobilaženju pomoću redosleda linkova. U ovom slučaju, hardlink je upućivao na symlink arhiviran na dubljoj putanji; rezervni postupak ekstrakcije proverio je relativni symlink na toj dubljoj lokaciji, ali ga je ponovo kreirao na plićoj lokaciji hardlinka, gde je isti relativni cilj izlazio izvan dozvoljene putanje. Ovo je koristan opšti test: proverite da li se osnovni direktorijum ili konačni tip člana razlikuju između validacije i materijalizacije.<sup>[[12]](#references)</sup>

### Node `tar` hardlink target escape through a symlink chain (GHSA-83g3-92jg-28cx)

Paket Node.js `tar` u funkciji `tar.extract()` prihvatao je hardlink čiji je cilj izgledao kao da se leksički nalazi unutar dozvoljene putanje, ali se preko dva ranije kreirana symlinka razrešavao izvan korena ekstrakcije. Napad funkcioniše sa podrazumevanim opcijama ekstrakcije: provere roditeljskog direktorijuma odredišta obuhvatale su ime hardlinka unutar korena, dok se cilj hardlinka prosleđivao sistemu datoteka bez razrešavanja celog lanca radi provere da li ostaje unutar dozvoljene putanje. Pogođene su verzije `tar` ≤ 7.5.7; verzija 7.5.8 ispravlja problem.<sup>[[13]](#references)</sup>

Važno je testirati **redosledni odnos** između članova, a ne ove doslovne nazive:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Ako ekstrakcija uspe, `exfil` ostaje vidljivo unutar izlaznog stabla, ali deli inode sa izabranom spoljnom datotekom; čitanjem se ta datoteka leak-uje, a pisanjem se menja original. Ovaj zaobilazni postupak pokazuje zašto nije dovoljno proveravati samo konačnu putanju, uklanjati apsolutne prefikse ili blokirati `..` u zaglavlju hardlink-a: validirajte ciljeve linkova nakon primene celokupnog prethodno ekstrahovanog stanja fajl-sistema.<sup>[[13]](#references)</sup>

## Saveti za detekciju

* **Statički pregled** – Navedite i imena članova i ciljeve linkova. Označite `../`, `..\\`, apsolutne/ukorenjene putanje, symlink-ove, hardlink-ove, specijalne datoteke, duplirana imena, promene tipa i kolizije ekvivalentne po veličini slova/Unicode-u. Sačuvajte redosled stavki tokom pregleda jer exploit može zavisiti od ranijih članova.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Kanonikalizacija** – Osigurajte da razrešeni roditeljski direktorijum zajedno sa završnim imenom ostane unutar razrešenog odredišta (upoređujte komponente putanje, a ne sirovi prefiks stringa). Ponovo proverite nakon obrade svakog prethodnog člana arhive; jednokratna provera `realpath(join(dest, name))` ranjiva je na zamenu linka i može da ne uspe ako završni element još nije kreiran.<sup>[[3]](#references)[[11]](#references)</sup>
* **Ekstrakcija u sandboxu** – Raspakujte u nov, privremen direktorijum pomoću alata za ekstrakciju koji proverava putanje i simboličke linkove (na primer, podrazumevane bezbednosne provere u bsdtar-u ili 7-Zip ≥ 25.00), a zatim proverite da rezultujuće stablo ne sadrži linkove ka spolja. Izolacija mora da spreči da već pokrenuto bekstvo pristupi putanjama na hostu.<sup>[[1]](#references)[[9]](#references)</sup>
* **Važna su i naknadna čitanja** – Preživeli simbolički ili hard link može da omogući čitanje proizvoljnih datoteka kada previewer, CDN, pregledač datoteka ili pipeline paketa kasnije otvori ili posluži izdvojeno ime, čak i ako sama ekstrakcija nije kreirala datoteku van odredišta.<sup>[[11]](#references)</sup>
* **Nadgledanje krajnjih tačaka** – Upozorite na novokreirane izvršne datoteke u direktorijumima `Startup`/`Run`/`cron` ubrzo nakon otvaranja arhive pomoću WinRAR-a/7-Zip-a/itd.

## Ublažavanje i ojačavanje zaštite

1. **Ažurirajte alat za ekstrakciju** – WinRAR 7.13+, 7-Zip 25.00+ i Node `tar` 7.5.8+ sadrže ispravke za navedene probleme sa putanjama, simboličkim linkovima i odredištima linkova.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Kad god je moguće, raspakujte arhive uz opciju „**Ne raspakuj putanje**“ / „**Zanemari putanje**“. Za nepouzdan ulaz odbacite simboličke linkove, hard linkove, uređaje i FIFO datoteke, osim ako su aplikaciji izričito potrebni.<sup>[[9]](#references)[[11]](#references)</sup>
3. Raspakujte u **nov, prazan direktorijum**. Ne spajajte nepouzdane članove sa stablom koje sadrži putanje koje napadač može da zameni i ne koristite ponovo direktorijum koji je ranija arhiva već pripremila.<sup>[[11]](#references)</sup>
4. Na Unixu smanjite privilegije i izolujte odredište pomoću **chroot/mount namespace** okruženja; na Windowsu koristite **AppContainer** ili sandbox. Naknadna provera sama po sebi nije dovoljna jer do upisa van odredišta dolazi pre provere.<sup>[[11]](#references)</sup>
5. U prilagođenom kodu primenite pravila ciljnog OS-a za separatore, velika i mala slova i Unicode, i proverite i člana arhive i odredište linka. Razrešite i otvorite odredište bez praćenja linkova; nemojte razdvajati proveru da li je putanja unutar odredišta od kasnije operacije kreiranja/zamene. Validator mora da koristi istu osnovnu putanju i istu semantiku emulacije linkova kao putanja upisa.<sup>[[11]](#references)[[12]](#references)</sup>

## Dodatni pogođeni / istorijski slučajevi

* 2018 – Opsežno upozorenje *Zip-Slip* kompanije Snyk, koje se odnosilo na brojne Java/Go/JS biblioteke.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): TAR ekstrakcija sa traversal-om u slugovima (ispravljeno u v0.16.3).<sup>[[7]](#references)</sup>
* Svaka prilagođena logika ekstrakcije koja proverava stringove zaglavlja, ali ne i odredišta linkova i konačnu putanju u sistemu datoteka koja se koristi za svaki upis.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – ZIP traversal preko 7-Zip simboličkog linka (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – Zip-Slip u mholt/archiver (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Sprečavanje Zip Slip-a u .NET-u](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack lanac](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Ažurirajte WinRAR alate odmah: RomCom i drugi iskorišćavaju ranjivost nultog dana (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Javno obelodanjivanje kritične ranjivosti koja omogućava proizvoljno prepisivanje datoteka: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug je ranjiv na Zip Slip napad (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Metoda Path.Combine](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – Bezbedne zastavice za bsdtar ekstrakciju](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – Prijavljen proof-of-concept exploit za CVE-2025-11001 u 7-Zip-u](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Zabava sa zip-slip-ovima, tar-slip-ovima, simboličkim linkovima, hard linkovima, kolizijama i još mnogo toga](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – Zaobilaženje filtera za tarfile ekstrakciju, CVE-2026-11940](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – Izlazak iz odredišta hard linka u node-tar-u preko lanca simboličkih linkova](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – Korenski direktorijum za SCORM ekstrakciju pod kontrolom korisnika](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Više ranjivosti u Frappe LMS-u koje dovode do udaljenog izvršavanja koda](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
