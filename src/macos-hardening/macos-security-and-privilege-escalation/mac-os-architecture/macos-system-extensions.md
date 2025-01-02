# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Za razliku od Kernel Extensions, **System Extensions se izvršavaju u korisničkom prostoru** umesto u kernel prostoru, smanjujući rizik od pada sistema zbog kvara ekstenzije.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Postoje tri tipa sistemskih ekstenzija: **DriverKit** ekstenzije, **Network** ekstenzije i **Endpoint Security** ekstenzije.

### **DriverKit Extensions**

DriverKit je zamena za kernel ekstenzije koje **obezbeđuju hardversku podršku**. Omogućava drajverima uređaja (kao što su USB, Serial, NIC i HID drajveri) da se izvršavaju u korisničkom prostoru umesto u kernel prostoru. DriverKit okvir uključuje **verzije određenih I/O Kit klasa u korisničkom prostoru**, a kernel prosleđuje normalne I/O Kit događaje u korisnički prostor, nudeći sigurnije okruženje za rad ovih drajvera.

### **Network Extensions**

Network Extensions pružaju mogućnost prilagođavanja mrežnih ponašanja. Postoji nekoliko tipova Network Extensions:

- **App Proxy**: Ovo se koristi za kreiranje VPN klijenta koji implementira protokol prilagođen VPN-u orijentisan na tok. To znači da upravlja mrežnim saobraćajem na osnovu veza (ili tokova) umesto pojedinačnih paketa.
- **Packet Tunnel**: Ovo se koristi za kreiranje VPN klijenta koji implementira protokol prilagođen VPN-u orijentisan na pakete. To znači da upravlja mrežnim saobraćajem na osnovu pojedinačnih paketa.
- **Filter Data**: Ovo se koristi za filtriranje mrežnih "tokova". Može pratiti ili modifikovati mrežne podatke na nivou toka.
- **Filter Packet**: Ovo se koristi za filtriranje pojedinačnih mrežnih paketa. Može pratiti ili modifikovati mrežne podatke na nivou paketa.
- **DNS Proxy**: Ovo se koristi za kreiranje prilagođenog DNS provajdera. Može se koristiti za praćenje ili modifikovanje DNS zahteva i odgovora.

## Endpoint Security Framework

Endpoint Security je okvir koji pruža Apple u macOS-u i koji obezbeđuje skup API-ja za bezbednost sistema. Namenjen je za korišćenje od strane **bezbednosnih provajdera i developera za izradu proizvoda koji mogu pratiti i kontrolisati aktivnost sistema** kako bi identifikovali i zaštitili se od zlonamernih aktivnosti.

Ovaj okvir pruža **kolekciju API-ja za praćenje i kontrolu aktivnosti sistema**, kao što su izvršenja procesa, događaji u datotečnom sistemu, mrežni i kernel događaji.

Osnova ovog okvira je implementirana u kernelu, kao Kernel Extension (KEXT) lociran u **`/System/Library/Extensions/EndpointSecurity.kext`**. Ovaj KEXT se sastoji od nekoliko ključnih komponenti:

- **EndpointSecurityDriver**: Ovo deluje kao "ulazna tačka" za kernel ekstenziju. To je glavno mesto interakcije između OS-a i Endpoint Security okvira.
- **EndpointSecurityEventManager**: Ova komponenta je odgovorna za implementaciju kernel hook-ova. Kernel hook-ovi omogućavaju okviru da prati događaje sistema presretanjem sistemskih poziva.
- **EndpointSecurityClientManager**: Ovo upravlja komunikacijom sa klijentima u korisničkom prostoru, prateći koji klijenti su povezani i treba da prime obaveštenja o događajima.
- **EndpointSecurityMessageManager**: Ovo šalje poruke i obaveštenja o događajima klijentima u korisničkom prostoru.

Događaji koje Endpoint Security okvir može pratiti su kategorizovani u:

- Događaji datoteka
- Događaji procesa
- Događaji soketa
- Kernel događaji (kao što su učitavanje/uklanjanje kernel ekstenzije ili otvaranje I/O Kit uređaja)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Komunikacija u korisničkom prostoru** sa Endpoint Security okvirom se dešava kroz IOUserClient klasu. Koriste se dve različite podklase, u zavisnosti od tipa pozivaoca:

- **EndpointSecurityDriverClient**: Ovo zahteva `com.apple.private.endpoint-security.manager` pravo, koje drži samo sistemski proces `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Ovo zahteva `com.apple.developer.endpoint-security.client` pravo. Ovo bi obično koristili softveri trećih strana za bezbednost koji treba da komuniciraju sa Endpoint Security okvirom.

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** je C biblioteka koju sistemske ekstenzije koriste za komunikaciju sa kernelom. Ova biblioteka koristi I/O Kit (`IOKit`) za komunikaciju sa Endpoint Security KEXT-om.

**`endpointsecurityd`** je ključni sistemski demon uključen u upravljanje i pokretanje sistemskih ekstenzija za bezbednost krajnjih tačaka, posebno tokom ranog procesa pokretanja. **Samo sistemske ekstenzije** označene sa **`NSEndpointSecurityEarlyBoot`** u njihovom `Info.plist` fajlu dobijaju ovu ranu obradu pokretanja.

Drugi sistemski demon, **`sysextd`**, **validira sistemske ekstenzije** i premesta ih na odgovarajuće sistemske lokacije. Zatim traži od relevantnog demona da učita ekstenziju. **`SystemExtensions.framework`** je odgovoran za aktiviranje i deaktiviranje sistemskih ekstenzija.

## Bypassing ESF

ESF se koristi od strane bezbednosnih alata koji će pokušati da otkriju red tim, tako da svaka informacija o tome kako se to može izbeći zvuči zanimljivo.

### CVE-2021-30965

Stvar je u tome da aplikacija za bezbednost mora imati **dozvole za pun pristup disku**. Dakle, ako bi napadač mogao da ukloni to, mogao bi sprečiti softver da se izvršava:
```bash
tccutil reset All
```
Za **više informacija** o ovom zaobilaženju i srodnim temama, pogledajte predavanje [#OBTS v5.0: "Ahilova peta EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Na kraju, ovo je ispravljeno davanjem nove dozvole **`kTCCServiceEndpointSecurityClient`** aplikaciji za bezbednost kojom upravlja **`tccd`**, tako da `tccutil` neće obrisati njene dozvole, sprečavajući je da ne može da se pokrene.

## Reference

- [**OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight**](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [**https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html**](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)

{{#include ../../../banners/hacktricks-training.md}}
