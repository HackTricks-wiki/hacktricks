# Sistemske ekstenzije za macOS

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Za razliku od Kernel Extensions, **System Extensions se izvršavaju u korisničkom prostoru** umesto u prostoru kernela, čime se smanjuje rizik od pada sistema usled neispravnog rada ekstenzije.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Postoje tri vrste sistemskih ekstenzija: **DriverKit** Extensions, **Network** Extensions i **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit je zamena za kernel extensions koje **obezbeđuju podršku za hardver**. Omogućava da se device drivers, kao što su USB, Serial, NIC i HID drivers, izvršavaju u korisničkom prostoru umesto u prostoru kernela. DriverKit framework uključuje **user space verzije određenih I/O Kit klasa**, a kernel prosleđuje uobičajene I/O Kit događaje u korisnički prostor, pružajući bezbednije okruženje za izvršavanje ovih drivers.<sup>[2]</sup>

### **Network Extensions**

Network Extensions omogućavaju prilagođavanje ponašanja mreže. Postoji nekoliko vrsta Network Extensions:

- **App Proxy**: Koristi se za kreiranje VPN klijenta koji implementira flow-oriented, prilagođeni VPN protokol. To znači da obrađuje mrežni saobraćaj na osnovu konekcija (ili flow-ova), a ne pojedinačnih paketa.
- **Packet Tunnel**: Koristi se za kreiranje VPN klijenta koji implementira packet-oriented, prilagođeni VPN protokol. To znači da obrađuje mrežni saobraćaj na osnovu pojedinačnih paketa.
- **Filter Data**: Koristi se za filtriranje mrežnih "flow-ova". Može da nadgleda ili menja mrežne podatke na nivou flow-a.
- **Filter Packet**: Koristi se za filtriranje pojedinačnih mrežnih paketa. Može da nadgleda ili menja mrežne podatke na nivou paketa.
- **DNS Proxy**: Koristi se za kreiranje prilagođenog DNS provajdera. Može da se koristi za nadgledanje ili menjanje DNS zahteva i odgovora.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security je framework koji Apple obezbeđuje u macOS-u i koji pruža skup API-ja za bezbednost sistema. Namenjen je **security vendorima i developerima za izradu proizvoda koji mogu da nadgledaju i kontrolišu aktivnosti sistema** radi identifikovanja i zaštite od zlonamernih aktivnosti.

Ovaj framework pruža **kolekciju API-ja za nadgledanje i kontrolu aktivnosti sistema**, kao što su izvršavanje procesa, događaji u fajl sistemu, mrežni događaji i događaji kernela.

Jezgro ovog frameworka implementirano je u kernelu, kao Kernel Extension (KEXT), koja se nalazi na lokaciji **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> Ovaj KEXT se sastoji od nekoliko ključnih komponenti:

- **EndpointSecurityDriver**: Funkcioniše kao "ulazna tačka" za kernel extension. Predstavlja glavnu tačku interakcije između OS-a i Endpoint Security frameworka.
- **EndpointSecurityEventManager**: Ova komponenta je zadužena za implementaciju kernel hooks. Kernel hooks omogućavaju frameworku da nadgleda sistemske događaje presretanjem system calls.
- **EndpointSecurityClientManager**: Upravlja komunikacijom sa klijentima u korisničkom prostoru, vodeći evidenciju o tome koji su klijenti povezani i koji treba da primaju obaveštenja o događajima.
- **EndpointSecurityMessageManager**: Šalje poruke i obaveštenja o događajima klijentima u korisničkom prostoru.

Događaji koje Endpoint Security framework može da nadgleda kategorisani su na sledeći način:

- Događaji fajl sistema
- Događaji procesa
- Socket događaji
- Događaji kernela (kao što su učitavanje/uklanjanje kernel extension-a ili otvaranje I/O Kit uređaja)

### Arhitektura Endpoint Security Frameworka

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Komunikacija iz korisničkog prostora** sa Endpoint Security frameworkom odvija se preko klase IOUserClient. Koriste se dve različite podklase, u zavisnosti od tipa pozivaoca:

- **EndpointSecurityDriverClient**: Zahteva entitlement `com.apple.private.endpoint-security.manager`, koji poseduje samo sistemski proces `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Zahteva entitlement `com.apple.developer.endpoint-security.client`. Ovo bi obično koristio third-party security software koji mora da komunicira sa Endpoint Security frameworkom.<sup>[1]</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** je C biblioteka koju system extensions koriste za komunikaciju sa kernelom. Ova biblioteka koristi I/O Kit (`IOKit`) za komunikaciju sa Endpoint Security KEXT-om.<sup>[2]</sup>

**`endpointsecurityd`** je ključni system daemon zadužen za upravljanje i pokretanje endpoint security system extensions, naročito tokom ranog procesa bootovanja. **Samo system extensions** označene sa **`NSEndpointSecurityEarlyBoot`** u svom `Info.plist` fajlu dobijaju ovaj tretman tokom ranog bootovanja.<sup>[2]</sup>

Drugi system daemon, **`sysextd`**, **validira system extensions** i premešta ih na odgovarajuće sistemske lokacije. Zatim od relevantnog daemon-a zahteva da učita extension. **`SystemExtensions.framework`** je zadužen za aktiviranje i deaktiviranje system extensions.<sup>[2]</sup>

## Zaobilaženje ESF-a

ESF koriste security alati koji će pokušati da otkriju red teamer-a, pa svaka informacija o tome kako se to može izbeći zvuči zanimljivo.

### CVE-2021-30965

Problem je u tome što security aplikacija mora da ima **Full Disk Access permissions**. Ako bi napadač mogao da ih ukloni, mogao bi da spreči pokretanje software-a:<sup>[3]</sup>
```bash
tccutil reset All
```
Za **više informacija** o ovom bypassu i srodnim bypassovima pogledajte predavanje [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Na kraju je ovo rešeno dodeljivanjem nove dozvole **`kTCCServiceEndpointSecurityClient`** security aplikaciji kojom upravlja **`tccd`**, tako da `tccutil` neće obrisati njene dozvole i sprečiti njeno pokretanje.<sup>[3]</sup>

## Reference

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
