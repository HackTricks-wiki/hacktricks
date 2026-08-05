# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Za razliku od Kernel Extensions, **System Extensions se izvršavaju u korisničkom prostoru** umesto u prostoru kernela, čime se smanjuje rizik od pada sistema usled kvara ekstenzije.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Postoje tri tipa system extensions: **DriverKit** Extensions, **Network** Extensions i **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit je zamena za kernel extensions koje **obezbeđuju podršku za hardver**. Omogućava da se device drivers (kao što su USB, Serial, NIC i HID drivers) izvršavaju u korisničkom prostoru umesto u prostoru kernela. DriverKit framework obuhvata **user space verzije određenih I/O Kit klasa**, a kernel prosleđuje uobičajene I/O Kit događaje korisničkom prostoru, pružajući bezbednije okruženje za izvršavanje ovih drivera.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions omogućavaju prilagođavanje ponašanja mreže. Postoji nekoliko tipova Network Extensions:

- **App Proxy**: Koristi se za kreiranje VPN client-a koji implementira flow-oriented, custom VPN protocol. To znači da obrađuje mrežni saobraćaj na osnovu konekcija (ili flow-ova), a ne pojedinačnih paketa.
- **Packet Tunnel**: Koristi se za kreiranje VPN client-a koji implementira packet-oriented, custom VPN protocol. To znači da obrađuje mrežni saobraćaj na osnovu pojedinačnih paketa.
- **Filter Data**: Koristi se za filtering mrežnih "flow-ova". Može da nadgleda ili menja mrežne podatke na nivou flow-a.
- **Filter Packet**: Koristi se za filtering pojedinačnih mrežnih paketa. Može da nadgleda ili menja mrežne podatke na nivou paketa.
- **DNS Proxy**: Koristi se za kreiranje custom DNS provider-a. Može da se koristi za nadgledanje ili menjanje DNS zahteva i odgovora.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security je framework koji Apple obezbeđuje u macOS-u i koji pruža skup API-ja za bezbednost sistema. Namenjen je **security vendor-ima i developer-ima za izgradnju proizvoda koji mogu da nadgledaju i kontrolišu aktivnost sistema** kako bi identifikovali i sprečili malicious activity.

Ovaj framework pruža **kolekciju API-ja za nadgledanje i kontrolu aktivnosti sistema**, kao što su izvršavanja procesa, događaji u file system-u, mrežni i kernel događaji.

Osnovni deo ovog framework-a implementiran je u kernelu, kao Kernel Extension (KEXT) koji se nalazi na lokaciji **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> Ovaj KEXT sastoji se od nekoliko ključnih komponenti:

- **EndpointSecurityDriver**: Ovo služi kao "entry point" za kernel extension. To je glavna tačka interakcije između OS-a i Endpoint Security framework-a.
- **EndpointSecurityEventManager**: Ova komponenta je zadužena za implementaciju kernel hooks. Kernel hooks omogućavaju framework-u da nadgleda sistemske događaje presretanjem system calls.
- **EndpointSecurityClientManager**: Ova komponenta upravlja komunikacijom sa user space client-ima, vodeći evidenciju o tome koji su client-i povezani i koji treba da primaju obaveštenja o događajima.
- **EndpointSecurityMessageManager**: Ova komponenta šalje poruke i obaveštenja o događajima user space client-ima.

Događaji koje Endpoint Security framework može da nadgleda kategorizovani su na sledeći način:

- File events
- Process events
- Socket events
- Kernel events (kao što su učitavanje/uklanjanje kernel extension-a ili otvaranje I/O Kit device-a)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**User-space communication** sa Endpoint Security framework-om odvija se kroz IOUserClient klasu. Koriste se dve različite podklase, u zavisnosti od tipa pozivaoca:

- **EndpointSecurityDriverClient**: Ovo zahteva `com.apple.private.endpoint-security.manager` entitlement, koji poseduje samo sistemski proces `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Ovo zahteva `com.apple.developer.endpoint-security.client` entitlement. To bi obično koristio third-party security software kojem je potrebna interakcija sa Endpoint Security framework-om.<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** je C biblioteka koju system extensions koriste za komunikaciju sa kernelom. Ova biblioteka koristi I/O Kit (`IOKit`) za komunikaciju sa Endpoint Security KEXT-om.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** je ključni sistemski daemon uključen u upravljanje i pokretanje endpoint security system extensions, naročito tokom ranog procesa boot-ovanja. **Samo system extensions** označene sa **`NSEndpointSecurityEarlyBoot`** u svom `Info.plist` fajlu dobijaju ovaj tretman tokom ranog boot-ovanja.<sup>[[2]](#references)</sup>

Drugi sistemski daemon, **`sysextd`**, **validira system extensions** i premešta ih na odgovarajuće sistemske lokacije. Zatim od relevantnog daemon-a traži da učita extension. **`SystemExtensions.framework`** je zadužen za aktiviranje i deaktiviranje system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF koriste security tools koji će pokušati da otkriju red teamer-a, pa svaka informacija o tome kako bi se to moglo izbeći zvuči zanimljivo.

### CVE-2021-30965

Problem je u tome što security application mora da ima **Full Disk Access permissions**. Ako bi attacker mogao da ih ukloni, mogao bi da spreči pokretanje software-a:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Za **više informacija** o ovom bypass-u i srodnim bypass-ovima pogledajte predavanje [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Na kraju je ovo rešeno davanjem nove dozvole **`kTCCServiceEndpointSecurityClient`** bezbednosnoj aplikaciji kojom upravlja **`tccd`**, tako da `tccutil` više ne može da obriše njene dozvole i spreči njeno pokretanje.<sup>[[3]](#references)</sup>

## Reference

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - Interni detalji System Extension-a](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}
