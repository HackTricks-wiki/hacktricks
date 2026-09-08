# Operativni sistemi usmereni na privatnost

Operativni sistemi usmereni na privatnost smanjuju greške u rutiranju i perzistenciji, ali nijedan ne može nadoknaditi ponašanje koje otkriva identitet ili kompromitovan hardver.

## Izaberite model izolacije

| Sistem | Najbolja namena | Perzistencija | Mrežno sprovođenje | Glavni kompromis |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Povremeno anonimno pregledanje veba | Stanje Browser-a je obično ograničeno na sesiju | Samo saobraćaj Browser-a | Druge aplikacije i host ostaju izvan Tor-a |
| **Tails** | Prenosive, amnezične sesije za jednu namenu | Opciono šifrovano Persistent Storage | Internet saobraćaj se usmerava kroz Tor | Ponovna pokretanja/otežan workflow; poverenje u firmware/hardver |
| **Whonix** | Perzistentne aplikacije kojima je potrebno prinudno Tor rutiranje | Perzistentne VM-ove | Podela na Gateway/Workstation | Host/hypervisor i mešanje identiteta ostaju problem |
| **Qubes-Whonix** | Snažno razdvajanje compartment-a za napredne korisnike | Po qube-u | Namenski network qubes i Whonix | Zahtevi hardvera i operativna složenost |

## Tails

Tails se nezavisno pokreće sa prenosivog medijuma, usmerava Internet saobraćaj kroz Tor i dizajniran je tako da ostavlja minimalno lokalno stanje. Njegova sopstvena upozorenja naglašavaju da ne može zaštititi od kompromitovanog BIOS-a/firmware-a/hardvera, otkrivanja identiteta, metapodataka datoteka ili moćnog posmatrača koji povezuje oba kraja.<sup>[[1]](#references)</sup>

### Workflow za Tails sa jednom namenom

1. Preuzmite Tails sa zvaničnog sajta na pouzdanom, ažuriranom računaru i pratite zvanični proces verifikacije/instalacije.
2. Koristite podržani USB drive samo za pokretanje Tails-a; nemojte ga koristiti i kao opšti drive za prenos datoteka.
3. Pokrenite sistem na hardveru koji fizički kontrolišete. Live OS ne može neutralisati hardverski keylogger ili zlonamerni firmware.
4. Ostavite Persistent Storage onemogućenim, osim ako ga workflow zaista zahteva. Ako je omogućen, sačuvajte samo neophodne kategorije i koristite snažnu passphrase.
5. Povežite se na zakonitu mrežu. Ako je captive portal neizbežan, koristite Tails' Unsafe Browser samo za portal, ne otkrivajte nepotrebne podatke o identitetu, odmah ga zatvorite i povežite se na Tor pre bilo kakve osetljive aktivnosti.<sup>[[2]](#references)</sup>
6. Konfigurišite Tor bridge ako su direktna vidljivost Tor-a ili blokiranje važni.
7. Obavljajte **jedan kontekstualni identitet/namenu po sesiji**. Tails preporučuje ponovno pokretanje između aktivnosti koje ne treba povezivati.<sup>[[1]](#references)</sup>
8. Pregledajte i očistite datoteke pre objavljivanja. Ne otvarajte preuzete aktivne dokumente u aplikaciji koja bi mogla zaobići predviđeni kontekst.
9. Potpuno ugasite sistem kada završite i fizički zaštitite USB.

## Whonix

Whonix razdvaja **Gateway** za Tor rutiranje od **Workstation-a**, čije aplikacije ne mogu direktno saznati eksternu IP adresu. Ovo značajno smanjuje greške sa proxy/DNS podešavanjima, ali host, hypervisor, ponašanje i dokumenti i dalje mogu otkriti identitet. Whonix izričito upozorava da se jedna Workstation ne koristi za više identiteta i da se ne kombinuju anonimne i neanonimne aktivnosti.<sup>[[3]](#references)</sup>

### Workflow za compartment-e

1. Verifikujte Whonix image i virtualization platform sa zvaničnih izvora.
2. Ažurirajte host, hypervisor, Gateway i Workstation pre korišćenja.
3. Klonirajte svežu Workstation za svaki identitet ili angažman; nikada ne klonirajte VM nakon uvođenja stanja koje sadrži identitet.
4. Držite lične naloge, shared folders na hostu, sinhronizaciju clipboard-a, USB uređaje i podatke o vremenu/lokaciji izvan Workstation-a.
5. Koristite snapshot-e za oporavak, a ne kao zamenu za backup ili razdvajanje identiteta.
6. Potvrdite da Workstation ne može pristupiti Internetu kada je Gateway zaustavljen.
7. Za naročito rizične datoteke koristite disposable VM/qube i izvezite samo očišćen rezultat.

## Qubes OS i Qubes-Whonix

Qubes primenjuje bezbednost compartmentalization-om, koristeći qubes zasnovane na Xen-u. Njegov dizajn ograničava mogućnost da kompromitovanje jednog domena automatski dosegne druge, ali aplikacije unutar **istog** qube-a nisu međusobno izolovane.<sup>[[4]](#references)</sup> Disposable qubes pružaju sveže stanje za nepouzdane sajtove, datoteke i uređaje.<sup>[[5]](#references)</sup>

Praktičan raspored:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Pravila:

- Dodelite svakom qube-u jedan nivo poverenja i svrhu identiteta.
- Čuvajte secrets u offline vault qube-u i koristite eksplicitne inter-qube operacije kopiranja/fajlova.
- Neželjene fajlove i linkove otvarajte u disposables.
- Kroz Whonix ili namenski VPN qube usmeravajte samo predviđene qube-ove.
- Jasno označite prozore i zaustavite nepovezane qube-ove tokom osetljivog rada.
- Nemojte pretpostavljati da dva qube-a sprečavaju korelaciju ako dele naloge, sadržaj, rasporede ili plaćanja.

## Verification and maintenance

- Proverite potpise/checksum-ove instalera prema zvaničnim uputstvima.
- Prvo ažurirajte template-e, zatim restartujte zavisne qube-ove/VM-ove.
- Potvrdite ponašanje pri zabrani mreže, DNS, IPv6, sat, clipboard, deljene direktorijume i dodelu USB uređaja.
- Pregledajte Persistent Storage i VM snapshots u potrazi za starim podacima koji otkrivaju identitet.
- Čuvajte šifrovane offline backup-e seed-ova/ključeva i testirajte njihovo vraćanje u izolovanom okruženju.
- Ponovo izgradite compartment nakon sumnje na compromise; promena izlazne IP adrese nije dovoljna.

## References

- [1] [Tails — Upozorenja: Tails je bezbedan, ali nije magičan](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Prijavljivanje na mrežu korišćenjem captive portala](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Ograničenja Whonix-a i Tor-a](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Ciljevi bezbednosnog dizajna](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Kako koristiti disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
