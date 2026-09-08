# Operativni sistemi usmereni na privatnost

{{#include ../banners/hacktricks-training.md}}

Operativni sistemi usmereni na privatnost smanjuju greške u rutiranju i postojanosti podataka, ali nijedan ne može da nadomesti ponašanje koje otkriva identitet ili kompromitovan hardver.

## Izaberite model izolacije

| Sistem | Najbolja namena | Postojanost podataka | Mrežno sprovođenje | Glavni kompromis |
|---|---|---|---|---|
| **Tor Browser on a maintained OS** | Povremeno anonimno pregledanje veba | Stanje Browser-a obično ograničeno na sesiju | Samo saobraćaj Browser-a | Druge aplikacije i host ostaju izvan Tor-a |
| **Tails** | Prenosive, amnezijske sesije za jednu namenu | Opciono šifrovano Persistent Storage | Internet saobraćaj se usmerava kroz Tor | Ponovna pokretanja i otežan tok rada; poverenje u firmware/hardver |
| **Whonix** | Persistent aplikacije kojima je potrebno obavezno Tor rutiranje | Persistent VM-ovi | Razdvajanje Gateway-a i Workstation-a | Host/hypervisor i mešanje identiteta ostaju mogući |
| **Qubes-Whonix** | Snažno razdvajanje compartment-a za napredne korisnike | Po qube-u | Namenski network qube-ovi i Whonix | Zahtevi hardvera i operativna složenost |

## Tails

Tails se nezavisno pokreće sa prenosivog medijuma, usmerava Internet saobraćaj kroz Tor i projektovan je tako da ostavlja minimalno lokalno stanje. Njegova sopstvena upozorenja naglašavaju da ne može da zaštiti od kompromitovanog BIOS-a/firmware-a/hardvera, otkrivanja identiteta, metapodataka datoteka ili moćnog posmatrača koji koreliše oba kraja.<sup>[[1]](#references)</sup>

### Tails tok rada za jednu namenu

1. Preuzmite Tails sa zvaničnog sajta na pouzdanom, ažuriranom računaru i pratite zvanični proces verifikacije i instalacije.
2. Koristite podržani USB disk samo za pokretanje Tails-a; nemojte ga koristiti i kao opšti disk za prenos datoteka.
3. Pokrenite sistem na hardveru koji fizički kontrolišete. Live OS ne može da neutrališe hardverski keylogger ili zlonamerni firmware.
4. Ostavite Persistent Storage onemogućenim, osim ako ga tok rada zaista zahteva. Ako ga omogućite, sačuvajte samo potrebne kategorije i koristite snažnu lozinku.
5. Povežite se na zakonitu mrežu. Ako je captive portal neizbežan, koristite Tails' Unsafe Browser samo za portal, ne otkrivajte nepotreban identitet, odmah ga zatvorite i povežite se na Tor pre bilo kakve osetljive aktivnosti.<sup>[[2]](#references)</sup>
6. Konfigurišite Tor bridge ako su direktna vidljivost Tor-a ili blokiranje važni.
7. Obavljajte **jedan kontekstualni identitet/namenu po sesiji**. Tails preporučuje ponovno pokretanje između aktivnosti koje ne bi trebalo povezivati.<sup>[[1]](#references)</sup>
8. Pregledajte i očistite datoteke pre objavljivanja. Nemojte otvarati preuzete aktivne dokumente u aplikaciji koja bi mogla da zaobiđe predviđeni kontekst.
9. Potpuno ugasite sistem kada završite i fizički zaštitite USB.

## Whonix

Whonix razdvaja Tor-rutirajući **Gateway** od **Workstation-a**, čije aplikacije ne mogu direktno da saznaju eksternu IP adresu. Ovo značajno smanjuje greške sa proxy-jem i DNS-om, ali host, hypervisor, ponašanje i dokumenti i dalje mogu otkriti identitet. Whonix izričito upozorava da se jedna Workstation ne koristi za više identiteta niti da se kombinuju anonimne i neanonimne aktivnosti.<sup>[[3]](#references)</sup>

### Tok rada sa compartment-ima

1. Verifikujte Whonix image i virtualization platform iz zvaničnih izvora.
2. Ažurirajte host, hypervisor, Gateway i Workstation pre upotrebe.
3. Klonirajte svežu Workstation za svaki identitet ili angažman; nikada nemojte klonirati VM nakon uvođenja stanja koje sadrži identitet.
4. Lične naloge, deljene foldere host-a, sinhronizaciju clipboard-a, USB uređaje i podatke o vremenu/lokaciji držite izvan Workstation-a.
5. Koristite snapshots za oporavak, a ne kao zamenu za backup ili razdvajanje identiteta.
6. Potvrdite da Workstation ne može da pristupi Internetu kada je Gateway zaustavljen.
7. Za naročito rizične datoteke koristite disposable VM/qube i izvezite samo očišćen rezultat.

## Qubes OS i Qubes-Whonix

Qubes implementira bezbednost compartmentalization-om pomoću qube-ova zasnovanih na Xen-u. Njegov dizajn ograničava mogućnost da kompromitovanje jednog domena automatski zahvati druge, ali aplikacije unutar **istog** qube-a nisu međusobno izolovane.<sup>[[4]](#references)</sup> Disposable qube-ovi obezbeđuju sveže stanje za nepouzdane sajtove, datoteke i uređaje.<sup>[[5]](#references)</sup>

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
- Čuvajte secrets u offline vault qube-u i koristite eksplicitne inter-qube copy/file operacije.
- Neželjene fajlove i linkove otvarajte u disposables.
- Usmeravajte samo predviđene qube-ove kroz Whonix ili namenski VPN qube.
- Jasno označite prozore i zaustavite nepovezane qube-ove tokom osetljivog rada.
- Nemojte pretpostaviti da dva qube-a sprečavaju korelaciju ako dele naloge, sadržaj, rasporede ili plaćanja.

## Verifikacija i održavanje

- Proverite potpise/checksum-e instalera prema zvaničnim uputstvima.
- Prvo zakrpite template-e, a zatim restartujte zavisne qube-ove/VM-ove.
- Potvrdite ponašanje pri zabrani mreže, DNS, IPv6, sat, clipboard, deljene direktorijume i USB assignment.
- Pregledajte Persistent Storage i VM snapshots u potrazi za starim podacima koji otkrivaju identitet.
- Čuvajte šifrovane offline backup-e seed-ova/ključeva i testirajte restoration u izolovanom okruženju.
- Ponovo izgradite compartment nakon sumnje na kompromitaciju; promena njegovog egress IP-ja nije dovoljna.

## References

- [1] [Tails — Upozorenja: Tails je bezbedan, ali nije magičan](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Prijavljivanje na mrežu korišćenjem captive portal-a](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Whonix i ograničenja Tor-a](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Ciljevi bezbednosnog dizajna](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Kako koristiti disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
