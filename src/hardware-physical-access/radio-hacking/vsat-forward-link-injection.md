# Ubrizgavanje signala u VSAT silaznu vezu

{{#include ../../banners/hacktricks-training.md}}

VSAT terminal obično tretira satelitsku silaznu vezu kao saobraćaj koji dolazi iz čvorišta operatora. U sistemu DVB-RCS, ta silazna veza može da prenosi i korisničke IP pakete i kontrolne poruke modema. Ako prijemnik ne proveri autentičnost poruke pre nego što je obradi, lokalno ubrizgan signal može da pređe granicu poverenja između radio-interfejsa i kontrolne ravni. Ovo je **ubrizgavanje u silaznu vezu na terminalu**, a ne uzlazna veza ka satelitu niti pasivno presretanje silazne veze. Ishod demonstracije zavisi od implementacije protokola i autentifikacije poruka na modemu, a ne samo od DVB-RCS-a.<sup>[[1]](#references)[[2]](#references)</sup>

## Testiranje u RF-izolovanoj laboratoriji

Koristite terminal koji posedujete, njegov firmware i SDR povezan na ulaz modema za prijem preko odgovarajućeg slabljenja signala, ili koristite RF-izolovano okruženje. Nemojte emitovati signal na aktivnom satelitskom kanalu. Najpre zabeležite podešeni početni nosilac, brzinu simbola i ID populacije terminala; te vrednosti pomažu pri uspostavljanju prijema silazne veze.<sup>[[1]](#references)[[3]](#references)</sup> Lanac uspostavljanja veze DVB-RCS koristi Network Information Table (NIT) da pronađe RCS Map Table (RMT), a zatim Program Association Table (PAT) i Program Map Table (PMT) da pronađe signalne tokove silazne veze. Terminal može da pređe na više nosilaca transportnog toka pre nego što stigne do toka podataka.<sup>[[3]](#references)</sup>

1. Dekodirajte ili ponovo sastavite početni transportni tok ciljnog uređaja i proverite njegov NIT, RMT, service ID-jeve, packet ID-jeve (PID-ove) i obradu časovne reference. Uporedite standard sa parserom i zapisima ciljnog uređaja; redosled ili deskriptori specifični za proizvođača mogu da spreče prihvatanje toka koji bi inače bio ispravan.
2. U laboratorijskom predajniku enkapsulirajte bezopasnu UDP probu kao `UDP/IP → MPE → MPEG-TS → DVB-S2 I/Q` i pošaljite je kroz SDR izlazni blok do izolovanog prijemnog puta. Uskladite Program Clock Reference (PCR) transportnog toka sa brzinom prenosa bajtova, inače modem može da izgubi sinhronizaciju pre nego što obradi probu.
3. Potvrdite i **zaključavanje demodulatora** i prijem probe na internom krajnjem uređaju koji posedujete. Samo zaključavanje dokazuje jedino da je fizički sloj prihvatio talasni oblik. Zatim proverite da li su dostupne neautentifikovane poruke za upravljanje ili *signalizacija* ažuriranja, bez instaliranja slike firmware-a ili menjanja konfiguracije usluge.

U objavljenom slučaju MDM2200 korišćen je GNU Radio izvorni modul za DVB-RCS/MPE/MPEG-TS i `gr-dtv` za DVB-S2 modulaciju. Modemu su bili potrebni detalji inicijalizacije specifični za ciljni uređaj: SDT pre PAT/PMT-a, RCS content descriptor sa ID-jem tabele `0x3E` i privatni bajt RMT-a `0x01` za njegov režim GSE/4CPM. Nemojte pretpostavljati da će te vrednosti raditi na drugom terminalu.<sup>[[1]](#references)</sup> Istraživači su takođe uočili da su multicast MPE paketi stizali do modema u prijemu u njihovom okruženju, pa ciljanje nije bilo ograničeno na poznatu unicast MAC adresu.<sup>[[1]](#references)</sup> Odvojena analiza otkrila je nezaštićenu kontrolnu signalizaciju i signalizaciju ažuriranja softvera u ispitivanom sistemu, ali taj nalaz treba proveriti za svaku implementaciju.<sup>[[2]](#references)</sup>

IPsec ili VPN tunel za korisnički saobraćaj ne autentifikuje raniju DVB-RCS signalizaciju niti parser za ažuriranja samog modema. Tokom ovlašćene procene razlikujte kriptografsku zaštitu **korisničkog IP saobraćaja**, **kontrole silazne veze** i saobraćaja **održavanja/oporavka**, umesto da bezbedan korisnički tunel smatrate dokazom da je ubrizgavanje putem radija blokirano.<sup>[[1]](#references)[[2]](#references)</sup>

Za početni pregled I/Q сигнала погледајте [анализу радио-сигнала](../hardware-hacking/radio.md). За анализу firmware-а и parser-а на нивоу плоче погледајте [анализу firmware-а](../firmware-analysis/). Вратите се на [преглед Radio Hacking-а](./) за друге интерфејсе.

## References

- [1] [Bisping et al. - Napadi ubrizgavanjem bežičnog signala na VSAT satelitske modeme (USENIX Security 2024)](https://www.usenix.org/system/files/usenixsecurity24-bisping.pdf)
- [2] [Willbold et al. - VSAsTer: Otkrivanje inherentnih bezbednosnih problema u aktuelnim praksama VSAT sistema (WiSec 2024)](https://www.lenders.ch/publications/conferences/wisec24.pdf)
- [3] [ETSI EN 301 790 - DVB interakcioni kanal za satelitske distributivne sisteme](https://www.etsi.org/deliver/etsi_en/301700_301799/301790/01.04.01_40/en_301790v010401o.pdf)
{{#include ../../banners/hacktricks-training.md}}
