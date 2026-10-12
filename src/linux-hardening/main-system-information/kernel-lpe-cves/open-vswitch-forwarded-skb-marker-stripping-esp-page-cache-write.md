# Open vSwitch uklanjanje oznake prosleđenog skb-a pri upisima u ESP keš stranica

{{#include ../../../banners/hacktricks-training.md}}

Korisna tehnika za eksploataciju Linux kernela jeste da se **očisti metapodatak o vlasništvu skb-a bez uklanjanja njegovih stranih fragmenata**, a zatim taj skb prosledi potrošaču koji upisuje direktno u njega. U slučaju Open vSwitch-a (OVS), neuspešan userspace upcall uklanja `SKBFL_SHARED_FRAG` sa još uvek aktivnog `MSG_ZEROCOPY` skb-a; ESP zatim dešifruje direktno preko folija keša stranica datoteke koja je samo za čitanje. To omogućava deterministički lokalni upis u keš stranica, a problem je praćen kroz CVE-2026-90049, CVE-2026-89487 i CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Ovo spada u klasu problema Copy Fail/Dirty Frag, a ne u klasičnu korupciju memorije: nije potrebna trka niti otkrivanje adrese, dovoljno je da datoteka bude čitljiva, a izmenjeni bajtovi postoje u kešu stranica, ne na disku.<sup>[[2]](#references)[[3]](#references)</sup>

## Bezbednosna invarijanta: strani fragmenti moraju ostati označeni

`SKBFL_SHARED_FRAG` ukazuje potrošačima koji upisuju direktno u podatke da fragment skb-a može da upućuje na memoriju koju ne poseduju privatno. ESP fast path u `esp_input()` može da dešifruje nelinearni, neklonirani skb direktno u mestu samo kada je `skb_has_shared_frag()` false; u suprotnom, `skb_cow_data()` prvo pravi privatnu memoriju. Ova provera na strani potrošača dodata je nakon problema Dirty Frag.<sup>[[5]](#references)</sup>

Invarijanta zato ima dva nezavisna dela:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Potrošači koji upisuju direktno u podatke moraju da provere `SKBFL_SHARED_FRAG` i kopiraju deljene podatke pre izmene.
2. Svaka putanja za kloniranje, spajanje, prenos ili prosleđivanje mora da sačuva oznaku dokle god je strana stranica pridružena.

Fragnesia je prekršila drugo pravilo prilikom premeštanja deskriptora fragmenata u `skb_try_coalesce()`. Putanja kroz OVS je suptilno drugačija: ona uopšte ne prenosi fragment; uklanja oznaku **direktno sa originalnog skb-a, a zatim nastavlja da ga prosleđuje**.<sup>[[2]](#references)[[4]](#references)</sup>

## OVS dostupan neprivilegovanim korisnicima

Datapath OVS-a u kernelu kontroliše se preko generic-netlink porodica kao što su `ovs_datapath`, `ovs_vport`, `ovs_flow` i `ovs_packet`. Njegove operacije koje menjaju stanje koriste namespace-aware `GENL_UNS_ADMIN_PERM`, pa proces pokrenut pod `unshare -Urn` dobija `CAP_NET_ADMIN`, neophodan za kreiranje datapath-a, priključivanje veth-a i instaliranje flow actions unutar sopstvenog network namespace-а. Razrešavanje OVS family може такође аутоматски učitati `openvswitch.ko`; za ovu površinu napada nisu potrebni host `CAP_SYS_MODULE`, `ovs-vsctl` ni `ovs-vswitchd`.<sup>[[2]](#references)[[7]](#references)</sup>

Važna je razlika između dve vrste upcall-a:<sup>[[2]](#references)[[7]](#references)</sup>

- **Flow miss** šalje paket procesu `ovs-vswitchd`; ako upcall ne uspe, paket se obično odbacuje.
- Eksplicitna akcija `OVS_ACTION_ATTR_USERSPACE` šalje pozajmljenu kopiju izabranom port ID-u, a zatim izvršava naredne akcije nad originalnim skb-om.

Napadač zato može da instalira flow sledećeg oblika:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Nijedan listener ne poseduje izabrani port ID, zbog čega userspace akcija predvidljivo ne uspeva, dok naredna akcija `OUTPUT` održava originalni paket aktivnim.<sup>[[1]](#references)[[2]](#references)</sup>

## Osnovni uzrok: `skb_tx_error()` nad paketom koji opstaje

Ranjiva OVS upcall putanja za obradu grešaka poziva `skb_tx_error(skb)`. Taj pomoćni program osmišljen je za neuspešan prenos nakon kog se skb oslobađa; on dovršava zerocopy bookkeeping pomoću `skb_zcopy_clear()`, чија je maska zastavica istorijski uklanjala i `SKBFL_SHARED_FRAG`. OVS je ignorisao grešku userspace akcije i nastavio listu akcija, čime je prekršio ugovor pomoćnog programa o životnom veku.<sup>[[1]](#references)[[2]](#references)</sup>

Iskoristivi prelaz stanja je:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Ovo funkcioniše samo kada `skb_zcopy()` pronađe zerocopy stanje. Fragment koji nosi samo `SKBFL_SHARED_FRAG` nije dovoljan; `MSG_ZEROCOPY` je koristan jer kreira `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` i postavlja i `SKBFL_DONT_ORPHAN`. Zbog ovog drugog, `skb_orphan_frags()` preskače zamenu stranica iz drugog izvora tokom OVS kopiranja u userspace.<sup>[[2]](#references)[[3]](#references)</sup>

## Izgradnja primitive za upis

Okidač od početka do kraja ima sledeće komponente.<sup>[[2]](#references)[[3]](#references)</sup>

1. Uđite u privatne korisničke i mrežne namespace-ove pomoću `unshare -Urn`.
2. Mapirajte ciljnu datoteku za čitanje pomoću `PROT_READ | MAP_SHARED`.
3. Koristite zaseban sender netns i veth par; lokalni loopback bi kopirao pozajmljene stranice i uništio primitivu.
4. Izgradite OVS datapath i tok `USERSPACE`-then-`OUTPUT` koji izaziva grešku.
5. Instalirajte XFRM stanje za ESP-in-UDP u transportnom režimu koristeći `rfc4106(gcm(aes))` i UDP port 4500.
6. Pošaljite jedan `MSG_ZEROCOPY` datagram sa iovec-om oblika `[ESP header | mapped file bytes | invalid ICV]`.

XFRM stanje koristi 20 bajtova ključnog materijala za AES-128-GCM: 16 bajtova AES ključa, iza kojih slede četiri bajta RFC 4106 salt-a. Za izabrani eksplicitni IV od osam bajtova, poverljivost sadržaja počinje brojačkim blokom `salt || IV || be32(2)`; vrednost brojača 1 umesto toga maskira rezultat autentifikacije.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Kada OVS ukloni marker, ESP koristi svoju no-copy putanju i izvršava `plaintext = ciphertext XOR keystream` nad fragmentom koji potiče iz datoteke. Provera autentičnosti se obavlja **nakon** ove transformacije, tako da neispravan ICV sastavljen od nula dovodi do pada paketa sa `-EBADMSG` tek pošto su bajtovi keš-stranice već izmenjeni.<sup>[[2]](#references)</sup>

### Pretvaranje GCM-a u izabrane bajtove

Za trenutni bajt `C` i željeni bajt `P`, prvi bajt keystream-a mora biti `C XOR P`. Pošto su AES ključ i salt fiksni, pretražite 16-bitni sufiks eksplicitnog IV-a i unapred izračunajte po jedan sufiks za svaki mogući prvi bajt keystream-a:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Javna implementacija ograničava ciphertext na 32 bajta i pomera fragment datoteke za jedan bajt za svaki paket. Izabrani prvi bajt prepisuje prethodni kolateralni bajt prethodnog paketa; `pread()` osvežava `C` pre svakog paketa, jednaki bajtovi se preskaču, a poslednji paket se skraćuje tako da upisi ne prelaze traženi opseg. Tako tabela pretrage sa 256 stavki pretvara primitivu u upis izabranog sadržaja u page cache na nivou bajta, uz približno jedan paket po različitom bajtu.<sup>[[2]](#references)[[3]](#references)</sup>

## Upis u page cache za dobijanje root pristupa

Praktična meta je postojeća izvršna datoteka sa setuid-root bitom. PoC zamenjuje prvih 160 bajtova kompletnim statičkim ELF-om koji sadrži jedan `PT_LOAD` sa fiksnom adresom i dozvolama za čitanje i izvršavanje, nema `PT_INTERP`, a njegov kod poziva `setuid(0)` pre `execve("/bin/sh", ...)`. Time se izbegavaju pretpostavke o ulaznoj tački originalnog binarnog fajla, PIE rasporedu, dinamičkom učitavaču ili relokacijama.<sup>[[2]](#references)[[3]](#references)</sup>

Izmena je vidljiva kroz user namespaces jer page cache nije vezan za namespace. Izmenjeni folio nije označen kao prljav, pa se neće upisati nazad na disk; izvršite metu dok je rezidentna, a zatim odbacite privremenu korupciju pomoću `posix_fadvise(..., POSIX_FADV_DONTNEED)` kako bi naredna čitanja ponovo učitala originalni sadržaj sa diska.<sup>[[2]](#references)[[3]](#references)</sup>

## Provere izloženosti i ublažavanje

Prvo proverite stvarni kernel dobavljača. Relevantni uslovi izloženosti su neprivilegovani user namespaces, dostupnost ili rezidentnost OVS-a i dostupna implementacija ESP-a.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Nadogradite na kernel koji sadrži kompletan niz ispravki; konačna popravka obuhvata putanju recirkulacije i izbegava izmenu deljenog stanja `skb_shinfo()`, a ujedno zatvara i povezani propust u `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Ako se OVS ne koristi, sprečite učitavanje i preko aliasa i po imenu pomoću `modprobe` pravila `install`, umesto da se oslonite samo na `blacklist`. Ako host ne završava IPsec veze, a ESP je modularan, ista kontrola može ukloniti i odredište za dešifrovanje.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Ova pravila ne pomažu ako je modul već učitan ili je funkcija ugrađena u kernel. Onemogućavanje neprivilegovanih korisničkih imenskih prostora uklanja i izvor mogućnosti za imenske prostore, ali može da pokvari rad browsera, Flatpak-a, Podman-a i drugih sandbox/container radnih opterećenja.<sup>[[2]](#references)</sup>

## Lekcije iz pregleda

Pri reviziji zero-copy umrežavanja, nemojte ograničiti pretragu na pomoćne funkcije koje kopiraju ili premeštaju fragmente. Identifikujte i pomoćne funkcije za obradu grešaka/završetka koje brišu grupisane oznake, a zatim proverite da li se svaki pozivalac pridržava dokumentovanog ugovora o životnom veku skb-a. Bit za vlasništvo nad stranicom, grupisan sa bitovima životnog ciklusa zerocopy-ja, bezbednosno je osetljiv čak i kada kod koji ga briše ne pristupa direktno nijednom fragmentu.<sup>[[1]](#references)[[2]](#references)</sup>

Robusna ispravka mora da obuhvati sve putanje kojima skb može da opstane—uključujući nastavak akcije i recirkulaciju—i mora da uzme u obzir klonove koji dele `skb_shinfo()`. Na strani potrošača, neuspešna autentifikacija ne poništava upise otvorenog teksta koji su već obavljeni in-place AEAD transformacijom, pa provere stranog skladišta moraju da se obave pre početka dešifrovanja.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev serija ispravki: net: ne uklanjati oznake zerocopy fragmenata sa prosleđenog skb-a](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Uklanjanje oznaka sa prosleđenog skb-a u Open vSwitch-u omogućava deterministički ESP page-cache LPE](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` dokaz koncepta](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Linux ispravka za originalnu putanju spajanja Fragnesia-e (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux provera deljenih fragmenata na strani ESP potrošača (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Upotreba režima Galois/Counter (GCM) u IPsec ESP-u](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Dokumentacija o putanji podataka kernela Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
