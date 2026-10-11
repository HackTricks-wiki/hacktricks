# Hvatanje saobraćaja, Firewall i trijaža izlaznog saobraćaja

{{#include ../../banners/hacktricks-training.md}}

Nakon što pronađete [lokalne listenere i Unix sokete](local-network-and-socket-triage.md), proverite koji interfejsi prenose njihov saobraćaj i koja pravila firewall-a ili proxy-ja utiču na dostupnost. Servis dostupan samo preko loopback interfejsa može prenositi osetljiva HTTP zaglavlja čak i kada nije dostupan sa drugog hosta.

## Proverite dozvole za hvatanje saobraćaja i izaberite interfejs

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` može imati mogućnosti hvatanja paketa čak i kada trenutni korisnik nema sudo pristup. Proverite stvarne mogućnosti izvršne datoteke i dozvole grupe. Snimajte na najmanjem korisnom mrežnom interfejsu, tokom najkraćeg korisnog trajanja i uz najrestriktivniji koristan filter; snimak može sadržati akreditive ili lične podatke.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruiše TCP tokove u otvorenom tekstu; `tshark` može da filtrira snimak i izdvaja polja iz njega. Za dešifrovanje TLS saobraćaja potrebni su ključevi krajnje tačke ili podržani klijent podešen da koristi `SSLKEYLOGFILE` pre uspostavljanja veze. [Stranica za trijažu lokalne mreže](local-network-and-socket-triage.md#tls-key-logging) prikazuje taj postupak. Nemojte pretpostaviti da se šifrovani snimak može čitati kao otvoren tekst.

Sačuvani artefakti incidenta mogu promeniti tu procenu. [Linux core dump je slika memorije procesa](https://man7.org/linux/man-pages/man5/core.5.html) koja može da sačuva ključ sesije; ako su čitljiv dump i snimak paketa potekli od istog procesa i sesije, analitičar možda može da dešifruje taj saobraćaj. Najpre popišite putanje artefakata i dozvole, a zatim zasebno proverite identitet procesa, vreme snimanja, protokol i format ključa. Dešifrovani saobraćaj ili pronađena arhiva ukazuju na moguće otkrivanje podataka, ali nisu dokaz pristupa drugom nalogu: svaki delimični materijal SSH ključa i dalje treba rekonstruisati, uporediti sa odgovarajućim javnim ključem i proveriti da li ga prihvata SSH politika tog naloga. Izbegavajte ispisivanje sadržaja core dump-a ili paketa u izlazu široke enumeracije.

## Utvrđivanje slojeva firewall-а

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogu biti dostupni preko distribucijskih omotača kao što su UFW ili firewalld. Pregledajte aktivna pravila i sačuvanu konfiguraciju omotača; pravilo prikazano u jednom obliku možda je generisao drugi alat. Pre nego što blokiranu uslugu pripišete određenom pravilu, proverite interfejs, smer, izvor, odredište, protokol, port i stanje veze. Pogledajte [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) za konkretan primer.

## Testiranje izlaznog saobraćaja i ponašanja proxy-ja

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Razdvojite DNS greške od grešaka TCP-a, TLS-a ili proxy-ja. Testirajte konkretno odredište i protokol relevantne za procenu; dostupnost preko ICMP-a ne znači da je TCP ili UDP dozvoljen. Ako je proxy konfigurisan, uporedite predviđeni zahtev preko proxy-ja sa zahtevom ka istom odredištu uz primenu odgovarajućih pravila `no_proxy`. `port forward` može i da učini uslugu na loopback interfejsu dostupnom drugde, zato proverite aktivne listenere i SSH tunele ako se prikaz zaštitnog zida i uočena izloženost ne podudaraju.
{{#include ../../banners/hacktricks-training.md}}
