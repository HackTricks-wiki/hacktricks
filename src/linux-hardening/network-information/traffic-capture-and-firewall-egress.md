# Trijaža snimanja saobraćaja, firewall-a i egress-a

{{#include ../../banners/hacktricks-training.md}}

Nakon što pronađete [lokalne listenere i Unix sokete](local-network-and-socket-triage.md), proverite koji interfejsi prenose njihov saobraćaj i koja firewall ili proxy pravila utiču na dostupnost. Servis dostupan samo preko loopback interfejsa može da prenosi osetljiva HTTP zaglavlja čak i kada mu se ne može pristupiti sa drugog hosta.

## Proverite dozvole za snimanje i izaberite interfejs

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` može imati mogućnosti za hvatanje paketa čak i kada trenutni korisnik nema sudo pristup. Proverite stvarne mogućnosti izvršne datoteke i dozvole grupe. Snimajte na najmanjem korisnom broju interfejsa, tokom najkraćeg korisnog perioda i uz odgovarajući filter; snimak može sadržati akreditive ili lične podatke.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruiše TCP tokove u otvorenom tekstu; `tshark` može da filtrira snimak i izdvaja polja. Za TLS saobraćaj, dešifrovanje zahteva ključeve krajnjih tačaka ili podržanog klijenta konfigurisanog za `SSLKEYLOGFILE` pre uspostavljanja veze. [Stranica za trijažu lokalne mreže](local-network-and-socket-triage.md#tls-key-logging) prikazuje taj postupak. Nemojte tretirati šifrovani snimak kao čitljiv otvoreni tekst.

Sačuvani artefakti incidenta mogu da promene tu procenu. [Linux core dump je slika memorije procesa](https://man7.org/linux/man-pages/man5/core.5.html), u kojoj može da ostane ključ sesije; ako potiču od istog procesa i sesije, analitičar bi možda mogao da dešifruje saobraćaj pomoću čitljivog dump-a i snimka paketa. Najpre popišite putanje artefakata i dozvole, a zatim zasebno proverite identitet procesa, vreme snimanja, protokol i format ključa. Dešifrovani saobraćaj ili pronađena arhiva ukazuju na moguće otkrivanje podataka, ali ne dokazuju pristup tuđem nalogu: svaki delimični materijal SSH ključa i dalje treba rekonstruisati, upariti sa odgovarajućim javnim ključem i proveriti da li ga SSH pravila tog naloga prihvataju. Izbegavajte ispisivanje sadržaja core dump-a ili paketa u izlazima opšte enumeracije.

## Identifikujte slojeve firewall-а

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogu biti dostupni preko distribucijskih omotača kao što su UFW ili firewalld. Pregledajte aktivna pravila i sačuvanu konfiguraciju omotača; pravilo prikazano u jednom obliku možda je generisao drugi alat. Pre nego što blokiranu uslugu pripišete određenom pravilu, proverite interfejs, smer, izvor, odredište, protokol, port i stanje veze. Pogledajte [pregled nftables pravila](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) za konkretan primer.

## Testirajte egress i ponašanje proxy-ja

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Razlikujte DNS greške od TCP, TLS ili proxy grešaka. Testirajte konkretno odredište i protokol relevantne za procenu; dostupnost preko ICMP-a ne znači da je TCP ili UDP dozvoljen. Ako je proxy konfigurisan, uporedite zahtev koji treba da ide preko proxy-ja sa zahtevom ka istom odredištu prema odgovarajućim pravilima `no_proxy`. Lokalno prosleđivanje porta takođe može učiniti loopback servis dostupnim sa drugog mesta, zato proverite aktivne listenere i SSH tunele ako se prikaz firewall-a ne podudara sa uočenom izloženošću.
{{#include ../../banners/hacktricks-training.md}}
