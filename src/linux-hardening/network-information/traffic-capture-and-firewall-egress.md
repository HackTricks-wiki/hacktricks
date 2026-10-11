# Trijaža hvatanja saobraćaja, firewall-a i izlaznog saobraćaja

{{#include ../../banners/hacktricks-training.md}}

Nakon što pronađete [lokalne listening servise i Unix socket-e](local-network-and-socket-triage.md), proverite koji interfejsi prenose njihov saobraćaj i koja firewall ili proxy pravila utiču na dostupnost. Servis dostupan samo preko loopback interfejsa može prenositi osetljiva HTTP zaglavlja čak i kada mu se ne može pristupiti sa drugog hosta.

## Provera dozvola za snimanje i izbor interfejsa

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` može imati mogućnosti za hvatanje paketa čak i kada trenutni korisnik nema sudo pristup. Proverite stvarne capabilities izvršne datoteke i dozvole grupe. Snimajte na najmanjem korisnom interfejsu, u najkraćem korisnom trajanju i uz odgovarajući filter; snimak može sadržati akreditive ili lične podatke.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruiše TCP tokove u otvorenom tekstu; `tshark` može da filtrira i izdvoji polja iz snimka. Za TLS saobraćaj, dešifrovanje zahteva ključeve krajnjih tačaka ili podržani klijent konfigurisan za `SSLKEYLOGFILE` pre uspostavljanja veze. [Stranica za trijažu lokalne mreže](local-network-and-socket-triage.md#tls-key-logging) prikazuje taj postupak. Nemojte tretirati šifrovani snimak kao čitljiv otvoreni tekst.

Sačuvani artefakti incidenta mogu da promene tu procenu. [Linux core dump je slika memorije procesa](https://man7.org/linux/man-pages/man5/core.5.html), u kojoj može da ostane ključ sesije; ako čitljiv dump i snimak paketa potiču od istog procesa i sesije, analitičar možda može da dešifruje taj saobraćaj. Najpre popišite putanje artefakata i dozvole, a zatim zasebno proverite identitet procesa, vreme snimanja, protokol i format ključa. Dešifrovani saobraćaj ili vraćena arhiva ukazuju na moguće otkrivanje podataka, ali nisu dokaz pristupa drugom nalogu: svaki delimični materijal SSH ključa i dalje treba rekonstruisati, uporediti sa odgovarajućim javnim ključem i proveriti da li ga SSH politika tog naloga prihvata. Izbegavajte ispisivanje sadržaja core dump-a ili podataka iz snimka u izlazu opsežnog nabrajanja.

## Prepoznajte slojeve zaštitnog zida

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogu biti dostupni preko omotača distribucije, kao što su UFW ili firewalld. Pročitajte aktivna pravila i sačuvanu konfiguraciju omotača; pravilo prikazano u jednom obliku možda je generisao drugi alat. Pre nego što blokiranu uslugu pripišete određenom pravilu, proverite interfejs, smer, izvor, odredište, protokol, port i stanje veze. Pogledajte [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) za konkretan primer.

## Testirajte izlazni saobraćaj i ponašanje proxy-ja

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Razlikujte DNS grešku od greške na TCP-u, TLS-u ili proxy-ju. Testirajte konkretno odredište i protokol relevantne za procenu; dostupnost preko ICMP-a ne znači da je TCP ili UDP dozvoljen. Ako je proxy konfigurisan, uporedite predviđeni zahtev preko proxy-ja sa zahtevom ka istom odredištu prema primenljivim pravilima `no_proxy`. Lokalno prosleđivanje porta takođe može učiniti loopback servis dostupnim sa drugog mesta, zato proverite aktivne portove koji slušaju i SSH tunele kada se prikaz u firewall-u ne poklapa sa opaženom izloženošću.
{{#include ../../banners/hacktricks-training.md}}
