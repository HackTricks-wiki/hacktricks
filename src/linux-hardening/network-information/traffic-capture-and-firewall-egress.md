# Hvatanje saobraćaja, firewall i brza procena izlaznog saobraćaja

{{#include ../../banners/hacktricks-training.md}}

Nakon što pronađete [lokalne listenere i Unix sokete](local-network-and-socket-triage.md), proverite preko kojih interfejsa prolazi njihov saobraćaj i koja firewall ili proxy pravila utiču na dostupnost. Servis dostupan samo preko loopback interfejsa i dalje može da prenosi osetljiva HTTP zaglavlja, iako mu se ne može pristupiti sa drugog hosta.

## Proverite dozvole za hvatanje saobraćaja i izaberite interfejs

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` može imati mogućnosti hvatanja paketa čak i kada trenutni korisnik nema sudo pristup. Proverite stvarne mogućnosti izvršne datoteke i dozvole grupe. Snimajte na najmanjem korisnom interfejsu, u najkraćem potrebnom trajanju i uz odgovarajući filter; snimak može sadržati akreditive ili lične podatke.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruiše nešifrovane TCP tokove; `tshark` može da filtrira i izdvaja polja iz capture-a. Za TLS saobraćaj, dešifrovanje zahteva ključeve endpoint-a ili podržani klijent konfigurisan za `SSLKEYLOGFILE` pre uspostavljanja veze. [Stranica o trijaži lokalne mreže](local-network-and-socket-triage.md#tls-key-logging) prikazuje taj postupak. Nemojte tretirati šifrovani capture kao čitljiv nešifrovani tekst.

Sačuvani artefakti incidenta mogu promeniti tu procenu. [Linux core dump je slika memorije procesa](https://man7.org/linux/man-pages/man5/core.5.html), koja može da sačuva ključ sesije; ako čitljiv dump i capture paketa potiču od istog procesa i sesije, analitičar možda može da dešifruje taj saobraćaj. Najpre popišite putanje artefakata i dozvole, a zatim zasebno proverite identitet procesa, vreme capture-a, protokol i format ključa. Dešifrovani saobraćaj ili oporavljena arhiva ukazuju na moguće otkrivanje podataka, ali ne dokazuju pristup nalogu druge osobe: svaki delimični materijal SSH ključa i dalje mora da se rekonstruiše, upari sa odgovarajućim javnim ključem i prihvati u skladu sa SSH pravilima tog naloga. Izbegavajte ispisivanje sadržaja core dump-a ili payload-a capture-a u širokom izlazu enumeracije.

## Identifikujte slojeve firewall-a

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogu biti izloženi preko distribucionih omotača kao što su UFW ili firewalld. Pročitajte aktivna pravila i sačuvanu konfiguraciju omotača; pravilo vidljivo u jednom prikazu možda je generisao neki drugi alat. Pre nego što blokiranu uslugu pripišete određenom pravilu, proverite interfejs, smer, izvor, odredište, protokol, port i stanje veze. Pogledajte [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) za konkretan primer.

## Testirajte egress i ponašanje proxy-ja

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Razlikujte greške DNS-a od grešaka TCP-a, TLS-a ili proxy-ja. Testirajte konkretno odredište i protokol relevantne za procenu; dostupnost preko ICMP-a ne znači da su TCP ili UDP dozvoljeni. Ako je proxy konfigurisan, uporedite predviđeni zahtev preko proxy-ja sa zahtevom ka istom odredištu uz primenu odgovarajućih pravila `no_proxy`. Lokalno prosleđivanje porta takođe može učiniti loopback servis dostupnim na drugom mestu, pa proverite aktivne listenere i SSH tunele ako se prikaz firewall-a ne poklapa sa utvrđenom izloženošću.
{{#include ../../banners/hacktricks-training.md}}
