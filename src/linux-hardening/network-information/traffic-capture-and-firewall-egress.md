# Verkeersvaslegging, firewall en egress-triage

{{#include ../../banners/hacktricks-training.md}}

Nadat jy [plaaslike luisteraars en Unix-sokke](local-network-and-socket-triage.md) opgespoor het, kyk watter koppelvlakke hul verkeer dra en watter firewall- of proxy-reëls bereikbaarheid beïnvloed. ’n Diens wat slegs op die loopback-koppelvlak luister, kan sensitiewe HTTP-opskrifte dra, selfs wanneer dit nie vanaf ’n ander gasheer bereikbaar is nie.

## Kontroleer vasleggingsregte en kies ’n koppelvlak

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` kan pakketvasleggingsvermoëns hê, selfs wanneer die huidige gebruiker geen sudo-toegang het nie. Gaan die uitvoerbare lêer se werklike vermoëns en groepstoestemmings na. Gebruik die kleinste nuttige koppelvlak, duur en filter vir die vaslegging; ’n vaslegging kan aanmeldbewyse of persoonlike data bevat.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstrueer plaintext TCP-strome; `tshark` kan verkeer filter en velde uit ’n capture onttrek. Vir TLS-verkeer vereis dekripsie endpoint-sleutels of ’n ondersteunde kliënt wat vóór die verbinding vir `SSLKEYLOGFILE` opgestel is. Die [plaaslike netwerk-triage-bladsy](local-network-and-socket-triage.md#tls-key-logging) wys dié werkvloei. Moenie ’n geënkripteerde capture as leesbare plaintext beskou nie.

Gestoorde insidentartefakte kan daardie beoordeling verander. ’n [Linux core dump is ’n beeld van prosesgeheue](https://man7.org/linux/man-pages/man5/core.5.html), wat moontlik ’n sessiesleutel bevat; as ’n leesbare dump en packet capture van dieselfde proses en sessie afkomstig is, kan ’n ontleder moontlik daardie verkeer dekripteer. Inventariseer eers artefakpaaie en toestemmings, en verifieer dan die prosesidentiteit, capture-tyd, protokol en sleutel-formaat afsonderlik. Gedepripteerde verkeer of ’n herstelde argief is ’n leidraad vir moontlike blootstelling, nie bewys van toegang tot ’n ander rekening nie: enige gedeeltelike SSH-sleutelmateriaal moet steeds gerekonstrueer word, met die ooreenstemmende publieke sleutel ooreenstem en deur daardie rekening se SSH-beleid aanvaar word. Moenie core-inhoud of capture-payloads in breë enumerasie-uitvoer dump nie.

## Identifiseer firewall-lae

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` en `iptables` kan via verspreidingswrappers soos UFW of firewalld beskikbaar wees. Lees die aktiewe reëls en die wrapper se gestoorde konfigurasie; ’n reël wat in een voorstelling sigbaar is, is dalk deur ’n ander nutsding gegenereer. Gaan die koppelvlak, rigting, bron, bestemming, protokol, poort en verbindingstoestand na voordat jy ’n geblokkeerde diens aan ’n spesifieke reël toeskryf. Sien [hersiening van nftables-reëls](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) vir ’n gefokusde voorbeeld.

## Toets uitgaande verkeer en proxy-gedrag

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Onderskei DNS-fout van TCP-, TLS- of proxy-fout. Toets die spesifieke bestemming en protokol wat vir die assessering relevant is; ICMP-bereikbaarheid beteken nie dat TCP of UDP toegelaat word nie. As ’n proxy opgestel is, vergelyk die beoogde proxied-versoek met ’n versoek na dieselfde teiken onder die toepaslike `no_proxy`-reëls. ’n Plaaslike poortaanstuurreël kan ook ’n loopback-diens elders beskikbaar stel, so hersien aktiewe luisteraars en SSH-tonnels wanneer die firewall-aansig en waargenome blootstelling nie ooreenstem nie.
{{#include ../../banners/hacktricks-training.md}}
