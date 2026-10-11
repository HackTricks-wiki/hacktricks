# Verkeersvaslegging, firewall- en egress-triage

{{#include ../../banners/hacktricks-training.md}}

Nadat jy [plaaslike luisteraars en Unix-sokke](local-network-and-socket-triage.md) opgespoor het, inspekteer watter koppelvlakke hul verkeer dra en watter firewall- of proxy-reëls bereikbaarheid beïnvloed. ’n Diens wat net op loopback luister, kan sensitiewe HTTP-opskrifte dra, selfs wanneer dit nie vanaf ’n ander gasheer bereikbaar is nie.

## Kontroleer vasleggingsregte en kies ’n koppelvlak

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` kan pakkievasleggingsvermoëns hê selfs wanneer die huidige gebruiker nie sudo-toegang het nie. Gaan die uitvoerbare lêer se werklike vermoëns en groepstoestemmings na. Leg die kleinste bruikbare koppelvlak, duur en filter vas; ’n vaslegging kan aanmeldbesonderhede of persoonlike data bevat.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstrueer gewone teks-TCP-strome; `tshark` kan ’n capture filter en velde daaruit onttrek. Vir TLS-verkeer vereis dekripsie eindpuntsleutels of ’n ondersteunde kliënt wat voor die verbinding vir `SSLKEYLOGFILE` opgestel is. Die [plaaslike netwerk-triageblad](local-network-and-socket-triage.md#tls-key-logging) wys dié werksvloei. Moenie ’n geënkripteerde capture as leesbare gewone teks beskou nie.

Gestoorde insidentartefakte kan daardie beoordeling verander. ’n [Linux core dump is ’n beeld van prosesgeheue](https://man7.org/linux/man-pages/man5/core.5.html), wat moontlik ’n sessiesleutel behou; as ’n leesbare dump en pakkie-capture van dieselfde proses en sessie afkomstig is, kan ’n ontleder dalk daardie verkeer dekripteer. Inventariseer eers artefakpaaie en -toestemmings, en verifieer daarna afsonderlik die prosesidentiteit, capture-tyd, protokol en sleutel-formaat. Gedekripteerde verkeer of ’n herwonne argief is ’n leidraad vir moontlike openbaarmaking, nie bewys van toegang tot ’n ander rekening nie: enige gedeeltelike SSH-sleutelmateriaal moet steeds gerekonstrueer word, met die ooreenstemmende publieke sleutel ooreenstem en deur daardie rekening se SSH-beleid aanvaar word. Vermy dit om core-inhoud of capture-looiervragte in breë enumerasie-uitvoer te vertoon.

## Identifiseer firewall-lae

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` en `iptables` kan via verspreidingspakkie-omhulsels soos UFW of firewalld beskikbaar gestel word. Lees die aktiewe reëls en die omhulsel se gestoorde konfigurasie; ’n reël wat in een voorstelling sigbaar is, is dalk deur ’n ander nutsprogram gegenereer. Gaan die koppelvlak, rigting, bron, bestemming, protokol, poort en verbindingstoestand na voordat jy ’n geblokkeerde diens aan ’n spesifieke reël toeskryf. Sien [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) vir ’n gefokusde voorbeeld.

## Toets uitgaande verkeer en proxygedrag

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Onderskei DNS-fout van TCP-, TLS- of proxy-fout. Toets die spesifieke bestemming en protokol wat vir die assessering relevant is; ICMP-bereikbaarheid beteken nie dat TCP of UDP toegelaat word nie. As ’n proxy opgestel is, vergelyk die beoogde proxy-versoekte met dieselfde teiken onder die toepaslike `no_proxy`-reëls. ’n local port forward kan ’n loopback-diens ook elders beskikbaar maak, so hersien aktiewe listeners en SSH-tunnels wanneer die firewall-oorsig en waargenome blootstelling nie ooreenstem nie.
{{#include ../../banners/hacktricks-training.md}}
