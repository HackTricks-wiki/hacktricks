# Verkeersvaslegging, Firewall- en Egress-triage

{{#include ../../banners/hacktricks-training.md}}

Nadat jy [plaaslike luisteraars en Unix-sokke](local-network-and-socket-triage.md) opgespoor het, ondersoek watter koppelvlakke hul verkeer dra en watter firewall- of proxy-reëls die bereikbaarheid beïnvloed. ’n Diens wat net op loopback luister, kan sensitiewe HTTP-opskrifte dra, selfs wanneer dit nie vanaf ’n ander gasheer bereikbaar is nie.

## Gaan vasleggingsregte na en kies ’n koppelvlak

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` kan pakkievasleggingsvermoëns hê selfs wanneer die huidige gebruiker geen sudo-toegang het nie. Gaan die uitvoerbare lêer se werklike vermoëns en groepstoestemmings na. Leg slegs die kleinste nuttige koppelvlak, tydsduur en filter vas; ’n vaslegging kan geloofsbriewe of persoonlike data bevat.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstrueer plaintext TCP-strome; `tshark` kan ’n opname filtreer en velde daaruit onttrek. Vir TLS-verkeer vereis dekripsie eindpunt-sleutels of ’n ondersteunde kliënt wat voor die verbinding vir `SSLKEYLOGFILE` gekonfigureer is. Die [bladsy oor plaaslike netwerktriage](local-network-and-socket-triage.md#tls-key-logging) wys dié werkvloei. Moenie ’n geënkripteerde opname as leesbare plaintext beskou nie.

Gestoorde insidentartefakte kan daardie beoordeling verander. ’n [Linux core dump is ’n beeld van prosesgeheue](https://man7.org/linux/man-pages/man5/core.5.html), wat ’n sessiesleutel kan behou; as ’n leesbare dump en pakkie-opname van dieselfde proses en sessie kom, kan ’n ontleder moontlik daardie verkeer dekripteer. Inventariseer eers die artefakpaaie en toestemmings, en verifieer dan afsonderlik die prosesidentiteit, opnametyd, protokol en sleutel-formaat. Gedekripteerde verkeer of ’n herwonne argief is ’n leidraad van openbaarmaking, nie bewys van toegang tot ’n ander rekening nie: enige gedeeltelike SSH-sleutelmateriaal moet steeds gerekonstrueer word, met die ooreenstemmende publieke sleutel ooreenstem, en deur daardie rekening se SSH-beleid aanvaar word. Vermy dit om core-dump-inhoud of opname-loongedeeltes in breë enumerasie-uitvoer te wys.

## Identifiseer firewall-lae

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` en `iptables` kan via verspreidings-wrappers soos UFW of firewalld beskikbaar wees. Lees die aktiewe reëls en die wrapper se persistente konfigurasie; ’n reël wat in een voorstelling sigbaar is, is moontlik deur ’n ander nutsmiddel gegenereer. Gaan die koppelvlak, rigting, bron, bestemming, protokol, poort en verbindingstoestand na voordat jy ’n geblokkeerde diens aan ’n spesifieke reël toeskryf. Sien [nftables rule review](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes) vir ’n gefokusde voorbeeld.

## Toets egress- en proxygedrag

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Skei DNS-fout van TCP-, TLS- of proxy-foute. Toets die spesifieke bestemming en protokol wat vir die assessering relevant is; ICMP-bereikbaarheid beteken nie dat TCP of UDP toegelaat word nie. As ’n proxy ingestel is, vergelyk die beoogde versoek deur die proxy met dieselfde teiken onder die toepaslike `no_proxy`-reëls. ’n Plaaslike poortaanstuur kan ook ’n loopback-diens elders beskikbaar stel, dus hersien aktiewe luisteraars en SSH-tonnels wanneer die firewall-aansig en die waargenome blootstelling nie ooreenstem nie.
{{#include ../../banners/hacktricks-training.md}}
