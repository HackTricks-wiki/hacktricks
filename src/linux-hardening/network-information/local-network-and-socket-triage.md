# Plaaslike netwerk- en sokettriage

{{#include ../../banners/hacktricks-training.md}}

Nadat jy 'n shell op 'n Linux-host verkry het, is die nuttigste netwerk-teikens dikwels nie ekstern blootgestel nie. Slegs-loopback-dienste, veth-netwerke, Unix-sockets, tydelike listeners, packet captures en plaaslike firewall-reëls kan credentials of plaaslike aanvalsvlakke blootstel.

Hierdie bladsy fokus op praktiese plaaslike post-exploitation-tegnieke, nie algemene afgeleë netwerk-pentesting nie.

## Loopback- en plaaslike diens-opsomming

Begin deur listeners, hul bind-adresse en die eienende proses te identifiseer wanneer toestemmings dit toelaat:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Belangrike patrone:

- `127.0.0.1:<port>` of `[::1]:<port>`: by verstek slegs vanaf die host bereikbaar.
- `0.0.0.0:<port>`: bereikbaar op alle IPv4-interfaces, tensy gefiltreer.
- `172.x`, `10.x`, of `192.168.x` op `veth*`, `docker*`, `br-*`, `cni*`: waarskynlik container- of plaaslike lab-netwerke.
- Unix sockets onder `/run`, `/var/run`, `/tmp`, of toepassingsgidse: plaaslike IPC-oppervlakke.

Karteer plaaslike poorte met liggewig probes:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Gebruik `nmap` plaaslik wanneer beskikbaar:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Verborge veth- en Container-subnette

Containerized- of labomgewings stel dikwels slegs dienste op ’n bridge- of veth-subnet bloot. Enumerate interfaces en roetes voordat jy aanvaar dat ’n diens onbereikbaar is:
```bash
ip -br addr
ip route
ip neigh
```
Vind waarskynlike plaaslike subnette:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Ondersoek 'n ontdekte subnet versigtig:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Die tegniek is nuttig wanneer ’n webpaneel, debug-endpoint of helper service vir eksterne skanderings versteek is, maar vanaf die gekompromitteerde host of houernetwerk bereikbaar is.

## Local Pivot met socat of SSH

As ’n service aan loopback gebind is, stel dit deur ’n toegelate kanaal bloot eerder as om die service self te verander.

Stuur ’n plaaslike HTTP-service met SSH aan:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Brug 'n plaaslike poort met `socat` wanneer jy reeds shell-toegang het:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Stuur 'n Unix-socket aan na TCP vir plaaslike toetsing:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Dit buit niks op sy eie uit nie. Dit maak ’n slegs-plaaslike oppervlak vanaf jou tooling bereikbaar, sodat jy daarmee kan interaksie hê soos met ’n normale diens.

## Banner Grabbing en Eenvoudige Protokolle

Nie elke diens is HTTP nie. Baie plaaslike dienste leak genoeg inligting deur ’n banner of eenreël-protokol.

Basiese probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
HTTP-kontrole sonder 'n blaaier:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Vir TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Die doel is om die protokol, verifikasieskema, weergawe en of die diens plaaslike kliënte vertrou, te identifiseer.

## Vaslegging van Loopback-verkeer

Plaaslike verkeer kan opskrifte, bearer tokens, Basic Auth-geloofsbriewe of toepassingspesifieke geheime blootlê. Leg slegs vas in gemagtigde omgewings.

Vang loopback HTTP-verkeer vas:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Vang ’n spesifieke plaaslike diens vas:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Dekodeer Basic Auth vanaf 'n vasgevangde of gelogde header:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Nuttige stringe om in teksvaslegginge na te soek:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

As jy die client process environment in ’n lab kan beheer, kan `SSLKEYLOGFILE` TLS-sessies in Wireshark of compatible tooling dekripteerbaar maak. Dit is nuttig om plaaslike HTTPS-verkeer te verstaan sonder om TLS self aan te val.

Run ’n client met key logging geaktiveer:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Vang die verkeer terselfdertyd vas:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Laai dan `/tmp/tls.pcap` en `/tmp/sslkeys.log` in Wireshark. Dit werk slegs wanneer die client library NSS-styl key logging ondersteun en jy die omgewing kan instel voordat die verbinding gemaak word.

## Unix-sok-interaksie en Command Injection

Unix-sockets is plaaslike IPC-endpoints. Hulle kan HTTP-API's, pasgemaakte protokolle of onveilige command handlers blootstel.

Vind sockets:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interaksie met HTTP oor ’n Unix-socket:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interaksie met 'n raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
As gebruiker-beheerde socket-invoer na 'n shell of bevoorregte helper gestuur word, kan dit command injection word. Sien [Socket Command Injection](socket-command-injection.md) vir 'n gefokusde voorbeeld.

## nftables Hersiening en Gemagtigde Reëlveranderings

Plaaslike firewall-reëls kan verduidelik waarom 'n diens plaaslik sigbaar is, maar op afstand geblokkeer word, of waarom 'n hoë poort vanaf een koppelvlak onbereikbaar lyk.

Hersien reëls:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Soek na drops wat ’n teikenpoort beïnvloed:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
In 'n gemagtigde laboratorium, verwyder 'n spesifieke blokkeringsreël volgens handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Verkies om die presiese handle te verwyder eerder as om volledige tabelle te flush. Die tegniek is om die presiese filter wat die gedrag veroorsaak, te identifiseer en slegs daardie reël te verander.

## Vinnige werkvloei
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Prioritiseer dienste wat slegs plaaslik is, as ’n meer bevoorregte gebruiker loop, admin-/debug-funksies blootstel, of loopback-/container-network-kliënte vertrou.

{{#include ../../banners/hacktricks-training.md}}
