# Plaaslike netwerk- en socket-triage

{{#include ../../banners/hacktricks-training.md}}

Nadat jy 'n shell op 'n Linux-host verkry het, is die nuttigste netwerk-teikens dikwels nie ekstern blootgestel nie. Loopback-only-dienste, veth-netwerke, Unix-sockets, tydelike listeners, packet captures en plaaslike firewall-reëls kan credentials of plaaslike aanvalsvlakke blootlê.

Hierdie bladsy fokus op praktiese plaaslike post-exploitation-tegnieke, nie algemene remote network pentesting nie.

## Loopback- en plaaslike diens-enumerasie

Begin deur listening services, hul bind-adresse en die owning process te identifiseer wanneer permissions dit toelaat.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Belangrike patrone:

- `127.0.0.1:<port>` of `[::1]:<port>`: by verstek slegs vanaf die gasheer bereikbaar.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: op alle IPv4-koppelvlakke bereikbaar, tensy gefiltreer.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, of `192.168.0.0/16` op `veth*`, `docker*`, `br-*`, `cni*`: waarskynlik container- of plaaslike lab-netwerke.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix-sockets onder `/run`, `/var/run`, `/tmp`, of toepassingsgidse: plaaslike IPC-oppervlakke.<sup>[[5]](#references)</sup>

Karteer plaaslike poorte met liggewig-sondes.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Gebruik `nmap` plaaslik wanneer beskikbaar.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Versteekte veth- en Container-subnette

Container- of lab-omgewings stel dikwels dienste slegs op ’n bridge- of veth-subnet bloot. Enumereer koppelvlakke en roetes voordat jy aanvaar dat ’n diens onbereikbaar is.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Vind waarskynlike plaaslike subnetwerke.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Probe 'n ontdekte subnet versigtig.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Die tegniek is nuttig wanneer ’n webpaneel, debug endpoint of helper service vir eksterne skanderings versteek is, maar vanaf die gekompromitteerde host of container network bereikbaar is.

## Plaaslike pivot met socat of SSH

As ’n diens aan loopback gebind is, stel dit deur ’n toegelate kanaal bloot in plaas daarvan om die diens self te verander.

Forward ’n plaaslike HTTP-diens met SSH.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Brug 'n plaaslike poort met `socat` wanneer jy reeds shell access het.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Stuur ’n Unix-socket na TCP vir plaaslike toetsing.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Dit exploit niks op sy eie nie. Dit maak ’n slegs-lokale oppervlak bereikbaar vanaf jou tooling sodat jy daarmee kan interaksie hê soos met ’n normale diens.

## Banner Grabbing en eenvoudige protokolle

Nie elke diens is HTTP nie. Baie plaaslike dienste leak genoeg inligting deur ’n banner of eenreël-protokol.

Basiese probes.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
HTTP-kontrole sonder 'n blaaier.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Vir TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Die doel is om die protokol, authentication scheme, weergawe en of die diens plaaslike clients vertrou, te identifiseer.

## Loopback-verkeer vaslê

Plaaslike verkeer kan headers, bearer tokens, Basic Auth credentials of application-specific secrets blootlê.<sup>[[17]](#references)[[25]](#references)</sup> Vang slegs verkeer in gemagtigde omgewings vas.

Vang loopback HTTP-verkeer vas.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Vang 'n spesifieke plaaslike diens vas.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Dekodeer Basic Auth vanaf 'n vasgevangde of gelogde header.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Nuttige stringe om in teksopnames na te soek:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

As jy die client-proses se omgewing in 'n lab kan beheer, kan `SSLKEYLOGFILE` TLS-sessies in Wireshark of versoenbare tooling dekripteerbaar maak.<sup>[[19]](#references)[[20]](#references)</sup> Dit is nuttig om plaaslike HTTPS-verkeer te verstaan sonder om TLS self aan te val.

Begin 'n client met key logging geaktiveer.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Vang die verkeer terselfdertyd vas.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Laai dan `/tmp/tls.pcap` en `/tmp/sslkeys.log` in Wireshark. Dit werk slegs wanneer die client library NSS-style key logging ondersteun en jy die omgewing kan instel voordat die verbinding gemaak word.<sup>[[20]](#references)[[21]](#references)</sup>

## Interaksie met Unix-sockets en Command Injection

Unix-sockets is plaaslike IPC-endpoints.<sup>[[5]](#references)</sup> Hulle kan HTTP APIs, custom protocols of onveilige command handlers blootstel.<sup>[[12]](#references)[[14]](#references)</sup>

Vind sockets.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interaksie met HTTP oor ’n Unix-socket.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interaksie met ’n raw socket.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
As socket-invoer wat deur die gebruiker beheer word aan ’n shell of bevoorregte helper deurgegee word, kan dit command injection word.<sup>[[26]](#references)</sup> Vir ’n gefokusde voorbeeld, sien [Socket Command Injection](socket-command-injection.md).

## nftables-hersiening en Gemagtigde Reëlwysigings

Plaaslike firewall-reëls kan verduidelik waarom ’n diens plaaslik sigbaar is, maar op afstand geblokkeer word, of waarom ’n hoë poort vanaf een koppelvlak onbereikbaar lyk.<sup>[[22]](#references)</sup>

Hersien reëls.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Soek na drops wat 'n teikenpoort beïnvloed.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
In ’n gemagtigde laboratorium, verwyder ’n spesifieke blokkeringsreël volgens handvatsel.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Verkies om die presiese handle te verwyder eerder as om volledige tabelle te flush. Die tegniek is om die presiese filter te identifiseer wat die gedrag veroorsaak en slegs daardie reël te verander.<sup>[[22]](#references)</sup>

## Vinnige werksvloei
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Prioritiseer dienste wat slegs plaaslik is, as ’n gebruiker met meer voorregte loop, admin/debug-funksies blootstel, of loopback-/container-network-kliënte vertrou.

## References

- [1] [ss(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IP Version 6 Addressing Architecture](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Redirections (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout invocation (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Port Scanning Techniques (Nmap Reference Guide)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Host Discovery (Nmap Reference Guide)](https://nmap.org/book/man-host-discovery.html)
- [10] [Port Specification and Scan Order (Nmap Reference Guide)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux-handleidingbladsy](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD-handleidingbladsy](https://man.openbsd.org/nc.1)
- [14] [curl command line tool manual](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL Documentation](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: The 'Basic' HTTP Authentication Scheme](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64 invocation (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL Documentation](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables manual](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Address Allocation for Private Internets (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [The OAuth 2.0 Authorization Framework: Bearer Token Usage (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
