# Plaaslike netwerk- en socket-triage

{{#include ../../banners/hacktricks-training.md}}

Nadat jy ’n shell op ’n Linux-gasheer verkry het, is die nuttigste netwerkteikens dikwels nie ekstern blootgestel nie. Dienste wat slegs op loopback beskikbaar is, veth-netwerke, Unix-sockets, tydelike listeners, pakkievasleggings en plaaslike firewall-reëls kan geloofsbriewe of aanvalsvlakke wat slegs plaaslik beskikbaar is, blootlê.

Hierdie bladsy fokus op praktiese plaaslike post-exploitation-tegnieke, nie op algemene afgeleë netwerk-pentesting nie.

## Enumerering van loopback- en plaaslike dienste

Begin deur luisterende dienste, hul bind-adresse en, waar toestemmings dit toelaat, die eienaarproses te identifiseer.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Belangrike patrone:

- `127.0.0.1:<port>` of `[::1]:<port>`: by verstek slegs vanaf die host bereikbaar.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: bereikbaar op alle IPv4-koppelvlakke, tensy dit gefiltreer word.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` of `192.168.0.0/16` op `veth*`, `docker*`, `br-*`, `cni*`: waarskynlik container- of plaaslike lab-netwerke.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix-sockets onder `/run`, `/var/run`, `/tmp` of toepassingsgidse: plaaslike IPC-oppervlakke.<sup>[[5]](#references)</sup>

Vir die historiese [snapd-socket-parsing-kwessie, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), ondersoek die lopende daemon, sy plaaslike API-socket en die geïnstalleerde pakket- of snap-hersiening in verhouding tot die regstelling vir daardie verspreiding. Die fout was in snapd se validering van ’n eweknie se socket-adres, nie in `snap-confine` nie; ’n `set-user-ID`-lêer genaamd `snap-confine` of ’n stroomop-weergawe-string alleen kan nie blootstelling bevestig nie. Ubuntu het regstellings in pakketweergawes spesifiek vir elke vrystelling verskaf, en snapd kon onafhanklik van die verspreidingspakket vanaf ’n snap verfris gewees het. Bevestig die werklike lopende bouweergawe en plaaslike bereikbaarheid van die socket voordat die bevoorregte API-grens beoordeel word. Passiewe enumerasie behoort nie ’n vervaardigde socket-versoek te stuur of ’n snap te installeer nie.

’n Loopback-listener wat met [`socat` en `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) begin is, kan plaaslike kliëntinvoer aan ’n afsonderlike program deurgee. Bring die listener se opdrag, uitvoerbare lêer se pad, effektiewe identiteit van die kindproses, plaaslike bereikbaarheid en verifikasie met mekaar in verband voordat ’n pasgemaakte diens wat deur root besit word as ’n moontlike voorregeskaleringsaanwysing beskou word. ’n Geheueveiligheidsfout of onveilige pad van invoer na opdrag vereis bewyse uit die spesifieke binêre lêer en bouweergawe; die poortnommer, `socat`-proses of root-eienaar alleen bevestig dit nie. Passiewe enumerasie behoort by proses-, socket- en lêermetadata te stop, eerder as om invoer na die diens te stuur.

’n Plaaslike Salt-master kan op TCP 4505 en 4506 luister, ook op loopback of ’n container-gepubliseerde host-poort. [Salt se 3000.2-vrystellingnotas](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) beskryf ’n fout in metode-toegang sonder verifikasie, CVE-2020-11651, wat in stroomop-weergawes 2019.2.4 en 3000.2 reggestel is. Bring die listener in verband met die werklike `salt-master`-proses, bereikbare koppelvlak, geïnstalleerde pakket en verskaffer se regstellings, en sy effektiewe container- of host-identiteit voordat dit as ’n moontlike voorregeskaleringsaanwysing beskou word; ’n poort of stroomop-weergawe alleen is nie bewys nie. As ’n master binne ’n container loop, is impak op host-root ’n afsonderlike grens: bevestig dat ’n bruikbare host-runtime-API-socket gemonteer is en vanuit daardie container toeganklik is. Passiewe enumerasie behoort nie die Salt-versoekbediener te navraagpleeg of ’n container te skep om blootstelling te bepaal nie. Sien [Salt se poortdokumentasie](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) en [runtime API-triage](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Karteer plaaslike poorte met liggewig-probes.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Gebruik `nmap` plaaslik wanneer dit beskikbaar is.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Verborge veth- en houersubnette

Gecontaineriseerde of laboratoriumomgewings stel dienste dikwels slegs op ’n bridge- of veth-subnet bloot. Lys koppelvlakke en roetes voordat jy aanvaar dat ’n diens onbereikbaar is.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Vind waarskynlike plaaslike subnetwerke.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Ondersoek ’n ontdekte subnet versigtig.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Die tegniek is nuttig wanneer ’n webpaneel, debug-eindpunt of helperdiens vir eksterne skanderings versteek is, maar vanaf die gekompromitteerde gasheer of houernetwerk bereikbaar is.

## Notebook-dienstokens oor gebruikersgrense

’n Notebook-diens op loopback kan met ’n opstarttoken verifieer wat na sy prosesuitvoer geskryf word. As daardie uitvoer na ’n log herlei word wat deur ’n ander plaaslike rekening gelees kan word, kan die token ’n gebruikersgrens oorsteek en kode-uitvoering in die Notebook-bediener se rekening moontlik maak. Kruisverwys die eienaar van die luisterproses, die logbestemming en -toestemmings, die huidige tokenkonfigurasie en Notebook-toegangsbeheer voordat jy ’n logpad as ’n eskalasie-aanwysing beskou. Lys logmetadata tydens passiewe enumerasie; moenie tokens vertoon of aan die diens koppel bloot om die gasheer te klassifiseer nie.

’n Jupyter Lab-diens kan sy token ook in ’n leesbare systemd `ExecStart` of in die lopende opdragreël (`ps auxww`) blootstel, eerder as net in opstartlogs. In die gerapporteerde voorbeeld het `User=analyst` en `--ServerApp.token` sowel die credential as die rekening agter ’n `127.0.0.1:8888`-luisteraar geïdentifiseer. Met toegang tot die gasheer het die token en `ssh -L 8888:127.0.0.1:8888 user@host` toegang tot Jupyter Lab se Terminal as daardie diensgebruiker moontlik gemaak. Gaan die effektiewe eenheidgebruiker, prosesargumente, luisteraar en token-geldigheid saam na; binding aan loopback alleen is nie ’n magtigingsgrens nie.<sup>[[28]](#references)</sup>

## Plaaslike pivot met socat of SSH

As ’n diens aan loopback gebind is, stel dit deur ’n toegelate kanaal beskikbaar in plaas daarvan om die diens self te verander.

Stuur ’n plaaslike HTTP-diens aan met SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Koppel ’n plaaslike poort met `socat` wanneer jy reeds shell access het.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Herlei ’n Unix socket na TCP vir plaaslike toetsing.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Dit buit niks op sigself uit nie. Dit maak ’n oppervlak wat slegs plaaslik beskikbaar is bereikbaar vanaf jou gereedskap, sodat jy daarmee kan kommunikeer soos met ’n gewone diens.

## Banner Grabbing en eenvoudige protokolle

Nie elke diens is HTTP nie. Baie plaaslike dienste lek genoeg inligting deur ’n banner of ’n eenreëlprotokol.

Basiese probes.<sup>[[13]](#references)</sup>

```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```

HTTP-kontrole sonder ’n webblaaier.<sup>[[13]](#references)[[14]](#references)</sup>

```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```

Vir TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Die doel is om die protokol, verifikasiemetode, weergawe en of die diens plaaslike kliënte vertrou, te identifiseer.

Vir ’n aiohttp-listener, hersien die statiese roetekonfigurasie sowel as die weergawe. CVE-2024-23334 raak aiohttp-weergawes voor 3.9.2 wanneer ’n statiese roete `follow_symlinks=True` aktiveer: versoeke na daardie roete kan lêers buite die statiese wortel lees. As die diens as root loop, kan dit lêers blootstel wat root kan lees, mits die roete bereikbaar is. ’n Weergawebanier of ’n loopback-binding bewys nie op sigself dat die kwesbare konfigurasie of lêertoegang teenwoordig is nie.<sup>[[27]](#references)</sup>

## Opname van Loopback-verkeer

Plaaslike verkeer kan headers, bearer tokens, Basic Auth-geloofsbriewe of toepassingspesifieke geheime blootstel.<sup>[[17]](#references)[[25]](#references)</sup> Neem slegs verkeer in gemagtigde omgewings op.

Neem loopback-HTTP-verkeer op.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Vang ’n spesifieke plaaslike diens vas.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Dekodeer Basic Auth vanaf ’n vasgevangde of gelogde header.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Nuttige stringe om in teksopnames na te soek:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS-sleutellogging

As jy die kliëntproses se omgewing in ’n laboratorium kan beheer, kan `SSLKEYLOGFILE` TLS-sessies ontsyferbaar maak in Wireshark of versoenbare gereedskap.<sup>[[19]](#references)[[20]](#references)</sup> Dit is nuttig om plaaslike HTTPS-verkeer te verstaan sonder om TLS self aan te val.

Voer ’n kliënt uit met sleutellogging geaktiveer.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Vang die verkeer terselfdertyd op.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Laai dan `/tmp/tls.pcap` en `/tmp/sslkeys.log` in Wireshark. Dit werk slegs wanneer die kliëntbiblioteek NSS-styl-sleutellogging ondersteun en jy die omgewing kan instel voordat die verbinding gemaak word.<sup>[[20]](#references)[[21]](#references)</sup>

## Interaksie met Unix-sokke en Command Injection

Unix-sokke is plaaslike IPC-eindpunte.<sup>[[5]](#references)</sup> Hulle kan HTTP-API's, pasgemaakte protokolle of onveilige opdraghanteerders blootstel.<sup>[[12]](#references)[[14]](#references)</sup>

'n Sok wat deur root besit word en skryftoestemming vir 'n groep het, is 'n magtigingsgrens, nie op sigself 'n kwesbaarheid nie. Vergelyk die groep en modus daarvan met die huidige rekening, identifiseer die luisterende proses en ondersoek wat daardie proses van kliënte aanvaar voordat jy die risiko bepaal. In die besonder kan 'n bevoorregte diens wat ingediende PHP uitvoer 'n tweede grens oorsteek as dit ook 'n pad na `php.ini` vertrou wat deur die oproeper gekies word, of die oproeper toelaat om `disable_functions` of `open_basedir` te verander; ondersoek die effektiewe konfigurasie en die diens se valideringspad. Die [PHP-konfigurasiegids](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) verduidelik daardie aanwysings. Sokmetadata alleen bewys nie kode-uitvoering nie.

Vind sokke.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Werk met HTTP oor ’n Unix-sok.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interaksie met 'n raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

As gebruikerbeheerde socket-invoer na ’n shell of geprivilegieerde helper deurgegee word, kan dit command injection tot gevolg hê.<sup>[[26]](#references)</sup> Sien [Socket Command Injection](socket-command-injection.md) vir ’n gefokusde voorbeeld.

## Hersiening van nftables en gemagtigde reëlveranderinge

Plaaslike firewall-reëls kan verduidelik waarom ’n diens plaaslik sigbaar is maar op afstand geblokkeer word, of waarom ’n hoë poort vanaf een koppelvlak onbereikbaar lyk.<sup>[[22]](#references)</sup>

Hersien die reëls.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Soek na drops wat 'n teikenpoort raak.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

In ’n gemagtigde laboratorium, verwyder ’n spesifieke blokkeringsreël met behulp van die handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Verkies om die presiese handle te verwyder eerder as om volledige tabelle te flush. Die tegniek is om die presiese filter wat die gedrag veroorsaak, te identifiseer en slegs daardie reël te verander.<sup>[[22]](#references)</sup>

## Vinnige Werkvloei

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Prioritiseer dienste wat slegs plaaslik beskikbaar is, as ’n gebruiker met meer voorregte loop, admin-/debug-funksies blootstel, of loopback-/houernetwerk-kliënte vertrou.

## References

- [1] [ss(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: IPv6-adresseringsargitektuur](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Herleidings (Bash-verwysingshandleiding)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [timeout-aanroep (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Poortskanderingstegnieke (Nmap-verwysingsgids)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Gasheerontdekking (Nmap-verwysingsgids)](https://nmap.org/book/man-host-discovery.html)
- [10] [Poortspesifikasie en skandeervolgorde (Nmap-verwysingsgids)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — Linux-handleidingbladsy](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — OpenBSD-handleidingbladsy](https://man.openbsd.org/nc.1)
- [14] [curl-opdragreëlnutsmiddelhandleiding](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — OpenSSL-dokumentasie](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Die HTTP-verifikasieskema 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [base64-aanroep (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — OpenSSL-dokumentasie](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark-wiki](https://wiki.wireshark.org/tls)
- [21] [Wireshark-gebruikersgids](https://www.wireshark.org/docs/wsug_html/)
- [22] [nftables-handleiding](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Adrestoekenning vir private internette (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Die OAuth 2.0-magtigingsraamwerk: Gebruik van Bearer-tokens (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Onbehoorlike neutralisering van spesiale elemente wat in ’n OS-opdrag gebruik word](https://cwe.mitre.org/data/definitions/78.html)
- [27] [aiohttp-instandhouer se sekuriteitskennisgewing: statiese roete-oorskryding met follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — Jupyter-token blootgestel deur systemd en prosesargumente](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
