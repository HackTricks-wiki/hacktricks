# Triage ya Mtandao wa Ndani na Socket

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata shell kwenye host ya Linux, shabaha muhimu zaidi za mtandao mara nyingi hazipatikani kutoka nje. Huduma za loopback pekee, mitandao ya veth, Unix sockets, listeners za muda, packet captures, na sheria za local firewall zinaweza kufichua credentials au attack surfaces za ndani pekee.

Ukurasa huu unaangazia mbinu za practical local post-exploitation, si remote network pentesting kwa ujumla.

## Uorodheshaji wa Loopback na Huduma za Ndani

Anza kwa kubaini huduma zinazosikiliza, anwani zao za bind, na process inayozimiliki pale ruhusa zinaporuhusu.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Mifumo muhimu:

- `127.0.0.1:<port>` au `[::1]:<port>`: inafikika kutoka kwenye host pekee kwa chaguomsingi.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: inafikika kwenye interfaces zote za IPv4 isipokuwa ichujwe.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, au `192.168.0.0/16` kwenye `veth*`, `docker*`, `br-*`, `cni*`: kuna uwezekano ni container au mitandao ya local lab.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets chini ya `/run`, `/var/run`, `/tmp`, au directories za application: maeneo ya local IPC.<sup>[[5]](#references)</sup>

Tambua local ports kwa kutumia probes nyepesi.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Tumia `nmap` ndani ya mfumo wa ndani inapopatikana.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Hidden veth and Container Subnets

Mazingira ya container au maabara mara nyingi huonyesha services kwenye bridge au veth subnet pekee. Orodhesha interfaces na routes kabla ya kudhani kuwa service haiwezi kufikiwa.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Tafuta subneti za ndani zinazowezekana.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Chunguza subnet iliyogunduliwa kwa uangalifu.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Mbinu hii ni muhimu wakati web panel, debug endpoint, au helper service imefichwa dhidi ya scans za nje lakini inapatikana kutoka kwenye host iliyoathirika au network ya container.

## Local Pivot kwa socat au SSH

Ikiwa service imefungwa kwenye loopback, ipeleke kupitia channel iliyoruhusiwa badala ya kubadilisha service yenyewe.

Fanya forward ya service ya HTTP inayopatikana local pekee kwa kutumia SSH.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Fanya bridge ya port ya ndani kwa `socat` wakati tayari una shell access.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Elekeza Unix socket kwenye TCP kwa ajili ya majaribio ya ndani.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Hii haitekelezi exploit yoyote yenyewe. Hufanya surface inayopatikana locally pekee ifikiwe kutoka kwenye tooling yako ili uweze kuingiliana nayo kama service ya kawaida.

## Banner Grabbing na Simple Protocols

Si kila service ni HTTP. Services nyingi za local huleakisha taarifa za kutosha kupitia banner au protocol ya mstari mmoja.

Probes za msingi.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Ukaguzi wa HTTP bila kivinjari.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Kwa TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Lengo ni kutambua protocol, authentication scheme, version, na ikiwa service inaamini local clients.

## Kukamata Loopback Traffic

Traffic ya ndani inaweza kufichua headers, bearer tokens, vitambulisho vya Basic Auth, au secrets mahususi za application.<sup>[[17]](#references)[[25]](#references)</sup> Capture tu katika mazingira yaliyoidhinishwa.

Capture loopback HTTP traffic.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Nasa huduma maalum ya ndani.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decode Basic Auth kutoka kwenye header iliyonaswa au iliyorekodiwa.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Mifuatano muhimu ya kutafuta katika kunasa maandishi:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Ikiwa unaweza kudhibiti mazingira ya mchakato wa client katika lab, `SSLKEYLOGFILE` inaweza kufanya sessions za TLS ziweze ku-decryptiwa katika Wireshark au tooling inayooana.<sup>[[19]](#references)[[20]](#references)</sup> Hii ni muhimu kwa kuelewa traffic ya HTTPS ya ndani bila kushambulia TLS yenyewe.

Endesha client ikiwa key logging imewezeshwa.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Nasa traffic wakati huohuo.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Kisha pakia `/tmp/tls.pcap` na `/tmp/sslkeys.log` kwenye Wireshark. Hii hufanya kazi tu wakati client library inaunga mkono key logging ya mtindo wa NSS na unaweza kuweka environment kabla connection haijaanzishwa.<sup>[[20]](#references)[[21]](#references)</sup>

## Mwingiliano wa Unix Socket na Command Injection

Unix sockets ni local IPC endpoints.<sup>[[5]](#references)</sup> Huenda zikaonyesha HTTP APIs, custom protocols, au unsafe command handlers.<sup>[[12]](#references)[[14]](#references)</sup>

Tafuta sockets.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Wasiliana na HTTP kupitia Unix socket.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Wasiliana na raw socket.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Ikiwa socket input inayodhibitiwa na user itapitishwa kwenye shell au privileged helper, inaweza kusababisha command injection.<sup>[[26]](#references)</sup> Kwa mfano unaolenga, tazama [Socket Command Injection](socket-command-injection.md).

## nftables: Mapitio na Mabadiliko ya Rules Yaliyoidhinishwa

Local firewall rules zinaweza kueleza kwa nini service inaonekana locally lakini imezuiwa remotely, au kwa nini port ya juu inaonekana kutofikika kupitia interface moja.<sup>[[22]](#references)</sup>

Kagua rules.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Tafuta drops zinazoathiri target port.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Katika maabara iliyoidhinishwa, ondoa rule mahususi ya kuzuia kwa kutumia handle yake.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Pendelea kufuta handle mahususi badala ya kufuta jedwali zima. Mbinu ni kutambua filter halisi inayosababisha tabia hiyo na kubadilisha rule hiyo pekee.<sup>[[22]](#references)</sup>

## Mtiririko wa Haraka
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Zipe kipaumbele huduma ambazo ni za ndani pekee, zinaendeshwa na mtumiaji mwenye marupurupu ya juu zaidi, zinafichua vitendaji vya usimamizi/debug, au zinaamini clients za loopback/container-network.

## References

- [1] [ss(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Usanifu wa Anwani wa IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Uelekezaji upya (Mwongozo wa Marejeo wa Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [mwito wa timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Mbinu za Kuchanganua Port (Mwongozo wa Marejeo wa Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Ugunduzi wa Host (Mwongozo wa Marejeo wa Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Uainishaji wa Port na Mpangilio wa Scan (Mwongozo wa Marejeo wa Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — ukurasa wa mwongozo wa Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — ukurasa wa mwongozo wa OpenBSD](https://man.openbsd.org/nc.1)
- [14] [mwongozo wa zana ya mstari wa amri ya curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Nyaraka za OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Mfumo wa Uthibitishaji wa HTTP wa 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [mwito wa base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Nyaraka za OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki ya Wireshark](https://wiki.wireshark.org/tls)
- [21] [Mwongozo wa Mtumiaji wa Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [mwongozo wa nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Ugawaji wa Anwani kwa Mitandao ya Kibinafsi (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Mfumo wa Uidhinishaji wa OAuth 2.0: Matumizi ya Bearer Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Kutoondoa Ipasavyo Vipengele Maalum vinavyotumika katika Amri ya OS](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
