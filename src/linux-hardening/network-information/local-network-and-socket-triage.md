# Uchanganuzi wa Mtandao wa Ndani na Socket

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata shell kwenye Linux host, targets muhimu zaidi za mtandao mara nyingi hazijawekwa wazi externally. Services za loopback-only, veth networks, Unix sockets, temporary listeners, packet captures, na local firewall rules zinaweza kufichua credentials au attack surfaces zinazopatikana locally pekee.

Ukurasa huu unalenga practical local post-exploitation techniques, si general remote network pentesting.

## Loopback na Local Service Enumeration

Anza kwa kutambua services zinazosikiliza, bind addresses zake, na process inayomiliki, pale permissions zinaporuhusu:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Mifumo muhimu:

- `127.0.0.1:<port>` au `[::1]:<port>`: kwa kawaida zinafikiwa na host pekee.
- `0.0.0.0:<port>`: zinafikiwa kwenye interfaces zote za IPv4 isipokuwa zimezuiwa.
- `172.x`, `10.x`, au `192.168.x` kwenye `veth*`, `docker*`, `br-*`, `cni*`: huenda ni container au mitandao ya local lab.
- Unix sockets chini ya `/run`, `/var/run`, `/tmp`, au directories za application: local IPC surfaces.

Map ports za local kwa kutumia probes nyepesi:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Tumia `nmap` ndani ya mfumo wa ndani inapopatikana:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Veth Zilizofichwa na Subnet za Containers

Mazingira ya Container au lab mara nyingi huonyesha services kwenye bridge au subnet ya veth pekee. Enumerate interfaces na routes kabla ya kudhani kuwa service haifikiwi:
```bash
ip -br addr
ip route
ip neigh
```
Tafuta subnets za ndani zinazowezekana:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Chunguza subnet iliyogunduliwa kwa uangalifu:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Mbinu hii ni muhimu wakati web panel, debug endpoint, au helper service imefichwa dhidi ya scans za nje lakini inaweza kufikiwa kutoka kwenye host iliyoathirika au mtandao wa container.

## Local Pivot With socat au SSH

Ikiwa service imefungwa kwenye loopback, iwasilishe kupitia channel inayoruhusiwa badala ya kubadilisha service yenyewe.

Forward service ya HTTP inayopatikana local-only kwa SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Unganisha port ya ndani kwa `socat` unapokuwa tayari una shell access:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Elekeza Unix socket kwenda TCP kwa ajili ya majaribio ya ndani:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Hii haiexploit chochote yenyewe. Inafanya local-only surface ipatikane kupitia tooling yako ili uweze kuingiliana nayo kama service ya kawaida.

## Banner Grabbing na Simple Protocols

Si kila service ni HTTP. Services nyingi za ndani hu-leak taarifa za kutosha kupitia banner au protocol ya mstari mmoja.

Basic probes:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Ukaguzi wa HTTP bila kivinjari:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Kwa TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Lengo ni kutambua protocol, authentication scheme, version, na ikiwa service inaamini local clients.

## Kukamata Loopback Traffic

Traffic ya ndani inaweza kufichua headers, bearer tokens, credentials za Basic Auth, au secrets maalum za application. Capture tu katika mazingira yaliyoidhinishwa.

Capture loopback HTTP traffic:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Nasa huduma mahususi ya ndani:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decode Basic Auth kutoka kwenye header iliyonaswa au iliyorekodiwa:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Mifuatano muhimu ya kutafuta katika kunasa maandishi:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Ikiwa unaweza kudhibiti mazingira ya process ya client katika lab, `SSLKEYLOGFILE` inaweza kufanya TLS sessions zisimbulike katika Wireshark au tooling inayooana. Hii ni muhimu kwa kuelewa traffic ya HTTPS ya ndani bila kushambulia TLS yenyewe.

Endesha client ikiwa key logging imewezeshwa:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Nasa traffic wakati huo huo:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Kisha pakia `/tmp/tls.pcap` na `/tmp/sslkeys.log` kwenye Wireshark. Hii hufanya kazi tu wakati client library inaunga mkono key logging ya mtindo wa NSS na unaweza kuweka environment kabla ya connection kufanywa.

## Unix Socket Interaction and Command Injection

Unix sockets ni local IPC endpoints. Zinaweza kufichua HTTP APIs, custom protocols, au command handlers zisizo salama.

Tafuta sockets:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Wasiliana na HTTP kupitia Unix socket:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Wasiliana na raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Ingizo la socket linalodhibitiwa na mtumiaji likipitishwa kwa shell au privileged helper, linaweza kuwa command injection. Kwa mfano unaolenga zaidi, angalia [Socket Command Injection](socket-command-injection.md).

## Mapitio ya nftables na Mabadiliko ya Rules yaliyoidhinishwa

Rules za local firewall zinaweza kueleza kwa nini service inaonekana locally lakini imezuiwa remotely, au kwa nini port ya juu inaonekana kutoweza kufikiwa kupitia interface moja.

Kagua rules:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Tafuta drops zinazoathiri port inayolengwa:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Katika maabara iliyoidhinishwa, ondoa sheria mahususi ya kuzuia kwa kutumia handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Pendelea kufuta handle halisi badala ya kufuta jedwali zima. Mbinu ni kutambua filter mahususi inayosababisha tabia hiyo na kubadilisha rule hiyo pekee.

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
Pangilia kwa kipaumbele services ambazo ni za local-only, zinaendeshwa na mtumiaji mwenye privilege ya juu zaidi, zinafichua admin/debug functions, au zinaamini loopback/container-network clients.
