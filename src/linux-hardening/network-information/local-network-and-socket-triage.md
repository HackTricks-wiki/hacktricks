# Uchunguzi wa Mtandao wa Ndani na Socket

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata shell kwenye Linux host, targets muhimu zaidi za network mara nyingi hazijawekwa wazi externally. Services za loopback-only, networks za veth, Unix sockets, temporary listeners, packet captures, na local firewall rules zinaweza kufichua credentials au attack surfaces zinazopatikana locally pekee.

Ukurasa huu unaangazia mbinu za vitendo za local post-exploitation, si general remote network pentesting.

## Kuhesabu Loopback na Local Services

Anza kwa kutambua services zinazosikiliza, bind addresses zake, na process inayoziendesha pale permissions zinaporuhusu:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Miundo muhimu:

- `127.0.0.1:<port>` au `[::1]:<port>`: inaweza kufikiwa tu kutoka kwa host kwa kawaida.
- `0.0.0.0:<port>`: inaweza kufikiwa kwenye interfaces zote za IPv4 isipokuwa ikiwa imechujwa.
- `172.x`, `10.x`, au `192.168.x` kwenye `veth*`, `docker*`, `br-*`, `cni*`: huenda ni mitandao ya container au maabara ya ndani.
- Unix sockets zilizo chini ya `/run`, `/var/run`, `/tmp`, au directories za application: IPC surfaces za ndani.

Map local ports kwa lightweight probes:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Tumia `nmap` kwenye mfumo wa ndani inapopatikana:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## veth Zilizofichwa na Subneti za Container

Mazingira ya container mara nyingi huweka services wazi kwenye bridge au subnet ya veth pekee. Orodhesha interfaces na routes kabla ya kudhani kuwa service haipatikani:
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
Mbinu hii ni muhimu wakati web panel, debug endpoint, au helper service imefichwa dhidi ya scans za nje lakini inafikika kutoka kwenye host iliyoathiriwa au network ya container.

## Local Pivot With socat or SSH

Ikiwa service imefungwa kwenye loopback, i-expose kupitia channel iliyoruhusiwa badala ya kubadilisha service yenyewe.

Forward service ya HTTP ya local-only kwa SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Bridge port ya ndani kwa kutumia `socat` wakati tayari una ufikiaji wa shell:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Elekeza Unix socket hadi TCP kwa ajili ya majaribio ya ndani:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Hii haiexploit chochote yenyewe. Inafanya surface inayopatikana locally pekee ifikike kutoka kwenye tooling yako ili uweze kuingiliana nayo kama service ya kawaida.

## Banner Grabbing na Simple Protocols

Si kila service ni HTTP. Services nyingi za local hu-leak taarifa za kutosha kupitia banner au protocol ya mstari mmoja.

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

## Kukusanya Loopback Traffic

Local traffic inaweza kufichua headers, bearer tokens, credentials za Basic Auth, au siri maalum za application. Nasa traffic pekee katika mazingira yaliyoidhinishwa.

Nasa loopback HTTP traffic:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Nasa huduma maalum ya ndani:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Decode Basic Auth kutoka kwenye header iliyonaswa au iliyorekodiwa:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Mishororo muhimu ya kutafuta katika text captures:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Ikiwa unaweza kudhibiti mazingira ya client process katika lab, `SSLKEYLOGFILE` inaweza kufanya TLS sessions ziweze kufanyiwa decryption katika Wireshark au tooling inayooana. Hii ni muhimu kwa kuelewa traffic ya HTTPS ya ndani bila kushambulia TLS yenyewe.

Endesha client ikiwa key logging imewezeshwa:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Nasa traffic kwa wakati mmoja:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Kisha pakia `/tmp/tls.pcap` na `/tmp/sslkeys.log` kwenye Wireshark. Hii hufanya kazi tu wakati client library inaunga mkono key logging ya mtindo wa NSS na unaweza kuweka environment kabla connection haijaanzishwa.

## Mwingiliano wa Unix Socket na Command Injection

Unix sockets ni endpoints za ndani za IPC. Zinaweza kufichua HTTP APIs, custom protocols, au command handlers zisizo salama.

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
Kuingiliana na raw socket:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Ikiwa socket input inayodhibitiwa na mtumiaji itapitishwa kwa shell au helper yenye privileges, inaweza kusababisha command injection. Kwa mfano unaolenga jambo hili, tazama [Socket Command Injection](socket-command-injection.md).

## Mapitio ya nftables na Mabadiliko ya Sheria Yaliyoidhinishwa

Sheria za local firewall zinaweza kueleza kwa nini service inaonekana locally lakini imezuiwa remotely, au kwa nini high port inaonekana haifikiwi kupitia interface moja.

Kagua sheria:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Tafuta drops zinazoathiri port lengwa:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
Katika maabara iliyoidhinishwa, ondoa rule maalum ya kuzuia kwa kutumia handle:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Pendelea kufuta handle halisi badala ya kuondoa jedwali zima. Mbinu ni kutambua filter mahususi inayosababisha tabia hiyo na kubadilisha rule hiyo pekee.

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
Zipa kipaumbele huduma ambazo ni local-only, zinaendeshwa na mtumiaji mwenye haki za juu zaidi, zinafichua functions za admin/debug, au zinaamini clients wa loopback/container-network.

{{#include ../../banners/hacktricks-training.md}}
