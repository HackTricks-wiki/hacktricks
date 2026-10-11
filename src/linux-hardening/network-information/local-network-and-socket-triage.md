# Uchunguzi wa Mtandao wa Ndani na Socket

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata shell kwenye host ya Linux, malengo muhimu zaidi ya mtandao mara nyingi huwa hayajawekwa wazi kwa mifumo ya nje. Huduma za loopback pekee, mitandao ya veth, Unix sockets, listeners za muda, packet captures na sheria za firewall za ndani zinaweza kufichua credentials au maeneo ya mashambulizi yanayopatikana ndani pekee.

Ukurasa huu unalenga mbinu za vitendo za post-exploitation za ndani, si pentesting ya jumla ya mtandao wa mbali.

## Kuhesabu Loopback na Huduma za Ndani

Anza kwa kutambua huduma zinazokubali miunganisho, anwani zake za bind, na mchakato unaomiliki huduma hizo pale ruhusa zinaporuhusu.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Mitindo muhimu:

- `127.0.0.1:<port>` au `[::1]:<port>`: kwa chaguomsingi, inaweza kufikiwa kutoka kwa host pekee.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: inaweza kufikiwa kupitia interfaces zote za IPv4 isipokuwa ichujwe.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, au `192.168.0.0/16` kwenye `veth*`, `docker*`, `br-*`, `cni*`: huenda ni mitandao ya container au maabara ya ndani.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets ndani ya `/run`, `/var/run`, `/tmp`, au saraka za programu: maeneo ya ndani ya IPC.<sup>[[5]](#references)</sup>

Kwa suala la kihistoria la uchanganuzi wa socket ya [snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), kagua daemon inayoendeshwa, socket yake ya API ya ndani, na toleo lililosakinishwa la package au snap ili kulinganisha na marekebisho ya distro hiyo. Hitilafu ilikuwa katika uthibitishaji wa snapd wa anwani ya socket ya peer, si katika `snap-confine`; faili ya `snap-confine` yenye set-user-ID au mfuatano wa toleo la upstream pekee haviwezi kuthibitisha kuwa mfumo uko hatarini. Ubuntu ilisambaza marekebisho katika matoleo ya package mahususi kwa kila toleo, na snapd huenda ilisasishwa kutoka snap kivyake, bila kutegemea package ya distro. Thibitisha build halisi inayoendeshwa na ufikikaji wa socket ya ndani kabla ya kutathmini mpaka wa API yenye mamlaka ya juu. Uhesabuji usioingilia mfumo haupaswi kutuma ombi la socket lililotengenezwa mahsusi wala kusakinisha snap.

Listener ya loopback iliyoanzishwa kupitia [`socat` with `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) inaweza kupitisha ingizo la mteja wa ndani kwa programu tofauti. Linganisha amri ya listener, njia ya executable, utambulisho bora wa child, ufikikaji wa ndani, na uthibitishaji kabla ya kuchukulia service maalum inayomilikiwa na root kama dalili ya privilege-escalation. Hitilafu ya usalama wa kumbukumbu au njia isiyo salama kutoka ingizo hadi amri inahitaji ushahidi kutoka kwa binary na build husika; nambari ya port, process ya `socat`, au umiliki wa root pekee havithibitishi hilo. Uhesabuji usioingilia mfumo unapaswa kuishia kwenye metadata ya process, socket, na faili badala ya kutuma ingizo kwa service.

Salt master ya ndani inaweza kusikiliza TCP 4505 na 4506, ikiwemo kwenye loopback au port ya host iliyochapishwa na container. [Maelezo ya toleo la Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) yanaeleza hitilafu ya ufikiaji wa method bila uthibitishaji, CVE-2020-11651, iliyorekebishwa katika upstream 2019.2.4 na 3000.2. Linganisha listener na process halisi ya `salt-master`, interface inayofikika, package iliyosakinishwa na marekebisho ya vendor, pamoja na utambulisho wake bora wa container au host kabla ya kuichukulia kama dalili ya escalation; port au toleo la upstream pekee si uthibitisho. Ikiwa master inaendeshwa ndani ya container, athari kwa root ya host ni mpaka tofauti: thibitisha kuwa socket ya API ya runtime ya host inayoweza kutumika imewekwa ndani ya container na inaweza kufikiwa kutoka humo. Uhesabuji usioingilia mfumo haupaswi kuuliza Salt request server au kuunda container ili kubaini kama mfumo uko hatarini. Tazama [nyaraka za port za Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) na [uchunguzi wa awali wa runtime API](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Weka ramani ya port za ndani kwa kutumia probes nyepesi.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Tumia `nmap` kwenye mfumo wa ndani inapopatikana.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Subneti za veth zilizofichwa na za kontena

Mazingira yanayotumia kontena au ya maabara mara nyingi hufichua huduma kupitia subneti ya bridge au veth pekee. Orodhesha violesura na njia kabla ya kudhani kuwa huduma haipatikani.<sup>[[2]](#references)</sup>

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

Mbinu hii ni muhimu wakati paneli ya wavuti, debug endpoint, au huduma saidizi imefichwa dhidi ya scans za nje lakini inafikika kutoka kwa host iliyoathiriwa au mtandao wa container.

Huduma ya notebook ya loopback inaweza kutumia token ya kuanzisha inayochapishwa kwenye matokeo ya process yake kuthibitisha utambulisho. Ikiwa matokeo hayo yanaelekezwa kwenye logi inayoweza kusomwa na akaunti nyingine ya ndani, token inaweza kuvuka mpaka wa mtumiaji na kuruhusu code execution katika akaunti ya seva ya notebook. Linganisha mmiliki wa process inayosikiliza, mahali logi inapohifadhiwa na ruhusa zake, usanidi wa sasa wa token, na vidhibiti vya ufikiaji wa notebook kabla ya kuchukulia njia ya logi kama njia ya kupata ruhusa za juu. Orodhesha metadata ya logi wakati wa enumeration tulivu; usichapishe token wala kuunganisha kwenye huduma kwa lengo la kuainisha host tu.

## Local Pivot With socat or SSH

Ikiwa huduma imefungwa kwenye loopback, ifichue kupitia njia inayoruhusiwa badala ya kubadilisha huduma yenyewe.

Elekeza huduma ya HTTP ya ndani kupitia SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Unganisha port ya ndani kwa kutumia `socat` unapokuwa tayari na shell access.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Elekeza Unix socket kwenye TCP kwa ajili ya majaribio ya ndani.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Hili halitumii udhaifu wowote lenyewe. Linafanya sehemu inayofikiwa tu ndani ya kifaa ipatikane kupitia zana zako, ili uweze kuwasiliana nayo kama huduma ya kawaida.

## Banner Grabbing na Itifaki Rahisi

Si kila huduma hutumia HTTP. Huduma nyingi za ndani hufichua taarifa za kutosha kupitia banner au itifaki ya mstari mmoja.

Majaribio ya msingi.<sup>[[13]](#references)</sup>

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

Lengo ni kubaini itifaki, mpango wa uthibitishaji, toleo, na kama huduma inawaamini wateja wa ndani.

Kwa listener ya aiohttp, kagua usanidi wa static-route pamoja na toleo lake. CVE-2024-23334 huathiri aiohttp kabla ya 3.9.2 pale static route inapowasha `follow_symlinks=True`: maombi kwa route hiyo yanaweza kusoma faili zilizo nje ya static root. Ikiwa huduma inaendeshwa kama root, inaweza kufichua faili zinazoweza kusomwa na root, mradi route hiyo inaweza kufikiwa. Bango la toleo au kufungamana na loopback pekee hakuthibitishi usanidi ulio hatarini au ufikiaji wa faili.<sup>[[27]](#references)</sup>

## Kunasa Trafiki ya Loopback

Trafiki ya ndani inaweza kufichua vichwa vya HTTP, bearer tokens, vitambulisho vya Basic Auth, au siri maalum za programu.<sup>[[17]](#references)[[25]](#references)</sup> Nasa trafiki katika mazingira yaliyoidhinishwa pekee.

Nasa trafiki ya HTTP ya loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Nasa huduma mahususi ya ndani.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Decodi Basic Auth kutoka kwenye header iliyonaswa au iliyorekodiwa.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Mifuatano muhimu ya kutafuta katika data ya maandishi iliyonaswa:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Kurekodi Funguo za TLS

Ikiwa unaweza kudhibiti mazingira ya mchakato wa client kwenye lab, `SSLKEYLOGFILE` inaweza kufanya vipindi vya TLS viweze kusimbuliwa kwenye Wireshark au zana zinazooana.<sup>[[19]](#references)[[20]](#references)</sup> Hii ni muhimu kwa kuelewa trafiki ya HTTPS ya ndani bila kushambulia TLS yenyewe.

Endesha client huku kurekodi funguo kukiwashwa.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Nasa trafiki kwa wakati huohuo.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Kisha pakia `/tmp/tls.pcap` na `/tmp/sslkeys.log` kwenye Wireshark. Hii hufanya kazi tu ikiwa maktaba ya client inasaidia uandishi wa funguo kwa mtindo wa NSS na unaweza kuweka mazingira kabla ya muunganisho kuanzishwa.<sup>[[20]](#references)[[21]](#references)</sup>

## Mwingiliano na Unix Socket na Command Injection

Unix sockets ni sehemu za mwisho za IPC za ndani.<sup>[[5]](#references)</sup> Zinaweza kufichua HTTP APIs, itifaki maalum, au vidhibiti vya amri visivyo salama.<sup>[[12]](#references)[[14]](#references)</sup>

Socket inayomilikiwa na root na yenye ruhusa ya kuandikiwa na kundi ni mpaka wa idhini, si udhaifu wenyewe. Linganisha kundi na hali yake ya ruhusa na akaunti ya sasa, tambua mchakato unaosikiliza, na kagua kile ambacho mchakato huo hukubali kutoka kwa clients kabla ya kubainisha kiwango cha hatari. Hasa, huduma yenye upendeleo inayotekeleza PHP iliyowasilishwa inaweza kuvuka mpaka wa pili ikiwa pia inaamini njia ya `php.ini` iliyochaguliwa na mpigaji au inamruhusu mpigaji kubadilisha `disable_functions` au `open_basedir`; kagua usanidi unaotumika na mchakato wa uthibitishaji wa huduma. [Mwongozo wa usanidi wa PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) unaeleza maagizo hayo. Metadata ya socket pekee haithibitishi utekelezaji wa msimbo.

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

Ikiwa ingizo la socket linalodhibitiwa na mtumiaji litapitishwa kwa shell au privileged helper, linaweza kusababisha command injection.<sup>[[26]](#references)</sup> Kwa mfano mahususi, angalia [Socket Command Injection](socket-command-injection.md).

## Mapitio ya nftables na Mabadiliko ya Sheria Zilizoidhinishwa

Sheria za firewall za ndani zinaweza kueleza kwa nini huduma inaonekana ndani ya mtandao lakini imezuiwa kutoka nje, au kwa nini port ya juu haipatikani kupitia interface moja.<sup>[[22]](#references)</sup>

Kagua sheria.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Tafuta pakiti zinazodondoshwa zinazoathiri port lengwa.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

Katika maabara iliyoidhinishwa, ondoa sheria maalum ya kuzuia kwa kutumia handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Pendelea kufuta handle mahususi badala ya kusafisha jedwali zima. Mbinu ni kutambua kichujio sahihi kinachosababisha tabia hiyo na kubadilisha kanuni hiyo pekee.<sup>[[22]](#references)</sup>

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

Pendelea huduma zinazopatikana ndani pekee, zinazoendeshwa na mtumiaji mwenye ruhusa zaidi, zinazofichua vitendaji vya admin/debug, au zinazoamini wateja wa loopback/container-network.

## References

- [1] [ss(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Muundo wa Uwekaji Anwani wa IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Uelekezaji upya (Mwongozo wa Marejeleo wa Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Matumizi ya timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Mbinu za Kuchanganua Porti (Mwongozo wa Marejeleo wa Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Ugunduzi wa Host (Mwongozo wa Marejeleo wa Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Uainishaji wa Porti na Mpangilio wa Uchanganuzaji (Mwongozo wa Marejeleo wa Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — ukurasa wa mwongozo wa Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — ukurasa wa mwongozo wa OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Mwongozo wa zana ya mstari wa amri ya curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Nyaraka za OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Mbinu ya Uthibitishaji wa HTTP ya 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Matumizi ya base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Nyaraka za OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki ya Wireshark](https://wiki.wireshark.org/tls)
- [21] [Mwongozo wa Mtumiaji wa Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Mwongozo wa nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Ugawaji wa Anwani kwa Mitandao ya Kibinafsi (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Mfumo wa Uidhinishaji wa OAuth 2.0: Matumizi ya Bearer Token (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Kutobatilisha Vizuri Vipengele Maalum Vinavyotumiwa katika Amri ya OS](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Ushauri wa maintainer wa aiohttp: traversal ya static route wakati follow_symlinks imewashwa](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
