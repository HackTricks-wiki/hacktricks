# Uchunguzi wa Haraka wa Mtandao wa Ndani na Soketi

{{#include ../../banners/hacktricks-training.md}}

Baada ya kupata shell kwenye host ya Linux, malengo muhimu zaidi ya mtandao mara nyingi hayafikiki kutoka nje. Huduma zinazopatikana kupitia loopback pekee, mitandao ya veth, soketi za Unix, wasikilizaji wa muda, packet capture, na sheria za firewall za ndani zinaweza kufichua credentials au maeneo ya mashambulizi yanayopatikana ndani pekee.

Ukurasa huu unaangazia mbinu za vitendo za local post-exploitation, si pentesting ya jumla ya mtandao wa mbali.

## Kuhesabu Huduma za Loopback na za Ndani

Anza kwa kutambua huduma zinazosikiliza, anwani zilizounganishwa nazo, na mchakato unaozimiliki, pale ruhusa zinaporuhusu.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Mifumo muhimu:

- `127.0.0.1:<port>` au `[::1]:<port>`: kwa chaguomsingi, inaweza kufikiwa na mashine hiyo pekee.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: inaweza kufikiwa kupitia interface zote za IPv4 isipokuwa ikiwa imechujwa.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12`, au `192.168.0.0/16` kwenye `veth*`, `docker*`, `br-*`, `cni*`: huenda ni mitandao ya container au maabara ya ndani.<sup>[[23]](#references)[[24]](#references)</sup>
- Unix sockets chini ya `/run`, `/var/run`, `/tmp`, au saraka za programu: maeneo ya ndani ya IPC.<sup>[[5]](#references)</sup>

Kwa suala la kihistoria la uchanganuzi wa socket la [snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing), kagua daemon inayoendesha, socket yake ya API ya ndani, na toleo lililosakinishwa la package au snap ili kulinganisha na marekebisho ya distro hiyo. Hitilafu ilikuwa katika uthibitishaji wa snapd wa anwani ya socket ya peer, si katika `snap-confine`; faili ya `snap-confine` yenye set-user-ID au mfuatano wa toleo la upstream pekee haviwezi kuthibitisha kuwa mfumo uko hatarini. Ubuntu ilisambaza marekebisho katika matoleo ya package mahususi kwa kila release, na snapd huenda ilisasishwa kutoka snap bila kutegemea package ya distro. Thibitisha build inayoendesha na uwezekano wa kufikia socket ya ndani kabla ya kutathmini mpaka wa API yenye upendeleo. Uchanganuzi wa passiv usitume ombi la socket lililotengenezwa mahsusi wala kusakinisha snap.

Listener ya loopback iliyoanzishwa kupitia [`socat` yenye `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) inaweza kupitisha ingizo la client wa ndani kwa programu tofauti. Linganisha command ya listener, njia ya executable, utambulisho unaotumika wa child process, uwezekano wa kufikiwa kutoka ndani, na uthibitishaji kabla ya kuchukulia huduma maalum inayomilikiwa na root kama njia ya kuongeza upendeleo. Hitilafu ya usalama wa kumbukumbu au njia isiyo salama ya ingizo hadi command inahitaji ushahidi kutoka kwa binary na build husika; nambari ya port, process ya `socat`, au umiliki wa root pekee haviithibitishi. Uchanganuzi wa passiv unapaswa kuishia kwenye metadata ya process, socket na faili badala ya kutuma ingizo kwa huduma.

Salt master ya ndani inaweza kusikiliza TCP 4505 na 4506, ikiwemo kwenye loopback au port ya host iliyochapishwa na container. [Vidokezo vya toleo la Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) vinaeleza hitilafu ya ufikiaji wa method bila uthibitishaji, CVE-2020-11651, iliyorekebishwa katika upstream 2019.2.4 na 3000.2. Linganisha listener na process halisi ya `salt-master`, interface inayoweza kufikiwa, package iliyosakinishwa pamoja na marekebisho ya vendor, na utambulisho wake unaotumika wa container au host kabla ya kuichukulia kama njia ya kuongeza upendeleo; port au toleo la upstream pekee si uthibitisho. Ikiwa master inaendesha ndani ya container, athari kwa root ya host ni mpaka tofauti: thibitisha kuwa socket ya API ya runtime ya host inayoweza kutumika imewekwa ndani na inaweza kufikiwa kutoka kwenye container hiyo. Uchanganuzi wa passiv haupaswi kuuliza Salt request server wala kuunda container ili kubaini hali ya kuathirika. Tazama [hati za Salt kuhusu port](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) na [uchunguzi wa runtime API](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Ramani port za ndani kwa kutumia probes nyepesi.<sup>[[6]](#references)[[7]](#references)</sup>

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

## Subneti Zilizofichwa za veth na Kontena

Mazingira ya kontena au maabara mara nyingi hufichua huduma kwenye subneti ya bridge au veth pekee. Orodhesha violesura na njia za mtandao kabla ya kudhani kuwa huduma haipatikani.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Tafuta subnet za ndani zinazowezekana.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Chunguza subnet iliyogunduliwa kwa uangalifu.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Mbinu hii ni muhimu pale ambapo paneli ya wavuti, endpoint ya utatuzi, au huduma saidizi imefichwa dhidi ya uchanganuzi kutoka nje, lakini inafikika kutoka kwa host iliyoathiriwa au mtandao wa container.

## Tokeni za huduma ya Notebook kati ya akaunti za watumiaji

Huduma ya notebook inayofungamana na loopback inaweza kuthibitisha utambulisho kwa kutumia tokeni ya kuanzisha inayochapishwa kwenye matokeo ya mchakato wake. Ikiwa matokeo hayo yanaelekezwa kwenye logi inayoweza kusomwa na akaunti nyingine ya ndani, tokeni inaweza kuvuka mpaka wa watumiaji na kuruhusu code execution katika akaunti ya seva ya notebook. Linganisha mmiliki wa mchakato unaosikiliza, mahali logi inapoandikwa na ruhusa zake, usanidi wa sasa wa tokeni, na vidhibiti vya ufikiaji vya notebook kabla ya kuichukulia njia ya logi kama fursa ya kupandisha ruhusa. Orodhesha metadata ya logi wakati wa upelelezi tulivu; usichapishe tokeni au kuunganishwa na huduma kwa lengo la kuainisha host pekee.

Huduma ya Jupyter Lab inaweza pia kufichua tokeni yake kwenye `ExecStart` ya systemd inayosomeka au kwenye command line ya mchakato unaoendesha (`ps auxww`), badala ya kuifichua kwenye logi za kuanzisha pekee. Katika mfano ulioripotiwa, `User=analyst` na `--ServerApp.token` vilibainisha kitambulisho cha uthibitishaji na akaunti iliyoendesha listener ya `127.0.0.1:8888`. Kwa ufikiaji wa host, tokeni na `ssh -L 8888:127.0.0.1:8888 user@host` ziliruhusu ufikiaji wa Terminal ya Jupyter Lab kama mtumiaji wa huduma hiyo. Kagua pamoja mtumiaji halisi wa unit, hoja za mchakato, listener, na uhalali wa tokeni; kufungamana na loopback pekee si mpaka wa uidhinishaji.<sup>[[28]](#references)</sup>

## Pivot ya Ndani kwa kutumia socat au SSH

Ikiwa huduma imefungamana na loopback, ifikie kupitia njia inayoruhusiwa badala ya kubadilisha huduma yenyewe.

Elekeza huduma ya HTTP inayopatikana ndani pekee kwa kutumia SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Unganisha port ya ndani kupitia `socat` ukiwa tayari una ufikiaji wa shell.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Elekeza soketi ya Unix kwenye TCP kwa majaribio ya ndani.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Hii yenyewe haiexploit chochote. Hufanya uso unaopatikana ndani ya kifaa pekee ufikiwe na zana zako, ili uweze kuwasiliana nao kama huduma ya kawaida.

## Banner Grabbing na Itifaki Rahisi

Si kila huduma hutumia HTTP. Huduma nyingi za ndani huleak taarifa za kutosha kupitia banner au itifaki ya mstari mmoja.

Probe za msingi.<sup>[[13]](#references)</sup>

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

Lengo ni kubaini protocol, mpango wa uthibitishaji, toleo, na kama huduma inawaamini wateja wa ndani.

Kwa listener ya aiohttp, kagua usanidi wake wa static route pamoja na toleo lake. CVE-2024-23334 huathiri aiohttp za matoleo kabla ya 3.9.2 wakati static route imewezesha `follow_symlinks=True`: maombi kwa route hiyo yanaweza kusoma faili zilizo nje ya static root. Huduma ikiendeshwa kama root, inaweza kufichua faili ambazo root anaweza kusoma, mradi route hiyo inaweza kufikiwa. Bango la toleo au kufunga kwenye loopback pekee hakuthibitishi usanidi ulio hatarini au ufikiaji wa faili.<sup>[[27]](#references)</sup>

## Kunasa Trafiki ya Loopback

Trafiki ya ndani inaweza kufichua vichwa, bearer tokens, vitambulisho vya Basic Auth, au siri mahususi za programu.<sup>[[17]](#references)[[25]](#references)</sup> Nasa trafiki katika mazingira yaliyoidhinishwa pekee.

Nasa trafiki ya HTTP ya loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Nasa huduma mahususi ya ndani.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Decode Basic Auth kutoka kwenye header iliyonaswa au kurekodiwa.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Mifuatano muhimu ya kutafuta katika data ya maandishi iliyonaswa:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## TLS Key Logging

Ikiwa unaweza kudhibiti mazingira ya mchakato wa client katika maabara, `SSLKEYLOGFILE` inaweza kufanya vipindi vya TLS visimbuliwe katika Wireshark au zana zinazooana.<sup>[[19]](#references)[[20]](#references)</sup> Hii ni muhimu kwa kuelewa trafiki ya HTTPS ya ndani bila kushambulia TLS yenyewe.

Endesha client huku key logging ikiwa imewashwa.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Nasa trafiki kwa wakati huohuo.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Kisha pakia `/tmp/tls.pcap` na `/tmp/sslkeys.log` katika Wireshark. Hili hufanya kazi tu wakati maktaba ya mteja inaunga mkono uandishi wa funguo kwa mtindo wa NSS na unaweza kuweka mazingira kabla ya muunganisho kuanzishwa.<sup>[[20]](#references)[[21]](#references)</sup>

## Mwingiliano na Unix Socket na Command Injection

Unix sockets ni sehemu za mwisho za IPC za ndani.<sup>[[5]](#references)</sup> Zinaweza kufichua HTTP APIs, protokali maalum au vidhibiti vya amri visivyo salama.<sup>[[12]](#references)[[14]](#references)</sup>

Socket inayomilikiwa na root na yenye ruhusa ya kuandika kwa kikundi ni mpaka wa uidhinishaji, si udhaifu yenyewe. Linganisha kikundi na mode yake na akaunti ya sasa, tambua mchakato unaosikiliza, na kagua kile ambacho mchakato huo hukubali kutoka kwa wateja kabla ya kutathmini hatari. Hasa, huduma yenye ruhusa za juu inayotekeleza PHP iliyowasilishwa inaweza kuvuka mpaka mwingine ikiwa pia inaamini njia ya `php.ini` iliyochaguliwa na mwitaji au inamruhusu mwitaji kubadilisha `disable_functions` au `open_basedir`; kagua usanidi unaotumika na njia ya uthibitishaji wa huduma. [Mwongozo wa usanidi wa PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) unaeleza maagizo hayo. Metadata ya socket pekee haithibitishi utekelezaji wa msimbo.

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

Wasiliana kupitia raw socket.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Ikiwa ingizo la socket linalodhibitiwa na mtumiaji litapitishwa kwa shell au helper yenye mapendeleo ya juu, linaweza kusababisha command injection.<sup>[[26]](#references)</sup> Kwa mfano mahususi, angalia [Socket Command Injection](socket-command-injection.md).

## Mapitio ya nftables na Mabadiliko ya Sheria Yaliyoidhinishwa

Sheria za firewall ya ndani zinaweza kueleza kwa nini huduma inaonekana ndani ya mfumo lakini imezuiwa kutoka mbali, au kwa nini port ya juu inaonekana kutofikika kutoka kwenye kiolesura kimoja.<sup>[[22]](#references)</sup>

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

Katika maabara iliyoidhinishwa, ondoa sheria mahususi ya kuzuia kwa kutumia handle.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Pendelea kufuta handle husika badala ya kusafisha jedwali zima. Mbinu hii ni kutambua kichujio mahususi kinachosababisha tabia hiyo na kubadilisha kanuni hiyo pekee.<sup>[[22]](#references)</sup>

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

Zipe kipaumbele huduma zinazopatikana tu ndani ya mfumo, zinazoendeshwa na mtumiaji mwenye mamlaka ya juu zaidi, zinazofichua vitendaji vya admin/debug, au zinazoamini wateja wa loopback/mtandao wa kontena.

## References

- [1] [ss(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Usanifu wa Ugawaji Anwani wa IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Uelekezaji upya (Mwongozo wa Marejeleo wa Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [matumizi ya timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Mbinu za Port Scanning (Mwongozo wa Marejeleo wa Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Ugunduzi wa Host (Mwongozo wa Marejeleo wa Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Uainishaji wa Port na Mpangilio wa Scan (Mwongozo wa Marejeleo wa Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — ukurasa wa mwongozo wa Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — ukurasa wa mwongozo wa OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Mwongozo wa zana ya mstari wa amri ya curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — Nyaraka za OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Mpango wa Uthibitishaji wa HTTP wa 'Basic'](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [matumizi ya base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — Nyaraka za OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki ya Wireshark](https://wiki.wireshark.org/tls)
- [21] [Mwongozo wa Mtumiaji wa Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Mwongozo wa nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Ugawaji wa Anwani kwa Mitandao ya Ndani Binafsi (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Mfumo wa Uidhinishaji wa OAuth 2.0: Matumizi ya Tokeni ya Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Kutokubatilisha Vizuri Vipengele Maalum Vinavyotumika kwenye Amri ya OS](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Ilani ya mshughulikiaji wa aiohttp: traversal ya njia tuli kwa kutumia follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — tokeni ya Jupyter imefichuliwa kupitia systemd na hoja za mchakato](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
