# Phơi dịch vụ local ra internet

{{#include ../banners/hacktricks-training.md}}

**Mục tiêu của trang này là đề xuất các giải pháp thay thế cho phép ít nhất phơi các cổng TCP thô và website local (HTTP) ra internet mà KHÔNG cần cài đặt gì trên server còn lại (chỉ cần cài trên máy local nếu cần).**

Để chuyển tiếp giữa các host thay vì xuất bản dịch vụ thông qua relay công khai, xem [Tunneling và chuyển tiếp cổng](tunneling-and-port-forwarding.md).

## **Serveo**

Tài liệu của Serveo mô tả tính năng chuyển tiếp SSH cho các endpoint HTTP và chuyển tiếp TCP riêng tư/công khai. Cổng `0` sẽ yêu cầu một cổng TCP công khai ngẫu nhiên, kể cả với các phiên ẩn danh, nhưng những phiên này bị giới hạn về thời gian và số kết nối; để yêu cầu một cổng TCP công khai cụ thể, cần có tài khoản trả phí.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Hướng dẫn bắt đầu của SocketXP giới thiệu `socketxp connect tcp://localhost:22` và `socketxp connect http://localhost:8080` để tạo tunnel TCP và HTTP; trước tiên, agent được xác thực bằng portal token.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

CLI của ngrok hỗ trợ tunnel HTTP và TCP. Endpoint TCP yêu cầu tài khoản có địa chỉ TCP được đặt trước; gói miễn phí cũng yêu cầu phương thức thanh toán hợp lệ, nhưng theo FAQ thì phương thức này không bị tính phí.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Tài liệu trợ giúp CLI cũ của Telebit.js hướng dẫn dùng `telebit http <port>` để chuyển tiếp HTTPS và `telebit tcp <local> [remote]` cho TCP thô; khả năng sử dụng tùy thuộc vào deployment và relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Trang web hiện tại của LocalXpose hướng dẫn dùng `loclx tunnel http --to 3000`, liệt kê hỗ trợ HTTP/TLS/TCP/UDP và cho biết gói miễn phí dành cho mục đích sử dụng cá nhân/kinh doanh thương mại quy mô nhỏ, trong khi tunneling TCP là tính năng thuộc gói trả phí.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose có tài liệu về `expose share` cho các URL HTTP/HTTPS cục bộ và lệnh `expose share-port` chỉ dành cho PRO để mở các cổng TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Repository chính thức của localtunnel mô tả cách đưa localhost ra ngoài để kiểm thử và ghi lại lệnh NPX bên dưới.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Tài liệu hiện tại của Cloudflare giới thiệu các tunnel "Quick" không cần xác thực để phát triển cục bộ, và phần tổng quan sản phẩm liệt kê HTTP, HTTPS, TCP, SSH và RDP trong số các giao thức được hỗ trợ khi publish.<sup>[[11]](#references)[[12]](#references)</sup> Không giống HTTP(S), các route TCP, SSH và RDP đã publish không thể truy cập trực tiếp bằng client thông thường: Cloudflare yêu cầu `cloudflared` trên client kết nối, vì vậy các route này không đáp ứng yêu cầu của trang này là không cần cài client để dùng raw TCP.<sup>[[24]](#references)</sup>

Đối với named tunnel được quản lý cục bộ, Cloudflare hướng dẫn quy trình `tunnel login`, `create`, `route dns` và `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels có thể định nghĩa nhiều quy tắc ingress trong YAML; các chính sách Cloudflare Access có thể kiểm soát quyền truy cập vào các ứng dụng được công bố, và Cloudflare tài liệu hóa các phương thức triển khai dịch vụ và Docker để chạy connector. Quick Tunnels là các tunnel thử nghiệm tạm thời, ẩn danh, giới hạn 200 yêu cầu đồng thời và không hỗ trợ Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

CLI hiện tại của Tailscale dùng Serve để chia sẻ chỉ trong tailnet và Funnel để chia sẻ công khai. Các lệnh hỗ trợ đích reverse-proxy HTTP/HTTPS và chuyển tiếp TCP; chế độ TCP thô của Funnel chỉ giới hạn ở các cổng 443, 8443 và 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Dùng `--bg` để lưu cấu hình mà không cần giữ tiến trình chạy ở foreground, và dùng `tailscale funnel status` để kiểm tra các dịch vụ có thể truy cập từ internet công cộng. Với các đích HTTPS Funnel, Tailscale ghi rõ rằng TLS được kết thúc trên node cục bộ trước khi yêu cầu được chuyển tiếp đến dịch vụ cục bộ.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` là một tùy chọn tự host, cho phép bạn kiểm soát máy chủ rendezvous (`frps`) và client (`frpc`); tài liệu của công cụ này hướng dẫn cách chuyển tiếp các dịch vụ cục bộ nằm sau NAT hoặc firewall bằng các cổng/tên miền từ xa có thể xác định trước.<sup>[[20]](#references)</sup>

<details>
<summary>Cấu hình frps/frpc mẫu</summary>

```bash
# Server: start frps with its server configuration
./frps -c frps.toml

# Client: save this as frpc.toml, then start it
cat > frpc.toml <<'EOF'
serverAddr = "c2.example.com"
serverPort = 7000

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "panel"
type = "http"
localPort = 8080
customDomains = ["panel.example.com"]
EOF
./frpc -c frpc.toml
```

</details>

Tài liệu dự án hiện tại bao gồm truyền tải QUIC, xác thực token/OIDC, giới hạn băng thông, kiểm tra tình trạng hoạt động và ánh xạ range trong Go-template — hãy tham khảo phiên bản tương ứng với bản triển khai của bạn trước khi sử dụng bất kỳ tùy chọn nào trong số này.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy mô tả cách chuyển tiếp ngược SSH qua cổng 443, nên có thể hoạt động trong các mạng chặn SSH đi ra trên cổng 22. Gói miễn phí hết thời hạn sau 60 phút và dùng URL mới khi kết nối lại, trong khi gói Pro bổ sung tunnel cố định và tên miền tùy chỉnh.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Bạn có thể yêu cầu domain tùy chỉnh và tunnel duy trì trên Pro.<sup>[[22]](#references)</sup> Bạn có thể tự động tạo lại các tunnel tạm thời bằng cách đặt lệnh trong một vòng lặp.

## Ghi chú về tình báo mối đe dọa và OPSEC

Các đối thủ đã lạm dụng tunnel tạm thời, bao gồm cả các endpoint `trycloudflare.com` không yêu cầu xác thực của Cloudflare, để phát tán Remote Access Trojan thông qua cơ sở hạ tầng tạm thời. Proofpoint báo cáo hoạt động được ghi nhận lần đầu vào tháng 2 năm 2024, liên quan đến Xworm, AsyncRAT, VenomRAT, GuLoader và Remcos; đồng thời lưu ý rằng tunnel tạm thời gây khó khăn cho các biện pháp phòng thủ dựa vào blocklist tĩnh.<sup>[[23]](#references)</sup> Hãy chủ động xoay vòng tunnel và domain, đồng thời theo dõi các truy vấn DNS bên ngoài đặc trưng đến tunneler bạn đang dùng để sớm phát hiện hoạt động phát hiện của blue team hoặc nỗ lực chặn cơ sở hạ tầng.

## References

- [1] [Tài liệu Serveo](https://serveo.net/docs/)
- [2] [Tài liệu SocketXP - Bắt đầu](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Giao diện dòng lệnh ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [Câu hỏi thường gặp về ngrok](https://ngrok.com/docs/faq)
- [5] [Trợ giúp CLI phiên bản cũ của Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Tài liệu LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Chia sẻ website](https://expose.dev/docs/client/sharing)
- [9] [Expose - Chia sẻ cổng TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Kho lưu trữ localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Tài liệu Cloudflare - Thiết lập Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Tổng quan về Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Tài liệu Cloudflare - Các lệnh tunnel hữu ích](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Tài liệu Cloudflare - Định tuyến](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Tài liệu Cloudflare - Tệp cấu hình](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Chính sách Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Tài liệu Cloudflare - Tham số chạy](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Lệnh Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Lệnh Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Kho lưu trữ Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Tài liệu Pinggy - Cách sử dụng](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Tunnel localhost đơn giản](https://pinggy.io/)
- [23] [Proofpoint - Tác nhân đe dọa lạm dụng Cloudflare Tunnels để phát tán RAT](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Tài liệu Cloudflare - Định tuyến tunnel và các giao thức được hỗ trợ](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
