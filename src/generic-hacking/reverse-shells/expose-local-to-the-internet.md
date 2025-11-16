# Yereli internete açma

{{#include ../../banners/hacktricks-training.md}}

**Bu sayfanın amacı, en azından yerel raw TCP portlarını ve yerel webleri (HTTP) internete, diğer sunucuya hiçbir şey kurmaya gerek kalmadan (gerekirse sadece yerelde kurulum yaparak) açmaya olanak veren alternatifler önermektir.**

## **Serveo**

From [https://serveo.net/](https://serveo.net/), https://serveo.net/ üzerinden çeşitli http ve port forwarding özelliklerini **ücretsiz** sunar.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download) üzerinden, tcp ve http servislerini internete açmaya olanak tanır:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) adresinden, http ve tcp portlarını internete açmaya izin verir:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) üzerinden http ve tcp portlarını açmaya olanak tanır:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) üzerinden birkaç http ve port yönlendirme özelliğini **ücretsiz** sunar.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/) üzerinden http ve tcp portlarını expose etmeye izin verir:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) üzerinden ücretsiz olarak http'yi dışarıya açmanızı sağlar:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare'ın `cloudflared` CLI'si hızlı demolar için kimlik doğrulaması gerektirmeyen "Quick" tüneller veya kendi domain/hostnames'inize bağlı isimlendirilmiş tüneller oluşturabilir. HTTP(S) reverse proxies ile Cloudflare'ın edge'i üzerinden yönlendirilen ham TCP eşlemelerini destekler.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels, `tunnel.yml` içinde birden fazla ingress kuralı (HTTP, SSH, RDP, vb.) tanımlamanıza, Cloudflare Access aracılığıyla hizmet başına erişim politikalarını desteklemenize ve kalıcılık için systemd container'ları olarak çalıştırılabilmenize olanak tanır. Quick Tunnels anonim ve geçicidir—phishing payload staging veya webhook testleri için idealdir, ancak Cloudflare çalışma süresini garanti etmez.

## Tailscale Funnel / Serve

Tailscale v1.52+ birleşik `tailscale serve` (tailnet içinde paylaşım) ve `tailscale funnel` (daha geniş internete yayınlama) iş akışları ile gelir. Her iki komut da otomatik TLS ve kısa `*.ts.net` host adları ile HTTP(S) için reverse proxy yapabilir veya ham TCP'yi iletebilir.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg` kullanarak yapılandırmayı ön planda bir süreç çalıştırmadan kalıcı hale getirin ve `tailscale funnel status` ile hangi servislerin genel internetten erişilebilir olduğunu denetleyin. Funnel, TLS'yi yerel node üzerinde sonlandırdığı için herhangi bir kimlik bilgisi istemi, header veya mTLS uygulaması kontrolünüz altında kalabilir.

## Fast Reverse Proxy (frp)

`frp`, rendezvous sunucusu (`frps`) ve istemci (`frpc`) üzerinde kontrol sahibi olduğunuz kendi barındırdığınız bir seçenektir. Zaten bir VPS'e sahip olan ve öngörülebilir domains/ports isteyen red teams için idealdir.

<details>
<summary>Örnek frps/frpc yapılandırması</summary>
```bash
# Server: bind TCP/HTTP entry points and enable dashboard
./frps -c frps.toml

# Client: forward local 22 to remote port 6000 and a web app to vhost
./frpc -c <<'EOF'
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
```
</details>

Son sürümler QUIC transport, token/OIDC auth, bandwidth caps, health checks ve Go-template-based range mappings ekliyor — farklı host'lardaki implantlara geri yönlenen birden fazla listener'ı hızlıca ayağa kaldırmak için kullanışlı.

## Pinggy (SSH-based)

Pinggy, TCP/443 üzerinden SSH-accessible tüneller sağlar; bu yüzden yalnızca HTTPS'e izin veren captive proxies'in arkasında bile çalışır. Oturumlar free tier'da 60 dakika sürer ve hızlı demo'lar veya webhook relay'leri için scriptlenebilir.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Ücretli planda özel domainler ve daha uzun ömürlü tüneller talep edebilir veya komutu bir döngü içine sararak tünelleri otomatik olarak yeniden kullanabilirsiniz.

## Tehdit istihbaratı & OPSEC notları

Saldırganlar, geçici tünelleme yöntemini giderek daha fazla kötüye kullanıyor (özellikle Cloudflare'ın kimlik doğrulaması olmayan `trycloudflare.com` uç noktalarını) Remote Access Trojan payload'ları hazırlamak ve C2 altyapısını gizlemek için. Proofpoint, Şubat 2024'ten beri AsyncRAT, Xworm, VenomRAT, GuLoader ve Remcos'u indirme aşamalarını kısa ömürlü TryCloudflare URL'lerine yönlendirerek dağıtan kampanyaları takip etti; bu da geleneksel statik blocklist'leri çok daha az etkili hale getiriyor. Tünelleri ve domainleri proaktif olarak döndürmeyi düşünün; ayrıca kullandığınız tünelleme servisine yönelik ayırt edici dış DNS sorgularını da izleyin, böylece blue-team tespitlerini veya altyapı engelleme girişimlerini erken fark edebilirsiniz.

## References

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
