# Yereli internete açma

{{#include ../../banners/hacktricks-training.md}}

**Bu sayfanın amacı, diğer server'a herhangi bir şey yüklemeye GEREK KALMADAN (gerekiyorsa yalnızca local'e yükleyerek) en azından local raw TCP portlarını ve local web'leri (HTTP) internete açmaya olanak tanıyan alternatifleri sunmaktır.**

## **Serveo**

[https://serveo.net/](https://serveo.net/) üzerinden, çeşitli HTTP ve port forwarding özelliklerini **ücretsiz** olarak sunar.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

[https://www.socketxp.com/download](https://www.socketxp.com/download) adresinden tcp ve http'yi açığa çıkarmaya olanak tanır:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

[https://ngrok.com/](https://ngrok.com/) üzerinden http ve tcp portlarını internete açabilirsiniz:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

[https://telebit.cloud/](https://telebit.cloud/) üzerinden http ve tcp portlarını expose etmeye olanak tanır:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

[https://localxpose.io/](https://localxpose.io/) üzerinden **ücretsiz olarak** çeşitli http ve port forwarding özellikleri kullanılabilir.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

[https://expose.dev/](https://expose.dev/) üzerinden http ve tcp portlarını internete açabilirsiniz:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

[https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel), HTTP hizmetini ücretsiz olarak internete açmaya olanak tanır:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare'ın `cloudflared` CLI'ı, hızlı demolar için kimlik doğrulaması gerektirmeyen "Quick" tunnel'lar veya kendi domain/hostname'larınıza bağlı named tunnel'lar oluşturabilir. Cloudflare edge üzerinden yönlendirilen HTTP(S) reverse proxy'lerin yanı sıra raw TCP mapping'lerini de destekler.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels, `tunnel.yml` içinde birden fazla ingress kuralı (HTTP, SSH, RDP vb.) tanımlamanıza olanak tanır, Cloudflare Access üzerinden servis başına erişim politikalarını destekler ve kalıcılık için systemd container'ları olarak çalışabilir. Quick Tunnels anonim ve geçicidir; phishing payload staging veya webhook testleri için idealdir, ancak Cloudflare uptime garantisi vermez.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+, birleşik `tailscale serve` (tailnet içinde paylaşım) ve `tailscale funnel` (daha geniş internete yayınlama) iş akışlarını sunar. Her iki komut da automatic TLS ve kısa `*.ts.net` hostname'leri ile HTTP(S) reverse proxy yapabilir veya raw TCP'yi forward edebilir.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg`, foreground process tutmadan yapılandırmayı kalıcı hale getirir. Hangi servislerin public internet üzerinden erişilebilir olduğunu denetlemek için `tailscale funnel status` komutunu kullanın. Funnel, TLS'yi local node üzerinde sonlandırdığından credential prompt'ları, header'lar veya mTLS enforcement sizin kontrolünüzde kalabilir.

## Fast Reverse Proxy (frp)

`frp`, rendezvous server (`frps`) ve client'ı (`frpc`) kontrol ettiğiniz self-hosted bir seçenektir. Zaten bir VPS sahibi olan ve öngörülebilir domain/port'lar isteyen red team'ler için idealdir.

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

Son sürümler QUIC transport, token/OIDC auth, bandwidth caps, health checks ve Go-template-based range mappings ekliyor; bu da farklı hostlardaki implantlara geri bağlanan birden fazla listener'ı hızlıca ayağa kaldırmak için kullanışlıdır.<sup>[[4]](#references)</sup>

## Pinggy (SSH tabanlı)

Pinggy, TCP/443 üzerinden SSH-accessible tunnel'lar sağlar; bu nedenle yalnızca HTTPS'e izin veren captive proxy'lerin arkasında bile çalışır. Ücretsiz tier'daki session'lar 60 dakika sürer ve hızlı demolar veya webhook relay'leri için script'lenebilir.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Ücretli tier'da custom domain'ler ve daha uzun ömürlü tunnel'lar talep edebilir veya command'i bir loop içine sararak tunnel'ları otomatik olarak yenileyebilirsiniz.

## Tehdit istihbaratı ve OPSEC notları

Saldırganlar, ephemeral tunneling yöntemlerini (özellikle Cloudflare'ın kimlik doğrulaması gerektirmeyen `trycloudflare.com` endpoint'lerini) Remote Access Trojan payload'larını stage etmek ve C2 infrastructure'ını gizlemek için giderek daha fazla kötüye kullanıyor. Proofpoint, Şubat 2024'ten bu yana AsyncRAT, Xworm, VenomRAT, GuLoader ve Remcos payload'larını, download stage'lerini kısa ömürlü TryCloudflare URL'lerine yönlendirerek dağıtan campaign'leri takip etti. Bu durum, geleneksel static blocklist'leri çok daha az etkili hale getiriyor. Tunnel'ları ve domain'leri proaktif olarak rotate etmeyi düşünün; ancak blue-team detection veya infrastructure blocking girişimlerini erkenden tespit edebilmek için kullandığınız tunneler'a yönelik belirgin external DNS lookup'larını da monitor edin.<sup>[[2]](#references)</sup>

## Referanslar

- [1] [Cloudflare Docs - Locally-managed tunnel oluşturma](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Serve ve Funnel'ı yeniden sunma](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Kullanım](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
