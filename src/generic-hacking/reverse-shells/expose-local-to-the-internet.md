# Yereli internete açma

**Bu sayfanın amacı, diğer sunucuya herhangi bir şey yüklemeye gerek kalmadan (gerekirse yalnızca local'e yükleyerek) en azından local raw TCP portlarını ve local web'leri (HTTP) internete açmaya olanak tanıyan alternatifler önermektir.**

## **Serveo**

Serveo'nun dokümantasyonu, HTTP endpoint'leri için SSH forwarding'i ve private/public TCP forwarding'i açıklar; 80/443 dışındaki bir public TCP portu istemek (rastgele bir port için port 0 dahil) kayıtlı bir kullanıcı gerektirir.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

SocketXP'in başlangıç kılavuzu, TCP ve HTTP tunnel'ları için `socketxp connect tcp://localhost:22` ve `socketxp connect http://localhost:8080` komutlarını belgeler; agent önce bir portal token'ı ile kimlik doğrulaması yapar.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

ngrok'in CLI belgeleri HTTP ve TCP tünellerini açıklar; SSS bölümünde, ücretsiz katmandaki TCP endpoint'lerinin geçerli bir ödeme yöntemi gerektirdiği ve karttan ücret alınmadığı belirtilir.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

Eski Telebit.js CLI yardım belgeleri, HTTPS yönlendirme için `telebit http <port>` ve raw TCP için `telebit tcp <local> [remote]` komutlarını belgeler; kullanılabilirlik dağıtıma ve relay'e bağlıdır.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

LocalXpose'un mevcut sitesi `loclx tunnel http --to 3000` komutunu belgelendirir, HTTP/TLS/TCP/UDP desteğini listeler ve ücretsiz planın kişisel/hafif ticari kullanımı kapsadığını, TCP tunneling özelliğinin ise ücretli planlara ait olduğunu belirtir.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
Expose, HTTP/HTTPS yerel URL'leri için `expose share` ve TCP portları için yalnızca PRO'ya özel `expose share-port` komutunu sunar.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Resmi localtunnel repository'si, test amacıyla localhost'u internete açmayı açıklar ve aşağıdaki NPX komutunu belgeler.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Cloudflare'ın güncel dokümanları, yerel geliştirme için kimlik doğrulaması gerektirmeyen "Quick" tunnel'ları gösterir ve ürün genel bakışında desteklenen yayınlanmış protokoller arasında HTTP, HTTPS, TCP, SSH ve RDP'yi listeler.<sup>[[11]](#references)[[12]](#references)</sup>

Yerel olarak yönetilen adlandırılmış bir tunnel için Cloudflare, `tunnel login`, `create`, `route dns` ve `--config ... run ...` workflow'unu belgeler.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Named tunnel'lar YAML'de birden fazla ingress kuralı tanımlayabilir; Cloudflare Access policies, yayınlanan application'lara erişimi kontrol edebilir ve Cloudflare, connector'ları çalıştırmak için service ve Docker deployment path'lerini belgeler. Quick Tunnels, 200 eşzamanlı request limiti olan ve Server-Sent Events (SSE) desteği sunmayan anonim, geçici testing tunnel'larıdır.<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale'in güncel CLI'ı tailnet-only sharing için Serve'ü, public sharing için ise Funnel'ı kullanır. Komutlar HTTP/HTTPS reverse-proxy target'larını ve TCP forwarding'i destekler; Funnel'ın raw TCP modu 443, 8443 ve 10000 portlarıyla sınırlıdır.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
`--bg` seçeneğini foreground process'i açık tutmadan yapılandırmayı kalıcı hale getirmek için kullanın ve hangi servislerin public internet üzerinden erişilebilir olduğunu denetlemek için `tailscale funnel status` komutunu kullanın. HTTPS Funnel hedefleri için Tailscale, isteği local service'e iletmeden önce local node üzerinde TLS termination gerçekleştirildiğini belirtir.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`, rendezvous server (`frps`) ve client (`frpc`) üzerinde kontrol sahibi olduğunuz self-hosted bir seçenektir; documentation, NAT veya firewall arkasındaki local service'lerin deterministic remote port/domain'ler üzerinden forward edilmesini kapsar.<sup>[[20]](#references)</sup>

<details>
<summary>Örnek frps/frpc yapılandırması</summary>
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

Mevcut proje belgelerinde QUIC transport, token/OIDC authentication, bandwidth limits, health checks ve Go-template range mappings bulunur; bu seçeneklerden herhangi birini kullanmadan önce deployment'ınıza uygun release'e başvurun.<sup>[[20]](#references)</sup>

## Pinggy (SSH tabanlı)

Pinggy, port 443 üzerinden SSH reverse forwarding kullanımını belgeler; bu nedenle outbound SSH bağlantılarının port 22'de engellendiği network'lerde çalışabilir. Free plan 60 dakika sonra timeout olur ve yeniden bağlanıldığında yeni bir URL kullanır; Pro ise persistent tunnels ve custom domains ekler.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Pro'da özel alan adları ve kalıcı tüneller talep edebilirsiniz.<sup>[[22]](#references)</sup> Komutu bir döngü içine alarak geçici tünelleri otomatik olarak yeniden oluşturabilirsiniz.

## Tehdit istihbaratı ve OPSEC notları

Saldırganlar, Cloudflare'ın kimlik doğrulaması gerektirmeyen `trycloudflare.com` uç noktaları da dahil olmak üzere, geçici altyapı üzerinden Remote Access Trojan dağıtmak için ephemeral tunneling yöntemlerini kötüye kullandı. Proofpoint, ilk olarak Şubat 2024'te gözlemlenen ve Xworm, AsyncRAT, VenomRAT, GuLoader ve Remcos'u içeren faaliyetleri raporladı ve geçici tünellerin statik blocklist'lere dayanan savunmaları zorlaştırdığını belirtti.<sup>[[23]](#references)</sup> Tünelleri ve alan adlarını proaktif olarak döndürmeyi ve kullandığınız tunneler'a yönelik belirgin harici DNS sorgularını izlemeyi değerlendirin; böylece blue-team tespiti veya altyapı engelleme girişimlerini erkenden fark edebilirsiniz.

## References

- [1] [Serveo Belgeleri](https://serveo.net/docs/)
- [2] [SocketXP Belgeleri - Başlarken](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Komut Satırı Arayüzü](https://ngrok.com/docs/agent/cli)
- [4] [ngrok SSS](https://ngrok.com/docs/faq)
- [5] [Telebit.js eski CLI yardımı](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose Belgeleri](https://localxpose.gitbook.io/docs)
- [8] [Expose - Siteleri paylaşma](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP portlarını paylaşma](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel repository](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Belgeleri - Cloudflare Tunnel kurulumu](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel genel bakışı](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Belgeleri - Faydalı tünel komutları](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Belgeleri - Yönlendirme](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Belgeleri - Yapılandırma dosyası](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access politikaları](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Belgeleri - Çalıştırma parametreleri](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve komutu](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel komutu](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy repository](https://github.com/fatedier/frp)
- [21] [Pinggy Belgeleri - Kullanım](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Basit Localhost Tünelleri](https://pinggy.io/)
- [23] [Proofpoint - Tehdit aktörü, RAT dağıtmak için Cloudflare Tunnel'larını kötüye kullanıyor](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
