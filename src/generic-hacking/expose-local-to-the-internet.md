# Yereli internete açma

{{#include ../banners/hacktricks-training.md}}

**Bu sayfanın amacı, diğer sunucuya herhangi bir şey yüklemeden (gerekirse yalnızca yerel makineye yükleyerek) yerel ham TCP portlarını ve yerel web sunucularını (HTTP) internete açmaya olanak tanıyan alternatifler sunmaktır.**

## **Serveo**

Serveo'nun belgeleri, HTTP uç noktaları için SSH forwarding'i ve özel/genel TCP forwarding'i açıklar; 80/443 dışındaki bir genel TCP portunu (rastgele bir port için 0 dâhil) istemek için kayıtlı bir kullanıcı gerekir.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP'nin başlangıç kılavuzunda TCP ve HTTP tünelleri için `socketxp connect tcp://localhost:22` ve `socketxp connect http://localhost:8080` komutları belgelenmiştir; agent önce bir portal token ile kimlik doğrulaması yapar.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok'un CLI'ı HTTP ve TCP tünellerini belgeler; SSS sayfasında ücretsiz katmandaki TCP uç noktaları için geçerli bir ödeme yöntemi gerektiği ve karttan ücret alınmadığı belirtilir.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Eski Telebit.js CLI yardım belgelerinde, HTTPS yönlendirme için `telebit http <port>` ve ham TCP için `telebit tcp <local> [remote]` komutları belgelenmiştir; kullanılabilirlik dağıtıma ve relay’e bağlıdır.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXpose'un güncel sitesi `loclx tunnel http --to 3000` komutunu belgeliyor, HTTP/TLS/TCP/UDP desteğini listeliyor ve ücretsiz planın kişisel/hafif ticari kullanımı kapsadığını, TCP tunneling'in ise ücretli plan özelliği olduğunu belirtiyor.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose, HTTP/HTTPS yerel URL'leri için `expose share` komutunu, TCP portları içinse yalnızca PRO sürümünde kullanılabilen `expose share-port` komutunu belgeler.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Resmi localtunnel deposu, test için localhost'u dışarıya açmayı anlatır ve aşağıdaki NPX komutunu belgeler.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare'ın güncel belgeleri, yerel geliştirme için kimlik doğrulaması gerektirmeyen "Quick" tünelleri gösteriyor ve ürün genel bakışında yayımlanması desteklenen protokoller arasında HTTP, HTTPS, TCP, SSH ve RDP'yi listeliyor.<sup>[[11]](#references)[[12]](#references)</sup>

Yerel olarak yönetilen adlandırılmış bir tünel için Cloudflare, `tunnel login`, `create`, `route dns` ve `--config ... run ...` iş akışını belgeliyor.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Adlandırılmış tüneller YAML içinde birden fazla ingress kuralı tanımlayabilir; Cloudflare Access policies, yayımlanan uygulamalara erişimi denetleyebilir ve Cloudflare, connector’ları çalıştırmak için service ve Docker deployment yollarını belgeler. Quick Tunnels, 200 eşzamanlı istek sınırı olan ve Server-Sent Events (SSE) desteği sunmayan, anonim ve geçici test tünelleridir.<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale’in mevcut CLI’ı, yalnızca tailnet içi paylaşım için Serve’ü, herkese açık paylaşım için ise Funnel’ı kullanır. Komutlar HTTP/HTTPS reverse-proxy hedeflerini ve TCP yönlendirmeyi destekler; Funnel’ın ham TCP modu 443, 8443 ve 10000 portlarıyla sınırlıdır.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

`--bg` kullanarak yapılandırmayı arka plan süreci çalıştırmadan kalıcı hâle getirin ve hangi hizmetlere genel internetten erişilebildiğini denetlemek için `tailscale funnel status` komutunu kullanın. HTTPS Funnel hedefleri için Tailscale, isteği yerel hizmete iletmeden önce TLS'nin yerel düğümde sonlandırıldığını belgeliyor.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`, buluşma sunucusunu (`frps`) ve istemciyi (`frpc`) sizin yönettiğiniz, kendi kendinize barındırabileceğiniz bir seçenektir; belgeleri, NAT veya güvenlik duvarı arkasındaki yerel hizmetlerin sabit uzak portlar/alan adları üzerinden yönlendirilmesini kapsar.<sup>[[20]](#references)</sup>

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

Mevcut proje belgelerinde QUIC aktarımı, token/OIDC kimlik doğrulaması, bant genişliği sınırları, sağlık kontrolleri ve Go-template aralık eşlemeleri yer alıyor; bu seçeneklerden herhangi birini kullanmadan önce dağıtımınıza uygun sürümün belgelerine başvurun.<sup>[[20]](#references)</sup>

## Pinggy (SSH tabanlı)

Pinggy, 443 numaralı port üzerinden SSH ters yönlendirmeyi belgeliyor; bu sayede giden 22 numaralı porttaki SSH bağlantılarının engellendiği ağlarda çalışabilir. Ücretsiz plan 60 dakika sonra zaman aşımına uğrar ve yeniden bağlanıldığında yeni bir URL kullanır. Pro planı ise kalıcı tüneller ve özel alan adları sunar.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Pro'da özel alan adları ve kalıcı tüneller talep edebilirsiniz.<sup>[[22]](#references)</sup> Komutu bir döngüye alarak geçici tünelleri otomatik olarak yenileyebilirsiniz.

## Tehdit istihbaratı ve OPSEC notları

Saldırganlar, Cloudflare'ın kimlik doğrulaması gerektirmeyen `trycloudflare.com` uç noktaları da dahil olmak üzere geçici tünelleme hizmetlerini kötüye kullanarak geçici altyapı üzerinden Remote Access Trojans dağıttı. Proofpoint, ilk olarak Şubat 2024'te gözlemlenen ve Xworm, AsyncRAT, VenomRAT, GuLoader ve Remcos'u içeren etkinlikleri bildirdi; ayrıca geçici tünellerin statik engelleme listelerine dayanan savunmaları zorlaştırdığını belirtti.<sup>[[23]](#references)</sup> Tünelleri ve alan adlarını proaktif olarak değiştirmeyi ve kullandığınız tünel hizmetine yönelik belirgin harici DNS sorgularını izlemeyi değerlendirin. Böylece blue-team tespitini veya altyapıyı engelleme girişimlerini erkenden fark edebilirsiniz.

## References

- [1] [Serveo Belgeleri](https://serveo.net/docs/)
- [2] [SocketXP Belgeleri - Başlangıç](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Komut Satırı Arayüzü](https://ngrok.com/docs/agent/cli)
- [4] [ngrok SSS](https://ngrok.com/docs/faq)
- [5] [Telebit.js eski CLI yardımı](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose Belgeleri](https://localxpose.gitbook.io/docs)
- [8] [Expose - Siteleri paylaşma](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP portlarını paylaşma](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel deposu](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Belgeleri - Cloudflare Tunnel kurulumu](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel genel bakış](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Belgeleri - Kullanışlı tünel komutları](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Belgeleri - Yönlendirme](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Belgeleri - Yapılandırma dosyası](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access ilkeleri](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Belgeleri - Çalıştırma parametreleri](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve komutu](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel komutu](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy deposu](https://github.com/fatedier/frp)
- [21] [Pinggy Belgeleri - Kullanım](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Basit localhost tünelleri](https://pinggy.io/)
- [23] [Proofpoint - Tehdit aktörü RAT dağıtmak için Cloudflare Tunnels'ı kötüye kullanıyor](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
