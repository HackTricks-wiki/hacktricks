# Yereli internete açma

{{#include ../banners/hacktricks-training.md}}

**Bu sayfanın amacı, diğer sunucuya herhangi bir şey yüklemeden (gerekirse yalnızca yerel makineye yükleyerek) yerel ham TCP portlarını ve yerel web sitelerini (HTTP) internete açmak için alternatifler sunmaktır.**

Bir hizmeti genel bir relay üzerinden yayınlamak yerine hostlar arasında yönlendirme yapmak için bkz. [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md).

## **Serveo**

Serveo'nun belgelerinde, HTTP endpoint'leri için SSH forwarding ve özel/genel TCP forwarding açıklanmaktadır. `0` portu, anonim oturumlarda bile rastgele bir genel TCP portu talep eder; ancak bu oturumların süresi ve bağlantı sayısı sınırlıdır. Belirli bir genel TCP portu talep etmek için ücretli hesap gerekir.<sup>[[1]](#references)</sup>

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

ngrok'un CLI dokümantasyonu HTTP ve TCP tünellerini açıklar. TCP uç noktaları için hesapta rezerve edilmiş bir TCP adresi gerekir; ücretsiz plan ayrıca geçerli bir ödeme yöntemi ister, ancak FAQ'da bu yöntemden ücret alınmadığı belirtilir.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Eski Telebit.js CLI yardım belgelerinde HTTPS yönlendirmesi için `telebit http <port>`, ham TCP için `telebit tcp <local> [remote]` komutları açıklanır; kullanılabilirlik dağıtıma ve relay'e bağlıdır.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXpose'un güncel sitesinde `loclx tunnel http --to 3000` komutu belgeleniyor, HTTP/TLS/TCP/UDP desteği listeleniyor ve ücretsiz planın kişisel/hafif ticari kullanımı kapsadığı, TCP tunneling özelliğinin ise ücretli planlarda sunulduğu belirtiliyor.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose, HTTP/HTTPS yerel URL'leri için `expose share` komutunu ve TCP portları için yalnızca PRO kullanıcılarına sunulan `expose share-port` komutunu belgeler.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Resmi localtunnel deposu, test amacıyla localhost’u internete açmayı açıklar ve aşağıdaki NPX komutunu belgeler.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare'ın güncel belgelerinde yerel geliştirme için kimlik doğrulaması gerektirmeyen "Quick" tüneller gösteriliyor ve ürün genel bakışında desteklenen yayınlanmış protokoller arasında HTTP, HTTPS, TCP, SSH ve RDP listeleniyor.<sup>[[11]](#references)[[12]](#references)</sup> HTTP(S)'den farklı olarak, yayınlanmış TCP, SSH ve RDP rotalarına standart bir istemciyle doğrudan erişilemez: Cloudflare, bağlanan istemcide `cloudflared` gerektirir; dolayısıyla bu rotalar, ham TCP için bu sayfanın istemci kurmadan kullanma gereksinimini karşılamaz.<sup>[[24]](#references)</sup>

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

Adlandırılmış tüneller YAML içinde birden fazla ingress kuralı tanımlayabilir; Cloudflare Access policies, yayımlanan uygulamalara erişimi denetleyebilir ve Cloudflare, connector'ları çalıştırmak için service ve Docker deployment yollarını belgeler. Quick Tunnels, 200 eşzamanlı istek sınırı olan ve Server-Sent Events (SSE) desteği sunmayan anonim, geçici test tünelleridir.<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale'ın güncel CLI'ı, yalnızca tailnet içinde paylaşım için Serve'ü, herkese açık paylaşım içinse Funnel'ı kullanır. Komutlar HTTP/HTTPS reverse-proxy hedeflerini ve TCP forwarding'i destekler; Funnel'ın ham TCP modu 443, 8443 ve 10000 portlarıyla sınırlıdır.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

`--bg` seçeneğini, ön planda çalışan bir süreç tutmadan yapılandırmayı kalıcı hâle getirmek için kullanın; hangi hizmetlere herkese açık internetten erişilebildiğini denetlemek için `tailscale funnel status` komutunu kullanın. HTTPS Funnel hedeflerinde Tailscale, isteği yerel hizmete iletmeden önce TLS'nin yerel düğümde sonlandırıldığını belgeliyor.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp`, rendezvous sunucusunu (`frps`) ve istemciyi (`frpc`) sizin yönettiğiniz, kendi barındırabileceğiniz bir seçenektir; belgeleri, NAT veya güvenlik duvarı arkasındaki yerel hizmetlerin öngörülebilir uzak portlar/alan adlarıyla yönlendirilmesini kapsar.<sup>[[20]](#references)</sup>

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

Mevcut proje belgelerinde QUIC taşıma protokolü, token/OIDC kimlik doğrulaması, bant genişliği sınırları, sağlık kontrolleri ve Go-template aralık eşlemeleri yer alır. Bu seçeneklerden herhangi birini kullanmadan önce dağıtımınıza uygun sürümün belgelerine başvurun.<sup>[[20]](#references)</sup>

## Pinggy (SSH tabanlı)

Pinggy, 443 numaralı port üzerinden SSH ters yönlendirmeyi belgeliyor; bu nedenle giden 22 numaralı port üzerindeki SSH bağlantılarının engellendiği ağlarda çalışabilir. Ücretsiz planın oturumu 60 dakika sonra zaman aşımına uğrar ve yeniden bağlanıldığında yeni bir URL kullanılır. Pro planı ise kalıcı tüneller ve özel alan adları sunar.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Pro'da özel domain'ler ve kalıcı tüneller talep edebilirsiniz.<sup>[[22]](#references)</sup> Komutu bir döngü içinde çalıştırarak geçici tünelleri otomatik olarak yenileyebilirsiniz.

## Tehdit istihbaratı ve OPSEC notları

Saldırganlar, Cloudflare'ın kimlik doğrulaması gerektirmeyen `trycloudflare.com` uç noktaları da dahil olmak üzere geçici tünelleri kötüye kullanarak geçici altyapı üzerinden Remote Access Trojan'lar dağıttı. Proofpoint, ilk olarak Şubat 2024'te gözlemlenen ve Xworm, AsyncRAT, VenomRAT, GuLoader ve Remcos'u içeren faaliyetleri bildirdi ve geçici tünellerin statik engelleme listelerine dayanan savunmaları zorlaştırdığını belirtti.<sup>[[23]](#references)</sup> Tünelleri ve domain'leri proaktif olarak değiştirmeyi ve blue-team tespiti veya altyapı engelleme girişimlerini erken fark edebilmek için kullandığınız tünel hizmetine yönelik tipik harici DNS sorgularını izlemeyi değerlendirin.

## References

- [1] [Serveo Belgeleri](https://serveo.net/docs/)
- [2] [SocketXP Belgeleri - Başlarken](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent Komut Satırı Arayüzü](https://ngrok.com/docs/agent/cli)
- [4] [ngrok SSS](https://ngrok.com/docs/faq)
- [5] [Telebit.js eski CLI yardım metni](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose Belgeleri](https://localxpose.gitbook.io/docs)
- [8] [Expose - Siteleri paylaşma](https://expose.dev/docs/client/sharing)
- [9] [Expose - TCP portlarını paylaşma](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel deposu](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare Belgeleri - Cloudflare Tunnel kurulumu](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Cloudflare Tunnel genel bakışı](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare Belgeleri - Yararlı tunnel komutları](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare Belgeleri - Yönlendirme](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare Belgeleri - Yapılandırma dosyası](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access politikaları](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare Belgeleri - Çalıştırma parametreleri](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve komutu](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel komutu](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy deposu](https://github.com/fatedier/frp)
- [21] [Pinggy Belgeleri - Kullanım](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Basit Localhost tünelleri](https://pinggy.io/)
- [23] [Proofpoint - Tehdit aktörü, RAT dağıtmak için Cloudflare Tunnels'ı kötüye kullanıyor](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Cloudflare Belgeleri - Tunnel yönlendirmesi ve desteklenen protokoller](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
