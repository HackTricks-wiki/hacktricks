# Expor local para a internet

{{#include ../../banners/hacktricks-training.md}}

**O objetivo desta página é propor alternativas que permitam, NO MÍNIMO, expor portas TCP locais e websites locais (HTTP) para a internet SEM precisar instalar nada no outro servidor (apenas localmente, se necessário).**

## **Serveo**

A partir de [https://serveo.net/](https://serveo.net/), permite várias funcionalidades de http e port forwarding **gratuitas**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

A partir de [https://www.socketxp.com/download](https://www.socketxp.com/download), permite expor tcp e http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Do [https://ngrok.com/](https://ngrok.com/), ele permite expor portas http e tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

A partir de [https://telebit.cloud/](https://telebit.cloud/) permite expor portas http e tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Segundo [https://localxpose.io/](https://localxpose.io/), permite vários recursos de encaminhamento HTTP e de portas **gratuitos**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

O [https://expose.dev/](https://expose.dev/) permite expor portas http e tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Segundo [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel), ele permite expor HTTP gratuitamente:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

O CLI `cloudflared` da Cloudflare pode criar túneis "Quick" não autenticados para demonstrações rápidas ou túneis nomeados vinculados aos seus próprios domínios/hostnames. Suporta proxies reversos HTTP(S) assim como mapeamentos TCP brutos encaminhados pela edge da Cloudflare.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels permitem que você defina múltiplas ingress rules (HTTP, SSH, RDP, etc.) dentro de `tunnel.yml`, suportam políticas de acesso por serviço via Cloudflare Access e podem rodar como containers systemd para persistência. Quick Tunnels são anônimos e efêmeros — ótimos para phishing payload staging ou webhook tests, mas a Cloudflare não garante uptime.

## Tailscale Funnel / Serve

Tailscale v1.52+ traz os fluxos unificados `tailscale serve` (compartilhar dentro do tailnet) e `tailscale funnel` (publicar para a internet mais ampla). Ambos os comandos podem reverse proxy HTTP(S) ou forward raw TCP com TLS automático e hostnames curtos `*.ts.net`.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Use `--bg` para persistir a configuração sem manter um processo em primeiro plano, e `tailscale funnel status` para auditar quais serviços estão acessíveis a partir da internet pública. Como o Funnel termina o TLS no nó local, quaisquer solicitações de credenciais, cabeçalhos ou a imposição de mTLS podem permanecer sob seu controle.

## Fast Reverse Proxy (frp)

`frp` é uma opção self-hosted onde você controla o servidor rendezvous (`frps`) e o cliente (`frpc`). É ideal para red teams que já possuem um VPS e querem domínios/portas determinísticos.

<details>
<summary>Exemplo de configuração frps/frpc</summary>
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

Lançamentos recentes adicionam QUIC transport, token/OIDC auth, bandwidth caps, health checks e Go-template-based range mappings — úteis para rapidamente colocar no ar múltiplos listeners que mapeiam de volta para implants em hosts diferentes.

## Pinggy (SSH-based)

Pinggy fornece túneis acessíveis por SSH sobre TCP/443, portanto funciona mesmo atrás de captive proxies que só permitem HTTPS. As sessões duram 60 minutos no free tier e podem ser automatizadas para demonstrações rápidas ou webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Você pode solicitar domínios personalizados e túneis de maior duração no plano pago, ou reciclar túneis automaticamente envolvendo o comando em um loop.

## Threat intel & OPSEC notes

Adversários têm abusado cada vez mais de tunneling efêmero (especialmente os endpoints não autenticados `trycloudflare.com` da Cloudflare) para distribuir payloads de Remote Access Trojan e ocultar infraestrutura de C2. A Proofpoint rastreou campanhas desde fevereiro de 2024 que distribuíram AsyncRAT, Xworm, VenomRAT, GuLoader e Remcos apontando estágios de download para URLs TryCloudflare de curta duração, tornando listas de bloqueio estáticas tradicionais muito menos eficazes. Considere rotacionar túneis e domínios proativamente, mas também monitore consultas DNS externas indicativas ao tunneler que você está usando, para detectar cedo tentativas de detecção pela blue-team ou bloqueio da infraestrutura.

## Referências

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
