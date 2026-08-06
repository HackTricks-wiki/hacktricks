# Expor o ambiente local à internet

{{#include ../../banners/hacktricks-training.md}}

**O objetivo desta página é propor alternativas que permitam, NO MÍNIMO, expor portas TCP brutas locais e sites locais (HTTP) à internet SEM precisar instalar nada no outro servidor (apenas no ambiente local, se necessário).**

## **Serveo**

Em [https://serveo.net/](https://serveo.net/), é possível usar vários recursos de HTTP e port forwarding **gratuitamente**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

A partir de [https://www.socketxp.com/download](https://www.socketxp.com/download), é possível expor tcp e http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

A partir de [https://ngrok.com/](https://ngrok.com/), é possível expor portas http e tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

A partir de [https://telebit.cloud/](https://telebit.cloud/), é possível expor portas http e tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

A partir de [https://localxpose.io/](https://localxpose.io/), ele permite vários recursos de encaminhamento de HTTP e de portas **gratuitamente**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Em [https://expose.dev/](https://expose.dev/), é possível expor portas http e tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

A partir de [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel), é possível expor http gratuitamente:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

A CLI `cloudflared` da Cloudflare pode criar túneis "Quick" não autenticados para demonstrações rápidas ou túneis nomeados vinculados ao seu próprio domínio/hostnames. Ela oferece suporte a proxies reversos HTTP(S), bem como a mapeamentos TCP brutos roteados pela edge da Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Named tunnels permitem definir múltiplas regras de ingress (HTTP, SSH, RDP etc.) dentro de `tunnel.yml`, oferecem políticas de acesso por serviço via Cloudflare Access e podem ser executados como containers systemd para persistência. Quick Tunnels são anônimos e efêmeros — ótimos para staging de payloads de phishing ou testes de webhooks, mas a Cloudflare não garante uptime.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

O Tailscale v1.52+ inclui os fluxos de trabalho unificados `tailscale serve` (compartilhar dentro da tailnet) e `tailscale funnel` (publicar na internet pública). Ambos os comandos podem fazer reverse proxy de HTTP(S) ou encaminhar TCP bruto com TLS automático e hostnames `*.ts.net` curtos.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Use `--bg` para persistir a configuração sem manter um processo em primeiro plano, e `tailscale funnel status` para auditar quais serviços estão acessíveis pela Internet pública. Como o Funnel encerra o TLS no node local, quaisquer prompts de credenciais, headers ou aplicação de mTLS podem permanecer sob seu controle.

## Fast Reverse Proxy (frp)

`frp` é uma opção self-hosted na qual você controla o servidor de rendezvous (`frps`) e o cliente (`frpc`). É excelente para red teams que já possuem um VPS e querem domínios/portas determinísticos.

<details>
<summary>Exemplo de configuração do frps/frpc</summary>
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

Versões recentes adicionam transporte QUIC, autenticação por token/OIDC, limites de largura de banda, health checks e mapeamentos de range baseados em Go templates — úteis para configurar rapidamente múltiplos listeners que fazem o mapeamento de volta para implants em hosts diferentes.<sup>[[4]](#references)</sup>

## Pinggy (baseado em SSH)

O Pinggy fornece túneis acessíveis por SSH sobre TCP/443, portanto funciona até mesmo atrás de proxies cativos que permitem apenas HTTPS. As sessões duram 60 minutos no free tier e podem ser automatizadas para demonstrações rápidas ou relays de webhook.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Você pode solicitar domínios personalizados e túneis com maior duração no plano pago ou reciclar túneis automaticamente envolvendo o comando em um loop.

## Notas de threat intel e OPSEC

Adversários têm abusado cada vez mais de túneis efêmeros (especialmente dos endpoints `trycloudflare.com` não autenticados da Cloudflare) para distribuir payloads de Remote Access Trojan e ocultar a infraestrutura de C2. A Proofpoint rastreou campanhas desde fevereiro de 2024 que distribuíam AsyncRAT, Xworm, VenomRAT, GuLoader e Remcos, apontando os estágios de download para URLs TryCloudflare de curta duração, tornando as blocklists estáticas tradicionais muito menos eficazes. Considere alternar túneis e domínios proativamente, mas também monitore consultas DNS externas reveladoras ao tunneler que você está usando, para identificar precocemente detecções pelo blue team ou tentativas de bloqueio da infraestrutura.<sup>[[2]](#references)</sup>

## Referências

- [1] [Documentação da Cloudflare - Criar um túnel gerenciado localmente](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroducing Serve and Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Repositório do Fast Reverse Proxy](https://github.com/fatedier/frp)
- [5] [Documentação do Pinggy - Uso](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
