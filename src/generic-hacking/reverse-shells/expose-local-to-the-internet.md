# Expor o ambiente local à internet

{{#include ../../banners/hacktricks-training.md}}

**O objetivo desta página é propor alternativas que permitam, NO MÍNIMO, expor portas TCP locais brutas e aplicações web locais (HTTP) à internet SEM precisar instalar nada no outro servidor (apenas no ambiente local, se necessário).**

## **Serveo**

A documentação do Serveo descreve o encaminhamento SSH para endpoints HTTP e o encaminhamento TCP privado/público; solicitar uma porta TCP pública diferente de 80/443 (incluindo a porta 0 para uma porta aleatória) exige um usuário registrado.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

O guia de introdução do SocketXP documenta `socketxp connect tcp://localhost:22` e `socketxp connect http://localhost:8080` para túneis TCP e HTTP; o agente é autenticado primeiro com um token do portal.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

A CLI do ngrok documenta túneis HTTP e TCP; sua FAQ informa que os endpoints TCP do plano gratuito exigem um método de pagamento válido e que o cartão não é cobrado.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

A documentação de ajuda legada da CLI do Telebit.js apresenta `telebit http <port>` para encaminhamento HTTPS e `telebit tcp <local> [remote]` para TCP bruto; a disponibilidade depende da implantação e do relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

O site atual do LocalXpose documenta `loclx tunnel http --to 3000`, lista suporte a HTTP/TLS/TCP/UDP e informa que o plano gratuito abrange uso pessoal/comercial leve, enquanto o tunneling TCP é um recurso dos planos pagos.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

O Expose disponibiliza URLs locais HTTP/HTTPS com `expose share` e oferece o comando `expose share-port`, exclusivo da versão PRO, para portas TCP.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

O repositório oficial do localtunnel descreve como expor o localhost para testes e documenta o comando NPX abaixo.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

A documentação atual da Cloudflare mostra túneis "Quick" não autenticados para desenvolvimento local, e a visão geral do produto lista HTTP, HTTPS, TCP, SSH e RDP entre os protocolos publicados compatíveis.<sup>[[11]](#references)[[12]](#references)</sup>

Para um túnel nomeado gerenciado localmente, a Cloudflare documenta o fluxo de trabalho `tunnel login`, `create`, `route dns` e `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Túneis nomeados podem definir várias regras de ingress em YAML; as políticas do Cloudflare Access podem controlar o acesso a aplicações publicadas, e o Cloudflare documenta caminhos de deployment de serviços e Docker para executar connectors. Quick Tunnels são túneis anônimos e temporários para testes, com limite de 200 requisições simultâneas e sem suporte a Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

A CLI atual do Tailscale usa Serve para compartilhamento exclusivo na tailnet e Funnel para compartilhamento público. Os comandos oferecem suporte a targets de reverse-proxy HTTP/HTTPS e encaminhamento TCP; o modo TCP bruto do Funnel é limitado às portas 443, 8443 e 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Use `--bg` para persistir a configuração sem manter um processo em primeiro plano e use `tailscale funnel status` para auditar quais serviços estão acessíveis pela internet pública. Para destinos HTTPS Funnel, a documentação do Tailscale descreve a terminação TLS no nó local antes do encaminhamento da requisição para o serviço local.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` é uma opção self-hosted na qual você controla o servidor de rendezvous (`frps`) e o cliente (`frpc`); sua documentação aborda o encaminhamento de serviços locais atrás de NAT ou de um firewall, com portas/domínios remotos determinísticos.<sup>[[20]](#references)</sup>

<details>
<summary>Exemplo de configuração do frps/frpc</summary>
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

A documentação atual do projeto inclui transporte QUIC, autenticação por token/OIDC, limites de largura de banda, verificações de integridade e mapeamentos de intervalo do Go-template—consulte a release correspondente à sua implantação antes de usar qualquer uma dessas opções.<sup>[[20]](#references)</sup>

## Pinggy (baseado em SSH)

O Pinggy documenta o encaminhamento reverso de SSH pela porta 443, portanto pode funcionar em redes onde o SSH de saída pela porta 22 está bloqueado. O plano gratuito expira após 60 minutos e usa uma nova URL após a reconexão, enquanto o Pro adiciona túneis persistentes e domínios personalizados.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Você pode solicitar domínios personalizados e túneis persistentes no Pro.<sup>[[22]](#references)</sup> Você pode reciclar túneis temporários automaticamente envolvendo o comando em um loop.

## Inteligência sobre ameaças e notas de OPSEC

Adversários abusaram de tunneling efêmero, incluindo os endpoints `trycloudflare.com` não autenticados da Cloudflare, para distribuir Remote Access Trojans por meio de infraestrutura temporária. A Proofpoint relatou atividades observadas pela primeira vez em fevereiro de 2024 envolvendo Xworm, AsyncRAT, VenomRAT, GuLoader e Remcos, e observou que túneis temporários complicam as defesas que dependem de blocklists estáticas.<sup>[[23]](#references)</sup> Considere rotacionar túneis e domínios proativamente e monitore consultas DNS externas indicativas ao tunneler que você está usando, para identificar antecipadamente detecções pelo blue team ou tentativas de bloqueio da infraestrutura.

## References

- [1] [Documentação do Serveo](https://serveo.net/docs/)
- [2] [Documentação do SocketXP - Primeiros passos](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interface de linha de comando do ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [FAQ do ngrok](https://ngrok.com/docs/faq)
- [5] [Ajuda legada da CLI do Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Documentação do LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Compartilhamento de sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - Compartilhamento de portas TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [repositório localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Documentação da Cloudflare - Configurar o Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Visão geral do Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Documentação da Cloudflare - Comandos úteis do tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Documentação da Cloudflare - Roteamento](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Documentação da Cloudflare - Arquivo de configuração](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Políticas do Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Documentação da Cloudflare - Parâmetros de execução](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Comando Serve do Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Comando Funnel do Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [repositório fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Documentação do Pinggy - Uso](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Túneis simples para localhost](https://pinggy.io/)
- [23] [Proofpoint - Ameaça usa Cloudflare Tunnels para distribuir RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
