# Esporre il locale su internet

{{#include ../../banners/hacktricks-training.md}}

**L'obiettivo di questa pagina è proporre alternative che consentano ALMENO di esporre su internet porte TCP raw locali e siti web locali (HTTP) SENZA dover installare nulla sull'altro server (solo in locale, se necessario).**

## **Serveo**

La documentazione di Serveo descrive il forwarding SSH per gli endpoint HTTP e il forwarding TCP privato/pubblico; per richiedere una porta TCP pubblica non standard (incluse le porte 0 per una porta casuale) è necessario un utente registrato.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

La guida introduttiva di SocketXP documenta `socketxp connect tcp://localhost:22` e `socketxp connect http://localhost:8080` per i tunnel TCP e HTTP; prima, l'agent viene autenticato con un token del portale.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

La CLI di ngrok documenta i tunnel HTTP e TCP; le FAQ indicano che gli endpoint TCP del piano gratuito richiedono un metodo di pagamento valido e che la carta non viene addebitata.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

La guida della CLI legacy di Telebit.js documenta `telebit http <port>` per il forwarding HTTPS e `telebit tcp <local> [remote]` per il TCP raw; la disponibilità dipende dal deployment e dal relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

La documentazione attuale del sito di LocalXpose descrive `loclx tunnel http --to 3000`, elenca il supporto per HTTP/TLS/TCP/UDP e indica che il piano gratuito copre l'uso personale e commerciale leggero, mentre il tunneling TCP è una funzionalità dei piani a pagamento.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose documenta `expose share` per gli URL locali HTTP/HTTPS e un comando `expose share-port` riservato ai PRO per le porte TCP.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Il repository ufficiale di localtunnel descrive come esporre localhost per i test e documenta il comando NPX riportato di seguito.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

La documentazione attuale di Cloudflare mostra i tunnel "Quick" non autenticati per lo sviluppo locale, mentre la panoramica del prodotto include HTTP, HTTPS, TCP, SSH e RDP tra i protocolli pubblicati supportati.<sup>[[11]](#references)[[12]](#references)</sup>

Per un tunnel denominato gestito localmente, Cloudflare documenta il workflow `tunnel login`, `create`, `route dns` e `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
I tunnel denominati possono definire più regole di ingress in YAML; le policy di Cloudflare Access possono controllare l'accesso alle applicazioni pubblicate e Cloudflare documenta i percorsi di deployment per service e Docker per l'esecuzione dei connector. I Quick Tunnels sono tunnel di test anonimi e temporanei con un limite di 200 richieste simultanee e senza supporto per Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

La CLI attuale di Tailscale usa Serve per la condivisione limitata al tailnet e Funnel per la condivisione pubblica. I comandi supportano target reverse-proxy HTTP/HTTPS e il forwarding TCP; la modalità TCP raw di Funnel è limitata alle porte 443, 8443 e 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Usa `--bg` per rendere persistente la configurazione senza mantenere un processo in primo piano e usa `tailscale funnel status` per verificare quali servizi sono raggiungibili da Internet pubblico. Per le destinazioni HTTPS Funnel, Tailscale documenta la terminazione TLS sul nodo locale prima dell'inoltro della richiesta al servizio locale.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` è un'opzione self-hosted in cui controlli il rendezvous server (`frps`) e il client (`frpc`); la relativa documentazione descrive l'inoltro di servizi locali dietro NAT o un firewall con porte o domini remoti deterministici.<sup>[[20]](#references)</sup>

<details>
<summary>Configurazione di esempio frps/frpc</summary>
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

La documentazione attuale del progetto include il trasporto QUIC, l'autenticazione tramite token/OIDC, i limiti di banda, i controlli dello stato e i mapping degli intervalli Go-template: consulta la release corrispondente al tuo deployment prima di usare una di queste opzioni.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy documenta il reverse forwarding SSH sulla porta 443, quindi può funzionare nelle reti in cui l'SSH in uscita sulla porta 22 è bloccato. Il suo free plan scade dopo 60 minuti e usa un nuovo URL dopo la riconnessione, mentre Pro aggiunge tunnel persistenti e custom domain.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Puoi richiedere custom domains e persistent tunnels su Pro.<sup>[[22]](#references)</sup> Puoi riciclare automaticamente i temporary tunnels racchiudendo il comando in un loop.

## Threat intel & OPSEC notes

Gli adversary hanno abusato dell'ephemeral tunneling, inclusi gli endpoint `trycloudflare.com` non autenticati di Cloudflare, per distribuire Remote Access Trojans attraverso un'infrastruttura temporanea. Proofpoint ha segnalato attività osservate per la prima volta a febbraio 2024 che coinvolgevano Xworm, AsyncRAT, VenomRAT, GuLoader e Remcos, sottolineando che i temporary tunnels complicano le difese basate su static blocklists.<sup>[[23]](#references)</sup> Valuta di ruotare proattivamente tunnels e domains e monitora eventuali external DNS lookups indicativi verso il tunneler in uso, così da individuare tempestivamente il rilevamento da parte del blue team o i tentativi di bloccare l'infrastruttura.

## References

- [1] [Documentazione di Serveo](https://serveo.net/docs/)
- [2] [Documentazione di SocketXP - Guida introduttiva](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfaccia a riga di comando dell'agent ngrok](https://ngrok.com/docs/agent/cli)
- [4] [FAQ di ngrok](https://ngrok.com/docs/faq)
- [5] [Guida della CLI legacy di Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Documentazione di LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Condivisione di siti](https://expose.dev/docs/client/sharing)
- [9] [Expose - Condivisione di porte TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repository localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Documentazione Cloudflare - Configurazione di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Panoramica di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Documentazione Cloudflare - Comandi utili di tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Documentazione Cloudflare - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Documentazione Cloudflare - File di configurazione](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Policy di Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Documentazione Cloudflare - Parametri di esecuzione](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Comando Serve di Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Comando Funnel di Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Repository fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Documentazione di Pinggy - Utilizzo](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Simple Localhost Tunnels](https://pinggy.io/)
- [23] [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
