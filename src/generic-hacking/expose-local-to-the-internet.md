# Esporre il locale a Internet

{{#include ../banners/hacktricks-training.md}}

**L'obiettivo di questa pagina è proporre alternative che permettano ALMENO di esporre su Internet porte TCP raw locali e siti web locali (HTTP), SENZA dover installare nulla sull'altro server (solo in locale, se necessario).**

Per l'inoltro tra host, anziché pubblicare un servizio tramite un relay pubblico, vedere [Tunneling e Port Forwarding](tunneling-and-port-forwarding.md).

## **Serveo**

La documentazione di Serveo descrive il forwarding SSH per endpoint HTTP e il forwarding TCP privato/pubblico. La porta `0` richiede una porta TCP pubblica casuale anche per le sessioni anonime, ma queste sessioni hanno limiti di durata e connessioni ridotti; per richiedere una porta TCP pubblica specifica serve un account a pagamento.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

La guida introduttiva di SocketXP documenta `socketxp connect tcp://localhost:22` e `socketxp connect http://localhost:8080` per i tunnel TCP e HTTP; prima, l’agent viene autenticato con un token del portale.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

La CLI di ngrok documenta i tunnel HTTP e TCP. Gli endpoint TCP richiedono un indirizzo TCP riservato nell’account; il piano gratuito richiede anche un metodo di pagamento valido, che, secondo le FAQ, non comporta addebiti.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

La guida della CLI legacy di Telebit.js documenta `telebit http <port>` per l'inoltro HTTPS e `telebit tcp <local> [remote]` per TCP grezzo; la disponibilità dipende dalla distribuzione e dal relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Il sito attuale di LocalXpose documenta `loclx tunnel http --to 3000`, indica il supporto per HTTP/TLS/TCP/UDP e afferma che il piano gratuito copre l'uso personale e commerciale leggero, mentre il tunneling TCP è disponibile nei piani a pagamento.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

I documenti `expose share` per URL locali HTTP/HTTPS e il comando `expose share-port`, disponibile solo nella versione PRO, per le porte TCP.<sup>[[8]](#references)[[9]](#references)</sup>

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

La documentazione attuale di Cloudflare descrive i tunnel "Quick" non autenticati per lo sviluppo locale, mentre la panoramica del prodotto elenca HTTP, HTTPS, TCP, SSH e RDP tra i protocolli pubblicati supportati.<sup>[[11]](#references)[[12]](#references)</sup> A differenza di HTTP(S), le route TCP, SSH e RDP pubblicate non sono accessibili direttamente con un client standard: Cloudflare richiede `cloudflared` sul client che si connette, quindi queste route non soddisfano il requisito di questa pagina di non installare un client per TCP raw.<sup>[[24]](#references)</sup>

Per un tunnel con nome gestito localmente, Cloudflare documenta il flusso di lavoro `tunnel login`, `create`, `route dns` e `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

I tunnel con nome possono definire più regole di ingress in YAML; le policy di Cloudflare Access possono controllare l'accesso alle applicazioni pubblicate e Cloudflare documenta le modalità di deployment con servizi e Docker per eseguire i connector. Quick Tunnels sono tunnel anonimi e temporanei per i test, con un limite di 200 richieste simultanee e senza supporto per Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

La CLI attuale di Tailscale usa Serve per la condivisione riservata al tailnet e Funnel per la condivisione pubblica. I comandi supportano destinazioni reverse-proxy HTTP/HTTPS e l'inoltro TCP; la modalità TCP raw di Funnel è limitata alle porte 443, 8443 e 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Usa `--bg` per rendere persistente la configurazione senza mantenere un processo in primo piano e usa `tailscale funnel status` per verificare quali servizi sono raggiungibili da Internet pubblico. Per le destinazioni HTTPS Funnel, Tailscale documenta la terminazione TLS sul nodo locale prima di inoltrare la richiesta al servizio locale.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` è un'opzione self-hosted in cui controlli il server rendezvous (`frps`) e il client (`frpc`); la documentazione spiega come inoltrare servizi locali dietro NAT o un firewall usando porte o domini remoti deterministici.<sup>[[20]](#references)</sup>

<details>
<summary>Configurazione di esempio di frps/frpc</summary>

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

La documentazione attuale del progetto include trasporto QUIC, autenticazione tramite token/OIDC, limiti di banda, controlli dello stato di salute e mappature range nei template Go: consulta la release corrispondente alla tua distribuzione prima di usare una di queste opzioni.<sup>[[20]](#references)</sup>

## Pinggy (basato su SSH)

Pinggy documenta il port forwarding inverso SSH sulla porta 443, quindi può funzionare nelle reti in cui le connessioni SSH in uscita sulla porta 22 sono bloccate. Il piano gratuito termina dopo 60 minuti e, alla riconnessione, assegna un nuovo URL, mentre il piano Pro aggiunge tunnel persistenti e domini personalizzati.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Puoi richiedere domini personalizzati e tunnel persistenti con Pro.<sup>[[22]](#references)</sup> Puoi ricreare automaticamente i tunnel temporanei inserendo il comando in un loop.

## Threat intel & OPSEC notes

Gli attori malevoli hanno abusato dei tunnel effimeri, inclusi gli endpoint `trycloudflare.com` di Cloudflare che non richiedono autenticazione, per distribuire Remote Access Trojans tramite infrastrutture temporanee. Proofpoint ha segnalato attività osservate per la prima volta nel febbraio 2024 che coinvolgevano Xworm, AsyncRAT, VenomRAT, GuLoader e Remcos, osservando che i tunnel temporanei complicano le difese basate su blocklist statiche.<sup>[[23]](#references)</sup> Valuta di ruotare proattivamente tunnel e domini e monitora eventuali lookup DNS esterni indicativi verso il tunneler che stai usando, così da individuare tempestivamente il rilevamento da parte del blue team o tentativi di bloccare l'infrastruttura.

## References

- [1] [Documentazione di Serveo](https://serveo.net/docs/)
- [2] [Documentazione di SocketXP - Per iniziare](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interfaccia a riga di comando dell'agente ngrok](https://ngrok.com/docs/agent/cli)
- [4] [FAQ di ngrok](https://ngrok.com/docs/faq)
- [5] [Guida della CLI legacy di Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Documentazione di LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Condivisione di siti](https://expose.dev/docs/client/sharing)
- [9] [Expose - Condivisione di porte TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Repository localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Documentazione di Cloudflare - Configurare Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Panoramica di Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Documentazione di Cloudflare - Comandi utili per i tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Documentazione di Cloudflare - Routing](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Documentazione di Cloudflare - File di configurazione](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Policy di Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Documentazione di Cloudflare - Parametri di esecuzione](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Comando Serve di Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Comando Funnel di Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Repository fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Documentazione di Pinggy - Utilizzo](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Tunnel semplici per localhost](https://pinggy.io/)
- [23] [Proofpoint - Un threat actor abusa di Cloudflare Tunnels per distribuire RAT](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Documentazione di Cloudflare - Routing dei tunnel e protocolli supportati](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
