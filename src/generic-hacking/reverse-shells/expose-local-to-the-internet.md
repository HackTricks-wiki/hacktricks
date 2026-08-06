# Esporre il locale su Internet

{{#include ../../banners/hacktricks-training.md}}

**L'obiettivo di questa pagina è proporre alternative che consentano ALMENO di esporre su Internet porte TCP raw locali e servizi web locali (HTTP) SENZA dover installare nulla sull'altro server (solo in locale, se necessario).**

## **Serveo**

Da [https://serveo.net/](https://serveo.net/) consente diverse funzionalità HTTP e di port forwarding **gratuitamente**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Da [https://www.socketxp.com/download](https://www.socketxp.com/download), consente di esporre tcp e http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Da [https://ngrok.com/](https://ngrok.com/), consente di esporre porte http e tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Da [https://telebit.cloud/](https://telebit.cloud/) è possibile esporre porte http e tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Da [https://localxpose.io/](https://localxpose.io/), consente diverse funzionalità di port forwarding HTTP **gratuitamente**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Da [https://expose.dev/](https://expose.dev/) è possibile esporre porte http e tcp:
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Da [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel) consente di esporre http gratuitamente:
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

La CLI `cloudflared` di Cloudflare può creare tunnel "Quick" non autenticati per demo rapide oppure tunnel con nome associati al proprio dominio/hostname. Supporta reverse proxy HTTP(S) e mapping TCP raw instradati tramite l'edge di Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
I tunnel con nome consentono di definire più regole di ingress (HTTP, SSH, RDP, ecc.) all'interno di `tunnel.yml`, supportano policy di accesso per servizio tramite Cloudflare Access e possono essere eseguiti come container systemd per garantire la persistenza. I Quick Tunnels sono anonimi ed effimeri: ottimi per lo staging di payload di phishing o per testare webhook, ma Cloudflare non garantisce l'uptime.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ include i workflow unificati `tailscale serve` (condivisione all'interno del tailnet) e `tailscale funnel` (pubblicazione sull'Internet pubblico). Entrambi i comandi possono fare da reverse proxy per HTTP(S) o inoltrare TCP raw con TLS automatico e hostname brevi `*.ts.net`.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Usa `--bg` per rendere persistente la configurazione senza mantenere un processo in primo piano e `tailscale funnel status` per verificare quali servizi sono raggiungibili da Internet pubblico. Poiché Funnel termina TLS sul nodo locale, qualsiasi richiesta di credenziali, header o applicazione di mTLS può rimanere sotto il tuo controllo.

## Fast Reverse Proxy (frp)

`frp` è un'opzione self-hosted in cui controlli il server di rendezvous (`frps`) e il client (`frpc`). È ottimo per i red team che possiedono già un VPS e desiderano domini/porte deterministici.

<details>
<summary>Configurazione di esempio frps/frpc</summary>
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

Le release recenti aggiungono il transport QUIC, l'autenticazione tramite token/OIDC, i limiti di banda, gli health check e i range mappings basati su Go template—utili per configurare rapidamente più listener che effettuano il mapping verso implant su host diversi.<sup>[[4]](#references)</sup>

## Pinggy (basato su SSH)

Pinggy fornisce tunnel accessibili tramite SSH su TCP/443, quindi funziona anche dietro captive proxy che consentono solo HTTPS. Le sessioni durano 60 minuti nel free tier e possono essere sottoposte a scripting per demo rapide o relay di webhook.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Puoi richiedere custom domains e tunnel con durata maggiore nel paid tier, oppure riciclare automaticamente i tunnel racchiudendo il comando in un loop.

## Note su threat intel e OPSEC

Gli avversari hanno abusato sempre più del tunneling effimero (in particolare degli endpoint `trycloudflare.com` non autenticati di Cloudflare) per distribuire payload di Remote Access Trojan e nascondere l'infrastruttura C2. Proofpoint ha monitorato campagne, a partire da febbraio 2024, che distribuivano AsyncRAT, Xworm, VenomRAT, GuLoader e Remcos indirizzando gli stage di download verso URL TryCloudflare di breve durata, rendendo le tradizionali static blocklist molto meno efficaci. Valuta di ruotare proattivamente tunnel e domini, ma monitora anche le richieste DNS esterne indicative verso il tunneler che stai utilizzando, così da individuare tempestivamente il rilevamento da parte del blue team o i tentativi di bloccare l'infrastruttura.<sup>[[2]](#references)</sup>

## Riferimenti

- [1] [Cloudflare Docs - Crea un tunnel gestito localmente](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Un threat actor abusa dei Cloudflare Tunnels per distribuire RAT](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Reintroduzione di Serve e Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Repository di Fast Reverse Proxy](https://github.com/fatedier/frp)
- [5] [Pinggy Documentation - Utilizzo](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
