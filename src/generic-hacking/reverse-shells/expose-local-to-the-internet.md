# Esporre il locale su Internet

{{#include ../../banners/hacktricks-training.md}}

**Lo scopo di questa pagina è proporre alternative che permettano ALMENO di esporre porte TCP raw locali e siti web locali (HTTP) su Internet SENZA dover installare nulla sull'altro server (solo in locale se necessario).**

## **Serveo**

Da [https://serveo.net/](https://serveo.net/), offre diverse funzionalità di HTTP e port forwarding **gratis**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Da [https://www.socketxp.com/download](https://www.socketxp.com/download), permette di esporre tcp e http:
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Da [https://ngrok.com/](https://ngrok.com/), permette di esporre porte http e tcp:
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Da [https://telebit.cloud/](https://telebit.cloud/) permette di esporre porte http e tcp:
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Dal sito [https://localxpose.io/](https://localxpose.io/), consente diverse funzionalità di http e port forwarding **gratis**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Da [https://expose.dev/](https://expose.dev/) consente di esporre porte http e tcp:
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

Il CLI `cloudflared` di Cloudflare può creare tunnel "Quick" non autenticati per demo rapide o tunnel nominativi legati al tuo dominio/hostnames. Supporta HTTP(S) reverse proxies così come raw TCP mappings instradati attraverso l'edge di Cloudflare.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
I Named tunnels consentono di definire più ingress rules (HTTP, SSH, RDP, ecc.) all'interno di `tunnel.yml`, supportano politiche di accesso per servizio tramite Cloudflare Access e possono essere eseguiti come container systemd per la persistenza. I Quick Tunnels sono anonimi ed effimeri — ottimi per lo staging di payload di phishing o per test di webhook, ma Cloudflare non garantisce l'uptime.

## Tailscale Funnel / Serve

Tailscale v1.52+ fornisce i workflow unificati `tailscale serve` (condividi all'interno del tailnet) e `tailscale funnel` (pubblica sul più ampio internet). Entrambi i comandi possono fare reverse proxy per HTTP(S) o inoltrare raw TCP con TLS automatico e host brevi `*.ts.net`.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Usa `--bg` per rendere persistente la configurazione senza mantenere un processo in foreground, e `tailscale funnel status` per verificare quali servizi sono raggiungibili da Internet pubblico. Poiché Funnel termina TLS sul nodo locale, eventuali prompt di credenziali, header o l'enforcement di mTLS possono rimanere sotto il tuo controllo.

## Fast Reverse Proxy (frp)

`frp` è un'opzione self-hosted dove controlli il rendezvous server (`frps`) e il client (`frpc`). È ottimo per red teams che possiedono già un VPS e vogliono domini/porte deterministici.

<details>
<summary>Esempio di configurazione frps/frpc</summary>
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

Le release recenti aggiungono QUIC transport, token/OIDC auth, limiti di banda, controlli di stato, e mappature di intervallo basate su Go-template—utili per avviare rapidamente più listener che rimandano agli implants su host diversi.

## Pinggy (SSH-based)

Pinggy fornisce tunnel accessibili via SSH su TCP/443, quindi funziona anche dietro captive proxies che consentono solo HTTPS. Le sessioni durano 60 minuti nel piano gratuito e possono essere scriptate per demo rapide o webhook relays.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Puoi richiedere domini personalizzati e tunnel con durata maggiore nel piano a pagamento, oppure riciclare automaticamente i tunnel racchiudendo il comando in un loop.

## Note su threat intel e OPSEC

Gli avversari hanno sempre più abusato del tunneling effimero (in particolare degli endpoint non autenticati di Cloudflare `trycloudflare.com`) per preparare payload di Remote Access Trojan e nascondere infrastrutture C2. Proofpoint ha monitorato campagne a partire da febbraio 2024 che hanno veicolato AsyncRAT, Xworm, VenomRAT, GuLoader e Remcos indirizzando le fasi di download verso URL TryCloudflare di breve durata, rendendo le tradizionali blocklist statiche molto meno efficaci. Valuta di ruotare proattivamente tunnel e domini, ma monitora anche le tipiche query DNS esterne verso il tunneler che stai usando in modo da poter individuare precocemente tentativi di rilevamento del blue team o di blocco dell'infrastruttura.

## Riferimenti

- [Cloudflare Docs - Crea un tunnel gestito localmente](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Un attore malintenzionato abusa dei Cloudflare Tunnels per distribuire RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
