# Exposer un service local sur Internet

{{#include ../../banners/hacktricks-training.md}}

**L'objectif de cette page est de proposer des alternatives permettant AU MINIMUM d'exposer des ports TCP bruts locaux et des services web locaux (HTTP) sur Internet SANS avoir besoin d'installer quoi que ce soit sur l'autre serveur (seulement localement si nécessaire).**

## **Serveo**

Depuis [https://serveo.net/](https://serveo.net/), il propose plusieurs fonctionnalités http et de port forwarding **gratuites**.
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:300 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Depuis [https://www.socketxp.com/download](https://www.socketxp.com/download), il permet d'exposer tcp et http :
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

Depuis [https://ngrok.com/](https://ngrok.com/), il permet d'exposer des ports http et tcp :
```bash
# Expose web in 3000
ngrok http 8000

# Expose port in 9000 (it requires a credit card, but you won't be charged)
ngrok tcp 9000
```
## Telebit

Depuis [https://telebit.cloud/](https://telebit.cloud/), il permet d'exposer des ports http et tcp :
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Depuis [https://localxpose.io/](https://localxpose.io/), il propose plusieurs fonctionnalités http et de port forwarding **gratuites**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Depuis [https://expose.dev/](https://expose.dev/) il permet d'exposer des ports http et tcp :
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

D'après [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel), il permet d'exposer http gratuitement :
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

Le CLI `cloudflared` de Cloudflare peut créer des tunnels "Quick" non authentifiés pour des démonstrations rapides ou des tunnels nommés liés à votre propre domaine/hostnames. Il prend en charge les reverse proxies HTTP(S) ainsi que les raw TCP mappings acheminés via l'edge de Cloudflare.
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Les Named tunnels vous permettent de définir plusieurs règles d'ingress (HTTP, SSH, RDP, etc.) dans `tunnel.yml`, de prendre en charge des politiques d'accès par service via Cloudflare Access, et peuvent s'exécuter en tant que conteneurs systemd pour la persistance. Les Quick Tunnels sont anonymes et éphémères — parfaits pour la mise en scène de payloads de phishing ou les tests de webhook, mais Cloudflare ne garantit pas la disponibilité.

## Tailscale Funnel / Serve

Tailscale v1.52+ propose les workflows unifiés `tailscale serve` (partager à l'intérieur du tailnet) et `tailscale funnel` (publier sur Internet). Les deux commandes peuvent agir comme reverse proxy pour HTTP(S) ou transférer du TCP brut avec TLS automatique et de courts noms d'hôte `*.ts.net`.
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Utilisez `--bg` pour persister la configuration sans garder un processus au premier plan, et `tailscale funnel status` pour auditer quels services sont accessibles depuis l'internet public. Parce que Funnel termine TLS sur le nœud local, toutes les invites d'identifiants, en-têtes ou l'application de mTLS peuvent rester sous votre contrôle.

## Proxy inverse rapide (frp)

`frp` est une option auto-hébergée où vous contrôlez le serveur de rendez-vous (`frps`) et le client (`frpc`). C'est idéal pour les red teams qui possèdent déjà un VPS et veulent des domaines/ports déterministes.

<details>
<summary>Exemple de configuration frps/frpc</summary>
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

Les récentes versions ajoutent QUIC transport, token/OIDC auth, bandwidth caps, health checks, et Go-template-based range mappings — utiles pour déployer rapidement plusieurs listeners qui se mappent à des implants sur différents hôtes.

## Pinggy (basé sur SSH)

Pinggy fournit des tunnels accessibles via SSH sur TCP/443, donc il fonctionne même derrière des captive proxies qui n'autorisent que HTTPS. Les sessions durent 60 minutes sur le plan gratuit et peuvent être scriptées pour des démos rapides ou des relais de webhook.
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Vous pouvez demander des domaines personnalisés et des tunnels plus durables avec l'offre payante, ou recycler automatiquement des tunnels en exécutant la commande dans une boucle.

## Renseignement sur les menaces & notes OPSEC

Les adversaires ont de plus en plus abusé des tunnels éphémères (en particulier les endpoints non authentifiés de Cloudflare `trycloudflare.com`) pour déployer des payloads Remote Access Trojan et dissimuler des infrastructures C2. Proofpoint a suivi des campagnes depuis février 2024 qui ont diffusé AsyncRAT, Xworm, VenomRAT, GuLoader et Remcos en pointant des étapes de téléchargement vers des TryCloudflare URLs de courte durée de vie, rendant les listes de blocage statiques traditionnelles beaucoup moins efficaces. Envisagez de faire tourner de manière proactive tunnels et domaines, mais surveillez aussi les requêtes DNS externes révélatrices vers le service de tunnel que vous utilisez afin de détecter tôt toute tentative de détection par la blue-team ou de blocage d'infrastructure.

## Références

- [Cloudflare Docs - Create a locally-managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [Proofpoint - Threat Actor Abuses Cloudflare Tunnels to Deliver RATs](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)

{{#include ../../banners/hacktricks-training.md}}
