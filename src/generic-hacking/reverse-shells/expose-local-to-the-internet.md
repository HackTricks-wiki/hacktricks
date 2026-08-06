# Exposer le local à Internet

{{#include ../../banners/hacktricks-training.md}}

**L’objectif de cette page est de proposer des alternatives permettant AU MOINS d’exposer des ports TCP bruts locaux et des sites web locaux (HTTP) à Internet SANS avoir besoin d’installer quoi que ce soit sur l’autre serveur (uniquement en local si nécessaire).**

## **Serveo**

Depuis [https://serveo.net/](https://serveo.net/), plusieurs fonctionnalités de forwarding HTTP et de ports sont disponibles **gratuitement**.
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

Depuis [https://ngrok.com/](https://ngrok.com/), il permet d’exposer des ports http et tcp :
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

Depuis [https://localxpose.io/](https://localxpose.io/), il permet plusieurs fonctionnalités de transfert HTTP et de ports **gratuitement**.
```bash
# Expose web in port 8989
loclx tunnel http -t 8989

# Expose tcp port in 4545 (requires pro)
loclx tunnel tcp --port 4545
```
## Expose

Depuis [https://expose.dev/](https://expose.dev/), il permet d’exposer des ports http et tcp :
```bash
# Expose web in 3000
./expose share http://localhost:3000

# Expose tcp port in port 4444 (REQUIRES PREMIUM)
./expose share-port 4444
```
## Localtunnel

Depuis [https://github.com/localtunnel/localtunnel](https://github.com/localtunnel/localtunnel), il est possible d'exposer un serveur http gratuitement :
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

La CLI `cloudflared` de Cloudflare peut créer des tunnels « Quick » non authentifiés pour des démonstrations rapides, ou des tunnels nommés associés à votre propre domaine/nom d’hôte. Elle prend en charge les proxys inverses HTTP(S), ainsi que les redirections TCP brutes acheminées via l’edge de Cloudflare.<sup>[[1]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # one-time device auth
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel run my-tunnel --config tunnel.yml
```
Les tunnels nommés permettent de définir plusieurs règles d’ingress (HTTP, SSH, RDP, etc.) dans `tunnel.yml`, prennent en charge des politiques d’accès par service via Cloudflare Access et peuvent s’exécuter comme des conteneurs systemd pour assurer la persistance. Les Quick Tunnels sont anonymes et éphémères — idéaux pour la préparation de payloads de phishing ou les tests de webhooks, mais Cloudflare ne garantit pas leur disponibilité.<sup>[[1]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale v1.52+ fournit les workflows unifiés `tailscale serve` (partage au sein du tailnet) et `tailscale funnel` (publication sur l’internet public). Les deux commandes peuvent faire office de proxy inverse pour HTTP(S) ou transférer du TCP brut, avec TLS automatique et des noms d’hôte `*.ts.net` courts.<sup>[[3]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Utilisez `--bg` pour conserver la configuration sans maintenir un processus au premier plan, et `tailscale funnel status` pour vérifier quels services sont accessibles depuis l’Internet public. Comme Funnel termine TLS sur le nœud local, les invites d’identifiants, les en-têtes ou l’application de mTLS peuvent rester sous votre contrôle.

## Fast Reverse Proxy (frp)

`frp` est une option self-hosted où vous contrôlez le serveur de rendez-vous (`frps`) et le client (`frpc`). Il est idéal pour les red teams qui possèdent déjà un VPS et souhaitent disposer de domaines/ports déterministes.

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

Les versions récentes ajoutent le transport QUIC, l’authentification par token/OIDC, des limites de bande passante, des health checks et des mappages de plages basés sur des templates Go, ce qui permet de mettre rapidement en place plusieurs listeners redirigeant vers des implants sur différents hôtes.<sup>[[4]](#references)</sup>

## Pinggy (SSH-based)

Pinggy fournit des tunnels accessibles via SSH sur TCP/443, ce qui lui permet de fonctionner même derrière des proxies captifs qui n’autorisent que HTTPS. Les sessions durent 60 minutes avec l’offre gratuite et peuvent être automatisées pour des démonstrations rapides ou des relais de webhook.<sup>[[5]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 a.pinggy.io
```
Vous pouvez demander des domaines personnalisés et des tunnels ayant une durée de vie plus longue avec l’offre payante, ou recycler automatiquement les tunnels en plaçant la commande dans une boucle.

## Notes de threat intel et d’OPSEC

Les adversaires exploitent de plus en plus les tunnels éphémères (en particulier les endpoints `trycloudflare.com` non authentifiés de Cloudflare) pour déployer des payloads de Remote Access Trojan et dissimuler l’infrastructure C2. Proofpoint a suivi depuis février 2024 des campagnes qui diffusaient AsyncRAT, Xworm, VenomRAT, GuLoader et Remcos en faisant pointer les étapes de téléchargement vers des URLs TryCloudflare à courte durée de vie, rendant les blocklists statiques traditionnelles bien moins efficaces. Envisagez de faire tourner proactivement les tunnels et les domaines, mais surveillez également les requêtes DNS externes révélatrices vers le tunneler que vous utilisez afin de détecter rapidement une détection par la blue-team ou des tentatives de blocage de l’infrastructure.<sup>[[2]](#references)</sup>

## Références

- [1] [Documentation Cloudflare - Créer un tunnel géré localement](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/create-local-tunnel/)
- [2] [Proofpoint - Un threat actor abuse des tunnels Cloudflare pour diffuser des RAT](https://www.proofpoint.com/us/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [3] [Tailscale - Réintroduction de Serve et Funnel](https://tailscale.com/blog/reintroducing-serve-funnel)
- [4] [fatedier/frp - Repository Fast Reverse Proxy](https://github.com/fatedier/frp)
- [5] [Documentation Pinggy - Utilisation](https://pinggy.io/docs/usages/)

{{#include ../../banners/hacktricks-training.md}}
