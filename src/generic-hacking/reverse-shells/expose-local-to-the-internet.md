# Exposer le local sur Internet

{{#include ../../banners/hacktricks-training.md}}

**L'objectif de cette page est de proposer des alternatives permettant d'exposer AU MINIMUM des ports TCP bruts locaux et des sites web locaux (HTTP) sur Internet SANS avoir besoin d'installer quoi que ce soit sur l'autre serveur (uniquement en local si nécessaire).**

## **Serveo**

La documentation de Serveo décrit le SSH forwarding pour les endpoints HTTP et le forwarding TCP privé/public ; demander un port TCP public autre que 80/443 (y compris le port 0 pour un port aléatoire) nécessite un utilisateur inscrit.<sup>[[1]](#references)</sup>
```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```
## SocketXP

Le guide de démarrage de SocketXP documente `socketxp connect tcp://localhost:22` et `socketxp connect http://localhost:8080` pour les tunnels TCP et HTTP ; l'agent est d'abord authentifié avec un token du portail.<sup>[[2]](#references)</sup>
```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```
## Ngrok

La CLI de ngrok documente les tunnels HTTP et TCP ; sa FAQ indique que les endpoints TCP de l'offre gratuite nécessitent un moyen de paiement valide et que la carte n'est pas débitée.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```
## Telebit

L'aide de l'ancien CLI Telebit.js documente `telebit http <port>` pour la redirection HTTPS et `telebit tcp <local> [remote]` pour le TCP brut ; la disponibilité dépend du déploiement et du relay.<sup>[[5]](#references)</sup>
```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```
## LocalXpose

Le site actuel de LocalXpose documente `loclx tunnel http --to 3000`, répertorie la prise en charge de HTTP/TLS/TCP/UDP et indique que le forfait gratuit couvre l'utilisation personnelle et commerciale légère, tandis que le tunneling TCP est une fonctionnalité réservée aux forfaits payants.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```
## Expose

Expose documente `expose share` pour les URL locales HTTP/HTTPS ainsi qu’une commande `expose share-port`, réservée aux utilisateurs PRO, pour les ports TCP.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```
## Localtunnel

Le repository officiel de localtunnel décrit l’exposition de localhost pour les tests et documente la commande NPX ci-dessous.<sup>[[10]](#references)</sup>
```bash
# Expose web in port 8000
npx localtunnel --port 8000
```
## Cloudflare Tunnel (cloudflared)

La documentation actuelle de Cloudflare présente les tunnels « Quick » non authentifiés pour le développement local, et la présentation du produit liste HTTP, HTTPS, TCP, SSH et RDP parmi les protocoles publiés pris en charge.<sup>[[11]](#references)[[12]](#references)</sup>

Pour un tunnel nommé géré localement, Cloudflare documente le workflow `tunnel login`, `create`, `route dns` et `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```
Les tunnels nommés peuvent définir plusieurs règles d’ingress dans un fichier YAML ; les politiques Cloudflare Access peuvent contrôler l’accès aux applications publiées, et Cloudflare documente les méthodes de déploiement des services et de Docker pour exécuter les connecteurs. Les Quick Tunnels sont des tunnels de test anonymes et temporaires, limités à 200 requêtes simultanées et ne prenant pas en charge les Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

La CLI actuelle de Tailscale utilise Serve pour le partage réservé au tailnet et Funnel pour le partage public. Les commandes prennent en charge les cibles de reverse-proxy HTTP/HTTPS et la redirection TCP ; le mode TCP brut de Funnel est limité aux ports 443, 8443 et 10000.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```
Utilisez `--bg` pour conserver la configuration sans maintenir un processus au premier plan, et utilisez `tailscale funnel status` pour vérifier quels services sont accessibles depuis l’Internet public. Pour les cibles HTTPS Funnel, Tailscale documente la terminaison TLS sur le nœud local avant la transmission de la requête au service local.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` est une option self-hosted où vous contrôlez le serveur de rendez-vous (`frps`) et le client (`frpc`) ; sa documentation couvre la redirection de services locaux situés derrière un NAT ou un firewall, avec des ports/domaines distants déterministes.<sup>[[20]](#references)</sup>

<details>
<summary>Exemple de configuration frps/frpc</summary>
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

La documentation actuelle du projet inclut le transport QUIC, l’authentification par token/OIDC, les limites de bande passante, les health checks et les mappings `range` de Go-template—consultez la release correspondant à votre déploiement avant d’utiliser l’une de ces options.<sup>[[20]](#references)</sup>

## Pinggy (SSH-based)

Pinggy documente le reverse forwarding SSH via le port 443, ce qui lui permet de fonctionner sur les réseaux où le SSH sortant sur le port 22 est bloqué. Son offre gratuite expire après 60 minutes et utilise une nouvelle URL après la reconnexion, tandis que l’offre Pro ajoute des tunnels persistants et des domaines personnalisés.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```
Vous pouvez demander des domaines personnalisés et des tunnels persistants avec Pro.<sup>[[22]](#references)</sup> Vous pouvez recycler automatiquement les tunnels temporaires en plaçant la commande dans une boucle.

## Threat intel & notes OPSEC

Des adversaires ont détourné des tunnels éphémères, notamment les endpoints `trycloudflare.com` de Cloudflare ne nécessitant pas d'authentification, pour distribuer des Remote Access Trojans via une infrastructure temporaire. Proofpoint a signalé une activité observée pour la première fois en février 2024 impliquant Xworm, AsyncRAT, VenomRAT, GuLoader et Remcos, et a noté que les tunnels temporaires compliquent les défenses reposant sur des blocklists statiques.<sup>[[23]](#references)</sup> Envisagez de faire tourner proactivement les tunnels et les domaines, et surveillez les requêtes DNS externes révélatrices vers le tunneler que vous utilisez afin de détecter rapidement une détection par la blue-team ou des tentatives de blocage de l'infrastructure.

## References

- [1] [Documentation de Serveo](https://serveo.net/docs/)
- [2] [Documentation de SocketXP - Premiers pas](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interface en ligne de commande de l'agent ngrok](https://ngrok.com/docs/agent/cli)
- [4] [FAQ de ngrok](https://ngrok.com/docs/faq)
- [5] [Aide de la CLI legacy de Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Documentation de LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Partage de sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - Partage de ports TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Dépôt de localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Documentation de Cloudflare - Configurer Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Présentation de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Documentation de Cloudflare - Commandes utiles de tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Documentation de Cloudflare - Routage](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Documentation de Cloudflare - Fichier de configuration](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Politiques Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Documentation de Cloudflare - Paramètres d'exécution](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Commande Serve de Tailscale](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Commande Funnel de Tailscale](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Dépôt de fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Documentation de Pinggy - Utilisation](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Tunnels localhost simples](https://pinggy.io/)
- [23] [Proofpoint - Un threat actor abuse de Cloudflare Tunnels pour distribuer des RAT](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../../banners/hacktricks-training.md}}
