# Exposer le local sur Internet

{{#include ../banners/hacktricks-training.md}}

**L’objectif de cette page est de proposer des solutions permettant AU MOINS d’exposer sur Internet des ports TCP bruts et des sites web (HTTP) locaux SANS devoir installer quoi que ce soit sur l’autre serveur (uniquement en local, si nécessaire).**

## **Serveo**

La documentation de Serveo décrit le transfert SSH pour les points de terminaison HTTP et le transfert TCP privé/public ; demander un port TCP public autre que 80/443 (y compris le port 0 pour obtenir un port aléatoire) nécessite un compte utilisateur enregistré.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Le guide de démarrage de SocketXP documente `socketxp connect tcp://localhost:22` et `socketxp connect http://localhost:8080` pour les tunnels TCP et HTTP ; l’agent doit d’abord être authentifié avec un jeton du portail.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

La CLI de ngrok documente les tunnels HTTP et TCP ; sa FAQ indique que les points de terminaison TCP de l’offre gratuite nécessitent un moyen de paiement valide et que la carte n’est pas débitée.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

L’aide de l’ancien CLI Telebit.js documente `telebit http <port>` pour le transfert HTTPS et `telebit tcp <local> [remote]` pour le TCP brut ; leur disponibilité dépend du déploiement et du relais.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Le site actuel de LocalXpose documente `loclx tunnel http --to 3000`, répertorie la prise en charge de HTTP/TLS/TCP/UDP et indique que l’offre gratuite couvre les usages personnels et commerciaux légers, tandis que le tunneling TCP est réservé aux offres payantes.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose documente `expose share` pour les URL locales HTTP/HTTPS et une commande `expose share-port` réservée à PRO pour les ports TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Le dépôt officiel de localtunnel explique comment exposer localhost à des fins de test et documente la commande NPX ci-dessous.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

La documentation actuelle de Cloudflare présente des tunnels « Quick » sans authentification pour le développement local, et l’aperçu du produit indique que les protocoles HTTP, HTTPS, TCP, SSH et RDP font partie des protocoles publiés pris en charge.<sup>[[11]](#references)[[12]](#references)</sup>

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

Les tunnels nommés peuvent définir plusieurs règles d’entrée en YAML ; les politiques Cloudflare Access peuvent contrôler l’accès aux applications publiées, et Cloudflare documente les méthodes de déploiement des services et de Docker pour exécuter des connecteurs. Les Quick Tunnels sont des tunnels de test temporaires et anonymes, limités à 200 requêtes simultanées et incompatibles avec Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

La CLI actuelle de Tailscale utilise Serve pour le partage réservé au tailnet et Funnel pour le partage public. Les commandes prennent en charge les cibles de reverse-proxy HTTP/HTTPS et le transfert TCP ; le mode TCP brut de Funnel est limité aux ports 443, 8443 et 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Utilisez `--bg` pour conserver la configuration sans maintenir de processus au premier plan, et utilisez `tailscale funnel status` pour vérifier quels services sont accessibles depuis l’Internet public. Pour les cibles HTTPS Funnel, Tailscale indique que le nœud local termine le TLS avant de transmettre la requête au service local.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` est une option auto-hébergée où vous contrôlez le serveur de rendez-vous (`frps`) et le client (`frpc`) ; sa documentation explique comment transférer des services locaux situés derrière un NAT ou un pare-feu à l’aide de ports/domaines distants déterministes.<sup>[[20]](#references)</sup>

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

La documentation actuelle du projet inclut le transport QUIC, l’authentification par token/OIDC, les limites de bande passante, les health checks et les mappings range Go-template. Consultez la version correspondant à votre déploiement avant d’utiliser ces options.<sup>[[20]](#references)</sup>

## Pinggy (basé sur SSH)

Pinggy documente le transfert inverse SSH via le port 443. Il peut donc fonctionner sur les réseaux où le SSH sortant sur le port 22 est bloqué. Son offre gratuite expire après 60 minutes et utilise une nouvelle URL après reconnexion, tandis que l’offre Pro ajoute des tunnels persistants et des domaines personnalisés.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Vous pouvez demander des domaines personnalisés et des tunnels persistants avec Pro.<sup>[[22]](#references)</sup> Vous pouvez renouveler automatiquement les tunnels temporaires en plaçant la commande dans une boucle.

## Renseignements sur les menaces et notes OPSEC

Des adversaires ont détourné des tunnels éphémères, notamment les points de terminaison `trycloudflare.com` de Cloudflare sans authentification, pour diffuser des chevaux de Troie d’accès à distance depuis une infrastructure temporaire. Proofpoint a signalé une activité observée pour la première fois en février 2024, impliquant Xworm, AsyncRAT, VenomRAT, GuLoader et Remcos, et a noté que les tunnels temporaires compliquent les défenses reposant sur des listes de blocage statiques.<sup>[[23]](#references)</sup> Envisagez de renouveler régulièrement les tunnels et les domaines, et surveillez les requêtes DNS externes révélatrices vers le service de tunneling que vous utilisez afin de repérer rapidement une détection par la blue team ou des tentatives de blocage de l’infrastructure.

## References

- [1] [Documentation de Serveo](https://serveo.net/docs/)
- [2] [Documentation de SocketXP - Premiers pas](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Interface de ligne de commande de l’agent ngrok](https://ngrok.com/docs/agent/cli)
- [4] [FAQ ngrok](https://ngrok.com/docs/faq)
- [5] [Aide de l’interface de ligne de commande héritée de Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Documentation de LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Partage de sites](https://expose.dev/docs/client/sharing)
- [9] [Expose - Partage de ports TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Dépôt localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Documentation Cloudflare - Configurer Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Présentation de Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Documentation Cloudflare - Commandes utiles pour les tunnels](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Documentation Cloudflare - Routage](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Documentation Cloudflare - Fichier de configuration](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Règles Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Documentation Cloudflare - Paramètres d’exécution](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Commande Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Commande Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Dépôt fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Documentation Pinggy - Utilisation](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Tunnels localhost simples](https://pinggy.io/)
- [23] [Proofpoint - Un acteur malveillant détourne Cloudflare Tunnels pour diffuser des RAT](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
