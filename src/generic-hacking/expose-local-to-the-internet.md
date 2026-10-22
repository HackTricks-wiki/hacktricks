# Stel plaaslike dienste aan die internet bloot

{{#include ../banners/hacktricks-training.md}}

**Die doel van hierdie bladsy is om alternatiewe voor te stel waarmee plaaslike rou TCP-poorte en plaaslike webwerwe (HTTP) TEN MINSTE aan die internet blootgestel kan word, SONDER dat enigiets op die ander bediener geïnstalleer hoef te word (slegs plaaslik, indien nodig).**

## **Serveo**

Serveo se dokumentasie beskryf SSH-aanstuur vir HTTP-eindpunte en private/openbare TCP-aanstuur; om ’n nie-80/443-openbare TCP-poort aan te vra (insluitend poort 0 vir ’n ewekansige poort), moet jy ’n geregistreerde gebruiker wees.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

SocketXP se aanvangsgids dokumenteer `socketxp connect tcp://localhost:22` en `socketxp connect http://localhost:8080` vir TCP- en HTTP-tunnels; die agent word eers met ’n portaal-token geverifieer.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

ngrok se CLI-dokumentasie beskryf HTTP- en TCP-tonnels; sy FAQ sê dat TCP-eindpunte op die gratis vlak ’n geldige betaalmetode vereis en dat geen bedrag van die kaart gehef word nie.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Die verouderde Telebit.js CLI-hulp dokumenteer `telebit http <port>` vir HTTPS-aanstuur en `telebit tcp <local> [remote]` vir rou TCP; beskikbaarheid hang af van die ontplooiing en relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

LocalXpose se huidige webwerf dokumenteer `loclx tunnel http --to 3000`, lys ondersteuning vir HTTP/TLS/TCP/UDP, en sê dat die gratis plan persoonlike/ligte kommersiële gebruik dek, terwyl TCP-tunneling ’n funksie van ’n betaalde plan is.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Expose dokumenteer `expose share` vir plaaslike HTTP/HTTPS-URL's en 'n `expose share-port`-opdrag vir TCP-poorte wat slegs vir PRO beskikbaar is.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Die amptelike Localtunnel-bewaarplek beskryf hoe om localhost vir toetsing bloot te stel en dokumenteer die NPX-opdrag hieronder.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Cloudflare se huidige dokumentasie wys ongemagtigde "Quick"-tunnels vir plaaslike ontwikkeling, en die produktoorsig lys HTTP, HTTPS, TCP, SSH en RDP onder die ondersteunde gepubliseerde protokolle.<sup>[[11]](#references)[[12]](#references)</sup>

Vir 'n plaaslik bestuurde benoemde tunnel dokumenteer Cloudflare die werkvloei `tunnel login`, `create`, `route dns` en `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels kan verskeie ingress-reëls in YAML definieer; Cloudflare Access-beleide kan toegang tot gepubliseerde toepassings beheer, en Cloudflare dokumenteer diens- en Docker-ontplooiingsroetes om connectors te laat loop. Quick Tunnels is anonieme, tydelike toetstonnels met ’n limiet van 200 gelyktydige versoeke en geen ondersteuning vir Server-Sent Events (SSE) nie.<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

Tailscale se huidige CLI gebruik Serve vir deel met net tailnet-gebruikers en Funnel vir openbare deel. Die opdragte ondersteun HTTP/HTTPS-omgekeerde-instaanbedienerteikens en TCP-aanstuur; Funnel se rou TCP-modus is beperk tot poorte 443, 8443 en 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Gebruik `--bg` om die konfigurasie te behou sonder om ’n voorgrondproses aan die gang te hou, en gebruik `tailscale funnel status` om te oudit watter dienste vanaf die openbare internet bereikbaar is. Vir HTTPS Funnel-teikens dokumenteer Tailscale TLS-terminering op die plaaslike node voordat die versoek na die plaaslike diens aangestuur word.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` is ’n self-gehoste opsie waar jy die rendezvous-bediener (`frps`) en die kliënt (`frpc`) beheer; die dokumentasie beskryf hoe om plaaslike dienste agter NAT of ’n firewall met deterministiese afgeleë poorte/domeine aan te stuur.<sup>[[20]](#references)</sup>

<details>
<summary>Voorbeeld van frps/frpc-konfigurasie</summary>

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

Die huidige projekdokumentasie sluit QUIC-vervoer, token-/OIDC-verifikasie, bandwydtelimiete, gesondheidstoetse en Go-template-reeksafbeeldings in—raadpleeg die weergawe wat by jou ontplooiing pas voordat jy enige van hierdie opsies gebruik.<sup>[[20]](#references)</sup>

## Pinggy (SSH-gebaseer)

Pinggy dokumenteer SSH-omgekeerde aanstuur oor poort 443, sodat dit kan werk op netwerke waar uitgaande SSH op poort 22 geblokkeer word. Die gratis plan verval ná 60 minute en gebruik ’n nuwe URL nadat jy weer koppel, terwyl Pro volgehoue tonnels en pasgemaakte domeine bied.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Jy kan custom domains en persistente tunnels op Pro aanvra.<sup>[[22]](#references)</sup> Jy kan tydelike tunnels outomaties herwin deur die opdrag in ’n lus te plaas.

## Bedreigingsintelligensie- en OPSEC-notas

Teenstanders het tydelike tunneling misbruik, insluitend Cloudflare se unauthenticated `trycloudflare.com`-endpoints, om Remote Access Trojans via tydelike infrastruktuur af te lewer. Proofpoint het aktiwiteit gerapporteer wat die eerste keer in February 2024 waargeneem is en waarby Xworm, AsyncRAT, VenomRAT, GuLoader en Remcos betrokke was. Hulle het ook opgemerk dat tydelike tunnels verdediging bemoeilik wat op statiese bloklyste staatmaak.<sup>[[23]](#references)</sup> Oorweeg dit om tunnels en domains proaktief te roteer, en monitor vir kenmerkende eksterne DNS-opsoeke na die tunneler wat jy gebruik, sodat jy blue-team-detectie of pogings om infrastruktuur te blokkeer vroeg kan opmerk.

## References

- [1] [Serveo-dokumentasie](https://serveo.net/docs/)
- [2] [SocketXP-dokumentasie - Aan die gang](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [ngrok Agent-opdragreël-koppelvlak](https://ngrok.com/docs/agent/cli)
- [4] [ngrok Gereelde vrae](https://ngrok.com/docs/faq)
- [5] [Telebit.js ou CLI-hulp](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [LocalXpose-dokumentasie](https://localxpose.gitbook.io/docs)
- [8] [Expose - Deel van webwerwe](https://expose.dev/docs/client/sharing)
- [9] [Expose - Deel van TCP-poorte](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [localtunnel/localtunnel-bewaarplek](https://github.com/localtunnel/localtunnel)
- [11] [Cloudflare-dokumentasie - Stel Cloudflare Tunnel op](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Oorsig van Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Cloudflare-dokumentasie - Nuttige tunnel-opdragte](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Cloudflare-dokumentasie - Roetering](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Cloudflare-dokumentasie - Konfigurasielêer](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Cloudflare Access-beleide](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Cloudflare-dokumentasie - Loopparameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Tailscale Serve-opdrag](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Tailscale Funnel-opdrag](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [fatedier/frp - Fast Reverse Proxy-bewaarplek](https://github.com/fatedier/frp)
- [21] [Pinggy-dokumentasie - Gebruik](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Eenvoudige Localhost-tunnels](https://pinggy.io/)
- [23] [Proofpoint - Bedreigingsakteur misbruik Cloudflare Tunnels om RATs af te lewer](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
