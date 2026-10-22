# Weka huduma ya ndani wazi kwenye intaneti

{{#include ../banners/hacktricks-training.md}}

**Lengo la ukurasa huu ni kupendekeza njia mbadala zinazowezesha angalau kufichua raw TCP ports za ndani na huduma za wavuti za ndani (HTTP) kwenye intaneti BILA kuhitaji kusakinisha chochote kwenye server nyingine (ni kwenye kifaa cha ndani tu, ikihitajika).**

## **Serveo**

Nyaraka za Serveo zinaeleza kuhusu SSH forwarding kwa HTTP endpoints na TCP forwarding za faragha/umma; kuomba public TCP port isiyo 80/443 (ikiwemo port 0 kwa port ya nasibu) kunahitaji mtumiaji aliyesajiliwa.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Mwongozo wa kuanza wa SocketXP unaeleza amri za `socketxp connect tcp://localhost:22` na `socketxp connect http://localhost:8080` kwa TCP na HTTP tunnels; agent huthibitishwa kwanza kwa token ya portal.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

CLI ya ngrok inaeleza HTTP na TCP tunnels; FAQ yake inasema kuwa endpoints za kiwango cha bure za TCP zinahitaji njia halali ya malipo na kwamba kadi haitatozwa.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Msaada wa CLI ya zamani ya Telebit.js unaeleza `telebit http <port>` kwa ajili ya forwarding ya HTTPS na `telebit tcp <local> [remote]` kwa TCP ghafi; upatikanaji hutegemea deployment na relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Tovuti ya sasa ya LocalXpose inaeleza `loclx tunnel http --to 3000`, inaorodhesha usaidizi wa HTTP/TLS/TCP/UDP, na inasema kuwa mpango wa bure unajumuisha matumizi ya kibinafsi/ya kibiashara kwa kiwango kidogo, huku TCP tunneling ikiwa kipengele cha mpango unaolipiwa.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Nyaraka za Expose zinaeleza `expose share` kwa URL za ndani za HTTP/HTTPS na amri ya `expose share-port`, inayopatikana kwa watumiaji wa PRO pekee, kwa port za TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Hazina rasmi ya localtunnel inaeleza jinsi ya kufichua localhost kwa ajili ya majaribio na inaandika amri ya NPX hapa chini.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Nyaraka za sasa za Cloudflare zinaonyesha tunnels za "Quick" zisizohitaji uthibitishaji kwa ajili ya uendelezaji wa ndani, na muhtasari wa bidhaa unataja HTTP, HTTPS, TCP, SSH, na RDP miongoni mwa protocols zinazotumika kuchapishwa.<sup>[[11]](#references)[[12]](#references)</sup>

Kwa tunnel yenye jina inayosimamiwa ndani, Cloudflare inaeleza mtiririko wa `tunnel login`, `create`, `route dns`, na `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Named tunnels zinaweza kufafanua sheria nyingi za ingress katika YAML; sera za Cloudflare Access zinaweza kudhibiti ufikiaji wa programu zilizochapishwa, na Cloudflare inaandika njia za deployment za service na Docker za kuendesha connectors. Quick Tunnels ni tunnels za majaribio za muda zinazotumia bila kujulikana, zenye kikomo cha maombi 200 kwa wakati mmoja na zisizotumia Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

CLI ya sasa ya Tailscale hutumia Serve kwa kushiriki na tailnet pekee na Funnel kwa kushiriki hadharani. Amri hizo zinaunga mkono targets za HTTP/HTTPS reverse-proxy na usambazaji wa TCP; hali ya Funnel ya raw TCP ina kikomo cha ports 443, 8443, na 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Tumia `--bg` kuhifadhi usanidi bila kuacha mchakato ukiendelea mbele, na utumie `tailscale funnel status` kukagua huduma zinazoweza kufikiwa kutoka kwenye intaneti ya umma. Kwa malengo ya HTTPS Funnel, Tailscale inaeleza kuwa TLS hukatizwa kwenye node ya ndani kabla ya ombi kuelekezwa kwa huduma ya ndani.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` ni chaguo linalojipangia mwenyewe ambapo unadhibiti seva ya rendezvous (`frps`) na mteja (`frpc`); nyaraka zake zinaeleza jinsi ya kuelekeza huduma za ndani zilizo nyuma ya NAT au firewall kwa kutumia port/domain za mbali zisizobadilika.<sup>[[20]](#references)</sup>

<details>
<summary>Usanidi wa mfano wa frps/frpc</summary>

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

Nyaraka za mradi wa sasa zinajumuisha usafirishaji wa QUIC, uthibitishaji wa token/OIDC, vikomo vya bandwidth, ukaguzi wa afya na ulinganishaji wa Go-template range—rejelea toleo linalolingana na deployment yako kabla ya kutumia chaguo hizo.<sup>[[20]](#references)</sup>

## Pinggy (inayotumia SSH)

Pinggy inaeleza jinsi ya kutumia SSH reverse forwarding kupitia port 443, hivyo inaweza kufanya kazi kwenye mitandao inayozuia SSH inayotoka kupitia port 22. Mpango wake wa bure huisha baada ya dakika 60 na hutumia URL mpya unapounganisha tena, huku Pro ikiongeza tunnels za kudumu na domains maalum.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Unaweza kuomba domains maalum na tunnels za kudumu kwenye Pro.<sup>[[22]](#references)</sup> Unaweza kuzungusha tunnels za muda kiotomatiki kwa kufunga amri ndani ya loop.

## Maelezo kuhusu threat intel na OPSEC

Wavamizi wametumia vibaya ephemeral tunneling, ikijumuisha endpoints za `trycloudflare.com` za Cloudflare zisizohitaji uthibitishaji, ili kusambaza Remote Access Trojans kupitia miundombinu ya muda. Proofpoint iliripoti shughuli zilizoonekana kwa mara ya kwanza mnamo Februari 2024, zilizohusisha Xworm, AsyncRAT, VenomRAT, GuLoader, na Remcos; pia ilibainisha kuwa tunnels za muda hutatiza ulinzi unaotegemea static blocklists.<sup>[[23]](#references)</sup> Fikiria kuzungusha tunnels na domains mapema, na ufuatilie DNS lookups za nje zinazotambulisha tunneler unayotumia ili uweze kugundua mapema detection ya blue-team au majaribio ya kuzuia miundombinu.

## References

- [1] [Nyaraka za Serveo](https://serveo.net/docs/)
- [2] [Nyaraka za SocketXP - Kuanza](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Kiolesura cha Mstari wa Amri cha ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [Maswali Yanayoulizwa Mara kwa Mara kuhusu ngrok](https://ngrok.com/docs/faq)
- [5] [Msaada wa CLI ya zamani ya Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Nyaraka za LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Kushiriki tovuti](https://expose.dev/docs/client/sharing)
- [9] [Expose - Kushiriki ports za TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Hifadhi ya localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Nyaraka za Cloudflare - Kusanidi Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Muhtasari wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Nyaraka za Cloudflare - Amri muhimu za tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Nyaraka za Cloudflare - Uelekezaji](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Nyaraka za Cloudflare - Faili ya usanidi](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Sera za Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Nyaraka za Cloudflare - Vigezo vya uendeshaji](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Amri ya Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Amri ya Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Hifadhi ya fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Nyaraka za Pinggy - Matumizi](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Tunnels rahisi za Localhost](https://pinggy.io/)
- [23] [Proofpoint - Mhusika wa tishio atumia vibaya Cloudflare Tunnels kusambaza RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
{{#include ../banners/hacktricks-training.md}}
