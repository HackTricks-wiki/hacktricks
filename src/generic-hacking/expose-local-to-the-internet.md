# Fichua ya ndani kwenye intaneti

{{#include ../banners/hacktricks-training.md}}

**Lengo la ukurasa huu ni kupendekeza njia mbadala zinazowezesha angalau kufichua port za ndani za raw TCP na tovuti za ndani (HTTP) kwenye intaneti BILA kuhitaji kusakinisha chochote kwenye server nyingine (ni kwenye kifaa cha ndani tu ikiwa inahitajika).**

Kwa usambazaji kati ya host badala ya kuchapisha service kupitia relay ya umma, angalia [Tunneling and Port Forwarding](tunneling-and-port-forwarding.md).

## **Serveo**

Nyaraka za Serveo zinaeleza SSH forwarding kwa HTTP endpoints na private/public TCP forwarding. Port `0` huomba port ya umma ya TCP ya nasibu hata kwa sessions zisizojulikana, lakini sessions hizo zina vikomo vifupi vya muda na muunganisho; kuomba port maalum ya umma kunahitaji akaunti ya kulipia.<sup>[[1]](#references)</sup>

```bash
# Get a random port from serveo.net to expose local port 4444
ssh -R 0:localhost:4444 serveo.net

# Expose a web listening in localhost:3000 in a random https URL
ssh -R 80:localhost:3000 serveo.net
```

## SocketXP

Mwongozo wa kuanza wa SocketXP unaeleza matumizi ya `socketxp connect tcp://localhost:22` na `socketxp connect http://localhost:8080` kwa TCP na HTTP tunnels; kwanza, agent huthibitishwa kwa token ya portal.<sup>[[2]](#references)</sup>

```bash
# Expose tcp port 22
socketxp connect tcp://localhost:22

# Expose http port 8080
socketxp connect http://localhost:8080
```

## Ngrok

CLI ya ngrok inaeleza kuhusu tunnels za HTTP na TCP. TCP endpoints zinahitaji anwani ya TCP iliyohifadhiwa kwenye akaunti; kiwango cha bure pia kinahitaji njia halali ya malipo, ambayo kulingana na FAQ haitatozwa.<sup>[[3]](#references)[[4]](#references)</sup>

```bash
# Expose a local web service on port 8000
ngrok http 8000

# Expose a local TCP service on port 9000
ngrok tcp 9000
```

## Telebit

Hati za usaidizi za CLI ya Telebit.js ya zamani zinaeleza `telebit http <port>` kwa uelekezaji wa HTTPS na `telebit tcp <local> [remote]` kwa TCP ghafi; upatikanaji hutegemea deployment na relay.<sup>[[5]](#references)</sup>

```bash
# Expose web in 3000
/Users/username/Applications/telebit/bin/telebit http 3000

# Expose port in 9000
/Users/username/Applications/telebit/bin/telebit tcp 9000
```

## LocalXpose

Tovuti ya sasa ya LocalXpose inaeleza `loclx tunnel http --to 3000`, inaorodhesha usaidizi wa HTTP/TLS/TCP/UDP, na inasema kuwa mpango wa bure unajumuisha matumizi binafsi/ya kibiashara kwa kiwango kidogo, huku TCP tunneling ikiwa kipengele cha mpango unaolipiwa.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# Expose a local web service on port 8989
loclx tunnel http --to 8989

# Expose a local TCP service on port 4545 (paid plan)
loclx tunnel tcp --to 4545
```

## Expose

Nyaraka za Expose zinaelezea `expose share` kwa URL za ndani za HTTP/HTTPS na amri ya `expose share-port`, inayopatikana kwa PRO pekee, kwa port za TCP.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Expose a local HTTP service on port 3000
./expose share http://localhost:3000

# Expose a local TCP service on port 4444 (PRO)
./expose share-port 4444
```

## Localtunnel

Hifadhi rasmi ya Localtunnel inaeleza jinsi ya kufichua localhost kwa ajili ya majaribio na inaandika amri ya NPX iliyo hapa chini.<sup>[[10]](#references)</sup>

```bash
# Expose web in port 8000
npx localtunnel --port 8000
```

## Cloudflare Tunnel (cloudflared)

Nyaraka za sasa za Cloudflare zinaonyesha tunnel za "Quick" zisizohitaji uthibitishaji kwa ajili ya maendeleo ya ndani, na muhtasari wa bidhaa unaorodhesha HTTP, HTTPS, TCP, SSH, na RDP miongoni mwa protocols zinazotumika kuchapishwa.<sup>[[11]](#references)[[12]](#references)</sup> Tofauti na HTTP(S), routes za TCP, SSH, na RDP zilizochapishwa haziwezi kufikiwa moja kwa moja kwa kutumia client ya kawaida: Cloudflare inahitaji `cloudflared` kwenye client inayounganisha, kwa hiyo routes hizi hazitimizi sharti la ukurasa huu la kutohitaji kusakinisha client kwa ajili ya raw TCP.<sup>[[24]](#references)</sup>

Kwa tunnel yenye jina inayosimamiwa ndani ya mfumo, Cloudflare inaeleza mtiririko wa kazi wa `tunnel login`, `create`, `route dns`, na `--config ... run ...`.<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```bash
# Quick Tunnel exposing localhost:8080 (random trycloudflare subdomain)
cloudflared tunnel --url http://localhost:8080

# Named tunnel bound to a DNS record
cloudflared tunnel login                       # authenticate with Cloudflare
cloudflared tunnel create my-tunnel
cloudflared tunnel route dns my-tunnel app.example.com
cloudflared tunnel --config tunnel.yml run my-tunnel
```

Tunnels zenye majina zinaweza kufafanua sheria nyingi za ingress katika YAML; sera za Cloudflare Access zinaweza kudhibiti ufikiaji wa programu zilizochapishwa, na Cloudflare inaeleza njia za deployment za service na Docker za kuendesha connectors. Quick Tunnels ni tunnels za majaribio zisizohitaji utambulisho na za muda, zenye kikomo cha maombi 200 kwa wakati mmoja na zisizounga mkono Server-Sent Events (SSE).<sup>[[11]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>

## Tailscale Funnel / Serve

CLI ya sasa ya Tailscale hutumia Serve kwa kushiriki ndani ya tailnet pekee na Funnel kwa kushiriki hadharani. Amri hizi zinaunga mkono malengo ya reverse-proxy ya HTTP/HTTPS na TCP forwarding; hali ya raw TCP ya Funnel ina kikomo cha ports 443, 8443, na 10000.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Share localhost:3000 within the tailnet
sudo tailscale serve 3000

# Publish it publicly on port 443 with Funnel
sudo tailscale funnel --https=443 localhost:3000

# Forward raw TCP (expose local SSH)
sudo tailscale funnel --tcp=10000 tcp://localhost:22
```

Tumia `--bg` ili kuhifadhi usanidi bila kuweka mchakato unaoendelea kwenye foreground, na utumie `tailscale funnel status` kukagua huduma zinazoweza kufikiwa kutoka kwenye intaneti ya umma. Kwa malengo ya HTTPS Funnel, Tailscale inaeleza kuwa TLS hukatizwa kwenye node ya ndani kabla ya ombi kuelekezwa kwa huduma ya ndani.<sup>[[18]](#references)[[19]](#references)</sup>

## Fast Reverse Proxy (frp)

`frp` ni chaguo la self-hosted ambapo unadhibiti seva ya rendezvous (`frps`) na mteja (`frpc`); nyaraka zake zinaeleza jinsi ya kupeleka huduma za ndani zilizo nyuma ya NAT au firewall kwa kutumia port/domain za mbali zinazotabirika.<sup>[[20]](#references)</sup>

<details>
<summary>Mfano wa usanidi wa frps/frpc</summary>

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

Nyaraka za sasa za mradi zinajumuisha usafirishaji wa QUIC, uthibitishaji wa token/OIDC, vikomo vya bandwidth, ukaguzi wa afya, na ulinganishaji wa range za Go-template—hakikisha unatumia toleo linalolingana na deployment yako kabla ya kutumia chaguo hizo.<sup>[[20]](#references)</sup>

## Pinggy (inayotegemea SSH)

Pinggy inaeleza uelekezaji wa reverse kupitia SSH kwenye port 443, hivyo inaweza kufanya kazi kwenye mitandao inayozuia SSH ya kutoka kwenye port 22. Mpango wake wa bure huisha baada ya dakika 60 na hutumia URL mpya baada ya kuunganisha tena, ilhali Pro huongeza tunnels zisizobadilika na domains maalum.<sup>[[21]](#references)[[22]](#references)</sup>

```bash
# Random subdomain exposing localhost:3000 via SSH reverse tunnel
ssh -p 443 -R0:localhost:3000 qr@free.pinggy.io
```

Unaweza kuomba custom domains na persistent tunnels kwenye Pro.<sup>[[22]](#references)</sup> Unaweza kuunda upya tunnels za muda kiotomatiki kwa kuweka amri ndani ya loop.

## Taarifa za vitisho na maelezo ya OPSEC

Wavamizi wametumia vibaya ephemeral tunneling, ikiwemo endpoints za Cloudflare `trycloudflare.com` zisizohitaji uthibitishaji, ili kusambaza Remote Access Trojans kupitia miundombinu ya muda. Proofpoint iliripoti shughuli ilizoziona kwa mara ya kwanza Februari 2024 zilizohusisha Xworm, AsyncRAT, VenomRAT, GuLoader, na Remcos, na ikabainisha kuwa tunnels za muda hutatiza ulinzi unaotegemea static blocklists.<sup>[[23]](#references)</sup> Fikiria kubadilisha tunnels na domains mara kwa mara mapema, na ufuatilie DNS lookups za nje zinazoashiria matumizi ya tunneler unayotumia ili uweze kutambua mapema jaribio la blue team la kugundua au kuzuia miundombinu.

## References

- [1] [Nyaraka za Serveo](https://serveo.net/docs/)
- [2] [Nyaraka za SocketXP - Kuanza](https://docs.socketxp.com/guide/getting-started/getting-started/)
- [3] [Kiolesura cha Mstari wa Amri cha ngrok Agent](https://ngrok.com/docs/agent/cli)
- [4] [Maswali Yanayoulizwa Mara kwa Mara kuhusu ngrok](https://ngrok.com/docs/faq)
- [5] [Msaada wa CLI ya zamani ya Telebit.js](https://git.rootprojects.org/root/telebit.js/src/commit/4aaa87fd6ca5a8b149ce4a5f9d7b22ee5052f5d7/lib/en-us.toml)
- [6] [LocalXpose](https://localxpose.io/)
- [7] [Nyaraka za LocalXpose](https://localxpose.gitbook.io/docs)
- [8] [Expose - Kushiriki tovuti](https://expose.dev/docs/client/sharing)
- [9] [Expose - Kushiriki port za TCP](https://github.com/exposedev/expose/blob/master/docs/client/sharing-tcp-ports.md)
- [10] [Hifadhi ya localtunnel/localtunnel](https://github.com/localtunnel/localtunnel)
- [11] [Nyaraka za Cloudflare - Kuweka Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [12] [Muhtasari wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [13] [Nyaraka za Cloudflare - Amri muhimu za tunnel](https://developers.cloudflare.com/tunnel/advanced/local-management/tunnel-useful-commands/)
- [14] [Nyaraka za Cloudflare - Uelekezaji](https://developers.cloudflare.com/tunnel/routing/)
- [15] [Nyaraka za Cloudflare - Faili ya usanidi](https://developers.cloudflare.com/tunnel/advanced/local-management/configuration-file/)
- [16] [Sera za Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
- [17] [Nyaraka za Cloudflare - Vigezo vya kuendesha](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [18] [Amri ya Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [19] [Amri ya Tailscale Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel)
- [20] [Hifadhi ya fatedier/frp - Fast Reverse Proxy](https://github.com/fatedier/frp)
- [21] [Nyaraka za Pinggy - Matumizi](https://pinggy.io/docs/usages/)
- [22] [Pinggy - Tunnels rahisi za Localhost](https://pinggy.io/)
- [23] [Proofpoint - Mhusika wa Tishio Atumia Vibaya Cloudflare Tunnels Kusambaza RATs](https://www.proofpoint.com/uk/blog/threat-insight/threat-actor-abuses-cloudflare-tunnels-deliver-rats)
- [24] [Nyaraka za Cloudflare - Uelekezaji wa tunnel na protokali zinazotumika](https://developers.cloudflare.com/tunnel/concepts/routing/)
{{#include ../banners/hacktricks-training.md}}
