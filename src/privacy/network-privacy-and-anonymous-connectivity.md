# Faragha ya Mtandao na Muunganisho Usiojulikana

Faragha ya mtandao ni uamuzi wa uelekezaji, si utambulisho kamili. Chagua njia kwa kujiuliza ni nani anayepaswa kushindwa kuunganisha **source**, **destination**, **content**, na **timing**.

Kwa orodha sanifu—`Pros`, `Cons`, `Procedure` ya hatua kwa hatua, na `Detection` kwa kila familia ya njia ya ufikiaji—anza na [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ukurasa huu unaeleza kwa kina chaguo za kawaida zinazoweza kutumika.

## Kile ambacho kila mtazamaji anaweza kwa kawaida kuona

| Path | Local network / ISP | Intermediary | Destination | Main limitation | Relative speed |
|---|---|---|---|---|---|
| Direct HTTPS | Metadata ya source, destination, timing/volume | Hosting/CDN huona connection | Source IP, browser/app data | Hakuna faragha ya source-IP | Ya kasi zaidi |
| Commercial VPN | Source iliyounganishwa na VPN; si metadata ya destination kwa kawaida | VPN huona metadata ya source na destination | VPN egress IP | Provider mmoja huwa sehemu ya correlation | Kwa kawaida ya haraka |
| Self-hosted VPN/VPS | Source iliyounganishwa na VPS | Host/account/payment/control-plane logs | VPS egress IP | Ni rahisi kuhusishwa na server/account iliyokodishwa | Kwa kawaida ya haraka |
| Tor Browser | Source iliyounganishwa na Tor/bridge; timing/volume | Relay moja moja huona sehemu ndogo tu | Tor exit, browser data | Polepole; hatari za account/endpoint/correlation | Wastani/polepole |
| Tails/Whonix | Njia ya Tor inayofanana, ikiwa na mipaka imara zaidi ya routing | Mipaka ileile ya Tor | Tor exit/application data | Makosa ya kiutendaji na host/hardware bado vipo | Wastani/polepole |
| Public guest Wi-Fi + HTTPS | Venue huona kifaa cha ndani/timing na destinations | Venue ISP huona metadata | Guest public IP | Correlation ya eneo halisi/captive-portal/device | Ya haraka/inabadilika |
| Cellular hotspot | Carrier huona subscriber/device/location na destinations | VPN/Tor ikiwa inatumika | Carrier, VPN, au Tor egress IP | Mobile subscription na location ni vitambulisho vinavyodumu | Ya haraka/inabadilika |
| Mixnet | Access huona matumizi ya mixnet; timing/volume | Mixing nodes nyingi | Gateway/egress | Mfumo unaoibuka; gharama ya latency na bandwidth | Polepole zaidi |

HTTPS hulinda content wakati wa usafirishaji, lakini si metadata yote. EFF inaeleza kuwa domain, muda, na ukubwa wa traffic vinaweza kubaki vinaonekana kwa intermediaries hata wakati page paths, credentials, na messages zimesimbwa kwa encryption.<sup>[[1]](#references)</sup>

## VPNs: faragha ya haraka yenye trust iliyokolezwa

VPN ni muhimu kwa kuficha metadata ya destination kutoka kwa access ISP, kulinda first hop kwenye mtandao usioaminika, kuwasilisha engagement egress address thabiti, au kufikia private network. **Haifanyi mtumiaji asiweze kutambuliwa.** VPN huona source connection na inaweza kuona metadata ya destination; accounts, cookies, GPS, fingerprints, na payment information hubaki.<sup>[[1]](#references)</sup>

### Orodha ya ukaguzi wa provider

1. **Ownership na jurisdiction:** tambua legal entity, parent company, nchi za uendeshaji, infrastructure subcontractors, na legal process inayotumika.
2. **Data inayokusanywa:** tofautisha account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries, na destination logs. “No browsing logs” haimaanishi “no data.”
3. **Retention na deletion:** tafuta muda kamili na uangalie kama backups, fraud systems, na processors hufuata ratiba hiyo hiyo.
4. **Evidence:** pendelea public audits zenye scope, tarehe, findings, na remediation; clients zinazoweza kuzalishwa tena/open; transparency reports; na incidents zilizorekodiwa.
5. **Protocol na client:** WireGuard, OpenVPN, au protocol nyingine iliyotunzwa na kukaguliwa; automatic updates; DNS na IPv6 handling; kill switch; na leak tests kwa kila platform.
6. **Business model:** elewa jinsi service ya bure au inayofadhiliwa inavyolipiwa. Kuwepo kwenye app store pekee si ushahidi wa uendeshaji unaoaminika.
7. **Payment fit:** alternative payment inaweza kupunguza taarifa za billing kwa VPN, lakini haifuti source IP inayoonekana kwenye kila connection.

### Kusanidi na kuthibitisha VPN

1. Sakinisha client iliyosainiwa ya provider/organization kutoka source yake rasmi.
2. Chagua **full tunnel** isipokuwa route iliyoandikwa lazima ipite nje yake. Split tunneling huunda correlation na leak paths.
3. Washa fail-closed/always-on behavior na zuia traffic wakati wa reconnect.
4. Peleka DNS kupitia tunnel na ujaribu IPv4 na IPv6 zote. Zima protocol tu ikiwa haiwezi kutunnel kwa usalama na umekubali kupoteza functionality.
5. Jaribu sleep/wake, kubadilisha network, captive-portal login, tunnel crash, na hotspot tethering. NCSC inaonya kuwa clients waliotetheriwa wanaweza kupita kwenye VPN ya simu kwenye baadhi ya platforms.<sup>[[2]](#references)</sup>
6. Tumia test endpoint inayodhibitiwa na organization kurekodi IPv4, IPv6, DNS resolver, na connection timing zinazoonekana. Usifichue engagement nyeti kwa “leak test” sites zisizoaminika.
7. Fanya test tena baada ya mabadiliko ya client, OS, network, au policy.

## Tor Browser: web unlinkability yenye nguvu zaidi

Tor huunda circuit kupitia relays nyingi ili kwa kawaida relay moja isijue source na destination zote mbili. Destination huona Tor exit badala ya IP ya mtumiaji; local network kwa kawaida huona Tor connection.<sup>[[3]](#references)</sup> Tor imeundwa kwa low-latency TCP applications, hivyo ni polepole na haiwezi kuhakikisha ulinzi dhidi ya adversary anayeweza ku-correlate ncha zote mbili.<sup>[[4]](#references)</sup>

### Utaratibu salama wa Tor Browser

1. Pakua Tor Browser kutoka Tor Project au official mirror pekee na uthibitishe signature inapowezekana.
2. Tumia **Tor Browser**, si browser ya kawaida iliyoelekezwa kwenye Tor SOCKS port. Browsers za kawaida zinaweza ku-leak DNS/WebRTC na identifying state.<sup>[[5]](#references)</sup>
3. Weka default size, fonts, extensions, na privacy settings. Add-ons za ziada zinaweza kuifanya browser iwe ya kipekee zaidi.<sup>[[6]](#references)</sup>
4. Chagua kiwango cha usalama **Safer** au **Safest** wakati breakage iliyoongezeka inakubalika.
5. Tumia bridge wakati direct Tor imezuiwa au IP za kawaida za relay zitasababisha local visibility isiyokubalika. Bridges hupunguza utambuzi rahisi; haziondoi traffic analysis.<sup>[[7]](#references)</sup>
6. Usiingie kwenye account inayokutambulisha, usitoe taarifa zinazokutambulisha, na usifungue active documents zilizopakuliwa kwenye external networked application.
7. Tumia session/context tofauti kwa kila identity. “New circuit” si sawa na kufuta browser/application identity; tumia **New Identity** au anzisha upya isolated environment inapofaa.
8. Pendelea authenticated HTTPS au authenticated onion service. Tor exit inaweza kuona HTTP traffic isiyo na encryption.

### Tor pamoja na VPN

Kuzichanganya hakumaanishi moja kwa moja usalama zaidi. VPN kabla ya Tor inaweza kuficha direct Tor relay connections kutoka kwa ISP huku VPN ikiiona source; Tor kabla ya VPN huipa VPN mtazamo thabiti wa post-Tor activity na inaweza kupunguza anonymity set. Misconfiguration inaweza kuleta leaks. Tor Project inapendekeza mchanganyiko huo tu kwa threat models za advanced na zilizoainishwa wazi.<sup>[[8]](#references)</sup>

## Public na guest Wi-Fi

HTTPS ya kisasa inamaanisha majirani wanaosikiliza kwa kawaida hawawezi kusoma web content iliyosimbwa ipasavyo, lakini guest Wi-Fi si anonymity. Venue inaweza kurekodi association times, device identifiers, captive-portal data, destinations, na DHCP details; cameras, purchases, transport, na physical observation vinaweza kumtambua mtumiaji. Hotspot bandia yenye jina linalofanana inaweza pia kukusanya portal credentials au kubadilisha traffic isiyo na encryption.<sup>[[9]](#references)</sup>

### Utaratibu halali wa guest network

1. Tumia network inayotolewa kwa guests pekee au ambayo owner amekupa ruhusa wazi. Waulize staff SSID sahihi na utaratibu wa portal.
2. Update endpoint na travel router kabla ya kuwasili. Zima file/printer sharing, inbound discovery, auto-join, na remembered-network probing.
3. Washa private/randomized Wi-Fi address ya OS. Apple systems za sasa zinaweza kutumia rotating addresses kwenye networks zilizo wazi/weak; Android ya kisasa kwa kawaida hutumia randomization inayodumu kwa kila SSID. Hii hupunguza identifier moja tu ya ndani.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Pendelea organization-controlled travel router au low-trust bridge device kati ya privileged workstation na guest network. Hii huweka firewall/VPN policy sehemu moja, lakini haimfichi router venue.<sup>[[12]](#references)</sup>
5. Kamilisha captive portal kupitia low-trust device/browser iliyoteuliwa pekee. Usiingize credentials za kibinafsi au zilizotumika tena katika context inayodaiwa kuwa anonymous. Funga portal browser baada ya connectivity kuanzishwa.
6. Anzisha full-tunnel VPN au Tor kabla ya shughuli nyeti na uthibitishe fail-closed behavior.
7. Sahau network baada ya matumizi na kagua portal account/data-retention policy.

{% hint style="danger" %}
Kuvunja Wi-Fi ya jirani, kupita portal bila ruhusa, kutumia guest credentials zilizovuja, kunakili access ya guest mwingine, au kuficha Raspberry Pi kwenye café ni shughuli isiyoidhinishwa—si mbinu ya faragha. Njia salama zinazolingana ni lawful guest network, client-approved site, au documented drop node iliyowekwa na kuchukuliwa tena kwa idhini ya maandishi ya property owner.
{% endhint %}

## Travel routers

Travel router inaweza kutenga workstation dhidi ya hostile local broadcasts, kutekeleza firewall, kutoa internal SSID thabiti, na kuunganisha VPN tena kiotomatiki. **Si anonymous:** upstream huona radio identity yake na traffic timing, na VPN provider huona tunnel source.

- Tumia firmware inayoungwa mkono ya OpenWrt/vendor na uondoe services zisizotumika.
- Administer kupitia Ethernet au dedicated management SSID yenye password ya kipekee.
- Zima WAN-side administration, UPnP, WPS, file sharing, na unsolicited inbound traffic.
- Tumia randomized/private WAN MAC pale tu inapoungwa mkono na inaporuhusiwa.
- Tekeleza VPN policy kwenye router, ikijumuisha DNS na IPv6, na zuia egress tunnel inaposhindwa.
- Usidhani kuwa phone hotspot hutunnel tethered devices kupitia VPN ya simu; ifanye test.

## Cellular, SIMs na eSIMs

Cellular ni rahisi lakini si anonymous. Operators hudumisha subscriber/device identifiers na location inayotokana na network attachment; eSIM bado ni mobile subscription. Prepaid haimaanishi kwa uhakika kuwa haijasajiliwa—masharti hutofautiana kwa nchi na hubadilika.<sup>[[13]](#references)</sup>

Kiutendaji:

- Tumia device tofauti inayoungwa mkono ili kupunguza kufichuka kwa personal data, si kuunda subscriber wa kubuni.
- Usibebe device “tofauti” kila wakati pamoja na personal phone ikiwa co-location iko kwenye threat model.
- Zima cellular, Wi-Fi, Bluetooth, na location access zisizotumika; kuzima kabisa ni radio boundary yenye nguvu zaidi kuliko UI toggles.
- Weka sensitive traffic ndani ya approved VPN/Tor path, huku ukitambua kuwa carrier bado inajua subscription/device location na tunnel endpoint.
- Thibitisha current registration na retention rules kwa national regulator au local counsel; usitegemee orodha za mtandaoni za “anonymous SIM countries.”

## DNS na TLS metadata

- **DoH/DoT/DoQ** husimba DNS kati ya client na resolver, kuzuia usomaji au urekebishaji rahisi wa ndani, lakini resolver bado huona queries na transport identifiers. Hubadilisha trust; haitoi anonymity.<sup>[[14]](#references)</sup>
- **ODoH** huongeza proxy ili resolver isihitaji kujua client IP, ikizingatiwa kuwa proxy na target hazishirikiani. Traffic analysis iko wazi nje ya scope.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** inaweza kulinda inner server name katika TLS handshake wakati client, DNS, na server zina-support. Destination IP, timing, volume, na endpoint bado vinaonekana.<sup>[[16]](#references)</sup>
- Katika VPN au Tor environment iliyosanidiwa ipasavyo, DNS inapaswa kufuata route inayoungwa mkono na environment hiyo. Kuongeza resolver tofauti kunaweza kuunda observer mpya au fingerprint.

### Utaratibu wa kuthibitisha Encrypted-DNS/ECH

1. Amua ikiwa DNS inadhibitiwa na VPN/Tor environment, OS, au application. Isanidi kwenye **layer** moja iliyokusudiwa badala ya kuweka resolvers zisizohusiana juu kwa juu.
2. Chagua resolver kutoka kwenye privacy/retention policy yake iliyochapishwa na uwashe strict encrypted mode pale platform inapoiunga mkono. Opportunistic fallback inaweza kurudi kimya kimya kwenye plaintext.
3. Query unique subdomain chini ya authoritative test zone unayoidhibiti; thibitisha authoritative log inaona intended recursive resolver.
4. Capture traffic ya test device pekee kwa authorization. Thibitisha access network haiwezi kusoma plaintext DNS, huku ukitambua kuwa inaweza kuona encrypted resolver/tunnel endpoint.
5. Jaribu encrypted resolver iliyozuiwa/isiyofikika. Sharti la kufaulu ni chosen fail-closed au documented fallback behavior—si clear query ya bahati mbaya.
6. Kwa ECH, tumia controlled ECH-enabled host na kagua client/server diagnostics kuthibitisha kuwa **inner** ClientHello ilikubaliwa. Kutoa tu HTTPS record hakuthibitishi kuwa ECH ilifanikiwa.
7. Rudia baada ya mabadiliko ya network, captive portals, browser updates na VPN reconnects. Rekodi ni component gani inamiliki DNS/ECH ili administrators wa baadaye wasitengeneze bypass.

## Mixnets

Mixnets kama Nym au Katzenpost huongeza fixed-size packets, delay, reordering, na cover traffic ili kupinga timing correlation. Sifa hizo hugharimu latency na bandwidth, na ushahidi huru wa deployment-scale bado ni mdogo. Zichukulie consumer mixnets za sasa kama **emerging/high-latency options**, si replacements zenye kasi au uhakika za Tor/VPNs.<sup>[[17]](#references)</sup>

### Utaratibu wa evaluation

1. Tambua client inayotunzwa na application kamili inayoungwa mkono; usilazimishe arbitrary browser/system traffic kupitia undocumented proxy.
2. Soma threat model ya sasa kwa entry, mix nodes, gateway, destination na collusion assumptions.
3. Sakinisha kutoka official signed source katika separate test compartment na utumie owned endpoint isiyo nyeti pekee.
4. Pima delivery latency, message-size limits, reliability, retransmission na kinachotokea gateway isipopatikana.
5. Kagua local traffic na owned endpoint kuthibitisha intended path na source. Angalia kama replies hutumia privacy design hiyo hiyo.
6. Jaribu shutdown/failure: application haipaswi kurudi kimya kimya kwenye direct Internet access.
7. Usizime cover traffic, kupunguza delays au kuchagua fixed routes zisizo za kawaida kwa ajili ya speed pekee; mabadiliko hayo yanaweza kubatilisha anonymity model iliyotajwa.
8. Iache ikiwa experimental hadi specific deployment, independent analysis na operational reliability zifikie kiwango cha consequence.

## Orodha ya ukaguzi wa network preflight

- [ ] Authorization inahusisha access network, target, dates, na source infrastructure.
- [ ] Endpoint haina unrelated identities au active sync sessions.
- [ ] IPv4, IPv6, DNS, na reconnect behavior zinaendana na mpango.
- [ ] Destination huona egress inayotarajiwa pekee.
- [ ] Captive portal na hotspot behavior zimejaribiwa bila sensitive traffic.
- [ ] Local sharing/discovery na automatic network joining zimezimwa.
- [ ] Observer table na residual traffic-correlation risk zimekubaliwa.
- [ ] Provider policy, retention, na emergency contact ni za sasa.

Kwa split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P, na disposable remote browsers, endelea kwenye [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Choosing the VPN That's Right for You](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Mwongozo wa usalama wa device: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Ulinzi wa faragha na anonymity unaotolewa na Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Utangulizi mfupi wa Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Kutumia Tor pamoja na browsers nyingine](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins na add-ons katika Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Kuondoa zuio la Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Kutumia Tor Browser pamoja na VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Je, Public Wi-Fi Networks ni salama?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy kwenye Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Kutekeleza MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principles za Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy na regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommendations kwa DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
