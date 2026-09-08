# Faragha ya Mtandao na Muunganisho Usiojulikana

{{#include ../banners/hacktricks-training.md}}

Faragha ya mtandao ni uamuzi wa njia ya kuelekeza mawasiliano, si utambulisho kamili. Chagua njia kwa kujiuliza ni nani hapaswi kuweza kuunganisha **source**, **destination**, **content**, na **timing**.

Kwa orodha sanifu—`Pros`, `Cons`, `Procedure` ya hatua kwa hatua, na `Detection` kwa kila familia ya njia ya ufikiaji—anza na [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ukurasa huu unapanua chaguo za kawaida zinazoweza kutumika.

## Kile ambacho kila mwangalizi anaweza kuona kwa kawaida

| Njia | Mtandao wa ndani / ISP | Mpatanishi | Destination | Kizuizi kikuu | Kasi ya kulinganisha |
|---|---|---|---|---|---|
| HTTPS ya moja kwa moja | Metadata ya source, destination, timing/volume | Hosting/CDN huona muunganisho | Source IP, browser/app data | Hakuna faragha ya source-IP | Ya haraka zaidi |
| Commercial VPN | Source iliyounganishwa na VPN; kwa kawaida si metadata ya destination | VPN huona metadata ya source na destination | VPN egress IP | Mtoa huduma mmoja huwa sehemu ya correlation | Kwa kawaida ya haraka |
| Self-hosted VPN/VPS | Source iliyounganishwa na VPS | Kumbukumbu za host/account/payment/control-plane | VPS egress IP | Ni rahisi kuhusisha na server/account iliyokodishwa | Kwa kawaida ya haraka |
| Tor Browser | Source iliyounganishwa na Tor/bridge; timing/volume | Relay huona kila mmoja sehemu ndogo | Tor exit, browser data | Polepole; hatari za account/endpoint/correlation | Ya wastani/polepole |
| Tails/Whonix | Njia ya Tor inayofanana, ikiwa na mipaka imara zaidi ya routing | Vizuizi vilevile vya Tor | Tor exit/application data | Makosa ya kiutendaji na host/hardware bado hubaki | Ya wastani/polepole |
| Public guest Wi-Fi + HTTPS | Venue huona device/timing ya ndani na destinations | Venue ISP huona metadata | Guest public IP | Correlation ya kimwili/captive-portal/device | Ya haraka/inayotofautiana |
| Cellular hotspot | Carrier huona subscriber/device/location na destinations | VPN/Tor ikiwa inatumika | Carrier, VPN, au Tor egress IP | Mobile subscription na location ni vitambulisho vya kudumu | Ya haraka/inayotofautiana |
| Mixnet | Access huona matumizi ya mixnet; timing/volume | Mixing nodes nyingi | Gateway/egress | Mfumo unaoibuka; gharama ya latency na bandwidth | Ya polepole zaidi |

HTTPS hulinda content wakati wa usafirishaji, lakini si metadata yote. EFF inabainisha kuwa domain, muda, na ukubwa wa traffic vinaweza kubaki vikionekana na intermediaries hata wakati page paths, credentials, na messages zimesimbwa.<sup>[[1]](#references)</sup>

## VPNs: faragha ya haraka yenye trust iliyojilimbikiza

VPN ni muhimu kwa kuficha metadata ya destination kutoka kwa access ISP, kulinda first hop kwenye mtandao usioaminika, kuwasilisha anwani thabiti ya engagement egress, au kufikia mtandao wa faragha. **Haifanyi mtumiaji awe anonymous.** VPN huona source connection na inaweza kuona metadata ya destination; accounts, cookies, GPS, fingerprints, na payment information bado hubaki.<sup>[[1]](#references)</sup>

### Orodha ya kukagua provider

1. **Umiliki na jurisdiction:** tambua legal entity, parent company, nchi zinazoendesha huduma, infrastructure subcontractors, na legal process inayotumika.
2. **Data inayokusanywa:** tofautisha account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries, na destination logs. “No browsing logs” haimaanishi “no data.”
3. **Uhifadhi na ufutaji:** tafuta muda kamili na kama backups, fraud systems, na processors hufuata ratiba hiyo hiyo.
4. **Ushahidi:** pendelea public audits zilizo na scope, tarehe, findings, na remediation; clients zinazoweza kuzalishwa tena/open clients; transparency reports; na incidents zilizorekodiwa.
5. **Protocol na client:** WireGuard, OpenVPN, au protocol nyingine iliyokaguliwa na inayotunzwa; automatic updates; DNS na IPv6 handling; kill switch; na per-platform leak tests.
6. **Business model:** elewa jinsi huduma ya bure au iliyosubsidizewa inavyofadhiliwa. Uwepo kwenye app store pekee si ushahidi wa operation inayoweza kuaminiwa.
7. **Ulinganifu wa malipo:** alternative payment inaweza kupunguza taarifa za billing zinazofichuliwa kwa VPN, lakini haifuti source IP inayoonekana kila connection.

### Sanidi na thibitisha VPN

1. Sakinisha client iliyosainiwa ya provider/organization kutoka source yake rasmi.
2. Chagua **full tunnel** isipokuwa route iliyorekodiwa lazima ipite nje yake. Split tunneling huunda correlation na leak paths.
3. Washa fail-closed/always-on behavior na zuia traffic wakati wa reconnect.
4. Tuma DNS kupitia tunnel na ujaribu IPv4 na IPv6 zote. Zima protocol ikiwa tu haiwezi kutunnelishwa kwa usalama na upotevu wa functionality umekubaliwa.
5. Jaribu sleep/wake, kubadilisha network, captive-portal login, tunnel crash, na hotspot tethering. NCSC inaonya kuwa tethered clients zinaweza kupita VPN ya simu kwenye baadhi ya platforms.<sup>[[2]](#references)</sup>
6. Tumia test endpoint inayodhibitiwa na organization ili kurekodi IPv4, IPv6, DNS resolver, na connection timing zinazoonekana. Usifichue engagement nyeti kwa random “leak test” sites.
7. Fanya test tena baada ya mabadiliko ya client, OS, network, au policy.

## Tor Browser: unlinkability imara zaidi kwenye web

Tor huunda circuit kupitia relays nyingi ili kwa kawaida relay moja isijue source na destination zote mbili. Destination huona Tor exit badala ya IP ya mtumiaji; kwa kawaida local network huona connection ya Tor.<sup>[[3]](#references)</sup> Tor imeundwa kwa low-latency TCP applications, hivyo ni polepole zaidi na haiwezi kuhakikisha ulinzi dhidi ya adversary anayeweza ku-correlate pande zote mbili.<sup>[[4]](#references)</sup>

### Workflow salama ya Tor Browser

1. Pakua Tor Browser kutoka Tor Project au official mirror pekee na thibitisha signature inapowezekana.
2. Tumia **Tor Browser**, si browser ya kawaida iliyoelekezwa kwenye Tor SOCKS port. Ordinary browsers zinaweza kuvuja DNS/WebRTC na identifying state.<sup>[[5]](#references)</sup>
3. Weka size, fonts, extensions, na privacy settings za default. Add-ons za ziada zinaweza kufanya browser iwe ya kipekee zaidi.<sup>[[6]](#references)</sup>
4. Chagua security level ya **Safer** au **Safest** wakati kuvurugika kwa functionality kunaweza kukubalika.
5. Tumia bridge wakati direct Tor imezuiwa au IP za kawaida za relay zingesababisha local visibility isiyokubalika. Bridges hupunguza recognition rahisi; haziondoi traffic analysis.<sup>[[7]](#references)</sup>
6. Usiingie kwenye identifying account, usitoe identifying information, wala kufungua active documents zilizopakuliwa katika external networked application.
7. Tumia session/context tofauti kwa kila identity. “New circuit” si sawa na kufuta browser/application identity; tumia **New Identity** au anzisha upya isolated environment inapofaa.
8. Pendelea authenticated HTTPS au authenticated onion service. Tor exit inaweza kuona HTTP traffic isiyosimbwa.

### Tor pamoja na VPN

Kuzichanganya si lazima kuwe salama zaidi. VPN kabla ya Tor inaweza kuficha direct Tor relay connections kutoka kwa ISP huku VPN ikiona source; Tor kabla ya VPN huipa VPN mwonekano thabiti wa post-Tor activity na huenda ikapunguza anonymity set. Misconfiguration inaweza kuanzisha leaks. Tor Project inapendekeza mchanganyiko huo kwa advanced, explicit threat models pekee.<sup>[[8]](#references)</sup>

## Public na guest Wi-Fi

HTTPS ya kisasa inamaanisha kuwa majirani wanaosikiliza kwa kawaida hawawezi kusoma web content iliyosimbwa ipasavyo, lakini guest Wi-Fi si anonymity. Venue inaweza kurekodi association times, device identifiers, captive-portal data, destinations, na DHCP details; cameras, purchases, transport, na physical observation vinaweza kumtambua mtumiaji. Hotspot bandia yenye jina linalofanana inaweza pia kukusanya portal credentials au kubadilisha traffic isiyosimbwa.<sup>[[9]](#references)</sup>

### Workflow halali ya guest-network

1. Tumia network inayotolewa kwa wageni pekee au ambayo owner ametoa ruhusa ya wazi. Waulize staff SSID kamili na utaratibu wa portal.
2. Sasisha endpoint na travel router kabla ya kufika. Zima file/printer sharing, inbound discovery, auto-join, na remembered-network probing.
3. Washa private/randomized Wi-Fi address ya OS. Apple systems za sasa zinaweza kutumia rotating addresses kwenye networks zilizo wazi/zenye udhaifu; Android ya kisasa kwa kawaida hutumia randomization inayodumu kwa kila SSID. Hii hupunguza identifier moja ya ndani pekee.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Pendelea organization-controlled travel router au low-trust bridge device kati ya privileged workstation na guest network. Hii huweka firewall/VPN policy sehemu moja lakini haimfichi router kutoka kwa venue.<sup>[[12]](#references)</sup>
5. Kamilisha captive portal kupitia low-trust device/browser iliyoteuliwa pekee. Usiweke kamwe personal au reused credentials kwa anonymous context inayodaiwa. Funga portal browser baada ya connectivity kuanzishwa.
6. Anzisha full-tunnel VPN au Tor kabla ya shughuli nyeti na thibitisha fail-closed behavior.
7. Sahau network baada ya matumizi na kagua portal account/data-retention policy.

{% hint style="danger" %}
Cracking Wi-Fi ya jirani, kupita portal bila ruhusa, kutumia leaked guest credentials, ku-clone access ya mgeni mwingine, au kuficha Raspberry Pi kwenye café ni shughuli zisizoidhinishwa—si privacy technique. Njia salama zinazolingana ni lawful guest network, client-approved site, au documented drop node iliyowekwa na kuondolewa kwa written consent ya property owner.
{% endhint %}

## Travel routers

Travel router inaweza kutenga workstation dhidi ya hostile local broadcasts, kutekeleza firewall, kutoa internal SSID thabiti, na kuunganisha VPN kiotomatiki. **Si anonymous:** upstream huona radio identity na traffic timing yake, na VPN provider huona tunnel source.

- Tumia firmware inayoungwa mkono ya OpenWrt/vendor na uondoe services zisizotumika.
- Administer kupitia Ethernet au dedicated management SSID yenye unique password.
- Zima WAN-side administration, UPnP, WPS, file sharing, na unsolicited inbound traffic.
- Tumia randomized/private WAN MAC pale tu inapoungwa mkono na inaporuhusiwa.
- Tekeleza VPN policy kwenye router, ikijumuisha DNS na IPv6, na zuia egress tunnel inaposhindwa.
- Usidhani kuwa phone hotspot hutunnel tethered devices kupitia VPN ya simu; ifanye test.

## Cellular, SIMs na eSIMs

Cellular ni rahisi lakini si anonymous. Operators huhifadhi subscriber/device identifiers na location inayotokana na network attachment; eSIM bado ni mobile subscription. Prepaid haimaanishi kwa uhakika kuwa haijasajiliwa—mahitaji hutofautiana kwa nchi na hubadilika.<sup>[[13]](#references)</sup>

Kiutendaji:

- Tumia device tofauti inayoungwa mkono ili kupunguza kufichuliwa kwa personal data, si kuunda subscriber wa kubuni.
- Usibebe “separate” device kila mara pamoja na personal phone ikiwa co-location iko kwenye threat model.
- Zima cellular, Wi-Fi, Bluetooth, na location access zisizotumika; kuzima kabisa ni radio boundary imara zaidi kuliko UI toggles.
- Weka sensitive traffic ndani ya approved VPN/Tor path, huku ukitambua kuwa carrier bado anajua subscription/device location na tunnel endpoint.
- Thibitisha registration na retention rules za sasa kupitia national regulator au local counsel; usitegemee online lists za “anonymous SIM countries.”

## DNS na TLS metadata

- **DoH/DoT/DoQ** husimba DNS kati ya client na resolver, hivyo kuzuia usomaji au urekebishaji rahisi wa ndani, lakini resolver bado huona queries na transport identifiers. Huhamisha trust; hazitoi anonymity.<sup>[[14]](#references)</sup>
- **ODoH** huongeza proxy ili resolver asilazimike kujua client IP, ikidhaniwa kuwa proxy na target hazi-collude. Traffic analysis iko wazi nje ya scope.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** inaweza kulinda inner server name kwenye TLS handshake wakati client, DNS, na server zina support hiyo. Destination IP, timing, volume, na endpoint bado vinaonekana.<sup>[[16]](#references)</sup>
- Katika VPN au Tor environment iliyosanidiwa kwa usahihi, DNS inapaswa kufuata route inayoungwa mkono na environment hiyo. Kuongeza resolver tofauti kunaweza kuunda observer mpya au fingerprint.

### Workflow ya kuthibitisha Encrypted-DNS/ECH

1. Amua kama DNS inadhibitiwa na VPN/Tor environment, OS, au application. Isanidi kwenye layer **moja** iliyokusudiwa badala ya kuweka resolvers zisizohusiana kwa pamoja.
2. Chagua resolver kulingana na privacy/retention policy yake iliyochapishwa na washa strict encrypted mode pale platform inapoiunga mkono. Opportunistic fallback inaweza kurudi kimya kimya kwenye plaintext.
3. Query unique subdomain chini ya authoritative test zone unayodhibiti; thibitisha authoritative log inaona intended recursive resolver.
4. Capture traffic ya test device pekee kwa authorization. Thibitisha access network haiwezi kusoma plaintext DNS, huku ukitambua kuwa inaweza kuona encrypted resolver/tunnel endpoint.
5. Jaribu encrypted resolver iliyozuiwa/isiyofikika. Hali ya kufaulu ni fail-closed iliyochaguliwa au documented fallback behavior—si clear query ya bahati mbaya.
6. Kwa ECH, tumia controlled ECH-enabled host na kagua client/server diagnostics ili kuthibitisha **inner** ClientHello ilikubaliwa. Kutoa HTTPS record pekee hakuthibitishi ECH ilifaulu.
7. Rudia baada ya mabadiliko ya network, captive portals, browser updates na VPN reconnects. Rekodi ni component gani inamiliki DNS/ECH ili administrators wa baadaye wasitengeneze bypass.

## Mixnets

Mixnets kama Nym au Katzenpost huongeza fixed-size packets, delay, reordering, na cover traffic ili kupinga timing correlation. Sifa hizo hugharimu latency na bandwidth, na ushahidi huru wa deployment-scale ni mdogo. Chukulia consumer mixnets za sasa kama **emerging/high-latency options**, si replacements za Tor/VPN zilizo na kasi au guarantee zaidi.<sup>[[17]](#references)</sup>

### Evaluation workflow

1. Tambua maintained client na application kamili inayoungwa mkono; usilazimishe arbitrary browser/system traffic kupitia undocumented proxy.
2. Soma threat model ya sasa kwa assumptions za entry, mix nodes, gateway, destination na collusion.
3. Sakinisha kutoka official signed source katika separate test compartment na utumie owned endpoint isiyo na madhara pekee.
4. Pima delivery latency, message-size limits, reliability, retransmission na kitakachotokea gateway isipopatikana.
5. Kagua local traffic na owned endpoint ili kuthibitisha intended path na source. Angalia kama replies hutumia privacy design hiyo hiyo.
6. Jaribu shutdown/failure: application haipaswi kurudi kimya kimya kwenye direct Internet access.
7. Usizime cover traffic, kupunguza delays au kuchagua fixed routes zisizo za kawaida kwa ajili ya speed tu; mabadiliko hayo yanaweza kubatilisha anonymity model iliyotajwa.
8. Iache ikiwa experimental hadi deployment maalum, independent analysis na operational reliability vifikie kiwango cha consequence.

## Orodha ya ukaguzi kabla ya kutumia mtandao

- [ ] Authorization inahusu access network, target, dates, na source infrastructure.
- [ ] Endpoint haina unrelated identities au active sync sessions.
- [ ] IPv4, IPv6, DNS, na reconnect behavior vinaendana na plan.
- [ ] Destination huona egress inayotarajiwa pekee.
- [ ] Captive portal na hotspot behavior vimejaribiwa bila sensitive traffic.
- [ ] Local sharing/discovery na automatic network joining vimezimwa.
- [ ] Observer table na residual traffic-correlation risk vimekubaliwa.
- [ ] Provider policy, retention, na emergency contact ni za sasa.

Kwa split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P, na disposable remote browsers, endelea kwenye [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).

## References

- [1] [EFF — Choosing the VPN That's Right for You](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Device security guidance: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — The privacy and anonymity protections Tor offers](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — A short introduction to Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Using Tor with other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins and add-ons in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Unblocking Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Using Tor Browser with a VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Are Public Wi-Fi Networks Safe?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy with Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Implement MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principles for Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: policy and regulatory perspectives](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Recommendations for DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
{{#include ../banners/hacktricks-training.md}}
