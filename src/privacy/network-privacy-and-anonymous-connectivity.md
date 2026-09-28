# Faragha ya Mtandao na Muunganisho Usiojulikana

{{#include ../banners/hacktricks-training.md}}

Faragha ya mtandao ni uamuzi wa routing, si utambulisho kamili. Chagua njia kwa kuuliza ni nani anayepaswa kushindwa kuunganisha **chanzo**, **lengwa**, **maudhui**, na **muda**.

Kwa inventory iliyosanifiwa—`Pros`, `Cons`, `Procedure`, na `Detection` kwa kila familia ya access-path—anza na [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md). Ukurasa huu unaeleza kwa upana chaguo za kawaida zinazoweza kutekelezwa.

## Kile ambacho kila observer anaweza kuona kwa kawaida

| Path | Local network / ISP | Intermediary | Destination | Main limitation | Relative speed |
|---|---|---|---|---|---|
| Direct HTTPS | Metadata ya chanzo, lengwa, muda/ujazo | Hosting/CDN huona muunganisho | Source IP, data ya browser/app | Hakuna faragha ya source-IP | Ya haraka zaidi |
| Commercial VPN | Chanzo kimeunganishwa na VPN; si metadata ya kawaida ya lengwa | VPN huona metadata ya chanzo na lengwa | VPN egress IP | Provider mmoja anakuwa sehemu ya correlation | Kwa kawaida ya haraka |
| Self-hosted VPN/VPS | Chanzo kimeunganishwa na VPS | Kumbukumbu za host/account/payment/control-plane | VPS egress IP | Rahisi kuhusishwa na server/account iliyokodishwa | Kwa kawaida ya haraka |
| Tor Browser | Chanzo kimeunganishwa na Tor/bridge; muda/ujazo | Kila relay huona sehemu ndogo tu | Tor exit, data ya browser | Polepole; hatari za account/endpoint/correlation | Wastani/polepole |
| Tails/Whonix | Njia ya Tor inayofanana, ikiwa na mipaka imara zaidi ya routing | Vikwazo vilevile vya Tor | Tor exit/application data | Makosa ya kiutendaji na host/hardware bado vinaendelea | Wastani/polepole |
| Public guest Wi-Fi + HTTPS | Venue huona kifaa cha ndani/muda na malengo | Venue ISP huona metadata | Guest public IP | Correlation ya eneo halisi/captive-portal/kifaa | Ya haraka/inabadilika |
| Cellular hotspot | Carrier huona subscriber/device/location na malengo | VPN/Tor ikiwa imetumika | Carrier, VPN, au Tor egress IP | Mobile subscription na location ni vitambulisho vya kudumu | Ya haraka/inabadilika |
| Mixnet | Access huona matumizi ya mixnet; muda/ujazo | Mixing nodes nyingi | Gateway/egress | Ecosystem inayoibuka; gharama ya latency na bandwidth | Polepole zaidi |

HTTPS hulinda maudhui yanayosafirishwa lakini si metadata yote. EFF inabainisha kuwa domain, muda, na ukubwa wa traffic vinaweza kubaki vinaonekana kwa intermediaries hata wakati page paths, credentials, na messages zimesimbwa kwa njia fiche.<sup>[[1]](#references)</sup>

## VPNs: faragha ya haraka yenye trust iliyokolezwa

VPN ni muhimu kwa kuficha metadata ya lengwa kutoka kwa access ISP, kulinda first hop kwenye mtandao usioaminika, kuwasilisha engagement egress address thabiti, au kufikia private network. **Haifanyi user asiweze kutambulika.** VPN huona source connection na inaweza kuona destination metadata; accounts, cookies, GPS, fingerprints, na payment information hubaki.<sup>[[1]](#references)</sup>

### Orodha ya ukaguzi wa provider

1. **Ownership and jurisdiction:** tambua legal entity, parent company, nchi za uendeshaji, infrastructure subcontractors, na legal process inayotumika.
2. **Collected data:** tofautisha account/billing, source IP, connection timestamps, bandwidth, crash telemetry, DNS queries, na destination logs. “No browsing logs” haimaanishi “no data.”
3. **Retention and deletion:** tafuta muda kamili wa kuhifadhi data na ikiwa backups, fraud systems, na processors hufuata ratiba hiyo hiyo.
4. **Evidence:** pendelea audits za umma zenye scope, tarehe, findings, na remediation; clients zinazoweza kuzalishwa upya/open; transparency reports; na incidents zilizorekodiwa.
5. **Protocol and client:** WireGuard, OpenVPN, au protocol nyingine iliyokaguliwa na inayotunzwa; automatic updates; DNS na IPv6 handling; kill switch; na per-platform leak tests.
6. **Business model:** elewa jinsi service ya bure au inayofadhiliwa inavyopata fedha. Kuonekana kwenye app store pekee si ushahidi wa operation inayoaminika.
7. **Payment fit:** alternative payment inaweza kupunguza billing disclosure kwa VPN lakini haifuti source IP inayoonekana kwenye kila connection.

### Configure na verify VPN

1. Install signed client ya provider/organization kutoka official source yake.
2. Chagua **full tunnel** isipokuwa route iliyorekodiwa lazima ipite nje yake. Split tunneling huunda correlation na leak paths.
3. Washa fail-closed/always-on behavior na zuia traffic wakati wa reconnect.
4. Tuma DNS kupitia tunnel na test IPv4 pamoja na IPv6. Zima protocol ikiwa tu haiwezi kutunnel kwa usalama na umekubali kupoteza functionality.
5. Test sleep/wake, kubadilisha network, captive-portal login, tunnel crash, na hotspot tethering. NCSC inaonya kuwa tethered clients zinaweza kupita VPN ya simu kwenye baadhi ya platforms.<sup>[[2]](#references)</sup>
6. Tumia test endpoint inayodhibitiwa na organization kurekodi IPv4, IPv6, DNS resolver, na connection timing zinazoonekana. Usifichue engagement nyeti kwa random “leak test” sites.
7. Fanya test tena baada ya mabadiliko ya client, OS, network, au policy.

### Hostile-LAN routing bypasses

VPN inaweza kuendelea kuonekana ikiwa “connected” huku packets zilizochaguliwa zikipita nje yake kwa sababu operating system huchagua route **kabla** VPN haijasimba packet. TunnelCrack ilionyesha njia mbili za kutumia vibaya routing exceptions za kawaida: **LocalNet** hufanya Internet destination ionekane iko kwenye directly connected subnet, huku **ServerIP** ikispoof VPN-gateway resolution ili target address irithi clear-network exception inayohitajika na VPN transport. Hizi ni client/routing failures, si kuvunjwa kwa WireGuard, OpenVPN, IPsec, au TLS; HTTPS payloads hubaki zimesimbwa end-to-end, lakini local observer anaweza kupata destination/timing metadata na data yoyote ya cleartext protocol.<sup>[[18]](#references)</sup>

TunnelVision hutumia primitive hiyo hiyo ya pre-encryption kupitia DHCP option 121. DHCP server hasidi au iliyoathiriwa inaweza kusakinisha classless route iliyo specific zaidi kuliko catch-all route ya VPN, na kuchagua physical interface kwa host au range yoyote. VPN control channel inaweza kubaki hai, hivyo kill switch inayowashwa tu tunnel inapokatika huenda isiwake na ukaguzi mmoja wa public “IP leak” unaweza kukosa bypasses zilizochaguliwa.<sup>[[19]](#references)</sup>

Packet-filter kill switch inayoruhusu DHCP na authenticated VPN transport pekee kwenye physical interface inapaswa kubadilisha hali hii kuwa fail-closed behavior, lakini targeted route injection bado inaweza kuunda selective-denial side channel. Kwa Linux workloads zenye madhara makubwa, pendelea [route-enforced network-namespace pattern](advanced-network-privacy-architectures.md#enforce-the-route-per-workload) yenye nguvu zaidi, ambapo application namespace haina physical interface wala clear-network default route.<sup>[[19]](#references)</sup>

#### Owned-lab verification

Test client/OS/version halisi kwenye AP, DHCP server, VPN endpoint, na destination unazomiliki; madai ya bidhaa nzima hupitwa na wakati haraka kwa sababu routing na packet-filter implementations hutegemea platform. Capture kwenye endpoint yenyewe pamoja na test server—website ya egress-IP pekee haithibitishi kuwa kila destination inafuata tunnel.<sup>[[18]](#references)[[19]](#references)</sup>

1. Connect VPN, rekodi VPN-server address, na hifadhi kila IPv4/IPv6 routing table pamoja na policy-routing rule. Kwenye Windows tumia `route print`; kwenye macOS tumia `netstat -rn`; kwenye Linux tumia commands zilizo hapa chini.
2. Query selected route kwa owned destination IPs kadhaa. Next hop/interface lazima iwe tunnel, isipokuwa documented VPN transport endpoint.
3. Kwa TunnelVision, renew lease kwenye controlled DHCP network na install option 121 route **kwa owned test destination pekee**. Pass inamaanisha traffic bado inatunnel au inazuiwa—haitolewi kamwe kama destination traffic kwenye physical interface.
4. Kwa LocalNet, mpe client lab-only public documentation subnet kama `203.0.113.0/24` na uweke owned test destination ndani yake. Thibitisha kuwa kuwezesha LAN access hakufanyi Internet-class destinations zipite nje ya tunnel.
5. Kwa ServerIP, kabla ya VPN connection, controlled DNS i-resolve owned VPN hostname kwa owned test destination, huku lab gateway iki-forward VPN transport kwenye real owned VPN endpoint. Client haipaswi ku-exempt unrelated application traffic kwenda kwenye spoofed address.
6. Rudia ukiwa na “local network access” ikiwa enabled na disabled, baada ya reconnect, sleep/wake, kubadilisha network, na VPN-process crash. Test IPv4, IPv6, na DNS kwa kujitegemea.
7. Kagua physical-interface capture. Inapaswa kuwa na DHCP na encrypted packets kwenda kwa VPN server, si packets zinazoelekezwa moja kwa moja kwa owned test destination. Pia thibitisha kuwa bypass iliyokataliwa haiwezi kujirudia kimya baada ya user prompts au connectivity repair.
```bash
# Run route monitoring and capture in separate terminals.
TEST_IP=203.0.113.10 # replace with the owned test endpoint
ip -4 route show table all
ip -6 route show table all
ip route get "$TEST_IP"
ip monitor route
sudo tcpdump -ni any "host $TEST_IP"
```
## Tor Browser: kutotenganishwa zaidi kwenye wavuti

Tor huunda mzunguko kupitia relays nyingi ili kwa kawaida relay moja isijue chanzo na lengwa kwa pamoja. Lengwa huona Tor exit badala ya IP ya mtumiaji; mtandao wa ndani kwa kawaida huona muunganisho wa Tor.<sup>[[3]](#references)</sup> Tor imeundwa kwa programu za TCP zenye latency ndogo, hivyo huwa polepole na haiwezi kuhakikisha ulinzi dhidi ya mshambuliaji anayeweza kuoanisha ncha zote mbili.<sup>[[4]](#references)</sup>

### Mtiririko salama wa Tor Browser

1. Pakua Tor Browser kutoka Tor Project au mirror rasmi pekee, na uthibitishe signature inapowezekana.
2. Tumia **Tor Browser**, si browser ya kawaida iliyoelekezwa kwenye Tor SOCKS port. Browser za kawaida zinaweza kuvuja DNS/WebRTC na hali inayotambulisha mtumiaji.<sup>[[5]](#references)</sup>
3. Dumisha size, fonts, extensions na privacy settings za default. Add-ons za ziada zinaweza kufanya browser itofautike zaidi.<sup>[[6]](#references)</sup>
4. Chagua kiwango cha usalama **Safer** au **Safest** wakati kuvunjika kwa baadhi ya tovuti kunakubalika.
5. Tumia bridge wakati Tor ya moja kwa moja imezuiwa au wakati IP za relay za kawaida zingesababisha mwonekano wa ndani usiokubalika. Bridges hupunguza utambuzi rahisi; haziondoi traffic analysis.<sup>[[7]](#references)</sup>
6. Usiingie kwenye account inayokutambulisha, usitoe taarifa zinazokutambulisha, wala usifungue documents active zilizopakuliwa katika application ya nje yenye muunganisho wa mtandao.
7. Tumia session/context tofauti kwa kila identity. “New circuit” si sawa na kufuta identity ya browser/application; tumia **New Identity** au anzisha upya isolated environment inapofaa.
8. Pendelea HTTPS yenye authentication au onion service yenye authentication. Tor exit inaweza kuona traffic ya HTTP isiyosimbwa.

### Tor pamoja na VPN

Kuzichanganya si salama zaidi moja kwa moja. VPN kabla ya Tor inaweza kuficha miunganisho ya moja kwa moja ya Tor relay kutoka kwa ISP huku VPN ikiiona source; Tor kabla ya VPN huipa VPN mwonekano thabiti wa shughuli za baada ya Tor na inaweza kupunguza anonymity set. Configuration isiyo sahihi inaweza kusababisha leaks. Tor Project inapendekeza michanganyiko hii kwa threat models za advanced na zilizoainishwa wazi pekee.<sup>[[8]](#references)</sup>

## Wi-Fi ya umma na ya wageni

HTTPS ya kisasa humaanisha kuwa majirani wanaosikiliza kwa kawaida hawawezi kusoma maudhui ya wavuti yaliyosimbwa ipasavyo, lakini guest Wi-Fi si anonymity. Eneo linaweza kurekodi nyakati za kujiunga, identifiers za kifaa, data ya captive portal, destinations na maelezo ya DHCP; cameras, manunuzi, usafiri na ufuatiliaji wa kimwili vinaweza kumtambua mtumiaji. Hotspot bandia yenye jina linalofanana inaweza pia kunasa credentials za portal au kubadilisha traffic isiyosimbwa.<sup>[[9]](#references)</sup>

### Mtiririko halali wa guest network

1. Tumia network inayotolewa kwa wageni pekee au ambayo mwenyewe amekupa ruhusa ya wazi. Waulize wahudumu SSID kamili na utaratibu wa portal.
2. Update endpoint na travel router kabla ya kuwasili. Zima file/printer sharing, inbound discovery, auto-join na uchunguzi wa networks zilizokumbukwa.
3. Washa private/randomized Wi-Fi address ya OS. Apple systems za sasa zinaweza kutumia rotating addresses kwenye networks zilizo wazi au dhaifu; randomization ya kisasa ya Android kwa kawaida hudumu kwa kila SSID. Hii hupunguza identifier moja ya ndani pekee.<sup>[[10]](#references)</sup><sup>[[11]](#references)</sup>
4. Pendelea travel router inayodhibitiwa na organization au low-trust bridge device kati ya workstation yenye privileges na guest network. Hii huweka firewall/VPN policy katikati, lakini haimfichi router kutoka kwa eneo.<sup>[[12]](#references)</sup>
5. Kamilisha captive portal kupitia low-trust device/browser iliyoteuliwa pekee. Usiweke kamwe credentials za binafsi au zilizotumika tena katika context inayodaiwa kuwa anonymous. Funga portal browser baada ya muunganisho kuanzishwa.
6. Anzisha full-tunnel VPN au Tor kabla ya shughuli nyeti na uthibitishe fail-closed behavior.
7. Sahau network baada ya matumizi na kagua policy ya portal kuhusu account na kuhifadhi data.

{% hint style="danger" %}
Kuvunja Wi-Fi ya jirani, kukwepa portal, kutumia guest credentials zilizovuja, kunakili access ya mgeni mwingine, au kuficha Raspberry Pi kwenye café ni shughuli isiyoruhusiwa—si mbinu ya privacy. Njia salama zinazolingana ni lawful guest network, site iliyoidhinishwa na client, au drop node iliyoandikwa na kuwekwa na kurejeshwa kwa ridhaa ya maandishi ya mwenye mali.
{% endhint %}

## Travel routers

Travel router inaweza kutenga workstation dhidi ya broadcasts hatari za ndani, kutekeleza firewall, kutoa SSID ya ndani thabiti na kuunganisha VPN upya kiotomatiki. **Si anonymous**: upstream huona radio identity yake na timing ya traffic, na VPN provider huona source ya tunnel.

- Tumia firmware inayoungwa mkono ya OpenWrt/vendor na uondoe services zisizotumika.
- Administer kupitia Ethernet au dedicated management SSID yenye password ya kipekee.
- Zima WAN-side administration, UPnP, WPS, file sharing na inbound traffic isiyoombwa.
- Tumia randomized/private WAN MAC pale tu inapoungwa mkono na inaporuhusiwa.
- Tekeleza VPN policy kwenye router, ikijumuisha DNS na IPv6, na zuia egress tunnel inaposhindwa.
- Usidhani phone hotspot hupitisha vifaa vilivyotether kupitia VPN ya simu; ifanyie test.

## Cellular, SIMs na eSIMs

Cellular ni rahisi lakini si anonymous. Operators huhifadhi subscriber/device identifiers na location inayotokana na kujiunga kwa kifaa kwenye network; eSIM bado ni mobile subscription. Prepaid haimaanishi kwa uhakika kuwa haijasajiliwa—mahitaji hutofautiana kwa nchi na hubadilika.<sup>[[13]](#references)</sup>

Kiutendaji:

- Tumia device tofauti inayoungwa mkono ili kupunguza kuanikwa kwa data binafsi, si kuunda subscriber wa kubuni.
- Usibebe kifaa “tofauti” muda wote kando ya simu binafsi ikiwa co-location iko kwenye threat model.
- Zima cellular, Wi-Fi, Bluetooth na location access zisizotumika; kuzima kifaa kunatoa mpaka wa radio wenye nguvu zaidi kuliko UI toggles.
- Weka traffic nyeti ndani ya approved VPN/Tor path, huku ukitambua kuwa carrier bado anajua subscription/device location na tunnel endpoint.
- Thibitisha current registration na retention rules kupitia national regulator au local counsel; usitegemee lists za mtandaoni za “anonymous SIM countries.”

## DNS na TLS metadata

- **DoH/DoT/DoQ** husimba DNS kati ya client na resolver, na kuzuia kusomwa au kubadilishwa kwa urahisi ndani ya mtandao, lakini resolver bado huona queries na transport identifiers. Hubadilisha trust; hazitoi anonymity.<sup>[[14]](#references)</sup>
- **ODoH** huongeza proxy ili resolver asilazimike kujua client IP, kwa kudhani proxy na target hazishirikiani. Traffic analysis iko wazi nje ya scope.<sup>[[15]](#references)</sup>
- **TLS Encrypted Client Hello (ECH)** inaweza kulinda server name ya ndani katika TLS handshake wakati client, DNS na server zina support. Destination IP, timing, volume na endpoint bado vinaonekana.<sup>[[16]](#references)</sup>
- Katika VPN au Tor environment iliyosanidiwa ipasavyo, DNS inapaswa kufuata route inayoungwa mkono na environment hiyo. Kuongeza resolver tofauti kunaweza kuunda observer mpya au fingerprint.

### Mtiririko wa kuthibitisha Encrypted-DNS/ECH

1. Amua kama DNS inadhibitiwa na VPN/Tor environment, OS au application. Isanidi katika layer **moja** iliyokusudiwa badala ya kuweka resolvers zisizohusiana kwa pamoja.
2. Chagua resolver kwa kuzingatia privacy/retention policy yake iliyochapishwa na uwashe strict encrypted mode pale platform inapoiunga mkono. Opportunistic fallback inaweza kurudi kimya kimya kwenye plaintext.
3. Query unique subdomain chini ya authoritative test zone unayoidhibiti; thibitisha kuwa authoritative log inaona recursive resolver iliyokusudiwa.
4. Capture traffic ya test device pekee kwa authorization. Thibitisha kuwa access network haiwezi kusoma plaintext DNS, huku ukitambua kuwa inaweza kuona encrypted resolver/tunnel endpoint.
5. Test encrypted resolver iliyozuiwa/isiyofikika. Hali ya kupita ni fail-closed iliyochaguliwa au fallback iliyoandikwa—si clear query iliyotokea kwa bahati mbaya.
6. Kwa ECH, tumia host inayodhibitiwa yenye ECH na kagua client/server diagnostics kuthibitisha kuwa **inner** ClientHello ilikubaliwa. Kutoa HTTPS record pekee hakuthibitishi kuwa ECH ilifaulu.
7. Rudia baada ya mabadiliko ya network, captive portals, browser updates na VPN reconnects. Rekodi component inayomiliki DNS/ECH ili administrators wa baadaye wasitengeneze bypass.

## Mixnets

Mixnets kama Nym au Katzenpost huongeza packets zenye size maalum, delay, reordering na cover traffic ili kupinga timing correlation. Sifa hizo hugharimu latency na bandwidth, na ushahidi huru wa deployment-scale ni mdogo. Zichukulie mixnets za consumer za sasa kama **emerging/high-latency options**, si replacements za haraka au zilizohakikishwa za Tor/VPNs.<sup>[[17]](#references)</sup>

### Mtiririko wa evaluation

1. Tambua client inayodumishwa na application kamili inayoungwa mkono; usilazimishe traffic ya browser/system isiyo ya kawaida kupitia proxy ambayo haijaandikwa.
2. Soma threat model ya sasa kuhusu assumptions za entry, mix nodes, gateway, destination na collusion.
3. Install kutoka official signed source katika test compartment tofauti na utumie endpoint yako salama pekee.
4. Pima delivery latency, limits za message-size, reliability, retransmission na kinachotokea gateway isipopatikana.
5. Kagua local traffic na endpoint yako ili kuthibitisha path na source iliyokusudiwa. Kagua kama replies hutumia privacy design hiyo hiyo.
6. Test shutdown/failure: application haipaswi kurudi kimya kimya kwenye direct Internet access.
7. Usizime cover traffic, kupunguza delays au kuchagua fixed routes zisizo za kawaida kwa ajili ya speed pekee; mabadiliko haya yanaweza kubatilisha anonymity model iliyotajwa.
8. Iache ikiwa experimental hadi deployment maalum, independent analysis na operational reliability zifikie kiwango cha madhara kinachowezekana.

## Orodha ya ukaguzi wa network preflight

- [ ] Authorization inahusu access network, target, dates na source infrastructure.
- [ ] Endpoint haina identities zisizohusiana au active sync sessions.
- [ ] IPv4, IPv6, DNS na reconnect behavior zinaendana na mpango.
- [ ] Controlled DHCP/local-subnet route injection haiwezi kuhamishia test traffic kwenye physical interface.
- [ ] Destination huona egress iliyotarajiwa pekee.
- [ ] Captive portal na hotspot behavior zimefanyiwa test bila traffic nyeti.
- [ ] Local sharing/discovery na automatic network joining zimezimwa.
- [ ] Observer table na residual traffic-correlation risk zimekubaliwa.
- [ ] Provider policy, retention na emergency contact ni za sasa.

Kwa split-knowledge relays, route-enforced workloads, pluggable transports, onion services, I2P na disposable remote browsers, endelea kwenye [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md).



## References

- [1] [EFF — Kuchagua VPN Inayokufaa](https://ssd.eff.org/module/choosing-vpn-thats-right-you)
- [2] [UK NCSC — Mwongozo wa usalama wa kifaa: Virtual Private Networks](https://www.ncsc.gov.uk/collection/device-security-guidance/infrastructure/virtual-private-networks)
- [3] [Tor Project — Ulinzi wa privacy na anonymity unaotolewa na Tor](https://support.torproject.org/about-tor/introduction/protections/)
- [4] [Tor Specifications — Utangulizi mfupi wa Tor](https://spec.torproject.org/intro/)
- [5] [Tor Project — Kutumia Tor pamoja na browsers nyingine](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [6] [Tor Project — Plugins na add-ons katika Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [7] [Tor Project — Kuondoa kizuizi cha Tor](https://support.torproject.org/tor-browser/circumvention/unblocking-tor/)
- [8] [Tor Project — Kutumia Tor Browser pamoja na VPN](https://support.torproject.org/tor-browser/general/vpn-with-tor/)
- [9] [FTC Consumer Advice — Je, Public Wi-Fi Networks ni salama?](https://consumer.ftc.gov/articles/are-public-wi-fi-networks-safe-what-you-need-know)
- [10] [Apple Platform Security — Wi-Fi privacy pamoja na Apple devices](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web)
- [11] [Android Open Source Project — Kutekeleza MAC randomization](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [12] [UK NCSC — Principles za Secure Privileged Access Workstations](https://www.ncsc.gov.uk/files/ncsc-principles-for-secure-privileged-access-workstations--paws-.pdf)
- [13] [GSMA — Mandatory SIM registration: mitazamo ya policy na regulatory](https://www.gsma.com/solutions-and-impact/connectivity-for-good/mobile-for-development/programme/digital-identity/mandatory-sim-registration-policy-and-regulatory-perspectives-in-the-absence-of-data-protection-laws/)
- [14] [RFC 8932 — Mapendekezo kwa DNS Privacy Service Operators](https://www.rfc-editor.org/rfc/rfc8932.html)
- [15] [RFC 9230 — Oblivious DNS over HTTPS](https://www.rfc-editor.org/rfc/rfc9230.html)
- [16] [RFC 9849 — TLS Encrypted Client Hello](https://www.rfc-editor.org/rfc/rfc9849.html)
- [17] [Katzenpost — Threat Model](https://katzenpost.network/docs/threat_model/)
- [18] [Xue et al. — Kukwepa Tunnels: Kuvuja Traffic ya VPN Client kwa Kutumia Routing Tables](https://www.usenix.org/system/files/usenixsecurity23-xue.pdf)
- [19] [Leviathan Security — TunnelVision: Jinsi Attackers Wanavyoweza Kufichua Routing-Based VPNs na Kusababisha VPN Leak Kamili](https://www.leviathansecurity.com/blog/tunnelvision)
{{#include ../banners/hacktricks-training.md}}
