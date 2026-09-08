# Nodi za Uwanjani Zilizoidhinishwa Zinazostahimili Kukamatwa

{{#include ../banners/hacktricks-training.md}}

Raspberry Pi, mini-PC, travel router au cellular appliance iliyo kwenye eneo husika inaweza kuipa red team iliyoidhinishwa vantage point ya kudumu. Pia ni sehemu inayoweza kugunduliwa, kuibwa na kuhusishwa na mhusika. Kwa hiyo, lengo sahihi la muundo ni **ufikiaji thabiti na unaodhibitiwa wenye mamlaka kidogo kwenye field node**, si implant isiyoweza kufuatiliwa.

Mwongozo huu unatumika tu kwa vifaa vilivyowekwa kwa idhini ya maandishi ya mwenye eneo. Coffee shop, jirani, hoteli au jengo linalotumiwa na watu wengi halihesabiwi kuwa ndani ya wigo kwa sababu tu mtandao wake unafikika. Usifiche hardware katika eneo lisilokubali, usipitie captive portal, usitumie credentials za mtu mwingine, usiingilie monitoring, wala usijaribu kufuta ushahidi baada ya kugunduliwa.

{% hint style="warning" %}
Hakuna setting ya kuaminika ya “kutokuacha athari”. Rekodi za radio association, DHCP/NAT, carrier, kamera, ununuzi, device, provider, controller na destination zinaweza kubaki baada ya kifaa kuondolewa. Red team inayowajibika badala yake huondoa **secrets za kibinafsi na zisizohusiana** kwenye node, huhifadhi attribution iliyolindwa upande wa controller, na hufanya capture iwe rahisi kudhibiti.
{% endhint %}

## Faida na hasara

**Faida:** source halisi ya ndani au iliyo karibu na target; testing thabiti yenye kasi kubwa; huthibitisha NAC, egress, physical inventory na SOC coverage; inaweza kuendelea wakati wa mabadiliko ya anwani ya operator; access iliyowekewa mipaka inaweza kufutwa centrally.

**Hasara:** uwekaji wa kimwili huunda ushahidi thabiti; kupotea kunaweza kufichua device credentials, network profiles na data iliyokusanywa; control traffic inayorudiwa inaweza kugunduliwa; nguvu za umeme, portals na mabadiliko ya radio hupunguza reliability; tunnel pana inaweza kuwa pivot isiyodhibitiwa.

## Threat model na kanuni zisizobadilika za muundo

Chukulia kwamba mtu anayekipata kifaa anaweza kuondoa storage, kukagua firmware, kunakili kila secret iliyohifadhiwa na software, kuchunguza tabia ya baadaye ya mtandao na kukikabidhi kifaa kwa client au vyombo vya sheria. Full-disk encryption hulinda kifaa kilichozimwa tu ndani ya threat model yake iliyobainishwa; node inayoendesha ikiwa unlocked na keys zilizotolewa kwenye memory ni hali tofauti.

| Kanuni isiyobadilika | Matokeo ya kiutendaji |
|---|---|
| Hakuna identity ya moja kwa moja kati ya operator na node | Operator huingia kwenye organization gateway; node huwa na device identity tofauti |
| Hakuna vifaa vya kibinafsi vya workstation | Hakuna personal SSH key, browser profile, email, password manager, phone pairing au cloud CLI cache |
| Hakuna controller master secret | Node moja haiwezi ku-enroll nyingine, kubadilisha policy au decrypt engagements nyingine |
| Outbound-only na yenye mipaka | Field network haikubali management listener; node hufikia tu rendezvous/update/time services zilizotajwa kwa majina |
| Mamlaka ya muda mfupi na yenye mipaka | Kila credential ina device, audience, service, expiry na njia ya immediate revocation moja |
| Data ndogo ya ndani | Results hutumwa kwa controller; caches zimesimbwa kwa encryption, zina ukubwa/TTL wenye mipaka na si chanzo cha mamlaka |
| Uwajibikaji wa controller hubaki baada ya capture | Mapping ya asset-to-engagement, approvals, operator access na commands huhifadhiwa centrally na access-controlled |
| Kupotea husimamisha kazi | Kugunduliwa au mabadiliko ya hali yasiyoelezeka husababisha kusimamisha kazi, revoke, kutoa taarifa na kuhifadhi ushahidi—not remote destruction |

IoT baseline ya NIST huweka device identification, configuration, data protection, logical access, secure software update na cybersecurity-state awareness kama capabilities za msingi. Pia hushughulikia state awareness na off-device event records kama msaada wa kuchunguza compromise.<sup>[[1]](#references)</sup>

## Muundo wa marejeleo
```text
operator workstation
|  phishing-resistant MFA; named user; no field-device key
v
organization access gateway ----> immutable audit / alerting
|  per-engagement authorization          ^
v                                        |
rendezvous/broker <==== outbound mTLS or WireGuard ==== field node
|                                                     |-- approved site Wi-Fi/Ethernet
+---- allowlisted owned test services                 +-- organization cellular fallback
```
Gateway lazima ijue ni operator gani alifikia device gani iliyotajwa. Field node inahitaji tu device credential kwa ajili ya rendezvous. Haijifunzi source address au authentication secret ya operator, na operator hainakili private management key ndani yake. Hii hupunguza personal link inayoweza kurejeshwa **kutoka kwenye field storage** bila kuharibu accountability ya zoezi.

Kwa fleet kubwa zaidi, workload-identity system inaweza kutoa X.509 identities za muda mfupi na kuzungusha keys kiotomatiki. SPIFFE inapendekeza X.509 SVIDs inapowezekana na inaeleza kuwa lifetimes fupi na rotation ya mara kwa mara hupunguza exposure ya key-compromise.<sup>[[2]](#references)</sup> Timu ndogo inaweza kutumia sifa hizo hizo kwa private CA na automated per-device certificates; kusakinisha SPIRE si lazima ili kutimiza pattern hii.

## Hatua ya 1: kuidhinisha na kusajili placement

1. Rekodi owner, site, exact allowed placement zone, allowed networks, assessment window, allowed destinations/actions na emergency contacts.
2. Rekodi model, serial, storage serial, wired/wireless MACs, modem IMEI/eSIM au SIM ICCID, power supply na photograph ya sasa.
3. Ipe device engagement identifier isiyohusishwa na mtu, kwa mfano `E2026-014-DROP03`. Usisimbishe jina la client kwenye broadcast hostnames au SSIDs.
4. Waambie exercise controller na kundi dogo linalohitajika la physical-security/SOC deconfliction maana ya “lost,” “moved,” na “discovered” kwa ajili ya test hii.
5. Kubalianeni mapema ni nani anayeweza kuiretrieve na finder anawezaje kuripoti. Safety label inaweza kuacha sensitive client detail huku ikitoa controlled callback.
6. Weka automatic authorization expiry. Connectivity inayoendelea baada ya scope kuisha haipaswi kuongeza permission.

## Hatua ya 2: kuunda image ndogo inayoweza kurejeshwa

Tumia supported OS image, thibitisha signature/checksum yake kupitia documented channel ya vendor, sakinisha security updates na uhifadhi reproducible build manifest. Pendelea read-only au immutable base yenye writable data partition ndogo pale software inaporuhusu.

1. Ondoa default accounts, demo services, compilers na packages zisizohitajika na authorized workload.
2. Zima local GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P na inbound administration isipokuwa exercise ihitaji mojawapo.
3. Washa secure boot na measured boot/TPM-backed key release ikiwa hardware inaziunga mkono kwa kweli; usidai kuwa Raspberry Pi configuration ina PC-class measured boot bila kuthibitisha exact model.
4. Encrypt local writable state na usanidi maximum size na retention time kali. Encryption ni control ya delay/containment, si uthibitisho kwamba running node haifichui chochote.
5. Tuma logs muhimu off-device. Weka kikomo kwa local journals ili kuzuia storage exhaustion, lakini usisanidi log wiping au anti-forensic deletion.
6. Hifadhi image manifest, package versions, configuration hash na recovery instructions kwenye controller.
7. Reimage spare kutoka kwenye manifest na uendeshe health test ile ile. Design ambayo builder wake pekee ndiye anaweza kuirecover haijawa tayari kwa field.

## Hatua ya 3: kutoa identities zenye one-way trust

Unda identities tatu tofauti:

- **device identity**, inayokubaliwa na rendezvous ya device hii pekee;
- **operator identity**, inayokubaliwa na organization gateway na kulindwa kwa phishing-resistant MFA; na
- **controller/deployment identity**, inayotumiwa kusaini approved jobs au configuration, na kuhifadhiwa nje ya operator na field node zote mbili.

Node inapaswa kuwa na public key inayohitajika kuthibitisha signed jobs, kamwe isiwe na signing key. Captured device credential haipaswi ku-authenticate kwenye cloud consoles, source repositories, payment accounts, nodes nyingine au client production.

Tumia certificate lifetimes fupi pale automatic renewal inapoaminika. Long-lived WireGuard key inapokuwa muhimu kiutendaji, ichukulie public key yake kama revocation handle na uibane kwa peer-specific tunnel address, firewall policy na broker authorization. Weka controller action iliyojaribiwa ambayo huondoa peer huyo mara moja.

## Hatua ya 4: stable outbound rendezvous

Pattern ifuatayo ya owned-lab hutoa stable management kupitia NAT bila kufichua inbound service. Hii ni ordinary WireGuard networking, si covert reverse shell. Tumia documentation addresses na uzibadilishe tu kwa endpoints zinazomilikiwa na organization.

Kwenye organization rendezvous, assign `10.77.0.1/32`; assign field node `10.77.0.20/32`. Gateway peer entry inapaswa kukubali address hiyo moja pekee ya node:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Node inaelekeza nje kwenda kwenye rendezvous na huhifadhi NAT mapping pale tu inapohitajika:
```ini
# field node: /etc/wireguard/wg-field.conf
[Interface]
Address = 10.77.0.20/32
PrivateKey = <DROP03_PRIVATE_KEY>

[Peer]
PublicKey = <RENDEZVOUS_PUBLIC_KEY>
Endpoint = vpn.redteam.example:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```
WireGuard inaandika sekunde 25 kama muda unaofaa wa keepalive katika utekelezaji mwingi wa NAT/firewall wakati persistence inahitajika; kuiacha ikiwa imezimwa ni bora wakati haihitajiki.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` kwa makusudi hufanya hii kuwa njia ya usimamizi, si pivot ya default-route.

Kisha tumia controls nje ya WireGuard:

1. Resolve `vpn.redteam.example` kupitia njia ya bootstrap DNS iliyoidhinishwa na pin endpoint ya shirika inayotarajiwa katika deployment records.
2. Kwenye node, ruhusu DHCP/RA ya kutoka, DNS/NTP inayohitajika, rendezvous endpoint na update path ya chini iliyoidhinishwa. Kataa traffic ya kuingia isiyoombwa kwenye kila uplink.
3. Kwenye rendezvous, ruhusu `10.77.0.20` kufikia tu broker/health service inayohitajika kwa zoezi. Usiiforward kwa ujumla ndani ya client network.
4. Weka operator access ya interactive nyuma ya organization gateway. Epuka kufichua SSH kutoka kwenye node kupitia tunnel ikiwa signed pull-job interface inatosheleza assessment.
5. Sanidi service manager ianzishe tunnel baada ya networking, ianze tena baada ya failure kwa bounded backoff na itoe alert baada ya failure zinazorudiwa. Restart loop haipaswi kuilemea venue au kuficha fault ya msingi.
6. Thibitisha latest handshake ya peer, lakini usitumie “handshake exists” kama uthibitisho kwamba device haija-compromise.

TURN inaweza kutoa reachability ya relay-only kwa control plane ya WebRTC iliyoundwa kwa kusudi maalum, na message queue inaweza kuvumilia service inayokatika mara kwa mara. TURN humpa client public relay address nyuma ya NAT; server yake hubaki observer.<sup>[[4]](#references)</sup> Chagua control architecture moja badala ya kuweka tunnels juu kwa juu bila observer au reliability benefit iliyotajwa.

## Hatua ya 5: uthabiti wa uplink bila personal links

Kwa venue node iliyoidhinishwa, pendelea mpangilio huu:

1. wired connection iliyotolewa na client au dedicated test VLAN;
2. enterprise/guest Wi-Fi profile iliyoidhinishwa na owner;
3. cellular/private APN fallback iliyowekewa mkataba na shirika.

Usiiweke kamwe na personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account au Wi-Fi profile iliyotolewa kutoka kwenye laptop ya matumizi ya kila siku. Hizo ndizo artifacts ambazo capture itaunganishwa nazo.

Kwa kila uplink iliyoidhinishwa:

- rekodi SSID/BSSID au switch/VLAN na tabia inayotarajiwa ya captive portal;
- weka priority ya deterministic na health check kuelekea endpoint inayomilikiwa;
- fanya failover ibadilishe underlay pekee; device na operator identities zibaki kwenye broker;
- hakikisha DNS, IPv6 na application traffic hazipiti rendezvous wakati wa transition;
- toa alert kuhusu SSID/BSSID isiyojulikana, SIM change, default gateway mpya, public-IP/ASN change au uplinks zinazotumika kwa wakati mmoja;
- jaribu power loss, DHCP renewal, AP restart, public-IP change, idle ya saa 24, tunnel loss na recovery ya primary-to-secondary-to-primary kabla ya deployment.

Private MAC addressing inaweza kupunguza cross-network tracking ya kawaida, lakini stable per-network MAC mara nyingi huhitajika kwa authorized NAC. Rekodi kile ambacho OS iliyochaguliwa hufanya kwa hakika na usizungushe MAC dhidi ya access control ya owner.

## Hatua ya 6: zuia kazi na data

Field node salama haipaswi kupokea shell text ya kiholela kutoka mailbox. Bainisha job types zilizosainiwa kama `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` au action nyingine iliyotajwa wazi katika rules of engagement. Validate destination, duration, rate, output size na scope tena kwenye node.

1. Kila job iwe na unique ID, device audience, issue time, expiry, scope reference na maximum output.
2. Isaini kwa controller/deployment identity.
3. Kataa fields zisizojulikana, jobs zilizo-expire/replayed na jobs za device nyingine.
4. Stream results kwa owned collector; encrypt na TTL local spool yoyote isiyoweza kuepukika.
5. Log accepted/rejected job ID na result hash kwenye controller. Usiweke sensitive command parameters kwenye public monitoring channel.
6. Acha processing authorization inapo-expire, identity rotation inaposhindwa au controller inapoweka device katika quarantine.

## Monitoring kwa ajili ya discovery, loss au compromise

Monitoring inaweza kuiambia controller kwamba observed state imebadilika. Haiwezi kuthibitisha kwa kutegemewa kwamba “investigators wamepata device,” na kujaribu kuwafuatilia responders au kupima systems zao kungeenda nje ya assessment iliyoidhinishwa.

### Kusanya state nje ya device

Tuma signed, low-volume health record kwa controller kwa operational interval ya randomized lakini bounded. Jumuisha tu kile ambacho controller inahitaji:

- device ID, boot ID/counter na monotonic uptime;
- configuration/image hash na software version;
- device-certificate serial na renewal state;
- uplink class, interface, BSSID au switch context iliyoidhinishwa, default-gateway hash na public IP/ASN kama inavyoonekana na owned service;
- tunnel handshake age, packet counters na queue depth;
- enclosure switch au hardware-tamper state ikiwa owner ameidhinisha sensor;
- disk pressure, temperature, clock-offset estimate na last successful job ID;
- sequence number na signature ili kufichua replay au gaps.

Hifadhi gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events na alerts centrally. CISA inapendekeza kuweka logs centrally, kuzilinda dhidi ya deletion, kuweka baseline ya activity ya kawaida na kuteua incident-response contacts.<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat haipo | power/network failure, portal change, damage, deliberate blocking au removal | linganisha provider/site state; usi-connect tena kupitia path isiyoidhinishwa |
| Boot counter imebadilika bila kutarajiwa | power cut, crash, removal au maintenance | quarantine jobs; linganisha muda na site events |
| Config/image hash imebadilika | update error, storage fault au tampering | simamisha work; revoke ikiwa si release iliyoidhinishwa na controller |
| Uplink/BSSID/gateway/ASN mpya | AP replacement, roaming, device kuhamishwa au interception | linganisha approved inventory; quarantine transition isiyoelezeka |
| Job/signature iliyokataliwa mara kwa mara | corruption, replay au controller isiyoidhinishwa | simamisha processing na chunguza gateway/controller logs |
| Device credential imetumika mara mbili au kutoka paths zisizolingana | cloned key, snapshot reuse au network transition | revoke immediately; hifadhi session records zote mbili |
| Local login, interface, process au privilege event isiyotarajiwa | maintenance au compromise | isolate kupitia broker policy; hifadhi evidence |
| Enclosure switch/state transition | service, movement au discovery | mjulishe named site contact; usichochee destructive action |
| Provider abuse notice/account query au SOC alert | detection, misconfiguration au traffic iliyo nje ya scope | simamisha activity na anza deconfliction/incident process |
| Sentinel credential imeguswa | mtu amesoma no-privilege decoy secret ya kipekee kwa node hii | revoke real device identity na hifadhi alert trail |

Sentinel credential lazima **isitoe access yoyote**, iite tu alert service inayomilikiwa na shirika na ifichuliwe katika rules of engagement. Ni tripwire ya unauthorized reading, si beacon ya kufuatilia aliyepata equipment.

### Alert thresholds

Tumia rules zenye state, si alarm moja ya kushangaza ya “caught”:

- **warning:** interval moja iliyokosekana, address change ya kawaida au queue growth;
- **degraded:** misses tatu mfululizo, renewal delay, primary-uplink loss au restart inayorudiwa;
- **quarantine:** hash/boot/uplink change isiyoidhinishwa, duplicate credential, sentinel use au privileged event isiyotarajiwa;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, device recovery na party isiyopangwa au provider/SOC escalation iliyothibitishwa.

Jaribu alert delivery kupitia channel isiyotegemea field node. Epuka kutuma client/device detail nyeti kwenye personal messaging au consumer push accounts.

## Runbook ya suspected discovery au capture

1. **Stop:** simamisha jobs mpya na operator sessions. Usitume probe ya “check if watched”.
2. **Quarantine:** fanya broker ikatae device identity na routes zake huku ikihifadhi logs zilizopo.
3. **Revoke:** revoke device certificate/key, queue token, update credential na single-purpose service token yoyote. Suspend organization SIM wakati physical loss inawezekana.
4. **Preserve:** snapshot controller, gateway, provider na alert records; rekodi trusted time, aliyefanya action na configuration ya mwisho inayojulikana. Usifute au ku-wipe node remotely.
5. **Notify:** wasiliana na exercise controller, client incident contact na legal/privacy contacts zilizobainishwa kwenye authorization. Ikiwa third party ameipata, tumia recovery process iliyokubaliwa mapema.
6. **Assess:** chukulia kwamba kila secret na cached result kwenye node imefichuka. Orodhesha kwa usahihi kila kitu ambacho kila secret ingeweza kufikia na ikiwa ilitumika baada ya suspicious event.
7. **Contain downstream:** rotate service credentials zilizoathirika, invalidate pending jobs na kagua owned target/provider logs kwa behavior isiyotarajiwa.
8. **Recover safely:** retrieve kupitia authorized person pekee; piga picha/package, rekodi custody na pata forensic evidence kulingana na maelekezo ya client.
9. **Resume with a new identity:** usiwahi kuwezesha tena captured credential kimya kimya. Rebuild kutoka known manifest, rekebisha control failure na upate approval ya wazi.

Mwongozo wa sasa wa NIST wa incident-response unaunganisha preparation, detection, response na recovery katika usimamizi wa cybersecurity risk wa shirika zima; hifadhi kwanza ili client aweze kubaini kilichotokea na kuchagua response inayofaa.<sup>[[6]](#references)</sup>

## Capture drill kabla ya deployment

Mkabidhi reviewer tofauti test unit ambayo haijafungwa au copy ya storage yake na umwombe aandike orodha ya:

1. device/site/engagement identifiers;
2. operator names, personal accounts, home/workstation networks na recovery contacts;
3. controller/broker destinations na credentials;
4. client network profiles na cached results;
5. devices/projects nyingine zinazoweza kufikiwa kwa kila secret;
6. value au payment credentials;
7. kile ambacho controller inaweza kurevoke na kwa kasi gani;
8. ni activity ipi bado inaweza kuhusishwa na central logs.

Vigezo vya kupita: hakuna personal accounts/workstation keys; hakuna cross-engagement au enrollment authority; hakuna payment credential; encrypted cache yenye mipaka; action moja iliyoandikwa ya device-revocation; accountability kamili upande wa controller. Chukulia personal link yoyote isiyotarajiwa au lateral capability kama release blocker.

## Closeout

1. Simamisha jobs na disable broker route mwisho wa scope.
2. Retrieve na reconcile inventory halisi; ripoti chochote kilichokosekana.
3. Hifadhi logs/results na, ikihitajika, forensic image kulingana na engagement retention plan.
4. Revoke device, SIM, queue, update na service identities hata hardware ikiwa imepatikana.
5. Ni baada tu ya preservation/acceptance, sanitize au destroy media kwa owner-approved data-disposal process na rekodi completion. Huu ni lifecycle management, si concealment.
6. Ondoa venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules na temporary contacts.
7. Andika detection iliyozingatiwa, telemetry iliyokosekana, time to quarantine na kila artifact ambayo capture ilifichua.

## References

- [1] [NIST — IoT Device Cybersecurity Capability Catalog](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts and short-lived workload identities](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
