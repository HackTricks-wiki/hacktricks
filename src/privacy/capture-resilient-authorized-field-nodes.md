# Capture-Resilient Authorized Field Nodes

Raspberry Pi, mini-PC, travel router au cellular appliance iliyo kwenye eneo la tovuti inaweza kuipa red team iliyoidhinishwa vantage point ya kudumu. Pia ni sehemu inayoweza kugunduliwa, kuibwa na kutumiwa kutambua mhusika. Kwa hiyo, lengo sahihi la muundo ni **upatikanaji thabiti na unaodhibitiwa wenye mamlaka machache kwenye node ya uwanjani**, si implant isiyoweza kufuatiliwa.

Mwongozo huu unatumika tu kwa vifaa vilivyowekwa kwa idhini ya maandishi ya mwenye tovuti. Coffee shop, jirani, hoteli au jengo linalotumiwa na watu wengi halipo kwenye wigo kwa sababu tu mtandao wake unaweza kufikiwa. Usifiche hardware katika eneo lisilokubali, usipitie captive portal, usitumie credentials za mtu mwingine, usiingilie monitoring, au kujaribu kufuta ushahidi baada ya kugunduliwa.

{% hint style="warning" %}
Hakuna setting ya kuaminika ya “kutowacha athari”. Rekodi za radio association, DHCP/NAT, carrier, camera, ununuzi, device, provider, controller na destination zinaweza kubaki hata baada ya kifaa kuondolewa. Badala yake, red team inayowajibika huondoa **secrets za kibinafsi na zisizohusiana** kutoka kwenye node, huhifadhi attribution iliyolindwa upande wa controller, na hufanya capture iwe rahisi kudhibiti.
{% endhint %}

## Faida na hasara

**Faida:** source halisi ya ndani au iliyo karibu na target; testing thabiti ya kasi kubwa; huthibitisha NAC, egress, physical inventory na ufunikaji wa SOC; inaweza kuendelea licha ya mabadiliko ya anwani ya operator; access yenye mipaka inaweza kufutwa centrally.

**Hasara:** kuwekwa kimwili hutengeneza ushahidi mkubwa; kupotea kunaweza kufichua device credentials, network profiles na data iliyokusanywa; control traffic inayojirudia inaweza kugunduliwa; power, portals na mabadiliko ya radio hupunguza reliability; tunnel pana inaweza kuwa pivot isiyodhibitiwa.

## Threat model na kanuni zisizobadilika za muundo

Chukulia kuwa aliyekipata anaweza kuondoa storage, kukagua firmware, kunakili kila secret iliyohifadhiwa na software, kuchunguza tabia ya baadaye ya mtandao na kukikabidhi kifaa kwa mteja au law enforcement. Full-disk encryption hulinda kifaa kilichozimwa tu ndani ya threat model yake iliyobainishwa; node inayoendelea kufanya kazi ikiwa unlocked na keys zilizotolewa kwenye memory ni hali tofauti.

| Kanuni | Matokeo ya kiutendaji |
|---|---|
| Hakuna utambulisho wa moja kwa moja wa operator hadi node | Operator huingia kwenye organization gateway; node ina device identity tofauti |
| Hakuna nyenzo za workstation ya kibinafsi | Hakuna personal SSH key, browser profile, email, password manager, phone pairing au cloud CLI cache |
| Hakuna controller master secret | Node moja haiwezi ku-enroll nyingine, kubadilisha policy au kusimbua engagements nyingine |
| Outbound-only na yenye mipaka finyu | Field network haikubali management listener; node hufikia tu rendezvous/update/time services zilizoainishwa kwa majina |
| Mamlaka ya muda mfupi na yenye scope | Kila credential ina device, audience, service, expiry na njia ya immediate revocation moja |
| Data ndogo ya ndani | Results hutumwa kwa controller; caches husimbwa, zina ukubwa/TTL wenye mipaka na si za kuaminika kama chanzo kikuu |
| Uwajibikaji wa controller hubaki baada ya capture | Mapping ya asset-to-engagement, approvals, operator access na commands huhifadhiwa centrally na kudhibitiwa kwa access control |
| Kupotea husimamisha kazi | Kugunduliwa au mabadiliko ya hali yasiyoelezeka husababisha kusimamisha kazi, revoke, kutoa taarifa na kuhifadhi ushahidi—si remote destruction |

NIST's IoT baseline huweka device identification, configuration, data protection, logical access, secure software update na cybersecurity-state awareness kama capabilities kuu. Inachukulia state awareness na off-device event records kama msaada wa uchunguzi wa compromise.<sup>[[1]](#references)</sup>

## Reference architecture
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
Gateway lazima ijue ni operator gani alifikia device gani iliyotajwa. Field node inahitaji device credential pekee kwa ajili ya rendezvous. Haijifunzi kamwe source address au authentication secret ya operator, na operator huwa hanakili private management key kwenye node hiyo. Hii hupunguza personal link inayoweza kurejeshwa **kutoka kwenye field storage** bila kuharibu uwajibikaji wa zoezi.

Kwa fleet kubwa, workload-identity system inaweza kutoa X.509 identities za muda mfupi na kuzungusha keys kiotomatiki. SPIFFE inapendekeza X.509 SVIDs inapowezekana na inaeleza kuwa muda mfupi wa matumizi pamoja na rotation ya mara kwa mara hupunguza exposure kutokana na key-compromise.<sup>[[2]](#references)</sup> Timu ndogo inaweza kutumia sifa hizo hizo kwa private CA na certificates za kila device zinazotengenezwa kiotomatiki; kusakinisha SPIRE si lazima ili kutimiza pattern hii.

## Hatua ya 1: authorize na register placement

1. Rekodi owner, site, eneo kamili linaloruhusiwa la placement, networks zinazoruhusiwa, assessment window, destinations/actions zinazoruhusiwa na emergency contacts.
2. Rekodi model, serial, storage serial, wired/wireless MACs, modem IMEI/eSIM au SIM ICCID, power supply na picha ya sasa.
3. Ipe device engagement identifier isiyomhusisha mtu, kwa mfano `E2026-014-DROP03`. Usiweke client name kwenye broadcast hostnames au SSIDs.
4. Waambie exercise controller na kundi dogo linalohitajika la physical-security/SOC deconfliction maana ya “lost,” “moved,” na “discovered” kwa ajili ya test hii.
5. Kubaliana mapema ni nani anayeruhusiwa kuichukua na jinsi finder anavyoweza kuripoti. Safety label inaweza kuacha client detail nyeti huku ikitoa controlled callback.
6. Weka authorization expiry ya kiotomatiki. Connectivity inayoendelea baada ya scope kuisha haipaswi kuongeza ruhusa.

## Hatua ya 2: build image inayoweza kurejeshwa kwa kiwango cha chini

Tumia supported OS image, thibitisha signature/checksum yake kupitia channel iliyoandikwa na vendor, sakinisha security updates na uhifadhi reproducible build manifest. Pendelea read-only au immutable base yenye writable data partition ndogo pale software inapoiruhusu.

1. Ondoa default accounts, demo services, compilers na packages zisizohitajika kwa authorized workload.
2. Zima local GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P na inbound administration isipokuwa zoezi linahitaji mojawapo.
3. Washa secure boot na measured boot/TPM-backed key release ikiwa hardware inaziunga mkono kwa kweli; usidai kuwa Raspberry Pi configuration ina PC-class measured boot bila kuthibitisha model halisi.
4. Encrypt local writable state na configure maximum size pamoja na retention time kali. Encryption ni control ya delay/containment, si uthibitisho kwamba running node haitafichua chochote.
5. Tuma logs muhimu off-device. Weka kikomo kwa local journals ili kuzuia storage exhaustion, lakini usi-configure log wiping au anti-forensic deletion.
6. Hifadhi image manifest, package versions, configuration hash na recovery instructions kwa controller.
7. Reimage spare kutoka kwenye manifest na uendeshe health test ileile. Design ambayo builder wake pekee ndiye anayeweza kuirecover haiko tayari kwa field.

## Hatua ya 3: issue identities zenye one-way trust

Tengeneza identities tatu tofauti:

- **device identity**, inayokubaliwa na rendezvous ya device hii pekee;
- **operator identity**, inayokubaliwa na organization gateway na kulindwa kwa phishing-resistant MFA; na
- **controller/deployment identity**, inayotumika kusign approved jobs au configuration, na kuhifadhiwa nje ya operator na field node.

Node inapaswa kuwa na public key inayohitajika kuthibitisha signed jobs, kamwe isiwe na signing key. Device credential iliyonaswa haipaswi ku-authenticate kwenye cloud consoles, source repositories, payment accounts, nodes nyingine au client production.

Tumia certificate lifetimes fupi pale automatic renewal inategemeka. Wakati long-lived WireGuard key inahitajika kiutendaji, chukulia public key yake kama revocation handle na uizuie kwa peer-specific tunnel address, firewall policy na broker authorization. Weka controller action iliyojaribiwa inayoweza kuondoa peer huyo mara moja.

## Hatua ya 4: stable outbound rendezvous

Pattern ifuatayo ya owned-lab hutoa stable management kupitia NAT bila kufichua inbound service. Hii ni ordinary WireGuard networking, si covert reverse shell. Tumia documentation addresses na uzibadilishe tu kwa endpoints zinazomilikiwa na organization.

Kwenye organization rendezvous, assign `10.77.0.1/32`; assign field node `10.77.0.20/32`. Gateway peer entry inapaswa kukubali address moja tu ya node:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Node inaelekeza mawasiliano outbound kwenye rendezvous na huhifadhi NAT mapping inapohitajika pekee:
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
WireGuard inaeleza sekunde 25 kama muda unaofaa wa keepalive katika utekelezaji mwingi wa NAT/firewall wakati persistence inahitajika; kuiacha ikiwa imezimwa ni bora wakati haihitajiki.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` kwa makusudi hufanya hii kuwa njia ya usimamizi, si pivot ya default-route.

Kisha tumia controls nje ya WireGuard:

1. Resolve `vpn.redteam.example` kupitia approved bootstrap DNS path na pin endpoint ya organization inayotarajiwa katika deployment records.
2. Kwenye node, ruhusu outbound DHCP/RA, DNS/NTP inayohitajika, rendezvous endpoint na njia ya chini kabisa ya approved update. Kataa unsolicited inbound traffic kwenye kila uplink.
3. Kwenye rendezvous, ruhusu `10.77.0.20` kufikia tu broker/health service inayohitajika kwa zoezi. Usiiforward kwa ujumla ndani ya client network.
4. Weka interactive operator access nyuma ya organization gateway. Epuka kuweka SSH wazi kutoka kwenye node kupitia tunnel ikiwa signed pull-job interface inatosheleza assessment.
5. Sanidi service manager ianzishe tunnel baada ya networking, iirestart baada ya failure kwa bounded backoff na itoe alert baada ya failure zinazorudiwa. Restart loop haipaswi kuzidisha mzigo kwenye venue au kuficha fault ya msingi.
6. Thibitisha latest handshake ya peer, lakini usitumie “handshake exists” kama uthibitisho kwamba device haija-compromise.

TURN inaweza kutoa relay-only reachability kwa purpose-built WebRTC control plane, na message queue inaweza kuvumilia intermittent service. TURN humtambulisha client kwa public relay address nyuma ya NAT; server yake hubaki observer.<sup>[[4]](#references)</sup> Chagua control architecture moja badala ya kuweka tunnels juu kwa juu bila observer au reliability benefit iliyotajwa.

## Hatua ya 5: uthabiti wa uplink bila personal links

Kwa venue node iliyoidhinishwa, pendelea mpangilio huu:

1. wired au dedicated test VLAN iliyotolewa na client;
2. enterprise/guest Wi-Fi profile iliyoidhinishwa na owner;
3. cellular/private APN fallback iliyocontractiwa na organization.

Usiiweke kamwe ikiwa na personal phone hotspot, home SSID, personal eSIM, personal Apple/Google account au Wi-Fi profile iliyotolewa kutoka kwenye daily laptop. Hizo ndizo artifacts ambazo capture itaunganisha.

Kwa kila uplink iliyoidhinishwa:

- rekodi SSID/BSSID au switch/VLAN na tabia inayotarajiwa ya captive-portal;
- weka priority ya deterministic na health check kuelekea owned endpoint;
- fanya failover ibadilishe underlay pekee; device na operator identities zibaki kwenye broker;
- hakikisha DNS, IPv6 na application traffic hazipiti rendezvous wakati wa transition;
- toa alert kuhusu SSID/BSSID isiyojulikana, SIM change, default gateway mpya, public-IP/ASN change au uplinks za wakati mmoja;
- test power loss, DHCP renewal, AP restart, public-IP change, saa 24 za kutotumika, tunnel loss na recovery ya primary-to-secondary-to-primary kabla ya deployment.

Private MAC addressing inaweza kupunguza casual cross-network tracking, lakini stable per-network MAC mara nyingi inahitajika kwa authorized NAC. Rekodi kile ambacho OS iliyochaguliwa hufanya na usizungushe MAC kuzunguka access control ya owner.

## Hatua ya 6: punguza kazi na data

Field node salama haipaswi kupokea arbitrary shell text kutoka mailbox. Bainisha signed job types kama `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` au action nyingine iliyotajwa wazi katika rules of engagement. Validate destination, duration, rate, output size na scope tena kwenye node.

1. Pea kila job unique ID, device audience, issue time, expiry, scope reference na maximum output.
2. Isaini kwa controller/deployment identity.
3. Kataa fields zisizojulikana, jobs zilizo-expire/replayed na jobs za device nyingine.
4. Stream results kwenda owned collector; encrypt na weka TTL kwa local spool yoyote isiyoweza kuepukwa.
5. Log accepted/rejected job ID na result hash kwenye controller. Usiweke sensitive command parameters kwenye public monitoring channel.
6. Acha processing wakati authorization ina-expire, identity rotation inafeli au controller inaweka device karantini.

## Monitoring ya discovery, loss au compromise

Monitoring inaweza kuambia controller kwamba observed state imebadilika. Haiwezi kuthibitisha kwa kutegemewa kwamba “investigators wamepata device,” na kujaribu kuwachunguza responders au ku-probe systems zao kungeenda nje ya assessment iliyoidhinishwa.

### Kusanya state nje ya device

Tuma signed, low-volume health record kwa controller katika operational interval iliyorandomize lakini yenye mipaka. Jumuisha tu kile ambacho controller inahitaji:

- device ID, boot ID/counter na monotonic uptime;
- configuration/image hash na software version;
- device-certificate serial na renewal state;
- uplink class, interface, BSSID au switch context kama ilivyoidhinishwa, default-gateway hash na public IP/ASN kama ilivyoonekana na owned service;
- tunnel handshake age, packet counters na queue depth;
- enclosure switch au hardware-tamper state ikiwa owner ameidhinisha sensor;
- disk pressure, temperature, clock-offset estimate na last successful job ID;
- sequence number na signature za kuonyesha replay au gaps.

Hifadhi gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events na alerts centrally. CISA inapendekeza centralizing logs, kuzilinda dhidi ya deletion, kuweka baseline ya activity ya kawaida na kuteua incident-response contacts.<sup>[[5]](#references)</sup>

### Viashiria vya discovery/compromise

| Signal | Possible explanations | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking au removal | corroborate provider/site state; usi-connect tena kutoka approved path isiyoidhinishwa |
| Boot counter changed unexpectedly | power cut, crash, removal au maintenance | quarantine jobs; linganisha muda na site events |
| Config/image hash changed | update error, storage fault au tampering | simamisha kazi; revoke ikiwa si release iliyoidhinishwa na controller |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, device kuhamishwa au interception | linganisha approved inventory; quarantine transition isiyoelezeka |
| Repeated rejected job/signature | corruption, replay au unauthorized controller | simamisha processing na chunguza gateway/controller logs |
| Device credential used twice or from incompatible paths | cloned key, snapshot reuse au network transition | revoke mara moja; hifadhi session records zote mbili |
| Unexpected local login, interface, process or privilege event | maintenance au compromise | isolate kupitia broker policy; hifadhi evidence |
| Enclosure switch/state transition | service, movement au discovery | mjulishe named site contact; usichochee destructive action |
| Provider abuse notice/account query or SOC alert | detection, misconfiguration au out-of-scope traffic | simamisha activity na anzisha deconfliction/incident process |
| Sentinel credential touched | mtu alisoma no-privilege decoy secret ya kipekee kwa node hii | revoke real device identity na hifadhi alert trail |

Sentinel credential lazima itoe **no access**, iite tu alert service inayomilikiwa na organization na ifichuliwe katika rules of engagement. Ni tripwire ya unauthorized reading, si beacon ya tracking mtu aliyepata equipment.

### Alert thresholds

Tumia rules zenye state, si alarm moja ya kushangaza ya “caught”:

- **warning:** interval moja iliyokosekana, address change ya kawaida au queue growth;
- **degraded:** misses tatu mfululizo, renewal delay, primary-uplink loss au restart inayorudiwa;
- **quarantine:** hash/boot/uplink change isiyoidhinishwa, duplicate credential, sentinel use au unexpected privileged event;
- **confirmed discovery/loss:** ripoti ya site/controller, physical inventory mismatch, device kupatikana na mtu asiyeplaniwa au validated provider/SOC escalation.

Test alert delivery kupitia channel inayojitegemea na field node. Epuka kutuma client/device detail nyeti kwenye personal messaging au consumer push accounts.

## Runbook ya suspected discovery au capture

1. **Simamisha:** suspend new jobs na operator sessions. Usitume probe ya “check if watched”.
2. **Quarantine:** fanya broker ikatae device identity na routes zake huku ikihifadhi existing logs.
3. **Revoke:** revoke device certificate/key, queue token, update credential na single-purpose service token yoyote. Suspend organization SIM wakati physical loss inawezekana.
4. **Preserve:** snapshot controller, gateway, provider na alert records; rekodi trusted time, aliyechukua hatua na last known configuration. Usifute au u-wipe node remotely.
5. **Notify:** wasiliana na exercise controller, client incident contact na legal/privacy contacts waliotajwa katika authorization. Ikiwa third party ameipata, tumia pre-agreed recovery process.
6. **Assess:** chukulia kwamba kila secret na cached result kwenye node imefichuka. Orodhesha kwa usahihi kile ambacho kila secret ingeweza kufikia na ikiwa ilitumika baada ya suspicious event.
7. **Contain downstream:** rotate affected service credentials, invalidate pending jobs na kagua owned target/provider logs kwa unexpected behavior.
8. **Recover safely:** retrieve kupitia authorized person pekee; ipige picha/ifungashe, rekodi custody na acquire forensic evidence kama client anavyoelekeza.
9. **Resume with a new identity:** usiwahi silently re-enable captured credential. Rebuild kutoka known manifest, rekebisha control failure na upate explicit approval.

Mwongozo wa sasa wa NIST wa incident-response unaunganisha preparation, detection, response na recovery katika organization-wide cybersecurity risk management; preserve kwanza ili client aweze kubaini kilichotokea na kuchagua response inayofaa.<sup>[[6]](#references)</sup>

## Capture drill kabla ya deployment

Mkabidhi reviewer tofauti test unit iliyofunguliwa au copy ya storage yake na umwombe aorodheshe:

1. device/site/engagement identifiers;
2. operator names, personal accounts, home/workstation networks na recovery contacts;
3. controller/broker destinations na credentials;
4. client network profiles na cached results;
5. devices/projects nyingine zinazoweza kufikiwa kwa kila secret;
6. value au payment credentials;
7. kile ambacho controller anaweza kurevoke na kwa kasi gani;
8. ni activity gani inabaki attributable kutoka central logs.

Pass criteria: hakuna personal accounts/workstation keys; hakuna cross-engagement au enrollment authority; hakuna payment credential; encrypted cache yenye mipaka; one documented device-revocation action; complete controller-side accountability. Chukulia personal link yoyote isiyotarajiwa au lateral capability kama release blocker.

## Closeout

1. Simamisha jobs na disable broker route mwisho wa scope.
2. Retrieve na reconcile exact inventory; ripoti chochote kilichokosekana.
3. Preserve logs/results na, ikihitajika, forensic image kulingana na engagement retention plan.
4. Revoke device, SIM, queue, update na service identities hata hardware ikiwa imerecovered.
5. Ni baada ya preservation/acceptance tu, sanitize au destroy media kwa owner-approved data-disposal process na rekodi completion. Hii ni lifecycle management, si concealment.
6. Ondoa venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules na temporary contacts.
7. Document detection iliyozingatiwa, telemetry iliyokosekana, time to quarantine na kila artifact ambayo capture ilifichua.

## References

- [1] [NIST — Katalogi ya Uwezo wa Cybersecurity wa IoT Device](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Dhana na workload identities za muda mfupi](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Mwanzo wa Haraka: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Tumia Logging kwenye Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Mapendekezo na Mazingatio ya Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
