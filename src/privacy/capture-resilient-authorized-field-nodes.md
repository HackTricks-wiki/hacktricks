# Capture-weerstandige gemagtigde veldnodes

{{#include ../banners/hacktricks-training.md}}

'n Raspberry Pi, mini-PC, travel router of sellulêre toestel op die perseel kan aan 'n gemagtigde red team 'n volhoubare uitkykpunt bied. Dit is ook 'n waarskynlike punt van ontdekking, diefstal en attribution. Die regte ontwerpdoelwit is dus **stabiele, beheerde toegang met min authority op die veldnode**, nie 'n onnaspeurbare implant nie.

Hierdie gids is slegs van toepassing op toerusting wat met die perseeleienaar se skriftelike toestemming geplaas word. 'n Koffiewinkel, buurman, hotel of gedeelde gebou is nie binne omvang bloot omdat sy netwerk bereikbaar is nie. Moenie hardeware in 'n venue plaas wat nie toestemming gegee het nie, 'n captive portal omseil, iemand anders se credentials gebruik, met monitoring inmeng of probeer om evidence uit te wis nadat dit ontdek is nie.

{% hint style="warning" %}
Daar is geen betroubare “leave no traces”-instelling nie. Radio association-, DHCP/NAT-, carrier-, kamera-, aankoop-, toestel-, provider-, controller- en destination-rekords kan die toestel oorleef. 'n Aanspreeklike red team verwyder eerder **persoonlike en onverwante secrets** van die node, behou beskermde attribution aan die controller-kant en maak dit goedkoop om 'n capture te beperk.
{% endhint %}

## Voor- en nadele

**Voordele:** realistiese interne of target-adjacent bron; stabiele hoëspoed-testing; valideer NAC, egress, fisiese inventory en SOC-dekking; kan voortgaan ondanks veranderinge aan die operator se address; begrensde toegang kan sentraal herroep word.

**Nadele:** fisiese plasing skep sterk evidence; verlies kan device credentials, network profiles en versamelde data blootstel; herhaalde control traffic is detecteerbaar; krag, portals en radioveranderinge benadeel reliability; 'n breë tunnel kan 'n onbeheerde pivot word.

## Threat model en ontwerp-invariante

Aanvaar dat 'n vinder storage kan verwyder, firmware kan inspekteer, elke software-held secret kan kopieer, latere netwerkgedrag kan waarneem en die toestel aan die kliënt of wetstoepassing kan oorhandig. Full-disk encryption beskerm 'n afgeskakelde toestel slegs binne sy verklaarde threat model; 'n lopende, ontsluite node en keys wat aan memory vrygestel is, is verskillende gevalle.

| Invariant | Praktiese gevolg |
|---|---|
| Geen direkte operator-to-node-identiteit nie | Operator meld aan by die organisasie se gateway; die node het 'n ander device identity |
| Geen persoonlike workstation-materiaal nie | Geen persoonlike SSH key, browser profile, email, password manager, phone pairing of cloud CLI cache nie |
| Geen controller master secret nie | Een node kan nie 'n ander node enroll, policy verander of ander engagements decrypt nie |
| Slegs outbound en beperk | Die veldnetwerk aanvaar geen management listener nie; die node bereik slegs benoemde rendezvous/update/time-dienste |
| Kortstondige, begrensde authority | Elke credential het een device, audience, service, expiry en onmiddellike revocation path |
| Minimum plaaslike data | Results word na die controller gestroom; caches is encrypted, met beperkte size/TTL en nie-authoritatief |
| Controller accountability oorleef capture | Asset-to-engagement mapping, approvals, operator access en commands word sentraal gestoor en access-controlled |
| Verlies stop werk | Discovery of onverklaarde state change aktiveer stop, revoke, notify en evidence preservation—nie remote destruction nie |

NIST se IoT-baseline groepeer device identification, configuration, data protection, logical access, secure software update en cybersecurity-state awareness as kernvermoëns. Dit behandel spesifiek state awareness en off-device event records as ondersteuning vir compromise-ondersoeke.<sup>[[1]](#references)</sup>

## Verwysingsargitektuur
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
Die gateway moet weet watter benoemde operator watter benoemde device bereik het. Die veldnode benodig slegs 'n device credential vir die rendezvous. Dit leer nooit die operator se bronadres of authentication secret nie, en die operator kopieer nooit 'n private management key daarheen nie. Dit verminder die persoonlike skakel wat **uit die field storage** herwin kan word sonder om oefening-accountability te vernietig.

Vir 'n groter vloot kan 'n workload-identity-stelsel kortlewende X.509-identiteite uitreik en keys outomaties roteer. SPIFFE beveel X.509 SVIDs aan waar moontlik en beskryf kort leeftye en gereelde rotasie as maatreëls wat blootstelling aan key compromise beperk.<sup>[[2]](#references)</sup> 'n Klein span kan dieselfde eienskappe met 'n private CA en geoutomatiseerde per-device certificates toepas; dit is nie nodig om SPIRE te installeer net om aan die patroon te voldoen nie.

## Stap 1: magtig en registreer die plasing

1. Teken die eienaar, terrein, presiese toegelate plasingsone, toegelate networks, assessment-venster, toegelate destinations/actions en emergency contacts aan.
2. Teken die model, serial, storage serial, bedrade/draadlose MACs, modem IMEI/eSIM of SIM ICCID, kragtoevoer en 'n huidige foto aan.
3. Gee die device 'n nie-persoonlike engagement identifier, byvoorbeeld `E2026-014-DROP03`. Moenie 'n client name in broadcast hostnames of SSIDs enkodeer nie.
4. Lig die exercise controller en die kleinste nodige physical-security/SOC-deconfliction-groep in oor wat “verlore,” “verskuif” en “ontdek” vir hierdie toets beteken.
5. Stem vooraf saam oor wie dit mag terughaal en hoe 'n vinder dit kan rapporteer. 'n Veiligheidslabel kan sensitiewe client detail weglaat terwyl dit 'n beheerde callback verskaf.
6. Stel 'n outomatiese authorization expiry. Connectivity wat ná die einde van die scope voortduur, mag nie permission verleng nie.

## Stap 2: bou 'n minimale recoverable image

Gebruik 'n ondersteunde OS image, verifieer sy signature/checksum deur die vendor se gedokumenteerde channel, installeer security updates en hou 'n reproduceerbare build manifest. Verkies 'n read-only of immutable base met 'n klein writable data partition waar die software dit toelaat.

1. Verwyder default accounts, demo services, compilers en packages wat nie vir die gemagtigde workload nodig is nie.
2. Deaktiveer local GUI, Bluetooth, discovery protocols, file sharing, Wi-Fi P2P en inbound administration tensy die exercise uitdruklik een vereis.
3. Aktiveer secure boot en measured boot/TPM-backed key release indien die hardware dit werklik ondersteun; moenie beweer dat 'n Raspberry Pi-konfigurasie PC-class measured boot het sonder om die presiese model te valideer nie.
4. Enkripteer local writable state en stel 'n streng maksimumgrootte en retention time op. Encryption is 'n delay/containment control, nie bewys dat 'n running node niks openbaar nie.
5. Stuur belangrike logs off-device. Beperk local journals om storage exhaustion te voorkom, maar moenie log wiping of anti-forensic deletion konfigureer nie.
6. Stoor die image manifest, package versions, configuration hash en recovery instructions by die controller.
7. Reimage 'n spare vanaf die manifest en voer dieselfde health test uit. 'n Ontwerp wat slegs deur sy bouer recovered kan word, is nie field-ready nie.

## Stap 3: reik identities uit met one-way trust

Skep drie verskillende identities:

- 'n **device identity**, wat slegs deur die rendezvous vir hierdie device aanvaar word;
- 'n **operator identity**, wat deur die organization gateway aanvaar word en met phishing-resistant MFA beskerm word; en
- 'n **controller/deployment identity**, wat gebruik word om goedgekeurde jobs of configuration te sign, en buite sowel die operator as die field node gehou word.

Die node moet die public key hê wat nodig is om signed jobs te verifieer, nooit die signing key nie. 'n Ge-capturede device credential mag nie by cloud consoles, source repositories, payment accounts, ander nodes of client production authenticate nie.

Gebruik kort certificate lifetimes waar automatic renewal betroubaar is. Wanneer 'n long-lived WireGuard key operasioneel noodsaaklik is, behandel sy public key as die revocation handle en beperk dit met peer-specific tunnel address, firewall policy en broker authorization. Hou 'n getoetste controller action wat daardie peer onmiddellik verwyder.

## Stap 4: stabiele outbound rendezvous

Die volgende owned-lab-patroon verskaf stabiele management deur NAT sonder om 'n inbound service bloot te stel. Dit is gewone WireGuard networking, nie 'n covert reverse shell nie. Gebruik documentation addresses en vervang hulle slegs met organization-owned endpoints.

By die organization rendezvous, ken `10.77.0.1/32` toe; ken `10.77.0.20/32` aan die field node toe. Die gateway peer entry moet slegs die node se enkele address aanvaar:
```ini
# rendezvous: /etc/wireguard/wg-field.conf (relevant peer only)
[Peer]
PublicKey = <DROP03_PUBLIC_KEY>
AllowedIPs = 10.77.0.20/32
```
Die node wys uitwaarts na die rendezvous en hou die NAT-mapping slegs wanneer dit vereis word:
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
WireGuard dokumenteer 25 sekondes as ’n sinvolle keepalive-interval oor baie NAT/firewall-implementerings wanneer persistentie nodig is; dit is verkieslik om dit gedeaktiveer te laat wanneer dit nie nodig is nie.<sup>[[3]](#references)</sup> `AllowedIPs = 10.77.0.1/32` maak dit doelbewus ’n bestuursroete, nie ’n default-route pivot nie.

Pas dan kontroles buite WireGuard toe:

1. Resolve `vpn.redteam.example` deur die goedgekeurde bootstrap-DNS-pad en pin die verwagte organisasie-endpoint in deployment-rekords.
2. Laat op die node uitgaande DHCP/RA, vereiste DNS/NTP, die rendezvous-endpoint en die minimum goedgekeurde update-pad toe. Deny ongevraagde inkomende verkeer op elke uplink.
3. Laat op die rendezvous slegs toe dat `10.77.0.20` die broker/health-service bereik wat vir die oefening vereis word. Moenie dit algemeen na ’n kliëntnetwerk forward nie.
4. Plaas interaktiewe operator-toegang agter die organisasie-gateway. Vermy SSH vanaf die node oor die tunnel as ’n signed pull-job-interface die assessment bevredig.
5. Konfigureer die service manager om die tunnel ná networking te start, dit ná ’n failure met begrensde backoff te restart en ’n alert te stuur ná herhaalde failures. ’n Restart loop mag nie die venue oorweldig of die onderliggende fout verberg nie.
6. Verifieer die peer se jongste handshake, maar moenie “handshake bestaan” as bewys gebruik dat die device nie compromised is nie.

TURN kan relay-only bereikbaarheid vir ’n doelgeboude WebRTC control plane bied, en ’n message queue kan intermittent service hanteer. TURN gee uitdruklik aan ’n kliënt ’n publieke relay-adres agter NAT; sy server bly ’n observer.<sup>[[4]](#references)</sup> Kies een control architecture eerder as om tunnels te stapel sonder ’n verklaarde observer- of reliability-voordeel.

## Stap 5: uplink-stabiliteit sonder persoonlike links

Vir ’n gemagtigde venue-node, verkies hierdie volgorde:

1. wired client-provided of toegewyde test VLAN;
2. owner-approved enterprise/guest Wi-Fi-profiel;
3. organisasie-gekontrakteerde cellular/private APN fallback.

Moet dit nooit met ’n persoonlike phone hotspot, home SSID, persoonlike eSIM, persoonlike Apple/Google-account of ’n Wi-Fi-profiel wat vanaf ’n daaglikse laptop geëksporteer is, provision nie. Dit is presies die artifacts waarby ’n capture sal aansluit.

Vir elke goedgekeurde uplink:

- teken SSID/BSSID of switch/VLAN en verwagte captive-portal-gedrag aan;
- stel deterministiese prioriteit en ’n health check na ’n endpoint wat besit word;
- laat failover slegs die underlay verander; die device- en operator-identiteite bly by die broker;
- verseker dat DNS, IPv6 en application traffic nie tydens die transition die rendezvous omseil nie;
- stuur ’n alert oor ’n onbekende SSID/BSSID, SIM-verandering, nuwe default gateway, public-IP/ASN-verandering of gelyktydige uplinks;
- toets power loss, DHCP renewal, AP restart, public-IP-verandering, 24-uur idle, tunnel loss en primary-to-secondary-to-primary recovery voor deployment.

Private MAC-addressing kan toevallige cross-network tracking verminder, maar ’n stabiele per-network MAC is dikwels nodig vir gemagtigde NAC. Teken aan wat die gekose OS werklik doen en moenie rondom ’n eienaar se access control roteer nie.

## Stap 6: beperk werk en data

’n Veilige field node behoort nie arbitrêre shell text vanaf ’n mailbox te aanvaar nie. Definieer signed job types soos `health`, `fetch-owned-url`, `capture-approved-interface-for-60s` of ’n ander action wat uitdruklik in die rules of engagement benoem word. Validate destination, duration, rate, output size en scope weer op die node.

1. Gee aan elke job ’n unieke ID, device audience, issue time, expiry, scope reference en maximum output.
2. Sign dit met die controller/deployment identity.
3. Reject onbekende velde, expired/replayed jobs en jobs vir ’n ander device.
4. Stream resultate na ’n collector wat besit word; encrypt en TTL enige onvermydelike plaaslike spool.
5. Log accepted/rejected job ID en result hash by die controller. Moenie sensitiewe command parameters in ’n publieke monitoring channel plaas nie.
6. Stop processing wanneer authorization expire, identity rotation fail of die controller die device as quarantined merk.

## Monitoring vir discovery, loss of compromise

Monitoring kan die controller vertel dat die waargenome toestand verander het. Dit kan nie betroubaar bewys dat “investigators die device gevind het” nie, en om responders te surveil of hul systems te probe, sou ’n gemagtigde assessment oorskry.

### Versamel off-device state

Stuur ’n signed, low-volume health record na die controller met ’n randomized maar begrensde operational interval. Sluit slegs in wat die controller nodig het:

- device ID, boot ID/counter en monotonic uptime;
- configuration/image hash en software version;
- device-certificate serial en renewal state;
- uplink class, interface, BSSID of switch context soos gemagtig, default-gateway hash en public IP/ASN soos deur ’n owned service waargeneem;
- tunnel handshake age, packet counters en queue depth;
- enclosure switch- of hardware-tamper-state indien die eienaar die sensor goedgekeur het;
- disk pressure, temperature, clock-offset estimate en last successful job ID;
- ’n sequence number en signature om replay of gaps bloot te lê.

Store gateway authentication, policy decisions, operator access, job submission, result hashes, provider audit events en alerts sentraal. CISA beveel aan dat logs gesentraliseer word, teen deletion beskerm word, normale activity gebaseline word en incident-response contacts aangewys word.<sup>[[5]](#references)</sup>

### Discovery/compromise indicators

| Signal | Moontlike verklarings | Controller action |
|---|---|---|
| Heartbeat absent | power/network failure, portal change, damage, deliberate blocking of removal | corroborate provider/site state; moenie vanaf ’n ongoedgekeurde pad reconnect nie |
| Boot counter changed unexpectedly | power cut, crash, removal of maintenance | quarantine jobs; vergelyk tyd en site events |
| Config/image hash changed | update error, storage fault of tampering | stop work; revoke indien dit nie ’n controller-approved release is nie |
| New uplink/BSSID/gateway/ASN | AP replacement, roaming, moved device of interception | vergelyk approved inventory; quarantine ’n onverklaarde transition |
| Repeated rejected job/signature | corruption, replay of unauthorized controller | stop processing en ondersoek gateway/controller logs |
| Device credential used twice or from incompatible paths | cloned key, snapshot reuse of network transition | revoke immediately; behou beide session records |
| Unexpected local login, interface, process or privilege event | maintenance of compromise | isolate deur broker policy; preserve evidence |
| Enclosure switch/state transition | service, movement of discovery | notify the named site contact; moenie destructive action trigger nie |
| Provider abuse notice/account query or SOC alert | detection, misconfiguration of out-of-scope traffic | stop activity en invoke deconfliction/incident process |
| Sentinel credential touched | iemand het ’n no-privilege decoy secret unique to this node gelees | revoke real device identity en preserve the alert trail |

’n Sentinel credential moet **geen access verleen nie**, slegs ’n organization-owned alert service call en in die rules of engagement disclosed word. Dit is ’n tripwire vir unauthorized reading, nie ’n beacon om whoever die equipment gevind het te track nie.

### Alert thresholds

Gebruik stateful rules, nie een dramatiese “caught”-alarm nie:

- **warning:** een missed interval, normale address change of queue growth;
- **degraded:** drie consecutive misses, renewal delay, primary-uplink loss of repeated restart;
- **quarantine:** unapproved hash/boot/uplink change, duplicate credential, sentinel use of unexpected privileged event;
- **confirmed discovery/loss:** site/controller report, physical inventory mismatch, device recovery deur ’n unplanned party of validated provider/SOC escalation.

Toets alert delivery deur ’n channel wat onafhanklik van die field node is. Vermy dit om sensitiewe client/device-detail na persoonlike messaging- of consumer-push-accounts te stuur.

## Runbook vir vermoedelike discovery of capture

1. **Stop:** suspend nuwe jobs en operator sessions. Moenie ’n “check if watched”-probe stuur nie.
2. **Quarantine:** laat die broker die device identity en sy routes deny terwyl bestaande logs behou word.
3. **Revoke:** revoke die device certificate/key, queue token, update credential en enige single-purpose service token. Suspend die organisasie-SIM wanneer physical loss plausible is.
4. **Preserve:** snapshot controller-, gateway-, provider- en alert-records; teken trusted time, wie opgetree het en die laaste bekende configuration aan. Moenie die node clear of remote wipe nie.
5. **Notify:** kontak die exercise controller, client incident contact en legal/privacy contacts wat in die authorization gedefinieer is. Indien ’n third party dit gevind het, gebruik die vooraf ooreengekome recovery process.
6. **Assess:** aanvaar dat elke secret en cached result op die node exposed is. Enumerate presies waartoe elke secret toegang kon hê en of dit ná die suspicious event gebruik is.
7. **Contain downstream:** rotate affected service credentials, invalidate pending jobs en inspect owned target/provider logs vir unexpected behavior.
8. **Recover safely:** retrieve slegs deur ’n gemagtigde persoon; photograph/package dit, teken custody aan en acquire forensic evidence soos die client aandui.
9. **Resume with a new identity:** moenie die captured credential stilweg her-enable nie. Rebuild vanaf die known manifest, fix die control failure en verkry eksplisiete approval.

NIST se huidige incident-response guidance integreer preparation, detection, response en recovery in organization-wide cybersecurity risk management; preserve eers sodat die client kan bepaal wat gebeur het en die toepaslike response kan kies.<sup>[[6]](#references)</sup>

## Capture-drill voor deployment

Gee ’n unlocked test unit of ’n kopie van sy storage aan ’n separate reviewer en vra hulle om te enumerate:

1. device/site/engagement-identifiers;
2. operator names, personal accounts, home/workstation networks en recovery contacts;
3. controller/broker-destinations en credentials;
4. client network profiles en cached results;
5. ander devices/projects wat met elke secret bereikbaar is;
6. value- of payment-credentials;
7. wat die controller kan revoke en hoe vinnig;
8. watter activity steeds uit sentrale logs attributable bly.

Pass criteria: zero personal accounts/workstation keys; zero cross-engagement- of enrollment authority; geen payment credential nie; bounded encrypted cache; een documented device-revocation action; volledige controller-side accountability. Behandel enige onverwagte personal link of lateral capability as ’n release blocker.

## Closeout

1. Stop jobs en disable die broker route aan die einde van die scope.
2. Retrieve en reconcile die presiese inventory; report enigiets wat ontbreek.
3. Preserve logs/results en, indien vereis, ’n forensic image volgens die engagement retention plan.
4. Revoke device-, SIM-, queue-, update- en service-identities selfs wanneer die hardware recovered is.
5. Slegs ná preservation/acceptance, sanitize of destroy media met die eienaar se goedgekeurde data-disposal process en record completion. Dit is lifecycle management, nie concealment nie.
6. Remove venue NAC/DHCP reservations, broker routes, DNS, cloud roles, alert rules en temporary contacts.
7. Document observed detection, missed telemetry, time to quarantine en elke artifact wat capture exposed.

## References

- [1] [NIST — Katalogus van IoT-device-cybersecurity-vermoëns](https://pages.nist.gov/IoT-Device-Cybersecurity-Requirement-Catalogs/) and [NIST — Cybersecurity Event Awareness](https://pages.nist.gov/FederalProfile-8259A/technical/event/)
- [2] [SPIFFE — Concepts en kortstondige workload-identiteite](https://spiffe.io/docs/latest/spiffe/concepts/)
- [3] [WireGuard — Quick Start: Persistent Keepalive](https://www.wireguard.com/quickstart/)
- [4] [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [5] [CISA — Gebruik logging op besigheidstelsels](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
- [6] [NIST SP 800-61 Rev. 3 — Aanbevelings en oorwegings vir incident response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
{{#include ../banners/hacktricks-training.md}}
