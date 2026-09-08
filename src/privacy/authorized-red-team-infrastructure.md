# Gemagtigde Red-Team-infrastruktuur

{{#include ../banners/hacktricks-training.md}}

Vir duursame toestelle op die terrein, gebruik die ontwerp en runbook vir [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) vir vermoedelike ontdekking.

Vir 'n professionele red team is die doel **beheerde toeskrywing**, nie immuniteit teen aanspreeklikheid nie. Die teiken behoort nie maklik 'n operateur se tuis-IP of persoonlike rekeninge te kan sien nie, terwyl die eienaar van die engagement die bron moet kan identifiseer, die operasie moet kan stop, misbruikverslae moet kan hanteer, bewyse moet kan bewaar en magtiging moet kan bewys.

Hierdie bladsy is die ontplooiingsbasislyn vir 'n wettige engagement. Vir die adversary tradecraft wat dit bedoel is om na te boots—insluitend gekompromitteerde ORBs, residensiële relays, fronting, dead drops en nabygeleë wireless pivots—begin met [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) en [Government and APT Case Studies](government-and-apt-case-studies.md), en reproduseer dan die vereiste telemetrie in die [gemagtigde labs](authorized-adversary-emulation-labs.md).

NIST definieer rules of engagement (ROE) as voorafbepaalde beperkings wat gesag vir gedefinieerde toetsaktiwiteite verleen.<sup>[[1]](#references)</sup> Privaatheidsargitektuur kan nie daardie gesag uitbrei nie.

## Kies 'n egress-patroon

| Patroon | Beste gebruik | Wat die teiken sien | Wat die provider/plaaslike waarnemer sien | Aanspreeklikheid |
|---|---|---|---|---|
| VPN/jump host wat deur die kliënt verskaf word | Die meeste assessments | Kliënt se adresreeks | Kliëntidentiteit en operateurtoegang | Sterkste |
| Bastion van die red-team-organisasie | Herhaalbare beheerde egress | Organisasie se reeks | Hosting provider en organisasie | Sterk |
| Engagement-spesifieke VPS | Isoleer kliënte/campaigns | VPS-adres | Host-rekening, fakturering, control-plane- en toegangslogboeke | Sterk indien gedokumenteer |
| Goedgekeurde kommersiële VPN | Research/scanning wat deur die provider en ROE toegelaat word | Gedeelde/toegewyde VPN-egress | VPN-rekening en bronverbinding | Medium |
| Tor Browser | Webresearch wat destination unlinkability benodig | Tor-exit | Plaaslike netwerk sien Tor/bridge; bestemming sien Tor | Swak geskik vir allowlisted source attribution |
| Kliëntgoedgekeurde on-site drop | Interne simulasie | Toestel/adres op die terrein | Werfnetwerk en remote tunnel provider | Sterk indien geïnventariseer |
| Wettige guest Wi-Fi | Laerisiko-administratiewe/research-gebruik | Venue se publieke IP of tunnel-egress | Venue, ISP, VPN/Tor | Swak en fisies waarneembaar |

Vir die meeste werk is 'n kliëntverskafte of organisasiebeheerde vaste egress veiliger en vinniger as consumer anonymity services. Dit stel verdedigers ook in staat om bekende bronreekse te allowlist, te monitor of doelbewus **nie** te allowlist nie, volgens die oefening se ontwerp.

## ROE-infrastruktuurbylae

Teken die volgende vóór ontplooiing aan:

- regsentiteite wat magtiging verleen en ontvang;
- presiese teikens en uitdruklike uitsluitings;
- begin-/eindtye, tydsone en toegelate tegnieke;
- bron-IP's, autonomous-system/provider-name, domains, redirectors, mail infrastructure en identifiseerders van toestelle op die terrein;
- of phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence of third-party services toegelaat word;
- kliënt- en provider-goedkeurings, insluitend enige pre-notification reference;
- emergency stop phrase, 24/7-kliënt- en provider-abuse-kontakte, en maksimum reaksietyd;
- dataklasse wat ingesamel mag word, encryption, access, retention en deletion;
- vereistes vir bewyse en logging, insluitend wie die mapping van publieke infrastruktuur na operateur hou;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery en finale attestation.

Verifieer dat publieke IP's en domains werklik deur die magtigende party beheer word of uitdruklik binne scope ingesluit is. NIST SP 800-115 beveel aan dat bevestig word dat publieke teikenadresse onder die organisasie se beheer val voordat testing begin.<sup>[[2]](#references)</sup>

## Engagement-spesifieke vinnige egress

### Bou-werkvloei

1. **Skep 'n engagement-rekening/-projek** onder die red-team-organisasie deur akkurate fakturerings- en eienaarskapbesonderhede te gebruik. Hou rolle, API keys, budgets en audit logs apart van ander kliënte.
2. **Gaan elke provider se beleid na.** Cloud-, VPS-, CDN-, domain-, email- en VPN-providers het verskillende reëls. AWS laat byvoorbeeld gespesifiseerde assessments toe, maar vereis voorafgoedkeuring vir hosted C2/covert simulations en verbied gelyste aktiwiteite.<sup>[[3]](#references)</sup>
3. **Ken vaste egress-addresses toe** en plaas dit in die ROE-bylae. Vermy vinnige IP/resource cycling; dit bemoeilik incident response en kan providerbeleid oortree.
4. **Verhard management:** key-only SSH of 'n identity-aware management plane, phishing-resistant MFA, aparte admin-netwerk, least privilege, patched images, geen publieke admin-ports nie, en encrypted secret storage.
5. **Skep 'n full-tunnel-pad** vanaf die operateur-endpoint na die bastion. Roeteer DNS en IPv6 doelbewus en dwing 'n firewall-deny af wanneer die tunnel af is.
6. **Beperk outbound destinations en ports** tot die gemagtigde scope waar dit haalbaar is. Rate-limit scanners en plaas onomkeerbare/destruktiewe tegnieke agter 'n aparte approval gate.
7. **Log vir aanspreeklikheid, nie surveillance nie:** operateur-authentication, configuration changes, start/stop, source address, scoped destination en tool/job identifiers. Vermy payload/credential capture tensy dit deur die oefening vereis word en deur die data plan beskerm word.
8. **Valideer deur 'n beheerde endpoint** wat deur die organisasie besit word: waargenome IPv4/IPv6, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect en provider-abuse-kontak.
9. **Deel die attribution map veilig** met die exercise controller of 'n ooreengekome escrow-kontak. Moenie dit aan die target team publiseer indien blind detection deel van die toets is nie.

### Argitektuur
```text
dedicated operator context
|
fail-closed tunnel
|
engagement bastion / fixed egress ---- management + audit plane
|
scope allowlist / rate limits
|
authorized targets
```
'n VPS is slegs teenoor die bestemming pseudoniem. Die host kan kontak-, faktuur-, identiteit-, bron-IP-, API-, toestel-, ligging- en gebruiksrekords hê; klant-sigbare AWS CloudTrail-geskiedenis alleen kan bestuursaktiwiteit blootlê.<sup>[[4]](#references)</sup> Om vir hosting met cryptocurrency te betaal, vee nie daardie rekords uit nie.

## Domains en sertifikate

- Gebruik 'n engagement-spesifieke registrar-rekening wat deur die organisasie besit word.
- Aktiveer registrar lock, DNSSEC waar dit ondersteun word, MFA/security keys, en auto-renew slegs vir die goedgekeurde tydperk.
- Gebruik registration privacy om openbare blootstelling te verminder, nie om registrant-inligting verkeerd voor te stel nie. ICANN-beleid vereis dat registrars registrasiedata insamel, selfs wanneer openbare vertoning geredigeer of geproxy word.<sup>[[5]](#references)</sup>
- Vermy name wat onverwante partye onwettig naboots. Typosquatting/lookalike domains vereis uitdruklike goedkeuring van die kliënt en provider.
- Inventariseer DNS, sertifikate, CDN/redirector-konfigurasie en derdeparty-analytics wat operators of kliënte kan leak.
- By teardown, verwyder rekords, revoke sertifikate/tokens, bewaar ooreengekome bewyse en besluit of die domain defensief behou moet word.

## Gemagtigde on-site drop nodes

'n Raspberry Pi of soortgelyke appliance is slegs aanvaarbaar wanneer die eiendom-/netwerkeienaar en kliënt die presiese plasing en gedrag daarvan uitdruklik magtig. 'n Veilige plan:

1. Teken die toestel se reeksnommer, MAC/private-MAC-beleid, foto, eienaar, presiese goedgekeurde ligging, kragbron, sperdatum vir terugwinning en kontakpersoon vir peutering aan.
2. Gebruik 'n minimale signed image, encrypted secrets, read-only of herstelbare storage, host firewall, automatic security updates waar prakties, en geen default credentials nie.
3. Konfigureer slegs-uitgaande kommunikasie na 'n benoemde engagement-endpoint. Moenie 'n unauthenticated listener blootstel nie.
4. Allowlist bestemmings en capabilities. Packet capture, credential collection, wireless impersonation en lateral movement moet elk uitdruklik gemagtig word.
5. Gebruik mutual authentication, short-lived keys, remote kill, health reporting en bandwidth limits.
6. Verseker dat verlies/diefstal nie herbruikbare credentials of kliëntdata openbaar nie.
7. Plaas retrieval en secure wipe/decommission op die kalender; verkry 'n getekende recovery record.

Moenie hardware by 'n café, hotel, gedeelde kantoor, buurman se eiendom of openbare venue versteek sonder die eienaar/operator se skriftelike toestemming nie.

## Guest networks en travel routers

Indien 'n gemagtigde scenario guest access vereis:

- verifieer die SSID en acceptable-use policy met die venue/kliënt;
- gebruik 'n organisasie-besitte travel router of low-trust bridge device om die privileged workstation te isoleer;
- voltooi captive portals buite die privileged workstation;
- begin die goedgekeurde tunnel voor assessment-verkeer;
- bevestig dat tethered devices werklik daardie tunnel gebruik;
- aanvaar dat die venue radio association, portal, fisiese teenwoordigheid en kamera-/betalingsrekords kan korreleer;
- moet nooit access control omseil, 'n ander toestel clone, Wi-Fi aanval of toerusting agterlaat nie.

## Operasionele skeiding

- Een kliënt/engagement per endpoint compartment, cloud project, secrets set, domain group, redirector set en evidence store.
- Geen persoonlike e-pos, browser sync, telefoonnommer, cloud drive, SSH/GPG key, code-signing identity of payment reimbursement buite goedgekeurde organisasiestelsels nie.
- Moenie distinctive payload configuration, callback paths, sertifikate of openbare repositories tussen kliënte hergebruik nie, tensy die oefeningsontwerp fingerprinting aanvaar.
- Gee infrastructure 'n kill date en budget alert. Verlate stelsels word 'n risiko vir beide die kliënt en die Internet.
- Bewaar genoeg interne attribution om ongelukke te ondersoek. “No logs” is gewoonlik onversoenbaar met professionele bewys- en veiligheidsverpligtinge.

## Blind vir defenders, attributable to the controller

Wanneer die oefeningsdoelwit is om detection te meet eerder as om 'n allowlist te toets, kan die teiken-SOC blind bly sonder om die operasie onaccountable te maak:

1. Die exercise controller keur elke openbare source, domain, sertifikaat en on-site device goed, maar weerhou die lys van die SOC.
2. Die controller stoor die source-to-engagement/operator-map in 'n afsonderlike encrypted vault met two-person emergency access.
3. Elke operator-job ontvang 'n signed manifest wat scope, time window, source compartment en irreversible job identifier bevat. Die teiken hoef nie die manifest tydens normale werking te sien nie.
4. Bastion audit events word chained of append-only na controller-storage gestuur sodat 'n operator nie attribution ná 'n incident stilweg kan herskryf nie.
5. 'n 24/7 provider-abuse contact hou 'n verification phrase/reference wat authorization bevestig sonder om die kliënt openbaar te maak.
6. Elke path implementeer 'n out-of-band stop channel wat nie van die assessment C2, target network of een operator se account afhanklik is nie.
7. Stuur voor live testing benign canaries vanaf elke source. Bevestig dat die controller dit binne die ROE-response time kan resolve en stop.
8. Vergelyk ná die oefening SOC-telemetry met die controller-ledger, openbaar die source list en verduidelik gemiste/verkeerde detections.

Moenie anti-forensics, log destruction, compromised relays of false subscriber identities byvoeg nie. Dit ondermyn accountable testing eerder as om dit te verbeter.

## Teardown-kontrolelys

- [ ] Exercise controller bevestig stop.
- [ ] C2, tunnels, redirectors, mail, VPN en scheduled jobs is disabled.
- [ ] On-site devices is fisies recovered en reconciled.
- [ ] Tokens, API keys, SSH keys, sertifikate en captured credentials is revoked/rotated.
- [ ] DNS- en cloud-resources word verwyder of vir defensive retention oorgedra.
- [ ] Kliëntdata word volgens die kontrak terugbesorg, behou of vernietig.
- [ ] Vereiste finansiële, audit- en authorization records bly encrypted en access-controlled.
- [ ] Provider-abuse cases is closed en die kliënt ontvang finale source indicators.
- [ ] 'n Tweede operator verifieer dat geen infrastructure aktief oorbly nie.

## References

- [1] [NIST CSRC — Reëls vir Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Tegniese Gids tot Information Security Testing en Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Customer Support Policy for Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Privacy Notice](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Registration Data Policy](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
