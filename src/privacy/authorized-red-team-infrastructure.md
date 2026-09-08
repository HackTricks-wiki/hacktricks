# Miundombinu ya Red-Team Iliyoidhinishwa

{{#include ../banners/hacktricks-training.md}}

Kwa vifaa vya kudumu vilivyowekwa kwenye eneo, tumia muundo wa [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) na runbook ya suspected-discovery.

Kwa red team ya kitaalamu, lengo ni **attribution inayodhibitiwa**, si kinga dhidi ya uwajibikaji. Target haipaswi kuona kwa urahisi IP ya nyumbani ya operator au akaunti binafsi, huku mwenye engagement akipaswa kuweza kutambua chanzo, kusimamisha operesheni, kushughulikia ripoti za matumizi mabaya, kuhifadhi ushahidi, na kuthibitisha authorization.

Ukurasa huu ni msingi wa deployment kwa engagement halali. Kwa adversary tradecraft inayokusudiwa kuigwa—ikiwemo ORBs zilizo-compromise, residential relays, fronting, dead drops na nearby wireless pivots—anza na [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) na [Government and APT Case Studies](government-and-apt-case-studies.md), kisha tengeneza telemetry inayohitajika katika [authorized labs](authorized-adversary-emulation-labs.md).

NIST inafafanua rules of engagement (ROE) kama vikwazo vilivyowekwa awali vinavyotoa authority kwa shughuli maalum za testing.<sup>[[1]](#references)</sup> Privacy architecture haiwezi kupanua authority hiyo.

## Chagua muundo wa egress

| Muundo | Matumizi bora | Target inaona | Provider/observer wa ndani anaona | Uwajibikaji |
|---|---|---|---|---|
| Client-provided VPN/jump host | Assessments nyingi | Client address range | Utambulisho wa client na access ya operator | Imara zaidi |
| Bastion ya red-team organization | Egress inayodhibitiwa na inayoweza kurudiwa | Organization range | Hosting provider na organization | Imara |
| VPS maalum ya engagement | Kutenganisha clients/campaigns | VPS address | Akaunti ya host, billing, control-plane na access logs | Imara ikiwa imeandikwa |
| Approved commercial VPN | Research/scanning inayoruhusiwa na provider na ROE | Shared/dedicated VPN egress | VPN account na source connection | Wastani |
| Tor Browser | Web research inayohitaji destination unlinkability | Tor exit | Local network inaona Tor/bridge; destination inaona Tor | Haifai kwa source attribution inayotumia allowlist |
| Client-approved on-site drop | Internal simulation | Kifaa/address ya eneo | Site network na remote tunnel provider | Imara ikiwa imeorodheshwa |
| Lawful guest Wi-Fi | Matumizi ya kiutawala/research yenye hatari ndogo | Venue public IP au tunnel egress | Venue, ISP, VPN/Tor | Dhaifu na inaonekana kimwili |

Kwa kazi nyingi, fixed egress inayotolewa na client au inayodhibitiwa na organization ni salama na ya haraka zaidi kuliko consumer anonymity services. Pia inawawezesha defenders kuweka allowlist, kufuatilia, au kwa makusudi **kutoweka kwenye allowlist** source ranges zinazojulikana kulingana na muundo wa exercise.

## ROE infrastructure annex

Rekodi kabla ya deployment:

- legal entities zinazotoa na kupokea authorization;
- targets kamili na exclusions zilizo wazi;
- muda wa kuanza/kumaliza, time zone, na techniques zinazoruhusiwa;
- source IPs, majina ya autonomous-system/provider, domains, redirectors, mail infrastructure, na vitambulisho vya vifaa vya eneo;
- ikiwa phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence, au third-party services zinaruhusiwa;
- approvals za client na provider, ikiwemo reference yoyote ya pre-notification;
- emergency stop phrase, contacts za abuse za client na provider za saa 24/7, na muda wa juu wa response;
- data classes zinazoweza kukusanywa, encryption, access, retention, na deletion;
- mahitaji ya ushahidi na logging, ikiwemo anayeshikilia mapping kutoka public infrastructure hadi kwa operator;
- teardown, domain expiration, certificate revocation, credential rotation, device recovery, na final attestation.

Thibitisha kuwa public IPs na domains zinadhibitiwa kwa kweli na upande unaotoa authorization au zimejumuishwa wazi kwenye scope. NIST SP 800-115 inapendekeza kuthibitisha kuwa public target addresses ziko chini ya usimamizi wa organization kabla ya testing.<sup>[[2]](#references)</sup>

## Engagement-specific fast egress

### Build workflow

1. **Tengeneza engagement account/project** chini ya red-team organization kwa kutumia taarifa sahihi za billing na ownership. Tenganisha roles, API keys, budgets, na audit logs na za clients wengine.
2. **Kagua kila provider policy.** Cloud, VPS, CDN, domain, email, na VPN providers zina rules tofauti. AWS, kwa mfano, inaruhusu assessments zilizobainishwa lakini inahitaji approval ya awali kwa hosted C2/covert simulations na inakataza shughuli zilizoorodheshwa.<sup>[[3]](#references)</sup>
3. **Tenga fixed egress addresses** na uziweke kwenye ROE annex. Epuka kubadilisha IP/resource kwa kasi; jambo hili hutatiza incident response na linaweza kukiuka provider policy.
4. **Imarisha management:** SSH ya key-only au identity-aware management plane, phishing-resistant MFA, separate admin network, least privilege, patched images, hakuna public admin ports, na encrypted secret storage.
5. **Tengeneza full-tunnel path** kutoka operator endpoint hadi bastion. Elekeza DNS na IPv6 kwa makusudi na utekeleze firewall deny tunnel inapokuwa chini.
6. **Punguza outbound destinations na ports** ziwe ndani ya authorized scope inapowezekana. Weka rate limit kwa scanners na weka techniques zisizoweza kubatilishwa/destructive nyuma ya separate approval gate.
7. **Log kwa ajili ya accountability, si surveillance:** operator authentication, configuration changes, start/stop, source address, scoped destination, na tool/job identifiers. Epuka payload/credential capture isipokuwa inahitajika na exercise na inalindwa na data plan.
8. **Thibitisha kupitia controlled endpoint** inayomilikiwa na organization: IPv4/IPv6 iliyotazamwa, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect, na provider abuse contact.
9. **Shiriki attribution map kwa usalama** na exercise controller au escrow contact iliyokubaliwa. Usiichapishe kwa target team ikiwa blind detection ni sehemu ya test.

### Architecture
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
VPS ni pseudonymous tu kwa destination. Host inaweza kuwa na rekodi za mawasiliano, malipo, utambulisho, source-IP, API, kifaa, eneo na matumizi; historia ya AWS CloudTrail inayoonekana kwa mteja pekee inaweza kufichua shughuli za usimamizi.<sup>[[4]](#references)</sup> Kulipia hosting kwa cryptocurrency hakufuti rekodi hizo.

## Domains na certificates

- Tumia akaunti ya registrar maalum kwa engagement inayomilikiwa na shirika.
- Washa registrar lock, DNSSEC inapoungwa mkono, MFA/security keys, na auto-renew kwa kipindi kilichoidhinishwa pekee.
- Tumia registration privacy kupunguza ufichuzi wa umma, si kupotosha taarifa za registrant. Sera ya ICANN inahitaji registrars kukusanya registration data hata wakati uonyeshaji wa umma umefichwa au ume-proxy.<sup>[[5]](#references)</sup>
- Epuka majina yanayoiga parties zisizohusiana kinyume cha sheria. Typosquatting/lookalike domains zinahitaji idhini ya wazi kutoka kwa mteja na provider.
- Tengeneza inventory ya DNS, certificates, usanidi wa CDN/redirector, na third-party analytics zinazoweza ku-leak operators au clients.
- Wakati wa teardown, ondoa records, revoke certificates/tokens, hifadhi ushahidi uliokubaliwa, na amua kama domain inapaswa kuhifadhiwa kwa madhumuni ya ulinzi.

## Authorized on-site drop nodes

Raspberry Pi au appliance inayofanana inakubalika tu wakati owner wa property/network na mteja wameidhinisha wazi mahali hasa pa kuwekwa na tabia yake. Mpango salama:

1. Rekodi serial ya kifaa, MAC/private-MAC policy, picha, owner, eneo kamili lililoidhinishwa, chanzo cha umeme, deadline ya kukiretrieve, na contact wa tamper.
2. Tumia image ndogo iliyosainiwa, secrets zilizotiwa encryption, storage ya read-only au inayoweza kurecoveriwa, host firewall, automatic security updates inapowezekana, na usitumie default credentials.
3. Sanidi mawasiliano ya outbound-only kwenda kwa engagement endpoint iliyotajwa kwa jina. Usifichue listener isiyo na authentication.
4. Ruhusu destinations na capabilities zilizo kwenye allowlist. Packet capture, credential collection, wireless impersonation, na lateral movement lazima kila moja iidhinishwe wazi.
5. Tumia mutual authentication, short-lived keys, remote kill, health reporting, na bandwidth limits.
6. Hakikisha kupotea au kuibiwa hakutafichui credentials zinazoweza kutumika tena au data ya mteja.
7. Weka retrieval na secure wipe/decommission kwenye kalenda; pata recovery record iliyosainiwa.

Usifiche hardware kwenye café, hotel, shared office, property ya jirani, au public venue bila ruhusa ya maandishi kutoka kwa owner/operator.

## Guest networks na travel routers

Ikiwa scenario iliyoidhinishwa inahitaji guest access:

- thibitisha SSID na acceptable-use policy pamoja na venue/client;
- tumia travel router inayomilikiwa na shirika au low-trust bridge device kutenga privileged workstation;
- kamilisha captive portals nje ya privileged workstation;
- anzisha approved tunnel kabla ya assessment traffic;
- thibitisha kuwa tethered devices zinatumia tunnel hiyo;
- chukulia kuwa venue inaweza kuhusisha radio association, portal, uwepo wa kimwili, na rekodi za kamera/malipo;
- kamwe usipite access control, usiclone kifaa kingine, usishambulie Wi-Fi, wala kuacha vifaa nyuma.

## Operational separation

- Client/engagement moja kwa kila endpoint compartment, cloud project, secrets set, domain group, redirector set, na evidence store.
- Usitumie personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity, au payment reimbursement nje ya approved organization systems.
- Usitumie tena distinctive payload configuration, callback paths, certificates, au public repositories kati ya clients isipokuwa exercise design ikubali fingerprinting.
- Weka kill date na budget alert kwa infrastructure. Systems zilizoachwa bila owner huwa risk kwa client na Internet.
- Hifadhi attribution ya ndani ya kutosha kuchunguza ajali. “No logs” kwa kawaida haiendani na ushahidi wa kitaalamu na wajibu wa usalama.

## Blind to defenders, attributable to the controller

Wakati objective ya exercise ni kupima detection badala ya kujaribu allowlist, target SOC inaweza kubaki blind bila kufanya operation isiwe accountable:

1. Exercise controller huidhinisha kila public source, domain, certificate na on-site device, lakini huficha orodha hiyo kutoka kwa SOC.
2. Controller huhifadhi ramani ya source-to-engagement/operator katika encrypted vault tofauti yenye two-person emergency access.
3. Kila operator job hupokea manifest iliyosainiwa yenye scope, time window, source compartment na irreversible job identifier. Target haihitaji kuona manifest wakati wa operation ya kawaida.
4. Bastion audit events huunganishwa au kutumwa append-only kwenye controller storage ili operator asiweze kubadilisha attribution kwa siri baada ya incident.
5. Provider-abuse contact wa 24/7 huhifadhi verification phrase/reference inayothibitisha authorization bila kumtaja mteja hadharani.
6. Kila path hutekeleza out-of-band stop channel isiyotegemea assessment C2, target network, au akaunti ya operator mmoja.
7. Kabla ya live testing, tuma benign canaries kutoka kwa kila source. Thibitisha kuwa controller inaweza kuzitatua na kuzisimamisha ndani ya ROE response time.
8. Baada ya exercise, linganisha SOC telemetry na controller ledger, disclose source list, na eleza detections zilizokosekana au zisizo sahihi.

Usiongeze anti-forensics, log destruction, compromised relays au false subscriber identities. Hivi huharibu accountable testing badala ya kukiboresha.

## Teardown checklist

- [ ] Exercise controller athibitisha stop.
- [ ] C2, tunnels, redirectors, mail, VPN, na scheduled jobs zimezimwa.
- [ ] On-site devices zimepatikana kimwili na kuthibitishwa.
- [ ] Tokens, API keys, SSH keys, certificates, na captured credentials zime-revoke/rotate.
- [ ] DNS na cloud resources zimeondolewa au kuhamishwa kwa defensive retention.
- [ ] Data ya mteja imerudishwa, imehifadhiwa, au imeharibiwa kulingana na mkataba.
- [ ] Financial, audit, na authorization records zinazohitajika zimesalia zikiwa encrypted na access-controlled.
- [ ] Provider abuse cases zimefungwa na mteja amepokea source indicators za mwisho.
- [ ] Operator wa pili amethibitisha kuwa hakuna infrastructure iliyosalia ikiwa active.

## References

- [1] [NIST CSRC — Kanuni za Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Mwongozo wa Kiufundi wa Upimaji na Tathmini ya Usalama wa Taarifa](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Sera ya Customer Support kwa Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Notisi ya Faragha](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Sera ya Registration Data](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
{{#include ../banners/hacktricks-training.md}}
