# Miundombinu ya Authorized Red-Team

Kwa vifaa vya kudumu vilivyo kwenye eneo, tumia muundo wa [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) na runbook ya suspected-discovery.

Kwa red team ya kitaalamu, lengo ni **attribution inayodhibitiwa**, si kinga dhidi ya uwajibikaji. Lengo halipaswi kuona kwa urahisi IP ya nyumbani ya operator au akaunti binafsi, huku mmiliki wa zoezi akitakiwa kuweza kutambua chanzo, kusimamisha operesheni, kushughulikia ripoti za matumizi mabaya, kuhifadhi ushahidi, na kuthibitisha authorization.

Ukurasa huu ni msingi wa deployment kwa zoezi halali. Kwa adversary tradecraft inayokusudiwa kuigwa—ikiwemo ORBs zilizo-compromise, residential relays, fronting, dead drops na nearby wireless pivots—anza na [Miundombinu ya Offensive na Kuepuka Attribution](offensive-infrastructure-and-attribution-evasion.md) na [Uchunguzi wa Kesi za Serikali na APT](government-and-apt-case-studies.md), kisha tengeneza telemetry inayohitajika katika [authorized labs](authorized-adversary-emulation-labs.md).

NIST inafafanua rules of engagement (ROE) kama masharti yaliyowekwa mapema yanayotoa mamlaka kwa shughuli maalum za testing.<sup>[[1]](#references)</sup> Usanifu wa privacy hauwezi kupanua mamlaka hayo.

## Chagua muundo wa egress

| Muundo | Matumizi bora | Lengo linaona | Provider/observer wa ndani anaona | Uwajibikaji |
|---|---|---|---|---|
| VPN/jump host iliyotolewa na client | Tathmini nyingi | Range ya anwani ya client | Utambulisho wa client na access ya operator | Imara zaidi |
| Bastion ya shirika la red team | Egress inayodhibitiwa na inayoweza kurudiwa | Range ya shirika | Hosting provider na shirika | Imara |
| VPS maalum kwa engagement | Kutenganisha clients/campaigns | Anwani ya VPS | Akaunti ya host, billing, control-plane na access logs | Imara ikiwa imeandikwa |
| VPN ya kibiashara iliyoidhinishwa | Research/scanning inayoruhusiwa na provider na ROE | Egress ya VPN inayoshirikiwa/maalum | Akaunti ya VPN na connection ya chanzo | Wastani |
| Tor Browser | Web research inayohitaji destination unlinkability | Tor exit | Mtandao wa ndani unaona Tor/bridge; destination inaona Tor | Haifai kwa source attribution iliyo kwenye allowlist |
| Drop ya eneo iliyoidhinishwa na client | Internal simulation | Kifaa/anwani ya eneo | Mtandao wa eneo na remote tunnel provider | Imara ikiwa imeorodheshwa |
| Guest Wi-Fi halali | Matumizi ya kiutawala/research yenye hatari ndogo | Public IP ya venue au egress ya tunnel | Venue, ISP, VPN/Tor | Dhaifu na inaonekana kimwili |

Kwa kazi nyingi, egress isiyobadilika inayotolewa na client au kudhibitiwa na shirika ni salama na ya haraka zaidi kuliko anonymity services za watumiaji. Pia huwawezesha defenders kuweka allowlist, kufuatilia, au kwa makusudi **kutoweka allowlist** ya source ranges zinazojulikana kulingana na muundo wa zoezi.

## Kiambatisho cha ROE infrastructure

Rekodi kabla ya deployment:

- entities za kisheria zinazotoa na kupokea authorization;
- targets kamili na exclusions zilizo wazi;
- nyakati za kuanza/kumaliza, time zone, na techniques zinazoruhusiwa;
- source IPs, majina ya autonomous-system/provider, domains, redirectors, mail infrastructure, na vitambulisho vya vifaa vilivyo kwenye eneo;
- ikiwa phishing, C2, credential capture, wireless testing, physical access, denial-of-service, persistence, au third-party services zinaruhusiwa;
- approvals za client na provider, ikiwemo reference yoyote ya pre-notification;
- emergency stop phrase, mawasiliano ya abuse ya client na provider ya saa 24/7, na muda wa juu wa response;
- aina za data zinazoweza kukusanywa, encryption, access, retention, na deletion;
- mahitaji ya ushahidi na logging, ikiwemo nani anayeshikilia mapping kutoka public infrastructure hadi kwa operator;
- teardown, ku-expire kwa domain, certificate revocation, credential rotation, kurejeshwa kwa kifaa, na final attestation.

Thibitisha kwamba public IPs na domains zinadhibitiwa na upande unaotoa authorization au zimejumuishwa wazi kwenye scope. NIST SP 800-115 inapendekeza kuthibitisha kwamba public target addresses ziko chini ya mamlaka ya shirika kabla ya testing.<sup>[[2]](#references)</sup>

## Fast egress maalum kwa engagement

### Workflow ya kujenga

1. **Unda akaunti/project ya engagement** chini ya shirika la red team ukitumia maelezo sahihi ya billing na umiliki. Tenganisha roles, API keys, budgets, na audit logs kutoka kwa clients wengine.
2. **Kagua policy ya kila provider.** Cloud, VPS, CDN, domain, email, na VPN providers wana rules tofauti. AWS, kwa mfano, inaruhusu assessments maalum lakini inahitaji approval ya awali kwa hosted C2/covert simulations na inakataza shughuli zilizoorodheshwa.<sup>[[3]](#references)</sup>
3. **Tenga fixed egress addresses** na uziweke kwenye ROE annex. Epuka kubadilisha IP/resource kwa kasi; hilo hutatiza incident response na linaweza kukiuka policy ya provider.
4. **Imarisha management:** SSH ya key-only au identity-aware management plane, phishing-resistant MFA, mtandao tofauti wa admin, least privilege, images zenye patches, hakuna public admin ports, na encrypted secret storage.
5. **Unda full-tunnel path** kutoka operator endpoint hadi bastion. Elekeza DNS na IPv6 kwa makusudi na utekeleze firewall deny wakati tunnel iko chini.
6. **Zuia outbound destinations na ports** kwa scope iliyoidhinishwa inapowezekana. Weka rate limit kwa scanners na weka techniques zisizoweza kutenduliwa/zinazoharibu nyuma ya approval gate tofauti.
7. **Log kwa ajili ya uwajibikaji, si surveillance:** operator authentication, mabadiliko ya configuration, start/stop, source address, scoped destination, na tool/job identifiers. Epuka payload/credential capture isipokuwa inahitajika na zoezi na inalindwa na data plan.
8. **Validate kupitia controlled endpoint** inayomilikiwa na shirika: IPv4/IPv6 iliyoonekana, DNS path, reverse DNS, clock, source-port behavior, failure/reconnect, na mawasiliano ya abuse ya provider.
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
VPS huwa pseudonymous kwa upande wa destination pekee. Host inaweza kuwa na records za mawasiliano, billing, utambulisho, source-IP, API, kifaa, location, na matumizi; historia ya AWS CloudTrail inayoonekana kwa customer pekee inaweza kufichua shughuli za usimamizi.<sup>[[4]](#references)</sup> Kulipia hosting kwa cryptocurrency hakufuti records hizo.

## Domains na certificates

- Tumia akaunti ya registrar maalum kwa engagement, inayomilikiwa na organization.
- Wezesha registrar lock, DNSSEC pale inapoungwa mkono, MFA/security keys, na auto-renew kwa kipindi kilichoidhinishwa pekee.
- Tumia registration privacy kupunguza exposure ya umma, si kupotosha taarifa za registrant. Sera ya ICANN inawataka registrar kukusanya registration data hata wakati uonyeshaji wa umma umefichwa au kufanywa kupitia proxy.<sup>[[5]](#references)</sup>
- Epuka majina yanayoiga parties zisizohusiana kinyume cha sheria. Typosquatting/lookalike domains zinahitaji idhini ya wazi ya client na provider.
- Tengeneza inventory ya DNS, certificates, CDN/redirector configuration, na third-party analytics ambazo zinaweza kuvuja taarifa kuhusu operators au clients.
- Wakati wa teardown, ondoa records, revoke certificates/tokens, hifadhi evidence iliyokubaliwa, na amua kama domain inapaswa retained defensively.

## Authorized on-site drop nodes

Raspberry Pi au appliance inayofanana inakubalika tu wakati property/network owner na client wameidhinisha wazi mahali pake halisi na tabia yake. Mpango salama:

1. Rekodi serial ya kifaa, MAC/private-MAC policy, picha, owner, location halisi iliyoidhinishwa, power source, deadline ya retrieval, na tamper contact.
2. Tumia image ndogo iliyosainiwa, secrets zilizosimbwa, storage ya read-only au inayoweza kurecoveriwa, host firewall, automatic security updates inapowezekana, na bila default credentials.
3. Sanidi mawasiliano ya outbound-only kwenda kwa engagement endpoint iliyotajwa. Usifichue listener isiyo na authentication.
4. Weka allowlist ya destinations na capabilities. Packet capture, credential collection, wireless impersonation, na lateral movement lazima kila moja iidhinishwe wazi.
5. Tumia mutual authentication, keys za muda mfupi, remote kill, health reporting, na bandwidth limits.
6. Hakikisha kupotea au kuibiwa hakufichui credentials zinazoweza kutumika tena au client data.
7. Weka retrieval na secure wipe/decommission kwenye calendar; pata recovery record iliyosainiwa.

Usifiche hardware kwenye café, hotel, shared office, property ya jirani, au public venue bila ruhusa ya maandishi kutoka kwa owner/operator.

## Guest networks na travel routers

Ikiwa scenario iliyoidhinishwa inahitaji guest access:

- thibitisha SSID na acceptable-use policy na venue/client;
- tumia travel router inayomilikiwa na organization au low-trust bridge device ili kutenganisha privileged workstation;
- kamilisha captive portals nje ya privileged workstation;
- anzisha approved tunnel kabla ya assessment traffic;
- thibitisha kuwa tethered devices zinatumia tunnel hiyo;
- chukulia kuwa venue inaweza kuhusianisha radio association, portal, uwepo wa kimwili, na records za camera/payment;
- usiwahi kubypass access control, kuclone kifaa kingine, kushambulia Wi-Fi, au kuacha equipment nyuma.

## Operational separation

- Client/engagement moja kwa kila endpoint compartment, cloud project, secrets set, domain group, redirector set, na evidence store.
- Hakuna personal email, browser sync, phone number, cloud drive, SSH/GPG key, code-signing identity, au payment reimbursement nje ya approved organization systems.
- Usitumie tena distinctive payload configuration, callback paths, certificates, au public repositories kwa clients tofauti isipokuwa exercise design ikubali fingerprinting.
- Weka kill date na budget alert kwa infrastructure. Orphaned systems huwa risk kwa client na Internet.
- Hifadhi internal attribution ya kutosha kuchunguza accidents. “No logs” kwa kawaida haiendani na evidence ya kitaalamu na wajibu wa safety.

## Blind to defenders, attributable to the controller

Wakati objective ya exercise ni kupima detection badala ya kujaribu allowlist, target SOC inaweza kubaki blind bila kufanya operation isiwe accountable:

1. Exercise controller huidhinisha kila public source, domain, certificate na on-site device lakini huficha list hiyo kutoka kwa SOC.
2. Controller huhifadhi source-to-engagement/operator map kwenye encrypted vault tofauti yenye emergency access ya watu wawili.
3. Kila operator job hupokea manifest iliyosainiwa yenye scope, time window, source compartment na irreversible job identifier. Target haihitaji kuona manifest wakati wa operation ya kawaida.
4. Bastion audit events huunganishwa au kutumwa append-only kwenye controller storage ili operator asiweze kubadilisha attribution kwa siri baada ya incident.
5. Provider-abuse contact wa 24/7 huhifadhi verification phrase/reference inayothibitisha authorization bila kumtaja client hadharani.
6. Kila path hutekeleza out-of-band stop channel ambayo haitegemei assessment C2, target network, au account ya operator mmoja.
7. Kabla ya live testing, tuma benign canaries kutoka kwa kila source. Thibitisha kuwa controller anaweza kuzitambua na kuzisimamisha ndani ya ROE response time.
8. Baada ya exercise, linganisha SOC telemetry na controller ledger, disclose source list, na eleza detections zilizokosekana au zisizo sahihi.

Usiongeze anti-forensics, log destruction, compromised relays au false subscriber identities. Hivyo vinaharibu accountable testing badala ya kuiboresha.

## Teardown checklist

- [ ] Exercise controller anathibitisha stop.
- [ ] C2, tunnels, redirectors, mail, VPN, na scheduled jobs zimezimwa.
- [ ] On-site devices zimerecoveriwa kimwili na kuthibitishwa dhidi ya records.
- [ ] Tokens, API keys, SSH keys, certificates, na captured credentials zime-revoke/rotate.
- [ ] DNS na cloud resources zimeondolewa au kuhamishwa kwa defensive retention.
- [ ] Client data imerudishwa, retained, au kuharibiwa kulingana na mkataba.
- [ ] Financial, audit, na authorization records zinazohitajika zinaendelea kuwa encrypted na access-controlled.
- [ ] Provider abuse cases zimefungwa na client amepokea source indicators za mwisho.
- [ ] Operator wa pili anathibitisha kuwa hakuna infrastructure iliyosalia ikiwa active.

## References

- [1] [NIST CSRC — Kanuni za Rules of Engagement](https://csrc.nist.gov/glossary/term/Rules_of_Engagement)
- [2] [NIST SP 800-115 — Mwongozo wa Kiufundi wa Testing na Assessment ya Information Security](https://csrc.nist.gov/pubs/sp/800/115/final)
- [3] [AWS — Sera ya Customer Support kwa Penetration Testing](https://aws.amazon.com/security/penetration-testing/)
- [4] [AWS — Ilani ya Faragha](https://aws.amazon.com/privacy/) and [CloudTrail Event History](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [5] [ICANN — Sera ya Registration Data](https://www.icann.org/en/contracted-parties/consensus-policies/registration-data-policy)
