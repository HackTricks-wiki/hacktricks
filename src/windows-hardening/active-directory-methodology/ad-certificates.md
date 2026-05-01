# AD Certificates

{{#include ../../banners/hacktricks-training.md}}

## Inleiding

### Komponente van 'n Sertifikaat

- Die **Subject** van die sertifikaat dui die eienaar daarvan aan.
- 'n **Public Key** word gepaar met 'n privaat gehoue sleutel om die sertifikaat aan sy regmatige eienaar te koppel.
- Die **Validity Period**, gedefinieer deur **NotBefore** en **NotAfter** datums, merk die sertifikaat se effektiewe duur.
- 'n Unieke **Serial Number**, verskaf deur die Certificate Authority (CA), identifiseer elke sertifikaat.
- Die **Issuer** verwys na die CA wat die sertifikaat uitgereik het.
- **SubjectAlternativeName** laat addisionele name vir die subject toe, wat identifikasiefleksibiliteit verbeter.
- **Basic Constraints** identifiseer of die sertifikaat vir 'n CA of 'n end entity is en definieer gebruiksbeperkings.
- **Extended Key Usages (EKUs)** dui die sertifikaat se spesifieke doeleindes aan, soos code signing of email encryption, deur Object Identifiers (OIDs).
- Die **Signature Algorithm** spesifiseer die metode vir die ondertekening van die sertifikaat.
- Die **Signature**, geskep met die uitreiker se private sleutel, waarborg die sertifikaat se egtheid.

### Spesiale Oorwegings

- **Subject Alternative Names (SANs)** brei 'n sertifikaat se toepasbaarheid na veelvuldige identiteite uit, wat van kritieke belang is vir servers met veelvuldige domains. Veilige uitreikingsprosesse is noodsaaklik om impersonation-risiko's te vermy deur attackers wat die SAN-spesifikasie manipuleer.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erken CA-sertifikate in 'n AD forest deur aangewese containers, elk met unieke rolle:

- **Certification Authorities** container hou vertroude root CA-sertifikate.
- **Enrolment Services** container gee besonderhede van Enterprise CAs en hul certificate templates.
- **NTAuthCertificates** object sluit CA-sertifikate in wat vir AD-authentication gemagtig is.
- **AIA (Authority Information Access)** container vergemaklik certificate chain validation met intermediate en cross CA-sertifikate.

### Certificate Acquisition: Client Certificate Request Flow

1. Die request-proses begin wanneer clients 'n Enterprise CA vind.
2. 'n CSR word geskep, wat 'n public key en ander besonderhede bevat, nadat 'n public-private key pair gegenereer is.
3. Die CA beoordeel die CSR teen beskikbare certificate templates, en reik die sertifikaat uit op grond van die template se permissions.
4. By goedkeuring onderteken die CA die sertifikaat met sy private key en stuur dit terug na die client.

### Certificate Templates

Hierdie templates, wat binne AD gedefinieer is, skets die settings en permissions vir die uitreiking van sertifikate, insluitend toegelate EKUs en enrollment- of modification-regte, krities vir die bestuur van toegang tot certificate services.

**Template schema version matters.** Legacy **v1** templates (for example, the built-in **WebServer** template) lack several modern enforcement knobs. The **ESC15/EKUwu** research showed that on **v1 templates**, a requester can embed **Application Policies/EKUs** in the CSR that are **preferred over** the template's configured EKUs, enabling client-auth, enrollment agent, or code-signing certificates with only enrollment rights. Prefer **v2/v3 templates**, remove or supersede v1 defaults, and tightly scope EKUs to the intended purpose.

## Certificate Enrollment

The enrollment process for certificates is initiated by an administrator who **creates a certificate template**, which is then **published** by an Enterprise Certificate Authority (CA). This makes the template available for client enrollment, a step achieved by adding the template's name to the `certificatetemplates` field of an Active Directory object.

For a client to request a certificate, **enrollment rights** must be granted. These rights are defined by security descriptors on the certificate template and the Enterprise CA itself. Permissions must be granted in both locations for a request to be successful.

### Template Enrollment Rights

These rights are specified through Access Control Entries (ACEs), detailing permissions like:

- **Certificate-Enrollment** and **Certificate-AutoEnrollment** rights, each associated with specific GUIDs.
- **ExtendedRights**, allowing all extended permissions.
- **FullControl/GenericAll**, providing complete control over the template.

### Enterprise CA Enrollment Rights

The CA's rights are outlined in its security descriptor, accessible via the Certificate Authority management console. Some settings even allow low-privileged users remote access, which could be a security concern.

### Additional Issuance Controls

Certain controls may apply, such as:

- **Manager Approval**: Places requests in a pending state until approved by a certificate manager.
- **Enrolment Agents and Authorized Signatures**: Specify the number of required signatures on a CSR and the necessary Application Policy OIDs.

### Methods to Request Certificates

Certificates can be requested through:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), using DCOM interfaces.
2. **ICertPassage Remote Protocol** (MS-ICPR), through named pipes or TCP/IP.
3. The **certificate enrollment web interface**, with the Certificate Authority Web Enrollment role installed.
4. The **Certificate Enrollment Service** (CES), in conjunction with the Certificate Enrollment Policy (CEP) service.
5. The **Network Device Enrollment Service** (NDES) for network devices, using the Simple Certificate Enrollment Protocol (SCEP).

Windows users can also request certificates via the GUI (`certmgr.msc` or `certlm.msc`) or command-line tools (`certreq.exe` or PowerShell's `Get-Certificate` command).
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Sertifikaat-verifikasie

Active Directory (AD) ondersteun sertifikaat-verifikasie, hoofsaaklik deur **Kerberos** en **Secure Channel (Schannel)** protokolle te gebruik.

### Kerberos-verifikasieproses

In die Kerberos-verifikasieproses word ’n gebruiker se versoek vir ’n Ticket Granting Ticket (TGT) geteken met behulp van die **private key** van die gebruiker se sertifikaat. Hierdie versoek ondergaan verskeie validerings deur die domain controller, insluitend die sertifikaat se **geldigheid**, **pad**, en **intrekkingsstatus**. Validerings sluit ook in die verifiëring dat die sertifikaat van ’n vertroude bron af kom en die bevestiging van die uitreiker se teenwoordigheid in die **NTAUTH certificate store**. Suksesvolle validerings lei tot die uitreiking van ’n TGT. Die **`NTAuthCertificates`** object in AD, gevind by:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
is sentraal tot die vestiging van trust vir certificate authentication.

Sedert die **KB5014754**-uitrol gaan moderne Kerberos certificate auth meestal oor **mapping strength**, nie net EKUs nie. In geharde forests:

- ’n Certificate wat slegs ’n **UPN/DNS SAN** dra, is dalk nie meer genoeg vir logon nie.
- Die KDC verkies ’n **strong binding**, tipies die **SID security extension** (`1.3.6.1.4.1.311.25.2`) of ’n sterk eksplisiete mapping in `altSecurityIdentities`.
- As die cert nie ’n strong mapping het nie, log DCs **Kdcsvc Event ID 39/41** in compatibility mode en weier auth in enforcement mode.
- In gemengde attack paths maak **ESC9/ESC16** saak omdat hulle die SID extension uit uitgereikte certs strip; operators steun dan op eksplisiete mappings of SAN URL SID formate waar die attack path dit ondersteun.

### Secure Channel (Schannel) Authentication

Schannel fasiliteer secure TLS/SSL connections, waar die client tydens ’n handshake ’n certificate aanbied wat, indien suksesvol gevalideer, toegang authoriseer. Die mapping van ’n certificate na ’n AD account kan onder meer Kerberos se **S4U2Self**-funksie of die certificate se **Subject Alternative Name (SAN)** behels.

Schannel is ook die praktiese fallback wanneer **PKINIT** onbeskikbaar is. Byvoorbeeld, as ’n domain controller nie ’n geskikte **Smart Card Logon** certificate het nie, kan `certipy auth`/PKINIT tooling dalk nie ’n TGT kry nie, maar dieselfde certificate kan steeds bruikbaar wees teen **LDAPS** of **LDAP StartTLS** vir authentication en LDAP operations.

### AD Certificate Services Enumeration

AD se certificate services kan via LDAP queries geënumerer word, wat inligting oor **Enterprise Certificate Authorities (CAs)** en hul konfigurasies blootstel. Dit is toeganklik vir enige domain-authenticated user sonder spesiale privileges. Tools soos **[Certify](https://github.com/GhostPack/Certify)** en **[Certipy](https://github.com/ly4k/Certipy)** word gebruik vir enumeration en vulnerability assessment in AD CS-omgewings.

Commands vir die gebruik van hierdie tools sluit in:
```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Onlangse kwesbaarhede & sekuriteitsopdaterings (2022-2025)

| Jaar | ID / Naam | Impak | Sleutel-wegneemtes |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* deur machine account certificates tydens PKINIT te spoof. | Patch is ingesluit in die **10 Mei 2022** sekuriteitsopdaterings. Ouditering & strong-mapping kontroles is via **KB5014754** ingestel; omgewings behoort nou in *Full Enforcement* modus te wees.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in die AD CS Web Enrollment (certsrv) en CES rolle. | Publieke PoCs is beperk, maar die kwesbare IIS-komponente is dikwels intern blootgestel. Patch vanaf **Julie 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Op **v1 templates**, kan ’n requester met enrollment rights **Application Policies/EKUs** in die CSR insluit wat voorkeur kry bo die template EKUs, wat client-auth, enrollment agent, of code-signing certificates produseer. | Gepatch vanaf **12 November 2024**. Vervang of oortref v1 templates (bv. default WebServer), beperk EKUs tot bedoeling, en beperk enrollment rights. |

### Microsoft hardening-tydlyn (KB5014754)

Microsoft het ’n drie-fase uitrol ingestel (Compatibility → Audit → Enforcement) om Kerberos certificate authentication weg te skuif van swak implisiete mappings. Vanaf **11 Februarie 2025**, skakel domain controllers outomaties oor na **Full Enforcement** as die `StrongCertificateBindingEnforcement` registry value nie ingestel is nie. Microsoft het later die tydlyn bygewerk sodat terugval na compatibility mode steeds moontlik bly tot die **9 September 2025** sekuriteitsopdatering. Administrateurs behoort:

1. Alle DCs & AD CS servers te patch (Mei 2022 of later).
2. Event ID 39/41 te monitor vir swak mappings tydens die *Audit* fase.
3. Client-auth certificates met die nuwe **SID extension** weer uit te reik of sterk handmatige mappings te configureer voordat enforcement swak mappings blokkeer.

### Operator-notas vir hardened forests

- **ESC1/ESC6 alleen is nie meer die hele storie** in 2025+ omgewings nie. As jy ’n cert vir ’n ander principal aanvra, benodig jy gewoonlik ook ’n strong mapping artifact soos die SID extension of ’n eksplisiete mapping.
- **ESC15 (EKUwu)** is meestal waardevol in ongepatchte omgewings omdat dit onskadelike **v1** templates soos **WebServer** omskep in authentication- of enrollment-agent-kapabele certs deur **Application Policies** in te spuit. Kerberos PKINIT evalueer steeds EKUs, maar **LDAP Schannel** eer ook Application Policies, wat LDAP-gebaseerde abuse relevant hou.
- **ESC16** is ’n CA-wye knob: as die CA die SID security extension globaal deaktiveer, val elke uitgereikte certificate terug na swakker mapping-gedrag tensy die attack chain ’n SID via ’n ander ondersteunde formaat inspuit.

---

## Detectie & Hardening-versterkings

* **Defender for Identity AD CS sensor (2023-2024)** toon nou posture assessments vir ESC1-ESC8/ESC11 en genereer real-time alerts soos *“Domain-controller certificate issuance for a non-DC”* (ESC8) en *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Verseker sensors word na alle AD CS servers ontplooi om voordeel uit hierdie detecties te trek.
* Deaktiveer of beperk streng die **“Supply in the request”** opsie op alle templates; verkies eksplisiet gedefinieerde SAN/EKU values.
* Verwyder **Any Purpose** of **No EKU** uit templates tensy absoluut vereis word (pak ESC2 scenarios aan).
* Vereis **manager approval** of toegewyde Enrollment Agent workflows vir sensitiewe templates (bv. WebServer / CodeSigning).
* Beperk web enrollment (`certsrv`) en CES/NDES endpoints tot vertroude netwerke of agter client-certificate authentication.
* Handhaaf RPC enrollment encryption (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`) om ESC11 (RPC relay) te verminder. Die flag is **by verstek aan**, maar word dikwels vir legacy clients gedeaktiveer, wat relay risk weer oopmaak.
* Beveilig **IIS-based enrollment endpoints** (CES/Certsrv): deaktiveer NTLM waar moontlik of vereis HTTPS + Extended Protection om ESC8 relays te blokkeer.

---



## Verwysings

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
