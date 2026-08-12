# Kerberos autentifikacija

{{#include ../../banners/hacktricks-training.md}}

Za pregled razmena na nivou protokola sažetih u nastavku pogledajte Tarlogic-ov članak o Kerberos-u.<sup>[[3]](#references)</sup>

## TL;DR za napadače
- Kerberos je podrazumevani AD auth protokol; većina lanaca lateral-movement-a će ga obuhvatiti.
- Razmišljajte u **tri operatorske faze**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → koristite password/hash/certificate da biste dobili **TGT**. Ovde se koriste **AS-REP roasting**, **over-pass-the-hash / pass-the-key** i **PKINIT**.
- **TGS-REQ / TGS-REP** → koristite TGT da biste dobili **service tickets**. Ovde postaju relevantni **Kerberoasting**, **S4U abuse**, **delegation abuse** i većina **ticket-forging tradecraft** tehnika.
- **AP-REQ / AP-REP** → prosledite ticket servisu. Ovde se koriste **pass-the-ticket** i lateral-movement specifičan za servis.
- Za praktične cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse itd.) pogledajte:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Koristite ovu stranicu kao **overview / indeks „šta se nedavno promenilo“**, a zatim pređite na posebne stranice za [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ili [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Sveže napomene o attack tehnikama (2024-2026)
- **RC4 hardening je promenio podrazumevane vrednosti, a ne sam Kerberos** – moderni DC hardening fokusira se na **podrazumevane pretpostavljene tipove enkripcije** za naloge koji eksplicitno ne postavljaju `msDS-SupportedEncryptionTypes`. Nakon uvođenja izmena 2026. godine, ti nalozi na zakrpljenim DC-ovima sve češće podrazumevano koriste **samo AES**, pa slepo oslanjanje na `/rc4` Kerberoast pretpostavke češće ne uspeva. Međutim, service accounts sa eksplicitno omogućenim RC4 i dalje predstavljaju odlične ciljeve za offline-cracking.<sup>[[1]](#references)</sup>
- **PAC validation enforcement je važan za forged tickets** – 2024. hardening PAC potpisa znači da **golden/diamond/sapphire/extraSID-style abuses** zahtevaju realističnije PAC podatke i odgovarajući signing context. Nezakrpljeni domeni ili domeni ostavljeni u compatibility/audit-style deployment-ima ostaju slabiji ciljevi.<sup>[[2]](#references)</sup>
- **Certificate-based Kerberos se promenio dva puta**:
- **Strong certificate binding** (vremenska linija KB5014754) čini neprecizna certificate-to-account mapiranja manje pouzdanim u potpuno enforced okruženjima.
- **CVE-2025-26647** je dodao još jedan sloj hardening-a oko `altSecurityIdentities` mapiranja koja koriste Subject Key Identifier sertifikata. Nivo zakrpa, enforcement ili audit stanje i eksplicitna konfiguracija mapiranja zato su važni pri proceni pass-the-certificate i srodnih certificate-based putanja.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Za PKINIT, KDC takođe validira putanju sertifikata i proverava da li je issuer trusted kroz NTAuth store.<sup>[[8]](#references)</sup>
- **Cross-domain / cross-forest delegation abuse je i dalje veoma aktuelan** – Windows podržava moderne cross-realm **S4U2Self/S4U2Proxy** tokove, pa su delegation attributes u drugom domenu koje je moguće menjati i dalje vredne. Prepreka su obično vernost alata i detalji trust/policy konfiguracije, a ne podrška protokola.
- **Recursive multi-domain RBCD je operativno važan** – u forest-ima sa 3 ili više domena, **S4U2Self/S4U2Proxy** može rekurzivno da prolazi kroz trust referrals, a **SPN-less** abuse može zahtevati završni **`S4U2Self+U2U`** hop i obradu ticket-a koja zavisi od RC4. Pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Windows Server 2025 je uveo delegated Managed Service Accounts (dMSAs)** i njihovu migration logiku. Ako u domenu iz 2025. godine vidite delegated rights nad OU-ovima ili objektima service account-a, pogledajte posebnu [BadSuccessor stranicu](acl-persistence-abuse/BadSuccessor.md) umesto da to tretirate kao „samo još jedan gMSA“.<sup>[[7]](#references)</sup>

## Brze operatorske provere u modernim domenima

Pre izbora Kerberos attack putanje, brzo odgovorite na četiri pitanja:

1. **Koji nalozi su i dalje RC4-friendly?**
2. **Koji korisnici ne zahtevaju pre-auth?**
3. **Koji objekti omogućavaju delegation abuse?**
4. **Koji delovi domena su dovoljno novi da primenjuju noviji hardening?**
```powershell
# 1) Service accounts explicitly pinned to RC4 / legacy etypes
Get-ADObject -LDAPFilter '(|(msDS-SupportedEncryptionTypes=4)(msDS-SupportedEncryptionTypes=12))' \
-Properties samAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes

# 2) Service accounts with no explicit etype config
#    (these increasingly inherit AES-only defaults on patched 2026 DCs)
Get-ADObject -LDAPFilter '(&(servicePrincipalName=*)(!(msDS-SupportedEncryptionTypes=*)))' \
-Properties samAccountName,servicePrincipalName

# 3) AS-REP roastable users
Get-ADUser -LDAPFilter '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
-Properties userAccountControl

# 4) Delegation hot spots
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' \
-Properties msDS-AllowedToActOnBehalfOfOtherIdentity
Get-ADObject -LDAPFilter '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' \
-Properties samAccountName,servicePrincipalName,userAccountControl

# 5) DC-side RC4 hardening / compatibility clues
Get-WinEvent -LogName System | Where-Object {
$_.ProviderName -eq 'Microsoft-Windows-Kerberos-Key-Distribution-Center' -and $_.Id -in 201..209
}
```
Praktično tumačenje:
- Ako su **zanimljivi SPN nalozi eksplicitno RC4-capable**, Kerberoasting ostaje jeftin i brz.
- Ako većina service naloga nema **eksplicitno podešen etype**, očekujte ponašanje **AES-only** na ažuriranim DC-ovima iz 2026. i planirajte sporije offline cracking ili drugačiji pristup.
- Ako su prisutni **RBCD / KCD / unconstrained delegation**, S4U često nadmašuje brute-force.
- Ako se koristi **certificate auth**, imajte na umu da neuspešna PKINIT putanja **ne znači uvek** da je sertifikat beskoristan; u mnogim okruženjima isti sertifikat i dalje radi za **Schannel/LDAPS** abuse (pogledajte [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Uobičajene Kerberos greške koje menjaju plan napada
- **`KDC_ERR_ETYPE_NOTSUPP`** → Ciljni nalog / DC neće koristiti encryption type koji ste zatražili. Prestanite da ponavljate zahtev samo sa RC4; navedite **AES keys** ili umesto toga zatražite **AES** roast material.
- **`KRB_AP_ERR_MODIFIED`** → Verovatno imate **pogrešan service key**, **pogrešan SPN** ili forged ticket koji se ne podudara sa service nalogom koji ga zapravo dešifruje.
- **`KRB_AP_ERR_SKEW`** → Vreme na vašem sistemu nije tačno. Sinhronizujte ga sa DC-om pre nego što otklanjate bilo koji drugi problem.
- **`KDC_ERR_BADOPTION`** tokom S4U / delegation tokova → često znači **sensitive/not-delegable users**, pogrešan delegation model ili da pokušavate **classic KCD** tamo gde bi samo **RBCD** prihvatio non-forwardable S4U2Self ticket.

## References
- [1] [Microsoft Learn - Otkrivanje i otklanjanje upotrebe RC4 u Kerberosu](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Najnovije smernice za Windows hardening i ključni datumi](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Kako Kerberos funkcioniše? – Teorija](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Promene autentikacije zasnovane na sertifikatima u KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 ranjivost mapiranja Kerberos sertifikata](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Pregled Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Zahtevi za smart-card sertifikate i KDC validacija](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
