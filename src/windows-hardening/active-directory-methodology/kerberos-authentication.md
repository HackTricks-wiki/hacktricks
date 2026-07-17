# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte odličan post na:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR za attackere
- Kerberos je podrazumevani AD auth protokol; većina lanaca za lateral-movement će ga dotaći.
- Razmišljajte u **tri operator faze**:
- **AS-REQ / AS-REP** → password/hash/certificate za dobijanje **TGT-a**. Ovde se koriste **AS-REP roasting**, **over-pass-the-hash / pass-the-key** i **PKINIT**.
- **TGS-REQ / TGS-REP** → korišćenje TGT-a za dobijanje **service tickets**. Ovde postaju relevantni **Kerberoasting**, **S4U abuse**, **delegation abuse** i većina **ticket-forging tradecraft** tehnika.
- **AP-REQ / AP-REP** → prosleđivanje ticketa servisu. Ovde se koriste **pass-the-ticket** i lateral-movement specifičan za servis.
- Za praktične cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse itd.) pogledajte:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Koristite ovu stranicu kao indeks za **pregled / „šta se nedavno promenilo“**, a zatim pređite na posebne stranice za [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ili [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Najnovije attack beleške (2024-2026)
- **RC4 hardening je promenio podrazumevane vrednosti, a ne sam Kerberos** – savremeni DC hardening fokusira se na **podrazumevane pretpostavljene tipove enkripcije** za naloge koji izričito ne postavljaju `msDS-SupportedEncryptionTypes`. Nakon rollout-a iz 2026. godine, takvi nalozi na zakrpljenim DC-ovima sve češće podrazumevano koriste **AES-only**, pa slepo oslanjanje na `/rc4` Kerberoast pretpostavke češće ne uspeva. Međutim, service accounts sa eksplicitno omogućenim RC4 i dalje predstavljaju odlične ciljeve za offline-crack.
- **PAC validation enforcement je važan za forged tickets** – hardening PAC potpisa iz 2024. znači da **golden/diamond/sapphire/extraSID-style abuses** zahtevaju realističnije PAC podatke i ispravan signing context. Nezakrpljeni domeni ili domeni ostavljeni u compatibility/audit-style deploymentima ostaju slabiji ciljevi.
- **Kerberos zasnovan na certificate-ima promenio se dva puta**:
- **Strong certificate binding** (KB5014754 timeline) čini nepažljiva certificate-to-account mapiranja manje pouzdanim u potpuno enforced okruženjima.
- **CVE-2025-26647** je dodao još jedan sloj hardeninga oko **altSecID / SKI certificate mappings**. Ako DC-ovi nisu zakrpljeni, i dalje rade u audit režimu ili eksplicitno zaobilaze NTAuth validation, naknadni abuse kroz pass-the-certificate / shadow-credential ostaje praktičniji.
- **Cross-domain / cross-forest delegation abuse je i dalje veoma aktuelan** – Windows podržava moderne cross-realm **S4U2Self/S4U2Proxy** tokove, pa su delegation atributi sa mogućnošću upisivanja u drugom domenu i dalje vredni. Prepreka su obično preciznost alata i detalji trust/policy konfiguracije, a ne podrška protokola.
- **Recursive multi-domain RBCD je operativno važan** – u šumama sa 3 ili više domena, **S4U2Self/S4U2Proxy** može rekurzivno prolaziti kroz trust referrals, a **SPN-less** abuse može zahtevati završni **`S4U2Self+U2U`** hop zajedno sa RC4-dependent obradom ticketa. Pogledajte [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- **Windows Server 2025 je uveo novu Kerberos-adjacent attack surface** kroz dMSA migration logiku. Ako u domenu iz 2025. godine uočite delegirana prava nad OU-ovima ili service-account objektima, proverite posebnu [BadSuccessor stranicu](acl-persistence-abuse/BadSuccessor.md) umesto da to tretirate kao „još jedan gMSA“.

## Brze operator provere u modernim domenima

Pre nego što izaberete Kerberos attack putanju, brzo odgovorite na četiri pitanja:

1. **Koji nalozi su još uvek RC4-friendly?**
2. **Koji korisnici ne zahtevaju pre-auth?**
3. **Koji objekti otkrivaju delegation abuse?**
4. **Koji delovi domena su dovoljno novi da primenjuju najnoviji hardening?**
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
- Ako su **zanimljivi SPN nalozi eksplicitno sposobni za RC4**, Kerberoasting ostaje jeftin i brz.
- Ako većina service naloga nema **eksplicitno podešen etype**, očekujte ponašanje **samo sa AES-om** na ažuriranim DC-ovima iz 2026. godine i planirajte sporije offline cracking napade ili drugi put.
- Ako su prisutni **RBCD / KCD / unconstrained delegation**, S4U često nadmašuje brute-force.
- Ako se koristi **autentifikacija sertifikatima**, imajte na umu da neuspešan PKINIT put **ne znači uvek** da je sertifikat neupotrebljiv; u mnogim okruženjima isti sertifikat i dalje može da se koristi za zloupotrebu **Schannel/LDAPS** (pogledajte [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Uobičajene Kerberos greške koje menjaju plan napada
- **`KDC_ERR_ETYPE_NOTSUPP`** → Ciljni nalog / DC neće koristiti encryption type koji ste zatražili. Prestanite da pokušavate samo sa RC4; prosledite **AES ključeve** ili umesto toga zatražite **AES** roast materijal.
- **`KRB_AP_ERR_MODIFIED`** → Verovatno imate **pogrešan service key**, **pogrešan SPN** ili forged ticket koji se ne podudara sa service nalogom koji ga stvarno dešifruje.
- **`KRB_AP_ERR_SKEW`** → Vreme vam nije usklađeno. Sinhronizujte ga sa DC-om pre nego što počnete da otklanjate bilo koji drugi problem.
- **`KDC_ERR_BADOPTION`** tokom S4U / delegation tokova → često znači **sensitive/not-delegable users**, pogrešan delegation model ili da pokušavate da koristite **classic KCD** tamo gde bi samo **RBCD** prihvatio ne-forwardable S4U2Self ticket.

## Reference
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
