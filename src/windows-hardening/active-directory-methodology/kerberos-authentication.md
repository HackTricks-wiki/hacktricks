# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Δείτε το εξαιρετικό post από:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR for attackers
- Το Kerberos είναι το προεπιλεγμένο AD auth protocol· οι περισσότερες lateral-movement chains θα το αγγίξουν.
- Σκέψου σε **τρεις operator phases**:
- **AS-REQ / AS-REP** → password/hash/certificate για να αποκτήσεις ένα **TGT**. Εδώ βρίσκονται τα **AS-REP roasting**, **over-pass-the-hash / pass-the-key**, και **PKINIT**.
- **TGS-REQ / TGS-REP** → χρησιμοποίησε ένα TGT για να αποκτήσεις **service tickets**. Εδώ γίνονται σχετικά τα **Kerberoasting**, **S4U abuse**, **delegation abuse**, και το περισσότερο **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → παρουσίασε το ticket στο service. Εδώ συμβαίνουν το **pass-the-ticket** και το service-specific lateral movement.
- Για hands-on cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse, κ.λπ.) δες:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Χρησιμοποίησε αυτή τη σελίδα ως τον **overview / “what changed recently”** index, και μετά πήγαινε στις dedicated pages για [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md), ή [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Fresh attack notes (2024-2026)
- **RC4 hardening changed the defaults, not Kerberos itself** – το σύγχρονο DC hardening εστιάζει στα **default assumed encryption types** για accounts που **δεν** ορίζουν ρητά `msDS-SupportedEncryptionTypes`. Μετά το 2026 rollout, αυτά τα accounts increasingly default σε **AES-only** σε patched DCs, οπότε τα blind `/rc4` Kerberoast assumptions αποτυγχάνουν πιο συχνά. Ωστόσο, τα **explicitly RC4-enabled service accounts remain excellent offline-crack targets**.
- **PAC validation enforcement matters for forged tickets** – το 2024 PAC-signature hardening σημαίνει ότι τα **golden/diamond/sapphire/extraSID-style abuses** χρειάζονται πιο realistic PAC data και το σωστό signing context. Unpatched domains ή domains που έχουν μείνει σε compatibility/audit-style deployments παραμένουν πιο soft targets.
- **Certificate-based Kerberos changed twice**:
- **Strong certificate binding** (KB5014754 timeline) κάνει τα sloppy certificate-to-account mappings λιγότερο reliable σε fully enforced environments.
- **CVE-2025-26647** πρόσθεσε άλλο ένα hardening layer γύρω από **altSecID / SKI certificate mappings**. Αν τα DCs είναι unpatched, still auditing, ή explicitly bypassing NTAuth validation, το pass-the-certificate / shadow-credential follow-on abuse παραμένει πιο practical.
- **Cross-domain / cross-forest delegation abuse is still very alive** – Windows supports modern cross-realm **S4U2Self/S4U2Proxy** flows, οπότε τα writable delegation attributes σε άλλο domain παραμένουν πολύτιμα. Το blocker είναι συνήθως η tooling fidelity και τα trust/policy details, όχι η protocol support.
- **Windows Server 2025 introduced new Kerberos-adjacent attack surface** μέσω του **dMSA** migration logic. Αν δεις delegated rights over OUs ή service-account objects σε ένα 2025 domain, έλεγξε τη dedicated [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) αντί να το αντιμετωπίσεις σαν “just another gMSA”.

## Fast operator checks in modern domains

Πριν επιλέξεις ένα Kerberos attack path, απάντησε γρήγορα σε τέσσερις ερωτήσεις:

1. **Ποιοι accounts είναι ακόμα RC4-friendly;**
2. **Ποιοι users δεν απαιτούν pre-auth;**
3. **Ποια objects expose delegation abuse;**
4. **Ποια μέρη του domain είναι αρκετά νέα ώστε να enforce recent hardening;**
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
Πρακτική ερμηνεία:
- Αν οι **interesting SPN accounts** είναι ρητά RC4-capable, το Kerberoasting παραμένει φθηνό και γρήγορο.
- Αν οι περισσότερες service accounts δεν έχουν **explicit etype configuration**, αναμένετε **AES-only** συμπεριφορά σε updated 2026 DCs και σχεδιάστε για πιο αργό offline cracking ή για διαφορετική προσέγγιση.
- Αν υπάρχει **RBCD / KCD / unconstrained delegation**, το S4U συχνά ξεπερνά το brute-force.
- Αν το **certificate auth** είναι σε χρήση, να θυμάστε ότι ένα αποτυχημένο PKINIT path δεν σημαίνει πάντα ότι το cert είναι άχρηστο· σε πολλά περιβάλλοντα το ίδιο cert εξακολουθεί να λειτουργεί για **Schannel/LDAPS** abuse (δείτε [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Common Kerberos errors that change the attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Το target account / DC δεν θα χρησιμοποιήσει τον encryption type που ζητήσατε. Σταματήστε να ξαναδοκιμάζετε μόνο με RC4· δώστε **AES keys** ή ζητήστε **AES** roast material αντί για αυτό.
- **`KRB_AP_ERR_MODIFIED`** → Πιθανότατα έχετε το **wrong service key**, το **wrong SPN**, ή ένα forged ticket που δεν ταιριάζει με το service account που το decrypts πραγματικά.
- **`KRB_AP_ERR_SKEW`** → Η ώρα σας είναι λάθος. Συγχρονιστείτε με το DC πριν κάνετε debugging οτιδήποτε άλλο.
- **`KDC_ERR_BADOPTION`** κατά τη διάρκεια S4U / delegation flows → συχνά σημαίνει **sensitive/not-delegable users**, το wrong delegation model, ή ότι προσπαθείτε να κάνετε **classic KCD** εκεί όπου μόνο το **RBCD** θα δεχόταν ένα non-forwardable S4U2Self ticket.

## References
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Latest Windows hardening guidance and key dates](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
