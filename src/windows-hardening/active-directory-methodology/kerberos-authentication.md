# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Δείτε το εξαιρετικό post από:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)

## TL;DR για attackers
- Το Kerberos είναι το προεπιλεγμένο πρωτόκολλο AD auth· οι περισσότερες αλυσίδες lateral movement θα το αγγίξουν.
- Σκεφτείτε το σε **τρεις φάσεις για operators**:
- **AS-REQ / AS-REP** → password/hash/certificate για την απόκτηση ενός **TGT**. Εδώ εντάσσονται τα **AS-REP roasting**, **over-pass-the-hash / pass-the-key** και **PKINIT**.
- **TGS-REQ / TGS-REP** → χρήση ενός TGT για την απόκτηση **service tickets**. Εδώ εντάσσονται τα **Kerberoasting**, **S4U abuse**, **delegation abuse** και το μεγαλύτερο μέρος του **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → παρουσίαση του ticket στην υπηρεσία. Εδώ πραγματοποιούνται τα **pass-the-ticket** και το service-specific lateral movement.
- Για πρακτικά cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse κ.λπ.) δείτε:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Χρησιμοποιήστε αυτή τη σελίδα ως ευρετήριο **επισκόπησης / “τι άλλαξε πρόσφατα”** και, στη συνέχεια, μεταβείτε στις ειδικές σελίδες για [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ή [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Πρόσφατες σημειώσεις για attacks (2024-2026)
- **Το RC4 hardening άλλαξε τα defaults, όχι το ίδιο το Kerberos** – το σύγχρονο DC hardening εστιάζει στους **default assumed encryption types** για accounts που **δεν** ορίζουν ρητά το `msDS-SupportedEncryptionTypes`. Μετά το rollout του 2026, αυτά τα accounts χρησιμοποιούν όλο και περισσότερο **AES-only** σε patched DCs, επομένως οι τυφλές υποθέσεις για `/rc4` Kerberoast αποτυγχάνουν συχνότερα. Ωστόσο, τα **explicitly RC4-enabled service accounts παραμένουν εξαιρετικοί στόχοι για offline cracking**.
- **Η επιβολή του PAC validation είναι σημαντική για forged tickets** – το PAC-signature hardening του 2024 σημαίνει ότι τα **golden/diamond/sapphire/extraSID-style abuses** χρειάζονται πιο ρεαλιστικά PAC data και το σωστό signing context. Τα unpatched domains ή τα domains που παραμένουν σε compatibility/audit-style deployments είναι πιο ευάλωτοι στόχοι.
- **Το certificate-based Kerberos άλλαξε δύο φορές**:
- Το **Strong certificate binding** (χρονοδιάγραμμα KB5014754) καθιστά τα πρόχειρα certificate-to-account mappings λιγότερο αξιόπιστα σε πλήρως enforced environments.
- Το **CVE-2025-26647** πρόσθεσε ένα ακόμη επίπεδο hardening γύρω από τα **altSecID / SKI certificate mappings**. Αν τα DCs είναι unpatched, εξακολουθούν να κάνουν auditing ή παρακάμπτουν ρητά το NTAuth validation, το pass-the-certificate / shadow-credential follow-on abuse παραμένει πιο πρακτικό.
- **Το Cross-domain / cross-forest delegation abuse παραμένει πολύ ενεργό** – τα Windows υποστηρίζουν σύγχρονες ροές cross-realm **S4U2Self/S4U2Proxy**, επομένως τα writable delegation attributes σε άλλο domain παραμένουν πολύτιμα. Το εμπόδιο είναι συνήθως η ακρίβεια των tools και οι λεπτομέρειες trust/policy, όχι η υποστήριξη του πρωτοκόλλου.
- **Το Recursive multi-domain RBCD έχει επιχειρησιακή σημασία** – σε forests με 3+ domains, τα **S4U2Self/S4U2Proxy** μπορούν να κάνουν recursion μέσω trust referrals και το **SPN-less** abuse μπορεί να απαιτεί ένα τελικό **`S4U2Self+U2U`** hop μαζί με RC4-dependent ticket handling. Δείτε το [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).
- Το **Windows Server 2025 εισήγαγε νέα Kerberos-adjacent attack surface** μέσω της λογικής migration του **dMSA**. Αν δείτε delegated rights σε OUs ή service-account objects σε domain του 2025, ελέγξτε την ειδική [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md), αντί να το αντιμετωπίσετε ως “άλλο ένα gMSA”.

## Γρήγοροι έλεγχοι για operators σε σύγχρονα domains

Πριν επιλέξετε μια διαδρομή Kerberos attack, απαντήστε γρήγορα σε τέσσερις ερωτήσεις:

1. **Ποια accounts εξακολουθούν να είναι RC4-friendly;**
2. **Ποιοι users δεν απαιτούν pre-auth;**
3. **Ποια objects εκθέτουν delegation abuse;**
4. **Ποια τμήματα του domain είναι αρκετά νέα ώστε να επιβάλλουν το πρόσφατο hardening;**
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
- Αν οι **ενδιαφέροντες λογαριασμοί SPN υποστηρίζουν ρητά RC4**, το Kerberoasting παραμένει οικονομικό και γρήγορο.
- Αν οι περισσότεροι service accounts **δεν έχουν ρητή ρύθμιση etype**, περιμένετε συμπεριφορά **μόνο AES** σε ενημερωμένους DC του 2026 και προγραμματίστε πιο αργό offline cracking ή διαφορετική διαδρομή.
- Αν υπάρχει **RBCD / KCD / unconstrained delegation**, το S4U συχνά υπερτερεί του brute-force.
- Αν χρησιμοποιείται **certificate auth**, θυμηθείτε ότι μια αποτυχημένη διαδρομή PKINIT **δεν σημαίνει πάντα** ότι το cert είναι άχρηστο· σε πολλά περιβάλλοντα το ίδιο cert εξακολουθεί να λειτουργεί για abuse μέσω **Schannel/LDAPS** (δείτε [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Συνηθισμένα σφάλματα Kerberos που αλλάζουν το attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Ο target account / DC δεν θα χρησιμοποιήσει τον τύπο κρυπτογράφησης που ζητήσατε. Σταματήστε να επαναλαμβάνετε το αίτημα μόνο με RC4· δώστε **AES keys** ή ζητήστε υλικό roast με **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Πιθανότατα έχετε το **λάθος service key**, το **λάθος SPN** ή ένα forged ticket που δεν αντιστοιχεί στο service account που το αποκρυπτογραφεί στην πραγματικότητα.
- **`KRB_AP_ERR_SKEW`** → Η ώρα σας είναι λανθασμένη. Κάντε συγχρονισμό με τον DC πριν κάνετε οτιδήποτε άλλο για debugging.
- **`KDC_ERR_BADOPTION`** κατά τη διάρκεια ροών S4U / delegation → συχνά σημαίνει **sensitive/not-delegable users**, λάθος μοντέλο delegation ή ότι προσπαθείτε να χρησιμοποιήσετε **classic KCD**, ενώ μόνο το **RBCD** θα αποδεχόταν ένα non-forwardable S4U2Self ticket.

## Αναφορές
- [Microsoft Learn - Εντοπισμός και αποκατάσταση χρήσης RC4 στο Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Support - Τελευταίες οδηγίες hardening των Windows και βασικές ημερομηνίες](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
{{#include ../../banners/hacktricks-training.md}}
