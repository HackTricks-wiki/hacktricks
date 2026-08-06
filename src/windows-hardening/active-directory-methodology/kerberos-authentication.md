# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

**Δείτε το εξαιρετικό post από:** [**https://www.tarlogic.com/en/blog/how-kerberos-works/**](https://www.tarlogic.com/en/blog/how-kerberos-works/)<sup>[[3]](#references)</sup>

## TL;DR για attackers
- Το Kerberos είναι το προεπιλεγμένο πρωτόκολλο auth του AD· οι περισσότερες αλυσίδες lateral movement θα αλληλεπιδράσουν μαζί του.
- Σκεφτείτε το σε **τρεις φάσεις operator**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → χρησιμοποιήστε password/hash/certificate για να αποκτήσετε ένα **TGT**. Εδώ ανήκουν τα **AS-REP roasting**, **over-pass-the-hash / pass-the-key** και **PKINIT**.
- **TGS-REQ / TGS-REP** → χρησιμοποιήστε ένα TGT για να αποκτήσετε **service tickets**. Εδώ είναι σχετικά τα **Kerberoasting**, **S4U abuse**, **delegation abuse** και το μεγαλύτερο μέρος του **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → παρουσιάστε το ticket στην υπηρεσία. Εδώ πραγματοποιούνται τα **pass-the-ticket** και το service-specific lateral movement.
- Για πρακτικά cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse κ.λπ.) δείτε:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Χρησιμοποιήστε αυτή τη σελίδα ως ευρετήριο **overview / «τι άλλαξε πρόσφατα»** και, στη συνέχεια, μεταβείτε στις dedicated σελίδες για [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ή [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Νέες σημειώσεις για attacks (2024-2026)
- **Το RC4 hardening άλλαξε τα defaults, όχι το ίδιο το Kerberos** – το σύγχρονο DC hardening εστιάζει στους **default assumed encryption types** για accounts που **δεν** ορίζουν ρητά το `msDS-SupportedEncryptionTypes`. Μετά το rollout του 2026, αυτά τα accounts χρησιμοποιούν όλο και περισσότερο **AES-only** ως default σε patched DCs, επομένως οι τυφλές υποθέσεις για `/rc4` στο Kerberoast αποτυγχάνουν συχνότερα. Ωστόσο, τα service accounts με **ρητά ενεργοποιημένο RC4** παραμένουν εξαιρετικοί στόχοι για offline cracking.<sup>[[1]](#references)</sup>
- **Η επιβολή του PAC validation έχει σημασία για τα forged tickets** – το PAC-signature hardening του 2024 σημαίνει ότι τα **golden/diamond/sapphire/extraSID-style abuses** χρειάζονται πιο ρεαλιστικά PAC data και το σωστό signing context. Τα unpatched domains ή τα domains που παραμένουν σε deployments τύπου compatibility/audit είναι πιο ευάλωτοι στόχοι.<sup>[[2]](#references)</sup>
- **Το certificate-based Kerberos άλλαξε δύο φορές**:<sup>[[2]](#references)</sup>
- Το **Strong certificate binding** (χρονοδιάγραμμα KB5014754) καθιστά τα πρόχειρα certificate-to-account mappings λιγότερο αξιόπιστα σε fully enforced environments.
- Το **CVE-2025-26647** πρόσθεσε ένα ακόμη επίπεδο hardening γύρω από τα **altSecID / SKI certificate mappings**. Αν οι DCs είναι unpatched, εξακολουθούν να κάνουν auditing ή παρακάμπτουν ρητά το NTAuth validation, το pass-the-certificate / shadow-credential follow-on abuse παραμένει πιο πρακτικό.
- Το **Cross-domain / cross-forest delegation abuse παραμένει απολύτως ενεργό** – τα Windows υποστηρίζουν σύγχρονες ροές cross-realm **S4U2Self/S4U2Proxy**, επομένως τα writable delegation attributes σε άλλο domain παραμένουν πολύτιμα. Το εμπόδιο είναι συνήθως η ακρίβεια των tools και οι λεπτομέρειες των trusts/policies, όχι η υποστήριξη του protocol.
- Το **Recursive multi-domain RBCD έχει επιχειρησιακή σημασία** – σε forests με 3+ domains, τα **S4U2Self/S4U2Proxy** μπορούν να επαναληφθούν μέσω trust referrals, ενώ το **SPN-less** abuse μπορεί να απαιτεί ένα τελικό **`S4U2Self+U2U`** hop μαζί με RC4-dependent ticket handling. Δείτε το [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- Το **Windows Server 2025 εισήγαγε νέα Kerberos-adjacent attack surface** μέσω του **dMSA** migration logic. Αν δείτε delegated rights πάνω σε OUs ή service-account objects σε domain του 2025, ελέγξτε την dedicated [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) αντί να το αντιμετωπίσετε ως «ακόμη ένα gMSA».

## Γρήγοροι operator έλεγχοι σε σύγχρονα domains

Πριν επιλέξετε μια διαδρομή Kerberos attack, απαντήστε γρήγορα σε τέσσερις ερωτήσεις:

1. **Ποια accounts παραμένουν RC4-friendly;**
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
- Αν οι περισσότεροι service accounts δεν έχουν **explicit etype configuration**, αναμένετε συμπεριφορά **AES-only** σε ενημερωμένους DC του 2026 και προγραμματίστε πιο αργό offline cracking ή διαφορετική διαδρομή.
- Αν υπάρχει **RBCD / KCD / unconstrained delegation**, το S4U συχνά υπερισχύει του brute-force.
- Αν χρησιμοποιείται **certificate auth**, θυμηθείτε ότι ένα αποτυχημένο PKINIT path **δεν σημαίνει πάντα** ότι το cert είναι άχρηστο· σε πολλά περιβάλλοντα το ίδιο cert εξακολουθεί να λειτουργεί για abuse μέσω **Schannel/LDAPS** (δείτε [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Συνήθη σφάλματα Kerberos που αλλάζουν το attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Ο target account / DC δεν θα χρησιμοποιήσει τον encryption type που ζητήσατε. Σταματήστε να επαναλαμβάνετε την προσπάθεια μόνο με RC4· παρέχετε **AES keys** ή ζητήστε υλικό **AES** για roasting.
- **`KRB_AP_ERR_MODIFIED`** → Πιθανότατα έχετε το **λάθος service key**, το **λάθος SPN** ή ένα forged ticket που δεν αντιστοιχεί στον service account που το αποκρυπτογραφεί πραγματικά.
- **`KRB_AP_ERR_SKEW`** → Η ώρα σας είναι λανθασμένη. Κάντε sync με τον DC πριν αποσφαλματώσετε οτιδήποτε άλλο.
- **`KDC_ERR_BADOPTION`** κατά τη διάρκεια ροών S4U / delegation → συχνά σημαίνει **sensitive/not-delegable users**, λάθος delegation model ή ότι προσπαθείτε να χρησιμοποιήσετε **classic KCD** ενώ μόνο το **RBCD** θα αποδεχόταν ένα non-forwardable S4U2Self ticket.

## Αναφορές
- [1] [Microsoft Learn - Εντοπισμός και αντιμετώπιση χρήσης RC4 στο Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Τελευταίες οδηγίες hardening των Windows και βασικές ημερομηνίες](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Πώς λειτουργεί το Kerberos; – Θεωρία](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)

{{#include ../../banners/hacktricks-training.md}}
