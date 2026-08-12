# Kerberos Authentication

{{#include ../../banners/hacktricks-training.md}}

Για μια walkthrough σε επίπεδο πρωτοκόλλου των exchanges που συνοψίζονται παρακάτω, δείτε το άρθρο της Tarlogic για το Kerberos.<sup>[[3]](#references)</sup>

## TL;DR για attackers
- Το Kerberos είναι το προεπιλεγμένο AD auth protocol· οι περισσότερες αλυσίδες lateral movement θα το αγγίξουν.
- Σκεφτείτε το σε **τρεις operator phases**:<sup>[[3]](#references)</sup>
- **AS-REQ / AS-REP** → χρησιμοποιήστε password/hash/certificate για να αποκτήσετε ένα **TGT**. Εδώ ανήκουν τα **AS-REP roasting**, **over-pass-the-hash / pass-the-key** και **PKINIT**.
- **TGS-REQ / TGS-REP** → χρησιμοποιήστε ένα TGT για να αποκτήσετε **service tickets**. Εδώ γίνονται relevant τα **Kerberoasting**, **S4U abuse**, **delegation abuse** και το μεγαλύτερο μέρος του **ticket-forging tradecraft**.
- **AP-REQ / AP-REP** → παρουσιάστε το ticket στην υπηρεσία. Εδώ συμβαίνουν το **pass-the-ticket** και το service-specific lateral movement.
- Για hands-on cheatsheets (AS-REP/Kerberoasting, ticket forgery, delegation abuse κ.λπ.) δείτε:
{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/README.md
{{#endref}}
- Χρησιμοποιήστε αυτή τη σελίδα ως το **overview / “τι άλλαξε πρόσφατα”** index και, στη συνέχεια, μεταβείτε στις dedicated σελίδες για [Kerberoast](kerberoast.md), [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md), [AD Certificates / PKINIT abuse](ad-certificates.md) ή [BadSuccessor / dMSA abuse](acl-persistence-abuse/BadSuccessor.md).

## Νέες σημειώσεις επιθέσεων (2024-2026)
- **Το RC4 hardening άλλαξε τα defaults, όχι το ίδιο το Kerberos** – το σύγχρονο DC hardening εστιάζει στους **default assumed encryption types** για accounts που **δεν** ορίζουν ρητά το `msDS-SupportedEncryptionTypes`. Μετά το rollout του 2026, αυτά τα accounts ορίζονται όλο και περισσότερο ως **AES-only** σε patched DCs, οπότε οι τυφλές υποθέσεις για `/rc4` Kerberoast αποτυγχάνουν συχνότερα. Ωστόσο, τα **explicitly RC4-enabled service accounts** παραμένουν εξαιρετικοί στόχοι για offline cracking.<sup>[[1]](#references)</sup>
- **Η επιβολή του PAC validation είναι σημαντική για forged tickets** – το PAC-signature hardening του 2024 σημαίνει ότι τα **golden/diamond/sapphire/extraSID-style abuses** χρειάζονται πιο ρεαλιστικά PAC data και το σωστό signing context. Domains χωρίς patches ή domains που παραμένουν σε deployments τύπου compatibility/audit εξακολουθούν να είναι πιο αδύναμοι στόχοι.<sup>[[2]](#references)</sup>
- **Το certificate-based Kerberos άλλαξε δύο φορές**:
- Το **Strong certificate binding** (χρονοδιάγραμμα KB5014754) κάνει τα πρόχειρα certificate-to-account mappings λιγότερο αξιόπιστα σε fully enforced environments.
- Το **CVE-2025-26647** πρόσθεσε ένα ακόμη hardening layer γύρω από τα `altSecurityIdentities` mappings που χρησιμοποιούν το Subject Key Identifier ενός certificate. Επομένως, το patch level, η κατάσταση enforcement ή audit και η ρητή mapping configuration έχουν σημασία κατά την αξιολόγηση του pass-the-certificate και συναφών certificate-based paths.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup> Για το PKINIT, το KDC επικυρώνει επίσης το certificate path και ελέγχει ότι ο issuer είναι trusted μέσω του NTAuth store.<sup>[[8]](#references)</sup>
- **Το cross-domain / cross-forest delegation abuse παραμένει πολύ ενεργό** – τα Windows υποστηρίζουν σύγχρονα cross-realm **S4U2Self/S4U2Proxy** flows, επομένως τα writable delegation attributes σε άλλο domain παραμένουν πολύτιμα. Το blocker είναι συνήθως η πιστότητα των tools και οι λεπτομέρειες trust/policy, όχι η υποστήριξη του πρωτοκόλλου.
- **Το recursive multi-domain RBCD έχει επιχειρησιακή σημασία** – σε forests με 3+ domains, τα **S4U2Self/S4U2Proxy** μπορούν να κάνουν recurse μέσω trust referrals και το **SPN-less** abuse μπορεί να απαιτεί ένα τελικό **`S4U2Self+U2U`** hop μαζί με RC4-dependent ticket handling. Δείτε το [Resource-Based Constrained Delegation](resource-based-constrained-delegation.md).<sup>[[4]](#references)</sup>
- **Το Windows Server 2025 εισήγαγε delegated Managed Service Accounts (dMSAs)** και τη λογική migration τους. Αν δείτε delegated rights πάνω σε OUs ή service-account objects σε ένα domain του 2025, ελέγξτε την dedicated [BadSuccessor page](acl-persistence-abuse/BadSuccessor.md) αντί να το αντιμετωπίσετε ως “ακόμη ένα gMSA”.<sup>[[7]](#references)</sup>

## Γρήγοροι operator checks σε σύγχρονα domains

Πριν επιλέξετε ένα Kerberos attack path, απαντήστε γρήγορα σε τέσσερις ερωτήσεις:

1. **Ποια accounts είναι ακόμη RC4-friendly;**
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
- Αν οι **interesting SPN accounts είναι ρητά RC4-capable**, το Kerberoasting παραμένει φθηνό και γρήγορο.
- Αν οι περισσότεροι service accounts **δεν έχουν ρητή ρύθμιση etype**, αναμένετε συμπεριφορά **AES-only** σε ενημερωμένα DCs του 2026 και προετοιμαστείτε για πιο αργό offline cracking ή για διαφορετική διαδρομή.
- Αν υπάρχει **RBCD / KCD / unconstrained delegation**, το S4U συχνά υπερτερεί του brute-force.
- Αν χρησιμοποιείται **certificate auth**, θυμηθείτε ότι μια αποτυχημένη διαδρομή PKINIT **δεν σημαίνει πάντα** ότι το cert είναι άχρηστο· σε πολλά περιβάλλοντα το ίδιο cert εξακολουθεί να λειτουργεί για abuse μέσω **Schannel/LDAPS** (δείτε [AD Certificates / PKINIT abuse](ad-certificates.md)).

## Συνήθη σφάλματα Kerberos που αλλάζουν το attack plan
- **`KDC_ERR_ETYPE_NOTSUPP`** → Ο target account / DC δεν θα χρησιμοποιήσει τον encryption type που ζητήσατε. Σταματήστε να επαναλαμβάνετε προσπάθειες μόνο με RC4· παρέχετε **AES keys** ή ζητήστε roast material **AES**.
- **`KRB_AP_ERR_MODIFIED`** → Πιθανότατα έχετε το **λάθος service key**, το **λάθος SPN** ή ένα forged ticket που δεν αντιστοιχεί στον service account που το αποκρυπτογραφεί στην πράξη.
- **`KRB_AP_ERR_SKEW`** → Η ώρα σας δεν είναι σωστή. Κάντε sync με το DC πριν κάνετε οτιδήποτε άλλο για debugging.
- **`KDC_ERR_BADOPTION`** κατά τη διάρκεια ροών S4U / delegation → συχνά σημαίνει **sensitive/not-delegable users**, λάθος μοντέλο delegation ή ότι προσπαθείτε να κάνετε **classic KCD**, ενώ μόνο το **RBCD** θα αποδεχόταν ένα non-forwardable S4U2Self ticket.

## References
- [1] [Microsoft Learn - Εντοπισμός και αποκατάσταση χρήσης RC4 στο Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [2] [Microsoft Support - Τελευταίες οδηγίες hardening των Windows και σημαντικές ημερομηνίες](https://support.microsoft.com/en-us/topic/latest-windows-hardening-guidance-and-key-dates-eb1bd411-f68c-4d74-a4e1-456721a6551b)
- [3] [Kerberos (I): Πώς λειτουργεί το Kerberos; – Θεωρία](https://www.tarlogic.com/en/blog/how-kerberos-works/)
- [4] [Synacktiv - Exploiting RBCD in Cross-Domain & Cross-Forest Environments: Part 2](https://www.synacktiv.com/publications/exploiter-la-rbcd-en-environnements-cross-domain-cross-forest-partie-2)
- [5] [Microsoft Support - Αλλαγές στο authentication βάσει certificate με το KB5014754](https://support.microsoft.com/help/5014754)
- [6] [Microsoft - CVE-2025-26647 Kerberos certificate mapping vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26647)
- [7] [Microsoft Learn - Επισκόπηση των Delegated Managed Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [8] [Microsoft Learn - Απαιτήσεις certificate για smart cards και επικύρωση KDC](https://learn.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration)
{{#include ../../banners/hacktricks-training.md}}
