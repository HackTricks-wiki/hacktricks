# Ενίσχυση LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία

Οι επιθέσεις LDAP relay/MITM προωθούν τον έλεγχο ταυτότητας σε έναν domain controller, ώστε να αποκτήσουν ένα authenticated LDAP context. Η [επισκόπηση του poisoning και του relay μέσω name resolution](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) καλύπτει την ευρύτερη ροή εργασίας. Δύο σχετικοί έλεγχοι περιορίζουν αυτές τις διαδρομές:

- Το **LDAP channel binding (CBT)** συνδέει τον σχετικό έλεγχο ταυτότητας με το TLS server certificate/channel που χρησιμοποιεί το LDAPS, δυσχεραίνοντας το cross-channel relay.
- Το **LDAP signing** απαιτεί προστασία ακεραιότητας για τα SASL LDAP binds. Δεν προσθέτει εμπιστευτικότητα· χρησιμοποιήστε TLS όταν χρειάζεται επίσης κρυπτογράφηση του περιεχομένου LDAP.<sup>[[2]](#references)</sup>

**Γρήγορος έλεγχος κατάστασης**: εργαλεία όπως το `netexec ldap <dc> -u user -p pass` αναφέρουν την πολιτική signing και channel binding που παρατηρούν. Τα `(signing:None)` και `(channel binding:Never)` υποδεικνύουν ότι λείπουν έλεγχοι, αλλά η επιτυχία ενός relay εξακολουθεί να εξαρτάται από τον τύπο του authentication που συλλέχθηκε, τη συμπεριφορά του EPA, τα προνόμια του λογαριασμού, το πρωτόκολλο-στόχο και τις προστασίες έναντι relay. Όταν το relayed principal έχει τα απαραίτητα δικαιώματα, εργαλεία όπως το KrbRelayUp μπορούν να γράψουν το `msDS-AllowedToActOnBehalfOfOtherIdentity`, να διαμορφώσουν resource-based constrained delegation (RBCD) και να χρησιμοποιήσουν τη διαδρομή delegation που προκύπτει για να κάνουν impersonate ένα privileged principal.<sup>[[4]](#references)</sup>

Οι **Server 2025 DCs** εισάγουν ένα νέο GPO (**LDAP server signing requirements Enforcement**), το οποίο έχει ως προεπιλογή το **Require Signing** όταν παραμένει **Not Configured**. Για να αποφύγετε την επιβολή, πρέπει να ορίσετε ρητά αυτή την πολιτική σε **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (μόνο LDAPS)

- **Απαιτήσεις**:
  - Το patch CVE-2017-8563 (2017) προσθέτει υποστήριξη Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - Το **KB4520412** (Server 2019/2022) προσθέτει τηλεμετρία LDAPS CBT “what-if”.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (προεπιλογή, χωρίς CBT)
  - `When Supported` (μερική επιβολή: οι clients που υποστηρίζουν CBT πρέπει να παρέχουν έγκυρο token· οι clients χωρίς υποστήριξη CBT μπορούν ακόμη να κάνουν bind και καταγράφονται audit events)
  - `Always` (επιβολή: απορρίπτει LDAPS binds χωρίς έγκυρο CBT)<sup>[[1]](#references)</sup>
- **Audit**: ορίστε το **When Supported** για να εμφανιστούν:
  - **3074** – Το LDAPS bind θα αποτύγχανε στην επικύρωση CBT αν η επιβολή ήταν ενεργοποιημένη.
  - **3075** – Το LDAPS bind δεν περιείχε δεδομένα CBT και θα απορριπτόταν αν η επιβολή ήταν ενεργοποιημένη.
  - (Το event **3039** εξακολουθεί να υποδεικνύει αποτυχίες CBT σε παλαιότερα builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Επιβολή**: ορίστε το **Always** μόλις οι clients LDAPS στέλνουν CBT· ισχύει μόνο για **LDAPS** (όχι για raw 389).<sup>[[1]](#references)</sup>

Το `When Supported` δεν είναι μόνο για audit: επικυρώνει το CBT για clients που το υποστηρίζουν, ενώ επιτρέπει τη σύνδεση σε clients χωρίς υποστήριξη CBT. Η [αναφορά πολιτικής της Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) περιγράφει τις προεπιλογές που εξαρτώνται από την έκδοση. Το LDAP signing εφαρμόζεται στα σχετικά binds μέσω LDAP/389· το channel binding εφαρμόζεται στον έλεγχο ταυτότητας LDAP που προστατεύεται με TLS.

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (αντί για την προεπιλογή `Negotiate signing` στα σύγχρονα Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (η προεπιλογή είναι `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: αφήστε την legacy πολιτική στο `None` και ορίστε το `LDAP server signing requirements Enforcement` = `Enabled` (το Not Configured σημαίνει ότι εφαρμόζεται από προεπιλογή· ορίστε το `Disabled` για να το αποφύγετε).<sup>[[1]](#references)</sup>
- **Συμβατότητα**: Καταγράψτε τις non-Windows συσκευές και εφαρμογές που χρησιμοποιούν simple binds ή unsigned SASL binds. Η Microsoft τεκμηριώνει την υποστήριξη σε συντηρούμενες εκδόσεις Windows· οι δηλώσεις συμβατότητας με legacy clients θα πρέπει να επαληθεύονται με βάση το πραγματικό client stack, αντί να περιορίζονται σε ένα όριο έκδοσης XP.<sup>[[2]](#references)</sup>

## Rollout με πρώτα το audit (συνιστώνται περίπου 30 ημέρες)

1. Ενεργοποιήστε τα διαγνωστικά του LDAP interface σε κάθε DC για να καταγράφονται τα unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Ορίστε το DC GPO `LDAP server channel binding token requirements` = **When Supported** για μερική επιβολή CBT και τηλεμετρία· πρώτα επαληθεύστε τη συμβατότητα με legacy clients.<sup>[[1]](#references)</sup>
3. Παρακολουθήστε τα συμβάντα Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – binds χωρίς υπογραφή/που επιτρέπουν binds χωρίς υπογραφή (μη συμμόρφωση με τις απαιτήσεις υπογραφής).
   - **3074/3075** – LDAPS binds που θα αποτύγχαναν ή δεν θα περιλάμβαναν CBT (απαιτείται το KB4520412 στα 2019/2022 και το παραπάνω βήμα 2).
4. Επιβάλετε τις ρυθμίσεις με ξεχωριστές αλλαγές:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **ή** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Δέσμευση καναλιού LDAP και υπογραφή LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Απαιτήσεις δέσμευσης καναλιού LDAP και υπογραφής LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Ενημέρωση μετριασμού LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (απενεργοποιημένη υπογραφή LDAP → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
