# Ενίσχυση LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία

Οι επιθέσεις LDAP relay/MITM προωθούν την αυθεντικοποίηση σε έναν domain controller, ώστε να αποκτήσουν ένα αυθεντικοποιημένο LDAP context. Δύο σχετικά controls περιορίζουν αυτές τις διαδρομές:

- Το **LDAP channel binding (CBT)** συνδέει την εφαρμοστέα αυθεντικοποίηση με το TLS server certificate/channel που χρησιμοποιεί το LDAPS, δυσχεραίνοντας το cross-channel relay.
- Το **LDAP signing** απαιτεί προστασία ακεραιότητας για τα SASL LDAP binds. Δεν προσθέτει εμπιστευτικότητα· χρησιμοποιήστε TLS όταν χρειάζεται επίσης κρυπτογράφηση του περιεχομένου LDAP.<sup>[[2]](#references)</sup>

**Γρήγορος έλεγχος κατάστασης**: εργαλεία όπως το `netexec ldap <dc> -u user -p pass` αναφέρουν τις παρατηρούμενες πολιτικές signing και channel binding. Τα `(signing:None)` και `(channel binding:Never)` υποδεικνύουν ότι λείπουν controls, αλλά η επιτυχία ενός relay εξακολουθεί να εξαρτάται από τον τύπο της υποκλαπείσας αυθεντικοποίησης, τη συμπεριφορά του EPA, τα δικαιώματα του λογαριασμού, το πρωτόκολλο-στόχο και τις προστασίες έναντι relay. Όταν το relayed principal έχει τα απαραίτητα δικαιώματα, εργαλεία όπως το KrbRelayUp μπορούν να τροποποιήσουν το `msDS-AllowedToActOnBehalfOfOtherIdentity`, να ρυθμίσουν resource-based constrained delegation (RBCD) και να χρησιμοποιήσουν τη διαδρομή delegation που προκύπτει για να κάνουν impersonate ένα privileged principal.<sup>[[4]](#references)</sup>

**Οι DC με Server 2025** εισάγουν ένα νέο GPO (**LDAP server signing requirements Enforcement**), το οποίο έχει ως προεπιλογή το **Require Signing** όταν παραμένει **Not Configured**. Για να αποφύγετε την επιβολή της πολιτικής, πρέπει να την ορίσετε ρητά σε **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (μόνο LDAPS)

- **Απαιτήσεις**:
  - Το patch CVE-2017-8563 (2017) προσθέτει υποστήριξη Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - Το **KB4520412** (Server 2019/2022) προσθέτει τηλεμετρία LDAPS CBT «what-if».<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (προεπιλογή, χωρίς CBT)
  - `When Supported` (μερική επιβολή: οι clients με υποστήριξη CBT πρέπει να παρέχουν έγκυρο token· οι clients χωρίς υποστήριξη CBT μπορούν ακόμη να κάνουν bind και καταγράφονται audit events)
  - `Always` (επιβολή: απορρίπτει LDAPS binds χωρίς έγκυρο CBT)<sup>[[1]](#references)</sup>
- **Audit**: ορίστε το **When Supported** για να εντοπίσετε:
  - **3074** – Το LDAPS bind θα αποτύγχανε στην επικύρωση CBT αν η πολιτική επιβαλλόταν.
  - **3075** – Το LDAPS bind δεν περιείχε δεδομένα CBT και θα απορριπτόταν αν η πολιτική επιβαλλόταν.
  - (Το event **3039** εξακολουθεί να υποδεικνύει αποτυχίες CBT σε παλαιότερες εκδόσεις.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Επιβολή**: ορίστε το **Always** μόλις οι LDAPS clients στέλνουν CBT· είναι αποτελεσματικό μόνο στο **LDAPS** (όχι στο raw 389).<sup>[[1]](#references)</sup>

Το `When Supported` δεν είναι μόνο για audit: επικυρώνει το CBT για clients με υποστήριξη, ενώ επιτρέπει τη σύνδεση σε clients χωρίς υποστήριξη CBT. Η [αναφορά πολιτικής της Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) περιγράφει τις προεπιλεγμένες ρυθμίσεις που εξαρτώνται από την έκδοση. Το LDAP signing εφαρμόζεται στα σχετικά binds μέσω LDAP/389· το channel binding εφαρμόζεται στην αυθεντικοποίηση LDAP που προστατεύεται από TLS.

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (αντί για την προεπιλογή `Negotiate signing` στις σύγχρονες εκδόσεις των Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (προεπιλογή: `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: αφήστε την παλαιότερη πολιτική στο `None` και ορίστε το `LDAP server signing requirements Enforcement` = `Enabled` (το `Not Configured` σημαίνει επιβολή από προεπιλογή· ορίστε το `Disabled` για να την αποφύγετε).<sup>[[1]](#references)</sup>
- **Συμβατότητα**: καταγράψτε τις συσκευές και εφαρμογές που δεν είναι Windows και χρησιμοποιούν simple binds ή unsigned SASL binds. Η Microsoft τεκμηριώνει την υποστήριξη σε εκδόσεις Windows που εξακολουθούν να συντηρούνται· οι δηλώσεις συμβατότητας με legacy clients πρέπει να επαληθεύονται ως προς το πραγματικό client stack, αντί να ανάγονται σε ένα όριο έκδοσης XP.<sup>[[2]](#references)</sup>

## Σταδιακή εφαρμογή με πρώτα το audit (συνιστώνται περίπου 30 ημέρες)

1. Ενεργοποιήστε τα διαγνωστικά LDAP interface σε κάθε DC, ώστε να καταγράφονται τα unsigned binds (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Ορίστε στο DC GPO `LDAP server channel binding token requirements` = **When Supported** για μερική επιβολή CBT και τηλεμετρία· πρώτα επαληθεύστε τη συμβατότητα με legacy clients.<sup>[[1]](#references)</sup>
3. Παρακολουθήστε τα συμβάντα Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – unsigned/unsigned-allow binds (μη συμμόρφωση με τις απαιτήσεις signing).
   - **3074/3075** – LDAPS binds που θα αποτύγχαναν ή θα παρέλειπαν το CBT (απαιτείται το KB4520412 στα 2019/2022 και το παραπάνω βήμα 2).
4. Επιβάλετε τις ρυθμίσεις σε ξεχωριστές αλλαγές:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **ή** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## References

- [1] [TrustedSec - LDAP Channel Binding και LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Απαιτήσεις LDAP channel binding και signing](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Ενημέρωση μετριασμού LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (απενεργοποιημένο LDAP signing → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
