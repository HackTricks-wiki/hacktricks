# Ενίσχυση LDAP Signing & Channel Binding

{{#include ../../banners/hacktricks-training.md}}

## Γιατί έχει σημασία

Οι επιθέσεις LDAP relay/MITM προωθούν τον έλεγχο ταυτότητας σε έναν domain controller, ώστε να αποκτήσουν ένα authenticated LDAP context. Η [επισκόπηση poisoning και relay ανάλυσης ονομάτων](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) καλύπτει τη γενικότερη ροή εργασίας. Δύο σχετικά μέτρα ελέγχου περιορίζουν αυτές τις διαδρομές:

- Το **LDAP channel binding (CBT)** συνδέει τον αντίστοιχο έλεγχο ταυτότητας με το TLS server certificate/channel που χρησιμοποιείται από το LDAPS, δυσχεραίνοντας το cross-channel relay.
- Το **LDAP signing** απαιτεί προστασία ακεραιότητας για τα SASL LDAP binds. Δεν προσθέτει εμπιστευτικότητα· χρησιμοποιήστε TLS όταν χρειάζεται επίσης κρυπτογράφηση του περιεχομένου LDAP.<sup>[[2]](#references)</sup>

**Γρήγορος έλεγχος κατάστασης**: εργαλεία όπως το `netexec ldap <dc> -u user -p pass` αναφέρουν την πολιτική signing και channel binding που παρατηρούν. Οι ενδείξεις `(signing:None)` και `(channel binding:Never)` υποδεικνύουν ότι λείπουν μέτρα ελέγχου, αλλά η επιτυχία ενός relay εξακολουθεί να εξαρτάται από τον τύπο ελέγχου ταυτότητας που υποκλάπηκε, τη συμπεριφορά EPA, τα δικαιώματα του λογαριασμού, το πρωτόκολλο-στόχο και τις προστασίες relay. Όταν ο relayed principal έχει τα απαιτούμενα δικαιώματα, εργαλεία όπως το KrbRelayUp μπορούν να γράψουν το `msDS-AllowedToActOnBehalfOfOtherIdentity`, να ρυθμίσουν resource-based constrained delegation (RBCD) και να χρησιμοποιήσουν την resulting delegation path για να υποδυθούν έναν privileged principal.<sup>[[4]](#references)</sup>

Οι **DCs με Server 2025** εισάγουν ένα νέο GPO (**LDAP server signing requirements Enforcement**), το οποίο από προεπιλογή ορίζεται σε **Require Signing** όταν παραμένει **Not Configured**. Για να αποφύγετε την επιβολή της πολιτικής, πρέπει να την ορίσετε ρητά σε **Disabled**.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (μόνο LDAPS)

- **Απαιτήσεις**:
  - Το patch CVE-2017-8563 (2017) προσθέτει υποστήριξη Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - Το **KB4520412** (Server 2019/2022) προσθέτει telemetry LDAPS CBT «what-if».<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (προεπιλογή, χωρίς CBT)
  - `When Supported` (μερική επιβολή: οι clients με υποστήριξη CBT πρέπει να παρέχουν έγκυρο token· οι clients χωρίς υποστήριξη CBT μπορούν να κάνουν bind και εκπέμπονται audit events)
  - `Always` (επιβολή: απορρίπτει LDAPS binds χωρίς έγκυρο CBT)<sup>[[1]](#references)</sup>
- **Audit**: ορίστε το **When Supported** για να εντοπίσετε:
  - **3074** – Το LDAPS bind θα είχε αποτύχει στην επικύρωση CBT αν η πολιτική επιβαλλόταν.
  - **3075** – Το LDAPS bind δεν περιλάμβανε δεδομένα CBT και θα απορριπτόταν αν η πολιτική επιβαλλόταν.
  - (Το event **3039** εξακολουθεί να σηματοδοτεί αποτυχίες CBT σε παλαιότερα builds.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Επιβολή**: ορίστε το **Always** μόλις οι LDAPS clients στέλνουν CBT· ισχύει μόνο για **LDAPS** (όχι για το raw 389).<sup>[[1]](#references)</sup>

Το `When Supported` δεν περιορίζεται μόνο σε audit: επικυρώνει το CBT για clients με υποστήριξη, ενώ επιτρέπει τη σύνδεση σε clients χωρίς υποστήριξη CBT. Η [αναφορά πολιτικής της Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) περιγράφει τις προεπιλεγμένες ρυθμίσεις ανά έκδοση. Το LDAP signing εφαρμόζεται στα αντίστοιχα binds μέσω LDAP/389· το channel binding εφαρμόζεται στον έλεγχο ταυτότητας LDAP που προστατεύεται από TLS.


## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (αντί του `Negotiate signing`, που είναι η προεπιλογή στα σύγχρονα Windows).<sup>[[1]](#references)</sup>
- **DC GPO**:
  - Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (η προεπιλογή είναι `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: αφήστε την legacy πολιτική στο `None` και ορίστε το `LDAP server signing requirements Enforcement` = `Enabled` (το Not Configured σημαίνει ότι επιβάλλεται από προεπιλογή· ορίστε το `Disabled` για να το αποφύγετε).<sup>[[1]](#references)</sup>
- **Συμβατότητα**: καταγράψτε τις μη-Windows συσκευές και εφαρμογές που χρησιμοποιούν simple binds ή unsigned SASL binds. Η Microsoft τεκμηριώνει την υποστήριξη σε συντηρούμενες εκδόσεις Windows· οι δηλώσεις συμβατότητας με legacy clients πρέπει να επαληθεύονται σε σχέση με το πραγματικό client stack και όχι να ανάγονται σε ένα όριο έκδοσης XP.<sup>[[2]](#references)</sup>

## Διαδρομές relay και signed-SASL reauthentication

Αν απαιτείται **μόνο signing**, το relay προς LDAPS μπορεί να λειτουργήσει όταν δεν επιβάλλεται το channel binding: το TLS παρέχει ακεραιότητα μεταφοράς. Αν απαιτείται **μόνο channel binding**, το απλό LDAP δεν διαθέτει TLS channel για να γίνει binding· ένα relay μπορεί να κάνει authenticate μέσω TCP 389 και στη συνέχεια να χρησιμοποιήσει StartTLS για λειτουργίες που απαιτούν TLS, εφόσον η relayed ταυτότητα έχει τα απαιτούμενα δικαιώματα. Η επιβολή και των δύο κλείνει αυτές τις συμβατικές εναλλακτικές, αλλά δεν σταμάτησε το ακόλουθο flaw σε μη ενημερωμένους domain controllers.<sup>[[5]](#references)</sup>

### Προσθήκη LDAP operation μετά από relayed Bind

Σε επηρεαζόμενους domain controllers Windows Server 2016–2025, πρώτα δημιουργήστε μια **signed NTLM SASL LDAP connection** μέσω TCP 389 ως ταυτότητα X, χρησιμοποιώντας credentials των οποίων γνωρίζετε το session key (ή ένα anonymous NTLM SASL context όπου αυτό γίνεται δεκτό). Εξαναγκάστε την ταυτότητα Y να κάνει authenticate **μέσω SMB** προς το relay. Προωθήστε τα NTLM NEGOTIATE της Y και CHALLENGE του DC μέσω GSS-SPNEGO Bind requests στην υπάρχουσα LDAP connection της X. Ο Windows SMB client ορίζει το `NTLMSSP_NEGOTIATE_SIGN`, επομένως το resulting LDAP bind απαιτεί signed SASL layer· μια ανταλλαγή που προέρχεται από HTTP/WebDAV γενικά δεν έχει αυτό το flag και δεν είναι εναλλάξιμη σε αυτή την περίπτωση.<sup>[[5]](#references)</sup>

Όταν η Y στείλει NTLM AUTHENTICATE, τοποθετήστε **δύο ξεχωριστά LDAP μηνύματα σε ένα length-prefixed SASL record**: ένα BindRequest που μεταφέρει αυτή την απόκριση και, στη συνέχεια, ένα ModifyRequest. Υπογράψτε ολόκληρο το record με το γνωστό key της X. Ο ευάλωτος DC επαληθεύει το record υπό την X, ολοκληρώνει το Bind και αλλάζει την εξουσιοδότηση της connection στην Y, και έπειτα εκτελεί το υπόλοιπο ModifyRequest ως Y χωρίς να επανελέγξει το record με το key της Y. Αυτό δεν αποκαλύπτει τον κωδικό πρόσβασης ή το session key της Y· ένα επόμενο record υπογεγραμμένο από την X αποτυγχάνει. Ένα RBCD write στο `msDS-AllowedToActOnBehalfOfOtherIdentity` ή ένα shadow-credential write στο `msDS-KeyCredentialLink` εξακολουθεί να απαιτεί η Y να έχει δικαίωμα στο αντικείμενο-στόχο. Δείτε τα [RBCD](resource-based-constrained-delegation.md), [shadow credentials](acl-persistence-abuse/shadow-credentials.md) και, για relayed DC machine account, το [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Πρόκειται για bypass του **plain LDAP**, όχι για bypass του LDAPS channel binding. Στο LDAPS, το TLS προστατεύει τη connection και τα Windows δεν δημιουργούν το NTLM SASL signing layer με το key της X που απαιτείται για αυτή τη διαδρομή record-stacking. Αν το TCP 389 δεν είναι διαθέσιμο, η τεχνική δεν μεταφέρεται απλώς στο TCP 636. Οι ενημερώσεις ασφαλείας του Οκτωβρίου 2026 αποτρέπουν τη λειτουργία same-record απορρίπτοντας τα υπόλοιπα δεδομένα μετά την αλλαγή της ταυτότητας της connection από το Bind.<sup>[[5]](#references)</sup> Το KB5126646 είναι η ενημέρωση για Windows Server 2025· οι άλλες επηρεαζόμενες εκδόσεις Server έχουν διαφορετικούς αριθμούς KB.<sup>[[7]](#references)</sup>

Το [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) του ερευνητή περιτυλίγει ένα τροποποιημένο `ntlmrelayx.py` για αυτή τη ροή εργασίας. Απαιτεί πηγή coercion μέσω **SMB**, ένα pinned Impacket tree που εκθέτει LDAP signing/security-context APIs (το PyPI Impacket 0.13.1 δεν επαρκεί) και έναν λογαριασμό ελεγχόμενο από τον επιτιθέμενο για το αρχικό signed bind. Για ένα RBCD write, δώστε το DN του αντικειμένου-θύματος και το SID ενός ελεγχόμενου delegating computer· χρησιμοποιήστε τα `-attribute` μαζί με `-value` ή `-value-hex` για άλλο επιτρεπόμενο write. Επιβεβαιώστε το ανεξάρτητο signed read-back του εργαλείου, αντί να θεωρείτε ότι ένα μήνυμα `FAILED` από την πλευρά του relay αποδεικνύει πως το ModifyRequest απέτυχε.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Προκαλέστε ξεχωριστά τον έλεγχο ταυτότητας SMB· δείτε το [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) για μία επιφάνεια coercion και την [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) για άλλες. Η εντολή και η υλοποίηση του εργαλείου τεκμηριώνονται στο repository του.<sup>[[6]](#references)</sup>

## Σταδιακή εφαρμογή με προτεραιότητα τον έλεγχο (συνιστώνται ~30 ημέρες)

1. Ενεργοποιήστε τα διαγνωστικά διεπαφής LDAP σε κάθε DC για την καταγραφή μη υπογεγραμμένων binds (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Ορίστε την πολιτική DC GPO `LDAP server channel binding token requirements` = **When Supported** για μερική επιβολή CBT και τηλεμετρία· ελέγξτε πρώτα τη συμβατότητα με παλαιότερους clients.<sup>[[1]](#references)</sup>
3. Παρακολουθήστε τα συμβάντα Directory Service:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – binds χωρίς υπογραφή/με αποδοχή χωρίς υπογραφή (μη συμμόρφωση με τις απαιτήσεις υπογραφής).
   - **3074/3075** – LDAPS binds που θα αποτύγχαναν ή θα παρέλειπαν το CBT (απαιτείται το KB4520412 στα 2019/2022 και το παραπάνω βήμα 2).
4. Επιβάλετε τις ρυθμίσεις σε ξεχωριστές αλλαγές:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **ή** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - Σύνδεση καναλιού LDAP και υπογραφή LDAP](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Απαιτήσεις σύνδεσης καναλιού LDAP και υπογραφής LDAP](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Ενημέρωση μετριασμού LDAP relay](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (απενεργοποιημένη υπογραφή LDAP → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Υπογεγραμμένο, σφραγισμένο και relayed, σε στυλ NTLM](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [Proof of concept LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Πληροφορίες εκδόσεων Windows Server](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
