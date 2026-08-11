# Προστασίες ασφαλείας macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Το Gatekeeper χρησιμοποιείται συνήθως για να αναφέρεται στον συνδυασμό **Quarantine + Gatekeeper + XProtect**, 3 security modules του macOS που θα προσπαθήσουν να **εμποδίσουν τους χρήστες από την εκτέλεση δυνητικά κακόβουλου λογισμικού που έχει ληφθεί**.

Περισσότερες πληροφορίες:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Περιορισμοί διεργασιών

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

Το MacOS Sandbox **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο sandbox στις **επιτρεπόμενες ενέργειες που καθορίζονται στο Sandbox profile** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο στους αναμενόμενους πόρους**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

Το **TCC (Transparency, Consent, and Control)** είναι ένα security framework. Έχει σχεδιαστεί για να **διαχειρίζεται τα permissions** των εφαρμογών, ρυθμίζοντας συγκεκριμένα την πρόσβασή τους σε ευαίσθητες δυνατότητες. Σε αυτές περιλαμβάνονται στοιχεία όπως οι **υπηρεσίες τοποθεσίας, οι επαφές, οι φωτογραφίες, το μικρόφωνο, η κάμερα, η προσβασιμότητα και η πλήρης πρόσβαση στον δίσκο**. Το TCC διασφαλίζει ότι οι εφαρμογές μπορούν να έχουν πρόσβαση σε αυτές τις δυνατότητες μόνο αφού λάβουν ρητή συγκατάθεση του χρήστη, ενισχύοντας έτσι το privacy και τον έλεγχο των προσωπικών δεδομένων.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Τα launch constraints στο macOS είναι ένα security feature για τη **ρύθμιση της εκκίνησης διεργασιών**, καθορίζοντας **ποιος μπορεί να εκκινήσει** μια διεργασία, **με ποιον τρόπο** και **από πού**. Παρουσιάστηκαν στο macOS Ventura και κατηγοριοποιούν τα system binaries σε κατηγορίες constraints μέσα σε ένα **trust cache**. Κάθε executable binary διαθέτει ένα σύνολο από **κανόνες** για το **launch** του, συμπεριλαμβανομένων των constraints **self**, **parent** και **responsible**. Επεκτάθηκαν σε εφαρμογές τρίτων ως **Environment Constraints** στο macOS Sonoma. Αυτές οι δυνατότητες βοηθούν στον περιορισμό πιθανών system exploitations, ελέγχοντας τις συνθήκες υπό τις οποίες εκκινούνται οι διεργασίες.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Το Malware Removal Tool (MRT) αποτελεί ένα ακόμη μέρος της security infrastructure του macOS. Όπως υποδηλώνει το όνομά του, η κύρια λειτουργία του MRT είναι να **αφαιρεί γνωστό malware από μολυσμένα συστήματα**.

Μόλις εντοπιστεί malware σε έναν Mac (είτε από το XProtect είτε με κάποιο άλλο μέσο), το MRT μπορεί να χρησιμοποιηθεί για την αυτόματη **αφαίρεση του malware**. Το MRT λειτουργεί αθόρυβα στο background και συνήθως εκτελείται κάθε φορά που ενημερώνεται το σύστημα ή όταν γίνεται λήψη ενός νέου malware definition (φαίνεται ότι οι rules που χρησιμοποιεί το MRT για τον εντοπισμό malware βρίσκονται μέσα στο binary).

Παρότι τα XProtect και MRT αποτελούν μέρος των security measures του macOS, εκτελούν διαφορετικές λειτουργίες:

- Το **XProtect** είναι ένα preventative tool. **Ελέγχει τα αρχεία κατά τη λήψη τους** (μέσω ορισμένων εφαρμογών) και, αν εντοπίσει γνωστούς τύπους malware, **εμποδίζει το άνοιγμα του αρχείου**, αποτρέποντας έτσι το malware από το να μολύνει εξαρχής το σύστημά σας.
- Το **MRT**, από την άλλη πλευρά, είναι ένα **reactive tool**. Λειτουργεί αφού έχει εντοπιστεί malware σε ένα σύστημα, με στόχο την αφαίρεση του offending software για τον καθαρισμό του συστήματος.

Η εφαρμογή MRT βρίσκεται στη διαδρομή **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Διαχείριση Background Tasks

Το **macOS** πλέον **ειδοποιεί** κάθε φορά που ένα tool χρησιμοποιεί μια γνωστή **technique για persistence code execution** (όπως Login Items, Daemons...), ώστε ο χρήστης να γνωρίζει καλύτερα **ποιο software κάνει persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Αυτό εκτελείται με έναν **daemon** που βρίσκεται στη διαδρομή `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` και τον **agent** στη διαδρομή `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Ο τρόπος με τον οποίο το **`backgroundtaskmanagementd`** γνωρίζει ότι κάτι έχει εγκατασταθεί σε έναν persistent folder είναι μέσω της **λήψης των FSEvents** και της δημιουργίας ορισμένων **handlers** για αυτά.<sup>[[1]](#references)</sup>

Επιπλέον, υπάρχει ένα αρχείο plist που περιέχει **γνωστές εφαρμογές** οι οποίες κάνουν συχνά persistence και συντηρείται από την Apple. Βρίσκεται στη διαδρομή: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Είναι δυνατό να γίνει **enumerate all** τα ρυθμισμένα στοιχεία παρασκηνίου που εκτελούνται, χρησιμοποιώντας το Apple cli tool:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Επιπλέον, είναι επίσης δυνατή η καταχώριση αυτών των πληροφοριών με το [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Αυτές οι πληροφορίες αποθηκεύονται στο **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** και το Terminal χρειάζεται FDA.<sup>[[2]](#references)</sup>

### Παρεμβάσεις στο BTM

Όταν εντοπίζεται ένα νέο persistence, δημιουργείται ένα event τύπου **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Επομένως, οποιοσδήποτε τρόπος **αποτροπής** αποστολής αυτού του **event** ή **παρεμπόδισης του agent από το να ειδοποιήσει** τον χρήστη θα βοηθήσει έναν attacker να _**παρακάμψει**_ το BTM.<sup>[[1]](#references)</sup>

- **Επαναφορά της database**: Η εκτέλεση της ακόλουθης εντολής επαναφέρει τη database (η οποία θα πρέπει να δημιουργηθεί ξανά από την αρχή). Ωστόσο, μετά από αυτό, **δεν εμφανίζονται νέες ειδοποιήσεις persistence μέχρι να γίνει επανεκκίνηση του συστήματος**.<sup>[[1]](#references)</sup>
- Απαιτούνται **root** privileges.
```bash
# Reset the database
sfltool resettbtm
```
- **Διακοπή του Agent**: Είναι δυνατό να σταλεί σήμα διακοπής στον agent, ώστε να **μην ειδοποιεί τον χρήστη** όταν εντοπίζονται νέες ανιχνεύσεις.<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: Εάν η **διεργασία που δημιούργησε το persistence τερματιστεί αμέσως μετά**, ο daemon προσπαθεί να **λάβει πληροφορίες** για αυτήν, **αποτυγχάνει** και **δεν μπορεί να στείλει το event** που υποδεικνύει ότι ένα νέο item παραμένει persistent.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: «Απομυθοποίηση (και παράκαμψη) της διαχείρισης εργασιών παρασκηνίου του macOS» - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Νέο εργαλείο (για developers): «DumpBTM» - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Διαχείριση στοιχείων σύνδεσης και εργασιών παρασκηνίου σε Mac - Ανάπτυξη πλατφορμών Apple](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
