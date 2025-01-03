# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Ο Gatekeeper χρησιμοποιείται συνήθως για να αναφέρεται στον συνδυασμό **Quarantine + Gatekeeper + XProtect**, 3 μονάδες ασφαλείας του macOS που προσπαθούν να **αποτρέψουν τους χρήστες από το να εκτελούν δυνητικά κακόβουλο λογισμικό που έχει κατεβεί**.

Περισσότερες πληροφορίες στο:

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Processes Limitants

### MACF

### SIP - System Integrity Protection

{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

Το MacOS Sandbox **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο sandbox στις **επιτρεπόμενες ενέργειες που καθορίζονται στο προφίλ Sandbox** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο σε αναμενόμενους πόρους**.

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** είναι ένα πλαίσιο ασφαλείας. Είναι σχεδιασμένο να **διαχειρίζεται τις άδειες** των εφαρμογών, ρυθμίζοντας συγκεκριμένα την πρόσβασή τους σε ευαίσθητες δυνατότητες. Αυτό περιλαμβάνει στοιχεία όπως **υπηρεσίες τοποθεσίας, επαφές, φωτογραφίες, μικρόφωνο, κάμερα, προσβασιμότητα και πλήρη πρόσβαση δίσκου**. Το TCC διασφαλίζει ότι οι εφαρμογές μπορούν να έχουν πρόσβαση σε αυτές τις δυνατότητες μόνο μετά από ρητή συγκατάθεση του χρήστη, ενισχύοντας έτσι την ιδιωτικότητα και τον έλεγχο των προσωπικών δεδομένων.

{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Οι περιορισμοί εκκίνησης στο macOS είναι μια λειτουργία ασφαλείας για να **ρυθμίζουν την εκκίνηση διαδικασιών** καθορίζοντας **ποιος μπορεί να εκκινήσει** μια διαδικασία, **πώς** και **από πού**. Εισήχθη στο macOS Ventura, κατηγοριοποιούν τα συστήματα δυαδικών αρχείων σε κατηγορίες περιορισμών μέσα σε μια **cache εμπιστοσύνης**. Κάθε εκτελέσιμο δυαδικό αρχείο έχει καθορισμένους **κανόνες** για την **εκκίνηση** του, συμπεριλαμβανομένων των **self**, **parent** και **responsible** περιορισμών. Επεκτάθηκε σε εφαρμογές τρίτων ως **Environment** Constraints στο macOS Sonoma, αυτές οι δυνατότητες βοηθούν στη μείωση πιθανών εκμεταλλεύσεων του συστήματος ρυθμίζοντας τις συνθήκες εκκίνησης διαδικασιών.

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Το Malware Removal Tool (MRT) είναι άλλο ένα μέρος της υποδομής ασφαλείας του macOS. Όπως υποδηλώνει το όνομα, η κύρια λειτουργία του MRT είναι να **αφαιρεί γνωστό κακόβουλο λογισμικό από μολυσμένα συστήματα**.

Μόλις ανιχνευθεί κακόβουλο λογισμικό σε ένα Mac (είτε από το XProtect είτε με κάποιο άλλο τρόπο), το MRT μπορεί να χρησιμοποιηθεί για να **αφαιρέσει αυτόματα το κακόβουλο λογισμικό**. Το MRT λειτουργεί σιωπηλά στο παρασκήνιο και συνήθως εκτελείται κάθε φορά που το σύστημα ενημερώνεται ή όταν κατεβαίνει μια νέα ορισμός κακόβουλου λογισμικού (φαίνεται ότι οι κανόνες που έχει το MRT για την ανίχνευση κακόβουλου λογισμικού είναι μέσα στο δυαδικό αρχείο).

Ενώ τόσο το XProtect όσο και το MRT είναι μέρος των μέτρων ασφαλείας του macOS, εκτελούν διαφορετικές λειτουργίες:

- **XProtect** είναι ένα προληπτικό εργαλείο. **Ελέγχει τα αρχεία καθώς κατεβαίνουν** (μέσω ορισμένων εφαρμογών), και αν ανιχνεύσει οποιοδήποτε γνωστό τύπο κακόβουλου λογισμικού, **αποτρέπει το άνοιγμα του αρχείου**, αποτρέποντας έτσι το κακόβουλο λογισμικό από το να μολύνει το σύστημα σας εξαρχής.
- **MRT**, από την άλλη πλευρά, είναι ένα **αντιδραστικό εργαλείο**. Λειτουργεί αφού έχει ανιχνευθεί κακόβουλο λογισμικό σε ένα σύστημα, με στόχο την αφαίρεση του ενοχλητικού λογισμικού για να καθαρίσει το σύστημα.

Η εφαρμογή MRT βρίσκεται στο **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** τώρα **ειδοποιεί** κάθε φορά που ένα εργαλείο χρησιμοποιεί μια γνωστή **τεχνική για τη διατήρηση της εκτέλεσης κώδικα** (όπως τα Login Items, Daemons...), ώστε ο χρήστης να γνωρίζει καλύτερα **ποιο λογισμικό διατηρείται**.

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Αυτό λειτουργεί με έναν **daemon** που βρίσκεται στο `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` και τον **agent** στο `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Ο τρόπος που **`backgroundtaskmanagementd`** γνωρίζει ότι κάτι είναι εγκατεστημένο σε έναν μόνιμο φάκελο είναι μέσω της **λήψης των FSEvents** και της δημιουργίας ορισμένων **handlers** για αυτά.

Επιπλέον, υπάρχει ένα αρχείο plist που περιέχει **γνωστές εφαρμογές** που διατηρούνται συχνά από την Apple και βρίσκεται στο: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
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

Είναι δυνατόν να **καταμετρήσετε όλα** τα ρυθμισμένα στοιχεία παρασκηνίου που εκτελούνται με το εργαλείο cli της Apple:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Επιπλέον, είναι επίσης δυνατό να καταχωρήσετε αυτές τις πληροφορίες με το [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Αυτές οι πληροφορίες αποθηκεύονται στο **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** και το Terminal χρειάζεται FDA.

### Παρεμβαίνοντας στο BTM

Όταν βρεθεί μια νέα επιμονή, δημιουργείται ένα γεγονός τύπου **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Έτσι, οποιοσδήποτε τρόπος για να **αποτραπεί** αυτή η **εκδήλωση** από το να σταλεί ή ο **πράκτορας από το να ειδοποιήσει** τον χρήστη θα βοηθήσει έναν επιτιθέμενο να _**παρακάμψει**_ το BTM.

- **Επαναφορά της βάσης δεδομένων**: Η εκτέλεση της παρακάτω εντολής θα επαναφέρει τη βάση δεδομένων (θα πρέπει να την ξαναχτίσει από την αρχή), ωστόσο, για κάποιο λόγο, μετά την εκτέλεση αυτού, **καμία νέα επιμονή δεν θα ειδοποιηθεί μέχρι να επανεκκινήσει το σύστημα**.
- Απαιτείται **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Σταματήστε τον Πράκτορα**: Είναι δυνατόν να στείλετε ένα σήμα διακοπής στον πράκτορα ώστε να **μην ειδοποιεί τον χρήστη** όταν εντοπίζονται νέες ανιχνεύσεις.
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
- **Σφάλμα**: Αν η **διαδικασία που δημιούργησε την επιμονή υπάρχει γρήγορα αμέσως μετά από αυτήν**, ο δαίμονας θα προσπαθήσει να **λάβει πληροφορίες** γι' αυτήν, **θα αποτύχει**, και **δεν θα μπορέσει να στείλει το γεγονός** που υποδεικνύει ότι ένα νέο πράγμα επιμένει.

Αναφορές και **περισσότερες πληροφορίες σχετικά με το BTM**:

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
