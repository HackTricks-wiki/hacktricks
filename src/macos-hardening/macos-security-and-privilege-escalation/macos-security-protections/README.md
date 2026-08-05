# Προστασίες ασφαλείας του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Ο όρος Gatekeeper χρησιμοποιείται συνήθως για να αναφερθεί στον συνδυασμό των **Quarantine + Gatekeeper + XProtect**, 3 security modules του macOS που προσπαθούν να **εμποδίσουν τους χρήστες να εκτελέσουν δυνητικά κακόβουλο λογισμικό που έχει ληφθεί**.

Περισσότερες πληροφορίες στο:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Περιορισμοί διεργασιών

### MACF

### SIP - Προστασία ακεραιότητας συστήματος


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

Το MacOS Sandbox **περιορίζει τις εφαρμογές** που εκτελούνται μέσα στο sandbox στις **επιτρεπόμενες ενέργειες που καθορίζονται στο Sandbox profile** με το οποίο εκτελείται η εφαρμογή. Αυτό βοηθά να διασφαλιστεί ότι **η εφαρμογή θα έχει πρόσβαση μόνο στους αναμενόμενους πόρους**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

Το **TCC (Transparency, Consent, and Control)** είναι ένα security framework. Έχει σχεδιαστεί για να **διαχειρίζεται τα permissions** των εφαρμογών, ρυθμίζοντας συγκεκριμένα την πρόσβασή τους σε ευαίσθητες λειτουργίες. Σε αυτές περιλαμβάνονται στοιχεία όπως οι **υπηρεσίες τοποθεσίας, οι επαφές, οι φωτογραφίες, το microphone, η camera, η accessibility και η full disk access**. Το TCC διασφαλίζει ότι οι εφαρμογές μπορούν να έχουν πρόσβαση σε αυτές τις λειτουργίες μόνο αφού λάβουν ρητή συγκατάθεση από τον χρήστη, ενισχύοντας έτσι το privacy και τον έλεγχο των προσωπικών δεδομένων.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Τα launch constraints στο macOS είναι ένα security feature που **ρυθμίζει την εκκίνηση διεργασιών**, καθορίζοντας **ποιος μπορεί να εκκινήσει** μια διεργασία, **πώς** και **από πού**. Παρουσιάστηκαν στο macOS Ventura και κατηγοριοποιούν τα system binaries σε κατηγορίες constraints μέσα σε ένα **trust cache**. Κάθε executable binary διαθέτει συγκεκριμένους **κανόνες** για το **launch** του, συμπεριλαμβανομένων των constraints **self**, **parent** και **responsible**. Επεκτάθηκαν σε third-party apps ως **Environment Constraints** στο macOS Sonoma. Αυτές οι δυνατότητες βοηθούν στον περιορισμό πιθανών system exploitations, ελέγχοντας τις συνθήκες υπό τις οποίες γίνεται το process launching.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Το Malware Removal Tool (MRT) αποτελεί ένα ακόμη μέρος της security infrastructure του macOS. Όπως υποδηλώνει και το όνομά του, η κύρια λειτουργία του MRT είναι να **αφαιρεί γνωστό malware από μολυσμένα συστήματα**.

Μόλις εντοπιστεί malware σε έναν Mac (είτε από το XProtect είτε με κάποιο άλλο τρόπο), το MRT μπορεί να χρησιμοποιηθεί για την αυτόματη **αφαίρεση του malware**. Το MRT λειτουργεί αθόρυβα στο background και συνήθως εκτελείται κάθε φορά που ενημερώνεται το σύστημα ή όταν γίνεται λήψη ενός νέου malware definition (φαίνεται ότι οι κανόνες που χρησιμοποιεί το MRT για τον εντοπισμό malware βρίσκονται μέσα στο binary).

Παρότι τόσο το XProtect όσο και το MRT αποτελούν μέρη των security measures του macOS, εκτελούν διαφορετικές λειτουργίες:

- Το **XProtect** είναι ένα preventative tool. **Ελέγχει τα αρχεία κατά τη λήψη τους** (μέσω συγκεκριμένων εφαρμογών) και, αν εντοπίσει γνωστούς τύπους malware, **εμποδίζει το άνοιγμα του αρχείου**, αποτρέποντας έτσι εξαρχής τη μόλυνση του συστήματός σας από το malware.
- Το **MRT**, από την άλλη, είναι ένα **reactive tool**. Λειτουργεί αφού έχει εντοπιστεί malware σε ένα σύστημα, με στόχο την αφαίρεση του offending software για τον καθαρισμό του συστήματος.

Η εφαρμογή MRT βρίσκεται στη διεύθυνση **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Διαχείριση Background Tasks

Το **macOS** πλέον **ειδοποιεί** κάθε φορά που ένα tool χρησιμοποιεί μια γνωστή **technique για persistence του code execution** (όπως Login Items, Daemons...), ώστε ο χρήστης να γνωρίζει καλύτερα **ποιο software κάνει persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Αυτό εκτελείται με ένα **daemon** που βρίσκεται στη διεύθυνση `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` και τον **agent** στη διεύθυνση `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Ο τρόπος με τον οποίο το **`backgroundtaskmanagementd`** γνωρίζει ότι κάτι έχει εγκατασταθεί σε έναν persistent folder είναι μέσω της **λήψης των FSEvents** και της δημιουργίας ορισμένων **handlers** για αυτά.<sup>[[1]](#references)</sup>

Επιπλέον, υπάρχει ένα plist file που περιέχει **γνωστές εφαρμογές** οι οποίες κάνουν συχνά persistence, συντηρείται από την Apple και βρίσκεται στη διεύθυνση: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Είναι δυνατή η **enumerate όλων** των ρυθμισμένων background items που εκτελούνται, χρησιμοποιώντας το Apple cli tool:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Επιπλέον, είναι επίσης δυνατή η απαρίθμηση αυτών των πληροφοριών με το [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Αυτές οι πληροφορίες αποθηκεύονται στο **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** και το Terminal χρειάζεται FDA.<sup>[[2]](#references)</sup>

### Παρέμβαση στο BTM

Όταν εντοπίζεται ένα νέο persistence, δημιουργείται ένα event τύπου **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Επομένως, οποιοσδήποτε τρόπος **αποτροπής** της αποστολής αυτού του **event** ή **παρεμπόδισης της ειδοποίησης** του χρήστη από τον **agent** θα βοηθήσει έναν attacker να _**παρακάμψει**_ το BTM.<sup>[[1]](#references)</sup>

- **Επαναφορά της βάσης δεδομένων**: Η εκτέλεση της ακόλουθης εντολής θα επαναφέρει τη βάση δεδομένων (θα πρέπει να τη δημιουργήσει ξανά από την αρχή). Ωστόσο, για κάποιο λόγο, μετά την εκτέλεσή της, **δεν θα ειδοποιηθεί κανένα νέο persistence μέχρι να γίνει επανεκκίνηση του συστήματος**.<sup>[[1]](#references)</sup>
- Απαιτούνται δικαιώματα **root**.
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
- **Σφάλμα**: Αν η **process που δημιούργησε το persistence τερματιστεί αμέσως μετά**, ο daemon θα προσπαθήσει να **λάβει πληροφορίες** γι' αυτήν, θα **αποτύχει** και **δεν θα μπορέσει να στείλει το event** που υποδεικνύει ότι ένα νέο στοιχείο κάνει persistence.<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [OBTS v6.0: "Απομυθοποίηση (& Παράκαμψη) του macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Νέο (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Διαχείριση login items και background tasks σε Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
