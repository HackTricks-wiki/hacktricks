# Περιορισμοί Launch/Environment του macOS & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Οι launch constraints στο macOS εισήχθησαν για την ενίσχυση της ασφάλειας, **ρυθμίζοντας πώς, από ποιον και από πού μπορεί να ξεκινήσει μια διεργασία**. Παρουσιάστηκαν στο macOS Ventura και παρέχουν ένα framework που κατηγοριοποιεί **κάθε system binary σε ξεχωριστές κατηγορίες περιορισμών**, οι οποίες ορίζονται μέσα στο **trust cache**, μια λίστα που περιέχει system binaries και τα αντίστοιχα hashes τους. Αυτοί οι περιορισμοί επεκτείνονται σε κάθε executable binary του συστήματος και περιλαμβάνουν ένα σύνολο από **κανόνες** που καθορίζουν τις απαιτήσεις για την **εκκίνηση ενός συγκεκριμένου binary**. Οι κανόνες περιλαμβάνουν self constraints που πρέπει να ικανοποιεί ένα binary, parent constraints που πρέπει να ικανοποιεί η parent process του και responsible constraints που πρέπει να τηρούνται από άλλες σχετικές οντότητες.

Ο μηχανισμός επεκτείνεται σε third-party apps μέσω των **Environment Constraints**, ξεκινώντας από το macOS Sonoma, επιτρέποντας στους developers να προστατεύουν τις εφαρμογές τους καθορίζοντας ένα **σύνολο από keys και values για environment constraints.**

Ορίζετε **launch environment και library constraints** σε constraint dictionaries, τα οποία είτε αποθηκεύετε σε **`launchd` property list files**, είτε σε **ξεχωριστά property list** files που χρησιμοποιείτε στο code signing.

Υπάρχουν 4 τύποι constraints:

- **Self Constraints**: Constraints που εφαρμόζονται στο **running** binary.
- **Parent Process**: Constraints που εφαρμόζονται στον **parent της διεργασίας** (για παράδειγμα το **`launchd`** που εκτελεί μια XP service)
- **Responsible Constraints**: Constraints που εφαρμόζονται στη **διεργασία που καλεί τη service** σε μια επικοινωνία XPC
- **Library load constraints**: Χρησιμοποιήστε library load constraints για να περιγράψετε επιλεκτικά τον κώδικα που μπορεί να φορτωθεί

Έτσι, όταν μια διεργασία προσπαθεί να εκκινήσει μια άλλη διεργασία — καλώντας `execve(_:_:_:)` ή `posix_spawn(_:_:_:_:_:_:)` — το operating system ελέγχει ότι το **executable** file **ικανοποιεί το δικό του self constraint**. Ελέγχει επίσης ότι το executable της **parent** **process** **ικανοποιεί το parent constraint** του executable και ότι το executable της **responsible** **process** **ικανοποιεί το responsible process constraint** του executable. Αν οποιοσδήποτε από αυτούς τους launch constraints δεν ικανοποιείται, το operating system δεν εκτελεί το πρόγραμμα.

Αν, κατά τη φόρτωση μιας library, οποιοδήποτε μέρος του **library constraint δεν είναι αληθές**, η process σας **δεν φορτώνει** τη library.

## LC Categories

Ένα LC αποτελείται από **facts** και **logical operations** (and, or..) που συνδυάζουν facts.

Τα[ **facts που μπορεί να χρησιμοποιήσει ένα LC τεκμηριώνονται**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Για παράδειγμα:

- is-init-proc: Μια Boolean τιμή που υποδεικνύει αν το executable πρέπει να είναι η initialization process του operating system (`launchd`).
- is-sip-protected: Μια Boolean τιμή που υποδεικνύει αν το executable πρέπει να είναι ένα file που προστατεύεται από το System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Μια Boolean τιμή που υποδεικνύει αν το operating system φόρτωσε το executable από ένα authorized, authenticated APFS volume.
- `on-authorized-authapfs-volume`: Μια Boolean τιμή που υποδεικνύει αν το operating system φόρτωσε το executable από ένα authorized, authenticated APFS volume.
- Cryptexes volume
- `on-system-volume:`Μια Boolean τιμή που υποδεικνύει αν το operating system φόρτωσε το executable από το system volume από το οποίο έγινε το τρέχον boot.
- Inside /System...
- ...

Όταν γίνεται sign ένα Apple binary, **το αντιστοιχίζει σε μια κατηγορία LC** μέσα στο **trust cache**.

- Οι **LC categories του iOS 16** [**αναλύθηκαν αντίστροφα και τεκμηριώθηκαν εδώ**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- Οι τρέχουσες **LC categories (macOS 14** - Somona) έχουν αναλυθεί αντίστροφα και οι [**περιγραφές τους βρίσκονται εδώ**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

Για παράδειγμα, η Category 1 είναι:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Πρέπει να βρίσκεται στο System ή στο Cryptexes volume.
- `launch-type == 1`: Πρέπει να είναι system service (plist στο LaunchDaemons).
- `validation-category == 1`: Εκτελέσιμο του λειτουργικού συστήματος.
- `is-init-proc`: Launchd

### Reversing LC Categories

Μπορείτε να βρείτε περισσότερες πληροφορίες [**εδώ**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), αλλά βασικά, ορίζονται στο **AMFI (AppleMobileFileIntegrity)**, επομένως πρέπει να κατεβάσετε το Kernel Development Kit για να λάβετε το **KEXT**. Τα symbols που ξεκινούν με **`kConstraintCategory`** είναι τα **ενδιαφέροντα**. Με την εξαγωγή τους θα λάβετε ένα stream κωδικοποιημένο σε DER (ASN.1), το οποίο θα πρέπει να αποκωδικοποιήσετε με το [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ή με τη βιβλιοθήκη python-asn1 και το script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), το οποίο θα σας δώσει ένα πιο κατανοητό string.<sup>[3]</sup>

## Περιορισμοί Περιβάλλοντος

Αυτοί είναι οι Launch Constraints που έχουν ρυθμιστεί σε **third party applications**. Ο developer μπορεί να επιλέξει τα **facts** και τα **logical operands** που θα χρησιμοποιηθούν στην εφαρμογή του, ώστε να περιορίσει την πρόσβαση σε αυτήν.

Είναι δυνατή η απαρίθμηση των Environment Constraints μιας εφαρμογής με:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

Στο **macOS** υπάρχουν μερικά trust caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Και στο iOS φαίνεται ότι βρίσκεται στο **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Σε macOS που εκτελείται σε συσκευές Apple Silicon, αν ένα binary υπογεγραμμένο από την Apple δεν βρίσκεται στο trust cache, το AMFI θα αρνηθεί να το φορτώσει.

### Enumerating Trust Caches

Τα προηγούμενα αρχεία trust cache είναι σε format **IMG4** και **IM4P**, με το IM4P να αποτελεί το payload section ενός format IMG4.

Μπορείτε να χρησιμοποιήσετε το [**pyimg4**](https://github.com/m1stadev/PyIMG4) για να κάνετε extract το payload των databases:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Μια άλλη επιλογή θα ήταν να χρησιμοποιήσετε το εργαλείο [**img4tool**](https://github.com/tihmstar/img4tool), το οποίο θα εκτελεστεί ακόμη και σε M1, παρόλο που το release είναι παλιό, καθώς και σε x86_64, εάν το εγκαταστήσετε στις σωστές τοποθεσίες).

Τώρα μπορείτε να χρησιμοποιήσετε το εργαλείο [**trustcache**](https://github.com/CRKatri/trustcache) για να λάβετε τις πληροφορίες σε αναγνώσιμη μορφή:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Το trust cache ακολουθεί την ακόλουθη δομή, επομένως η **κατηγορία LC είναι η 4η στήλη**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Έπειτα, θα μπορούσες να χρησιμοποιήσεις ένα script όπως [**αυτό**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) για την εξαγωγή δεδομένων.

Από αυτά τα δεδομένα μπορείς να ελέγξεις τις εφαρμογές με **τιμή launch constraints `0`**, οι οποίες είναι αυτές που δεν υπόκεινται σε περιορισμούς ([**δείτε εδώ**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) για τη σημασία κάθε τιμής).<sup>[6]</sup>

## Mitigations επιθέσεων

Τα Launch Constraints θα είχαν μετριάσει αρκετές παλιές επιθέσεις, **διασφαλίζοντας ότι η διεργασία δεν θα εκτελείται υπό απρόβλεπτες συνθήκες:** για παράδειγμα, από απρόβλεπτες τοποθεσίες ή μέσω invocation από ένα απρόβλεπτο parent process (αν μόνο το launchd θα έπρεπε να την εκκινεί).

Επιπλέον, τα Launch Constraints **μετριάζουν και τα downgrade attacks.**

Ωστόσο, **δεν μετριάζουν τα συνηθισμένα XPC** abuses, τα code injections σε **Electron** ή τα **dylib injections** χωρίς library validation (εκτός αν είναι γνωστά τα team IDs που μπορούν να φορτώσουν libraries).<sup>[3]</sup>

### Προστασία XPC Daemon

Στην έκδοση Sonoma, ένα αξιοσημείωτο σημείο είναι η **responsibility configuration** της υπηρεσίας XPC daemon. Η υπηρεσία XPC είναι υπεύθυνη για τον εαυτό της, σε αντίθεση με τον connecting client, ο οποίος είναι υπεύθυνος. Αυτό τεκμηριώνεται στο feedback report FB13206884. Αυτή η ρύθμιση μπορεί να φαίνεται ελαττωματική, καθώς επιτρέπει ορισμένες αλληλεπιδράσεις με την υπηρεσία XPC:

- **Εκκίνηση της υπηρεσίας XPC**: Αν θεωρηθεί bug, αυτή η ρύθμιση δεν επιτρέπει την εκκίνηση της υπηρεσίας XPC μέσω attacker code.
- **Σύνδεση σε ενεργή υπηρεσία**: Αν η υπηρεσία XPC εκτελείται ήδη (πιθανώς επειδή ενεργοποιήθηκε από την αρχική της εφαρμογή), δεν υπάρχουν εμπόδια για τη σύνδεση σε αυτήν.

Παρότι η εφαρμογή constraints στην υπηρεσία XPC μπορεί να είναι χρήσιμη, **περιορίζοντας το χρονικό παράθυρο πιθανών επιθέσεων**, δεν αντιμετωπίζει το βασικό ζήτημα. Η διασφάλιση της ασφάλειας της υπηρεσίας XPC απαιτεί θεμελιωδώς **την αποτελεσματική επικύρωση του connecting client**. Αυτή παραμένει η μοναδική μέθοδος ενίσχυσης της ασφάλειας της υπηρεσίας. Επίσης, αξίζει να σημειωθεί ότι η προαναφερθείσα responsibility configuration είναι επί του παρόντος ενεργή, κάτι που μπορεί να μην συμφωνεί με τον προβλεπόμενο σχεδιασμό.<sup>[3]</sup>

### Προστασία Electron

Ακόμη και αν απαιτείται η εφαρμογή να έχει **ανοιχτεί από το LaunchService** (στο parents constraints), αυτό μπορεί να επιτευχθεί με τη χρήση του **`open`** (το οποίο μπορεί να ορίσει env variables) ή μέσω του **Launch Services API** (όπου μπορούν να καθοριστούν env variables).<sup>[3]</sup>

### CVE-2025-43253 - Παράκαμψη των ενσωματωμένων constraints κατά το spawn time

Τα Launch constraints (επισήμως **lightweight code requirements**, *LWCR*) επιβάλλονται από την **AMFI MAC policy**. Το `posix_spawn` επιτρέπει σε έναν caller να περάσει ένα αυθαίρετο blob σε μια MAC policy μέσω του **`posix_spawnattr_setmacpolicyinfo_np()`**, και η AMFI αποδεχόταν ένα LWCR dictionary που παρεχόταν από τον caller μέσω αυτής της διαδρομής. Το bug ήταν ότι τα **constraints που παρείχε ο attacker αντικαθιστούσαν τα ενσωματωμένα constraints του binary**, αντί να ελέγχονται επιπλέον αυτών:

- Δημιουργία ενός minimal (ακόμη και κενού) launch-constraints dictionary.
- Ορισμός του **constraint category σε `127`**, μια τιμή που η AMFI επιτρέπει στα spawn attributes αλλά **δεν επιβάλλει** — καταγράφει μόνο `Launch Constraint Violation (not enforcing)` αντί να μπλοκάρει την εκτέλεση.
- Μεταβίβασή του μέσω των spawn attributes, ώστε η διεργασία να εκκινήσει σε context όπου τα πραγματικά self/parent constraints θα το είχαν απαγορεύσει.

Μετά το fix, επικυρώνονται **τόσο τα ενσωματωμένα όσο και τα παρεχόμενα constraints**, επομένως το παρεχόμενο dictionary δεν μπορεί πλέον να αποδυναμώσει το ενσωματωμένο.<sup>[2]</sup>

> [!TIP]
> Αυτή είναι η γενική μορφή που πρέπει να αναζητάτε κατά τον έλεγχο της επιβολής constraints: ένα API που επιτρέπει σε untrusted input να *παρέχει* μια policy είναι συνήθως ενδιαφέρον, όταν το policy engine αντιμετωπίζει την παρεχόμενη τιμή ως αντικατάσταση αντί για πρόσθετη απαίτηση.

## Αναφορές

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Παράκαμψη των Launch Constraints στο macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Αναλυτική παρουσίαση των Launch και Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Γιατί δεν εκτελείται μια system app ή command tool; Launch constraints και trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Προστατέψτε τη Mac app σας με environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Περιγραφή των Launch Constraints που εισήχθησαν στο iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
