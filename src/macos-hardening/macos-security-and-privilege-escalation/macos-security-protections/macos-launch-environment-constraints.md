# Περιορισμοί Launch/Environment του macOS & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Οι launch constraints στο macOS εισήχθησαν για την ενίσχυση της ασφάλειας, **ρυθμίζοντας το πώς, από ποιον και από πού μπορεί να εκκινηθεί μια διεργασία**. Ξεκινώντας από το macOS Ventura, παρέχουν ένα framework που κατηγοριοποιεί **κάθε system binary σε ξεχωριστές κατηγορίες constraints**, οι οποίες ορίζονται μέσα στο **trust cache**, μια λίστα που περιέχει system binaries και τα αντίστοιχα hashes τους. Αυτά τα constraints επεκτείνονται σε κάθε executable binary του συστήματος και περιλαμβάνουν ένα σύνολο από **κανόνες** που καθορίζουν τις απαιτήσεις για την **εκκίνηση ενός συγκεκριμένου binary**. Οι κανόνες περιλαμβάνουν self constraints που πρέπει να ικανοποιεί ένα binary, parent constraints που πρέπει να πληροί το parent process του και responsible constraints που πρέπει να τηρούνται από άλλες σχετικές οντότητες.<sup>[[1]](#references)[[4]](#references)</sup>

Ο μηχανισμός επεκτείνεται σε third-party apps μέσω των **Environment Constraints**, ξεκινώντας από το macOS Sonoma, επιτρέποντας στους developers να προστατεύουν τις εφαρμογές τους καθορίζοντας ένα **σύνολο από keys και values για environment constraints.**<sup>[[5]](#references)</sup>

Ορίζετε **launch environment και library constraints** σε constraint dictionaries, τα οποία είτε αποθηκεύετε σε **`launchd` property list files** είτε σε **ξεχωριστά property list** files που χρησιμοποιείτε στο code signing.<sup>[[5]](#references)</sup>

Υπάρχουν 4 τύποι constraints:

- **Self Constraints**: Constraints που εφαρμόζονται στο **running** binary.
- **Parent Process**: Constraints που εφαρμόζονται στο **parent του process** (για παράδειγμα το **`launchd`** που εκτελεί ένα XP service)
- **Responsible Constraints**: Constraints που εφαρμόζονται στο **process που καλεί το service** σε μια XPC communication
- **Library load constraints**: Χρησιμοποιήστε library load constraints για να περιγράψετε επιλεκτικά κώδικα που μπορεί να φορτωθεί

Όταν ένα process προσπαθεί να εκκινήσει ένα άλλο process — καλώντας τις `execve(_:_:_:)` ή `posix_spawn(_:_:_:_:_:_:)` — το operating system ελέγχει ότι το **executable** file **ικανοποιεί το δικό του self constraint**. Ελέγχει επίσης ότι το executable του **parent process** **ικανοποιεί το parent constraint** του executable και ότι το executable του **responsible process** **ικανοποιεί το responsible process constraint** του executable. Αν οποιοδήποτε από αυτά τα launch constraints δεν ικανοποιείται, το operating system δεν εκτελεί το πρόγραμμα.

Αν, κατά τη φόρτωση μιας library, οποιοδήποτε μέρος του **library constraint δεν είναι αληθές**, το process σας **δεν φορτώνει** τη library.

## Κατηγορίες LC

Ένα LC αποτελείται από **facts** και **logical operations** (and, or κ.λπ.) που συνδυάζουν facts.

Τα[ **facts που μπορεί να χρησιμοποιήσει ένα LC τεκμηριώνονται**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Για παράδειγμα:

- is-init-proc: Μια Boolean value που υποδεικνύει αν το executable πρέπει να είναι το initialization process του operating system (`launchd`).
- is-sip-protected: Μια Boolean value που υποδεικνύει αν το executable πρέπει να είναι file προστατευμένο από το System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Μια Boolean value που υποδεικνύει αν το operating system φόρτωσε το executable από authorized, authenticated APFS volume.
- `on-authorized-authapfs-volume`: Μια Boolean value που υποδεικνύει αν το operating system φόρτωσε το executable από authorized, authenticated APFS volume.
- Cryptexes volume
- `on-system-volume:`Μια Boolean value που υποδεικνύει αν το operating system φόρτωσε το executable από το currently-booted system volume.
- Μέσα στο /System...
- ...

Όταν ένα Apple binary γίνεται signed, **το αντιστοιχίζει σε μια LC category** μέσα στο **trust cache**.

- Οι **iOS 16 LC categories** [**έγιναν reverse και τεκμηριώθηκαν εδώ**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Οι τρέχουσες **LC categories (macOS 14** - Somona) έχουν γίνει reverse και οι [**περιγραφές τους βρίσκονται εδώ**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Για παράδειγμα, η Category 1 είναι:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Πρέπει να βρίσκεται στο System ή στο Cryptexes volume.
- `launch-type == 1`: Πρέπει να είναι system service (plist στο LaunchDaemons).
- `validation-category == 1`: Ένα εκτελέσιμο αρχείο του operating system.
- `is-init-proc`: Launchd

### Αντίστροφη ανάλυση των κατηγοριών LC

Μπορείτε να βρείτε περισσότερες πληροφορίες [**εδώ**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), αλλά βασικά, ορίζονται στο **AMFI (AppleMobileFileIntegrity)**, επομένως πρέπει να κατεβάσετε το Kernel Development Kit για να λάβετε το **KEXT**. Τα σύμβολα που ξεκινούν με **`kConstraintCategory`** είναι τα **ενδιαφέροντα**. Με την εξαγωγή τους θα λάβετε ένα κωδικοποιημένο σε DER (ASN.1) stream, το οποίο θα χρειαστεί να αποκωδικοποιήσετε με το [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ή με τη βιβλιοθήκη python-asn1 και το script `dump.py` της [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), το οποίο θα σας δώσει ένα πιο κατανοητό string.<sup>[[3]](#references)[[8]](#references)</sup>

## Περιορισμοί Περιβάλλοντος

Αυτοί είναι οι Launch Constraints που έχουν ρυθμιστεί σε **third party applications**. Ο developer μπορεί να επιλέξει τα **facts** και τους **λογικούς τελεστές** που θα χρησιμοποιηθούν στην εφαρμογή του, ώστε να περιορίσει την πρόσβαση σε αυτήν.

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
(Μια άλλη επιλογή θα μπορούσε να είναι η χρήση του εργαλείου [**img4tool**](https://github.com/tihmstar/img4tool), το οποίο θα εκτελεστεί ακόμη και σε M1, παρότι το release είναι παλιό, καθώς και σε x86_64, αν το εγκαταστήσετε στις κατάλληλες τοποθεσίες).

Τώρα μπορείτε να χρησιμοποιήσετε το εργαλείο [**trustcache**](https://github.com/CRKatri/trustcache) για να λάβετε τις πληροφορίες σε ευανάγνωστη μορφή:
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
Το trust cache ακολουθεί την παρακάτω δομή, επομένως η **κατηγορία LC είναι η 4η στήλη**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Στη συνέχεια, θα μπορούσατε να χρησιμοποιήσετε ένα script όπως [**αυτό εδώ**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) για την εξαγωγή δεδομένων.

Από αυτά τα δεδομένα μπορείτε να ελέγξετε τις Apps με **τιμή launch constraints ίση με `0`**, οι οποίες είναι εκείνες που δεν υπόκεινται σε περιορισμούς (δείτε [**εδώ**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) τι σημαίνει κάθε τιμή).<sup>[[6]](#references)</sup>

## Mitigations επιθέσεων

Τα Launch Constraints θα είχαν μετριάσει αρκετές παλιές επιθέσεις, **διασφαλίζοντας ότι η διεργασία δεν θα εκτελείται υπό απρόβλεπτες συνθήκες:** Για παράδειγμα, από απρόβλεπτες τοποθεσίες ή μέσω κλήσης από μια μη αναμενόμενη parent process (αν υποτίθεται ότι θα την εκκινούσε μόνο το launchd).

Επιπλέον, τα Launch Constraints **μετριάζουν και τις downgrade attacks.**

Ωστόσο, **δεν μετριάζουν τα συνηθισμένα XPC** abuses, τα **Electron** code injections ή τα **dylib injections** χωρίς library validation (εκτός αν είναι γνωστά τα team IDs που μπορούν να φορτώσουν libraries).<sup>[[3]](#references)</sup>

### Προστασία XPC Daemon

Στην έκδοση Sonoma, ένα αξιοσημείωτο σημείο είναι η **διαμόρφωση responsibility** της υπηρεσίας XPC daemon. Η υπηρεσία XPC είναι υπεύθυνη για τον εαυτό της, σε αντίθεση με τον connecting client, ο οποίος είναι υπεύθυνος. Αυτό τεκμηριώνεται στην αναφορά feedback FB13206884. Αυτή η ρύθμιση μπορεί να φαίνεται προβληματική, καθώς επιτρέπει ορισμένες αλληλεπιδράσεις με την υπηρεσία XPC:

- **Εκκίνηση της υπηρεσίας XPC**: Αν θεωρηθεί bug, αυτή η ρύθμιση δεν επιτρέπει την εκκίνηση της υπηρεσίας XPC μέσω attacker code.
- **Σύνδεση σε ενεργή υπηρεσία**: Αν η υπηρεσία XPC εκτελείται ήδη (πιθανώς επειδή ενεργοποιήθηκε από την αρχική της εφαρμογή), δεν υπάρχουν εμπόδια στη σύνδεση με αυτήν.

Παρόλο που η εφαρμογή constraints στην υπηρεσία XPC μπορεί να είναι χρήσιμη, **περιορίζοντας το παράθυρο για πιθανές επιθέσεις**, δεν αντιμετωπίζει την κύρια ανησυχία. Για να διασφαλιστεί η ασφάλεια της υπηρεσίας XPC, απαιτείται ουσιαστικά **η αποτελεσματική επικύρωση του connecting client**. Αυτή παραμένει η μοναδική μέθοδος ενίσχυσης της ασφάλειας της υπηρεσίας. Αξίζει επίσης να σημειωθεί ότι η προαναφερθείσα διαμόρφωση responsibility είναι επί του παρόντος ενεργή, κάτι που μπορεί να μην συμφωνεί με τον προβλεπόμενο σχεδιασμό.<sup>[[3]](#references)</sup>

### Προστασία Electron

Ακόμη και αν απαιτείται η εφαρμογή να **ανοίγεται από το LaunchService** (στους parents constraints), αυτό μπορεί να επιτευχθεί χρησιμοποιώντας το **`open`** (το οποίο μπορεί να ορίσει env variables) ή το **Launch Services API** (όπου μπορούν να καθοριστούν env variables).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Παράκαμψη των ενσωματωμένων constraints κατά το spawn

Τα launch constraints (επίσημα **lightweight code requirements**, *LWCR*) επιβάλλονται από το **AMFI MAC policy**. Το `posix_spawn` επιτρέπει σε έναν caller να παραδώσει ένα αυθαίρετο blob σε ένα MAC policy μέσω του **`posix_spawnattr_setmacpolicyinfo_np()`**, και το AMFI αποδεχόταν ένα LWCR dictionary που παρεχόταν από τον caller μέσω αυτής της διαδρομής. Το bug ήταν ότι τα **constraints που παρείχε ο attacker αντικαθιστούσαν τα ενσωματωμένα constraints του binary**, αντί να ελέγχονται επιπλέον αυτών:

- Δημιουργία ενός minimal (ακόμη και κενού) launch-constraints dictionary.
- Ορισμός του **constraint category σε `127`**, μια τιμή που το AMFI επιτρέπει στα spawn attributes αλλά **δεν επιβάλλει** — καταγράφει μόνο `Launch Constraint Violation (not enforcing)` αντί να εμποδίζει την εκτέλεση.
- Μεταβίβασή του μέσω των spawn attributes, ώστε η διεργασία να εκκινηθεί σε ένα context στο οποίο τα πραγματικά self/parent constraints θα το είχαν απαγορεύσει.

Μετά τη διόρθωση, επικυρώνονται **τόσο τα ενσωματωμένα όσο και τα παρεχόμενα constraints**, επομένως το παρεχόμενο dictionary δεν μπορεί πλέον να αποδυναμώσει το ενσωματωμένο.<sup>[[2]](#references)</sup>

> [!TIP]
> Αυτή είναι η γενική μορφή που πρέπει να αναζητάτε κατά τον έλεγχο της επιβολής constraints: ένα API που επιτρέπει σε untrusted input να *παρέχει* μια policy είναι συνήθως ενδιαφέρον, όταν το policy engine αντιμετωπίζει την παρεχόμενη τιμή ως αντικατάσταση αντί για πρόσθετη απαίτηση.

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Beyond the good ol` LaunchAgents - about it in here](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}
