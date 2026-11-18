# Περιορισμοί Launch/Environment του macOS και Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Οι περιορισμοί launch στο macOS εισήχθησαν για να ενισχύσουν την ασφάλεια **ρυθμίζοντας πώς, από ποιον και από πού μπορεί να εκκινηθεί μια διεργασία**. Παρουσιάστηκαν στο macOS Ventura και παρέχουν ένα πλαίσιο που κατατάσσει **κάθε system binary σε διακριτές κατηγορίες περιορισμών**, οι οποίες ορίζονται στο **trust cache** — μια λίστα που περιέχει system binaries και τα αντίστοιχα hashes τους. Αυτοί οι περιορισμοί ισχύουν για κάθε εκτελέσιμο binary του συστήματος και περιλαμβάνουν ένα σύνολο **κανόνων** που καθορίζουν τις απαιτήσεις για την **εκκίνηση ενός συγκεκριμένου binary**. Οι κανόνες περιλαμβάνουν self constraints που πρέπει να ικανοποιεί ένα binary, parent constraints που πρέπει να ικανοποιεί η γονική του διεργασία και responsible constraints που πρέπει να τηρούνται από άλλες σχετικές οντότητες.<sup>[[1]](#references)[[4]](#references)</sup>

Ο μηχανισμός επεκτείνεται σε εφαρμογές τρίτων μέσω των **Environment Constraints**, από το macOS Sonoma και μετά, επιτρέποντας στους developers να προστατεύουν τις εφαρμογές τους καθορίζοντας ένα **σύνολο από keys και values για τους environment constraints**.<sup>[[5]](#references)</sup>

Ορίζετε **περιορισμούς launch environment και library** σε dictionaries περιορισμών, τα οποία είτε αποθηκεύετε σε αρχεία property list του **`launchd`** είτε σε **ξεχωριστά αρχεία property list** που χρησιμοποιείτε κατά την υπογραφή κώδικα.<sup>[[5]](#references)</sup>

Υπάρχουν 4 τύποι περιορισμών:

- **Self Constraints**: Περιορισμοί που εφαρμόζονται στο **εκτελούμενο** binary.
- **Parent Process**: Περιορισμοί που εφαρμόζονται στη **γονική διεργασία** (για παράδειγμα, το **`launchd`** που εκτελεί μια υπηρεσία XP)
- **Responsible Constraints**: Περιορισμοί που εφαρμόζονται στη **διεργασία που καλεί την υπηρεσία** σε μια επικοινωνία XPC
- **Library load constraints**: Χρησιμοποιήστε library load constraints για να περιγράψετε επιλεκτικά τον κώδικα που μπορεί να φορτωθεί

Όταν, λοιπόν, μια διεργασία προσπαθεί να εκκινήσει μια άλλη διεργασία — καλώντας τα `execve(_:_:_:)` ή `posix_spawn(_:_:_:_:_:_:)` — το λειτουργικό σύστημα ελέγχει αν το **εκτελέσιμο** αρχείο **ικανοποιεί** το δικό του **self constraint**. Ελέγχει επίσης αν το εκτελέσιμο της **γονικής διεργασίας** **ικανοποιεί το parent constraint** του εκτελέσιμου και αν το εκτελέσιμο της **responsible διεργασίας** **ικανοποιεί το responsible process constraint** του εκτελέσιμου. Αν δεν ικανοποιείται οποιοσδήποτε από αυτούς τους launch constraints, το λειτουργικό σύστημα δεν εκτελεί το πρόγραμμα.

Αν, κατά τη φόρτωση μιας library, οποιοδήποτε μέρος του **library constraint δεν είναι αληθές**, η διεργασία σας **δεν φορτώνει** τη library.

## Κατηγορίες LC

Ένα LC αποτελείται από **facts** και **λογικές πράξεις** (and, or..) που συνδυάζουν facts.

Τα[ **facts που μπορεί να χρησιμοποιήσει ένα LC τεκμηριώνονται**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Για παράδειγμα:

- is-init-proc: Μια Boolean τιμή που υποδεικνύει αν το εκτελέσιμο πρέπει να είναι η διαδικασία αρχικοποίησης του λειτουργικού συστήματος (`launchd`).
- is-sip-protected: Μια Boolean τιμή που υποδεικνύει αν το εκτελέσιμο πρέπει να είναι αρχείο προστατευμένο από το System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Μια Boolean τιμή που υποδεικνύει αν το λειτουργικό σύστημα φόρτωσε το εκτελέσιμο από εξουσιοδοτημένο, πιστοποιημένο APFS volume.
- `on-authorized-authapfs-volume`: Μια Boolean τιμή που υποδεικνύει αν το λειτουργικό σύστημα φόρτωσε το εκτελέσιμο από εξουσιοδοτημένο, πιστοποιημένο APFS volume.
  - Cryptexes volume
- `on-system-volume:`Μια Boolean τιμή που υποδεικνύει αν το λειτουργικό σύστημα φόρτωσε το εκτελέσιμο από το system volume που έχει εκκινηθεί αυτήν τη στιγμή.
  - Μέσα στο /System...
- ...

Όταν υπογράφεται ένα Apple binary, **αντιστοιχίζεται σε μια κατηγορία LC** μέσα στο **trust cache**.

- Οι **κατηγορίες LC του iOS 16** [**έχουν γίνει reverse engineering και τεκμηριώνονται εδώ**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Οι τρέχουσες **κατηγορίες LC (macOS 14** - Somona) έχουν γίνει reverse engineering και οι [**περιγραφές τους βρίσκονται εδώ**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Για παράδειγμα, η Κατηγορία 1 είναι:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Πρέπει να βρίσκεται σε τόμο System ή Cryptexes.
- `launch-type == 1`: Πρέπει να είναι system service (plist στο LaunchDaemons).
- `validation-category == 1`: Εκτελέσιμο λειτουργικού συστήματος.
- `is-init-proc`: Launchd

### Αντίστροφη ανάλυση κατηγοριών LC

Μπορείτε να βρείτε περισσότερες πληροφορίες [**εδώ**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), αλλά, βασικά, ορίζονται στο **AMFI (AppleMobileFileIntegrity)**, επομένως θα χρειαστεί να κατεβάσετε το Kernel Development Kit για να αποκτήσετε το **KEXT**. Τα σύμβολα που ξεκινούν με **`kConstraintCategory`** είναι τα **ενδιαφέροντα**. Αν τα εξαγάγετε, θα λάβετε μια ροή κωδικοποιημένη σε DER (ASN.1), την οποία θα πρέπει να αποκωδικοποιήσετε με το [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ή τη βιβλιοθήκη python-asn1 και το script `dump.py` της, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), ώστε να λάβετε ένα πιο κατανοητό string.<sup>[[3]](#references)[[8]](#references)</sup>

## Περιορισμοί περιβάλλοντος

Αυτοί είναι οι Launch Constraints που έχουν ρυθμιστεί σε **εφαρμογές τρίτων**. Ο developer μπορεί να επιλέξει τα **facts** και τους **λογικούς τελεστές προς χρήση** στην εφαρμογή του, ώστε να περιορίσει την πρόσβαση σε αυτήν.

Είναι δυνατή η απαρίθμηση των Environment Constraints μιας εφαρμογής με:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

Στο **macOS** υπάρχουν μερικά trust caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Στο iOS, φαίνεται ότι βρίσκεται στο **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Στο macOS που εκτελείται σε συσκευές Apple Silicon, αν ένα δυαδικό αρχείο υπογεγραμμένο από την Apple δεν βρίσκεται στο trust cache, το AMFI θα αρνηθεί να το φορτώσει.

### Απαρίθμηση Trust Caches

Τα προηγούμενα αρχεία trust cache είναι σε μορφή **IMG4** και **IM4P**, με το IM4P να είναι το τμήμα payload μιας μορφής IMG4.

Μπορείτε να χρησιμοποιήσετε το [**pyimg4**](https://github.com/m1stadev/PyIMG4) για να εξαγάγετε το payload των βάσεων δεδομένων:

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

(Μια άλλη επιλογή είναι να χρησιμοποιήσετε το εργαλείο [**img4tool**](https://github.com/tihmstar/img4tool), το οποίο εκτελείται ακόμη και σε M1, παρόλο που η έκδοσή του είναι παλιά και προορίζεται για x86_64, αν το εγκαταστήσετε στις σωστές τοποθεσίες).

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

Το trust cache ακολουθεί την ακόλουθη δομή, επομένως **η κατηγορία LC είναι η 4η στήλη**

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Έπειτα, θα μπορούσες να χρησιμοποιήσεις ένα script όπως [**αυτό**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) για να εξαγάγεις δεδομένα.

Από αυτά τα δεδομένα μπορείς να εντοπίσεις τις εφαρμογές με **τιμή launch constraints `0`**, δηλαδή εκείνες που δεν υπόκεινται σε περιορισμούς ([**δες εδώ**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) για να δεις τι σημαίνει κάθε τιμή).<sup>[[6]](#references)</sup>

## Μετριασμός επιθέσεων

Τα Launch Constraints θα είχαν μετριάσει αρκετές παλιές επιθέσεις, **διασφαλίζοντας ότι η διεργασία δεν θα εκτελείται υπό μη αναμενόμενες συνθήκες**: για παράδειγμα, από μη αναμενόμενες τοποθεσίες ή όταν εκκινείται από μη αναμενόμενη γονική διεργασία (αν θα έπρεπε να την εκκινεί μόνο το launchd).

Επιπλέον, τα Launch Constraints **μετριάζουν και τις επιθέσεις downgrade**.

Ωστόσο, **δεν μετριάζουν τις συνήθεις καταχρήσεις XPC**, τις εγχύσεις κώδικα **Electron** ή τις **dylib injections** χωρίς library validation (εκτός αν είναι γνωστά τα team IDs που μπορούν να φορτώσουν libraries).<sup>[[3]](#references)</sup>

### Προστασία XPC Daemon

Στην έκδοση Sonoma, ένα αξιοσημείωτο σημείο είναι η **ρύθμιση ευθύνης** της υπηρεσίας XPC daemon. Η υπηρεσία XPC είναι υπεύθυνη για τον εαυτό της, αντί να είναι υπεύθυνος ο client που συνδέεται. Αυτό τεκμηριώνεται στην αναφορά feedback FB13206884. Αυτή η ρύθμιση μπορεί να φαίνεται ελαττωματική, καθώς επιτρέπει ορισμένες αλληλεπιδράσεις με την υπηρεσία XPC:

- **Εκκίνηση της υπηρεσίας XPC**: Αν θεωρήσουμε ότι πρόκειται για bug, αυτή η ρύθμιση δεν επιτρέπει την εκκίνηση της υπηρεσίας XPC μέσω κώδικα του attacker.
- **Σύνδεση σε ενεργή υπηρεσία**: Αν η υπηρεσία XPC εκτελείται ήδη (ενδεχομένως επειδή την ενεργοποίησε η αρχική εφαρμογή της), δεν υπάρχουν εμπόδια στη σύνδεση με αυτήν.

Η εφαρμογή περιορισμών στην υπηρεσία XPC μπορεί να είναι ωφέλιμη, καθώς **περιορίζει το χρονικό περιθώριο πιθανών επιθέσεων**, αλλά δεν αντιμετωπίζει το κύριο ζήτημα. Για να διασφαλιστεί ουσιαστικά η ασφάλεια της υπηρεσίας XPC, πρέπει **να επικυρώνεται αποτελεσματικά ο client που συνδέεται**. Αυτή παραμένει η μόνη μέθοδος για την ενίσχυση της ασφάλειας της υπηρεσίας. Αξίζει επίσης να σημειωθεί ότι η προαναφερθείσα ρύθμιση ευθύνης βρίσκεται επί του παρόντος σε ισχύ, κάτι που μπορεί να μη συνάδει με τον επιδιωκόμενο σχεδιασμό.<sup>[[3]](#references)</sup>

### Προστασία Electron

Ακόμη κι αν απαιτείται η εφαρμογή να **ανοιχτεί από το LaunchService** (στους περιορισμούς των γονικών διεργασιών), αυτό μπορεί να επιτευχθεί μέσω του **`open`** (το οποίο μπορεί να ορίσει env variables) ή μέσω του **Launch Services API** (όπου μπορούν να καθοριστούν env variables).<sup>[[3]](#references)</sup>

Για τον γενικό μηχανισμό MACF πίσω από τα policy-specific spawn attributes, δες [MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Παράκαμψη των ενσωματωμένων περιορισμών κατά το spawn

Τα launch constraints (επίσημα **lightweight code requirements**, *LWCR*) επιβάλλονται από την **πολιτική MAC του AMFI**. Η `posix_spawn` επιτρέπει στον caller να διαβιβάσει ένα αυθαίρετο blob σε μια πολιτική MAC μέσω της **`posix_spawnattr_setmacpolicyinfo_np()`**, και το AMFI δεχόταν ένα λεξικό LWCR που παρείχε ο caller μέσω αυτής της διαδρομής. Το bug ήταν ότι οι **περιορισμοί που παρείχε ο attacker αντικαθιστούσαν τους ενσωματωμένους περιορισμούς του binary**, αντί να ελέγχονται επιπλέον αυτών:

- Δημιούργησε ένα ελάχιστο λεξικό launch constraints (ακόμη και κενό).
- Όρισε την **κατηγορία περιορισμού σε `127`**, μια τιμή που το AMFI επιτρέπει στα spawn attributes, αλλά **δεν επιβάλλει** — απλώς καταγράφει `Launch Constraint Violation (not enforcing)` αντί να αποκλείει την εκτέλεση.
- Πέρασέ το μέσω των spawn attributes, ώστε η διεργασία να εκκινηθεί σε περιβάλλον που θα απαγόρευαν οι πραγματικοί περιορισμοί της ίδιας ή της γονικής διεργασίας.

Μετά την επιδιόρθωση, επικυρώνονται **τόσο** οι ενσωματωμένοι περιορισμοί **όσο και** αυτοί που παρέχονται, οπότε το παρεχόμενο λεξικό δεν μπορεί πλέον να αποδυναμώσει τους ενσωματωμένους περιορισμούς.<sup>[[2]](#references)</sup>

> [!TIP]
> Αυτή είναι η γενική μορφή που πρέπει να αναζητάς κατά τον έλεγχο της επιβολής περιορισμών: ένα API που επιτρέπει σε μη έμπιστη είσοδο να *παρέχει* μια πολιτική είναι συνήθως ενδιαφέρον όταν η μηχανή πολιτικών αντιμετωπίζει την παρεχόμενη τιμή ως αντικατάσταση και όχι ως πρόσθετη απαίτηση.



## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Ζωντανή μετάδοση)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Παράκαμψη των Launch Constraints στο macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Σε βάθος ανάλυση των Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Γιατί δεν εκτελείται μια εφαρμογή συστήματος ή ένα εργαλείο εντολών; Launch constraints και trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Προστατέψτε την εφαρμογή Mac με environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Περιγραφή των Launch Constraints που εισήχθησαν στο iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints του macOS Sonoma (14) (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Πέρα από τα παλιά καλά LaunchAgents - σχετικές πληροφορίες εδώ](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
