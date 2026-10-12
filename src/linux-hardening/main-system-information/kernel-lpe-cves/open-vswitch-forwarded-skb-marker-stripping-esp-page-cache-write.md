# Open vSwitch: αφαίρεση του marker από forwarded skb για εγγραφές ESP στην page cache

{{#include ../../../banners/hacktricks-training.md}}

Ένα χρήσιμο μοτίβο exploitation του Linux kernel είναι να **αποσυνδέεις τα metadata ιδιοκτησίας από ένα skb χωρίς να αφαιρείς τα ξένα fragments του** και έπειτα να δρομολογείς αυτό το skb σε έναν consumer που γράφει επιτόπου. Στην περίπτωση του Open vSwitch (OVS), ένα αποτυχημένο userspace upcall καθαρίζει το `SKBFL_SHARED_FRAG` από ένα ενεργό `MSG_ZEROCOPY` skb· στη συνέχεια, το ESP κάνει decrypt απευθείας πάνω σε ένα folio της page cache ενός αρχείου μόνο για ανάγνωση. Έτσι προκύπτει μια deterministic τοπική εγγραφή στην page cache, η οποία έχει καταγραφεί στα CVE-2026-90049, CVE-2026-89487 και CVE-2026-80977.<sup>[[1]](#references)[[2]](#references)</sup>

Πρόκειται για ζήτημα τύπου Copy Fail/Dirty Frag και όχι για κλασική αλλοίωση μνήμης: δεν απαιτείται race ή αποκάλυψη διεύθυνσης, αρκεί το αρχείο να είναι αναγνώσιμο, και τα αλλαγμένα bytes υπάρχουν στην page cache και όχι στον δίσκο.<sup>[[2]](#references)[[3]](#references)</sup>

## Αμετάβλητη συνθήκη ασφαλείας: τα ξένα fragments πρέπει να παραμένουν σημειωμένα

Το `SKBFL_SHARED_FRAG` ενημερώνει τους consumers που γράφουν επιτόπου ότι ένα fragment του skb μπορεί να αναφέρεται σε αποθηκευτικό χώρο που δεν τους ανήκει αποκλειστικά. Το fast path του ESP στην `esp_input()` μπορεί να κάνει decrypt επιτόπου ένα μη γραμμικό, μη κλωνοποιημένο skb μόνο όταν η `skb_has_shared_frag()` είναι false· διαφορετικά, η `skb_cow_data()` δημιουργεί πρώτα ιδιωτικό αποθηκευτικό χώρο. Αυτός ο έλεγχος στην πλευρά του consumer προστέθηκε μετά το Dirty Frag.<sup>[[5]](#references)</sup>

Επομένως, η αμετάβλητη συνθήκη έχει δύο ανεξάρτητα μέρη:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Οι writers που γράφουν επιτόπου πρέπει να ελέγχουν το `SKBFL_SHARED_FRAG` και να αντιγράφουν τα shared data πριν από την τροποποίησή τους.
2. Κάθε διαδρομή clone, coalesce, transfer ή forwarding πρέπει να διατηρεί το marker όσο η ξένη page παραμένει συνδεδεμένη.

Το Fragnesia παραβίασε τον δεύτερο κανόνα κατά τη μετακίνηση των fragment descriptors στην `skb_try_coalesce()`. Η διαδρομή του OVS διαφέρει ελαφρώς: δεν κάνει καθόλου transfer του fragment· καθαρίζει το marker **επιτόπου, στο αρχικό skb, και έπειτα συνεχίζει να το προωθεί**.<sup>[[2]](#references)[[4]](#references)</sup>

## Δυνατότητα πρόσβασης στο OVS χωρίς προνόμια

Το kernel datapath του OVS ελέγχεται μέσω generic-netlink families, όπως οι `ovs_datapath`, `ovs_vport`, `ovs_flow` και `ovs_packet`. Οι λειτουργίες που τροποποιούν την κατάσταση χρησιμοποιούν namespace-aware `GENL_UNS_ADMIN_PERM`, επομένως μια διεργασία που εκτελείται με `unshare -Urn` αποκτά το `CAP_NET_ADMIN` που χρειάζεται για να δημιουργήσει ένα datapath, να συνδέσει ένα veth και να εγκαταστήσει flow actions μέσα στο δικό της network namespace. Η επίλυση της OVS family μπορεί επίσης να κάνει autoload το `openvswitch.ko`· για αυτή την επιφάνεια επίθεσης δεν απαιτούνται host `CAP_SYS_MODULE`, `ovs-vsctl` ή `ovs-vswitchd`.<sup>[[2]](#references)[[7]](#references)</sup>

Η σημαντική διάκριση είναι ανάμεσα σε δύο τύπους upcall:<sup>[[2]](#references)[[7]](#references)</sup>

- Ένα **flow miss** στέλνει το packet στο `ovs-vswitchd`· αν το upcall αποτύχει, το packet συνήθως απορρίπτεται.
- Μια ρητή ενέργεια `OVS_ACTION_ATTR_USERSPACE` στέλνει ένα borrowed copy σε ένα επιλεγμένο port ID και έπειτα εκτελεί τις επόμενες ενέργειες στο αρχικό skb.

Επομένως, ένας attacker μπορεί να εγκαταστήσει ένα flow της μορφής:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Κανένας listener δεν έχει στην κατοχή του το επιλεγμένο port ID, με αποτέλεσμα η ενέργεια userspace να αποτυγχάνει προβλέψιμα, ενώ η επόμενη ενέργεια `OUTPUT` διατηρεί το αρχικό packet ενεργό.<sup>[[1]](#references)[[2]](#references)</sup>

## Βασική αιτία: `skb_tx_error()` σε packet που επιβιώνει

Η ευάλωτη διαδρομή σφάλματος upcall του OVS καλεί την `skb_tx_error(skb)`. Αυτός ο helper σχεδιάστηκε για αποτυχημένη μετάδοση, μετά την οποία το skb ελευθερώνεται· ολοκληρώνει την bookkeeping διαδικασία του zerocopy μέσω της `skb_zcopy_clear()`, της οποίας η μάσκα flags αφαιρούσε ιστορικά και το `SKBFL_SHARED_FRAG`. Το OVS αγνόησε το σφάλμα της ενέργειας userspace και συνέχισε τη λίστα ενεργειών, παραβιάζοντας το συμβόλαιο διάρκειας ζωής του helper.<sup>[[1]](#references)[[2]](#references)</sup>

Η εκμεταλλεύσιμη μετάβαση κατάστασης είναι:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Αυτό λειτουργεί μόνο όταν η `skb_zcopy()` εντοπίζει κατάσταση zerocopy. Ένα fragment που φέρει μόνο `SKBFL_SHARED_FRAG` δεν αρκεί· το `MSG_ZEROCOPY` είναι χρήσιμο επειδή δημιουργεί τα `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` και ορίζει επίσης το `SKBFL_DONT_ORPHAN`. Το τελευταίο κάνει το `skb_orphan_frags()` να παραλείπει την αντικατάσταση των ξένων σελίδων κατά την αντιγραφή από το userspace του OVS.<sup>[[2]](#references)[[3]](#references)</sup>

## Δημιουργία του primitive εγγραφής

Το end-to-end trigger αποτελείται από τα εξής στοιχεία.<sup>[[2]](#references)[[3]](#references)</sup>

1. Είσοδος σε ιδιωτικά user και network namespaces με `unshare -Urn`.
2. Αντιστοίχιση ενός αρχείου-στόχου για ανάγνωση με `PROT_READ | MAP_SHARED`.
3. Χρήση ξεχωριστού sender netns και ενός ζεύγους veth· το τοπικό loopback θα αντέγραφε τις δανεισμένες σελίδες και θα κατέστρεφε το primitive.
4. Δημιουργία ενός OVS datapath και του flow `USERSPACE`-και-μετά-`OUTPUT` που προκαλεί την αστοχία.
5. Εγκατάσταση μιας κατάστασης XFRM ESP-in-UDP σε transport mode με χρήση του `rfc4106(gcm(aes))` και της θύρας UDP 4500.
6. Αποστολή ενός datagram `MSG_ZEROCOPY` με iovec της μορφής `[ESP header | mapped file bytes | invalid ICV]`.

Η κατάσταση XFRM χρησιμοποιεί 20 bytes υλικού κλειδιού AES-128-GCM: 16 bytes κλειδιού AES και στη συνέχεια το salt RFC 4106 των τεσσάρων bytes. Για ένα επιλεγμένο explicit IV οκτώ bytes, η εμπιστευτικότητα του payload ξεκινά με το counter block `salt || IV || be32(2)`· η τιμή counter 1 καλύπτει αντίθετα το αποτέλεσμα του authentication.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

Μόλις το OVS αφαιρέσει το marker, το ESP ακολουθεί τη διαδρομή no-copy και εκτελεί `plaintext = ciphertext XOR keystream` πάνω στο fragment που υποστηρίζεται από αρχείο. Ο έλεγχος ταυτοποίησης γίνεται **μετά** από αυτόν τον μετασχηματισμό, οπότε ένα μη έγκυρο ICV με όλα τα byte μηδενικά προκαλεί αποτυχία του πακέτου με `-EBADMSG` μόνο αφού έχουν ήδη αλλάξει τα byte της page cache.<sup>[[2]](#references)</sup>

### Μετατροπή του GCM σε επιλεγμένα byte

Για το τρέχον byte `C` και το επιθυμητό byte `P`, το πρώτο byte του keystream του payload πρέπει να είναι `C XOR P`. Με σταθερά το AES key και το salt, σαρώστε ένα επίθημα 16 bit του explicit IV και υπολογίστε εκ των προτέρων ένα επίθημα για κάθε πιθανό πρώτο byte του keystream:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Η δημόσια υλοποίηση περιορίζει το ciphertext στα 32 bytes και μετακινεί το file fragment κατά ένα byte για κάθε packet. Το επιλεγμένο πρώτο byte αντικαθιστά το πρώτο collateral byte του προηγούμενου packet· η `pread()` ανανεώνει το `C` πριν από κάθε packet, τα ίδια bytes παραλείπονται και το τελευταίο packet μικραίνει, ώστε οι εγγραφές να μην υπερβαίνουν το ζητούμενο εύρος. Έτσι, ένας πίνακας αναζήτησης 256 θέσεων μετατρέπει το primitive σε εγγραφή επιλεγμένου περιεχομένου στο page cache, με ακρίβεια byte και περίπου ένα packet ανά byte που διαφέρει.<sup>[[2]](#references)[[3]](#references)</sup>

## Εγγραφή στο page cache για απόκτηση root

Ένας πρακτικός στόχος είναι ένα υπάρχον εκτελέσιμο setuid-root. Το PoC αντικαθιστά τα πρώτα 160 bytes με ένα πλήρες static ELF που περιέχει ένα `PT_LOAD` σταθερής διεύθυνσης με δικαιώματα ανάγνωσης/εκτέλεσης, χωρίς `PT_INTERP`, και κώδικα που καλεί `setuid(0)` πριν από το `execve("/bin/sh", ...)`. Έτσι αποφεύγονται οι υποθέσεις σχετικά με το entry point του αρχικού binary, τη διάταξη PIE, τον dynamic loader ή τα relocations.<sup>[[2]](#references)[[3]](#references)</sup>

Η τροποποίηση είναι ορατή σε όλα τα user namespaces, επειδή το page cache δεν περιορίζεται σε namespaces. Το αλλοιωμένο folio δεν επισημαίνεται ως dirty, επομένως δεν εγγράφεται πίσω στον δίσκο· εκτελέστε τον στόχο όσο παραμένει resident και, στη συνέχεια, απορρίψτε την προσωρινή αλλοίωση με `posix_fadvise(..., POSIX_FADV_DONTNEED)`, ώστε οι επόμενες αναγνώσεις να φορτώσουν ξανά τα αρχικά περιεχόμενα από τον δίσκο.<sup>[[2]](#references)[[3]](#references)</sup>

## Έλεγχοι έκθεσης και μετριασμός

Ελέγξτε πρώτα τον πραγματικό kernel του vendor. Οι σχετικές προϋποθέσεις έκθεσης είναι τα unprivileged user namespaces, η διαθεσιμότητα ή η παρουσία του OVS και μια διαθέσιμη υλοποίηση ESP.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Αναβαθμίστε σε kernel που περιλαμβάνει ολόκληρη τη σειρά διορθώσεων· η τελική επιδιόρθωση καλύπτει τη διαδρομή recirculation και αποφεύγει την τροποποίηση της κοινόχρηστης κατάστασης `skb_shinfo()`, ενώ κλείνει επίσης ένα σχετικό strip στο `skb_zerocopy()`.<sup>[[1]](#references)[[2]](#references)</sup>

Αν το OVS δεν χρησιμοποιείται, αποτρέψτε τη φόρτωση τόσο μέσω alias όσο και μέσω ονόματος, με κανόνα `install` του modprobe αντί να βασίζεστε μόνο στο `blacklist`. Αν ο host δεν τερματίζει IPsec και το ESP είναι modular, ο ίδιος έλεγχος μπορεί να αφαιρέσει και το decrypt sink.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Αυτοί οι κανόνες δεν βοηθούν όταν ένα module είναι ήδη φορτωμένο ή όταν η δυνατότητα είναι ενσωματωμένη στον kernel. Η απενεργοποίηση των unprivileged user namespaces αφαιρεί επίσης την πηγή δυνατότητας namespace, αλλά μπορεί να προκαλέσει προβλήματα σε browsers, Flatpak, Podman και άλλους φόρτους εργασίας sandboxing/container.<sup>[[2]](#references)</sup>

## Μαθήματα από την ανασκόπηση

Κατά τον έλεγχο δικτύωσης zero-copy, μην περιορίζετε την αναζήτηση σε helpers που αντιγράφουν ή μετακινούν fragments. Εντοπίστε επίσης helpers χειρισμού σφαλμάτων/ολοκλήρωσης που εκκαθαρίζουν ομάδες flags και, στη συνέχεια, επαληθεύστε ότι κάθε caller τηρεί το τεκμηριωμένο συμβόλαιο διάρκειας ζωής του skb. Ένα bit ιδιοκτησίας σελίδας, ομαδοποιημένο με bits του κύκλου ζωής zerocopy, είναι ευαίσθητο από άποψη ασφάλειας ακόμη κι όταν ο κώδικας εκκαθάρισης δεν προσπελαύνει άμεσα κάποιο fragment.<sup>[[1]](#references)[[2]](#references)</sup>

Μια ανθεκτική διόρθωση πρέπει να καλύπτει όλες τις διαδρομές μέσω των οποίων μπορεί να επιβιώσει το skb —συμπεριλαμβανομένων της συνέχισης action και της επανακυκλοφορίας— και να λαμβάνει υπόψη ότι τα clones μοιράζονται το `skb_shinfo()`. Από την πλευρά του consumer, η αποτυχία authentication δεν αναιρεί τις εγγραφές plaintext που έχουν ήδη πραγματοποιηθεί από έναν in-place μετασχηματισμό AEAD. Επομένως, οι έλεγχοι για foreign storage πρέπει να γίνονται πριν αρχίσει η αποκρυπτογράφηση.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Σειρά διορθώσεων της Doyensec για το netdev: net: να μην αφαιρούνται οι δείκτες frag zerocopy από ένα προωθημένο skb](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Η αφαίρεση δεικτών από προωθημένο SKB του Open vSwitch επιτρέπει ντετερμινιστικό ESP Page-Cache LPE](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Proof of concept `ovs-pagecache-write` της Doyensec](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Διόρθωση του Linux για την αρχική διαδρομή συνένωσης Fragnesia (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Έλεγχος κοινόχρηστων fragments στην πλευρά consumer του Linux ESP (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: Η χρήση του Galois/Counter Mode (GCM) στο IPsec ESP](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Τεκμηρίωση του kernel datapath του Open vSwitch](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
