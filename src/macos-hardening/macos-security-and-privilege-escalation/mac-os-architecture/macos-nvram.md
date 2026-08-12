# macOS NVRAM

{{#include ../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το **NVRAM** (Non-Volatile Random-Access Memory) αποθηκεύει το firmware και την κατάσταση της πρώιμης εκκίνησης εκτός του κανονικού filesystem του macOS. Ο αντίκτυπός του στην ασφάλεια εξαρτάται τόσο από τη μεταβλητή όσο και από την αρχιτεκτονική εκκίνησης:

| Μεταβλητή | Σκοπός / σημασία για την ασφάλεια |
|---|---|
| `boot-args` | Ορίσματα που παρέχονται στον kernel. Τα ορίσματα για debugging ή για μείωση της ασφάλειας φιλτράρονται, εκτός αν η boot policy τα επιτρέπει. |
| `csr-active-config` | Bitmask του SIP σε Intel Mac. Στο Apple silicon, η αντίστοιχη policy αποθηκεύεται στο `LocalPolicy` ανά volume και δεν θεωρείται άμεσα αξιόπιστη από αυτήν τη μεταβλητή. |
| `efi-boot-device` / `efi-boot-device-data` | Προορισμός εκκίνησης του Intel EFI. |
| `boot-volume` | Κατάσταση επιλογής boot volume στο Apple silicon. |
| `SystemAudioVolume`, `prev-lang:kbd` | Παραδείγματα συνηθισμένων persistent ρυθμίσεων. |

Η σημαντική διάκριση είναι μεταξύ των **δεδομένων που αποθηκεύονται στο NVRAM** και μιας **security policy που γίνεται αποδεκτή από την αλυσίδα εκκίνησης**. Στο Apple silicon, το Secure Enclave υπογράφει ένα `LocalPolicy` ανά boot-volume-group. Ένα nonce που διατηρείται στο Secure Storage Component παρέχει προστασία anti-replay. Επομένως, η αλλαγή μιας ιδιότητας NVRAM με παρόμοιο όνομα δεν ξαναγράφει από μόνη της την αποδεκτή boot policy.<sup>[[1]](#references)[[4]](#references)</sup>

## Πρόσβαση στο NVRAM από το User Space

### Ανάγνωση και συλλογή baseline
```bash
# List variables (values are separated from names by a tab)
nvram -p

# Read individual variables. Absence is normal on many configurations.
nvram boot-args
nvram csr-active-config

# Export typed values as an XML plist; useful for diffing two acquisitions
nvram -xp > "nvram-$(date +%Y%m%d-%H%M%S).plist"

# The same properties as exposed through the IODeviceTree plane
ioreg -lw0 -p IODeviceTree -n options

# Effective SIP status
csrutil status
```
Μην ταξινομείτε κάθε άγνωστο key ως κακόβουλο. Το hardware, το recoveryOS, οι ενημερώσεις, το Find My και οι αποτυχίες εκκίνησης δημιουργούν μεταβλητές που εξαρτώνται από το μοντέλο και την έκδοση. Συγκρίνετε ένα capture με ένα προηγούμενο baseline από το **ίδιο Mac** και αντιμετωπίζετε τα απροσδόκητα binary blobs, την αλλαγμένη επιλογή εκκίνησης ή τα arguments που μειώνουν την ασφάλεια ως ενδείξεις και όχι ως απόδειξη compromise.

### Writing NVRAM

Το Root μπορεί να δημιουργήσει ή να αλλάξει πολλές συνηθισμένες μεταβλητές, όμως οι προστατευμένες μεταβλητές εξαρτώνται επιπλέον από το namespace της μεταβλητής, το SIP, τους kernel rules ανά μεταβλητή και τα περιορισμένα Apple entitlements. Επομένως, το ότι το `sudo` εκτελείται επιτυχώς για ένα harmless custom key **δεν** αποδεικνύει ότι η διεργασία μπορεί να τροποποιήσει τα `boot-args`, το SIP ή τις μεταβλητές του system-region.
```bash
# Harmless test variable (perform only on a disposable test host)
sudo nvram HTTest='persistence-value'
nvram HTTest
sudo nvram -d HTTest

# Delete one variable
sudo nvram -d variable-name
```
> [!CAUTION]
> Αποφύγετε το `nvram -c` κατά τη διάρκεια των δοκιμών: ζητά τη διαγραφή όλων των μεταβλητών που μπορούν να διαγραφούν και μπορεί να αλλάξει τη συμπεριφορά εκκίνησης/ανάκτησης. Ορισμένες μεταβλητές είναι διαθέσιμες μόνο στον kernel, προστατεύονται μέσω entitlements, αποκρύπτονται κατά την ανάγνωση ή μπορούν να διαγραφούν μόνο κατά την επαναφορά του NVRAM.

## NVRAM Entitlements και `CS_NVRAM_UNRESTRICTED`

Κατά τον χρόνο εκτέλεσης, το XNU αντιστοιχίζει το `com.apple.rootless.restricted-nvram-variables.heritable` στη σημαία διεργασίας **`CS_NVRAM_UNRESTRICTED`** (`0x00008000`). Αυτό δεν είναι ισοδύναμο με τον συνηθισμένο έλεγχο του effective UID 0. Υπάρχουν επίσης πιο περιορισμένα private entitlements για συγκεκριμένες μεταβλητές ή λειτουργίες.

Επιθεωρήστε τα entitlements αντί να βασίζεστε στη γενική γραμμή flags που εκτυπώνει το `codesign`:
```bash
# Static entitlements embedded in a Mach-O signature
codesign -d --entitlements :- /path/to/binary 2>&1

# Quickly highlight NVRAM-related entitlements
codesign -d --entitlements :- /path/to/binary 2>&1 |
grep -Ei 'nvram|restricted-nvram'

# The nvram CLI itself normally asks the IOKit service to enforce the caller's
# privilege; possession of /usr/sbin/nvram is not an entitlement bypass.
codesign -d --entitlements :- /usr/sbin/nvram 2>&1
```
Κατά το audit ενός privileged helper, ανιχνεύστε την **πραγματική ταυτότητα του client και τη διαδρομή του request**. Ένα confused-deputy bug σε ένα entitled service μπορεί να είναι πιο χρήσιμο από την απευθείας κλήση του `nvram`, αλλά η προσβάσιμη variable/operation ενδέχεται και πάλι να περιορίζεται από το XNU.

## Intel SIP State vs Apple Silicon `LocalPolicy`

### Intel: `csr-active-config`

Στο Intel, το `csr-active-config` κωδικοποιεί τις εξαιρέσεις `CSR_ALLOW_*`. Οι bit θέσεις που συνήθως σχετίζονται είναι:
```text
0x001  untrusted kexts                 0x002  unrestricted filesystem
0x004  task_for_pid                    0x008  kernel debugger
0x010  Apple-internal behavior         0x020  unrestricted DTrace
0x040  unrestricted NVRAM              0x080  device configuration
0x100  any recovery OS                 0x200  unapproved kexts
0x400  executable-policy override      0x800  unauthenticated root (SSV)
```
Διαβάστε την ενεργή ρύθμιση με `csrutil status`. Η ακατέργαστη έξοδος του `nvram` ενδέχεται να χρησιμοποιεί percent-encoded bytes little-endian. Δείτε το [macOS SIP](../macos-security-protections/macos-sip.md) για τις επιπτώσεις σχετικά με την προστασία και τα bypass.
```bash
nvram csr-active-config 2>/dev/null
csrutil status
```
### Apple Silicon: επιθεώρηση της αποδεκτής boot policy

Στο Apple silicon, το `sip0` στο υπογεγραμμένο από το Secure Enclave `LocalPolicy` περιέχει τα bit της SIP policy που αποθηκεύονταν προηγουμένως στο NVRAM. Τα άλλα σχετικά πεδία policy είναι τα `sip1` (επιτρέπει αποτυχία επαλήθευσης του root-hash του SSV), `sip2` (να μην κλειδώνεται η μνήμη του kernel με CTRR) και `sip3` (απενεργοποιεί τη allowlist του `boot-args` στο iBoot). Αυτά τα πεδία μπορούν να τροποποιηθούν μόνο από paired One True recoveryOS (1TR). Η ενεργοποίηση του `sip3` απαιτεί επίσης downgrade σε Permissive Security.<sup>[[4]](#references)</sup>

Χρησιμοποιήστε μόνο τις display operations κατά την enumeration:
```bash
# Apple silicon: show the selected volume group's LocalPolicy
sudo bputil -d

# Machine-readable display, or display every bootable OS policy
sudo bputil -d -j
sudo bputil -e -j

# Map policy output to APFS volume groups when multiple OSes are installed
diskutil apfs listVolumeGroups
```
> [!WARNING]
> Μην χρησιμοποιείτε τις επιλογές αλλαγής policy του `bputil` κατά τη διάρκεια audit. Ένα κανονικό macOS compromise δεν θα πρέπει να μπορεί να ενεργοποιήσει σιωπηλά τα παραπάνω πεδία: η διαδρομή downgrade απαιτεί σκόπιμα φυσική πρόσβαση στο paired 1TR και authentication του owner.<sup>[[4]](#references)</sup>

## Επιπτώσεις στην ασφάλεια

### Το `boot-args` ως Post-Compromise Amplifier

Ορίσματα όπως kernel-debugging options, `kcsuffix=development` ή `amfi_get_out_of_my_way=1` μπορούν να αποδυναμώσουν τα επόμενα boot stages, αλλά μόνο όταν η πλατφόρμα τα αποδέχεται. Σε Apple silicon με Full ή Reduced Security, το iBoot φιλτράρει arguments που μειώνουν την ασφάλεια· unrestricted arguments απαιτούν το SIP policy downgrade που περιγράφηκε παραπάνω. Σε Intel, ο περιορισμός NVRAM του SIP αποτρέπει αντίστοιχα το να θεωρείται ένα root shell ως αυτόματος έλεγχος του `boot-args`.
```bash
# Enumerate, do not assume that a value shown here was accepted by iBoot
nvram boot-args 2>/dev/null

# Confirm what the running kernel reports it received
sysctl kern.bootargs

# Search for common security-reducing/debug strings
{ nvram boot-args 2>/dev/null; sysctl -n kern.bootargs 2>/dev/null; } |
grep -Ei 'amfi|cs_enforcement|debug|kcsuffix|keepsyms|ktrace|rc\.trampoline'
```
Δείτε τα [AMFI](../macos-security-protections/macos-amfi-applemobilefileintegrity.md) και [kernel debugging](macos-kernel-extensions.md), αντί να υποθέτετε ότι ένα ιστορικό επιχείρημα λειτουργεί πανομοιότυπα σε κάθε έκδοση του macOS.

### Εκτέλεση του `rc.trampoline` μέσω NVRAM

Πρόσφατη έρευνα κατέγραψε έναν συγκεκριμένο consumer δεδομένων NVRAM: το Apple platform binary `/System/Library/CoreServices/rc.trampoline`. Όταν το launchd εντοπίζει το boot argument `rc.trampoline=1`, αυτή η boot task διαβάζει την ιδιότητα `apple-trusted-trampoline` από το `IODeviceTree:/options`, την εγγράφει σε ένα προσωρινό executable, το εκκινεί σε suspended κατάσταση, ελέγχει την code-signing κατάστασή του, το αποσυνδέει και στη συνέχεια το επαναφέρει σε εκτέλεση. Η boot task μπλοκάρει το launchd μέχρι να τερματιστεί το child.<sup>[[5]](#references)</sup>

Αυτό είναι ένα **post-downgrade persistence primitive, όχι SIP bypass**. Η αποδεδειγμένη διαδρομή απαιτούσε να είναι απενεργοποιημένο το SIP, ώστε να εκτελεστεί η boot task και να μπορεί να οριστεί το `boot-args`. Η έρευνα παρατήρησε επίσης ένα κατά προσέγγιση όριο μεγέθους τιμής 390 KB. Η αξία του έγκειται στο ότι executable bytes μπορούν να παραμένουν εκτός του κανονικού filesystem και να υλοποιούνται κατά την εκκίνηση, αφού ένας attacker έχει ήδη αποκτήσει το απαιτούμενο security downgrade.<sup>[[5]](#references)</sup>

Αναζητήστε και τα δύο απαιτούμενα artifacts, καθώς και το launchd event:
```bash
# Print names only so a large binary value is not dumped to the terminal
nvram -p | cut -f1 | grep -E '^(apple-trusted-trampoline|boot-args)$'
nvram boot-args 2>/dev/null | grep -F 'rc.trampoline='

# The research-observed execution produces an rc.trampoline boot-task event
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"'
```
Οι αυθαίρετες προσαρμοσμένες μεταβλητές NVRAM είναι διαφορετικά μόνο **αποθήκευση**: δεν εκτελούν τίποτα, εκτός αν τις χρησιμοποιεί το firmware, ένα Apple boot component ή ένας ξεχωριστός μηχανισμός persistence. Αυτή η διάκριση αποτρέπει την υπερβολική παρουσίαση ενός marker όπως το `nvram attacker-config=...` ως εκτέλεση κώδικα firmware.

## Script απαρίθμησης

<details>
<summary>Έλεγχος πολιτικής εκκίνησης NVRAM και Apple silicon</summary>
```bash
#!/bin/bash
set -u

echo '=== NVRAM / boot-policy audit ==='
echo '[*] Architecture:'
uname -m

echo '[*] Effective SIP:'
csrutil status 2>&1

echo '[*] Stored and effective boot arguments:'
nvram boot-args 2>/dev/null || echo 'boot-args: <not set/readable>'
sysctl kern.bootargs 2>/dev/null || true

echo '[*] Intel SIP variable (absence on Apple silicon is expected):'
nvram csr-active-config 2>/dev/null || echo 'csr-active-config: <not set/readable>'

echo '[*] High-signal NVRAM names:'
nvram -p 2>/dev/null | cut -f1 |
grep -E '^(apple-trusted-trampoline|boot-args|csr-active-config|efi-boot-device(-data)?|boot-volume)$' || true

echo '[*] rc.trampoline log evidence:'
log show --last 30d --style compact \
--predicate 'eventMessage CONTAINS[c] "rc.trampoline"' 2>/dev/null | tail -20

if [[ "$(uname -m)" == 'arm64' ]] && command -v bputil >/dev/null; then
echo '[*] Apple silicon LocalPolicy (read-only display):'
bputil -d -j 2>&1
fi
```
</details>



## References

- [1] [Οδηγός ασφάλειας πλατφορμών Apple — Διαδικασία εκκίνησης](https://support.apple.com/guide/security/boot-process-secac71d5623/web)
- [2] [Ενημερώσεις ασφάλειας Apple — CVE που σχετίζονται με το NVRAM](https://support.apple.com/en-us/HT201222)
- [3] [Duo Labs — Ασφάλεια Apple T2](https://duo.com/labs/research/apple-t2-xpc)
- [4] [Ασφάλεια πλατφορμών Apple — Περιεχόμενα ενός αρχείου LocalPolicy για Mac με Apple silicon](https://support.apple.com/guide/security/contents-a-localpolicy-file-mac-apple-silicon-secc745a0845/web)
- [5] [Πέρα από τα παλιά καλά LaunchAgents — Persist μέσω NVRAM με το apple-trusted-trampoline](https://theevilbit.github.io/beyond/beyond_0035/)
{{#include ../../../banners/hacktricks-training.md}}
