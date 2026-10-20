# Χρήστες macOS & Εξωτερικοί Λογαριασμοί

{{#include ../../banners/hacktricks-training.md}}

## Συνήθεις χρήστες

- **Λογαριασμοί daemon**: Προορίζονται για system daemons. Τα σύντομα ονόματά τους συνήθως ξεκινούν με κάτω παύλα (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Επισκέπτης**: Ένας περιορισμένος, προσωρινός λογαριασμός, του οποίου η διαθεσιμότητα μπορεί να ελέγχεται τοπικά ή μέσω ενός payload Accounts του MDM.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Μια σκόπιμα μη προνομιούχα ταυτότητα που χρησιμοποιείται από υπηρεσίες οι οποίες απαιτούν ελάχιστα δικαιώματα στο σύστημα αρχείων.
- **Root**: Ο υπερχρήστης. Η διαδραστική σύνδεση ως root είναι απενεργοποιημένη από προεπιλογή, αν και οι διαχειριστές μπορούν να εκτελούν προνομιούχες λειτουργίες μέσω εξουσιοδότησης και του `sudo`.<sup>[[2]](#references)</sup>

Το υλικό επαλήθευσης κωδικών πρόσβασης τοπικών λογαριασμών και η διαδικασία εξαγωγής του καλύπτονται στην ενότητα [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## User Privileges

- **Τυπικός χρήστης:** Ο συνηθισμένος τύπος λογαριασμού χωρίς δικαιώματα διαχειριστή. Για αλλαγές διαχείρισης απαιτείται εξουσιοδότηση από διαχειριστή.
- **Χρήστης διαχειριστής**: Μέλος της τοπικής ομάδας `admin`. Οι χρήστες διαχειριστές εξακολουθούν να εκτελούν τις συνήθεις διεργασίες με τη δική τους ταυτότητα χρήστη, αλλά μπορούν να εξουσιοδοτούν προνομιούχες λειτουργίες. Μην υποθέτετε ότι η συμμετοχή στην ομάδα από μόνη της κάνει κάθε εντολή να εκτελείται ως root· εξακολουθούν να ισχύουν οι έλεγχοι των `sudo`, Authorization Services, πολιτικών και εφαρμογών.<sup>[[2]](#references)</sup>
- **Root**: Ο root είναι χρήστης που μπορεί να εκτελέσει σχεδόν οποιαδήποτε ενέργεια (υπάρχουν περιορισμοί που επιβάλλονται από προστασίες όπως το System Integrity Protection).
  - Για παράδειγμα, το System Integrity Protection και ο υπογεγραμμένος τόμος συστήματος εμποδίζουν ακόμη και τον root να τροποποιεί μόνιμα προστατευμένο περιεχόμενο του `/System` κατά την κανονική λειτουργία.

## Εξωτερικοί λογαριασμοί

Το macOS υποστηρίζει επίσης λογαριασμούς εφαρμογών από εξωτερικούς παρόχους. Το daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) μεσολαβεί για την πρόσβαση στα δεδομένα του Accounts framework, ενώ τα plug-ins ελέγχου ταυτότητας βρίσκονται στη διαδρομή `/System/Library/Accounts/Authentication/`. Πρόκειται για λογαριασμούς εφαρμογών/υπηρεσιών και όχι απαραίτητα για ταυτότητες που μπορούν να συνδεθούν από το παράθυρο σύνδεσης του macOS. Το `accountsd` διαβάζει επίσης τους γνωστούς τύπους λογαριασμών από το `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Φορτίο διαχείρισης συσκευών Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Δικαιώματα και ιδιοκτησία BSD: λογαριασμοί διαχειριστή και root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
