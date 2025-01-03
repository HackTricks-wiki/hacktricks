# macOS Χρήστες & Εξωτερικοί Λογαριασμοί

{{#include ../../banners/hacktricks-training.md}}

## Κοινές Χρήστες

- **Daemon**: Χρήστης που προορίζεται για συστήματα daemons. Οι προεπιλεγμένες ονομασίες λογαριασμού daemon συνήθως ξεκινούν με ένα "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Λογαριασμός για επισκέπτες με πολύ αυστηρές άδειες
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Κανένας**: Οι διεργασίες εκτελούνται με αυτόν τον χρήστη όταν απαιτούνται ελάχιστα δικαιώματα
- **Ρούτ**

## Δικαιώματα Χρηστών

- **Τυπικός Χρήστης:** Ο πιο βασικός από τους χρήστες. Αυτός ο χρήστης χρειάζεται δικαιώματα που παραχωρούνται από έναν διαχειριστή όταν προσπαθεί να εγκαταστήσει λογισμικό ή να εκτελέσει άλλες προχωρημένες εργασίες. Δεν μπορεί να το κάνει μόνος του.
- **Διαχειριστής Χρήστης**: Ένας χρήστης που λειτουργεί τις περισσότερες φορές ως τυπικός χρήστης αλλά επιτρέπεται επίσης να εκτελεί ενέργειες ρουτ, όπως η εγκατάσταση λογισμικού και άλλες διοικητικές εργασίες. Όλοι οι χρήστες που ανήκουν στην ομάδα διαχειριστών **έχουν πρόσβαση σε ρουτ μέσω του αρχείου sudoers**.
- **Ρούτ**: Ο Ρούτ είναι ένας χρήστης που επιτρέπεται να εκτελεί σχεδόν οποιαδήποτε ενέργεια (υπάρχουν περιορισμοί που επιβάλλονται από προστασίες όπως η Προστασία Ακεραιότητας Συστήματος).
- Για παράδειγμα, ο ρούτ δεν θα μπορεί να τοποθετήσει ένα αρχείο μέσα στο `/System`

## Εξωτερικοί Λογαριασμοί

Το MacOS υποστηρίζει επίσης σύνδεση μέσω εξωτερικών παρόχων ταυτότητας όπως το FaceBook, το Google... Ο κύριος δαίμονας που εκτελεί αυτή τη δουλειά είναι το `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) και είναι δυνατόν να βρείτε πρόσθετα που χρησιμοποιούνται για εξωτερική αυθεντικοποίηση μέσα στον φάκελο `/System/Library/Accounts/Authentication/`.\
Επιπλέον, το `accountsd` αποκτά τη λίστα τύπων λογαριασμών από το `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
