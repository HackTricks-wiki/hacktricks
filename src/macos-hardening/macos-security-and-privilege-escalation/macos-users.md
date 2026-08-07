# Χρήστες macOS & Εξωτερικοί Λογαριασμοί

{{#include ../../banners/hacktricks-training.md}}

## Συνήθεις χρήστες

- **Daemon**: Χρήστης που προορίζεται για system daemons. Τα προεπιλεγμένα ονόματα λογαριασμών daemon συνήθως ξεκινούν με "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Λογαριασμός για guests με πολύ αυστηρά δικαιώματα
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Οι διεργασίες εκτελούνται με αυτόν τον χρήστη όταν απαιτούνται ελάχιστα δικαιώματα
- **Root**

## Δικαιώματα χρηστών

- **Standard User:** Ο πιο βασικός τύπος χρήστη. Αυτός ο χρήστης χρειάζεται δικαιώματα που παραχωρούνται από έναν admin user όταν προσπαθεί να εγκαταστήσει software ή να εκτελέσει άλλες προηγμένες εργασίες. Δεν μπορεί να το κάνει μόνος του.
- **Admin User**: Ένας χρήστης που λειτουργεί τις περισσότερες φορές ως standard user, αλλά επιτρέπεται επίσης να εκτελεί root actions, όπως η εγκατάσταση software και άλλες administrative tasks. Όλοι οι χρήστες που ανήκουν στο admin group **αποκτούν πρόσβαση στο root μέσω του sudoers file**.
- **Root**: Το Root είναι ένας χρήστης που επιτρέπεται να εκτελεί σχεδόν οποιαδήποτε ενέργεια (υπάρχουν περιορισμοί που επιβάλλονται από protections όπως το System Integrity Protection).
- Για παράδειγμα, το root δεν θα μπορεί να τοποθετήσει ένα αρχείο μέσα στο `/System`

## External Accounts

Το MacOS υποστηρίζει επίσης login μέσω external identity providers, όπως FaceBook, Google... Ο κύριος daemon που εκτελεί αυτή την εργασία είναι ο `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) και είναι δυνατό να βρεθούν τα plugins που χρησιμοποιούνται για external authentication μέσα στον φάκελο `/System/Library/Accounts/Authentication/`.\
Επιπλέον, το `accountsd` λαμβάνει τη λίστα με τους τύπους λογαριασμών από το `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
