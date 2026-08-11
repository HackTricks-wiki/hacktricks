# Χρήστες macOS και εξωτερικοί λογαριασμοί

{{#include ../../banners/hacktricks-training.md}}

## Συνήθεις χρήστες

- **Λογαριασμοί Daemon**: Προορίζονται για system daemons. Τα σύντομα ονόματά τους συνήθως ξεκινούν με κάτω παύλα (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Ένας περιορισμένος, προσωρινός λογαριασμός, του οποίου η διαθεσιμότητα μπορεί να ελέγχεται τοπικά ή μέσω ενός MDM Accounts payload.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Μια σκόπιμα μη προνομιούχα ταυτότητα που χρησιμοποιείται από services τα οποία απαιτούν ελάχιστα δικαιώματα στο filesystem.
- **Root**: Ο superuser. Η interactive σύνδεση ως root είναι απενεργοποιημένη από προεπιλογή, αν και οι administrators μπορούν να εκτελούν προνομιούχες λειτουργίες μέσω authorization και `sudo`.<sup>[[2]](#references)</sup>

## User Privileges

- **Τυπικός χρήστης:** Ο συνήθης, μη administrative τύπος λογαριασμού. Οι administrative αλλαγές απαιτούν authorization από έναν administrator.
- **Admin user**: Μέλος του τοπικού `admin` group. Οι admin users εξακολουθούν να εκτελούν τις συνήθεις διεργασίες με τη δική τους user identity, αλλά μπορούν να παρέχουν authorization για προνομιούχες λειτουργίες. Μην υποθέτετε ότι η ιδιότητα μέλους από μόνη της κάνει κάθε command να εκτελείται ως root· τα `sudo`, Authorization Services, η policy και οι application-specific έλεγχοι εξακολουθούν να ισχύουν.<sup>[[2]](#references)</sup>
- **Root**: Ο root είναι ένας user που επιτρέπεται να εκτελεί σχεδόν οποιαδήποτε ενέργεια (υπάρχουν περιορισμοί που επιβάλλονται από protections όπως το System Integrity Protection).
- Για παράδειγμα, το System Integrity Protection και το signed system volume εμποδίζουν ακόμη και τον root από το να τροποποιεί μόνιμα προστατευμένο περιεχόμενο του `/System` κατά την κανονική λειτουργία.

## External Accounts

Το macOS υποστηρίζει επίσης application accounts από external providers. Το daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) λειτουργεί ως broker για τα δεδομένα του Accounts framework, ενώ authentication plug-ins μπορούν να βρεθούν στο `/System/Library/Accounts/Authentication/`. Αυτοί είναι application/service accounts και όχι απαραίτητα identities που μπορούν να συνδεθούν στο macOS login window. Το `accountsd` διαβάζει επίσης τους γνωστούς τύπους λογαριασμών από το `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — payload διαχείρισης Accounts για συσκευές](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Δικαιώματα και ιδιοκτησία BSD: administrative και root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
