# macOS Users और External Accounts

{{#include ../../banners/hacktricks-training.md}}

## सामान्य Users

- **Daemon accounts**: सिस्टम daemons के लिए आरक्षित। इनके short names आमतौर पर underscore (`_`) से शुरू होते हैं:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: एक restricted, temporary account जिसकी availability को locally या MDM Accounts payload द्वारा नियंत्रित किया जा सकता है।<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: ऐसी जानबूझकर कम-अधिकार वाली identity, जिसका उपयोग उन services द्वारा किया जाता है जिन्हें न्यूनतम filesystem permissions की आवश्यकता होती है।
- **Root**: Superuser। Interactive root login डिफ़ॉल्ट रूप से disabled होता है, हालांकि administrators authorization और `sudo` के माध्यम से privileged operations कर सकते हैं।<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** सामान्य, non-administrative account type। Administrative changes के लिए administrator से authorization आवश्यक होता है।
- **Admin user**: स्थानीय `admin` group का member। Admin users अभी भी ordinary processes को अपनी user identity के साथ चलाते हैं, लेकिन privileged operations को authorize कर सकते हैं। यह न मानें कि केवल membership के कारण हर command root के रूप में चलती है; `sudo`, Authorization Services, policy और application-specific checks अभी भी लागू होते हैं।<sup>[[2]](#references)</sup>
- **Root**: Root ऐसा user है जिसे लगभग कोई भी action करने की अनुमति होती है (System Integrity Protection जैसी protections द्वारा कुछ limitations लगाई जाती हैं)।
- उदाहरण के लिए, System Integrity Protection और signed system volume, normal operation के दौरान root को भी protected `/System` content को persistently modify करने से रोकते हैं।

## External Accounts

macOS external providers के application accounts को भी support करता है। `accountsd` daemon (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) Accounts-framework data को broker करता है, और authentication plug-ins `/System/Library/Accounts/Authentication/` के अंतर्गत पाए जा सकते हैं। ये application/service accounts हैं, आवश्यक नहीं कि ऐसी identities हों जो macOS login window पर login कर सकें। `accountsd`, `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` से known account types भी पढ़ता है।

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: administrative and root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
