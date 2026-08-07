# macOS Users और External Accounts

{{#include ../../banners/hacktricks-training.md}}

## Common Users

- **Daemon**: System daemons के लिए reserved User। Default daemon account names आमतौर पर "\_" से शुरू होते हैं:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: बहुत सख्त permissions वाले guests के लिए Account
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: न्यूनतम permissions की आवश्यकता होने पर processes इस user के साथ execute की जाती हैं
- **Root**

## User Privileges

- **Standard User:** Users में सबसे basic user। Software install करने या अन्य advanced tasks को perform करने का प्रयास करते समय इस user को admin user द्वारा permissions granted करनी पड़ती हैं। वे इसे स्वयं नहीं कर सकते।
- **Admin User**: ऐसा user जो अधिकांश समय standard user के रूप में operate करता है, लेकिन software install करने और अन्य administrative tasks जैसे root actions perform करने की अनुमति भी रखता है। admin group से संबंधित सभी users को **sudoers file के माध्यम से root का access दिया जाता है**।
- **Root**: Root ऐसा user है जिसे लगभग कोई भी action perform करने की अनुमति होती है (System Integrity Protection जैसी protections द्वारा कुछ limitations imposed हैं)।
- उदाहरण के लिए root `/System` के अंदर कोई file नहीं रख पाएगा

## External Accounts

MacOS FaceBook, Google... जैसे external identity providers के माध्यम से login करने का भी support करता है। इस कार्य को perform करने वाला मुख्य daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) है और external authentication के लिए उपयोग किए जाने वाले plugins को `/System/Library/Accounts/Authentication/` folder के अंदर find करना संभव है।\
इसके अलावा, `accountsd` account types की list `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` से प्राप्त करता है।

{{#include ../../banners/hacktricks-training.md}}
