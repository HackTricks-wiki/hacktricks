# macOS Users & External Accounts

{{#include ../../banners/hacktricks-training.md}}

## सामान्य उपयोगकर्ता

- **Daemon**: सिस्टम डेमन्स के लिए आरक्षित उपयोगकर्ता। डिफ़ॉल्ट डेमन खाता नाम आमतौर पर "\_" से शुरू होते हैं:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: मेहमानों के लिए खाता जिसमें बहुत सख्त अनुमतियाँ हैं
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **कोई नहीं**: प्रक्रियाएँ इस उपयोगकर्ता के साथ निष्पादित होती हैं जब न्यूनतम अनुमतियों की आवश्यकता होती है
- **रूट**

## उपयोगकर्ता विशेषाधिकार

- **मानक उपयोगकर्ता:** उपयोगकर्ताओं का सबसे बुनियादी प्रकार। इस उपयोगकर्ता को सॉफ़्टवेयर स्थापित करने या अन्य उन्नत कार्य करने का प्रयास करते समय एक व्यवस्थापक उपयोगकर्ता से अनुमतियाँ प्राप्त करने की आवश्यकता होती है। वे इसे अपने दम पर नहीं कर सकते।
- **व्यवस्थापक उपयोगकर्ता**: एक उपयोगकर्ता जो अधिकांश समय मानक उपयोगकर्ता के रूप में कार्य करता है लेकिन सॉफ़्टवेयर स्थापित करने और अन्य प्रशासनिक कार्य करने जैसे रूट क्रियाएँ करने की अनुमति भी है। व्यवस्थापक समूह से संबंधित सभी उपयोगकर्ताओं को **sudoers फ़ाइल के माध्यम से रूट तक पहुँच दी जाती है**।
- **रूट**: रूट एक उपयोगकर्ता है जिसे लगभग किसी भी क्रिया को करने की अनुमति है (सिस्टम इंटीग्रिटी प्रोटेक्शन जैसी सुरक्षा द्वारा कुछ सीमाएँ लगाई गई हैं)।
- उदाहरण के लिए, रूट `/System` के अंदर एक फ़ाइल रखने में असमर्थ होगा

## बाहरी खाते

MacOS बाहरी पहचान प्रदाताओं जैसे FaceBook, Google के माध्यम से लॉगिन का समर्थन करता है... इस कार्य को करने वाला मुख्य डेमन `accountsd` है (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) और बाहरी प्रमाणीकरण के लिए उपयोग किए जाने वाले प्लगइन्स को `/System/Library/Accounts/Authentication/` फ़ोल्डर के अंदर पाया जा सकता है।\
इसके अलावा, `accountsd` `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` से खाता प्रकारों की सूची प्राप्त करता है।

{{#include ../../banners/hacktricks-training.md}}
