# macOS उपयोगकर्ता और बाहरी खाते

{{#include ../../banners/hacktricks-training.md}}

## सामान्य उपयोगकर्ता

- **Daemon खाते**: सिस्टम daemons के लिए आरक्षित। इनके छोटे नाम आमतौर पर अंडरस्कोर (`_`) से शुरू होते हैं:

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **अतिथि**: एक प्रतिबंधित, अस्थायी खाता, जिसकी उपलब्धता स्थानीय रूप से या MDM Accounts payload के माध्यम से नियंत्रित की जा सकती है।<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: जानबूझकर बनाया गया एक गैर-विशेषाधिकार प्राप्त पहचानकर्ता, जिसका उपयोग उन सेवाओं द्वारा किया जाता है जिन्हें फ़ाइल सिस्टम की न्यूनतम अनुमतियों की आवश्यकता होती है।
- **Root**: सुपरयूज़र। डिफ़ॉल्ट रूप से इंटरैक्टिव root लॉगिन अक्षम होता है, हालांकि एडमिनिस्ट्रेटर authorization और `sudo` के माध्यम से विशेषाधिकार प्राप्त ऑपरेशन कर सकते हैं।<sup>[[2]](#references)</sup>

स्थानीय अकाउंट के पासवर्ड-सत्यापन सामग्री और उसे निकालने की प्रक्रिया [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords) में शामिल हैं।

## User Privileges

- **Standard user:** सामान्य, गैर-एडमिनिस्ट्रेटिव अकाउंट प्रकार। एडमिनिस्ट्रेटिव बदलावों के लिए एडमिनिस्ट्रेटर से authorization आवश्यक है।
- **Admin user**: स्थानीय `admin` group का सदस्य। Admin users सामान्य प्रक्रियाएँ अपनी user identity के साथ ही चलाते हैं, लेकिन विशेषाधिकार प्राप्त ऑपरेशन को authorize कर सकते हैं। यह न मानें कि केवल group में सदस्यता होने से हर command root के रूप में चलेगी; `sudo`, Authorization Services, policy और application-विशिष्ट जाँचें भी लागू होती हैं।<sup>[[2]](#references)</sup>
- **Root**: Root ऐसा user है जिसे लगभग कोई भी action करने की अनुमति है (System Integrity Protection जैसे सुरक्षा उपायों द्वारा कुछ सीमाएँ लगाई जाती हैं)।
  - उदाहरण के लिए, System Integrity Protection और signed system volume सामान्य संचालन के दौरान root को भी संरक्षित `/System` सामग्री में स्थायी बदलाव करने से रोकते हैं।

## External Accounts

macOS बाहरी providers के application accounts का भी समर्थन करता है। `accountsd` daemon (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) Accounts-framework डेटा को ब्रोकर करता है, और authentication plug-ins `/System/Library/Accounts/Authentication/` में मिल सकते हैं। ये application/service accounts हैं, और ज़रूरी नहीं कि macOS login window पर लॉगिन करने योग्य identities हों। `accountsd`, ज्ञात account types को `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` से भी पढ़ता है।

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: प्रशासनिक और root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
