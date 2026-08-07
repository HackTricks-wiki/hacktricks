# macOS Kullanıcıları ve Harici Hesaplar

{{#include ../../banners/hacktricks-training.md}}

## Yaygın Kullanıcılar

- **Daemon**: Sistem daemon'ları için ayrılmış kullanıcı. Varsayılan daemon hesap adları genellikle "\_" ile başlar:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Çok kısıtlı izinlere sahip konuklar için hesap.
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Minimum izinler gerektiğinde işlemler bu kullanıcıyla yürütülür
- **Root**

## Kullanıcı Ayrıcalıkları

- **Standart Kullanıcı:** Kullanıcıların en temel türüdür. Bu kullanıcı yazılım yüklemeye veya diğer gelişmiş görevleri gerçekleştirmeye çalıştığında bir admin user tarafından verilen izinlere ihtiyaç duyar. Bunları kendi başına gerçekleştiremez.
- **Admin User**: Çoğu zaman standart kullanıcı olarak çalışan, ancak yazılım yüklemek ve diğer yönetim görevlerini gerçekleştirmek gibi root işlemlerini de gerçekleştirebilen kullanıcıdır. Admin grubuna dahil olan tüm kullanıcılara **sudoers file üzerinden root erişimi verilir**.
- **Root**: Root, neredeyse her işlemi gerçekleştirmesine izin verilen kullanıcıdır (System Integrity Protection gibi korumalar tarafından kısıtlamalar uygulanır).
- Örneğin root, `/System` içine bir dosya yerleştiremez

## External Accounts

MacOS ayrıca FaceBook, Google... gibi harici identity provider'lar üzerinden giriş yapmayı da destekler. Bu işi gerçekleştiren ana daemon `accountsd`'dir (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) ve harici authentication için kullanılan plugin'leri `/System/Library/Accounts/Authentication/` klasörü içinde bulmak mümkündür.\
Ayrıca `accountsd`, account type listesini `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` dosyasından alır.

{{#include ../../banners/hacktricks-training.md}}
