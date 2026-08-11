# Користувачі macOS і зовнішні облікові записи

{{#include ../../banners/hacktricks-training.md}}

## Поширені користувачі

- **Облікові записи daemon**: Зарезервовані для системних daemon. Їхні короткі імена зазвичай починаються з символу підкреслення (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Обмежений тимчасовий обліковий запис, доступність якого можна контролювати локально або за допомогою payload Accounts у MDM.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Навмисно непривілейована ідентичність, яку використовують служби, що потребують мінімальних дозволів файлової системи.
- **Root**: Суперкористувач. Інтерактивний вхід до root типово вимкнено, хоча адміністратори можуть виконувати привілейовані операції через авторизацію та `sudo`.<sup>[[2]](#references)</sup>

## Привілеї користувачів

- **Standard user:** Звичайний обліковий запис без адміністративних прав. Для адміністративних змін потрібна авторизація адміністратора.
- **Admin user**: Член локальної групи `admin`. Admin users як і раніше запускають звичайні процеси зі своєю ідентичністю користувача, але можуть авторизувати привілейовані операції. Не слід вважати, що саме членство автоматично запускає кожну команду від імені root; також застосовуються `sudo`, Authorization Services, політики та перевірки, специфічні для застосунків.<sup>[[2]](#references)</sup>
- **Root**: Root — це користувач, якому дозволено виконувати майже будь-які дії (існують обмеження, встановлені такими засобами захисту, як System Integrity Protection).
- Наприклад, System Integrity Protection і підписаний системний том не дозволяють навіть root постійно змінювати захищений вміст `/System` під час нормальної роботи.

## Зовнішні облікові записи

macOS також підтримує облікові записи застосунків від зовнішніх провайдерів. Демон `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) забезпечує брокеринг даних Accounts-framework, а plug-ins автентифікації можна знайти в `/System/Library/Accounts/Authentication/`. Це облікові записи застосунків/служб, а не обов’язково ідентичності, які можуть входити через вікно входу macOS. `accountsd` також читає відомі типи облікових записів із `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — П payload керування обліковими записами пристрою](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Дозволи BSD і права власності: адміністративні облікові записи та root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
