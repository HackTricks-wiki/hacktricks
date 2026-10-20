# Користувачі macOS і зовнішні облікові записи

{{#include ../../banners/hacktricks-training.md}}

## Типові користувачі

- **Облікові записи daemon**: призначені для системних daemon. Їхні короткі імена зазвичай починаються з підкреслення (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Гість**: Обмежений тимчасовий обліковий запис, доступність якого можна контролювати локально або за допомогою payload Accounts у MDM.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Навмисно непривілейований обліковий запис, який використовують служби, що потребують мінімальних дозволів файлової системи.
- **Root**: Суперкористувач. Інтерактивний вхід root за замовчуванням вимкнено, хоча адміністратори можуть виконувати привілейовані операції через авторизацію та `sudo`.<sup>[[2]](#references)</sup>

Матеріал для перевірки паролів локальних облікових записів і процес його вилучення описані в розділі [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## Привілеї користувачів

- **Стандартний користувач:** звичайний обліковий запис без прав адміністратора. Для адміністративних змін потрібна авторизація адміністратора.
- **Користувач-адміністратор**: член локальної групи `admin`. Користувачі-адміністратори й далі запускають звичайні процеси від імені свого облікового запису, але можуть авторизувати привілейовані операції. Не припускайте, що саме членство в групі змушує кожну команду виконуватися від імені root: усе ще застосовуються `sudo`, Authorization Services, політики та перевірки конкретних програм.<sup>[[2]](#references)</sup>
- **Root**: користувач, якому дозволено виконувати майже будь-які дії (є обмеження, встановлені такими засобами захисту, як System Integrity Protection).
  - Наприклад, System Integrity Protection і підписаний системний том за звичайної роботи не дають навіть root постійно змінювати захищений вміст `/System`.

## Зовнішні облікові записи

macOS також підтримує облікові записи програм від зовнішніх постачальників. Демон `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) надає доступ до даних Accounts framework, а модулі автентифікації можна знайти в `/System/Library/Accounts/Authentication/`. Це облікові записи програм і служб, які не обов’язково є ідентичностями, що можуть входити в систему через вікно входу macOS. `accountsd` також зчитує відомі типи облікових записів із `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — корисне навантаження керування обліковими записами пристрою](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — дозволи BSD і власність: облікові записи адміністратора та root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
