# macOS Користувачі та Зовнішні Облікові Записи

{{#include ../../banners/hacktricks-training.md}}

## Загальні Користувачі

- **Daemon**: Користувач, зарезервований для системних демонів. Імена облікових записів демонів за замовчуванням зазвичай починаються з "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Обліковий запис для гостей з дуже суворими правами доступу
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Процеси виконуються з цим користувачем, коли потрібні мінімальні дозволи
- **Root**

## Привілеї користувачів

- **Стандартний користувач:** Найбазовіший з користувачів. Цьому користувачу потрібні дозволи, надані адміністратором, при спробі встановити програмне забезпечення або виконати інші складні завдання. Вони не можуть зробити це самостійно.
- **Адміністратор:** Користувач, який в основному працює як стандартний користувач, але також має право виконувати дії root, такі як встановлення програмного забезпечення та інші адміністративні завдання. Усі користувачі, що належать до групи адміністраторів, **отримують доступ до root через файл sudoers**.
- **Root**: Root - це користувач, якому дозволено виконувати майже будь-яку дію (існують обмеження, накладені такими захистами, як System Integrity Protection).
- Наприклад, root не зможе помістити файл у `/System`

## Зовнішні облікові записи

MacOS також підтримує вхід через зовнішні постачальники ідентичності, такі як FaceBook, Google... Основний демон, що виконує цю роботу, - це `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`), і можна знайти плагіни, що використовуються для зовнішньої аутентифікації, у папці `/System/Library/Accounts/Authentication/`.\
Більше того, `accountsd` отримує список типів облікових записів з `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
