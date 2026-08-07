# Користувачі macOS і зовнішні облікові записи

{{#include ../../banners/hacktricks-training.md}}

## Поширені користувачі

- **Daemon**: Користувач, призначений для системних daemon. Назви облікових записів daemon зазвичай починаються з "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Обліковий запис для гостей із дуже суворими дозволами
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Процеси виконуються від імені цього користувача, коли потрібні мінімальні дозволи
- **Root**

## Привілеї користувачів

- **Standard User:** Найбільш базовий тип користувача. Цьому користувачеві потрібні дозволи, надані користувачем-адміністратором, під час спроби встановити програмне забезпечення або виконати інші розширені завдання. Він не може виконувати їх самостійно.
- **Admin User**: Користувач, який більшість часу працює як стандартний користувач, але також може виконувати дії root, як-от встановлення програмного забезпечення та інші адміністративні завдання. Усім користувачам, що належать до групи admin, **надається доступ до root через файл sudoers**.
- **Root**: Root — це користувач, якому дозволено виконувати майже будь-які дії (існують обмеження, встановлені засобами захисту, такими як System Integrity Protection).
- Наприклад, root не зможе розмістити файл усередині `/System`

## Зовнішні облікові записи

MacOS також підтримує вхід через зовнішніх постачальників ідентифікації, таких як FaceBook, Google... Основним daemon, що виконує це завдання, є `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`), а plugins, що використовуються для external authentication, можна знайти в папці `/System/Library/Accounts/Authentication/`.\
Крім того, `accountsd` отримує список типів облікових записів із `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
