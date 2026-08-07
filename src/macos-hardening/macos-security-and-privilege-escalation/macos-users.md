# macOS 用户与外部账户

{{#include ../../banners/hacktricks-training.md}}

## 常见用户

- **Daemon**：为系统 daemons 保留的用户。默认的 daemon 账户名称通常以“\_”开头：

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**：为访客提供的账户，具有非常严格的权限。
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**：在需要最小权限时，进程会以此用户身份执行
- **Root**

## 用户权限

- **标准用户：** 最基本的用户。尝试安装软件或执行其他高级任务时，此用户需要获得管理员用户授予的权限，无法自行执行这些操作。
- **管理员用户：** 大多数时间以标准用户身份运行，但也可以执行安装软件和其他管理任务等 root 操作的用户。属于 admin 组的所有用户都**可通过 sudoers file 获得 root 权限**。
- **Root：** Root 是几乎可以执行任何操作的用户（但会受到 System Integrity Protection 等保护机制施加的限制）。
- 例如，root 无法将文件放入 `/System`

## 外部账户

MacOS 也支持通过 FaceBook、Google 等外部身份提供商登录。执行此任务的主要 daemon 是 `accountsd`（`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`），并且可以在文件夹 `/System/Library/Accounts/Authentication/` 中找到用于外部身份验证的插件。\
此外，`accountsd` 会从 `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` 获取账户类型列表。

{{#include ../../banners/hacktricks-training.md}}
