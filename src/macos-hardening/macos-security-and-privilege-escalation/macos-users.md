# macOS 用户与外部账户

{{#include ../../banners/hacktricks-training.md}}

## 常见用户

- **Daemon**: 保留给系统守护进程的用户。默认的守护进程账户名称通常以“\_”开头：

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: 访客账户，权限非常严格
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: 当需要最小权限时，以此用户执行进程
- **Root**

## 用户权限

- **标准用户**：最基本的用户。此用户在尝试安装软件或执行其他高级任务时需要管理员用户授予的权限。他们无法独立完成这些操作。
- **管理员用户**：大多数时候作为标准用户操作，但也被允许执行根操作，如安装软件和其他管理任务。所有属于管理员组的用户**通过sudoers文件获得root访问权限**。
- **Root**：Root是一个被允许执行几乎任何操作的用户（受系统完整性保护等保护措施的限制）。
- 例如，root无法将文件放置在`/System`内

## 外部账户

MacOS还支持通过外部身份提供者登录，如FaceBook、Google等。执行此工作的主要守护进程是`accountsd`（`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`），可以在文件夹`/System/Library/Accounts/Authentication/`中找到用于外部身份验证的插件。\
此外，`accountsd`从`/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`获取账户类型列表。

{{#include ../../banners/hacktricks-training.md}}
