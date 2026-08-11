# macOS 用户与外部账户

{{#include ../../banners/hacktricks-training.md}}

## 常见用户

- **Daemon 账户**：为系统 Daemon 保留。其短名称通常以下划线（`_`）开头：

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**：一种受限的临时账户，其可用性可在本地控制，也可通过 MDM Accounts payload 控制。<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**：服务使用的、特意设置为无特权的身份，仅需要最小的文件系统权限。
- **Root**：超级用户。默认情况下禁用交互式 root 登录，但管理员可以通过授权和 `sudo` 执行特权操作。<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user：** 普通的非管理员账户类型。管理性更改需要管理员授权。
- **Admin user**：本地 `admin` 组的成员。Admin 用户仍以自身用户身份运行普通进程，但可以为特权操作提供授权。不要假设仅凭组成员身份就能让每条命令都以 root 身份运行；`sudo`、Authorization Services、policy 以及特定于应用程序的检查仍然适用。<sup>[[2]](#references)</sup>
- **Root**：Root 是一个几乎可以执行任何操作的用户（System Integrity Protection 等保护机制会施加一些限制）。
- 例如，System Integrity Protection 和 signed system volume 会阻止 root 在正常运行期间持久修改受保护的 `/System` 内容。

## External Accounts

macOS 还支持来自外部提供商的 application accounts。`accountsd` daemon（`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`）负责中介处理 Accounts-framework 数据，而 authentication plug-ins 位于 `/System/Library/Accounts/Authentication/` 下。这些是 application/service accounts，不一定是可以在 macOS 登录窗口中登录的身份。`accountsd` 还会从 `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` 读取已知的账户类型。

## References

- [1] [Apple Developer — Accounts 设备管理 payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD 权限和所有权：管理账户与 root 账户](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
