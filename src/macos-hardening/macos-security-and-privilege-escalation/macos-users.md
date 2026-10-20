# macOS 用户与外部账户

{{#include ../../banners/hacktricks-training.md}}

## 常见用户

- **守护进程账户**：为系统守护进程保留。它们的短名称通常以下划线（`_`）开头：

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **访客**：受限的临时账户，其可用性可由本地或 MDM Accounts payload 控制。<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**：一种刻意设置为低权限的身份，供只需最小文件系统权限的服务使用。
- **Root**：超级用户。默认情况下禁用交互式 root 登录，但管理员可以通过授权和 `sudo` 执行特权操作。<sup>[[2]](#references)</sup>

本地账户的密码验证材料及其提取流程详见[Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords)。

## 用户权限

- **标准用户：**普通的非管理员账户类型。进行管理性更改需要获得管理员授权。
- **管理员用户**：本地 `admin` 组的成员。管理员用户仍以自己的用户身份运行普通进程，但可以授权特权操作。不要认为仅凭组成员身份就能让每条命令都以 root 身份运行；`sudo`、Authorization Services、策略和应用程序特定检查仍然适用。<sup>[[2]](#references)</sup>
- **Root**：Root 是可以执行几乎任何操作的用户（但 System Integrity Protection 等保护机制会施加限制）。
  - 例如，在正常运行期间，System Integrity Protection 和签名系统卷会阻止 root 持久修改受保护的 `/System` 内容。

## 外部账户

macOS 还支持来自外部提供商的应用程序账户。`accountsd` 守护进程（`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`）负责中介处理 Accounts-framework 数据，身份验证插件位于 `/System/Library/Accounts/Authentication/` 下。这些是应用程序/服务账户，不一定是能在 macOS 登录窗口登录的身份。`accountsd` 还会从 `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` 读取已知账户类型。

## References

- [1] [Apple Developer — 账户设备管理负载](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD 权限与所有权：管理账户和 root 账户](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
