# macOS Users & External Accounts

{{#include ../../banners/hacktricks-training.md}}

## 一般ユーザー

- **Daemon accounts**: システム daemon 用に予約されています。短い名前は通常、アンダースコア（`_`）で始まります。

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: 制限付きの一時アカウントで、利用可否はローカルまたは MDM Accounts payload によって制御できます。<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: ファイルシステム権限を最小限しか必要としないサービスが使用する、意図的に権限を制限された identity。
- **Root**: superuser。対話型の root login はデフォルトで無効になっていますが、administrators は authorization と `sudo` を通じて特権操作を実行できます。<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** 通常の非管理者 account type。管理上の変更には administrator による authorization が必要です。
- **Admin user**: ローカルの `admin` group のメンバー。Admin users は通常のプロセスを自身の user identity で実行しますが、特権操作を authorization できます。メンバーであるだけで、すべての command が root として実行されると想定しないでください。`sudo`、Authorization Services、policy、application 固有の checks が引き続き適用されます。<sup>[[2]](#references)</sup>
- **Root**: Root はほぼすべての action を実行できる user です（System Integrity Protection などの保護による制限があります）。
- たとえば、System Integrity Protection と signed system volume により、通常の operation 中は root であっても、保護された `/System` content を永続的に変更することはできません。

## External Accounts

macOS は外部 provider の application accounts もサポートしています。`accountsd` daemon（`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`）は Accounts-framework data の仲介を行い、authentication plug-ins は `/System/Library/Accounts/Authentication/` にあります。これらは application/service accounts であり、macOS login window に login できる identities とは限りません。`accountsd` は既知の account types を `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` からも読み取ります。

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: administrative and root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
