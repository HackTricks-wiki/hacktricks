# macOS Users & External Accounts

{{#include ../../banners/hacktricks-training.md}}

## Common Users

- **Daemon**: system daemon 用に予約されたユーザー。デフォルトの daemon アカウント名は通常 "\_" で始まります:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: 非常に厳格な権限を持つゲスト用アカウント
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: 最小限の権限が必要な場合、プロセスはこのユーザーで実行されます
- **Root**

## User Privileges

- **Standard User:** 最も基本的なユーザーです。このユーザーがソフトウェアをインストールしたり、その他の高度なタスクを実行したりする場合、admin user から付与された権限が必要です。自分自身で実行することはできません。
- **Admin User**: 通常は standard user として操作しますが、ソフトウェアのインストールやその他の管理タスクなど、root actions の実行も許可されているユーザーです。admin group に属するすべてのユーザーには、**sudoers file を介して root へのアクセス権が付与されます**。
- **Root**: Root は、ほぼすべての操作を実行できるユーザーです（System Integrity Protection などの保護機能による制限があります）。
- 例えば root でも、`/System` 内にファイルを配置することはできません

## External Accounts

MacOS は FaceBook、Google などの external identity providers を介した login もサポートしています。この処理を実行する主な daemon は `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) であり、external authentication に使用される plugins は `/System/Library/Accounts/Authentication/` フォルダ内で確認できます。\
さらに、`accountsd` は `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` から account types の一覧を取得します。

{{#include ../../banners/hacktricks-training.md}}
