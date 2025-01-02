# macOS ユーザーと外部アカウント

{{#include ../../banners/hacktricks-training.md}}

## 一般的なユーザー

- **Daemon**: システムデーモン用に予約されたユーザー。デフォルトのデーモンアカウント名は通常「\_」で始まります：

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: 非常に厳しい権限を持つゲスト用アカウント
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: 最小限の権限が必要なときにこのユーザーでプロセスが実行されます
- **Root**

## ユーザープリビレッジ

- **標準ユーザー:** 最も基本的なユーザー。このユーザーは、ソフトウェアをインストールしたり、他の高度なタスクを実行しようとする際に、管理者ユーザーから権限を付与される必要があります。自分自身ではそれを行うことができません。
- **管理者ユーザー**: 大部分の時間を標準ユーザーとして操作しますが、ソフトウェアのインストールやその他の管理タスクなどのrootアクションを実行することも許可されています。管理者グループに属するすべてのユーザーは**sudoersファイルを介してrootにアクセスが与えられます**。
- **Root**: Rootはほぼすべてのアクションを実行することが許可されているユーザーです（System Integrity Protectionのような保護によって制限があります）。
- 例えば、rootは`/System`内にファイルを置くことができません。

## 外部アカウント

MacOSは、FaceBookやGoogleなどの外部アイデンティティプロバイダーを介してログインすることもサポートしています。この作業を行う主なデーモンは`accountsd`（`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`）であり、外部認証に使用されるプラグインは`/System/Library/Accounts/Authentication/`フォルダー内にあります。\
さらに、`accountsd`は`/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`からアカウントタイプのリストを取得します。

{{#include ../../banners/hacktricks-training.md}}
