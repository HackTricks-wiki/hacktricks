# macOSユーザーと外部アカウント

{{#include ../../banners/hacktricks-training.md}}

## 一般的なユーザー

- **Daemonアカウント**: システムデーモン用に予約されています。短縮名は通常、アンダースコア（`_`）で始まります。

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **ゲスト**: ローカルまたはMDM Accounts payloadで利用可否を制御できる、制限付きの一時アカウント。<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: ファイルシステム権限を最小限にする必要があるサービスが使用する、意図的に権限を制限されたIDです。
- **Root**: スーパーユーザーです。対話型のrootログインはデフォルトで無効ですが、管理者はAuthorizationと`sudo`を通じて特権操作を実行できます。<sup>[[2]](#references)</sup>

ローカルアカウントのパスワード検証情報とその抽出手順については、[Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords)で説明しています。

## ユーザー権限

- **標準ユーザー:** 通常の非管理者アカウントです。管理者による認証がなければ、管理上の変更はできません。
- **管理者ユーザー**: ローカルの`admin`グループのメンバーです。管理者ユーザーも通常のプロセスは自身のユーザーIDで実行しますが、特権操作を承認できます。グループへの所属だけで、すべてのコマンドがrootとして実行されると考えてはいけません。`sudo`、Authorization Services、ポリシー、アプリケーション固有のチェックが引き続き適用されます。<sup>[[2]](#references)</sup>
- **Root**: Rootは、ほぼあらゆる操作を実行できるユーザーです（System Integrity Protectionなどの保護機能による制限があります）。
  - たとえば、System Integrity Protectionと署名済みシステムボリュームにより、通常の動作中はrootであっても、保護された`/System`の内容を永続的に変更できません。

## 外部アカウント

macOSは外部プロバイダーのアプリケーションアカウントにも対応しています。`accountsd`デーモン（`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`）はAccounts frameworkのデータを仲介し、認証プラグインは`/System/Library/Accounts/Authentication/`にあります。これらはアプリケーション／サービスのアカウントであり、必ずしもmacOSのログインウィンドウでログインできるIDではありません。`accountsd`は、既知のアカウントタイプを`/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`からも読み取ります。

## References

- [1] [Apple Developer — Accountsデバイス管理ペイロード](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSDの権限と所有権: 管理者アカウントとrootアカウント](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
