# macOS 사용자 및 External Accounts

{{#include ../../banners/hacktricks-training.md}}

## 일반 사용자

- **Daemon accounts**: 시스템 데몬용으로 예약된 계정입니다. 짧은 이름은 일반적으로 밑줄(`_`)로 시작합니다:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: 로컬에서 또는 MDM Accounts payload를 통해 사용 가능 여부를 제어할 수 있는 제한된 임시 계정입니다.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: 최소한의 파일시스템 권한이 필요한 서비스에서 사용하는 의도적으로 권한이 없는 identity입니다.
- **Root**: superuser입니다. 기본적으로 대화형 root login은 비활성화되어 있지만, 관리자는 authorization 및 `sudo`를 통해 privileged operation을 수행할 수 있습니다.<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** 일반적인 non-administrative account type입니다. Administrative change를 수행하려면 administrator의 authorization이 필요합니다.
- **Admin user**: 로컬 `admin` group의 member입니다. Admin user도 일반 process를 자신의 user identity로 실행하지만, privileged operation을 authorize할 수 있습니다. membership만으로 모든 command가 root로 실행된다고 가정하지 마세요. `sudo`, Authorization Services, policy 및 application-specific check가 여전히 적용됩니다.<sup>[[2]](#references)</sup>
- **Root**: 거의 모든 action을 수행할 수 있는 user입니다(System Integrity Protection과 같은 protection에 의해 제한이 적용됨).
- 예를 들어 System Integrity Protection과 signed system volume은 정상 operation 중 root조차 보호된 `/System` content를 지속적으로 수정하지 못하도록 합니다.

## External Accounts

macOS는 external provider의 application account도 지원합니다. `accountsd` daemon (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`)은 Accounts-framework data를 broker하며, authentication plug-in은 `/System/Library/Accounts/Authentication/` 아래에서 찾을 수 있습니다. 이러한 account는 application/service account이며, macOS login window에서 login할 수 있는 identity인 것은 반드시 아닙니다. `accountsd`는 `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`에서 known account type도 읽습니다.

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: administrative and root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
