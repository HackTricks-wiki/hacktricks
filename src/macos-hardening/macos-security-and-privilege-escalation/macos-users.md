# macOS 사용자 및 외부 계정

{{#include ../../banners/hacktricks-training.md}}

## 일반 사용자

- **Daemon 계정**: 시스템 데몬용으로 예약되어 있습니다. 짧은 이름은 일반적으로 밑줄(`_`)로 시작합니다:

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **게스트**: 로컬에서 또는 MDM Accounts 페이로드를 통해 사용 여부를 제어할 수 있는 제한된 임시 계정입니다.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: 파일 시스템 권한을 최소한으로 필요로 하는 서비스에서 사용하는 의도적으로 권한을 제한한 계정입니다.
- **Root**: 슈퍼유저입니다. 기본적으로 대화형 root 로그인이 비활성화되어 있지만, 관리자는 authorization과 `sudo`를 통해 권한이 필요한 작업을 수행할 수 있습니다.<sup>[[2]](#references)</sup>

로컬 계정의 password-verification 자료와 이를 추출하는 절차는 [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords)에서 다룹니다.

## User Privileges

- **Standard user:** 일반적인 비관리자 계정 유형입니다. 관리 작업을 수행하려면 관리자의 authorization이 필요합니다.
- **Admin user**: 로컬 `admin` 그룹의 구성원입니다. Admin user도 일반 프로세스는 자신의 사용자 ID로 실행하지만, 권한이 필요한 작업을 승인할 수 있습니다. 그룹 구성원이라는 이유만으로 모든 명령이 root로 실행된다고 가정하지 마세요. `sudo`, Authorization Services, 정책 및 애플리케이션별 검사가 여전히 적용됩니다.<sup>[[2]](#references)</sup>
- **Root**: 거의 모든 작업을 수행할 수 있는 사용자입니다(System Integrity Protection과 같은 보호 기능에 따른 제한은 있습니다).
  - 예를 들어, System Integrity Protection과 signed system volume은 일반적인 작동 중 root조차 보호된 `/System` 콘텐츠를 지속적으로 수정하지 못하게 합니다.

## External Accounts

macOS는 외부 제공업체의 애플리케이션 계정도 지원합니다. `accountsd` 데몬(`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`)은 Accounts framework 데이터를 중개하며, 인증 플러그인은 `/System/Library/Accounts/Authentication/`에서 찾을 수 있습니다. 이러한 계정은 애플리케이션/서비스 계정이며, 반드시 macOS 로그인 창에서 로그인할 수 있는 ID인 것은 아닙니다. `accountsd`는 알려진 계정 유형도 `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`에서 읽습니다.

## References

- [1] [Apple Developer — Accounts 기기 관리 페이로드](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD 권한 및 소유권: 관리자 및 root 계정](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
