# macOS 사용자 및 외부 계정

{{#include ../../banners/hacktricks-training.md}}

## 일반 사용자

- **Daemon**: 시스템 데몬을 위한 사용자. 기본 데몬 계정 이름은 보통 "\_"로 시작합니다:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: 매우 제한된 권한을 가진 게스트 계정
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: 최소 권한이 필요할 때 이 사용자로 프로세스가 실행됩니다.
- **Root**

## 사용자 권한

- **표준 사용자:** 가장 기본적인 사용자입니다. 이 사용자는 소프트웨어를 설치하거나 다른 고급 작업을 수행할 때 관리자 사용자로부터 권한을 부여받아야 합니다. 스스로는 이를 수행할 수 없습니다.
- **관리자 사용자**: 대부분의 경우 표준 사용자로 작동하지만 소프트웨어 설치 및 기타 관리 작업과 같은 루트 작업을 수행할 수 있는 권한이 부여된 사용자입니다. 관리자 그룹에 속한 모든 사용자는 **sudoers 파일을 통해 루트에 접근할 수 있습니다**.
- **Root**: Root는 거의 모든 작업을 수행할 수 있는 사용자입니다(시스템 무결성 보호와 같은 보호에 의해 제한이 있습니다).
- 예를 들어, root는 `/System` 내부에 파일을 배치할 수 없습니다.

## 외부 계정

MacOS는 FaceBook, Google 등과 같은 외부 신원 제공자를 통해 로그인하는 것도 지원합니다. 이 작업을 수행하는 주요 데몬은 `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`)이며, 외부 인증에 사용되는 플러그인은 `/System/Library/Accounts/Authentication/` 폴더 내에서 찾을 수 있습니다.\
또한, `accountsd`는 `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`에서 계정 유형 목록을 가져옵니다.

{{#include ../../banners/hacktricks-training.md}}
