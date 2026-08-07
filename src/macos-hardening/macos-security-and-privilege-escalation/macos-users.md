# macOS 사용자 및 외부 계정

{{#include ../../banners/hacktricks-training.md}}

## 일반 사용자

- **Daemon**: 시스템 daemon용으로 예약된 사용자입니다. 기본 daemon 계정 이름은 일반적으로 "\_"로 시작합니다:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: 매우 엄격한 권한을 가진 게스트용 계정
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: 최소한의 권한만 필요한 경우 프로세스는 이 사용자로 실행됩니다
- **Root**

## 사용자 권한

- **Standard User:** 가장 기본적인 사용자입니다. 이 사용자가 software를 설치하거나 기타 고급 작업을 수행하려면 admin user로부터 권한을 부여받아야 합니다. 스스로는 이를 수행할 수 없습니다.
- **Admin User**: 대부분의 경우 standard user로 작동하지만, software 설치 및 기타 관리 작업과 같은 root 작업도 수행할 수 있는 사용자입니다. admin group에 속한 모든 사용자는 **sudoers file을 통해 root에 대한 access가 부여됩니다**.
- **Root**: Root는 거의 모든 작업을 수행할 수 있는 사용자입니다(System Integrity Protection과 같은 보호 기능에 의해 제한되는 작업은 예외입니다).
- 예를 들어 root도 `/System` 내부에 file을 배치할 수 없습니다

## External Accounts

MacOS는 FaceBook, Google 등의 external identity provider를 통한 login도 지원합니다. 이 작업을 수행하는 주요 daemon은 `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`)이며, external authentication에 사용되는 plugin은 `/System/Library/Accounts/Authentication/` folder 내부에서 찾을 수 있습니다.\
또한 `accountsd`는 `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`에서 account type 목록을 가져옵니다.

{{#include ../../banners/hacktricks-training.md}}
