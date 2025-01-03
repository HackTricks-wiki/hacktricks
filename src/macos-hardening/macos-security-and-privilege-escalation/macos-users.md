# macOS Users & External Accounts

{{#include ../../banners/hacktricks-training.md}}

## Common Users

- **Daemon**: User reserved for system daemons. The default daemon account names usually start with a "\_":

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Guest**: Account for guests with very strict permissions

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Processes are executed with this user when minimal permissions are required
- **Root**

## User Privileges

- **Standard User:** The most basic of users. This user needs permissions granted from an admin user when attempting to install software or perform other advanced tasks. They are not able to do it on their own.
- **Admin User**: A user who operates most of the time as a standard user but is also allowed to perform root actions such as install software and other administrative tasks. All users belonging to the admin group are **given access to root via the sudoers file**.
- **Root**: Root is a user allowed to perform almost any action (there are limitations imposed by protections like System Integrity Protection).
  - For example root won't be able to place a file inside `/System`

## External Accounts

MacOS also support to login via external identity providers such as FaceBook, Google... The main daemon performing this job is `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) and it's possible to find plugins used for external authentication inside the folder `/System/Library/Accounts/Authentication/`.\
Moreover, `accountsd` gets the list of account types from `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}



