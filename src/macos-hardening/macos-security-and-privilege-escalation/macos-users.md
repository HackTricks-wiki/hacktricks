# macOS Kullanıcıları ve Harici Hesaplar

{{#include ../../banners/hacktricks-training.md}}

## Yaygın Kullanıcılar

- **Daemon hesapları**: Sistem daemon'ları için ayrılmıştır. Kısa adları genellikle alt çizgi (`_`) ile başlar:

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Misafir**: Kullanılabilirliği yerel olarak veya bir MDM Accounts payload aracılığıyla denetlenebilen kısıtlı, geçici bir hesaptır.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Minimum dosya sistemi izinleri gerektiren servisler tarafından kullanılan, kasıtlı olarak ayrıcalıksız bir kimlik.
- **Root**: Superuser. Etkileşimli root login varsayılan olarak devre dışıdır; ancak yöneticiler authorization ve `sudo` aracılığıyla ayrıcalıklı işlemler gerçekleştirebilir.<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** Normal, yönetici olmayan hesap türü. Yönetimsel değişiklikler bir yöneticinin authorization işlemini gerektirir.
- **Admin user**: Yerel `admin` grubunun üyesi. Admin users, normal işlemleri hâlâ kendi kullanıcı kimlikleriyle çalıştırır; ancak ayrıcalıklı işlemler için authorization sağlayabilir. Tek başına grup üyeliğinin her komutun root olarak çalışacağı anlamına geldiğini varsaymayın; `sudo`, Authorization Services, policy ve uygulamaya özgü kontroller yine geçerlidir.<sup>[[2]](#references)</sup>
- **Root**: Root, neredeyse her işlemi gerçekleştirmesine izin verilen bir user'dır (System Integrity Protection gibi korumalar tarafından getirilen sınırlamalar vardır).
- Örneğin System Integrity Protection ve signed system volume, normal çalışma sırasında root'un bile korunan `/System` içeriğini kalıcı olarak değiştirmesini engeller.

## External Accounts

macOS ayrıca external provider'lardan application accounts desteği de sunar. `accountsd` daemon'ı (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) Accounts-framework verilerini broker olarak yönetir ve authentication plug-in'leri `/System/Library/Accounts/Authentication/` altında bulunabilir. Bunlar application/service accounts'tur ve macOS login window'da oturum açabilen identities olmak zorunda değildir. `accountsd`, bilinen account type'larını `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` dosyasından da okur.

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: administrative and root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
