# macOS Kullanıcıları ve Harici Hesaplar

{{#include ../../banners/hacktricks-training.md}}

## Yaygın Kullanıcılar

- **Daemon hesapları**: Sistem daemon'ları için ayrılmıştır. Kısa adları genellikle alt çizgi (`_`) ile başlar:

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Konuk**: Kullanılabilirliği yerel olarak veya bir MDM Accounts payload ile denetlenebilen, kısıtlı ve geçici bir hesap.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Hizmetler tarafından, minimum dosya sistemi izinleriyle çalışmak için kullanılan, bilerek ayrıcalıksız bırakılmış bir kimlik.
- **Root**: Süper kullanıcı. Etkileşimli root oturumu açma varsayılan olarak devre dışıdır; ancak yöneticiler yetkilendirme ve `sudo` aracılığıyla ayrıcalıklı işlemler gerçekleştirebilir.<sup>[[2]](#references)</sup>

Yerel hesap parolası doğrulama materyali ve bunun çıkarılmasına yönelik iş akışı [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords) bölümünde ele alınmıştır.

## User Privileges

- **Standard user:** Normal, yönetici olmayan hesap türü. Yönetimsel değişiklikler için bir yöneticinin yetkilendirmesi gerekir.
- **Admin user**: Yerel `admin` grubunun üyesi. Admin kullanıcıları normal işlemleri kendi kullanıcı kimlikleriyle yürütür, ancak ayrıcalıklı işlemleri yetkilendirebilir. Üyeliğin tek başına her komutun root olarak çalışmasını sağladığını varsaymayın; `sudo`, Authorization Services, ilkeler ve uygulamaya özgü denetimler yine geçerlidir.<sup>[[2]](#references)</sup>
- **Root**: Root, neredeyse her işlemi gerçekleştirebilen bir kullanıcıdır (System Integrity Protection gibi korumaların getirdiği sınırlamalar vardır).
  - Örneğin System Integrity Protection ve imzalı sistem birimi, normal çalışma sırasında root kullanıcısının bile korunan `/System` içeriğini kalıcı olarak değiştirmesini engeller.

## External Accounts

macOS, harici sağlayıcılardan gelen uygulama hesaplarını da destekler. `accountsd` daemon'ı (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) Accounts framework verilerine aracılık eder ve kimlik doğrulama eklentileri `/System/Library/Accounts/Authentication/` altında bulunabilir. Bunlar uygulama/hizmet hesaplarıdır; macOS giriş penceresinde oturum açabilen kimlikler olmaları şart değildir. `accountsd`, bilinen hesap türlerini `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist` dosyasından da okur.

## References

- [1] [Apple Developer — Accounts aygıt yönetimi payload'u](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD izinleri ve sahiplik: yönetici ve root hesapları](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
