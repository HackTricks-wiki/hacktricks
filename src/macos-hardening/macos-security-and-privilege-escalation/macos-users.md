# Watumiaji wa macOS na Akaunti za Nje

{{#include ../../banners/hacktricks-training.md}}

## Watumiaji wa Kawaida

- **Akaunti za Daemon**: Zimetengwa kwa ajili ya system daemons. Majina yao mafupi kwa kawaida huanza na alama ya underscore (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Mgeni**: Akaunti yenye vikwazo na ya muda, ambayo upatikanaji wake unaweza kudhibitiwa ndani ya mfumo au kupitia MDM Accounts payload.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Utambulisho usio na privileges uliowekwa kimakusudi, unaotumiwa na services zinazohitaji ruhusa ndogo zaidi za filesystem.
- **Root**: Superuser. Kuingia kama root kwa njia ya moja kwa moja kumezimwa kwa chaguo-msingi, ingawa administrators wanaweza kutekeleza operesheni zenye privileges kupitia authorization na `sudo`.<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** Aina ya kawaida ya account isiyo ya administrative. Mabadiliko ya kiutawala yanahitaji authorization kutoka kwa administrator.
- **Admin user**: Mwanachama wa group ya ndani ya `admin`. Admin users bado huendesha processes za kawaida kwa kutumia user identity yao, lakini wanaweza ku-authorize operesheni zenye privileges. Usidhani kwamba uanachama pekee hufanya kila command iendeshwe kama root; `sudo`, Authorization Services, policy, na ukaguzi maalum wa application bado hutumika.<sup>[[2]](#references)</sup>
- **Root**: Root ni user anayeruhusiwa kutekeleza karibu action yoyote (kuna limitations zinazowekwa na protections kama System Integrity Protection).
- Kwa mfano, System Integrity Protection na signed system volume humzuia hata root kurekebisha kwa kudumu maudhui yaliyolindwa ya `/System` wakati wa utendakazi wa kawaida.

## External Accounts

macOS pia inasaidia application accounts kutoka kwa external providers. Daemon ya `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) hufanya broker wa data ya Accounts-framework, na authentication plug-ins zinaweza kupatikana chini ya `/System/Library/Accounts/Authentication/`. Hizi ni application/service accounts, si lazima ziwe identities zinazoweza kuingia kwenye macOS login window. `accountsd` pia husoma aina za accounts zinazojulikana kutoka `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload ya usimamizi wa kifaa cha Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Ruhusa na umiliki wa BSD: administrative na root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
