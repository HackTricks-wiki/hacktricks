# Watumiaji wa macOS na Akaunti za Nje

{{#include ../../banners/hacktricks-training.md}}

## Watumiaji wa Kawaida

- **Akaunti za daemon**: Zimetengwa kwa ajili ya daemon za mfumo. Majina yao mafupi kwa kawaida huanza na underscore (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Mgeni**: Akaunti ya muda yenye vizuizi, ambayo upatikanaji wake unaweza kudhibitiwa kwenye kifaa au kupitia payload ya MDM Accounts.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Utambulisho usio na ruhusa za ziada unaotumiwa kimakusudi na huduma zinazohitaji ruhusa chache za mfumo wa faili.
- **Root**: Mtumiaji mkuu. Kuingia kwa Root kwa njia ya mwingiliano kumezimwa kwa chaguomsingi, ingawa wasimamizi wanaweza kutekeleza shughuli zenye ruhusa za ziada kupitia idhini na `sudo`.<sup>[[2]](#references)</sup>

Nyenzo za uthibitishaji wa nywila za akaunti za ndani na utaratibu wa kuzitoa zimefafanuliwa chini ya [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## User Privileges

- **Mtumiaji wa kawaida:** Aina ya kawaida ya akaunti isiyo ya msimamizi. Mabadiliko ya kiusimamizi yanahitaji idhini ya msimamizi.
- **Mtumiaji msimamizi**: Mwanachama wa kikundi cha ndani cha `admin`. Watumiaji wasimamizi bado huendesha michakato ya kawaida kwa kutumia utambulisho wao wa mtumiaji, lakini wanaweza kuidhinisha shughuli zenye ruhusa za ziada. Usidhani kwamba uanachama pekee hufanya kila amri iendeshwe kama root; `sudo`, Authorization Services, sera na ukaguzi mahususi wa programu bado hutumika.<sup>[[2]](#references)</sup>
- **Root**: Root ni mtumiaji anayeruhusiwa kutekeleza karibu kitendo chochote (kuna vizuizi vinavyowekwa na ulinzi kama System Integrity Protection).
  - Kwa mfano, System Integrity Protection na signed system volume huzuia hata root kufanya mabadiliko ya kudumu kwenye maudhui yaliyolindwa ya `/System` wakati wa matumizi ya kawaida.

## Akaunti za Nje

macOS pia hutumia akaunti za programu kutoka kwa watoa huduma wa nje. Daemon ya `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) huratibu data ya Accounts framework, na programu-jalizi za uthibitishaji zinaweza kupatikana chini ya `/System/Library/Accounts/Authentication/`. Hizi ni akaunti za programu/huduma, na si lazima ziwe utambulisho unaoweza kuingia kwenye dirisha la kuingia la macOS. `accountsd` pia husoma aina za akaunti zinazojulikana kutoka `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload ya usimamizi wa kifaa cha Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Ruhusa na umiliki wa BSD: akaunti za usimamizi na root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
