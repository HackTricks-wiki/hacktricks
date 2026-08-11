# Usuários do macOS e Contas Externas

{{#include ../../banners/hacktricks-training.md}}

## Usuários Comuns

- **Contas de daemon**: Reservadas para daemons do sistema. Seus nomes curtos geralmente começam com um sublinhado (`_`):

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Uma conta restrita e temporária cuja disponibilidade pode ser controlada localmente ou por um payload de Contas do MDM.<sup>[[1]](#references)</sup>
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Uma identidade deliberadamente sem privilégios, usada por serviços que exigem permissões mínimas no sistema de arquivos.
- **Root**: O superusuário. O login interativo como root é desabilitado por padrão, embora os administradores possam realizar operações privilegiadas por meio de autorização e `sudo`.<sup>[[2]](#references)</sup>

## User Privileges

- **Standard user:** O tipo normal de conta não administrativa. Alterações administrativas exigem autorização de um administrador.
- **Admin user**: Um membro do grupo local `admin`. Usuários admin ainda executam processos comuns com a identidade do próprio usuário, mas podem autorizar operações privilegiadas. Não presuma que a associação ao grupo, por si só, faça todos os comandos serem executados como root; `sudo`, Authorization Services, políticas e verificações específicas dos aplicativos ainda se aplicam.<sup>[[2]](#references)</sup>
- **Root**: Root é um usuário autorizado a realizar praticamente qualquer ação (há limitações impostas por proteções como System Integrity Protection).
- Por exemplo, o System Integrity Protection e o signed system volume impedem até mesmo que root modifique persistentemente o conteúdo protegido de `/System` durante a operação normal.

## External Accounts

O macOS também oferece suporte a contas de aplicativos de provedores externos. O daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) intermedeia os dados do Accounts-framework, e plug-ins de autenticação podem ser encontrados em `/System/Library/Accounts/Authentication/`. Essas são contas de aplicativos/serviços, não necessariamente identidades que podem fazer login na janela de login do macOS. `accountsd` também lê os tipos de conta conhecidos em `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Accounts device-management payload](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — BSD permissions and ownership: administrative and root accounts](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
