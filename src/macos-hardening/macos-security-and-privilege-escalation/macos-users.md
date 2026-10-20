# Usuários do macOS e contas externas

{{#include ../../banners/hacktricks-training.md}}

## Usuários comuns

- **Contas de daemon**: Reservadas para daemons do sistema. Seus nomes curtos geralmente começam com um sublinhado (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Convidado**: Uma conta temporária restrita cuja disponibilidade pode ser controlada localmente ou por um payload Accounts de MDM.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Uma identidade deliberadamente sem privilégios, usada por serviços que precisam de permissões mínimas no sistema de arquivos.
- **Root**: O superusuário. O login interativo como root é desativado por padrão, embora administradores possam realizar operações privilegiadas por meio de autorização e do `sudo`.<sup>[[2]](#references)</sup>

O material local de verificação de senhas de contas e o fluxo de trabalho para extraí-lo são abordados em [Senhas shadow](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## Privilégios de usuário

- **Usuário padrão:** O tipo normal de conta, sem privilégios administrativos. Alterações administrativas exigem autorização de um administrador.
- **Usuário admin**: Um membro do grupo local `admin`. Usuários admin ainda executam processos comuns com sua identidade de usuário, mas podem autorizar operações privilegiadas. Não presuma que a associação ao grupo, por si só, faz com que todos os comandos sejam executados como root; `sudo`, Authorization Services, as políticas e as verificações específicas de cada aplicativo ainda se aplicam.<sup>[[2]](#references)</sup>
- **Root**: Root é um usuário autorizado a realizar quase qualquer ação (há limitações impostas por proteções como System Integrity Protection).
  - Por exemplo, System Integrity Protection e o volume de sistema assinado impedem até mesmo root de modificar persistentemente conteúdo protegido de `/System` durante a operação normal.

## Contas externas

O macOS também oferece suporte a contas de aplicativos de provedores externos. O daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) intermedeia os dados do Accounts framework, e plug-ins de autenticação podem ser encontrados em `/System/Library/Accounts/Authentication/`. Essas são contas de aplicativos/serviços, não necessariamente identidades que podem fazer login na janela de login do macOS. `accountsd` também lê os tipos de conta conhecidos de `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload de gerenciamento de dispositivos Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Permissões e propriedade BSD: contas administrativas e root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}
