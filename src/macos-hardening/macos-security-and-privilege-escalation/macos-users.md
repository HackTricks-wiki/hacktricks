# macOS Users & External Accounts

{{#include ../../banners/hacktricks-training.md}}

## Common Users

- **Daemon**: Usuário reservado para daemons do sistema. Os nomes das contas de daemon padrão geralmente começam com um "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Conta para convidados com permissões muito restritas
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Ninguém**: Processos são executados com este usuário quando permissões mínimas são necessárias
- **Root**

## Privilégios do Usuário

- **Usuário Padrão:** O mais básico dos usuários. Este usuário precisa de permissões concedidas por um usuário administrador ao tentar instalar software ou realizar outras tarefas avançadas. Eles não conseguem fazer isso sozinhos.
- **Usuário Administrador**: Um usuário que opera na maior parte do tempo como um usuário padrão, mas também é permitido realizar ações de root, como instalar software e outras tarefas administrativas. Todos os usuários pertencentes ao grupo de administradores **têm acesso ao root via o arquivo sudoers**.
- **Root**: Root é um usuário permitido a realizar quase qualquer ação (existem limitações impostas por proteções como a Proteção de Integridade do Sistema).
- Por exemplo, o root não poderá colocar um arquivo dentro de `/System`

## Contas Externas

MacOS também suporta login via provedores de identidade externos, como FaceBook, Google... O principal daemon que realiza esse trabalho é `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`) e é possível encontrar plugins usados para autenticação externa dentro da pasta `/System/Library/Accounts/Authentication/`.\
Além disso, `accountsd` obtém a lista de tipos de conta de `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
