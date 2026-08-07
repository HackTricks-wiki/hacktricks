# Usuários e Contas Externas do macOS

{{#include ../../banners/hacktricks-training.md}}

## Usuários Comuns

- **Daemon**: Usuário reservado para daemons do sistema. Os nomes padrão das contas de daemon geralmente começam com um "\_":

```bash
_amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
```

- **Guest**: Conta para convidados com permissões muito restritas
```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```
- **Nobody**: Os processos são executados com este usuário quando são necessárias permissões mínimas
- **Root**

## Privilégios de Usuário

- **Usuário Padrão:** O tipo de usuário mais básico. Este usuário precisa receber permissões de um usuário administrador ao tentar instalar software ou realizar outras tarefas avançadas. Ele não consegue fazer isso por conta própria.
- **Usuário Administrador**: Um usuário que opera na maior parte do tempo como um usuário padrão, mas que também pode executar ações de root, como instalar software e realizar outras tarefas administrativas. Todos os usuários pertencentes ao grupo admin **recebem acesso a root por meio do arquivo sudoers**.
- **Root**: Root é um usuário autorizado a executar praticamente qualquer ação (há limitações impostas por proteções como o System Integrity Protection).
- Por exemplo, root não poderá colocar um arquivo dentro de `/System`

## Contas Externas

O MacOS também oferece suporte ao login por meio de provedores de identidade externos, como FaceBook, Google... O principal daemon que realiza essa tarefa é o `accountsd` (`/System/Library/Frameworks/Accounts.framework//Versions/A/Support/accountsd`), e é possível encontrar plugins usados para autenticação externa dentro da pasta `/System/Library/Accounts/Authentication/`.\
Além disso, o `accountsd` obtém a lista de tipos de conta de `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

{{#include ../../banners/hacktricks-training.md}}
