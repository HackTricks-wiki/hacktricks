# Abusando de Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se você **não sabe o que são Windows Access Tokens** leia esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Talvez você consiga escalar privilégios abusando dos tokens que já possui**

### SeImpersonatePrivilege

Este é um privilégio que, quando detido por um processo, permite a impersonação (mas não a criação) de qualquer token, desde que um handle para ele possa ser obtido. Um token privilegiado pode ser adquirido a partir de um serviço Windows (DCOM) induzindo-o a realizar autenticação NTLM contra um exploit, possibilitando subsequentemente a execução de um processo com privilégios SYSTEM. Essa vulnerabilidade pode ser explorada usando várias ferramentas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer winrm desativado), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

É muito similar ao **SeImpersonatePrivilege**, ele usará o **mesmo método** para obter um token privilegiado.\
Então, esse privilégio permite **atribuir um primary token** a um processo novo/suspenso. Com o token de impersonação privilegiado você pode derivar um primary token (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, não é possível modificar o primary token de um processo em execução).

### SeTcbPrivilege

Se você possuir esse privilégio ativado, pode usar **KERB_S4U_LOGON** para obter um **token de impersonação** de qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (admins) ao token, definir o **nível de integridade** do token para "**medium**", e atribuir esse token à **thread atual** (SetThreadToken).

### SeBackupPrivilege

Esse privilégio faz com que o sistema **conceda todo o acesso de leitura** a qualquer arquivo (limitado a operações de leitura). É utilizado para **ler os hashes de senha do Administrador local** a partir do registro, após o que ferramentas como "psexec" ou "wmiexec" podem ser usadas com o hash (técnica Pass-the-Hash). Contudo, essa técnica falha em duas condições: quando a conta Local Administrator está desabilitada, ou quando existe uma política que remove direitos administrativos de Local Administrators que se conectam remotamente.\
Você pode **abusar desse privilégio** com:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- seguindo o **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou como explicado na seção **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}

### SeRestorePrivilege

Este privilégio fornece permissão para **acesso de escrita** a qualquer arquivo do sistema, independentemente da Access Control List (ACL) do arquivo. Abre inúmeras possibilidades para escalada, incluindo a capacidade de **modificar serviços**, realizar DLL Hijacking e configurar **debuggers** via Image File Execution Options, entre várias outras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário possui a capacidade de impersonar tokens, mas também mesmo na ausência de SeImpersonatePrivilege. Essa capacidade depende da habilidade de impersonar um token que represente o mesmo usuário e cujo nível de integridade não exceda o do processo atual.

Pontos-chave:

- **Impersonação sem SeImpersonatePrivilege:** É possível aproveitar SeCreateTokenPrivilege para EoP ao impersonar tokens sob condições específicas.
- **Condições para impersonação de token:** A impersonação bem-sucedida requer que o token alvo pertença ao mesmo usuário e tenha um nível de integridade menor ou igual ao nível de integridade do processo que tenta a impersonação.
- **Criação e modificação de tokens de impersonação:** Usuários podem criar um token de impersonação e aprimorá-lo adicionando o SID de um grupo privilegiado.

### SeLoadDriverPrivilege

Esse privilégio permite **carregar e descarregar drivers de dispositivo** criando uma entrada no registro com valores específicos para `ImagePath` e `Type`. Como o acesso de escrita direto a `HKLM` (HKEY_LOCAL_MACHINE) é restrito, `HKCU` (HKEY_CURRENT_USER) deve ser utilizado em vez disso. Entretanto, para fazer com que o kernel reconheça `HKCU` para configuração do driver, um caminho específico deve ser seguido.

Esse caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Relative Identifier do usuário atual. Dentro de `HKCU`, todo esse caminho deve ser criado, e dois valores precisam ser definidos:

- `ImagePath`, que é o caminho para o binário a ser executado
- `Type`, com o valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Acesse `HKCU` em vez de `HKLM` devido ao acesso de escrita restrito.
2. Crie o caminho `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro de `HKCU`, onde `<RID>` representa o Relative Identifier do usuário atual.
3. Defina `ImagePath` para o caminho de execução do binário.
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
Mais maneiras de abusar deste privilégio em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isto é semelhante ao **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando a exigência de acesso discricionário explícito por meio da concessão de direitos de acesso WRITE_OWNER. O processo envolve primeiro garantir a propriedade da chave de registro desejada para fins de escrita, e então alterar o DACL para permitir operações de escrita.
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

Este privilégio permite o **debug other processes**, incluindo ler e escrever na memória. Várias estratégias de memory injection, capazes de evadir a maioria dos antivirus e das soluções de host intrusion prevention, podem ser empregadas com esse privilégio.

#### Dump memory

Você pode usar [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) da [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar a memória de um processo**. Especificamente, isso pode se aplicar ao processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, que é responsável por armazenar as credenciais dos usuários assim que um usuário efetua login com sucesso em um sistema.

Você pode então carregar esse dump no mimikatz para obter senhas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se quiser obter um shell `NT SYSTEM`, você pode usar:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Este direito (Perform volume maintenance tasks) permite abrir handles de dispositivo de volume bruto (por ex., \\.\C:) para I/O direto em disco que contorna as NTFS ACLs. Com ele você pode copiar bytes de qualquer arquivo no volume lendo os blocos subjacentes, possibilitando leitura arbitrária de arquivos contendo material sensível (por ex., chaves privadas da máquina em %ProgramData%\Microsoft\Crypto\, hives do registro, SAM/NTDS via VSS). É particularmente impactante em servidores CA, onde exfiltrar a chave privada da CA permite forjar um Golden Certificate para se passar por qualquer principal.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Verificar privilégios
```
whoami /priv
```
Os **tokens que aparecem como Disabled** podem ser habilitados; na verdade você pode abusar de tokens _Enabled_ e _Disabled_.

### Habilitar todos os tokens

Se você tiver tokens Disabled, pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos os tokens:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou o **script** embutido neste [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Cheatsheet completo de privilégios de token em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), o resumo abaixo listará apenas maneiras diretas de explorar o privilégio para obter uma sessão de administrador ou ler arquivos sensíveis.

| Privilege                  | Impacto     | Ferramenta             | Caminho de execução                                                                                                                                                                                                                                                                                                                                  | Observações                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | ----------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Administrador**_ | ferramenta de terceiros | _"Permite que um usuário se passe por tokens e faça privesc para o sistema nt usando ferramentas como potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                              | Obrigado [Aurélien Chalot](https://twitter.com/Defte_) pela atualização. Vou tentar reformular isso para algo mais no estilo de receita em breve.                                                                                                                                                                                |
| **`SeBackup`**             | **Ameaça**  | _**Built-in commands**_ | Leia arquivos sensíveis com `robocopy /b`                                                                                                                                                                                                                                                                                                           | <p>- Pode ser mais interessante se você puder ler %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) não é útil quando se trata de arquivos abertos.<br><br>- Robocopy requer tanto SeBackup quanto SeRestore para funcionar com o parâmetro /b.</p>                                                                  |
| **`SeCreateToken`**        | _**Administrador**_ | ferramenta de terceiros | Cria token arbitrário incluindo direitos de administrador local com `NtCreateToken`.                                                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                 |
| **`SeDebug`**              | _**Administrador**_ | **PowerShell**         | Duplicar o token de `lsass.exe`.                                                                                                                                                                                                                                                                                                                    | Script pode ser encontrado em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                  |
| **`SeLoadDriver`**         | _**Administrador**_ | ferramenta de terceiros | <p>1. Carregar driver de kernel com bug como <code>szkg64.sys</code><br>2. Explorar a vulnerabilidade do driver<br><br>Alternativamente, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando embutido <code>ftlMC</code>. i.e.: <code>fltMC sysmondrv</code></p>                                        | <p>1. A vulnerabilidade <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. O <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">código de exploit</a> foi criado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Administrador**_ | **PowerShell**         | <p>1. Execute PowerShell/ISE com o privilégio SeRestore presente.<br>2. Habilite o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>.<br>3. Renomeie utilman.exe para utilman.old<br>4. Renomeie cmd.exe para utilman.exe<br>5. Trave o console e pressione Win+U</p> | <p>O ataque pode ser detectado por alguns softwares AV.</p><p>Método alternativo depende de substituir binários de serviços armazenados em "Program Files" usando o mesmo privilégio</p>                                                                                                                               |
| **`SeTakeOwnership`**      | _**Administrador**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomeie cmd.exe para utilman.exe<br>4. Trave o console e pressione Win+U</p>                                                                                                                                      | <p>O ataque pode ser detectado por alguns softwares AV.</p><p>Método alternativo depende de substituir binários de serviços armazenados em "Program Files" usando o mesmo privilégio.</p>                                                                                                                                   |
| **`SeTcb`**                | _**Administrador**_ | ferramenta de terceiros | <p>Manipular tokens para incluir direitos de administrador local. Pode requerer SeImpersonate.</p><p>Para ser verificado.</p>                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                 |

## Referência

- Veja esta tabela definindo tokens do Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Veja [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) sobre privesc com tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
