# Níveis de Integridade

{{#include ../../banners/hacktricks-training.md}}

## Níveis de Integridade

No Windows Vista e versões posteriores, objetos protegíveis podem conter um rótulo de **nível de integridade**. A maioria dos objetos é tratada como de integridade média, enquanto locais específicos destinados a aplicações de baixa integridade podem ser rotulados como baixos. Processos iniciados por usuários padrão normalmente são executados com integridade média, aplicações elevadas são executadas com integridade alta e muitos serviços são executados com integridade de sistema.<sup>[[1]](#references)</sup>

Uma regra fundamental é que objetos não podem ser modificados por processos com um nível de integridade inferior ao nível do objeto. O Windows aplica essa verificação de Mandatory Integrity Control (MIC) antes de avaliar a discretionary access control list (DACL) do objeto. Os níveis normalmente encontrados são:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: O nível mais baixo, representado por `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Não confunda esse rótulo de integridade com a identidade **Anonymous Logon** (`S-1-5-7`); identidades de autenticação e rótulos MIC são namespaces de SID separados. Como exemplo do mundo real, o sandbox do Chromium no Windows inicialmente atribui integridade Low aos alvos em sandbox e, depois da inicialização, reduz os alvos do renderer para a integridade Untrusted.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Principalmente para interações com a internet, especialmente no Protected Mode do Internet Explorer, afetando arquivos e processos associados e determinadas pastas, como a **Temporary Internet Folder**. Processos de integridade Low enfrentam restrições significativas, incluindo nenhum acesso de escrita ao registro e acesso limitado de escrita ao perfil do usuário.
- **Medium**: O nível padrão para a maioria das atividades, atribuído a usuários padrão e objetos sem níveis de integridade específicos. Até mesmo membros do grupo Administrators operam nesse nível por padrão.
- **High**: Reservado para administradores, permitindo modificar objetos em níveis de integridade inferiores, incluindo aqueles no próprio nível High.
- **System**: O nível operacional mais alto para o kernel do Windows e os serviços principais, fora do alcance até mesmo dos administradores, garantindo a proteção de funções vitais do sistema.

O Windows também define um valor de integridade de protected-process acima de System. No entanto, **TrustedInstaller** é uma identidade de serviço do Windows, e não um nível MIC separado; sua capacidade de modificar recursos protegidos do sistema operacional vem das permissões concedidas a essa identidade.

Não presuma que um local como a raiz de uma unidade do sistema sempre tenha um rótulo fixo de integridade High. Inspecione a DACL efetiva e qualquer mandatory label explícito com `icacls`; um objeto sem rótulo é tratado como Medium pelo MIC, enquanto sua DACL e propriedade ainda podem restringir o acesso de forma independente.<sup>[[1]](#references)[[4]](#references)</sup>

Você pode obter o nível de integridade de um processo usando o **Process Explorer** do **Sysinternals**, abrindo as propriedades do processo e visualizando a aba **Security**:<sup>[[3]](#references)</sup>

![Níveis de Integridade - Níveis de Integridade: Você pode obter o nível de integridade de um processo usando o Process Explorer do Sysinternals, acessando as propriedades do processo e visualizando a aba "...](<../../images/image (824).png>)

Você também pode obter seu **nível de integridade atual** usando `whoami /groups`:

![Níveis de Integridade - Níveis de Integridade: Você também pode obter seu nível de integridade atual usando whoami /groups](<../../images/image (325).png>)

### Níveis de Integridade no Sistema de Arquivos

Um objeto no sistema de arquivos pode ter um **requisito mínimo de nível de integridade**. Um processo abaixo desse nível está sujeito à policy obrigatória do objeto, mesmo quando sua DACL concederia acesso de outra forma. Por exemplo, crie um arquivo regular em um console de usuário padrão e inspecione suas permissões:<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Agora, atribua um nível de integridade mínimo **High** ao arquivo. Isso **deve ser feito a partir de um console** executado como **administrador**, pois um console comum é executado com integridade Medium e **não terá permissão** para atribuir integridade High a um objeto:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
O usuário `DESKTOP-IDJHTKP\user` tem **privilégios FULL** sobre o arquivo porque foi esse usuário que o criou. No entanto, o mandatory label impede que o usuário modifique o arquivo, a menos que o processo esteja sendo executado com High integrity. O usuário ainda pode lê-lo porque a mandatory policy exibida é `(NW)`, ou no-write-up (sem escrita ascendente):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Portanto, quando um arquivo tem um nível de integridade mínimo, para modificá-lo você precisa estar executando pelo menos nesse nível de integridade.**

### Níveis de integridade em binários

O exemplo a seguir usa uma cópia de `cmd.exe` em `C:\Windows\System32\cmd-low.exe` e atribui a ela um **nível de integridade Low a partir de um console de administrador**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Agora, quando executo `cmd-low.exe`, ele será **executado em um nível de integridade baixo** em vez de médio:

![Níveis de integridade no sistema de arquivos - Níveis de integridade em binários: Agora, quando executo cmd-low.exe, ele será executado em um nível de integridade baixo em vez de médio](<../../images/image (313).png>)

Atribuir um rótulo de integridade Alto a um binário (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) não faz com que ele seja executado automaticamente com integridade Alta. Se for iniciado por um processo com integridade Média, ele será executado com integridade Média, pois um novo processo recebe o menor dos níveis de integridade do arquivo executável e do processo chamador.<sup>[[1]](#references)</sup>

### Níveis de integridade em processos

Nem todos os arquivos e pastas têm um rótulo de integridade mínimo explícito, **mas todo processo é executado em um nível de integridade**. Assim como ocorre com os objetos do sistema de arquivos, **um processo que deseja acesso de gravação a outro processo deve ter pelo menos o mesmo nível de integridade**. Portanto, um processo com integridade Baixa não pode abrir um processo com integridade Média com acesso total.<sup>[[1]](#references)</sup>

Devido a essas restrições, a abordagem mais segura é **executar cada processo no nível de integridade mais baixo que ainda permita realizar o trabalho pretendido**.

## References

- [1] [Microsoft Learn – Controle de integridade obrigatório](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Enumeração MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Código-fonte do Chromium – Política de sandbox padrão do Windows](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – SIDs conhecidos](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
