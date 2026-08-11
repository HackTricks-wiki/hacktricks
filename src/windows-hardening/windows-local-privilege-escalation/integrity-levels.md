# Níveis de Integridade

{{#include ../../banners/hacktricks-training.md}}

## Níveis de Integridade

No Windows Vista e em versões posteriores, objetos protegíveis podem conter um rótulo de **nível de integridade**. A maioria dos objetos é tratada como tendo integridade média, enquanto locais específicos destinados a aplicações de baixa integridade podem ser rotulados como de baixa integridade. Processos iniciados por usuários padrão normalmente são executados com integridade média, aplicações elevadas são executadas com integridade alta e muitos serviços são executados com integridade de sistema.<sup>[[1]](#references)</sup>

Uma regra importante é que objetos não podem ser modificados por processos com um nível de integridade inferior ao nível do objeto. O Windows aplica essa verificação de Mandatory Integrity Control (MIC) antes de avaliar a lista de controle de acesso discricionário (DACL) do objeto. Os níveis normalmente encontrados são:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: O nível mais baixo, representado por `SECURITY_MANDATORY_UNTRUSTED_RID`. Como exemplo do mundo real, o sandbox do Chromium para Windows inicialmente atribui integridade Low aos alvos em sandbox e, depois da inicialização, reduz os alvos do renderer para a integridade Untrusted.<sup>[[5]](#references)</sup>
- **Low**: Usado principalmente para interações com a internet, especialmente no Protected Mode do Internet Explorer, afetando arquivos e processos associados e determinadas pastas, como a **Temporary Internet Folder**. Processos com integridade Low enfrentam restrições significativas, incluindo ausência de acesso de gravação ao registro e acesso limitado de gravação ao perfil do usuário.
- **Medium**: O nível padrão para a maioria das atividades, atribuído a usuários padrão e a objetos sem níveis de integridade específicos. Até mesmo os membros do grupo Administrators operam nesse nível por padrão.
- **High**: Reservado para administradores, permitindo que modifiquem objetos em níveis de integridade inferiores, incluindo aqueles no próprio nível High.
- **System**: O nível operacional mais alto para o kernel do Windows e os serviços essenciais, inacessível até mesmo para administradores, garantindo a proteção de funções vitais do sistema.

O Windows também define um valor de integridade de protected-process acima de System. **TrustedInstaller**, entretanto, é uma identidade de serviço do Windows, e não um nível separado de MIC; sua capacidade de modificar recursos protegidos do sistema operacional vem das permissões concedidas a essa identidade.

Você pode obter o nível de integridade de um processo usando o **Process Explorer** do **Sysinternals**, abrindo as propriedades do processo e visualizando a guia **Security**:<sup>[[3]](#references)</sup>

![Níveis de Integridade - Níveis de Integridade: Você pode obter o nível de integridade de um processo usando o Process Explorer do Sysinternals, acessando as propriedades do processo e visualizando a guia "...](<../../images/image (824).png>)

Você também pode obter seu **nível de integridade atual** usando `whoami /groups`:

![Níveis de Integridade - Níveis de Integridade: Você também pode obter seu nível de integridade atual usando whoami /groups](<../../images/image (325).png>)

### Níveis de Integridade no Sistema de Arquivos

Um objeto no sistema de arquivos pode ter um **requisito mínimo de nível de integridade**. Um processo abaixo desse nível está sujeito à política obrigatória do objeto, mesmo quando sua DACL concederia acesso. Por exemplo, crie um arquivo comum a partir de um console de usuário padrão e inspecione suas permissões:<sup>[[1]](#references)[[4]](#references)</sup>
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
Agora, atribua um nível mínimo de integridade **High** ao arquivo. Isso **deve ser feito a partir de um console** executado como **administrador**, pois um console regular é executado com integridade Medium e **não terá permissão para atribuir integridade High a um objeto**:
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
O usuário `DESKTOP-IDJHTKP\user` tem **privilégios FULL** sobre o arquivo porque foi esse usuário que o criou. No entanto, o rótulo obrigatório impede que o usuário modifique o arquivo, a menos que o processo esteja sendo executado com integridade High. O usuário ainda pode lê-lo porque a política obrigatória exibida é `(NW)`, ou no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Portanto, quando um arquivo possui um nível de integridade mínimo, para modificá-lo é necessário estar executando pelo menos nesse nível de integridade.**

### Níveis de integridade em binários

O exemplo a seguir usa uma cópia de `cmd.exe` em `C:\Windows\System32\cmd-low.exe` e atribui a ela um **Low integrity level a partir de um console de administrador**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Agora, quando executo `cmd-low.exe`, ele será executado em um **nível de integridade baixo**, em vez de um nível médio:

![Níveis de integridade no sistema de arquivos - Níveis de integridade em binários: Agora, quando executo cmd-low.exe, ele será executado em um nível de integridade baixo, em vez de um nível médio](<../../images/image (313).png>)

Atribuir um rótulo de integridade High a um binário (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) não faz com que ele seja executado automaticamente com integridade High. Se for invocado a partir de um processo com integridade Medium, ele será executado com integridade Medium, pois um novo processo recebe o menor dos níveis de integridade do arquivo executável e do processo chamador.<sup>[[1]](#references)</sup>

### Níveis de integridade em processos

Nem todos os arquivos e pastas têm um rótulo de integridade mínimo explícito, **mas todo processo é executado em um nível de integridade**. Assim como ocorre com os objetos do sistema de arquivos, **um processo que deseja acesso de gravação a outro processo deve ter pelo menos o mesmo nível de integridade**. Portanto, um processo com integridade Low não pode abrir um processo com integridade Medium com acesso total.<sup>[[1]](#references)</sup>

Devido a essas restrições, a abordagem mais segura é **executar cada processo no nível de integridade mais baixo que ainda permita realizar o trabalho pretendido**.

## References

- [1] [Microsoft Learn – Controle de integridade obrigatório](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Enumeração MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Código-fonte do Chromium – Política de integridade padrão do sandbox do Windows](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
