# Níveis de Integridade

{{#include ../../banners/hacktricks-training.md}}

## Níveis de Integridade

No Windows Vista e versões posteriores, todos os itens protegidos possuem uma tag de **nível de integridade**. Essa configuração atribui principalmente um nível de integridade "médio" a arquivos e chaves do registro, exceto determinadas pastas e arquivos nos quais o Internet Explorer 7 pode escrever com um nível de integridade baixo. O comportamento padrão é que processos iniciados por usuários padrão tenham um nível de integridade médio, enquanto os serviços normalmente operam com um nível de integridade do sistema. Uma etiqueta de alta integridade protege o diretório raiz.

Uma regra fundamental é que os objetos não podem ser modificados por processos com um nível de integridade inferior ao nível do objeto. Os níveis de integridade são:

- **Untrusted**: Este nível é destinado a processos com logins anônimos. Exemplo: Chrome
- **Low**: Usado principalmente para interações com a internet, especialmente no Protected Mode do Internet Explorer, afetando arquivos e processos associados, além de determinadas pastas, como a **Temporary Internet Folder**. Processos de baixa integridade enfrentam restrições significativas, incluindo nenhuma permissão de escrita no registro e acesso limitado para escrita no perfil do usuário.
- **Medium**: O nível padrão para a maioria das atividades, atribuído a usuários padrão e objetos sem níveis de integridade específicos. Até mesmo membros do grupo Administrators operam nesse nível por padrão.
- **High**: Reservado para administradores, permitindo modificar objetos em níveis de integridade inferiores, incluindo os que estão no próprio nível alto.
- **System**: O nível operacional mais alto para o kernel do Windows e os serviços essenciais, inacessível até mesmo para administradores, garantindo a proteção de funções vitais do sistema.
- **Installer**: Um nível exclusivo que está acima de todos os outros, permitindo que objetos nesse nível desinstalem qualquer outro objeto.

Você pode obter o nível de integridade de um processo usando o **Process Explorer** do **Sysinternals**, acessando as **properties** do processo e visualizando a aba "**Security**":

![Níveis de Integridade - Níveis de Integridade: Você pode obter o nível de integridade de um processo usando o Process Explorer do Sysinternals, acessando as properties do processo e visualizando a aba "...](<../../images/image (824).png>)

Você também pode obter seu **nível de integridade atual** usando `whoami /groups`

![Níveis de Integridade - Níveis de Integridade: Você também pode obter seu nível de integridade atual usando whoami /groups](<../../images/image (325).png>)

### Níveis de Integridade no sistema de arquivos

Um objeto dentro do sistema de arquivos pode exigir um **nível mínimo de integridade** e, se um processo não tiver esse nível de integridade, não poderá interagir com ele.\
Por exemplo, vamos **criar um arquivo comum a partir de um console de usuário comum e verificar as permissões**:
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
Agora, vamos atribuir um nível de integridade mínimo **Alto** ao arquivo. Isso **deve ser feito a partir de um console** executado como **administrador**, pois um **console comum** estará sendo executado com nível de integridade Médio e **não terá permissão** para atribuir o nível de integridade Alto a um objeto:
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
É aqui que as coisas ficam interessantes. Você pode ver que o usuário `DESKTOP-IDJHTKP\user` tem **privilégios COMPLETOS** sobre o arquivo (na verdade, este foi o usuário que criou o arquivo); no entanto, devido ao nível de integridade mínimo implementado, ele não poderá mais modificar o arquivo, a menos que esteja executando dentro de um High Integrity Level (observe que ele poderá lê-lo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Portanto, quando um arquivo possui um nível de integridade mínimo, para modificá-lo, você precisa estar executando pelo menos nesse nível de integridade.**

### Níveis de integridade em binários

Fiz uma cópia de `cmd.exe` em `C:\Windows\System32\cmd-low.exe` e defini um **nível de integridade baixo a partir de um console de administrador:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Agora, quando executo `cmd-low.exe`, ele será **executado com um nível de integridade baixo** em vez de um nível médio:

![Níveis de integridade no sistema de arquivos - Níveis de integridade em binários: Agora, quando executo cmd-low.exe, ele será executado com um nível de integridade baixo em vez de um nível médio](<../../images/image (313).png>)

Para os curiosos, se você atribuir um nível de integridade alto a um binário (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), ele não será executado automaticamente com um nível de integridade alto (se você o invocar a partir de um nível de integridade médio --por padrão--, ele será executado com um nível de integridade médio).

### Níveis de integridade em processos

Nem todos os arquivos e pastas têm um nível mínimo de integridade, **mas todos os processos são executados com um nível de integridade**. E, de forma semelhante ao que acontece com o sistema de arquivos, **se um processo quiser escrever dentro de outro processo, ele deverá ter pelo menos o mesmo nível de integridade**. Isso significa que um processo com um nível de integridade baixo não pode abrir um handle com acesso total a um processo com um nível de integridade médio.

Devido às restrições mencionadas nesta e na seção anterior, do ponto de vista da segurança, é sempre **recomendado executar um processo com o menor nível de integridade possível**.

{{#include ../../banners/hacktricks-training.md}}
