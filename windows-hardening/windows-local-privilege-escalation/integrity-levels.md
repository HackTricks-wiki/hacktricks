# Níveis de Integridade

A partir do Windows Vista, todos os **objetos protegidos são rotulados com um nível de integridade**. A maioria dos arquivos de usuário e do sistema e chaves do registro no sistema têm um rótulo padrão de integridade "média". A principal exceção é um conjunto de pastas e arquivos específicos graváveis pelo Internet Explorer 7 em baixa integridade. **A maioria dos processos** executados por **usuários padrão** são rotulados com **integridade média** (mesmo aqueles iniciados por um usuário dentro do grupo de administradores), e a maioria dos **serviços** são rotulados com **integridade do sistema**. O diretório raiz é protegido por um rótulo de alta integridade.\
Observe que **um processo com um nível de integridade inferior não pode gravar em um objeto com um nível de integridade superior**.\
Existem vários níveis de integridade:

* **Não confiável** - processos que fazem login anonimamente são automaticamente designados como Não confiáveis. _Exemplo: Chrome_
* **Baixo** - O nível de integridade Baixo é o nível usado por padrão para interação com a Internet. Desde que o Internet Explorer seja executado em seu estado padrão, Modo Protegido, todos os arquivos e processos associados a ele são atribuídos ao nível de integridade Baixo. Algumas pastas, como a **Pasta de Internet Temporária**, também são atribuídas ao nível de integridade **Baixo** por padrão. No entanto, observe que um **processo de baixa integridade** é muito **restrito**, ele **não pode** gravar no **registro** e é limitado a gravar em **maioria das localizações** no perfil do usuário atual. _Exemplo: Internet Explorer ou Microsoft Edge_
* **Médio** - Médio é o contexto em que **a maioria dos objetos será executada**. Os usuários padrão recebem o nível de integridade Médio, e qualquer objeto não explicitamente designado com um nível de integridade inferior ou superior é Médio por padrão. Observe que um usuário dentro do grupo Administradores por padrão usará níveis de integridade médios.
* **Alto** - Os **administradores** recebem o nível de integridade Alto. Isso garante que os administradores sejam capazes de interagir e modificar objetos atribuídos aos níveis de integridade Médio ou Baixo, mas também podem agir em outros objetos com um nível de integridade Alto, o que os usuários padrão não podem fazer. _Exemplo: "Executar como Administrador"_
* **Sistema** - Como o nome indica, o nível de integridade do Sistema é reservado para o sistema. O kernel do Windows e os serviços principais recebem o nível de integridade do Sistema. Sendo ainda mais alto do que o nível de integridade Alto dos Administradores, protege essas funções principais de serem afetadas ou comprometidas mesmo pelos Administradores. Exemplo: Serviços
* **Instalador** - O nível de integridade do Instalador é um caso especial e é o mais alto de todos os níveis de integridade. Por ser igual ou superior a todos os outros níveis de integridade do WIC, os objetos atribuídos ao nível de integridade do Instalador também são capazes de desinstalar todos os outros objetos.

Você pode obter o nível de integridade de um processo usando o **Process Explorer** da **Sysinternals**, acessando as **propriedades** do processo e visualizando a guia "**Segurança**":

![](<../../.gitbook/assets/image (318).png>)

Você também pode obter seu **nível de integridade atual** usando `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Níveis de Integridade no Sistema de Arquivos

Um objeto dentro do sistema de arquivos pode precisar de um **requisito mínimo de nível de integridade** e, se um processo não tiver esse nível de integridade, não poderá interagir com ele.\
Por exemplo, vamos **criar um arquivo a partir do console de usuário regular e verificar as permissões**:
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
Agora, vamos atribuir um nível mínimo de integridade **Alto** ao arquivo. Isso **deve ser feito a partir de um console** executado como **administrador**, pois um **console regular** será executado no nível de integridade Médio e **não terá permissão** para atribuir o nível de integridade Alto a um objeto:
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
Aqui é onde as coisas ficam interessantes. Você pode ver que o usuário `DESKTOP-IDJHTKP\user` tem **privilégios COMPLETOS** sobre o arquivo (de fato, este foi o usuário que criou o arquivo), no entanto, devido ao nível mínimo de integridade implementado, ele não poderá mais modificar o arquivo, a menos que esteja sendo executado em um Nível de Integridade Alto (observe que ele poderá lê-lo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
Portanto, quando um arquivo tem um nível mínimo de integridade, para modificá-lo é necessário estar executando pelo menos nesse nível de integridade.
{% endhint %}

## Níveis de Integridade em Binários

Eu fiz uma cópia do `cmd.exe` em `C:\Windows\System32\cmd-low.exe` e defini um **nível de integridade baixo a partir de um console de administrador:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
                                BUILTIN\Administrators:(I)(F)
                                BUILTIN\Users:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
                                Mandatory Label\Low Mandatory Level:(NW)
```
Agora, quando eu executar `cmd-low.exe`, ele **será executado com um nível de integridade baixo** em vez de médio:

![](<../../.gitbook/assets/image (320).png>)

Para pessoas curiosas, se você atribuir um nível de integridade alto a um binário (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), ele não será executado automaticamente com um nível de integridade alto (se você invocá-lo a partir de um nível de integridade médio - por padrão - ele será executado com um nível de integridade médio).

## Níveis de Integridade em Processos

Nem todos os arquivos e pastas têm um nível mínimo de integridade, **mas todos os processos são executados com um nível de integridade**. E, semelhante ao que aconteceu com o sistema de arquivos, **se um processo quiser escrever dentro de outro processo, ele deve ter pelo menos o mesmo nível de integridade**. Isso significa que um processo com um nível de integridade baixo não pode abrir um identificador com acesso total a um processo com um nível de integridade médio.

Devido às restrições comentadas nesta e na seção anterior, do ponto de vista da segurança, é sempre **recomendado executar um processo no nível mais baixo de integridade possível**.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
