# ACLs - DACLs/SACLs/ACEs

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para criar e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenha o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## **Lista de Controle de Acesso (ACL)**

Uma **ACL é uma lista ordenada de ACEs** que definem as proteções que se aplicam a um objeto e suas propriedades. Cada **ACE identifica um princípio de segurança** e especifica um **conjunto de direitos de acesso** que são permitidos, negados ou auditados para esse princípio de segurança.

O descritor de segurança do objeto pode conter **duas ACLs**:

1. Um **DACL que identifica** os **usuários** e **grupos** que são **permitidos** ou **negados** acesso
2. Um **SACL que controla como** o acesso é **auditado**

Quando um usuário tenta acessar um arquivo, o sistema Windows executa um AccessCheck e compara o descritor de segurança com o token de acesso do usuário e avalia se o usuário tem acesso concedido e que tipo de acesso, dependendo dos ACEs definidos.

### **Lista de Controle de Acesso Discricionário (DACL)**

Um DACL (mencionado frequentemente como ACL) identifica os usuários e grupos que são atribuídos ou negados permissões de acesso em um objeto. Ele contém uma lista de ACEs emparelhados (Conta + Direito de Acesso) para o objeto seguro.

### **Lista de Controle de Acesso do Sistema (SACL)**

SACLs tornam possível monitorar o acesso a objetos seguros. ACEs em um SACL determinam **que tipos de acesso são registrados no Log de Eventos de Segurança**. Com ferramentas de monitoramento, isso pode gerar um alarme para as pessoas certas se usuários mal-intencionados tentarem acessar o objeto seguro e, em um cenário de incidente, podemos usar os logs para rastrear os passos de volta no tempo. E por último, você pode habilitar o registro para solucionar problemas de acesso.

## Como o Sistema Usa as ACLs

Cada **usuário logado** no sistema **possui um token de acesso com informações de segurança** para aquela sessão de logon. O sistema cria um token de acesso quando o usuário faz o logon. **Cada processo executado** em nome do usuário **tem uma cópia do token de acesso**. O token identifica o usuário, os grupos do usuário e os privilégios do usuário. Um token também contém um SID de logon (Identificador de Segurança) que identifica a sessão de logon atual.

Quando uma thread tenta acessar um objeto seguro, o LSASS (Autoridade de Segurança Local) concede ou nega acesso. Para fazer isso, o **LSASS procura o DACL** (Lista de Controle de Acesso Discricionário) no fluxo de dados SDS, procurando ACEs que se aplicam à thread.

**Cada ACE no DACL do objeto** especifica os direitos de acesso que são permitidos ou negados para um princípio de segurança ou sessão de logon. Se o proprietário do objeto não criou nenhum ACE no DACL para
### Entradas de Controle de Acesso

Como mencionado anteriormente, uma ACL (Lista de Controle de Acesso) é uma lista ordenada de ACEs (Entradas de Controle de Acesso). Cada ACE contém o seguinte:

* Um SID (Identificador de Segurança) que identifica um usuário ou grupo específico.
* Uma máscara de acesso que especifica os direitos de acesso.
* Um conjunto de flags que determinam se objetos filhos podem ou não herdar o ACE.
* Uma flag que indica o tipo de ACE.

Os ACEs são fundamentalmente iguais. O que os diferencia é o grau de controle que eles oferecem sobre a herança e o acesso ao objeto. Existem dois tipos de ACE:

* Tipo genérico que são anexados a todos os objetos seguráveis.
* Tipo específico do objeto que só pode ocorrer em ACLs para objetos do Active Directory.

### ACE Genérico

Um ACE genérico oferece controle limitado sobre os tipos de objetos filhos que podem herdá-los. Basicamente, eles só podem distinguir entre contêineres e não contêineres.

Por exemplo, a DACL (Lista de Controle de Acesso Discricionário) em um objeto de Pasta no NTFS pode incluir um ACE genérico que permite que um grupo de usuários liste o conteúdo da pasta. Como listar o conteúdo de uma pasta é uma operação que só pode ser realizada em um objeto Contêiner, o ACE que permite a operação pode ser marcado como um ACE de CONTAINER\_INHERIT\_ACE. Somente objetos Contêineres na pasta (ou seja, apenas outros objetos de Pasta) herdam o ACE. Objetos não contêineres (ou seja, objetos de Arquivo) não herdam o ACE do objeto pai.

Um ACE genérico se aplica a todo o objeto. Se um ACE genérico dá a um usuário específico acesso de Leitura, o usuário pode ler todas as informações associadas ao objeto - tanto dados quanto propriedades. Isso não é uma limitação séria para a maioria dos tipos de objetos. Objetos de Arquivo, por exemplo, têm poucas propriedades, que são todas usadas para descrever características do objeto em vez de armazenar informações. A maioria das informações em um objeto de Arquivo é armazenada como dados do objeto; portanto, há pouca necessidade de controles separados nas propriedades de um arquivo.

### ACE Específico do Objeto

Um ACE específico do objeto oferece um grau maior de controle sobre os tipos de objetos filhos que podem herdá-los.

Por exemplo, a ACL de um objeto de OU (Unidade Organizacional) pode ter um ACE específico do objeto que é marcado para herança apenas por objetos de Usuário. Outros tipos de objetos, como objetos de Computador, não herdarão o ACE.

Essa capacidade é por que os ACEs específicos do objeto são chamados de específicos do objeto. Sua herança pode ser limitada a tipos específicos de objetos filhos.

Existem diferenças semelhantes em como as duas categorias de tipos de ACE controlam o acesso aos objetos.

Um ACE específico do objeto pode se aplicar a qualquer propriedade individual de um objeto ou a um conjunto de propriedades desse objeto. Esse tipo de ACE é usado apenas em uma ACL para objetos do Active Directory, que, ao contrário de outros tipos de objetos, armazenam a maior parte de suas informações em propriedades. É frequentemente desejável colocar controles independentes em cada propriedade de um objeto do Active Directory, e os ACEs específicos do objeto tornam isso possível.

Por exemplo, ao definir permissões para um objeto de Usuário, você pode usar um ACE específico do objeto para permitir que o Principal Self (ou seja, o usuário) tenha acesso de Gravação à propriedade Phone-Home-Primary (homePhone), e você pode usar outros ACEs específicos do objeto para negar o acesso do Principal Self à propriedade Logon-Hours (logonHours) e outras propriedades que definem restrições na conta do usuário.

A tabela abaixo mostra o layout de cada ACE.

### Layout da Entrada de Controle de Acesso

| Campo do ACE | Descrição                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo         | Flag que indica o tipo de ACE. O Windows 2000 e o Windows Server 2003 suportam seis tipos de ACE: três tipos genéricos de ACE que são anexados a todos os objetos seguráveis. Três tipos de ACE específicos do objeto que podem ocorrer para objetos do Active Directory.                                                                                                                                                                                                                                                            |
| Flags        | Conjunto de flags que controlam a herança e a auditoria.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamanho      | Número de bytes de memória alocados para o ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acesso | Valor de 32 bits cujos bits correspondem aos direitos de acesso para o objeto. Os bits podem ser definidos como ligados ou desligados, mas o significado da configuração depende do tipo de ACE. Por exemplo, se o bit que corresponde ao direito de ler permissões estiver ligado e o tipo de ACE for Negar, o ACE nega o direito de ler as permissões do objeto. Se o mesmo bit estiver ligado, mas o tipo de ACE for Permitir, o ACE concede o direito de ler as permissões do objeto. Mais detalhes da Máscara de Acesso aparecem na tabela a seguir. |
| SID          | Identifica um usuário ou grupo cujo acesso é controlado ou monitorado por este ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Layout da Máscara de Acesso

| Bit (Intervalo) | Significado                            | Descrição/Exemplo                       |
| --------------- | -------------------------------------- | --------------------------------------- |
| 0 - 15          | Direitos de Acesso Específicos do Objeto | Ler dados, Executar, Anexar dados        |
| 16 - 22         | Direitos de Acesso Padrão               | Excluir, Escrever ACL, Escrever Proprietário |
| 23              | Pode acessar a ACL de segurança         |                                           |
| 24 - 27         | Reservado                              |                                           |
| 28              | Genérico TODOS (Ler, Escrever, Executar) | Tudo abaixo                              |
| 29              | Genérico Executar                      | Todas as coisas necessárias para executar um programa |
| 30              | Genérico Escrever                      | Todas as coisas necessárias para escrever em um arquivo |
| 31              | Genérico Ler                           | Todas as coisas necessárias para ler um arquivo |

## Referências

* [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
* [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![]
