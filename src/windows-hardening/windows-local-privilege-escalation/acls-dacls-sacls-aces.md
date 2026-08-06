# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Uma Access Control List (ACL) consiste em um conjunto ordenado de Access Control Entries (ACEs) que define as proteções de um objeto e de suas propriedades. Em essência, uma ACL define quais ações, realizadas por quais security principals (usuários ou grupos), são permitidas ou negadas em determinado objeto.

Existem dois tipos de ACLs:

- **Discretionary Access Control List (DACL):** Especifica quais usuários e grupos têm ou não têm acesso a um objeto.
- **System Access Control List (SACL):** Controla a auditoria das tentativas de acesso a um objeto.

O processo de acesso a um arquivo envolve o sistema verificar o security descriptor do objeto em relação ao access token do usuário para determinar se o acesso deve ser concedido e qual será sua extensão, com base nas ACEs.<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL:** Contém ACEs que concedem ou negam permissões de acesso a usuários e grupos para um objeto. É essencialmente a ACL principal que define os direitos de acesso.
- **SACL:** Usada para auditar o acesso a objetos, com ACEs que definem os tipos de acesso a serem registrados no Security Event Log. Isso pode ser muito útil para detectar tentativas de acesso não autorizado ou solucionar problemas de acesso.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Cada sessão de usuário está associada a um access token que contém informações de segurança relevantes para essa sessão, incluindo identidades de usuário, grupos e privilégios. Esse token também inclui um logon SID que identifica exclusivamente a sessão.

A Local Security Authority (LSASS) processa solicitações de acesso a objetos examinando a DACL em busca de ACEs que correspondam ao security principal que está tentando acessar o objeto. O acesso é concedido imediatamente se nenhuma ACE relevante for encontrada. Caso contrário, o LSASS compara as ACEs com o SID do security principal no access token para determinar se o acesso deve ser permitido.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** Definem permissões de acesso por meio de DACLs e regras de auditoria por meio de SACLs.
- **Access Token:** Contém informações do usuário, grupo e privilégios para uma sessão.
- **Access Decision:** É tomada comparando as ACEs da DACL com o access token; as SACLs são usadas para auditoria.<sup>[[1]](#references)</sup>

### ACEs

Existem **três tipos principais de Access Control Entries (ACEs)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Essa ACE nega explicitamente o acesso a um objeto para usuários ou grupos especificados (em uma DACL).
- **Access Allowed ACE**: Essa ACE concede explicitamente acesso a um objeto para usuários ou grupos especificados (em uma DACL).
- **System Audit ACE**: Posicionada em uma System Access Control List (SACL), essa ACE é responsável por gerar logs de auditoria quando usuários ou grupos tentam acessar um objeto. Ela registra se o acesso foi permitido ou negado e a natureza do acesso.

Cada ACE tem **quatro componentes críticos**:<sup>[[1]](#references)</sup>

1. O **Security Identifier (SID)** do usuário ou grupo (ou o nome do principal em uma representação gráfica).
2. Um **flag** que identifica o tipo de ACE (acesso negado, permitido ou auditoria do sistema).
3. **Inheritance flags** que determinam se objetos filhos podem herdar a ACE de seu objeto pai.
4. Uma [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), um valor de 32 bits que especifica os direitos concedidos ao objeto.

A determinação do acesso é realizada examinando sequencialmente cada ACE até que:<sup>[[1]](#references)</sup>

- Uma **Access-Denied ACE** negue explicitamente os direitos solicitados a um trustee identificado no access token.
- Uma ou mais **Access-Allowed ACEs** concedam explicitamente todos os direitos solicitados a um trustee presente no access token.
- Após a verificação de todas as ACEs, se algum direito solicitado **não tiver sido permitido** explicitamente, o acesso será **negado** implicitamente.

### Order of ACEs

A forma como as **ACEs** (regras que indicam quem pode ou não acessar algo) são colocadas em uma lista chamada **DACL** é muito importante. Isso ocorre porque, depois que o sistema concede ou nega o acesso com base nessas regras, ele para de verificar o restante.<sup>[[1]](#references)</sup>

Existe uma melhor forma de organizar essas ACEs, chamada **"canonical order."** Esse método ajuda a garantir que tudo funcione de maneira adequada e justa. Veja como isso funciona em sistemas como o **Windows 2000** e o **Windows Server 2003**:

- Primeiro, coloque todas as regras criadas **especificamente para este item** antes das regras provenientes de outro local, como uma pasta pai.
- Entre essas regras específicas, coloque primeiro as que dizem **"não" (deny)** e depois as que dizem **"sim" (allow)**.
- Para as regras provenientes de outro local, comece pelas regras da **fonte mais próxima**, como o objeto pai, e depois prossiga para as fontes mais distantes. Novamente, coloque **"não"** antes de **"sim."**

Essa configuração ajuda de duas formas importantes:

- Garante que, se houver um **"não"** específico, ele seja respeitado, independentemente de quaisquer outras regras **"sim"** existentes.
- Permite que o proprietário de um item tenha a **decisão final** sobre quem pode entrar, antes que as regras das pastas pai ou de locais mais distantes sejam consideradas.

Ao organizar as regras dessa forma, o proprietário de um arquivo ou pasta pode controlar com precisão quem terá acesso, garantindo que as pessoas certas possam entrar e as erradas não.

![Diagrama da ordenação de access control entries do NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Portanto, essa **"canonical order"** tem como objetivo garantir que as regras de acesso sejam claras e funcionem corretamente, colocando as regras específicas primeiro e organizando tudo de maneira adequada.

### GUI Example

[**Example from here**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Esta é a clássica guia de segurança de uma pasta, mostrando a ACL, a DACL e as ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Se clicarmos no **Advanced button**, teremos mais opções, como a herança:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

E se você adicionar ou editar um Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Por fim, temos a SACL na guia Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Ao gerenciar o acesso a recursos, como uma pasta, usamos listas e regras conhecidas como Access Control Lists (ACLs) e Access Control Entries (ACEs). Elas definem quem pode ou não acessar determinados dados.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Imagine que você tenha uma pasta chamada Cost e queira que todos possam acessá-la, exceto uma equipe de marketing. Ao configurar as regras corretamente, podemos garantir que o acesso da equipe de marketing seja explicitamente negado antes de permitir o acesso a todos os demais. Isso é feito colocando a regra que nega o acesso à equipe de marketing antes da regra que permite o acesso a todos.

#### Allowing Access to a Specific Member of a Denied Group

Suponha que Bob, o diretor de marketing, precise acessar a pasta Cost, embora a equipe de marketing não deva ter acesso em geral. Podemos adicionar uma regra específica (ACE) para Bob, concedendo-lhe acesso, e colocá-la antes da regra que nega o acesso à equipe de marketing. Dessa forma, Bob terá acesso apesar da restrição geral aplicada à sua equipe.

#### Understanding Access Control Entries

As ACEs são as regras individuais de uma ACL. Elas identificam usuários ou grupos, especificam qual acesso é permitido ou negado e determinam como essas regras se aplicam a subitens (herança). Existem dois tipos principais de ACEs:

- **Generic ACEs**: Aplicam-se de forma ampla, afetando todos os tipos de objetos ou distinguindo apenas entre containers (como pastas) e objetos que não são containers (como arquivos). Por exemplo, uma regra que permite aos usuários visualizar o conteúdo de uma pasta, mas não acessar os arquivos dentro dela.
- **Object-Specific ACEs**: Fornecem um controle mais preciso, permitindo definir regras para tipos específicos de objetos ou até mesmo para propriedades individuais dentro de um objeto. Por exemplo, em um diretório de usuários, uma regra pode permitir que um usuário atualize seu número de telefone, mas não seus horários de login.

Cada ACE contém informações importantes, como a quem a regra se aplica (usando um Security Identifier ou SID), o que a regra permite ou nega (usando uma access mask) e como ela é herdada por outros objetos.

#### Key Differences Between ACE Types

- **Generic ACEs** são adequadas para cenários simples de controle de acesso, nos quais a mesma regra se aplica a todos os aspectos de um objeto ou a todos os objetos dentro de um container.
- **Object-Specific ACEs** são usadas em cenários mais complexos, especialmente em ambientes como o Active Directory, nos quais pode ser necessário controlar de forma diferente o acesso a propriedades específicas de um objeto.

Em resumo, ACLs e ACEs ajudam a definir controles de acesso precisos, garantindo que somente os indivíduos ou grupos corretos tenham acesso a informações ou recursos confidenciais, com a possibilidade de ajustar os direitos de acesso até o nível de propriedades individuais ou tipos de objetos.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag que indica o tipo de ACE. O Windows 2000 e o Windows Server 2003 são compatíveis com seis tipos de ACE: três tipos de ACE genéricas, anexadas a todos os objetos protegíveis; e três tipos de ACE específicas de objetos, que podem ocorrer em objetos do Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Conjunto de flags de bits que controlam a herança e a auditoria.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Número de bytes de memória alocados para a ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Valor de 32 bits cujos bits correspondem aos direitos de acesso do objeto. Os bits podem estar ativados ou desativados, mas o significado da configuração depende do tipo de ACE. Por exemplo, se o bit correspondente ao direito de ler permissões estiver ativado e o tipo de ACE for Deny, a ACE negará o direito de ler as permissões do objeto. Se o mesmo bit estiver ativado, mas o tipo de ACE for Allow, a ACE concederá o direito de ler as permissões do objeto. Mais detalhes sobre a Access mask aparecem na próxima tabela. |
| SID         | Identifica um usuário ou grupo cujo acesso é controlado ou monitorado por esta ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Direitos de acesso específicos do objeto      | Ler dados, Executar, Anexar dados           |
| 16 - 22     | Direitos de acesso padrão             | Excluir, Escrever ACL, Escrever proprietário            |
| 23          | Pode acessar a security ACL            |                                           |
| 24 - 27     | Reservado                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Tudo abaixo                          |
| 29          | Generic Execute                    | Tudo o que é necessário para executar um programa |
| 30          | Generic Write                      | Tudo o que é necessário para escrever em um arquivo   |
| 31          | Generic Read                       | Tudo o que é necessário para ler um arquivo       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
