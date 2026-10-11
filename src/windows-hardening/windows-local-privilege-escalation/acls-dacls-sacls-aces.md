# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Lista de Controle de Acesso (ACL)**

Uma Lista de Controle de Acesso (ACL) consiste em um conjunto ordenado de Entradas de Controle de Acesso (ACEs) que determinam as proteções de um objeto e de suas propriedades. Em essência, uma ACL define quais ações de quais entidades de segurança (usuários ou grupos) são permitidas ou negadas em determinado objeto.

Há dois tipos de ACL:

- **Lista de Controle de Acesso Discricionário (DACL):** Especifica quais usuários e grupos têm ou não acesso a um objeto.
- **Lista de Controle de Acesso do Sistema (SACL):** Controla a auditoria das tentativas de acesso a um objeto.

O processo de acesso a um arquivo envolve o sistema verificando o descritor de segurança do objeto em relação ao token de acesso do usuário para determinar se o acesso deve ser concedido e qual será sua extensão, com base nas ACEs.<sup>[[1]](#references)</sup>

Quando um diretório pai concede Controle Total, mas um arquivo filho nega a leitura, examine separadamente a DACL efetiva, o proprietário e a herança do **arquivo filho**. Alterar a DACL desse arquivo exige `WRITE_DAC` no arquivo ou o direito de proprietário aplicável; [a Microsoft define `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) e [documenta o acesso implícito do proprietário](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). As permissões do diretório pai, por si só, não garantem que o arquivo filho possa ser lido nem que sua DACL possa ser alterada.

### **Componentes principais**

- **DACL:** Contém ACEs que concedem ou negam permissões de acesso a usuários e grupos para um objeto. É essencialmente a ACL principal que determina os direitos de acesso.
- **SACL:** Usada para auditar o acesso a objetos; suas ACEs definem os tipos de acesso que serão registrados no Log de Eventos de Segurança. Isso pode ser muito útil para detectar tentativas de acesso não autorizado ou solucionar problemas de acesso.<sup>[[1]](#references)</sup>

### **Interação do sistema com ACLs**

Cada sessão de usuário está associada a um token de acesso que contém informações de segurança relevantes para essa sessão, incluindo identidades de usuários e grupos e privilégios. Esse token também inclui um SID de logon que identifica a sessão de forma exclusiva.

A Autoridade de Segurança Local (LSASS) processa as solicitações de acesso a objetos examinando a DACL em busca de ACEs que correspondam à entidade de segurança que está tentando acessar o objeto. O acesso é concedido imediatamente se nenhuma ACE relevante for encontrada. Caso contrário, o LSASS compara as ACEs com o SID da entidade de segurança no token de acesso para determinar se o acesso pode ser concedido.<sup>[[1]](#references)</sup>

### **Processo resumido**

- **ACLs:** Definem permissões de acesso por meio de DACLs e regras de auditoria por meio de SACLs.
- **Token de acesso:** Contém informações de usuário, grupo e privilégios de uma sessão.
- **Decisão de acesso:** É tomada comparando as ACEs da DACL com o token de acesso; as SACLs são usadas para auditoria.<sup>[[1]](#references)</sup>

### ACEs

Há **três tipos principais de Entradas de Controle de Acesso (ACEs)**:<sup>[[1]](#references)</sup>

- **ACE de negação de acesso**: Nega explicitamente o acesso a um objeto para usuários ou grupos especificados (em uma DACL).
- **ACE de permissão de acesso**: Concede explicitamente acesso a um objeto para usuários ou grupos especificados (em uma DACL).
- **ACE de auditoria do sistema**: Localizada em uma Lista de Controle de Acesso do Sistema (SACL), essa ACE é responsável por gerar logs de auditoria quando usuários ou grupos tentam acessar um objeto. Ela registra se o acesso foi permitido ou negado e a natureza do acesso.

Cada ACE tem **quatro componentes essenciais**:<sup>[[1]](#references)</sup>

1. O **Identificador de Segurança (SID)** do usuário ou grupo (ou o nome da entidade de segurança em uma representação gráfica).
2. Uma **flag** que identifica o tipo de ACE (negação de acesso, permissão de acesso ou auditoria do sistema).
3. **Flags de herança** que determinam se os objetos filhos podem herdar a ACE do objeto pai.
4. Uma [**máscara de acesso**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), um valor de 32 bits que especifica os direitos concedidos no objeto.

A determinação do acesso é feita examinando cada ACE em sequência até que:<sup>[[1]](#references)</sup>

- Uma **ACE de negação de acesso** negue explicitamente os direitos solicitados a um trustee identificado no token de acesso.
- Uma ou mais **ACEs de permissão de acesso** concedam explicitamente todos os direitos solicitados a um trustee no token de acesso.
- Após a verificação de todas as ACEs, qualquer direito solicitado que **não tenha sido permitido explicitamente** seja **negado** implicitamente.

### Ordem das ACEs

A maneira como as **ACEs** (regras que definem quem pode ou não acessar algo) são organizadas em uma lista chamada **DACL** é muito importante. Isso ocorre porque, assim que o sistema concede ou nega acesso com base nessas regras, ele para de verificar as demais.<sup>[[1]](#references)</sup>

Há uma maneira recomendada de organizar essas ACEs, chamada **“ordem canônica”**. Esse método ajuda a garantir que tudo funcione de forma consistente e justa. Veja como funciona em sistemas como **Windows 2000** e **Windows Server 2003**:

- Primeiro, coloque todas as regras **específicas para esse item** antes das regras herdadas de outro local, como uma pasta pai.
- Entre essas regras específicas, coloque primeiro as que dizem **“não” (negar)** e depois as que dizem **“sim” (permitir)**.
- Para as regras herdadas de outro local, comece pelas do **objeto de origem mais próximo**, como a pasta pai, e depois siga para as mais distantes. Mais uma vez, coloque **“não”** antes de **“sim”**.

Essa organização ajuda de duas maneiras importantes:

- Garante que uma **negação** específica seja respeitada, independentemente de outras regras de **permissão**.
- Permite que o proprietário de um item tenha a **palavra final** sobre quem pode acessá-lo, antes que as regras das pastas pai ou de outros locais mais distantes sejam consideradas.

Com essa organização, o proprietário de um arquivo ou pasta pode controlar com precisão quem tem acesso, garantindo que as pessoas certas possam entrar e as erradas não.

![Diagrama da ordem das entradas de controle de acesso do NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Assim, essa **“ordem canônica”** serve para deixar claras as regras de acesso e garantir que funcionem bem, priorizando as regras específicas e organizando todo o restante de forma inteligente.

### Exemplo de GUI

[**Exemplo daqui**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Esta é a guia de segurança clássica de uma pasta, mostrando a ACL, a DACL e as ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Se clicarmos no **botão Avançado**, veremos mais opções, como a herança:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

E se adicionarmos ou editarmos uma entidade de segurança:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Por fim, temos a SACL na guia Auditoria:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explicação simplificada do controle de acesso

Para gerenciar o acesso a recursos, como uma pasta, usamos listas e regras conhecidas como Listas de Controle de Acesso (ACLs) e Entradas de Controle de Acesso (ACEs). Elas definem quem pode ou não acessar determinados dados.<sup>[[1]](#references)</sup>

#### Negar acesso a um grupo específico

Imagine que você tem uma pasta chamada Cost e quer permitir que todos a acessem, exceto uma equipe de marketing. Configurando as regras corretamente, podemos garantir que o acesso seja negado explicitamente à equipe de marketing antes de permitir o acesso a todos os demais. Para isso, colocamos a regra que nega acesso à equipe de marketing antes da regra que permite o acesso a todos.

#### Permitir acesso a um membro específico de um grupo cujo acesso foi negado

Digamos que Bob, o diretor de marketing, precise acessar a pasta Cost, embora a equipe de marketing em geral não deva ter acesso. Podemos adicionar uma regra específica (ACE) para Bob que conceda acesso a ele e colocá-la antes da regra que nega acesso à equipe de marketing. Assim, Bob obtém acesso apesar da restrição geral aplicada à equipe.

#### Entendendo as Entradas de Controle de Acesso

As ACEs são regras individuais dentro de uma ACL. Elas identificam usuários ou grupos, especificam quais acessos são permitidos ou negados e determinam como essas regras se aplicam aos itens subordinados (herança). Existem dois tipos principais de ACEs:

- **ACEs genéricas**: Aplicam-se de forma ampla, afetando todos os tipos de objetos ou distinguindo apenas entre contêineres (como pastas) e objetos que não são contêineres (como arquivos). Por exemplo, uma regra que permite aos usuários ver o conteúdo de uma pasta, mas não acessar os arquivos dentro dela.
- **ACEs específicas de objeto**: Oferecem um controle mais preciso, permitindo definir regras para tipos específicos de objetos ou até mesmo propriedades individuais de um objeto. Por exemplo, em um diretório de usuários, uma regra pode permitir que um usuário atualize seu número de telefone, mas não seu horário de login.

Cada ACE contém informações importantes, como a quem a regra se aplica (usando um Identificador de Segurança ou SID), o que a regra permite ou nega (usando uma máscara de acesso) e como ela é herdada por outros objetos.

#### Principais diferenças entre os tipos de ACE

- **ACEs genéricas** são adequadas para cenários simples de controle de acesso, nos quais a mesma regra se aplica a todos os aspectos de um objeto ou a todos os objetos de um contêiner.
- **ACEs específicas de objeto** são usadas em cenários mais complexos, especialmente em ambientes como o Active Directory, nos quais pode ser necessário controlar de maneiras diferentes o acesso a propriedades específicas de um objeto.

Em resumo, ACLs e ACEs ajudam a definir controles de acesso precisos, garantindo que apenas as pessoas ou grupos certos tenham acesso a informações ou recursos confidenciais, com a possibilidade de ajustar os direitos de acesso até o nível de propriedades individuais ou tipos de objeto.

### Estrutura de uma entrada de controle de acesso

| Campo da ACE | Descrição                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tipo        | Flag que indica o tipo de ACE. O Windows 2000 e o Windows Server 2003 oferecem suporte a seis tipos de ACE: três tipos genéricos anexados a todos os objetos protegíveis e três tipos específicos de objeto que podem ocorrer em objetos do Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Conjunto de flags de bits que controlam a herança e a auditoria.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tamanho     | Número de bytes de memória alocados para a ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Máscara de acesso | Valor de 32 bits cujos bits correspondem aos direitos de acesso ao objeto. Os bits podem estar ligados ou desligados, mas o significado da configuração depende do tipo de ACE. Por exemplo, se o bit correspondente ao direito de ler permissões estiver ligado e o tipo de ACE for Deny, a ACE negará o direito de ler as permissões do objeto. Se o mesmo bit estiver ligado e o tipo de ACE for Allow, a ACE concederá o direito de ler as permissões do objeto. Mais detalhes sobre a máscara de acesso são apresentados na tabela seguinte. |
| SID         | Identifica um usuário ou grupo cujo acesso é controlado ou monitorado por essa ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Estrutura da máscara de acesso

| Bit (intervalo) | Significado                         | Descrição/Exemplo                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Direitos de acesso específicos do objeto | Ler dados, executar, acrescentar dados           |
| 16 - 22     | Direitos de acesso padrão          | Excluir, gravar ACL, gravar proprietário            |
| 23          | Pode acessar a ACL de segurança    |                                           |
| 24 - 27     | Reservado                          |                                           |
| 28          | Generic ALL (leitura, gravação, execução) | Tudo abaixo                          |
| 29          | Generic Execute                    | Tudo o que é necessário para executar um programa |
| 30          | Generic Write                      | Tudo o que é necessário para gravar em um arquivo   |
| 31          | Generic Read                       | Tudo o que é necessário para ler um arquivo       |

## References

- [1] [Como o sistema usa ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL e a ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
