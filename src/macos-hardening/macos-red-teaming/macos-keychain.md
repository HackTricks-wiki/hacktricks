# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Keychains Principais

- O **User Keychain** (`~/Library/Keychains/login.keychain-db`), usado para armazenar **credenciais específicas do usuário**, como senhas de aplicativos, senhas da Internet, certificados gerados pelo usuário, senhas de rede e chaves públicas/privadas geradas pelo usuário.
- O **System Keychain** (`/Library/Keychains/System.keychain`), que armazena credenciais **em todo o sistema**, como senhas de WiFi, certificados raiz do sistema, chaves privadas do sistema e senhas de aplicativos do sistema.<sup>[[1]](#references)</sup>
- É possível encontrar outros componentes, como certificados, em `/System/Library/Keychains/*`
- No **iOS**, existe apenas um **Keychain**, localizado em `/private/var/Keychains/`. Essa pasta também contém bancos de dados para o `TrustStore`, autoridades de certificação (`caissuercache`) e entradas OSCP (`ocspache`).
- Os aplicativos terão acesso restrito no keychain somente à sua área privada, com base no identificador do aplicativo.

### Acesso ao Keychain por Senha

Embora esses arquivos não tenham proteção inerente e possam ser **baixados**, eles são criptografados e exigem a **senha do usuário em texto simples para serem descriptografados**. Uma ferramenta como o [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usada para descriptografia.<sup>[[1]](#references)</sup>

## Proteções das Entradas do Keychain

### ACLs

Cada entrada no keychain é controlada por **Access Control Lists (ACLs)**, que determinam quem pode realizar várias ações na entrada do keychain, incluindo:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Permite que o titular obtenha o texto claro do segredo.
- **ACLAuhtorizationExportWrapped**: Permite que o titular obtenha o texto claro criptografado com outra senha fornecida.
- **ACLAuhtorizationAny**: Permite que o titular execute qualquer ação.

As ACLs também são acompanhadas por uma **lista de aplicativos confiáveis** que podem executar essas ações sem solicitar confirmação. Isso pode ser:<sup>[[1]](#references)</sup>

- **N`il`** (nenhuma autorização necessária, **todos são confiáveis**)
- Uma lista **vazia** (**ninguém** é confiável)
- **Lista** de **aplicativos** específicos.

A entrada também pode conter a chave **`ACLAuthorizationPartitionID`,** usada para identificar o **teamid, apple** e **cdhash.**<sup>[[1]](#references)</sup>

- Se o **teamid** for especificado, para **acessar o valor da entrada** **sem** um **prompt**, o aplicativo utilizado deverá ter o **mesmo teamid**.
- Se **apple** for especificado, o aplicativo precisará ser **assinado** pela **Apple**.
- Se o **cdhash** for indicado, o **aplicativo** deverá ter o **cdhash** específico.

### Criando uma Entrada no Keychain

Quando uma **nova** **entrada** é criada usando o **`Keychain Access.app`**, as seguintes regras se aplicam:<sup>[[1]](#references)</sup>

- Todos os aplicativos podem criptografar.
- **Nenhum aplicativo** pode exportar/descriptografar (sem solicitar confirmação ao usuário).
- Todos os aplicativos podem visualizar a verificação de integridade.
- Nenhum aplicativo pode alterar as ACLs.
- O **partitionID** é definido como **`apple`**.

Quando um **aplicativo cria uma entrada no keychain**, as regras são ligeiramente diferentes:<sup>[[1]](#references)</sup>

- Todos os aplicativos podem criptografar.
- Somente o **aplicativo criador** (ou qualquer outro aplicativo explicitamente adicionado) pode exportar/descriptografar (sem solicitar confirmação ao usuário).
- Todos os aplicativos podem visualizar a verificação de integridade.
- Nenhum aplicativo pode alterar as ACLs.
- O **partitionID** é definido como **`teamid:[teamID here]`**.

## Acessando o Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> A **enumeração e o dumping de secrets do keychain** que **não gerarão um prompt** podem ser feitos com a ferramenta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Outros endpoints de API podem ser encontrados no código-fonte de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Liste e obtenha **informações** sobre cada entrada do keychain usando o **Security Framework** ou consulte também a ferramenta cli open source da Apple, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alguns exemplos de API:<sup>[[1]](#references)</sup>

- A API **`SecItemCopyMatching`** fornece informações sobre cada entrada, e há alguns atributos que você pode definir ao usá-la:
- **`kSecReturnData`**: Se for true, tentará descriptografar os dados (defina como false para evitar possíveis pop-ups)
- **`kSecReturnRef`**: Obtém também uma referência ao item do keychain (defina como true caso posteriormente você descubra que pode descriptografá-lo sem um pop-up)
- **`kSecReturnAttributes`**: Obtém metadados sobre as entradas
- **`kSecMatchLimit`**: Quantidade de resultados a retornar
- **`kSecClass`**: Tipo de entrada do keychain

Obtenha as **ACLs** de cada entrada:<sup>[[1]](#references)</sup>

- Com a API **`SecAccessCopyACLList`**, você pode obter a **ACL do item do keychain**, e ela retornará uma lista de ACLs (como `ACLAuhtorizationExportClear` e as outras mencionadas anteriormente), em que cada lista contém:
- Descrição
- **Lista de Aplicações Confiáveis**. Isso pode ser:
- Um app: /Applications/Slack.app
- Um binário: /usr/libexec/airportd
- Um grupo: group://AirPort

Exporte os dados:<sup>[[1]](#references)</sup>

- A API **`SecKeychainItemCopyContent`** obtém o plaintext
- A API **`SecItemExport`** exporta as chaves e os certificados, mas pode ser necessário definir senhas para exportar o conteúdo criptografado

E estes são os **requisitos** para conseguir **exportar um secret sem um prompt**:<sup>[[1]](#references)</sup>

- Se houver 1 ou mais apps **trusted** listados:
- Precisa das **authorizations** apropriadas (**`Nil`** ou fazer **parte** da lista permitida de apps na authorization para acessar as informações do secret)
- A assinatura do código precisa corresponder ao **PartitionID**
- A assinatura do código precisa corresponder à de um **app trusted** (ou ser membro do KeychainAccessGroup correto)
- Se **todas as aplicações forem trusted**:
- Precisa das **authorizations** apropriadas
- A assinatura do código precisa corresponder ao **PartitionID**
- Se não houver **PartitionID**, isso não será necessário

> [!CAUTION]
> Portanto, se houver **1 aplicação listada**, você precisará **injetar código nessa aplicação**.
>
> Se **apple** estiver indicado no **partitionID**, você poderá acessá-lo com **`osascript`**, portanto qualquer aplicação que confie em todas as aplicações e tenha apple no partitionID. **`Python`** também pode ser usado para isso.

### Dois atributos adicionais

- **Invisible**: É um sinalizador booleano para **ocultar** a entrada do app **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Serve para armazenar **metadados** (portanto, NÃO É CRIPTOGRAFADO)<sup>[[1]](#references)</sup>
- A Microsoft armazenava em texto simples todos os refresh tokens para acessar endpoints sensíveis.<sup>[[1]](#references)</sup>

## Referências

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
