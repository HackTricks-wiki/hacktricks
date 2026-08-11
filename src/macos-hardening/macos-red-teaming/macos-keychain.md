# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- O **User Keychain** (`~/Library/Keychains/login.keychain-db`), usado para armazenar **credenciais específicas do usuário**, como senhas de aplicações, senhas da Internet, certificados gerados pelo usuário, senhas de rede e chaves públicas/privadas geradas pelo usuário.
- O **System Keychain** (`/Library/Keychains/System.keychain`), que armazena credenciais **em todo o sistema**, como senhas de WiFi, certificados raiz do sistema, chaves privadas do sistema e senhas de aplicações do sistema.<sup>[[1]](#references)</sup>
- É possível encontrar outros componentes, como certificados, em `/System/Library/Keychains/*`
- No **iOS**, há apenas um **Keychain**, localizado em `/private/var/Keychains/`. Essa pasta também contém bancos de dados para o `TrustStore`, autoridades de certificação (`caissuercache`) e entradas OSCP (`ocspache`).
- As aplicações ficarão restritas, no Keychain, apenas à sua área privada, com base no identificador da aplicação.

### Acesso por senha ao Keychain

Embora esses arquivos não tenham proteção inerente e possam ser **baixados**, eles são criptografados e exigem a **senha em texto simples do usuário para serem descriptografados**. Uma ferramenta como o [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usada para a descriptografia.<sup>[[1]](#references)</sup>

## Proteções das entradas do Keychain

### ACLs

Cada entrada no Keychain é regida por **Listas de Controle de Acesso (ACLs)**, que determinam quem pode executar várias ações na entrada do Keychain, incluindo:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: Permite que o titular obtenha o segredo em texto simples.
- **ACLAuthorizationExportWrapped**: Permite que o titular obtenha o texto simples criptografado com outra senha fornecida.
- **ACLAuthorizationAny**: Permite que o titular execute qualquer ação.

As ACLs também são acompanhadas por uma **lista de aplicações confiáveis** que podem executar essas ações sem exibir um prompt. Isso pode ser:<sup>[[1]](#references)</sup>

- **N`il`** (nenhuma autorização necessária, **todos são confiáveis**)
- Uma lista **vazia** (**ninguém** é confiável)
- **Lista** de **aplicações** específicas.

Além disso, a entrada pode conter a chave **`ACLAuthorizationPartitionID`,** usada para identificar o **teamid, apple** e **cdhash**.<sup>[[1]](#references)</sup>

- Se o **teamid** for especificado, a aplicação deverá ter o **mesmo teamid** para **acessar** o valor da **entrada** **sem** um **prompt**.
- Se **apple** for especificado, a aplicação precisará ser **assinada** pela **Apple**.
- Se o **cdhash** for indicado, a **aplicação** deverá ter o **cdhash** específico.

### Criando uma entrada no Keychain

Quando uma **nova** **entrada** é criada usando o **`Keychain Access.app`**, as seguintes regras se aplicam:<sup>[[1]](#references)</sup>

- Todas as aplicações podem criptografar.
- **Nenhuma aplicação** pode exportar/descriptografar (sem solicitar confirmação ao usuário).
- Todas as aplicações podem ver a verificação de integridade.
- Nenhuma aplicação pode alterar as ACLs.
- O **partitionID** é definido como **`apple`**.

Quando uma **aplicação cria uma entrada no Keychain**, as regras são ligeiramente diferentes:<sup>[[1]](#references)</sup>

- Todas as aplicações podem criptografar.
- Apenas a **aplicação criadora** (ou qualquer outra aplicação explicitamente adicionada) pode exportar/descriptografar (sem solicitar confirmação ao usuário).
- Todas as aplicações podem ver a verificação de integridade.
- Nenhuma aplicação pode alterar as ACLs.
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> A **enumeração e o dumping de secrets do keychain** que **não gerarão um prompt** podem ser realizados com a ferramenta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Outros endpoints de API podem ser encontrados no código-fonte [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Liste e obtenha **informações** sobre cada entrada do keychain usando o **Security Framework** ou consulte também a ferramenta cli open source da Apple, [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alguns exemplos de API:<sup>[[1]](#references)</sup>

- A API **`SecItemCopyMatching`** fornece informações sobre cada entrada, e há alguns atributos que você pode definir ao utilizá-la:
- **`kSecReturnData`**: Se true, tentará descriptografar os dados (defina como false para evitar possíveis pop-ups)
- **`kSecReturnRef`**: Obtém também uma referência ao item do keychain (defina como true caso depois você descubra que pode descriptografá-lo sem pop-up)
- **`kSecReturnAttributes`**: Obtém metadados sobre as entradas
- **`kSecMatchLimit`**: Quantos resultados retornar
- **`kSecClass`**: Que tipo de entrada do keychain

Obtenha as **ACLs** de cada entrada:<sup>[[1]](#references)</sup>

- Com a API **`SecAccessCopyACLList`**, você pode obter a **ACL do item do keychain**. Ela retorna uma lista de ACLs (como `ACLAuthorizationExportClear` e as outras mencionadas anteriormente), em que cada entrada possui:
- Descrição
- **Trusted Application List**. Isso pode ser:
- Um app: /Applications/Slack.app
- Um binário: /usr/libexec/airportd
- Um grupo: group://AirPort

Exporte os dados:<sup>[[1]](#references)</sup>

- A API **`SecKeychainItemCopyContent`** obtém o texto não criptografado
- A API **`SecItemExport`** exporta as keys e os certificados, mas pode ser necessário definir passwords para exportar o conteúdo criptografado

E estes são os **requisitos** para conseguir **exportar um secret sem um prompt**:<sup>[[1]](#references)</sup>

- Se houver **1 ou mais apps trusted** listados:
- É necessário ter as **authorizations** apropriadas (**`Nil`** ou fazer **parte** da lista permitida de apps na autorização para acessar as informações secretas)
- A code signature precisa corresponder ao **PartitionID**
- A code signature precisa corresponder à de um **trusted app** (ou ser membro do KeychainAccessGroup correto)
- Se **todas as aplicações forem trusted**:
- É necessário ter as **authorizations** apropriadas
- A code signature precisa corresponder ao **PartitionID**
- Se não houver **PartitionID**, isso não será necessário

> [!CAUTION]
> Portanto, se houver **1 aplicação listada**, será necessário **injetar code em tal aplicação**.
>
> Se **apple** estiver indicado no **partitionID**, você poderá acessá-lo com **`osascript`**, portanto qualquer aplicação que confie em todas as aplicações com apple no partitionID. **`Python`** também pode ser usado para isso.

### Dois atributos adicionais

- **Invisible**: É uma flag booleana para **ocultar** a entrada do app **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Serve para armazenar **metadados** (portanto, NÃO É CRIPTOGRAFADO)<sup>[[1]](#references)</sup>
- A Microsoft estava armazenando em texto não criptografado todos os refresh tokens para acessar endpoints sensíveis.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Arrombando o macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
