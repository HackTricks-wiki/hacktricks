# Keychain do macOS

{{#include ../../banners/hacktricks-training.md}}

## Keychains principais

- O **Keychain do usuário** (`~/Library/Keychains/login.keychain-db`), usado para armazenar **credenciais específicas do usuário**, como senhas de aplicativos, senhas da internet, certificados gerados pelo usuário, senhas de rede e chaves públicas/privadas geradas pelo usuário.
- O **Keychain do sistema** (`/Library/Keychains/System.keychain`), que armazena **credenciais de todo o sistema**, como senhas de WiFi, certificados raiz do sistema, chaves privadas do sistema e senhas de aplicativos do sistema.<sup>[[1]](#references)</sup>
  - É possível encontrar outros componentes, como certificados, em `/System/Library/Keychains/*`
- No **iOS**, há apenas um **Keychain**, localizado em `/private/var/Keychains/`. Essa pasta também contém bancos de dados do `TrustStore`, autoridades de certificação (`caissuercache`) e entradas OSCP (`ocspache`).
  - Os apps terão acesso restrito no keychain apenas à sua área privada, com base no identificador do aplicativo.

### Acesso ao Keychain por senha

Esses arquivos, embora não tenham proteção inerente e possam ser **baixados**, são criptografados e exigem a **senha em texto simples do usuário para serem descriptografados**. Uma ferramenta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usada para descriptografá-los.<sup>[[1]](#references)</sup>

## Proteções das entradas do Keychain

### ACLs

Cada entrada no keychain é regida por **Listas de Controle de Acesso (ACLs)**, que determinam quem pode executar várias ações na entrada do keychain, incluindo:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Permite que o detentor obtenha o segredo em texto simples.
- **`kSecACLAuthorizationExportWrapped`**: Permite que o detentor obtenha o texto simples criptografado com outra senha fornecida.
- **`kSecACLAuthorizationAny`**: Permite que o detentor execute qualquer ação.

As ACLs são acompanhadas por uma **lista de aplicativos confiáveis** que podem executar essas ações sem solicitar confirmação. Essa lista pode ser:<sup>[[1]](#references)</sup>

- **N`il`** (nenhuma autorização necessária, **todos são confiáveis**)
- Uma lista **vazia** (**ninguém** é confiável)
- Uma **lista** de **aplicativos** específicos.

A entrada também pode conter a chave **`kSecACLAuthorizationPartitionID`,** usada para identificar o **teamid, apple** e **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Se o **teamid** for especificado, o aplicativo deverá ter o **mesmo teamid** para **acessar** o valor da **entrada sem** uma **solicitação**.
- Se **apple** for especificado, o app precisará ser **assinado** pela **Apple**.
- Se o **cdhash** for indicado, o **app** deverá ter o **cdhash** específico.

### Criando uma entrada no Keychain

Quando uma **nova** **entrada** é criada usando **`Keychain Access.app`**, aplicam-se as seguintes regras:<sup>[[1]](#references)</sup>

- Todos os apps podem criptografar.
- **Nenhum app** pode exportar/descriptografar (sem solicitar confirmação ao usuário).
- Todos os apps podem ver a verificação de integridade.
- Nenhum app pode alterar as ACLs.
- O **partitionID** é definido como **`apple`**.

Quando um **aplicativo cria uma entrada no keychain**, as regras são um pouco diferentes:<sup>[[1]](#references)</sup>

- Todos os apps podem criptografar.
- Somente o **aplicativo criador** (ou outros apps adicionados explicitamente) pode exportar/descriptografar (sem solicitar confirmação ao usuário).
- Todos os apps podem ver a verificação de integridade.
- Nenhum app pode alterar as ACLs.
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
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` define a lista de partições do item, enquanto `-k` fornece a senha atual do Keychain necessária para fazer essa alteração; a flag que recebe a senha está obsoleta.<sup>[[4]](#references)</sup> Uma atualização bem-sucedida não prova que uma leitura posterior será silenciosa: um protótipo observado, embora desativado, ainda acionou um prompt de confirmação ao consultar o item por meio de `Security.framework`. Um ID de partição correspondente é apenas uma parte das verificações de ACL e de aplicativos confiáveis descritas acima, portanto, verifique o caminho de leitura real.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> A **enumeração e o dumping de secrets** que **não geram um prompt** podem ser feitos com a ferramenta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Outros endpoints de API podem ser encontrados no código-fonte de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Liste e obtenha **informações** sobre cada entrada do Keychain usando o **Security Framework** ou consulte também a ferramenta CLI open source da Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alguns exemplos de API:<sup>[[1]](#references)</sup>

- A API **`SecItemCopyMatching`** fornece informações sobre cada entrada, e há alguns atributos que você pode definir ao usá-la:
  - **`kSecReturnData`**: Se for true, tentará descriptografar os dados (defina como false para evitar possíveis pop-ups)
  - **`kSecReturnRef`**: Também obtém uma referência ao item do Keychain (defina como true caso depois você veja que é possível descriptografar sem pop-up)
  - **`kSecReturnAttributes`**: Obtém metadados sobre as entradas
  - **`kSecMatchLimit`**: Quantos resultados retornar
  - **`kSecClass`**: Tipo de entrada do Keychain

Obtenha as **ACLs** de cada entrada:<sup>[[1]](#references)</sup>

- Com a API **`SecAccessCopyACLList`**, você pode obter a **ACL do item do Keychain**. Ela retorna uma lista de ACLs (como `kSecACLAuthorizationExportClear` e as outras mencionadas anteriormente), em que cada entrada tem:<sup>[[1]](#references)[[2]](#references)</sup>
  - Descrição
  - **Lista de aplicativos confiáveis**. Pode ser:
    - Um app: /Applications/Slack.app
    - Um binário: /usr/libexec/airportd
    - Um grupo: group://AirPort

Exporte os dados:<sup>[[1]](#references)</sup>

- A API **`SecKeychainItemCopyContent`** obtém o texto simples
- A API **`SecItemExport`** exporta as chaves e os certificados, mas talvez seja necessário definir senhas para exportar o conteúdo criptografado

Estes são os **requisitos** para poder **exportar um secret sem um prompt**:<sup>[[1]](#references)</sup>

- Se houver **1 ou mais apps confiáveis** listados:
  - São necessárias as **autorizações** apropriadas (**`Nil`** ou fazer **parte** da lista de apps permitidos na autorização para acessar as informações secretas)
  - A assinatura de código precisa corresponder ao **PartitionID**
  - A assinatura de código precisa corresponder à de um **app confiável** (ou ser membro do KeychainAccessGroup correto)
- Se **todos os aplicativos forem confiáveis**:
  - São necessárias as **autorizações** apropriadas
  - A assinatura de código precisa corresponder ao **PartitionID**
    - Se **não houver PartitionID**, isso não é necessário

> [!CAUTION]
> Portanto, se houver **1 aplicativo listado**, você precisará **injetar código nesse aplicativo**.
>
> Se **apple** estiver indicado no **partitionID**, você poderá acessá-lo com **`osascript`**; assim, qualquer coisa que confie em todos os aplicativos com apple no partitionID. **`Python`** também pode ser usado.

### Dois atributos adicionais

- **Invisible**: É uma flag booleana para **ocultar** a entrada do app **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Serve para armazenar **metadados** (ou seja, NÃO É CRIPTOGRAFADO)<sup>[[1]](#references)</sup>
  - A Microsoft armazenava em texto simples todos os refresh tokens para acessar endpoints sensíveis.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Uma nova versão do malware ladrão de informações MacSync para macOS tem como alvo entusiastas de criptomoedas e desenvolvedores](https://securelist.com/macsync-new-version/121383/)
- [4] [Espelho da página man security(1) da Apple](https://keith.github.io/xcode-man-pages/security.1.html)
