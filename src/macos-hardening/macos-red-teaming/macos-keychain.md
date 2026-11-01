# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Principais Keychains

- O **User Keychain** (`~/Library/Keychains/login.keychain-db`), usado para armazenar **credenciais específicas do usuário**, como senhas de aplicativos, senhas da internet, certificados gerados pelo usuário, senhas de rede e chaves públicas/privadas geradas pelo usuário.
- O **System Keychain** (`/Library/Keychains/System.keychain`), que armazena **credenciais de todo o sistema**, como senhas de WiFi, certificados raiz do sistema, chaves privadas do sistema e senhas de aplicativos do sistema.<sup>[[1]](#references)</sup>
  - É possível encontrar outros componentes, como certificados, em `/System/Library/Keychains/*`
- O **data protection keychain** por usuário aparece como **Local Items** ou **iCloud** no Keychain Access. Ele é separado de `login.keychain-db` e inclui itens somente locais e sincronizáveis; `security` é principalmente uma ferramenta para keychains baseados em arquivos, portanto, um resultado curto de `dump-keychain` não descarta a existência de credenciais aqui.<sup>[[5]](#references)</sup>
- No **iOS**, há apenas um **Keychain**, localizado em `/private/var/Keychains/`. Essa pasta também contém bancos de dados do `TrustStore`, autoridades certificadoras (`caissuercache`) e entradas OSCP (`ocspache`).
  - Os apps terão acesso restrito no keychain apenas à sua área privada, com base no identificador do aplicativo.

### Acesso ao Keychain com senha

Um keychain **baseado em arquivo** copiado não está em texto simples. A descriptografia offline de seus itens protegidos requer a senha do keychain ou material de chave equivalente; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) tem como alvo esse formato.<sup>[[1]](#references)</sup> Isso é diferente de uma leitura em tempo real em uma sessão de usuário desbloqueada, na qual os controles de acesso aos itens podem permitir a leitura ou exibir uma solicitação sem exigir novamente a senha de login. O data protection keychain tem um modelo diferente de proteção e de grupos de acesso.<sup>[[5]](#references)</sup>

## Proteções das entradas do Keychain

### ACLs de keychains baseados em arquivos

As regras de ACL `SecAccess` e de partition-list abaixo descrevem keychains **baseados em arquivos**. Em vez disso, os itens do data protection keychain usam grupos de acesso de assinatura de código e condições opcionais de `SecAccessControl`; não deduza a acessibilidade deles a partir de um dump de ACL de um keychain baseado em arquivo.<sup>[[5]](#references)</sup>

Cada entrada em um keychain baseado em arquivo é regida por **listas de controle de acesso (ACLs)**, que determinam quem pode executar várias ações na entrada do keychain, incluindo:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Permite que o titular obtenha o segredo em texto simples.
- **`kSecACLAuthorizationExportWrapped`**: Permite que o titular obtenha o texto simples criptografado com outra senha fornecida.
- **`kSecACLAuthorizationAny`**: Permite que o titular execute qualquer ação.

As ACLs também são acompanhadas por uma **lista de aplicativos confiáveis** que podem executar essas ações sem exibir uma solicitação. Ela pode ser:<sup>[[1]](#references)</sup>

- **N`il`** (nenhuma autorização necessária, **todos são confiáveis**)
- Uma lista **vazia** (**ninguém** é confiável)
- Uma **lista** de **aplicativos** específicos.

A entrada também pode conter a chave **`kSecACLAuthorizationPartitionID`,** usada para identificar o **teamid, apple** e **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Se o **teamid** for especificado, o aplicativo deverá ter o **mesmo teamid** para **acessar o valor** da **entrada sem** uma **solicitação**.
- Se **apple** for especificado, o app precisará ser **assinado** pela **Apple**.
- Se o **cdhash** for indicado, o **app** deverá ter o **cdhash** específico.

### Criando uma entrada em um keychain baseado em arquivo

Quando uma **nova** **entrada** é criada usando o **`Keychain Access.app`**, aplicam-se as seguintes regras:<sup>[[1]](#references)</sup>

- Todos os apps podem criptografar.
- **Nenhum app** pode exportar/descriptografar (sem solicitar a autorização do usuário).
- Todos os apps podem ver a verificação de integridade.
- Nenhum app pode alterar ACLs.
- O **partitionID** é definido como **`apple`**.

Quando um **aplicativo cria uma entrada no keychain**, as regras são ligeiramente diferentes:<sup>[[1]](#references)</sup>

- Todos os apps podem criptografar.
- Somente o **aplicativo criador** (ou qualquer outro app adicionado explicitamente) pode exportar/descriptografar (sem solicitar a autorização do usuário).
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

`-S` define a lista de partições do item, enquanto `-k` fornece a senha atual do Keychain necessária para fazer essa alteração; a flag que recebe a senha está obsoleta.<sup>[[4]](#references)</sup> Uma atualização bem-sucedida não prova que uma leitura posterior será silenciosa: um protótipo desativado observado ainda acionou uma solicitação de confirmação ao consultar o item por meio de `Security.framework`. Um ID de partição correspondente é apenas uma parte das verificações de ACL e de aplicações confiáveis descritas acima; portanto, verifique o caminho real de leitura.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> A **enumeração e extração de segredos do Keychain** que **não gerarão uma solicitação** podem ser feitas com a ferramenta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Outros endpoints de API podem ser encontrados no código-fonte de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Liste e obtenha **informações** sobre cada entrada do Keychain usando o **Security Framework** ou consulte também a ferramenta CLI de código aberto da Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Alguns exemplos de API:<sup>[[1]](#references)</sup>

- A API **`SecItemCopyMatching`** fornece informações sobre cada entrada e permite definir alguns atributos ao usá-la:
  - **`kSecReturnData`**: Se for true, tentará descriptografar os dados (defina como false para evitar possíveis pop-ups)
  - **`kSecReturnRef`**: Obtém uma referência de objeto para uma chave, certificado ou identidade; itens de senha não têm essa representação de objeto. Use `kSecReturnPersistentRef` para identificar uma senha em uma consulta direcionada posterior.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: Obtém metadados sobre as entradas
  - **`kSecMatchLimit`**: Quantos resultados retornar
  - **`kSecClass`**: Que tipo de entrada do Keychain

Obtenha as **ACLs** de cada entrada:<sup>[[1]](#references)</sup>

- Com a API **`SecAccessCopyACLList`**, você pode obter a **ACL do item do Keychain**. Ela retorna uma lista de ACLs (como `kSecACLAuthorizationExportClear` e as outras mencionadas anteriormente), em que cada entrada contém:<sup>[[1]](#references)[[2]](#references)</sup>
  - Descrição
  - **Lista de aplicações confiáveis**. Pode ser:
    - Um app: /Applications/Slack.app
    - Um binário: /usr/libexec/airportd
    - Um grupo: group://AirPort

Exporte os dados:<sup>[[1]](#references)</sup>

- A API **`SecKeychainItemCopyContent`** obtém o texto simples
- A API **`SecItemExport`** exporta as chaves e os certificados, mas talvez seja necessário definir senhas para exportar o conteúdo criptografado

E estes são os **requisitos** para **exportar um segredo sem uma solicitação**:<sup>[[1]](#references)</sup>

- Se houver **1 ou mais aplicações confiáveis** listadas:
  - São necessárias as **autorizações** apropriadas (**`Nil`** ou fazer **parte** da lista de aplicações permitidas na autorização para acessar as informações secretas)
  - A assinatura de código precisa corresponder ao **PartitionID**
  - A assinatura de código precisa corresponder à de uma **aplicação confiável** (ou ser membro do KeychainAccessGroup correto)
- Se **todas as aplicações forem confiáveis**:
  - São necessárias as **autorizações** apropriadas
  - A assinatura de código precisa corresponder ao **PartitionID**
    - Se **não houver PartitionID**, isso não é necessário

> [!CAUTION]
> Portanto, se houver **1 aplicação listada**, você precisa **injetar código nessa aplicação**.
>
> Se **Apple** estiver indicado no **partitionID**, você poderá acessá-lo com **`osascript`**; assim, qualquer coisa que confie em todas as aplicações com Apple no partitionID poderá ser acessada. **`Python`** também pode ser usado para isso.

### Dois atributos adicionais

- **Invisible**: É uma flag booleana para **ocultar** a entrada do app **UI** Keychain<sup>[[1]](#references)</sup>
- **General**: Serve para armazenar **metadados** (portanto, NÃO É CRIPTOGRAFADO)<sup>[[1]](#references)</sup>
  - A Microsoft estava armazenando em texto simples todos os refresh tokens para acessar um endpoint sensível.<sup>[[1]](#references)</sup>

### Keychain de proteção de dados: enumerar e, depois, consultar um item

Execute `SecItemCopyMatching` de um **app assinado no contexto de login do usuário-alvo** com `kSecUseDataProtectionKeychain: true`; não presuma que `security dump-keychain` ou uma consulta SecItem padrão pesquisou esse armazenamento. O chamador só vê os grupos de acesso para os quais está autorizado.<sup>[[5]](#references)</sup>

Se o código de teste for executado dentro de outro processo, o acesso dele ao Keychain de proteção de dados seguirá os entitlements do executável hospedeiro. Inspecione os entitlements realmente assinados com `codesign -d --entitlements - /path/to/Target.app` e consulte [entitlements de assinatura de código do macOS](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) para verificações relacionadas.<sup>[[7]](#references)</sup>

Primeiro, solicite **somente os atributos** para uma classe de item. `kSecAttrSynchronizableAny` inclui correspondências locais e sincronizáveis com o iCloud; omiti-lo exclui os itens sincronizáveis.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` evita a interface de autenticação durante a enumeração ampla, mas deixa de incluir as correspondências protegidas.<sup>[[9]](#references)</sup> Repita com `kSecClassInternetPassword` se necessário.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Para uma leitura autorizada de segredo, crie uma consulta **nova** e restrita para o item selecionado (por exemplo, classe, serviço e conta), defina `kSecReturnData: true` e `kSecMatchLimit: kSecMatchLimitOne`, e espere uma autenticação específica do item ou um erro. Não combine `kSecReturnData` com `kSecMatchLimitAll` para itens de senha.<sup>[[10]](#references)</sup> Um resultado `errSecItemNotFound` também pode indicar uma store incorreta, um filtro de sincronização ou a falta do entitlement do grupo de acesso, e não a ausência de uma credencial.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: "Arrombando o macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Nova versão do ladrão de macOS MacSync tem como alvo entusiastas de criptomoedas e desenvolvedores](https://securelist.com/macsync-new-version/121383/)
- [4] [Espelho da página man security(1) da Apple](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Sobre APIs e implementações do Keychain no Mac](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem: Fundamentos](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem: Armadilhas e práticas recomendadas](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Acessar itens do Keychain com Face ID ou Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
