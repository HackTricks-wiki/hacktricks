# macOS Keychain

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Principais Keychains

* O **User Keychain** (`~/Library/Keychains/login.keycahin-db`), que é usado para armazenar **credenciais específicas do usuário** como senhas de aplicativos, senhas de internet, certificados gerados pelo usuário, senhas de rede e chaves públicas/privadas geradas pelo usuário.
* O **System Keychain** (`/Library/Keychains/System.keychain`), que armazena **credenciais em todo o sistema** como senhas WiFi, certificados raiz do sistema, chaves privadas do sistema e senhas de aplicativos do sistema.

### Acesso à Senha do Keychain

Esses arquivos, embora não tenham proteção inerente e possam ser **baixados**, são criptografados e exigem a **senha em texto simples do usuário para serem descriptografados**. Uma ferramenta como [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pode ser usada para descriptografar.

## Proteções de Entradas do Keychain

### ACLs

Cada entrada no keychain é governada por **Listas de Controle de Acesso (ACLs)** que ditam quem pode executar várias ações na entrada do keychain, incluindo:

* **ACLAuhtorizationExportClear**: Permite que o detentor obtenha o texto claro do segredo.
* **ACLAuhtorizationExportWrapped**: Permite que o detentor obtenha o texto claro criptografado com outra senha fornecida.
* **ACLAuhtorizationAny**: Permite que o detentor execute qualquer ação.

As ACLs são acompanhadas por uma **lista de aplicativos confiáveis** que podem executar essas ações sem solicitação. Isso pode ser:

* &#x20;**N`il`** (nenhuma autorização necessária, **todos são confiáveis**)
* Uma lista **vazia** (**ninguém** é confiável)
* **Lista** de **aplicativos** específicos.

Além disso, a entrada pode conter a chave **`ACLAuthorizationPartitionID`**, que é usada para identificar o **teamid, apple** e **cdhash.**

* Se o **teamid** for especificado, então para **acessar o valor da entrada** sem uma **solicitação**, o aplicativo usado deve ter o **mesmo teamid**.
* Se a **apple** for especificada, o aplicativo precisa ser **assinado** pela **Apple**.
* Se o **cdhash** for indicado, o **aplicativo** deve ter o **cdhash** específico.

### Criando uma Entrada do Keychain

Quando uma **nova entrada** é criada usando o **`Keychain Access.app`**, as seguintes regras se aplicam:

* Todos os aplicativos podem criptografar.
* **Nenhum aplicativo** pode exportar/descriptografar (sem solicitar ao usuário).
* Todos os aplicativos podem ver a verificação de integridade.
* Nenhum aplicativo pode alterar as ACLs.
* O **partitionID** é definido como **`apple`**.

Quando um **aplicativo cria uma entrada no keychain**, as regras são um pouco diferentes:

* Todos os aplicativos podem criptografar.
* Somente o **aplicativo criador** (ou qualquer outro aplicativo adicionado explicitamente) pode exportar/descriptografar (sem solicitar ao usuário).
* Todos os aplicativos podem ver a verificação de integridade.
* Nenhum aplicativo pode alterar as ACLs.
* O **partitionID** é definido como **`teamid:[teamID aqui]`**.

## Acessando o Keychain

### `security`
```bash
# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S
```
### APIs

{% hint style="success" %}
A enumeração e o dumping do **keychain** de segredos que **não geram um prompt** podem ser feitos com a ferramenta [**LockSmith**](https://github.com/its-a-feature/LockSmith)
{% endhint %}

Liste e obtenha **informações** sobre cada entrada do keychain:

* A API **`SecItemCopyMatching`** fornece informações sobre cada entrada e existem alguns atributos que você pode definir ao usá-la:
  * **`kSecReturnData`**: Se verdadeiro, tentará descriptografar os dados (defina como falso para evitar possíveis pop-ups)
  * **`kSecReturnRef`**: Obtenha também a referência ao item do keychain (defina como verdadeiro no caso de você ver que pode descriptografar sem pop-up)
  * **`kSecReturnAttributes`**: Obtenha metadados sobre as entradas
  * **`kSecMatchLimit`**: Quantos resultados retornar
  * **`kSecClass`**: Que tipo de entrada do keychain

Obtenha as **ACLs** de cada entrada:

* Com a API **`SecAccessCopyACLList`** você pode obter a **ACL para o item do keychain**, e ela retornará uma lista de ACLs (como `ACLAuhtorizationExportClear` e as outras mencionadas anteriormente) onde cada lista tem:
  * Descrição
  * **Lista de aplicativos confiáveis**. Isso pode ser:
    * Um aplicativo: /Applications/Slack.app
    * Um binário: /usr/libexec/airportd
    * Um grupo: group://AirPort

Exporte os dados:

* A API **`SecKeychainItemCopyContent`** obtém o texto simples
* A API **`SecItemExport`** exporta as chaves e certificados, mas pode ser necessário definir senhas para exportar o conteúdo criptografado

E estes são os **requisitos** para poder **exportar um segredo sem um prompt**:

* Se **1 ou mais aplicativos confiáveis** estiverem listados:
  * Precisa das **autorizações** apropriadas (**`Nil`**, ou ser **parte** da lista permitida de aplicativos na autorização para acessar as informações secretas)
  * Precisa que a assinatura do código corresponda ao **PartitionID**
  * Precisa que a assinatura do código corresponda à de um **aplicativo confiável** (ou ser um membro do grupo KeychainAccessGroup correto)
* Se **todos os aplicativos são confiáveis**:
  * Precisa das **autorizações** apropriadas
  * Precisa que a assinatura do código corresponda ao **PartitionID**
    * Se **não houver PartitionID**, isso não é necessário

{% hint style="danger" %}
Portanto, se houver **1 aplicativo listado**, você precisará **injetar código nesse aplicativo**.

Se a **apple** for indicada no **partitionID**, você pode acessá-la com **`osascript`** para qualquer coisa que esteja confiando em todos os aplicativos com apple no partitionID. **`Python`** também pode ser usado para isso.
{% endhint %}

### Dois atributos adicionais

* **Invisível**: É uma sinalização booleana para **ocultar** a entrada do aplicativo **UI** Keychain
* **Geral**: É para armazenar **metadados** (portanto, NÃO É CRIPTOGRAFADO)
  * A Microsoft estava armazenando em texto simples todos os tokens de atualização para acessar pontos de extremidade sensíveis.

## Referências

* [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenha o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas dicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
