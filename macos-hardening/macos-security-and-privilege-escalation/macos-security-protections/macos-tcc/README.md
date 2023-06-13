## **Informações Básicas**

O **TCC (Transparência, Consentimento e Controle)** é um mecanismo no macOS para **limitar e controlar o acesso do aplicativo a determinados recursos**, geralmente do ponto de vista da privacidade. Isso pode incluir coisas como serviços de localização, contatos, fotos, microfone, câmera, acessibilidade, acesso total ao disco e muito mais.

Do ponto de vista do usuário, eles veem o TCC em ação **quando um aplicativo deseja acessar um dos recursos protegidos pelo TCC**. Quando isso acontece, o **usuário é solicitado** com uma caixa de diálogo perguntando se eles desejam permitir o acesso ou não.

Também é possível **conceder acesso a aplicativos** a arquivos por **intenções explícitas** dos usuários, por exemplo, quando um usuário **arrasta e solta um arquivo em um programa** (obviamente, o programa deve ter acesso a ele).

![Um exemplo de uma solicitação TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** é tratado pelo **daemon** localizado em `/System/Library/PrivateFrameworks/TCC.framework/Resources/tccd` configurado em `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registrando o serviço mach `com.apple.tccd.system`).

Existe um **tccd de modo de usuário** em execução por usuário conectado definido em `/System/Library/LaunchAgents/com.apple.tccd.plist` registrando os serviços mach `com.apple.tccd` e `com.apple.usernotifications.delegate.com.apple.tccd`.

As permissões são **herdadas do aplicativo pai** e as **permissões** são **rastreadas** com base no **ID do pacote** e no **ID do desenvolvedor**.

### Banco de Dados TCC

As seleções são então armazenadas no banco de dados do sistema TCC em **`/Library/Application Support/com.apple.TCC/TCC.db`** ou em **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** para preferências por usuário. O banco de dados é **protegido contra edição com SIP** (Proteção de Integridade do Sistema), mas você pode lê-los concedendo **acesso total ao disco**.

{% hint style="info" %}
A **interface do centro de notificação** pode fazer **alterações no banco de dados do TCC do sistema**:

{% code overflow="wrap" %}
```bash
codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
[..]
com.apple.private.tcc.manager
com.apple.rootless.storage.TCC
```
No entanto, os usuários podem **excluir ou consultar regras** com o utilitário de linha de comando **`tccutil`**. 
{% endhint %}

{% tabs %}
{% tab title="user DB" %}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}

{% tab title="macOS TCC" %}
# Proteções de segurança do macOS: Controle de Acesso ao TCC

O Controle de Acesso ao TCC (TCC, na sigla em inglês) é um recurso de segurança do macOS que controla o acesso de aplicativos a recursos protegidos, como a câmera, o microfone, a localização e os contatos. O TCC é implementado pelo `tccd`, um daemon do sistema que é executado em segundo plano e gerencia as solicitações de acesso do aplicativo.

O TCC é uma parte importante do modelo de segurança do macOS, pois ajuda a proteger a privacidade do usuário e a impedir que aplicativos mal-intencionados acessem informações confidenciais. No entanto, o TCC não é infalível e pode ser contornado por aplicativos mal-intencionados que exploram vulnerabilidades no sistema ou usam técnicas de engenharia social para enganar o usuário.

Este diretório contém informações e ferramentas relacionadas ao TCC, incluindo:

- **tccutil.py**: uma ferramenta Python que permite visualizar e modificar as configurações do TCC.
- **tcc.db**: um arquivo SQLite que contém as configurações do TCC para cada usuário do sistema.
- **tcc_profiles.md**: uma lista de perfis TCC comuns e suas configurações padrão.
- **tcc_vulnerabilities.md**: uma lista de vulnerabilidades conhecidas do TCC e técnicas de contorno.

## Referências

- [Controle de Acesso ao TCC](https://developer.apple.com/documentation/security/tcc)
- [Proteções de segurança do macOS](https://support.apple.com/pt-br/guide/mac-help/sec14fef8a3b/mac)
- [Explorando o TCC para obter acesso a recursos protegidos no macOS](https://objective-see.com/blog/blog_0x4D.html)
- [Explorando o TCC para obter acesso a recursos protegidos no macOS: parte 2](https://objective-see.com/blog/blog_0x4E.html)
- [Explorando o TCC para obter acesso a recursos protegidos no macOS: parte 3](https://objective-see.com/blog/blog_0x4F.html)
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{% endtab %}
{% endtabs %}

{% hint style="success" %}
Ao verificar ambos os bancos de dados, você pode verificar as permissões que um aplicativo permitiu, proibiu ou não tem (ele pedirá).
{% endhint %}

* O **`auth_value`** pode ter valores diferentes: negado(0), desconhecido(1), permitido(2) ou limitado(3).
* O **`auth_reason`** pode ter os seguintes valores: Erro(1), Consentimento do usuário(2), Configuração do usuário(3), Configuração do sistema(4), Política de serviço(5), Política MDM(6), Política de substituição(7), String de uso ausente(8), Tempo limite de prompt(9), Preflight desconhecido(10), Com direito(11), Política de tipo de aplicativo(12).
* Para obter mais informações sobre os **outros campos** da tabela, [**verifique esta postagem no blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

{% hint style="info" %}
Algumas permissões do TCC são: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Não há uma lista pública que defina todas elas, mas você pode verificar esta [**lista de conhecidas**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).
{% endhint %}

Você também pode verificar as **permissões já concedidas** aos aplicativos em `Preferências do Sistema --> Segurança e Privacidade --> Privacidade --> Arquivos e Pastas`.

### Verificações de assinatura do TCC

O **banco de dados** do TCC armazena o **ID do pacote** do aplicativo, mas também **armazena informações** sobre a **assinatura** para **garantir** que o aplicativo que solicita o uso de uma permissão seja o correto. 

{% code overflow="wrap" %}
```bash
# From sqlite
sqlite> select hex(csreq) from access where client="ru.keepcoder.Telegram";
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"

```
{% endcode %}

### Entitlements

Os aplicativos **não apenas precisam** solicitar e ter sido **concedido acesso** a alguns recursos, eles também precisam **ter as permissões relevantes**.\
Por exemplo, o **Telegram** tem a permissão `com.apple.security.device.camera` para solicitar **acesso à câmera**. Um **aplicativo** que **não tenha** essa **permissão não poderá** acessar a câmera (e o usuário nem mesmo será solicitado a conceder as permissões).

No entanto, para que os aplicativos tenham **acesso** a **certas pastas do usuário**, como `~/Desktop`, `~/Downloads` e `~/Documents`, eles **não precisam** ter nenhuma **permissão específica**. O sistema lidará com o acesso de forma transparente e **solicitará permissão ao usuário** conforme necessário.

Os aplicativos da Apple **não gerarão prompts**. Eles contêm **direitos pré-concedidos** em sua lista de **permissões**, o que significa que eles **nunca gerarão um pop-up**, **nem** aparecerão em nenhum dos **bancos de dados do TCC**. Por exemplo:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```
Isso evitará que o Calendário solicite ao usuário acesso a lembretes, calendário e lista de endereços.

### Locais sensíveis desprotegidos

* $HOME (ele mesmo)
* $HOME/.ssh, $HOME/.aws, etc
* /tmp

### Intenção do usuário / com.apple.macl

Como mencionado anteriormente, é possível **conceder acesso a um aplicativo a um arquivo arrastando-o e soltando-o nele**. Esse acesso não será especificado em nenhum banco de dados TCC, mas como um **atributo estendido do arquivo**. Esse atributo irá **armazenar o UUID** do aplicativo permitido:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
{% hint style="info" %}
É curioso que o atributo **`com.apple.macl`** seja gerenciado pelo **Sandbox**, e não pelo tccd
{% endhint %}

O atributo estendido `com.apple.macl` **não pode ser apagado** como outros atributos estendidos, pois ele é **protegido pelo SIP**. No entanto, como [**explicado neste post**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), é possível desabilitá-lo **compactando** o arquivo, **apagando-o** e **descompactando-o**.

## Referências

* [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
