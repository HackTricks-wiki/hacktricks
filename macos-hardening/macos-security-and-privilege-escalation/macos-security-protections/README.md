## Gatekeeper

**Gatekeeper** é um recurso de segurança desenvolvido para sistemas operacionais Mac, projetado para garantir que os usuários executem apenas software confiável em seus sistemas. Ele funciona **validando o software** que um usuário baixa e tenta abrir de **fontes fora da App Store**, como um aplicativo, um plug-in ou um pacote de instalação.

O mecanismo chave do Gatekeeper reside em seu processo de **verificação**. Ele verifica se o software baixado é **assinado por um desenvolvedor reconhecido**, garantindo a autenticidade do software. Além disso, ele verifica se o software é **notarizado pela Apple**, confirmando que ele está livre de conteúdo malicioso conhecido e não foi adulterado após a notarização.

Além disso, o Gatekeeper reforça o controle e a segurança do usuário, **solicitando que os usuários aprovem a abertura** do software baixado pela primeira vez. Esse recurso ajuda a evitar que os usuários executem inadvertidamente código executável potencialmente prejudicial que possam ter confundido com um arquivo de dados inofensivo.
```bash
# Check the status
spctl --status
# Enable Gatekeeper
sudo spctl --master-enable
# Disable Gatekeeper
sudo spctl --master-disable
```
### Assinaturas de Aplicativos

As assinaturas de aplicativos, também conhecidas como assinaturas de código, são um componente crítico da infraestrutura de segurança da Apple. Elas são usadas para **verificar a identidade do autor do software** (o desenvolvedor) e garantir que o código não tenha sido adulterado desde a última vez que foi assinado.

Veja como funciona:

1. **Assinando o Aplicativo:** Quando um desenvolvedor está pronto para distribuir seu aplicativo, ele **o assina usando uma chave privada**. Essa chave privada está associada a um **certificado que a Apple emite para o desenvolvedor** quando ele se inscreve no Programa de Desenvolvedores da Apple. O processo de assinatura envolve a criação de um hash criptográfico de todas as partes do aplicativo e a criptografia desse hash com a chave privada do desenvolvedor.
2. **Distribuindo o Aplicativo:** O aplicativo assinado é então distribuído aos usuários juntamente com o certificado do desenvolvedor, que contém a chave pública correspondente.
3. **Verificando o Aplicativo:** Quando um usuário faz o download e tenta executar o aplicativo, o sistema operacional Mac usa a chave pública do certificado do desenvolvedor para descriptografar o hash. Ele então recalcula o hash com base no estado atual do aplicativo e compara isso com o hash descriptografado. Se eles corresponderem, significa que **o aplicativo não foi modificado** desde que o desenvolvedor o assinou, e o sistema permite que o aplicativo seja executado.

As assinaturas de aplicativos são uma parte essencial da tecnologia Gatekeeper da Apple. Quando um usuário tenta **abrir um aplicativo baixado da internet**, o Gatekeeper verifica a assinatura do aplicativo. Se ele for assinado com um certificado emitido pela Apple para um desenvolvedor conhecido e o código não foi adulterado, o Gatekeeper permite que o aplicativo seja executado. Caso contrário, ele bloqueia o aplicativo e alerta o usuário.

A partir do macOS Catalina, **o Gatekeeper também verifica se o aplicativo foi notarizado** pela Apple, adicionando uma camada extra de segurança. O processo de notarização verifica o aplicativo em busca de problemas de segurança conhecidos e código malicioso, e se essas verificações passarem, a Apple adiciona um ticket ao aplicativo que o Gatekeeper pode verificar.

#### Verificar Assinaturas

Ao verificar alguma **amostra de malware**, você sempre deve **verificar a assinatura** do binário, pois o **desenvolvedor** que o assinou pode estar **relacionado** com **malware**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarização

O processo de notarização da Apple serve como uma salvaguarda adicional para proteger os usuários de softwares potencialmente prejudiciais. Ele envolve o **desenvolvedor submeter sua aplicação para exame** pelo **Serviço de Notarização da Apple**, que não deve ser confundido com a Revisão de Aplicativos. Este serviço é um **sistema automatizado** que examina o software enviado em busca de **conteúdo malicioso** e quaisquer problemas potenciais com a assinatura de código.

Se o software **passar** nesta inspeção sem levantar preocupações, o Serviço de Notarização gera um bilhete de notarização. O desenvolvedor é então obrigado a **anexar este bilhete ao seu software**, um processo conhecido como 'grampeamento'. Além disso, o bilhete de notarização também é publicado online onde o Gatekeeper, a tecnologia de segurança da Apple, pode acessá-lo.

Na primeira instalação ou execução do software pelo usuário, a existência do bilhete de notarização - seja grampeado ao executável ou encontrado online - **informa o Gatekeeper que o software foi notarizado pela Apple**. Como resultado, o Gatekeeper exibe uma mensagem descritiva no diálogo de lançamento inicial, indicando que o software passou por verificações de conteúdo malicioso pela Apple. Este processo, portanto, aumenta a confiança do usuário na segurança do software que eles instalam ou executam em seus sistemas.

### Arquivos em Quarentena

Ao **baixar** um aplicativo ou arquivo, aplicativos específicos do macOS, como navegadores da web ou clientes de e-mail, **anexam um atributo de arquivo estendido**, comumente conhecido como "**sinalizador de quarentena**", ao arquivo baixado. Este atributo atua como uma medida de segurança para **marcar o arquivo** como proveniente de uma fonte não confiável (a internet) e potencialmente carregando riscos. No entanto, nem todos os aplicativos anexam este atributo, por exemplo, o software comum de cliente BitTorrent geralmente ignora este processo.

**A presença de um sinalizador de quarentena sinaliza a funcionalidade de segurança do Gatekeeper do macOS quando um usuário tenta executar o arquivo**.

No caso em que o **sinalizador de quarentena não está presente** (como em arquivos baixados via alguns clientes BitTorrent), as verificações do Gatekeeper **podem não ser realizadas**. Assim, os usuários devem ter cuidado ao abrir arquivos baixados de fontes menos seguras ou desconhecidas.

{% hint style="info" %}
**Verificar** a **validade** das assinaturas de código é um processo **intensivo em recursos** que inclui a geração de **hashes criptográficos** do código e de todos os seus recursos agrupados. Além disso, verificar a validade do certificado envolve fazer uma **verificação online** nos servidores da Apple para ver se ele foi revogado após ter sido emitido. Por essas razões, uma verificação completa de assinatura de código e notarização é **impraticável de ser executada toda vez que um aplicativo é lançado**.

Portanto, essas verificações são **executadas apenas ao executar aplicativos com o atributo de quarentena**.
{% endhint %}

{% hint style="warning" %}
**Observe que o Safari e outros navegadores da web e aplicativos são os que precisam marcar os arquivos baixados**

Além disso, **os arquivos criados por processos em sandbox** também recebem este atributo para evitar a fuga da sandbox.
{% endhint %}

É possível **verificar seu status e habilitar/desabilitar** (necessário acesso root) com:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Você também pode **encontrar se um arquivo tem o atributo de quarentena estendido** com:
```bash
xattr portada.png
com.apple.macl
com.apple.quarantine
```
Verifique o **valor** dos **atributos estendidos** com:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 0081;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
```
E **remova** esse atributo com:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
E encontre todos os arquivos em quarentena com:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
## XProtect

XProtect é um recurso **anti-malware** integrado no macOS. Ele faz parte do sistema de segurança da Apple que trabalha silenciosamente em segundo plano para manter seu Mac seguro contra malware conhecido e plug-ins maliciosos.

O XProtect funciona **verificando qualquer arquivo baixado em seu banco de dados** de malware conhecido e tipos de arquivo inseguros. Quando você baixa um arquivo por meio de determinados aplicativos, como Safari, Mail ou Mensagens, o XProtect verifica automaticamente o arquivo. Se ele corresponder a algum malware conhecido em seu banco de dados, o XProtect **impedirá que o arquivo seja executado** e o alertará sobre a ameaça.

O banco de dados do XProtect é **atualizado regularmente** pela Apple com novas definições de malware, e essas atualizações são baixadas e instaladas automaticamente em seu Mac. Isso garante que o XProtect esteja sempre atualizado com as últimas ameaças conhecidas.

No entanto, vale ressaltar que o **XProtect não é uma solução antivírus completa**. Ele verifica apenas uma lista específica de ameaças conhecidas e não realiza a verificação de acesso como a maioria dos softwares antivírus. Portanto, embora o XProtect forneça uma camada de proteção contra malware conhecido, ainda é recomendável ter cuidado ao baixar arquivos da internet ou abrir anexos de e-mail.

Você pode obter informações sobre a última atualização do XProtect em execução:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
## MRT - Ferramenta de Remoção de Malware

A Ferramenta de Remoção de Malware (MRT) é outra parte da infraestrutura de segurança do macOS. Como o nome sugere, a principal função do MRT é **remover malware conhecido de sistemas infectados**.

Uma vez que o malware é detectado em um Mac (seja pelo XProtect ou por outros meios), o MRT pode ser usado para **remover automaticamente o malware**. O MRT opera silenciosamente em segundo plano e geralmente é executado sempre que o sistema é atualizado ou quando uma nova definição de malware é baixada (parece que as regras que o MRT tem para detectar malware estão dentro do binário).

Embora tanto o XProtect quanto o MRT façam parte das medidas de segurança do macOS, eles desempenham funções diferentes:

* **XProtect** é uma ferramenta preventiva. Ele **verifica arquivos conforme são baixados** (por meio de determinados aplicativos) e, se detectar algum tipo conhecido de malware, **impede que o arquivo seja aberto**, evitando assim que o malware infecte o sistema em primeiro lugar.
* **MRT**, por outro lado, é uma **ferramenta reativa**. Ele opera depois que o malware foi detectado em um sistema, com o objetivo de remover o software ofensivo para limpar o sistema.

## Limitantes de Processos

### SIP - Proteção de Integridade do Sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

O Sandbox do macOS **limita as aplicações** que rodam dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o aplicativo está sendo executado. Isso ajuda a garantir que **a aplicação acesse apenas os recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - Transparência, Consentimento e Controle

**TCC (Transparência, Consentimento e Controle)** é um mecanismo no macOS para **limitar e controlar o acesso do aplicativo a determinados recursos**, geralmente do ponto de vista da privacidade. Isso pode incluir coisas como serviços de localização, contatos, fotos, microfone, câmera, acessibilidade, acesso total ao disco e muito mais.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
