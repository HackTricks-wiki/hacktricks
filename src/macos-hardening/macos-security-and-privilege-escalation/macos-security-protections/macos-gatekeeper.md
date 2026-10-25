# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** é um recurso de segurança desenvolvido para os sistemas operacionais Mac, projetado para garantir que os usuários **executem apenas software confiável** em seus sistemas. Ele funciona **validando o software** que o usuário baixa e tenta abrir de **fontes externas à App Store**, como um app, um plug-in ou um pacote de instalação.

O principal mecanismo do Gatekeeper está em seu processo de **verificação**. Ele verifica se o software baixado está **assinado por um desenvolvedor reconhecido**, garantindo sua autenticidade. Além disso, verifica se o software foi **notarizado pela Apple**, confirmando que não contém conteúdo malicioso conhecido e não foi adulterado após a notarização.

Além disso, o Gatekeeper reforça o controle do usuário e a segurança ao **solicitar que os usuários aprovem a abertura** do software baixado na primeira vez. Essa proteção ajuda a evitar que os usuários executem inadvertidamente código executável potencialmente prejudicial que possam ter confundido com um arquivo de dados inofensivo.

### Assinaturas de Aplicativos

As assinaturas de aplicativos, também conhecidas como assinaturas de código, são um componente essencial da infraestrutura de segurança da Apple. Elas são usadas para **verificar a identidade do autor do software** (o desenvolvedor) e garantir que o código não tenha sido adulterado desde a última assinatura.

Veja como funciona:

1. **Assinatura do Aplicativo:** Quando um desenvolvedor está pronto para distribuir seu aplicativo, ele **assina o aplicativo usando uma chave privada**. Essa chave privada está associada a um **certificado que a Apple emite para o desenvolvedor** quando ele se inscreve no Apple Developer Program. O processo de assinatura envolve criar um hash criptográfico de todas as partes do app e criptografar esse hash com a chave privada do desenvolvedor.
2. **Distribuição do Aplicativo:** O aplicativo assinado é então distribuído aos usuários junto com o certificado do desenvolvedor, que contém a chave pública correspondente.
3. **Verificação do Aplicativo:** Quando um usuário baixa e tenta executar o aplicativo, o sistema operacional Mac usa a chave pública do certificado do desenvolvedor para descriptografar o hash. Em seguida, recalcula o hash com base no estado atual do aplicativo e o compara com o hash descriptografado. Se forem iguais, isso significa que **o aplicativo não foi modificado** desde que o desenvolvedor o assinou, e o sistema permite que ele seja executado.

As assinaturas de aplicativos são uma parte essencial da tecnologia Gatekeeper da Apple. Quando um usuário tenta **abrir um aplicativo baixado da internet**, o Gatekeeper verifica a assinatura do aplicativo. Se ele estiver assinado com um certificado emitido pela Apple para um desenvolvedor conhecido e o código não tiver sido adulterado, o Gatekeeper permite que o aplicativo seja executado. Caso contrário, ele bloqueia o aplicativo e alerta o usuário.

A partir do macOS Catalina, o **Gatekeeper também verifica se o aplicativo foi notarizado** pela Apple, adicionando uma camada extra de segurança. O processo de notarização verifica se há problemas de segurança conhecidos e código malicioso no aplicativo e, se essas verificações forem aprovadas, a Apple adiciona um ticket ao aplicativo que o Gatekeeper pode verificar.

#### Verificar Assinaturas

Ao verificar uma **amostra de malware**, você deve sempre **verificar a assinatura** do binário, pois o **desenvolvedor** que o assinou pode já estar **relacionado** a **malware**.

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

O processo de notarização da Apple serve como uma proteção adicional para proteger os usuários de softwares potencialmente nocivos. Ele envolve o **desenvolvedor enviar seu aplicativo para análise** pelo **Apple's Notary Service**, que não deve ser confundido com o App Review. Esse serviço é um **sistema automatizado** que examina o software enviado em busca de **conteúdo malicioso** e de possíveis problemas com a assinatura de código.

Se o software **passar** por essa análise sem levantar preocupações, o Notary Service gera um ticket de notarização. Em seguida, o desenvolvedor precisa **anexar esse ticket ao software**, um processo conhecido como “stapling”. Além disso, o ticket de notarização também é publicado online, onde o Gatekeeper, a tecnologia de segurança da Apple, pode acessá-lo.

Na primeira instalação ou execução do software pelo usuário, a existência do ticket de notarização — anexado ao executável ou encontrado online — **informa ao Gatekeeper que o software foi notarizado pela Apple**. Como resultado, o Gatekeeper exibe uma mensagem descritiva na caixa de diálogo de inicialização, indicando que a Apple verificou o software em busca de conteúdo malicioso. Assim, esse processo aumenta a confiança dos usuários na segurança do software que instalam ou executam em seus sistemas.

### spctl & syspolicyd

> [!CAUTION]
> Observe que, a partir da versão Sequoia, **`spctl`** não permite mais modificar a configuração do Gatekeeper.

**`spctl`** é a ferramenta CLI para enumerar e interagir com o Gatekeeper (com o daemon `syspolicyd` por meio de mensagens XPC). Por exemplo, é possível ver o **status** do GateKeeper com:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Observe que as verificações de assinatura do GateKeeper são realizadas apenas em **arquivos com o atributo Quarantine**, não em todos os arquivos.

O GateKeeper verifica se, de acordo com as **preferências e a assinatura**, um binário pode ser executado:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** é o principal daemon responsável por aplicar o Gatekeeper. Ele mantém um banco de dados localizado em `/var/db/SystemPolicy`, e é possível encontrar o código de suporte para o [banco de dados aqui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e o [modelo SQL aqui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Observe que o banco de dados não é restringido pelo SIP e pode ser gravado pelo root; o banco de dados `/var/db/.SystemPolicy-default` é usado como backup original caso o outro seja corrompido.

Além disso, os bundles **`/var/db/gke.bundle`** e **`/var/db/gkopaque.bundle`** contêm arquivos com regras que são inseridas no banco de dados. Você pode consultar esse banco de dados como root com:

```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```

**`syspolicyd`** também expõe um servidor XPC com diferentes operações, como `assess`, `update`, `record` e `cancel`, que também podem ser acessadas usando as APIs **`SecAssessment*`** do **`Security.framework`**. Na verdade, o **`spctl`** se comunica com o **`syspolicyd`** via XPC.

Observe que a primeira regra terminava em "**App Store**" e a segunda em "**Developer ID**" e que, na imagem anterior, era possível executar apps da App Store e de desenvolvedores identificados.\
Se você **modificar** essa configuração para App Store, as regras de "**Developer ID Notarizado" desaparecerão**.

Há também milhares de regras do **tipo GKE** :

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Estes são hashes provenientes de:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ou você poderia listar as informações anteriores com:

```bash
sudo spctl --list
```

As opções **`--master-disable`** e **`--global-disable`** do **`spctl`** **desativam** completamente essas verificações de assinatura:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Quando estiver totalmente ativada, uma nova opção aparecerá:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

É possível **verificar se um app será permitido pelo GateKeeper** com:

```bash
spctl --assess -v /Applications/App.app
```

No macOS 14 e versões posteriores, **`syspolicy_check`** é uma verificação de nível mais alto útil antes de distribuir um pacote de aplicativo. Ela produz diagnósticos de execução confiável mais úteis do que um resultado simples do `spctl`, embora a Apple ainda recomende testar o fluxo real de download/extração/primeira inicialização, pois isso também verifica a propagação da quarentena.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```

É possível adicionar novas regras ao GateKeeper para permitir a execução de determinados aplicativos com:

```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```

Regarding **extensões de kernel**, a pasta `/var/db/SystemPolicyConfiguration` contém arquivos com listas de kexts que podem ser carregadas. Além disso, `spctl` tem o entitlement `com.apple.private.iokit.nvram-csr` porque é capaz de adicionar novas extensões de kernel pré-aprovadas, que também precisam ser salvas na NVRAM em uma chave `kext-allowed-teams`.

#### Gerenciando o Gatekeeper no macOS 15 (Sequoia) e posteriores

- O antigo bypass do Finder **Ctrl+Open / clique com o botão direito → Abrir** foi removido; após a primeira caixa de diálogo de bloqueio, os usuários precisam permitir explicitamente o app bloqueado em **Ajustes do Sistema → Privacidade e Segurança → Abrir Mesmo Assim**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` não são mais aceitos como alterações de política não assistidas. As operações que modificam o banco de dados de regras ou o estado global de avaliação foram descontinuadas; portanto, use `spctl` para avaliação e configure a aplicação da política pela interface ou pelo MDM.

A partir do macOS 15 Sequoia, os usuários finais não podem mais alternar a política do Gatekeeper pelo `spctl`. O gerenciamento é feito pelos Ajustes do Sistema ou pela implantação de um perfil de configuração MDM com o payload `com.apple.systempolicy.control`. Exemplo de trecho de perfil para permitir a App Store e desenvolvedores identificados (mas não “Qualquer lugar”):

<details>
<summary>Perfil MDM para permitir a App Store e desenvolvedores identificados</summary>

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.systempolicy.control</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.example.gatekeeper</string>
      <key>EnableAssessment</key>
      <true/>
      <key>AllowIdentifiedDevelopers</key>
      <true/>
    </dict>
  </array>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadIdentifier</key>
  <string>com.example.profile.gatekeeper</string>
  <key>PayloadUUID</key>
  <string>00000000-0000-0000-0000-000000000000</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadDisplayName</key>
  <string>Gatekeeper</string>
</dict>
</plist>
```

</details>

### Arquivos em Quarentena

Ao **baixar** um aplicativo ou arquivo, alguns **aplicativos** do macOS, como navegadores ou clientes de e-mail, **anexam um atributo de arquivo estendido**, conhecido como "**quarantine flag**", ao arquivo baixado. Esse atributo funciona como uma medida de segurança para **marcar o arquivo** como proveniente de uma fonte não confiável (a internet) e potencialmente arriscado. No entanto, nem todos os aplicativos anexam esse atributo; por exemplo, softwares comuns de clientes BitTorrent geralmente ignoram esse processo.

**A presença de uma quarantine flag sinaliza o recurso de segurança Gatekeeper do macOS quando um usuário tenta executar o arquivo**.

Se a **quarantine flag não estiver presente** (como ocorre com arquivos baixados por alguns clientes BitTorrent), as **verificações** do Gatekeeper podem não ser realizadas. Portanto, os usuários devem ter cuidado ao abrir arquivos baixados de fontes menos seguras ou desconhecidas.

> [!NOTE] > **Verificar** a **validade** das assinaturas de código é um processo **que consome muitos recursos**, que inclui gerar **hashes** criptográficos do código e de todos os recursos incluídos nele. Além disso, verificar a validade do certificado envolve fazer uma **verificação online** nos servidores da Apple para saber se ele foi revogado após sua emissão. Por esses motivos, é **impraticável executar uma verificação completa da assinatura de código e da notarização sempre que um aplicativo é iniciado**.
>
> Portanto, essas verificações são **executadas somente ao iniciar aplicativos com o atributo de quarentena**.

> [!WARNING]
> Esse atributo deve ser **definido pelo aplicativo que cria/baixa** o arquivo.
>
> No entanto, arquivos em sandbox terão esse atributo definido em todos os arquivos que criarem. Aplicativos que não estão em sandbox podem defini-lo por conta própria ou especificar a chave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) no **Info.plist**, o que fará com que o sistema defina o atributo estendido `com.apple.quarantine` nos arquivos criados.

Além disso, todos os arquivos criados por um processo que chama **`qtn_proc_apply_to_self`** são colocados em quarentena. A API **`qtn_file_apply_to_path`** também adiciona o atributo de quarentena ao caminho de arquivo especificado.

É possível **verificar o status e ativar/desativar** (requer root) com:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Você também pode **verificar se um arquivo tem o atributo estendido de quarantine** com:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Verifique o **valor** dos **atributos estendidos** e descubra qual app gravou o atributo `quarantine` com:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

Na verdade, um processo "poderia definir flags de quarentena nos arquivos que cria" (já tentei aplicar a flag USER_APPROVED a um arquivo criado, mas não funcionou):

<details>

<summary>Código-fonte: aplicar flags de quarentena</summary>

```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
    QTN_FLAG_DOWNLOAD = 0x0001,
    QTN_FLAG_SANDBOX = 0x0002,
    QTN_FLAG_HARD = 0x0004,
    QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

  qtn_proc_t qp = qtn_proc_alloc();
  qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
  qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
  qtn_proc_apply_to_self(qp);
  qtn_proc_free(qp);

  FILE *fp;
  fp = fopen("thisisquarantined.txt", "w+");
  fprintf(fp, "Hello Quarantine\n");
  fclose(fp);

  return 0;

}
```

</details>

E **remova** esse atributo com:

```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```

E encontre todos os arquivos em quarentena com:

```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```

As informações de quarantine também são armazenadas em um banco de dados central gerenciado pelo LaunchServices em **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, que permite à GUI obter dados sobre as origens dos arquivos. Além disso, esse banco de dados pode ser sobrescrito por aplicativos que talvez queiram ocultar suas origens. Isso também pode ser feito por meio das APIs do LaunchServices.

#### **libquarantine.dylib**

Esta biblioteca exporta várias funções que permitem manipular os campos de atributos estendidos.

As APIs `qtn_file_*` tratam das políticas de quarantine de arquivos; as APIs `qtn_proc_*` são aplicadas a processos (arquivos criados pelo processo). As funções não exportadas `__qtn_syscall_quarantine*` aplicam as políticas chamando `mac_syscall` com "Quarantine" como primeiro argumento, que envia as solicitações para `Quarantine.kext`.

#### **Quarantine.kext**

A extensão do kernel só está disponível no **kernel cache do sistema**; no entanto, você _pode_ baixar o **Kernel Debug Kit em** [**https://developer.apple.com/**](https://developer.apple.com/), que contém uma versão da extensão com símbolos.

Esta Kext usa hooks via MACF em várias chamadas para interceptar todos os eventos do ciclo de vida dos arquivos: criação, abertura, renomeação, criação de hard links... até `setxattr`, para impedir que defina o atributo estendido `com.apple.quarantine`.

Ela também usa alguns MIBs:

- `security.mac.qtn.sandbox_enforce`: Impõe quarantine junto com o Sandbox
- `security.mac.qtn.user_approved_exec`: processos em quarantine só podem executar arquivos aprovados

#### Provenance xattr (Ventura e posterior)

O macOS 13 Ventura introduziu um mecanismo de provenance separado, preenchido na primeira vez que um app em quarantine tem sua execução permitida.<sup>[[2]](#references)</sup> Dois artefatos são criados:

- O xattr `com.apple.provenance` no diretório do bundle `.app` (valor binário de tamanho fixo contendo uma chave primária e flags).
- Uma linha na tabela `provenance_tracking` dentro do banco de dados ExecPolicy em `/var/db/SystemPolicyConfiguration/ExecPolicy/`, que armazena o cdhash e os metadados do app.

Uso prático:

```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```

### XProtect

O XProtect é um recurso **anti-malware** integrado ao macOS. O XProtect **verifica qualquer aplicativo quando ele é iniciado pela primeira vez ou modificado, comparando-o com seu banco de dados** de malware conhecido e tipos de arquivo inseguros. Quando você baixa um arquivo por determinados aplicativos, como Safari, Mail ou Messages, o XProtect verifica o arquivo automaticamente. Se ele corresponder a algum malware conhecido em seu banco de dados, o XProtect **impedirá a execução do arquivo** e alertará você sobre a ameaça.

A Apple **atualiza regularmente** o banco de dados do XProtect com novas definições de malware, e essas atualizações são baixadas e instaladas automaticamente no Mac. Isso garante que o XProtect esteja sempre atualizado com as ameaças conhecidas mais recentes.

No entanto, vale observar que **o XProtect não é uma solução antivírus completa**. Ele verifica apenas uma lista específica de ameaças conhecidas e não realiza varredura em tempo real, como a maioria dos softwares antivírus.

Você pode obter informações sobre a atualização mais recente do XProtect executando:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect está localizado em um local protegido pelo SIP: **/Library/Apple/System/Library/CoreServices/XProtect.bundle**. Dentro do bundle, você encontra informações usadas pelo XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que código com esses cdhashes use legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista plugins e extensões cujo carregamento é proibido por BundleID e TeamID, ou indica uma versão mínima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regras Yara para detectar malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Banco de dados SQLite3 com hashes de aplicativos bloqueados e TeamIDs.

Observe que há outro app em **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionado ao XProtect, que não está envolvido no processo do Gatekeeper.

> XProtect Remediator: Nas versões modernas do macOS, a Apple fornece scanners sob demanda (XProtect Remediator) que são executados periodicamente via launchd para detectar e remediar famílias de malware. Você pode observar essas verificações nos logs unificados:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Não é o Gatekeeper

> [!CAUTION]
> Observe que o Gatekeeper **não é executado sempre** que você executa um aplicativo; apenas o _**AppleMobileFileIntegrity**_ (AMFI) **verifica as assinaturas do código executável** quando você executa um app que já foi executado e verificado pelo Gatekeeper.

Portanto, antes era possível executar um app para armazená-lo em cache pelo Gatekeeper e, em seguida, **modificar arquivos não executáveis do aplicativo** (como arquivos asar ou NIB do Electron). Se nenhuma outra proteção estivesse em vigor, o aplicativo seria **executado** com as adições **maliciosas**.

No entanto, agora isso não é possível porque o macOS **impede a modificação de arquivos** dentro de bundles de aplicativos. Portanto, se você tentar o ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), verá que não é mais possível explorá-lo: depois de executar o app para armazená-lo em cache pelo Gatekeeper, você não poderá modificar o bundle. E se você, por exemplo, alterar o nome do diretório Contents para NotCon (conforme indicado no exploit) e, em seguida, executar o binário principal do app para armazená-lo em cache pelo Gatekeeper, isso acionará um erro e o app não será executado.

## Bypasses do Gatekeeper

Qualquer forma de contornar o Gatekeeper (fazer com que o usuário baixe algo e execute quando o Gatekeeper deveria impedir) é considerada uma vulnerabilidade no macOS. Estes são alguns CVEs atribuídos a técnicas que permitiram contornar o Gatekeeper no passado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Foi observado que, quando o **Archive Utility** é usado para extrair arquivos, arquivos com **caminhos que excedem 886 caracteres** não recebem o atributo estendido com.apple.quarantine. Essa situação permite inadvertidamente que esses arquivos **contornem** as verificações de segurança do Gatekeeper.<sup>[[5]](#references)</sup>

Consulte o [**relatório original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para obter mais informações.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando um aplicativo é criado com o **Automator**, as informações sobre o que ele precisa executar ficam em `application.app/Contents/document.wflow`, e não no executável. O executável é apenas um binário genérico do Automator chamado **Automator Application Stub**.

Portanto, você poderia fazer com que `application.app/Contents/MacOS/Automator\ Application\ Stub` **apontasse, por meio de um link simbólico, para outro Automator Application Stub no sistema**; ele executaria o conteúdo de `document.wflow` (seu script) **sem acionar o Gatekeeper**, pois o executável real não tem o xattr de quarentena.<sup>[[6]](#references)</sup>

Exemplo do local esperado: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulte o [**relatório original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para obter mais informações.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Nesse bypass, foi criado um arquivo zip com um aplicativo cuja compactação começava em `application.app/Contents`, em vez de `application.app`. Portanto, o **atributo de quarentena** foi aplicado a todos os **arquivos de `application.app/Contents`**, mas **não a `application.app`**, que era o que o Gatekeeper verificava. Assim, o Gatekeeper foi contornado porque, quando `application.app` era acionado, **não tinha o atributo de quarentena.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Consulte o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para obter mais informações.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Mesmo que os componentes sejam diferentes, a exploração desta vulnerabilidade é muito semelhante à anterior. Neste caso, vamos gerar um Apple Archive a partir de **`application.app/Contents`**, para que **`application.app` não receba o atributo quarantine** quando for descompactado pelo **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Consulte o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para obter mais informações.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

A ACL **`writeextattr`** pode ser usada para impedir que qualquer pessoa grave um atributo em um arquivo:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Além disso, o formato de arquivo **AppleDouble** copia um arquivo incluindo seus ACEs.<sup>[[9]](#references)</sup>

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), é possível ver que a representação de texto da ACL armazenada no xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descompactado. Portanto, se você compactar um aplicativo em um arquivo zip usando o formato de arquivo **AppleDouble** com uma ACL que impede a gravação de outros xattrs nele... o xattr quarantine não será definido no aplicativo:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Consulte o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para mais informações.<sup>[[9]](#references)</sup> Consulte a [reprodução de AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md) para ver as etapas de criação e validação do arquivo sidecar.

Observe que isso também poderia ser explorado com AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Foi descoberto que o **Google Chrome não definia o atributo de quarentena** nos arquivos baixados devido a alguns problemas internos do macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

O AppleDouble armazena os atributos de um arquivo em um arquivo separado cujo nome começa com `._`; isso ajuda a copiar atributos **entre máquinas macOS**. No entanto, após descompactar um arquivo AppleDouble, o arquivo cujo nome começava com `._` **não recebia o atributo de quarentena**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Como era possível criar um arquivo sem o atributo de quarentena, **era possível contornar o Gatekeeper.** O truque consistia em **criar um arquivo de aplicativo DMG** usando a convenção de nomes AppleDouble (começando com `._`) e criar um **arquivo visível como um link simbólico para esse arquivo oculto** sem o atributo de quarentena.\
Quando o **arquivo DMG é executado**, como não tem um atributo de quarentena, ele **contorna o Gatekeeper**.

```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```

### [CVE-2023-41067]

A Apple corrigiu um erro lógico do LaunchServices no macOS Sonoma 14.0 por meio de verificações aprimoradas. O comunicado público apenas afirma que um app poderia contornar o Gatekeeper; portanto, não infira um formato de arquivo específico ou uma cadeia de exploração apenas com base na entrada do CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Um bypass do Gatekeeper no macOS 14.4 (lançado em março de 2024), decorrente do tratamento de ZIPs maliciosos pelo `libarchive`, permitia que apps evitassem a avaliação. Atualize para a versão 14.4 ou posterior, na qual a Apple corrigiu o problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Um **Automator Quick Action workflow** incorporado a um app baixado poderia ser acionado sem a avaliação do Gatekeeper, pois os workflows eram tratados como dados e executados pelo auxiliar do Automator fora do fluxo normal de solicitação de notarização. Assim, um `.app` criado especialmente, que incluísse uma Quick Action para executar um shell script (por exemplo, dentro de `Contents/PlugIns/*.workflow/Contents/document.wflow`), poderia ser executado imediatamente ao abrir o app. A Apple adicionou uma caixa de diálogo extra de consentimento e corrigiu o fluxo de avaliação no Ventura **13.7**, Sonoma **14.7** e Sequoia **15**.<sup>[[3]](#references)</sup>

### Falhas na propagação da quarentena durante a extração e a cópia

Um estudo de 2024 encontrou lacunas de propagação nas versões testadas do iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) e 7z Utility (DMG/ZIP/7Z); também observou a perda do atributo durante cópias do host para o guest usando VMware Tools. Vários fornecedores anunciaram correções posteriormente; portanto, considere esses nomes como pistas para **novos testes específicos por versão**, e não como uma lista permanente de softwares vulneráveis. O mesmo problema de limite de confiança se aplica a workflows nativos do Unix: `curl`/`scp` não adicionam quarentena, e `tar`/`unzip` na linha de comando não a herdam automaticamente de um arquivo compactado transportador.<sup>[[15]](#references)</sup>

Para testes ofensivos, compare o arquivo transportador e o app final após **cada** transição por navegador, cliente de e-mail, arquivo compactado, imagem de disco, sincronização na nuvem, pasta compartilhada e cópia de VM. Uma rejeição explícita do `spctl` não corrige a ausência do xattr: sem quarentena, o fluxo normal do Gatekeeper na primeira abertura talvez nunca solicite essa avaliação.<sup>[[15]](#references)</sup>

```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
  'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```

### uchg (desta [palestra](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crie um diretório contendo um app.
- Adicione uchg ao app.
- Compacte o app em um arquivo tar.gz.
- Envie o arquivo tar.gz para uma vítima.
- A vítima abre o arquivo tar.gz e executa o app.
- Gatekeeper não verifica o app.<sup>[[12]](#references)</sup>

### Impedir o xattr de Quarantine

Em um pacote ".app", se o xattr de quarantine não for adicionado, o **Gatekeeper não será acionado** ao executá-lo.

Consulte [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) para primitives baseadas em filesystem, flags, ACL e AppleDouble que podem impedir ou descartar extended attributes.





## References

- [1] [Segurança da plataforma Apple: Sobre o conteúdo de segurança do macOS Sonoma 14.4 (inclui CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Como o macOS agora rastreia a procedência dos apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Sobre o conteúdo de segurança do macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia remove o bypass do Gatekeeper por Control-clique em “Abrir”](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: A descoberta de CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, contornando o macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifica vulnerabilidade no Safari que permite contornar o Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifica vulnerabilidade no macOS Archive Utility que permite contornar o Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Calcanhar de Aquiles do Gatekeeper: descobrindo uma vulnerabilidade no macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Descoberta de um bypass do Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Encontrando e reportando um exploit de bypass do Gatekeeper com a ajuda do Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Contornando os mecanismos de segurança e privacidade do macOS — do Gatekeeper à System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Sobre o conteúdo de segurança do macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Testando um produto notarizado](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Bypass do Gatekeeper — revelando vulnerabilidades em um mecanismo de segurança do macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
