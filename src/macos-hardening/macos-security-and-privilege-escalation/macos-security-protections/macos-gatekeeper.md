# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** é um recurso de segurança desenvolvido para os sistemas operacionais Mac, projetado para garantir que os usuários **executem apenas software confiável** em seus sistemas. Ele funciona **validando o software** que um usuário baixa e tenta abrir a partir de **fontes externas à App Store**, como um aplicativo, um plug-in ou um pacote de instalação.

O principal mecanismo do Gatekeeper está em seu processo de **verificação**. Ele verifica se o software foi **assinado por um desenvolvedor reconhecido**, garantindo a autenticidade do software. Além disso, verifica se o software foi **notarizado pela Apple**, confirmando que ele não contém conteúdo malicioso conhecido e não foi adulterado após a notarização.

Adicionalmente, o Gatekeeper reforça o controle e a segurança do usuário ao **solicitar a aprovação do usuário para abrir** o software baixado pela primeira vez. Essa proteção ajuda a impedir que os usuários executem inadvertidamente código executável potencialmente perigoso que possam ter confundido com um arquivo de dados inofensivo.

### Assinaturas de Aplicativos

As assinaturas de aplicativos, também conhecidas como assinaturas de código, são um componente essencial da infraestrutura de segurança da Apple. Elas são usadas para **verificar a identidade do autor do software** (o desenvolvedor) e garantir que o código não tenha sido adulterado desde a última assinatura.

Veja como funciona:

1. **Assinatura do Aplicativo:** Quando um desenvolvedor está pronto para distribuir seu aplicativo, ele **assina o aplicativo usando uma chave privada**. Essa chave privada está associada a um **certificado que a Apple emite para o desenvolvedor** quando ele se inscreve no Apple Developer Program. O processo de assinatura envolve a criação de um hash criptográfico de todas as partes do aplicativo e a criptografia desse hash com a chave privada do desenvolvedor.
2. **Distribuição do Aplicativo:** O aplicativo assinado é então distribuído aos usuários junto com o certificado do desenvolvedor, que contém a chave pública correspondente.
3. **Verificação do Aplicativo:** Quando um usuário baixa e tenta executar o aplicativo, o sistema operacional do Mac usa a chave pública do certificado do desenvolvedor para descriptografar o hash. Em seguida, recalcula o hash com base no estado atual do aplicativo e compara esse valor com o hash descriptografado. Se forem iguais, significa que **o aplicativo não foi modificado** desde que o desenvolvedor o assinou, e o sistema permite que o aplicativo seja executado.

As assinaturas de aplicativos são uma parte essencial da tecnologia Gatekeeper da Apple. Quando um usuário tenta **abrir um aplicativo baixado da Internet**, o Gatekeeper verifica a assinatura do aplicativo. Se ele estiver assinado com um certificado emitido pela Apple para um desenvolvedor conhecido e o código não tiver sido adulterado, o Gatekeeper permite que o aplicativo seja executado. Caso contrário, ele bloqueia o aplicativo e alerta o usuário.

A partir do macOS Catalina, o **Gatekeeper também verifica se o aplicativo foi notarizado** pela Apple, adicionando uma camada extra de segurança. O processo de notarização verifica o aplicativo em busca de problemas de segurança conhecidos e código malicioso e, se essas verificações forem aprovadas, a Apple adiciona um ticket ao aplicativo que o Gatekeeper pode verificar.

#### Verificar Assinaturas

Ao verificar alguma **amostra de malware**, você deve sempre **verificar a assinatura** do binário, pois o **desenvolvedor** que o assinou pode já estar **relacionado** a **malware.**
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

O processo de notarização da Apple funciona como uma proteção adicional para proteger os usuários contra software potencialmente nocivo. Ele envolve o **desenvolvedor enviando o aplicativo para análise** pelo **Notary Service da Apple**, que não deve ser confundido com o App Review. Esse serviço é um **sistema automatizado** que examina o software enviado em busca de **conteúdo malicioso** e de possíveis problemas relacionados à assinatura de código.

Se o software **for aprovado** nessa inspeção sem apresentar preocupações, o Notary Service gera um ticket de notarização. Em seguida, o desenvolvedor deve **anexar esse ticket ao software**, em um processo conhecido como "stapling". Além disso, o ticket de notarização também é publicado online, onde o Gatekeeper, a tecnologia de segurança da Apple, pode acessá-lo.

Na primeira instalação ou execução do software pelo usuário, a existência do ticket de notarização - seja anexado ao executável ou encontrado online - **informa ao Gatekeeper que o software foi notarizado pela Apple**. Como resultado, o Gatekeeper exibe uma mensagem descritiva na caixa de diálogo do primeiro lançamento, indicando que o software passou por verificações de conteúdo malicioso realizadas pela Apple. Esse processo aumenta a confiança do usuário na segurança do software instalado ou executado em seus sistemas.

### spctl & syspolicyd

> [!CAUTION]
> Observe que, a partir da versão Sequoia, o **`spctl`** não permite mais modificar a configuração do Gatekeeper.

O **`spctl`** é a ferramenta CLI para enumerar e interagir com o Gatekeeper (com o daemon `syspolicyd` por meio de mensagens XPC). Por exemplo, é possível ver o **status** do GateKeeper com:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Observe que as verificações de assinatura do GateKeeper são realizadas apenas em **arquivos com o atributo Quarantine**, não em todos os arquivos.

O GateKeeper verificará se, de acordo com as **preferências e a assinatura**, um binário pode ser executado:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** é o daemon principal responsável por aplicar o Gatekeeper. Ele mantém um banco de dados localizado em `/var/db/SystemPolicy`, e é possível encontrar o código de suporte ao [banco de dados aqui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e o [modelo SQL aqui](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Observe que o banco de dados não é restringido pelo SIP e pode ser gravado pelo root, e o banco de dados `/var/db/.SystemPolicy-default` é usado como backup original caso o outro seja corrompido.

Além disso, os bundles **`/var/db/gke.bundle`** e **`/var/db/gkopaque.bundle`** contêm arquivos com regras que são inseridas no banco de dados. Você pode verificar este banco de dados como root com:
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
**`syspolicyd`** também expõe um servidor XPC com diferentes operações, como `assess`, `update`, `record` e `cancel`, que também podem ser acessadas usando as APIs **`Security.framework`'s `SecAssessment*`**, e o **`spctl`** na verdade se comunica com o **`syspolicyd`** via XPC.

Observe como a primeira regra terminou em "**App Store**" e a segunda em "**Developer ID**", e que na imagem anterior ele estava **habilitado para executar aplicativos da App Store e de desenvolvedores identificados**.\
Se você **modificar** essa configuração para App Store, as regras "**Notarized Developer ID" desaparecerão**.

Também existem milhares de regras do **tipo GKE**:
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
As opções **`--master-disable`** e **`--global-disable`** do **`spctl`** **desativarão completamente** estas verificações de assinatura:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Quando completamente ativada, uma nova opção aparecerá:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

É possível **verificar se um App será permitido pelo GateKeeper** com:
```bash
spctl --assess -v /Applications/App.app
```
No macOS 14 e posteriores, **`syspolicy_check`** é uma verificação de nível mais alto útil antes da distribuição de um application bundle. Ele produz diagnósticos de execução confiável mais acionáveis do que um resultado simples do `spctl`, embora a Apple ainda recomende testar o fluxo real de download/extração/primeiro lançamento, pois isso também exercita a propagação da quarentena.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
É possível adicionar novas regras no GateKeeper para permitir a execução de determinados aplicativos com:
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
Em relação às **kernel extensions**, a pasta `/var/db/SystemPolicyConfiguration` contém arquivos com listas de kexts permitidas para carregamento. Além disso, `spctl` possui o entitlement `com.apple.private.iokit.nvram-csr`, pois é capaz de adicionar novas kernel extensions pré-aprovadas, que também precisam ser salvas na NVRAM em uma chave `kext-allowed-teams`.

#### Gerenciando o Gatekeeper no macOS 15 (Sequoia) e posteriores

- O bypass tradicional do Finder **Ctrl+Open / clique com o botão direito → Open** foi removido; os usuários precisam permitir explicitamente um app bloqueado em **System Settings → Privacy & Security → Open Anyway** após o primeiro diálogo de bloqueio.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` não são mais aceitos como alterações de política não supervisionadas. As operações que modificam o banco de dados de regras ou o estado global de avaliação estão obsoletas; portanto, use `spctl` para avaliação e configure a aplicação da política pela interface ou pelo MDM.

A partir do macOS 15 Sequoia, os usuários finais não podem mais alternar a política do Gatekeeper usando `spctl`. O gerenciamento é realizado por meio de System Settings ou pela implantação de um perfil de configuração MDM com o payload `com.apple.systempolicy.control`. Exemplo de trecho de perfil para permitir a App Store e desenvolvedores identificados (mas não "Anywhere"):

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

### Arquivos em Quarantine

Ao **baixar** uma aplicação ou arquivo, determinadas **aplicações** do macOS, como navegadores ou clientes de e-mail, **anexam um atributo de arquivo estendido**, comumente conhecido como "**quarantine flag**", ao arquivo baixado. Esse atributo atua como uma medida de segurança para **marcar o arquivo** como proveniente de uma fonte não confiável (a internet) e potencialmente contendo riscos. No entanto, nem todas as aplicações anexam esse atributo; por exemplo, softwares comuns de clientes BitTorrent geralmente ignoram esse processo.

**A presença de um quarantine flag sinaliza o recurso de segurança Gatekeeper do macOS quando um usuário tenta executar o arquivo**.

Quando o **quarantine flag não está presente** (como no caso de arquivos baixados por alguns clientes BitTorrent), as **verificações do Gatekeeper podem não ser realizadas**. Portanto, os usuários devem ter cautela ao abrir arquivos baixados de fontes menos seguras ou desconhecidas.

> [!NOTE] > **Verificar** a **validade** das assinaturas de código é um processo que consome muitos **recursos**, incluindo a geração de **hashes criptográficos** do código e de todos os recursos agrupados. Além disso, verificar a validade do certificado envolve realizar uma **verificação online** nos servidores da Apple para conferir se ele foi revogado após sua emissão. Por esses motivos, uma verificação completa da assinatura de código e da notarização é **impraticável de ser executada toda vez que uma aplicação é iniciada**.
>
> Portanto, essas verificações são **executadas somente ao iniciar aplicações com o atributo quarantine.**

> [!WARNING]
> Esse atributo deve ser **definido pela aplicação que cria/baixa** o arquivo.
>
> No entanto, arquivos em sandbox terão esse atributo definido em todos os arquivos que criarem. E aplicações sem sandbox podem defini-lo por conta própria ou especificar a chave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) no **Info.plist**, o que fará com que o sistema defina o atributo estendido `com.apple.quarantine` nos arquivos criados.

Além disso, todos os arquivos criados por um processo que chama **`qtn_proc_apply_to_self`** são colocados em quarantine. Ou a API **`qtn_file_apply_to_path`** adiciona o atributo quarantine a um caminho de arquivo especificado.

É possível **verificar seu status e ativá-lo/desativá-lo** (é necessário ser root) com:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Você também pode **verificar se um arquivo possui o atributo estendido de quarentena** com:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Verifique o **valor** dos **atributos** **extended** e descubra o app que gravou o atributo de quarantine com:
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
Na verdade, um processo "poderia definir flags de quarantine nos arquivos que cria" (já tentei aplicar a flag USER_APPROVED em um arquivo criado, mas ela não é aplicada):

<details>

<summary>Código-fonte para aplicar flags de quarantine</summary>
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
As informações de quarantine também são armazenadas em um banco de dados central gerenciado pelo LaunchServices em **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, o que permite que a GUI obtenha dados sobre as origens dos arquivos. Além disso, isso pode ser sobrescrito por aplicações que possam estar interessadas em ocultar suas origens. Isso também pode ser feito por meio das APIs do LaunchServices.

#### **libquarantine.dylib**

Esta biblioteca exporta várias funções que permitem manipular os campos de atributos estendidos.

As APIs `qtn_file_*` lidam com políticas de quarantine de arquivos, enquanto as APIs `qtn_proc_*` são aplicadas a processos (arquivos criados pelo processo). As funções não exportadas `__qtn_syscall_quarantine*` são as que aplicam as políticas e chamam `mac_syscall` com "Quarantine" como primeiro argumento, enviando as solicitações para `Quarantine.kext`.

#### **Quarantine.kext**

A extensão do kernel está disponível apenas por meio do **kernel cache no sistema**; no entanto, você _pode baixar o **Kernel Debug Kit em** [**https://developer.apple.com/**](https://developer.apple.com/), que conterá uma versão da extensão com símbolos.

Esta Kext usa hooks via MACF em várias chamadas para interceptar todos os eventos do ciclo de vida dos arquivos: criação, abertura, renomeação, hard-linking... até mesmo `setxattr`, para impedir que ele defina o atributo estendido `com.apple.quarantine`.

Ela também usa alguns MIBs:

- `security.mac.qtn.sandbox_enforce`: Impõe o quarantine junto com o Sandbox
- `security.mac.qtn.user_approved_exec`: Processos em quarantine só podem executar arquivos aprovados

#### Provenance xattr (Ventura e posteriores)

O macOS 13 Ventura introduziu um mecanismo de provenance separado, que é preenchido na primeira vez que um app em quarantine tem permissão para ser executado.<sup>[[2]](#references)</sup> Dois artefatos são criados:

- O xattr `com.apple.provenance` no diretório do bundle `.app` (valor binário de tamanho fixo contendo uma chave primária e flags).
- Uma linha na tabela `provenance_tracking` dentro do banco de dados ExecPolicy em `/var/db/SystemPolicyConfiguration/ExecPolicy/`, armazenando o cdhash e os metadados do app.

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

XProtect é um recurso integrado de **anti-malware** do macOS. O XProtect **verifica qualquer aplicativo quando ele é iniciado pela primeira vez ou modificado, comparando-o com seu banco de dados** de malware conhecidos e tipos de arquivo não seguros. Quando você baixa um arquivo por determinados aplicativos, como Safari, Mail ou Messages, o XProtect verifica automaticamente o arquivo. Se ele corresponder a algum malware conhecido em seu banco de dados, o XProtect **impedirá a execução do arquivo** e alertará você sobre a ameaça.

O banco de dados do XProtect é **atualizado regularmente** pela Apple com novas definições de malware, e essas atualizações são baixadas e instaladas automaticamente no Mac. Isso garante que o XProtect esteja sempre atualizado com as ameaças conhecidas mais recentes.

No entanto, vale observar que **o XProtect não é uma solução antivírus completa**. Ele verifica apenas uma lista específica de ameaças conhecidas e não realiza verificação no acesso, como a maioria dos softwares antivírus.

Você pode obter informações sobre a atualização mais recente do XProtect executando:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
O XProtect está localizado em um local protegido pelo SIP em **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e, dentro do bundle, você pode encontrar informações usadas pelo XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que códigos com esses cdhashes usem legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins e extensões que não podem ser carregados por meio de BundleID e TeamID ou que indicam uma versão mínima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regras Yara para detectar malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Banco de dados SQLite3 com hashes de aplicações bloqueadas e TeamIDs.

Observe que existe outro App em **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionado ao XProtect, mas que não está envolvido no processo do Gatekeeper.

> XProtect Remediator: Em versões modernas do macOS, a Apple distribui scanners sob demanda (XProtect Remediator) que são executados periodicamente pelo launchd para detectar e remediar famílias de malware. Você pode observar essas varreduras nos unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Não é o Gatekeeper

> [!CAUTION]
> Observe que o Gatekeeper **não é executado toda vez** que você executa uma aplicação; apenas o _**AppleMobileFileIntegrity**_ irá **verificar as assinaturas do código executável** quando você executar um app que já tenha sido executado e verificado pelo Gatekeeper.

Portanto, anteriormente era possível executar um app para armazená-lo em cache com o Gatekeeper e, em seguida, **modificar arquivos não executáveis da aplicação** (como arquivos asar do Electron ou arquivos NIB); se nenhuma outra proteção estivesse presente, a aplicação seria **executada** com as adições **maliciosas**.

No entanto, agora isso não é possível porque o macOS **impede a modificação de arquivos** dentro de application bundles. Portanto, se você tentar o ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), descobrirá que não é mais possível explorá-lo, pois, depois de executar o app para armazená-lo em cache com o Gatekeeper, você não conseguirá modificar o bundle. E, se você alterar, por exemplo, o nome do diretório Contents para NotCon (como indicado no exploit) e, em seguida, executar o binário principal do app para armazená-lo em cache com o Gatekeeper, isso acionará um erro e não será executado.

## Bypasses do Gatekeeper

Qualquer forma de fazer bypass do Gatekeeper (conseguir fazer com que o usuário baixe algo e o execute quando o Gatekeeper deveria impedi-lo) é considerada uma vulnerabilidade no macOS. Estes são alguns CVEs atribuídos a técnicas que permitiram fazer bypass do Gatekeeper no passado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Foi observado que, quando o **Archive Utility** é usado para extração, arquivos com **paths que excedem 886 caracteres** não recebem o extended attribute com.apple.quarantine. Essa situação permite inadvertidamente que esses arquivos **contornem as verificações de segurança do Gatekeeper**.<sup>[[5]](#references)</sup>

Consulte o [**relatório original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para obter mais informações.<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando uma aplicação é criada com o **Automator**, as informações sobre o que ela precisa executar ficam dentro de `application.app/Contents/document.wflow`, e não no executável. O executável é apenas um binário genérico do Automator chamado **Automator Application Stub**.

Portanto, você poderia fazer `application.app/Contents/MacOS/Automator\ Application\ Stub` **apontar, por meio de um symbolic link, para outro Automator Application Stub dentro do sistema**, e ele executaria o conteúdo de `document.wflow` (seu script) **sem acionar o Gatekeeper**, porque o executável real não possui o quarantine xattr.<sup>[[6]](#references)</sup>

Exemplo de localização esperada: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulte o [**relatório original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para obter mais informações.<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Nesse bypass, um arquivo zip foi criado com uma aplicação cuja compactação começava em `application.app/Contents`, em vez de `application.app`. Portanto, o **quarantine attr** foi aplicado a todos os **arquivos de `application.app/Contents`**, mas **não a `application.app`**, que era o que o Gatekeeper verificava. Assim, o Gatekeeper foi contornado porque, quando `application.app` era acionado, **não tinha o atributo quarantine.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Consulte o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para obter mais informações.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Mesmo que os componentes sejam diferentes, a exploração desta vulnerabilidade é muito semelhante à anterior. Neste caso, vamos gerar um Apple Archive a partir de **`application.app/Contents`**, portanto **`application.app` não receberá o atributo de quarentena** quando for descompactado pelo **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulte o [**relatório original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para obter mais informações.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

A ACL **`writeextattr`** pode ser usada para impedir que qualquer pessoa escreva um atributo em um arquivo:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Além disso, o formato de arquivo **AppleDouble** copia um arquivo incluindo seus ACEs.<sup>[[9]](#references)</sup>

No [**código-fonte**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html), é possível ver que a representação textual da ACL armazenada dentro do xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descompactado. Portanto, se você compactasse um aplicativo em um arquivo zip com o formato **AppleDouble** e uma ACL que impedisse a gravação de outros xattrs nele... o xattr quarantine não seria definido no aplicativo:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulte o [**relatório original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obter mais informações.<sup>[[9]](#references)</sup>

Observe que isso também poderia ser explorado com AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Foi descoberto que o **Google Chrome não estava definindo o atributo de quarentena** para arquivos baixados devido a alguns problemas internos do macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

O AppleDouble armazena os atributos de um arquivo em um arquivo separado cujo nome começa com `._`; isso ajuda a copiar os atributos dos arquivos **entre máquinas macOS**. No entanto, após descompactar um arquivo AppleDouble, o arquivo começando com `._` **não recebia o atributo de quarentena**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Sendo possível criar um arquivo que não tivesse o atributo de quarentena definido, era **possível contornar o Gatekeeper.** O truque era **criar um aplicativo em um arquivo DMG** usando a convenção de nomenclatura AppleDouble (começando com `._`) e criar um **arquivo visível como um link simbólico para esse** arquivo oculto sem o atributo de quarentena.\
Quando o **arquivo DMG é executado**, como não possui um atributo de quarentena, ele **contorna o Gatekeeper**.
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

A Apple corrigiu um erro lógico do LaunchServices no macOS Sonoma 14.0 por meio de verificações aprimoradas. O comunicado público afirma apenas que um app poderia ignorar o Gatekeeper; portanto, não infira um formato específico de carrier ou uma cadeia de exploração apenas com base na entrada do CVE.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Um bypass do Gatekeeper no macOS 14.4 (lançado em março de 2024), decorrente do tratamento de ZIPs maliciosos pela `libarchive`, permitia que apps escapassem da avaliação. Atualize para a versão 14.4 ou posterior, na qual a Apple corrigiu o problema.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Um **Automator Quick Action workflow** incorporado a um app baixado poderia ser acionado sem a avaliação do Gatekeeper, pois os workflows eram tratados como dados e executados pelo helper do Automator fora do fluxo normal do prompt de notarização. Portanto, um `.app` criado para incluir uma Quick Action que executa um shell script (por exemplo, dentro de `Contents/PlugIns/*.workflow/Contents/document.wflow`) poderia ser executado imediatamente ao ser iniciado. A Apple adicionou um diálogo de consentimento extra e corrigiu o fluxo de avaliação no Ventura **13.7**, Sonoma **14.7** e Sequoia **15**.<sup>[[3]](#references)</sup>

### Falhas na propagação de quarantine durante extração e cópia

Um estudo de 2024 encontrou lacunas de propagação nas versões testadas do iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) e 7z Utility (DMG/ZIP/7Z); o estudo também observou que o atributo era perdido durante cópias host-to-guest do VMware Tools. Vários fornecedores anunciaram correções posteriormente; portanto, trate esses nomes como pontos de partida para **novos testes específicos de versão**, e não como uma lista permanente de software vulnerável. O mesmo problema de trust boundary se aplica a workflows Unix nativos: `curl`/`scp` não adicionam quarantine, e `tar`/`unzip` de linha de comando não a herdam automaticamente de um carrier archive.<sup>[[15]](#references)</sup>

Para testes ofensivos, compare o carrier e o app final após **cada** transição realizada por navegador, cliente de e-mail, archive, disk image, cloud-sync, shared folder e cópia de VM. Uma rejeição explícita do `spctl` não corrige um xattr ausente: sem quarantine, o fluxo normal do Gatekeeper na primeira abertura pode nunca solicitar essa avaliação.<sup>[[15]](#references)</sup>
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
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Crie um diretório contendo um app.
- Adicione uchg ao app.
- Comprima o app em um arquivo tar.gz.
- Envie o arquivo tar.gz para uma vítima.
- A vítima abre o arquivo tar.gz e executa o app.
- O Gatekeeper não verifica o app.<sup>[[12]](#references)</sup>

### Impedir quarantine xattr

Em um bundle ".app", se o quarantine xattr não for adicionado a ele, o **Gatekeeper não será acionado** ao executá-lo.

Consulte [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks) para conhecer primitives baseadas em filesystem, flags, ACL e AppleDouble que podem impedir ou descartar extended attributes.



## References

- [1] [Apple Platform Security: Sobre o conteúdo de segurança do macOS Sonoma 14.4 (inclui CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Como o macOS agora rastreia a proveniência dos apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Sobre o conteúdo de segurança do macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia remove o bypass do Gatekeeper por meio de “Open” com Control‑click](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: A descoberta da CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypass do Gatekeeper do macOS](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifica vulnerabilidade no Safari que permite o bypass do Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifica vulnerabilidade no macOS Archive Utility que permite o bypass do Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [O calcanhar de Aquiles do Gatekeeper: descobrindo uma vulnerabilidade do macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Descoberta de um bypass do Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Encontrando e reportando um exploit de bypass do Gatekeeper com a ajuda do Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypass dos mecanismos de segurança e privacidade do macOS — do Gatekeeper ao System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Sobre o conteúdo de segurança do macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Testando um produto notarised](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Bypass do Gatekeeper — descobrindo fraquezas em um mecanismo de segurança do macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
