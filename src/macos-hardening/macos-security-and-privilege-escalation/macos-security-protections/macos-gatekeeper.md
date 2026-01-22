# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** é um recurso de segurança desenvolvido para os sistemas operacionais Mac, projetado para garantir que os usuários **executem apenas software confiável** em seus sistemas. Ele funciona **validando o software** que um usuário baixa e tenta abrir de **fontes fora do App Store**, como um app, um plug-in ou um pacote de instalação.

O mecanismo-chave do Gatekeeper está em seu processo de **verificação**. Ele checa se o software baixado está **assinada por um desenvolvedor reconhecido**, assegurando a autenticidade do software. Além disso, verifica se o software foi **notarizado pela Apple**, confirmando que não contém conteúdo malicioso conhecido e que não foi adulterado após a notarização.

Adicionalmente, o Gatekeeper reforça o controle e a segurança do usuário **solicitando a aprovação para abrir** o software baixado pela primeira vez. Essa proteção ajuda a evitar que usuários executem inadvertidamente código executável potencialmente perigoso que possam ter confundido com um arquivo de dados inofensivo.

### Application Signatures

Application signatures, também conhecidas como code signatures, são um componente crítico da infraestrutura de segurança da Apple. Elas são usadas para **verificar a identidade do autor do software** (o desenvolvedor) e para garantir que o código não foi adulterado desde a última assinatura.

Veja como funciona:

1. **Signing the Application:** Quando um desenvolvedor está pronto para distribuir seu aplicativo, ele **assina o aplicativo usando uma chave privada**. Essa chave privada está associada a um **certificado que a Apple emite ao desenvolvedor** quando este se inscreve no Apple Developer Program. O processo de assinatura envolve criar um hash criptográfico de todas as partes do app e criptografar esse hash com a chave privada do desenvolvedor.
2. **Distributing the Application:** O aplicativo assinado é então distribuído aos usuários junto com o certificado do desenvolvedor, que contém a chave pública correspondente.
3. **Verifying the Application:** Quando um usuário baixa e tenta executar o aplicativo, seu sistema operacional Mac usa a chave pública do certificado do desenvolvedor para descriptografar o hash. Em seguida, recalcula o hash com base no estado atual do aplicativo e compara com o hash descriptografado. Se eles coincidirem, significa que **o aplicativo não foi modificado** desde que o desenvolvedor o assinou, e o sistema permite que o aplicativo seja executado.

Application signatures são uma parte essencial da tecnologia Gatekeeper da Apple. Quando um usuário tenta **abrir um aplicativo baixado da internet**, o Gatekeeper verifica a assinatura do aplicativo. Se ele estiver assinado com um certificado emitido pela Apple a um desenvolvedor conhecido e o código não tiver sido adulterado, o Gatekeeper permite a execução do aplicativo. Caso contrário, ele bloqueia o aplicativo e alerta o usuário.

A partir do macOS Catalina, **o Gatekeeper também verifica se o aplicativo foi notarizado pela Apple**, adicionando uma camada extra de segurança. O processo de notarização verifica o aplicativo em busca de problemas de segurança conhecidos e código malicioso, e se essas verificações forem aprovadas, a Apple adiciona um ticket ao aplicativo que o Gatekeeper pode verificar.

#### Check Signatures

Ao verificar alguma amostra de malware você deve sempre verificar a assinatura do binário, pois o desenvolvedor que a assinou pode já estar relacionado com malware.
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

O processo de notarização da Apple funciona como uma salvaguarda adicional para proteger os usuários de software potencialmente prejudicial. Envolve o **desenvolvedor submetendo sua aplicação para exame** pelo **Apple's Notary Service**, que não deve ser confundido com App Review. Esse serviço é um **sistema automatizado** que analisa o software submetido em busca de **conteúdo malicioso** e de possíveis problemas com assinatura de código.

Se o software **passar** nessa inspeção sem levantar preocupações, o Notary Service gera um ticket de notarização. O desenvolvedor então precisa **anexar esse ticket ao seu software**, um processo conhecido como 'stapling'. Além disso, o ticket de notarização também é publicado online, onde o Gatekeeper, a tecnologia de segurança da Apple, pode acessá-lo.

Na primeira instalação ou execução do software pelo usuário, a existência do ticket de notarização — seja 'stapled' ao executável ou disponível online — **informa ao Gatekeeper que o software foi notarizado pela Apple**. Como resultado, o Gatekeeper exibe uma mensagem descritiva no diálogo de primeira execução, indicando que o software passou por verificações de conteúdo malicioso pela Apple. Esse processo, assim, aumenta a confiança do usuário na segurança do software que instala ou executa em seus sistemas.

### spctl & syspolicyd

> [!CAUTION]
> Observe que, a partir da versão Sequoia, **`spctl`** não permite mais modificar a configuração do Gatekeeper.

**`spctl`** é a ferramenta CLI para enumerar e interagir com o Gatekeeper (com o `syspolicyd` daemon via mensagens XPC). Por exemplo, é possível ver o **status** do GateKeeper com:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Observe que as verificações de assinatura do GateKeeper são realizadas apenas em **arquivos com o atributo Quarantine**, e não em todos os arquivos.

GateKeeper verifica, de acordo com as **preferências & a assinatura**, se um binário pode ser executado:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** é o daemon principal responsável por aplicar o GateKeeper. Ele mantém um banco de dados localizado em `/var/db/SystemPolicy` e é possível encontrar o código que suporta o [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) e o [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Observe que o banco de dados não é restringido pelo SIP e é gravável por root, e o banco de dados `/var/db/.SystemPolicy-default` é usado como um backup original caso o outro fique corrompido.

Além disso, os bundles **`/var/db/gke.bundle`** e **`/var/db/gkopaque.bundle`** contêm arquivos com regras que são inseridas no banco de dados. Você pode verificar esse banco de dados como root com:
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
**`syspolicyd`** também expõe um servidor XPC com diferentes operações como `assess`, `update`, `record` e `cancel` que também são alcançáveis usando as APIs **`Security.framework`'s `SecAssessment*`** e **`spctl`** na verdade conversa com **`syspolicyd`** via XPC.

Note how the first rule ended in "**App Store**" and the second one in "**Developer ID**" and that in the previous imaged it was **enabled to execute apps from the App Store and identified developers**.\
Se você **modificar** essa configuração para App Store, as "**Notarized Developer ID" rules will disappear**.

Existem também milhares de regras do **tipo GKE** :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Estes são hashes que vêm de:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Ou você pode listar as informações anteriores com:
```bash
sudo spctl --list
```
As opções **`--master-disable`** e **`--global-disable`** do **`spctl`** irão desativar completamente essas verificações de assinatura:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Quando totalmente ativado, uma nova opção aparecerá:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

É possível **verificar se um App será permitido pelo GateKeeper** com:
```bash
spctl --assess -v /Applications/App.app
```
É possível adicionar novas regras no GateKeeper para permitir a execução de certos apps com:
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
Regarding **kernel extensions**, the folder `/var/db/SystemPolicyConfiguration` contains files with lists of kexts allowed to be loaded. Moreover, `spctl` has the entitlement `com.apple.private.iokit.nvram-csr` because it's capable of adding new pre-approved kernel extensions which need to be saved also in NVRAM in a `kext-allowed-teams` key.

#### Gerenciando o Gatekeeper no macOS 15 (Sequoia) e posteriores

- O bypass antigo do Finder **Ctrl+Open / Right‑click → Open** foi removido; os usuários devem permitir explicitamente um app bloqueado em **System Settings → Privacy & Security → Open Anyway** após o primeiro diálogo de bloqueio.
- `spctl --master-disable/--global-disable` não são mais aceitos; `spctl` é efetivamente somente leitura para avaliação e gerenciamento de rótulos, enquanto a aplicação da política é configurada via UI ou MDM.

A partir do macOS 15 Sequoia, usuários finais não podem mais alternar a política do Gatekeeper via `spctl`. O gerenciamento é feito através de System Settings ou implantando um perfil de configuração MDM com o payload `com.apple.systempolicy.control`. Exemplo de snippet de perfil para permitir App Store e desenvolvedores identificados (mas não "Anywhere"):

<details>
<summary>Perfil MDM para permitir App Store e desenvolvedores identificados</summary>
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

### Arquivos em quarentena

Ao **baixar** um aplicativo ou arquivo, determinadas **aplicações** do macOS, como navegadores web ou clientes de email, **anexam um atributo estendido de arquivo**, comumente conhecido como "**quarantine flag**", ao arquivo baixado. Esse atributo atua como uma medida de segurança para **marcar o arquivo** como proveniente de uma fonte não confiável (a internet) e que pode representar riscos. Contudo, nem todas as aplicações anexam esse atributo; por exemplo, clientes BitTorrent comuns normalmente contornam esse processo.

**A presença de um quarantine flag sinaliza o recurso de segurança Gatekeeper do macOS quando o usuário tenta executar o arquivo**.

No caso em que o **quarantine flag não está presente** (como em arquivos baixados por alguns clientes BitTorrent), as **verificações do Gatekeeper podem não ser realizadas**. Portanto, os usuários devem ter cautela ao abrir arquivos baixados de fontes menos seguras ou desconhecidas.

> [!NOTE] > **Verificar** a **validade** das assinaturas de código é um processo **intensivo em recursos** que inclui gerar **hashes** criptográficos do código e de todos os seus recursos empacotados. Além disso, verificar a validade de certificados envolve fazer uma **checagem online** nos servidores da Apple para ver se ele foi revogado após a emissão. Por essas razões, uma verificação completa de assinatura de código e notarização é **impraticável para executar toda vez que um app é iniciado**.
>
> Portanto, essas verificações são **executadas apenas ao executar apps com o atributo quarantined.**

> [!WARNING]
> Este atributo deve ser **definido pela aplicação que cria/baixa** o arquivo.
>
> Entretanto, arquivos criados por processos sandboxed terão esse atributo definido em todos os arquivos que criam. E apps não-sandboxed podem defini‑lo por si mesmos, ou especificar a [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key no **Info.plist**, o que fará o sistema definir o atributo estendido `com.apple.quarantine` nos arquivos criados,

Além disso, todos os arquivos criados por um processo que chama **`qtn_proc_apply_to_self`** ficam em quarentena. Ou a API **`qtn_file_apply_to_path`** adiciona o atributo de quarentena a um caminho de arquivo especificado.

É possível **verificar seu status e habilitar/desabilitar** (é necessário root) com:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Você também pode **verificar se um arquivo tem o atributo estendido de quarentena** com:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Verifique o **valor** dos **atributos** **estendidos** e descubra o app que escreveu o quarantine attr com:
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
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
Na verdade, um processo "pode definir quarantine flags nos arquivos que cria" (já tentei aplicar a flag USER_APPROVED em um arquivo criado, mas ela não é aplicada):

<details>

<summary>Código-fonte: aplicar quarantine flags</summary>
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
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

This library exports several functions that allow to manipulate the extended attribute fields.

The `qtn_file_*` APIs deal with file quarantine policies, the `qtn_proc_*` APIs are applied to processes (files created by the process). The unexported `__qtn_syscall_quarantine*` functions are the ones that applies the policies which calls `mac_syscall` with "Quarantine" as first argument which sends the requests to `Quarantine.kext`.

#### **Quarantine.kext**

The kernel extension is only available through the **kernel cache on the system**; however, you _can_ download the **Kernel Debug Kit from** [**https://developer.apple.com/**](https://developer.apple.com/), which will contain a symbolicated version of the extension.

This Kext will hook via MACF several calls in order to traps all file lifecycle events: Creation, opening, renaming, hard-linkning... even `setxattr` to prevent it from setting the `com.apple.quarantine` extended attribute.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Enforce quarantine along Sandbox
- `security.mac.qtn.user_approved_exec`: Querantined procs can only execute approved files

#### Provenance xattr (Ventura and later)

macOS 13 Ventura introduced a separate provenance mechanism which is populated the first time a quarantined app is allowed to run. Two artefacts are created:

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect é um recurso integrado de **anti-malware** no macOS. O XProtect **verifica qualquer aplicação quando é iniciada pela primeira vez ou modificada em relação ao seu banco de dados** de malware conhecidos e tipos de arquivo inseguros. Quando você baixa um arquivo por certos apps, como Safari, Mail ou Messages, o XProtect automaticamente analisa o arquivo. Se corresponder a qualquer malware conhecido no seu banco de dados, o XProtect irá **impedir que o arquivo seja executado** e alertá-lo sobre a ameaça.

O banco de dados do XProtect é **atualizado regularmente** pela Apple com novas definições de malware, e essas atualizações são baixadas e instaladas automaticamente no seu Mac. Isso garante que o XProtect esteja sempre atualizado com as ameaças conhecidas mais recentes.

No entanto, vale notar que o **XProtect não é uma solução antivírus completa**. Ele verifica apenas uma lista específica de ameaças conhecidas e não realiza on-access scanning como a maioria dos softwares antivírus.

Você pode obter informações sobre a atualização mais recente do XProtect executando:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect está localizado em um local protegido pelo SIP em **/Library/Apple/System/Library/CoreServices/XProtect.bundle** e dentro do bundle você pode encontrar as informações que o XProtect utiliza:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que código com esses cdhashes use entitlements legados.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de plugins e extensões que estão proibidos de carregar via BundleID e TeamID ou indicando uma versão mínima.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Regras Yara para detectar malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Banco de dados SQLite3 com hashes de aplicações bloqueadas e TeamIDs.

Note que existe outro App em **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionado ao XProtect que não está envolvido no processo do Gatekeeper.

> XProtect Remediator: No macOS moderno, a Apple fornece scanners sob demanda (XProtect Remediator) que são executados periodicamente via launchd para detectar e remediar famílias de malware. Você pode observar essas varreduras nos logs unificados:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Não é Gatekeeper

> [!CAUTION]
> Observe que o Gatekeeper **não é executado toda vez** que você executa uma aplicação; apenas o _**AppleMobileFileIntegrity**_ (AMFI) irá **verificar as assinaturas de código executável** quando você executar um app que já foi executado e verificado pelo Gatekeeper.

Portanto, anteriormente era possível executar um app para armazená-lo em cache pelo Gatekeeper, então **modificar arquivos não executáveis da aplicação** (como Electron asar ou arquivos NIB) e, se nenhuma outra proteção estivesse em vigor, a aplicação seria **executada** com as adições **maliciosas**.

No entanto, agora isso não é possível porque o macOS **impede a modificação de arquivos** dentro dos bundles de aplicações. Então, se você tentar o [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack, verá que não é mais possível abusar dele porque após executar o app para armazená-lo em cache pelo Gatekeeper, você não poderá modificar o bundle. E se você alterar, por exemplo, o nome do diretório Contents para NotCon (conforme indicado no exploit), e então executar o binário principal do app para armazená-lo em cache com o Gatekeeper, isso irá gerar um erro e não será executado.

## Bypasses do Gatekeeper

Qualquer forma de burlar o Gatekeeper (conseguir que o usuário baixe algo e o execute quando o Gatekeeper deveria impedi-lo) é considerada uma vulnerabilidade no macOS. Abaixo estão alguns CVEs atribuídos a técnicas que permitiram burlar o Gatekeeper no passado:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Foi observado que se o **Archive Utility** for usado para extração, arquivos com **caminhos excedendo 886 caracteres** não recebem o atributo estendido com.apple.quarantine. Essa situação inadvertidamente permite que esses arquivos **contornem as** verificações de segurança do Gatekeeper.

Consulte o [**relatório original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para mais informações.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Quando uma aplicação é criada com o **Automator**, as informações sobre o que ela precisa para executar ficam dentro de `application.app/Contents/document.wflow` e não no executável. O executável é apenas um binário genérico do Automator chamado **Automator Application Stub**.

Portanto, você poderia fazer `application.app/Contents/MacOS/Automator\ Application\ Stub` **apontar, por meio de um link simbólico, para outro Automator Application Stub dentro do sistema** e ele executará o que está em `document.wflow` (seu script) **sem acionar o Gatekeeper** porque o executável real não possui o xattr de quarantine.

Exemplo do local esperado: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulte o [**relatório original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para mais informações.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

Nesse bypass, um arquivo zip foi criado com uma aplicação começando a compressão a partir de `application.app/Contents` em vez de `application.app`. Portanto, o **atributo de quarantine** foi aplicado a todos os **arquivos de `application.app/Contents`**, mas **não a `application.app`**, que é o que o Gatekeeper verificava; assim, o Gatekeeper foi burlado porque quando `application.app` foi acionado ele **não tinha o atributo de quarantine.**
```bash
zip -r test.app/Contents test.zip
```
Check the [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) for more information.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Mesmo que os componentes sejam diferentes, a exploração desta vulnerabilidade é muito similar à anterior. Neste caso será gerado um Apple Archive a partir de **`application.app/Contents`** de modo que **`application.app` não receberá o quarantine attr** quando descomprimido pelo **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Consulte o [**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para mais informações.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

A ACL **`writeextattr`** pode ser usada para impedir que alguém escreva um atributo em um arquivo:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Além disso, o formato de arquivo **AppleDouble** copia um arquivo incluindo seus ACEs.

No [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) é possível ver que a representação em texto da ACL armazenada no xattr chamado **`com.apple.acl.text`** será definida como ACL no arquivo descomprimido. Então, se você compactou uma aplicação em um arquivo zip com o formato **AppleDouble** com uma ACL que impede que outros xattrs sejam escritos nela... o quarantine xattr não foi definido na aplicação:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Consulte o [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para mais informações.

Observe que isto também poderia ser explorado com AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Foi descoberto que **Google Chrome não estava definindo o atributo de quarentena** em arquivos baixados devido a alguns problemas internos do macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Os formatos AppleDouble armazenam os atributos de um arquivo em um arquivo separado que começa com `._`, isso ajuda a copiar atributos de arquivo **entre máquinas macOS**. No entanto, foi observado que, após descompactar um arquivo AppleDouble, o arquivo que começa com `._` **não recebeu o atributo de quarentena**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Sendo possível criar um arquivo que não tenha o quarantine attribute definido, era **possível contornar o Gatekeeper.** O truque era **criar um DMG file application** usando a convenção de nomes AppleDouble (comece com `._`) e criar um **arquivo visível como um sym link para esse arquivo oculto** sem o quarantine attribute.\
Quando o **dmg file é executado**, como ele não tem o quarantine attribute, ele irá **contornar o Gatekeeper**.
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

Um bypass do Gatekeeper corrigido no macOS Sonoma 14.0 permitia que apps criados especificamente rodassem sem exibir prompt. Detalhes foram divulgados publicamente após a correção e o problema foi explorado ativamente na natureza antes do patch. Garanta que o Sonoma 14.0 ou posterior esteja instalado.

### [CVE-2024-27853]

Um bypass do Gatekeeper no macOS 14.4 (lançado em março de 2024) originado do manuseio de ZIPs maliciosos pelo `libarchive` permitia que apps evadissem a avaliação. Atualize para 14.4 ou posterior, onde a Apple corrigiu o problema.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

An **Automator Quick Action workflow** embutido em um app baixado podia ser acionado sem a avaliação do Gatekeeper, porque workflows eram tratados como dados e executados pelo helper do Automator fora do caminho normal do prompt de notarization. Um `.app` criado sob medida que embala uma Quick Action que roda um shell script (por exemplo, dentro de `Contents/PlugIns/*.workflow/Contents/document.wflow`) podia, portanto, executar imediatamente ao ser aberto. A Apple adicionou um diálogo extra de consentimento e corrigiu o caminho de avaliação em Ventura **13.7**, Sonoma **14.7**, e Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Várias vulnerabilidades em ferramentas de extração populares (por exemplo, The Unarchiver) fizeram com que arquivos extraídos de arquivos compactados perdessem o xattr `com.apple.quarantine`, possibilitando oportunidades de bypass do Gatekeeper. Sempre confie no macOS Archive Utility ou em ferramentas corrigidas ao testar, e valide os xattrs após a extração.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Create a directory containing an app.
- Add uchg to the app.
- Compress the app to a tar.gz file.
- Send the tar.gz file to a victim.
- The victim opens the tar.gz file and runs the app.
- Gatekeeper does not check the app.

### Prevent Quarantine xattr

In an ".app" bundle if the quarantine xattr is not added to it, when executing it **Gatekeeper won't be triggered**.


## References

- Apple Platform Security: Sobre o conteúdo de segurança do macOS Sonoma 14.4 (inclui CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: Como o macOS agora rastreia a proveniência de apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: Sobre o conteúdo de segurança do macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
