# Proteções de Segurança do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper geralmente é usado para se referir à combinação de **Quarantine + Gatekeeper + XProtect**, 3 módulos de segurança do macOS que tentarão **impedir que usuários executem software potencialmente malicioso baixado**.

Mais informações em:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Limitadores de Processos

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

O Sandbox do MacOS **limita os aplicativos** executados dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o app está sendo executado. Isso ajuda a garantir que **o aplicativo acesse apenas os recursos esperados**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** é um framework de segurança. Ele foi projetado para **gerenciar as permissões** dos aplicativos, regulando especificamente o acesso deles a recursos sensíveis. Isso inclui elementos como **serviços de localização, contatos, fotos, microfone, câmera, acessibilidade e acesso total ao disco**. O TCC garante que os apps só possam acessar esses recursos após obter o consentimento explícito do usuário, fortalecendo assim a privacidade e o controle sobre os dados pessoais.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

As launch constraints no macOS são um recurso de segurança para **regular a inicialização de processos**, definindo **quem pode iniciar** um processo, **como** e **a partir de onde**. Introduzidas no macOS Ventura, elas categorizam os binários do sistema em categorias de constraints dentro de um **trust cache**. Cada binário executável possui **regras** definidas para seu **launch**, incluindo constraints **self**, **parent** e **responsible**. Estendidos a apps de terceiros como constraints de **Environment** no macOS Sonoma, esses recursos ajudam a mitigar possíveis explorações do sistema ao controlar as condições de inicialização dos processos.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

O Malware Removal Tool (MRT) é outra parte da infraestrutura de segurança do macOS. Como o nome sugere, a principal função do MRT é **remover malware conhecido de sistemas infectados**.

Quando um malware é detectado em um Mac (pelo XProtect ou por algum outro meio), o MRT pode ser usado para **remover automaticamente o malware**. O MRT opera silenciosamente em segundo plano e normalmente é executado sempre que o sistema é atualizado ou quando uma nova definição de malware é baixada (parece que as regras que o MRT usa para detectar malware estão dentro do binário).

Embora o XProtect e o MRT façam parte das medidas de segurança do macOS, eles desempenham funções diferentes:

- **XProtect** é uma ferramenta preventiva. Ele **verifica os arquivos enquanto são baixados** (por determinados aplicativos) e, se detectar algum tipo conhecido de malware, **impede a abertura do arquivo**, evitando assim que o malware infecte o sistema.
- O **MRT**, por outro lado, é uma **ferramenta reativa**. Ele opera depois que um malware foi detectado em um sistema, com o objetivo de remover o software malicioso e limpar o sistema.

O aplicativo MRT está localizado em **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gerenciamento de Tarefas em Segundo Plano

O **macOS** agora **alerta** sempre que uma ferramenta usa uma **técnica conhecida para persistir a execução de código** (como Login Items, Daemons...), para que o usuário saiba melhor **qual software está persistindo**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Isso é executado com um **daemon** localizado em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` e o **agent** em `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

A maneira como o **`backgroundtaskmanagementd`** sabe que algo está instalado em uma pasta persistente é **obtendo os FSEvents** e criando alguns **handlers** para eles.<sup>[[1]](#references)</sup>

Além disso, há um arquivo plist que contém **aplicativos conhecidos** que frequentemente mantêm persistência, mantido pela Apple e localizado em: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeração

É possível **enumerar todos** os itens de segundo plano configurados usando a ferramenta CLI da Apple:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Além disso, também é possível listar essas informações com o [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Essas informações são armazenadas em **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** e o Terminal precisa de FDA.<sup>[[2]](#references)</sup>

### Interferindo no BTM

Quando uma nova persistência é encontrada, um evento do tipo **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** é gerado. Portanto, qualquer forma de **impedir** que esse **evento** seja enviado ou que o **agent gere um alerta** para o usuário ajudará um atacante a _**bypassar**_ o BTM.<sup>[[1]](#references)</sup>

- **Redefinindo o database**: executar o comando a seguir redefine o database (que deve ser recriado do zero). No entanto, depois disso, **nenhum novo alerta de persistência aparece até que o sistema seja reinicializado**.<sup>[[1]](#references)</sup>
- **root** é necessário.
```bash
# Reset the database
sfltool resettbtm
```
- **Parar o Agent**: É possível enviar um sinal de parada ao agent para que ele **não alerte o usuário** quando novas detecções forem encontradas.<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: Se o **process que criou a persistence sair imediatamente depois**, o daemon tenta **obter informações** sobre ele, **falha** e **não consegue enviar o evento** indicando que um novo item está persistindo.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Desmistificando (e contornando) o gerenciamento de tarefas em segundo plano do macOS" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Nova ferramenta (para desenvolvedores): "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Gerenciar itens de login e tarefas em segundo plano no Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
