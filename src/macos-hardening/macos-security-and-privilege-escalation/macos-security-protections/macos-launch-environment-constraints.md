# Restrições de Launch/Environment do macOS e Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

As launch constraints no macOS foram introduzidas para aumentar a segurança, **regulando como, por quem e de onde um processo pode ser iniciado**. Introduzidas no macOS Ventura, elas fornecem uma estrutura que categoriza **cada binário do sistema em categorias distintas de restrições**, definidas dentro do **trust cache**, uma lista que contém os binários do sistema e seus respectivos hashes​. Essas restrições se estendem a todos os binários executáveis do sistema, envolvendo um conjunto de **regras** que delineiam os requisitos para **iniciar um determinado binário**. As regras abrangem self constraints que um binário deve satisfazer, parent constraints que precisam ser atendidas pelo processo pai e responsible constraints que devem ser obedecidas por outras entidades relevantes​.

O mecanismo se estende a aplicativos de terceiros por meio de **Environment Constraints**, a partir do macOS Sonoma, permitindo que os desenvolvedores protejam seus aplicativos especificando um **conjunto de chaves e valores para environment constraints.**

Você define **launch environment e library constraints** em dicionários de restrições que salva em arquivos de lista de propriedades do **`launchd`** ou em arquivos de **lista de propriedades separados** usados em code signing.

Existem 4 tipos de constraints:

- **Self Constraints**: Restrições aplicadas ao binário **em execução**.
- **Parent Process**: Restrições aplicadas ao **processo pai** do processo (por exemplo, o **`launchd`** executando um serviço XP)
- **Responsible Constraints**: Restrições aplicadas ao **processo que chama o serviço** em uma comunicação XPC
- **Library load constraints**: Use library load constraints para descrever seletivamente o código que pode ser carregado

Assim, quando um processo tenta iniciar outro processo — chamando `execve(_:_:_:)` ou `posix_spawn(_:_:_:_:_:_:)` — o sistema operacional verifica se o arquivo **executável** **satisfaz sua própria self constraint**. Ele também verifica se o executável do processo **pai** **satisfaz a parent constraint** do executável e se o executável do processo **responsável** **satisfaz a responsible process constraint** do executável. Se alguma dessas launch constraints não for satisfeita, o sistema operacional não executa o programa.

Se, ao carregar uma library, qualquer parte da **library constraint não for verdadeira**, seu processo **não carregará** a library.

## Categorias de LC

Uma LC é composta por **facts** e **operações lógicas** (and, or...) que combinam facts.

Os[ **facts que uma LC pode usar estão documentados**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Por exemplo:

- is-init-proc: Um valor Boolean que indica se o executável deve ser o processo de inicialização do sistema operacional (`launchd`).
- is-sip-protected: Um valor Boolean que indica se o executável deve ser um arquivo protegido pelo System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Um valor Boolean que indica se o sistema operacional carregou o executável de um volume APFS autorizado e autenticado.
- `on-authorized-authapfs-volume`: Um valor Boolean que indica se o sistema operacional carregou o executável de um volume APFS autorizado e autenticado.
- Cryptexes volume
- `on-system-volume:`Um valor Boolean que indica se o sistema operacional carregou o executável do volume do sistema atualmente inicializado.
- Dentro de /System...
- ...

Quando um binário da Apple é assinado, ele **o atribui a uma categoria de LC** dentro do **trust cache**.

- As **categorias de LC do iOS 16** foram [**revertidas e documentadas aqui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- As **categorias de LC atuais (macOS 14** - Somona) foram revertidas, e suas [**descrições podem ser encontradas aqui**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Por exemplo, a Category 1 é:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Deve estar no volume System ou Cryptexes.
- `launch-type == 1`: Deve ser um serviço do sistema (plist em LaunchDaemons).
- `validation-category == 1`: Um executável do sistema operacional.
- `is-init-proc`: Launchd

### Reversing LC Categories

Você encontra mais informações [**sobre isso aqui**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), mas, basicamente, elas são definidas no **AMFI (AppleMobileFileIntegrity)**, portanto, é necessário baixar o Kernel Development Kit para obter o **KEXT**. Os símbolos que começam com **`kConstraintCategory`** são os **interessantes**. Ao extraí-los, você obterá um fluxo codificado em DER (ASN.1), que precisará ser decodificado com [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ou com a biblioteca python-asn1 e seu script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), que fornecerá uma string mais compreensível.<sup>[[3]](#references)</sup>

## Restrições de Ambiente

Estas são as Launch Constraints configuradas em **aplicativos de terceiros**. O desenvolvedor pode selecionar os **fatos** e os **operandos lógicos a serem usados** em seu aplicativo para restringir o acesso a ele.

É possível enumerar as Environment Constraints de um aplicativo com:
```bash
codesign -d -vvvv app.app
```
## Caches de confiança

No **macOS**, existem alguns caches de confiança:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

No iOS, parece que ele está em **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> No macOS executado em dispositivos Apple Silicon, se um binário assinado pela Apple não estiver no trust cache, o AMFI se recusará a carregá-lo.

### Enumerando Caches de confiança

Os arquivos de trust cache anteriores estão no formato **IMG4** e **IM4P**, sendo IM4P a seção de payload de um formato IMG4.

Você pode usar [**pyimg4**](https://github.com/m1stadev/PyIMG4) para extrair o payload dos bancos de dados:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Uma outra opção seria usar a ferramenta [**img4tool**](https://github.com/tihmstar/img4tool), que funcionará até mesmo em M1, embora o release seja antigo, e em x86_64 se você a instalar nos locais corretos).

Agora você pode usar a ferramenta [**trustcache**](https://github.com/CRKatri/trustcache) para obter as informações em um formato legível:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
O trust cache segue a seguinte estrutura, portanto, a **categoria LC é a 4ª coluna**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Então, você poderia usar um script como [**este**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) para extrair dados.

A partir desses dados, você pode verificar os Apps com um **valor de Launch Constraints igual a `0`**, que são aqueles que não possuem restrições ([**verifique aqui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) o significado de cada valor).<sup>[[6]](#references)</sup>

## Mitigações contra ataques

As Launch Constraints teriam mitigado vários ataques antigos ao **garantir que o processo não fosse executado em condições inesperadas:** por exemplo, a partir de locais inesperados ou sendo invocado por um processo pai inesperado (caso apenas o launchd devesse iniciá-lo).

Além disso, as Launch Constraints também **mitigam ataques de downgrade.**

No entanto, elas **não mitigam abusos comuns de XPC**, injeções de código **Electron** ou **injeções de dylib** sem validação de biblioteca (a menos que os team IDs que podem carregar bibliotecas sejam conhecidos).<sup>[[3]](#references)</sup>

### Proteção de Daemons XPC

Na versão Sonoma, um ponto notável é a **configuração de responsabilidade** do serviço XPC do daemon. O serviço XPC é responsável por si próprio, em oposição ao cliente que se conecta ser o responsável. Isso está documentado no relatório de feedback FB13206884. Essa configuração pode parecer falha, pois permite certas interações com o serviço XPC:

- **Inicialização do Serviço XPC**: Se for considerado um bug, essa configuração não permite iniciar o serviço XPC por meio de código do atacante.
- **Conexão a um Serviço Ativo**: Se o serviço XPC já estiver em execução (possivelmente ativado pelo aplicativo original), não há barreiras para conectar-se a ele.

Embora implementar restrições no serviço XPC possa ser benéfico ao **reduzir a janela para possíveis ataques**, isso não resolve a preocupação principal. Garantir a segurança do serviço XPC exige fundamentalmente **validar efetivamente o cliente que se conecta**. Esse continua sendo o único método para reforçar a segurança do serviço. Além disso, vale observar que a configuração de responsabilidade mencionada está atualmente operacional, o que pode não estar alinhado ao design pretendido.<sup>[[3]](#references)</sup>

### Proteção do Electron

Mesmo que seja exigido que o aplicativo tenha de ser **aberto pelo LaunchService** (nas restrições dos processos pais). Isso pode ser feito usando **`open`** (que pode definir variáveis de ambiente) ou usando a **API do Launch Services** (na qual as variáveis de ambiente podem ser indicadas).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Substituição das restrições integradas no momento do spawn

As Launch Constraints (oficialmente **lightweight code requirements**, *LWCR*) são aplicadas pela **política MAC do AMFI**. `posix_spawn` permite que um chamador forneça um blob arbitrário a uma política MAC por meio de **`posix_spawnattr_setmacpolicyinfo_np()`**, e o AMFI aceitava um dicionário LWCR fornecido pelo chamador por esse caminho. O bug consistia no fato de que as **restrições fornecidas pelo atacante substituíam as restrições integradas do binário**, em vez de serem verificadas além delas:

- Criar um dicionário mínimo (até mesmo vazio) de launch constraints.
- Definir a **categoria de restrição como `127`**, um valor que o AMFI permite nos atributos de spawn, mas **não aplica** — ele apenas registra `Launch Constraint Violation (not enforcing)` em vez de bloquear a execução.
- Passá-lo pelos atributos de spawn; assim, o processo é iniciado em um contexto que suas restrições reais de self/parent teriam proibido.

Após a correção, **tanto as restrições integradas quanto as fornecidas são validadas**, portanto o dicionário fornecido não pode mais enfraquecer as restrições integradas.<sup>[[2]](#references)</sup>

> [!TIP]
> Este é o padrão geral a ser procurado ao auditar a aplicação de restrições: uma API que permite que uma entrada não confiável *forneça* uma política tende a ser interessante sempre que o mecanismo de políticas trata o valor fornecido como uma substituição, em vez de um requisito adicional.

## Referências

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
