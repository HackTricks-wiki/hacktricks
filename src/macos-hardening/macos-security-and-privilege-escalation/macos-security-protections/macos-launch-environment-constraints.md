# Restrições de Lançamento/Ambiente do macOS e Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

As restrições de lançamento no macOS foram introduzidas para aumentar a segurança, **regulando como, por quem e de onde um processo pode ser iniciado**. Introduzidas no macOS Ventura, elas fornecem uma estrutura que categoriza **cada binário do sistema em categorias de restrição distintas**, definidas no **trust cache**, uma lista que contém binários do sistema e seus respectivos hashes. Essas restrições se aplicam a todos os binários executáveis do sistema e incluem um conjunto de **regras** que definem os requisitos para **iniciar um determinado binário**. As regras abrangem restrições próprias que um binário precisa satisfazer, restrições do processo pai que precisam ser atendidas pelo processo pai e restrições de responsabilidade que devem ser cumpridas por outras entidades relevantes.<sup>[[1]](#references)[[4]](#references)</sup>

O mecanismo também se aplica a apps de terceiros por meio de **Environment Constraints**, a partir do macOS Sonoma, permitindo que os desenvolvedores protejam seus apps ao especificar um **conjunto de chaves e valores para restrições de ambiente**.<sup>[[5]](#references)</sup>

Você define **restrições de ambiente de lançamento e de bibliotecas** em dicionários de restrições que são salvos em arquivos de lista de propriedades do **`launchd`** ou em arquivos de lista de propriedades **separados**, usados na assinatura de código.<sup>[[5]](#references)</sup>

Há 4 tipos de restrições:

- **Self Constraints**: restrições aplicadas ao binário **em execução**.
- **Parent Process**: restrições aplicadas ao **processo pai do processo** (por exemplo, **`launchd`** executando um serviço XP)
- **Responsible Constraints**: restrições aplicadas ao **processo que chama o serviço** em uma comunicação XPC
- **Library load constraints**: use restrições de carregamento de bibliotecas para descrever seletivamente o código que pode ser carregado

Assim, quando um processo tenta iniciar outro processo — chamando `execve(_:_:_:)` ou `posix_spawn(_:_:_:_:_:_:)` — o sistema operacional verifica se o arquivo **executável** **satisfaz** sua **própria restrição**. Ele também verifica se o executável do **processo pai** **satisfaz a restrição de processo pai** do executável e se o executável do processo **responsável** **satisfaz a restrição de processo responsável** do executável. Se alguma dessas restrições de lançamento não for satisfeita, o sistema operacional não executa o programa.

Se qualquer parte da **restrição da biblioteca** não for verdadeira durante o carregamento de uma biblioteca, seu processo **não carregará** a biblioteca.

## Categorias de LC

Uma LC é composta de **fatos** e **operações lógicas** (and, or...) que combinam fatos.

Os [**fatos que uma LC pode usar estão documentados**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Por exemplo:

- is-init-proc: valor booleano que indica se o executável precisa ser o processo de inicialização do sistema operacional (`launchd`).
- is-sip-protected: valor booleano que indica se o executável precisa ser um arquivo protegido pelo System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` valor booleano que indica se o sistema operacional carregou o executável de um volume APFS autorizado e autenticado.
- `on-authorized-authapfs-volume`: valor booleano que indica se o sistema operacional carregou o executável de um volume APFS autorizado e autenticado.
  - Volume Cryptexes
- `on-system-volume:`valor booleano que indica se o sistema operacional carregou o executável do volume do sistema atualmente inicializado.
  - Dentro de /System...
- ...

Quando um binário da Apple é assinado, ele **é atribuído a uma categoria de LC** dentro do **trust cache**.

- As [**categorias de LC do iOS 16 foram analisadas e documentadas aqui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- As **categorias de LC atuais (macOS 14** - Somona) foram analisadas, e suas [**descrições podem ser encontradas aqui**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Por exemplo, a categoria 1 é:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Deve estar no volume System ou Cryptexes.
- `launch-type == 1`: Deve ser um serviço do sistema (plist em LaunchDaemons).
- `validation-category == 1`: Um executável do sistema operacional.
- `is-init-proc`: Launchd

### Engenharia reversa das categorias LC

Você encontra mais informações [**aqui**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), mas, basicamente, elas são definidas no **AMFI (AppleMobileFileIntegrity)**. Portanto, você precisa baixar o Kernel Development Kit para obter o **KEXT**. Os símbolos que começam com **`kConstraintCategory`** são os **mais interessantes**. Ao extraí-los, você obterá um fluxo codificado em DER (ASN.1), que precisará decodificar com [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) ou com a biblioteca python-asn1 e seu script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), que fornecerá uma string mais compreensível.<sup>[[3]](#references)[[8]](#references)</sup>

## Restrições de ambiente

Estas são as Launch Constraints configuradas em **aplicativos de terceiros**. O desenvolvedor pode selecionar os **fatos** e **operandos lógicos a serem usados** em seu aplicativo para restringir o acesso a ele.

É possível enumerar as Environment Constraints de um aplicativo com:

```bash
codesign -d -vvvv app.app
```

## Caches de confiança

No **macOS**, existem alguns caches de confiança:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

No iOS, parece estar em **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> No macOS em execução em dispositivos Apple Silicon, se um binário assinado pela Apple não estiver no cache de confiança, o AMFI se recusará a carregá-lo.

### Enumerando caches de confiança

Os arquivos de cache de confiança acima estão no formato **IMG4** e **IM4P**; IM4P é a seção de payload de um formato IMG4.

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

(Uma outra opção seria usar a ferramenta [**img4tool**](https://github.com/tihmstar/img4tool), que funciona até mesmo no M1, apesar de a versão ser antiga, e em x86_64, se você a instalar nos locais corretos).

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

O trust cache segue a seguinte estrutura, então **a categoria LC é a 4ª coluna**.

```c
struct trust_cache_entry2 {
	uint8_t cdhash[CS_CDHASH_LEN];
	uint8_t hash_type;
	uint8_t flags;
	uint8_t constraintCategory;
	uint8_t reserved0;
} __attribute__((__packed__));
```

Então, você poderia usar um script como [**este**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) para extrair os dados.

Com esses dados, você pode verificar os apps com um **valor de launch constraints igual a `0`**, que são os que não têm restrições ([**veja aqui**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) o significado de cada valor).<sup>[[6]](#references)</sup>

## Mitigações de ataques

Launch Constraints teriam mitigado vários ataques antigos ao **garantir que o processo não fosse executado em condições inesperadas**: por exemplo, a partir de locais inesperados ou invocado por um processo pai inesperado (caso somente o launchd devesse iniciá-lo).

Além disso, Launch Constraints também **mitigam ataques de downgrade**.

No entanto, elas **não mitigam abusos comuns de XPC**, injeções de código em **Electron** ou **injeções de dylib** sem validação de bibliotecas (a menos que os IDs de equipe autorizados a carregar bibliotecas sejam conhecidos).<sup>[[3]](#references)</sup>

### Proteção de daemons XPC

Na versão Sonoma, um ponto notável é a configuração de **responsabilidade** do serviço XPC do daemon. O serviço XPC é responsável por si mesmo, em vez de o cliente que se conecta ser responsável. Isso está documentado no relatório de feedback FB13206884. Essa configuração pode parecer falha, pois permite certas interações com o serviço XPC:

- **Iniciar o serviço XPC**: Se isso for considerado um bug, essa configuração não permite iniciar o serviço XPC por meio de código do atacante.
- **Conectar-se a um serviço ativo**: Se o serviço XPC já estiver em execução (possivelmente ativado pelo aplicativo original), não há barreiras para se conectar a ele.

Embora implementar restrições no serviço XPC possa ser benéfico por **reduzir a janela para possíveis ataques**, isso não resolve a preocupação principal. Para garantir a segurança do serviço XPC, é fundamental **validar adequadamente o cliente que se conecta**. Esse continua sendo o único método para reforçar a segurança do serviço. Também vale notar que a configuração de responsabilidade mencionada está atualmente em funcionamento, o que talvez não corresponda ao design pretendido.<sup>[[3]](#references)</sup>

### Proteção do Electron

Mesmo que seja exigido que o aplicativo seja **aberto pelo LaunchService** (nas restrições do processo pai), isso pode ser feito usando **`open`** (que pode definir variáveis de ambiente) ou a **API Launch Services** (na qual é possível indicar variáveis de ambiente).<sup>[[3]](#references)</sup>

Para conhecer o mecanismo MACF geral por trás dos atributos de criação de processos específicos de políticas, consulte [atributos de criação de processos específicos de políticas MACF](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 - Substituição das restrições integradas no momento da criação do processo

As launch constraints (oficialmente **requisitos de código leves**, *LWCR*) são impostas pela **política MAC do AMFI**. `posix_spawn` permite que um chamador passe um blob arbitrário para uma política MAC por meio de **`posix_spawnattr_setmacpolicyinfo_np()`**, e o AMFI aceitava um dicionário LWCR fornecido pelo chamador por esse caminho. O bug era que as **restrições fornecidas pelo atacante substituíam as restrições integradas ao binário**, em vez de serem verificadas em conjunto com elas:

- Crie um dicionário mínimo (até mesmo vazio) de launch constraints.
- Defina a **categoria da restrição como `127`**, um valor que o AMFI permite nos atributos de criação de processos, mas **não impõe** — ele apenas registra `Launch Constraint Violation (not enforcing)` em vez de bloquear a execução.
- Passe o dicionário pelos atributos de criação de processos, e o processo será iniciado em um contexto que suas restrições reais de processo e de processo pai teriam proibido.

Após a correção, **ambas** as restrições — as integradas e as fornecidas — são validadas, portanto o dicionário fornecido não pode mais enfraquecer as restrições integradas.<sup>[[2]](#references)</sup>

> [!TIP]
> Este é o padrão geral a procurar ao auditar a aplicação de restrições: uma API que permite que entradas não confiáveis *forneçam* uma política tende a ser interessante sempre que o mecanismo de políticas trata o valor fornecido como uma substituição, e não como um requisito adicional.



## References

- [1] [Objective by the Sea #OBTS v6.0 Dia 2 (transmissão ao vivo)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Contornando Launch Constraints no macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Análise aprofundada de Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Por que um app ou uma ferramenta de sistema não é executado? Launch constraints e caches de confiança - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Proteja seu app para Mac com restrições de ambiente - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Descrição das Launch Constraints introduzidas no iOS 16 (gist de LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints do macOS Sonoma (14) (gist de theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Além dos bons e velhos LaunchAgents - saiba mais aqui](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
