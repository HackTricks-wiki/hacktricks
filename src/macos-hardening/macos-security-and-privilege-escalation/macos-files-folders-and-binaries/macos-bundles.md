# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

Bundles no macOS servem como contêineres para uma variedade de recursos, incluindo aplicativos, bibliotecas e outros arquivos necessários, fazendo com que apareçam como objetos únicos no Finder, como os familiares arquivos `*.app`. O bundle mais comumente encontrado é o bundle `.app`, embora outros tipos como `.framework`, `.systemextension` e `.kext` também sejam prevalentes.

### Componentes Essenciais de um Bundle

Dentro de um bundle, particularmente no diretório `<application>.app/Contents/`, uma variedade de recursos importantes está armazenada:

- **\_CodeSignature**: Este diretório armazena detalhes de assinatura de código vitais para verificar a integridade do aplicativo. Você pode inspecionar as informações de assinatura de código usando comandos como: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
- **MacOS**: Contém o binário executável do aplicativo que é executado ao interagir com o usuário.
- **Resources**: Um repositório para os componentes da interface do usuário do aplicativo, incluindo imagens, documentos e descrições da interface (arquivos nib/xib).
- **Info.plist**: Funciona como o arquivo de configuração principal do aplicativo, crucial para que o sistema reconheça e interaja com o aplicativo de forma apropriada.

#### Chaves Importantes em Info.plist

O arquivo `Info.plist` é uma pedra angular para a configuração do aplicativo, contendo chaves como:

- **CFBundleExecutable**: Especifica o nome do arquivo executável principal localizado no diretório `Contents/MacOS`.
- **CFBundleIdentifier**: Fornece um identificador global para o aplicativo, amplamente utilizado pelo macOS para gerenciamento de aplicativos.
- **LSMinimumSystemVersion**: Indica a versão mínima do macOS necessária para o aplicativo ser executado.

### Explorando Bundles

Para explorar o conteúdo de um bundle, como `Safari.app`, o seguinte comando pode ser usado: `bash ls -lR /Applications/Safari.app/Contents`

Essa exploração revela diretórios como `_CodeSignature`, `MacOS`, `Resources`, e arquivos como `Info.plist`, cada um servindo a um propósito único, desde a segurança do aplicativo até a definição de sua interface do usuário e parâmetros operacionais.

#### Diretórios Adicionais de Bundles

Além dos diretórios comuns, bundles também podem incluir:

- **Frameworks**: Contém frameworks agrupados usados pelo aplicativo. Frameworks são como dylibs com recursos extras.
- **PlugIns**: Um diretório para plug-ins e extensões que aprimoram as capacidades do aplicativo.
- **XPCServices**: Armazena serviços XPC usados pelo aplicativo para comunicação fora do processo.

Essa estrutura garante que todos os componentes necessários estejam encapsulados dentro do bundle, facilitando um ambiente de aplicativo modular e seguro.

Para informações mais detalhadas sobre as chaves `Info.plist` e seus significados, a documentação do desenvolvedor da Apple fornece recursos extensivos: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{{#include ../../../banners/hacktricks-training.md}}
