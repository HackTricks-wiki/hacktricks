## Informação Básica

Basicamente, um bundle é uma **estrutura de diretório** dentro do sistema de arquivos. Curiosamente, por padrão, este diretório **parece ser um único objeto no Finder**.

O bundle mais **comum** que encontraremos é o **`.app` bundle**, mas muitos outros executáveis também são empacotados como bundles, como **`.framework`** e **`.systemextension`** ou **`.kext`**.

Os tipos de recursos contidos em um bundle podem consistir em aplicativos, bibliotecas, imagens, documentação, arquivos de cabeçalho, etc. Todos esses arquivos estão dentro de `<application>.app/Contents/`.
```bash
ls -lR /Applications/Safari.app/Contents
```
*   `Contents/_CodeSignature`

    Contém informações de **assinatura de código** sobre o aplicativo (ou seja, hashes, etc.).
*   `Contents/MacOS`

    Contém o **binário do aplicativo** (que é executado quando o usuário clica duas vezes no ícone do aplicativo na interface do usuário).
*   `Contents/Resources`

    Contém **elementos da interface do usuário do aplicativo**, como imagens, documentos e arquivos nib/xib (que descrevem várias interfaces do usuário).
* `Contents/Info.plist`\
  O “**arquivo de configuração principal**” do aplicativo. A Apple observa que “o sistema depende da presença deste arquivo para identificar informações relevantes sobre o aplicativo e quaisquer arquivos relacionados”.
  * **Arquivos** **plist** contêm informações de configuração. Você pode encontrar informações sobre o significado das chaves plist em [https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)
  *   Pares que podem ser de interesse ao analisar um aplicativo incluem:\\

      * **CFBundleExecutable**

      Contém o **nome do binário do aplicativo** (encontrado em Contents/MacOS).

      * **CFBundleIdentifier**

      Contém o identificador de pacote do aplicativo (frequentemente usado pelo sistema para **identificar** globalmente o aplicativo).

      * **LSMinimumSystemVersion**

      Contém a **versão mais antiga** do **macOS** com a qual o aplicativo é compatível.
