# Macros do Word

{{#include ../banners/hacktricks-training.md}}

### Código inútil

É muito comum encontrar **código inútil que nunca é usado** para tornar a análise reversa da macro mais difícil.\
Por exemplo, na imagem a seguir, você pode ver que uma condição `If` que nunca será verdadeira é usada para executar código inútil e sem propósito.

![Macros do Word - Código inútil: por exemplo, na imagem a seguir, você pode ver que uma condição If que nunca será verdadeira é usada para executar código inútil e sem propósito](<../images/image (369).png>)

### Formulários de macro

Usando a função **GetObject**, é possível obter dados dos formulários da macro. Isso pode ser usado para dificultar a análise. A seguir, há uma foto de um formulário de macro usado para **ocultar dados dentro de caixas de texto** (uma caixa de texto pode estar ocultando outras caixas de texto):

![Código inútil - Formulários de macro: usando a função GetObject, é possível obter dados dos formulários da macro. Isso pode ser usado para dificultar a análise. A seguir, há uma foto de um...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
