# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Código Lixo

É muito comum encontrar **código lixo que nunca é usado** para dificultar a reversão do macro.\
Por exemplo, na imagem a seguir, você pode ver que um If que nunca será verdadeiro é usado para executar algum código lixo e inútil.

![](<../images/image (369).png>)

### Formulários de Macro

Usando a função **GetObject**, é possível obter dados de formulários do macro. Isso pode ser usado para dificultar a análise. A seguir, está uma foto de um formulário de macro usado para **ocultar dados dentro de caixas de texto** (uma caixa de texto pode estar ocultando outras caixas de texto):

![](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
