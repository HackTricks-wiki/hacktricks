# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Para mais informações sobre o que é um iButton, consulte:


{{#ref}}
../ibutton.md
{{#endref}}

## Design

A parte **azul** da imagem a seguir mostra como você deve **posicionar o iButton real** para que o Flipper possa **lê-lo.** A parte **verde** mostra como você deve **encostar o leitor** no Flipper Zero para **emular corretamente um iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Ações

### Ler

No modo de leitura, o Flipper aguarda que a chave iButton seja encostada e é capaz de processar três tipos de chaves: **Dallas, Cyfral e Metakom**. O Flipper **identificará o tipo da chave automaticamente**. O nome do protocolo da chave será exibido na tela, acima do número de ID.<sup>[[1]](#references)</sup>

### Adicionar manualmente

É possível **adicionar manualmente** um iButton dos tipos: **Dallas, Cyfral e Metakom**

### **Emular**

É possível **emular** iButtons salvos (lidos ou adicionados manualmente).

> [!TIP]
> Se você não conseguir fazer com que os contatos esperados do Flipper Zero encostem no leitor, poderá **usar o GPIO externo:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Referências

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
