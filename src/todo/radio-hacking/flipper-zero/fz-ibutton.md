# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Para mais informações sobre o que é um iButton, consulte:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

A parte **azul** da imagem a seguir é como você precisaria **colocar o iButton real** para que o Flipper possa **lê-lo.** A parte **verde** é como você precisa **tocar o leitor** com o Flipper zero para **emular corretamente um iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

No Modo de Leitura, o Flipper está esperando que a chave iButton toque e é capaz de processar qualquer um dos três tipos de chaves: **Dallas, Cyfral e Metakom**. O Flipper **descobrirá o tipo da chave por conta própria**. O nome do protocolo da chave será exibido na tela acima do número de ID.

### Add manually

É possível **adicionar manualmente** um iButton do tipo: **Dallas, Cyfral e Metakom**

### **Emulate**

É possível **emular** iButtons salvos (lidos ou adicionados manualmente).

> [!NOTE]
> Se você não conseguir fazer os contatos esperados do Flipper Zero tocarem o leitor, você pode **usar o GPIO externo:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
