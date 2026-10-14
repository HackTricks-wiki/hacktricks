# FZ - RFID de 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Para saber como funcionam as tags de 125 kHz, consulte:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

A [introdução a RFID de baixa frequência](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) explica as famílias comuns de tags e seus formatos de dados.

## Ações

### Ler

Use **Ler** para capturar os dados da tag. Após uma leitura bem-sucedida, o Flipper Zero pode emular a tag salva.<sup>[[1]](#references)</sup>

> [!WARNING]
> Alguns leitores de interfone tentam detectar tags duplicadas graváveis enviando um comando de gravação antes da leitura. A emulação do Flipper Zero não expõe a memória gravável da tag da mesma forma.<sup>[[1]](#references)</sup>

### Adicionar manualmente

Você pode inserir manualmente os dados da tag no Flipper Zero, salvá-los e, em seguida, emulá-la.<sup>[[1]](#references)</sup>

#### IDs em cartões

Às vezes, todo ou parte do ID de um cartão está impresso na parte externa.

- **EM Marin**

Por exemplo, o cartão EM-Marin mostrado na imagem exibe os três últimos dos seus cinco bytes de ID. Se a tag não puder ser lida, os dois bytes ausentes podem ser encontrados por força bruta.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Da mesma forma, o cartão HID mostrado na imagem exibe apenas dois dos três bytes de ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emular/Gravar

Depois de ler uma tag ou inserir seu ID manualmente, o Flipper Zero pode emular a credencial salva. Para tags graváveis compatíveis, também pode gravar os dados salvos em um cartão compatível.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Mergulhando nos protocolos RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
