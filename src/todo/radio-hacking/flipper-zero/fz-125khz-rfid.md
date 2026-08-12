# FZ - RFID de 125 kHz

{{#include ../../../banners/hacktricks-training.md}}

## Introdução

Para obter informações básicas sobre como funcionam as tags de 125 kHz, consulte:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

A [introdução às RFID de baixa frequência](../pentesting-rfid.md#low-frequency-rfid-tags-125khz) explica as famílias comuns de tags e seus formatos de dados.

## Ações

### Ler

Use **Ler** para capturar os dados da tag. Após uma leitura bem-sucedida, o Flipper Zero pode emular a tag salva.<sup>[[1]](#references)</sup>

> [!WARNING]
> Alguns leitores de intercomunicadores tentam detectar tags duplicadas graváveis emitindo um comando de gravação antes da leitura. Uma emulação do Flipper Zero não expõe a memória gravável da tag da mesma forma.<sup>[[1]](#references)</sup>

### Adicionar manualmente

Você pode inserir manualmente os dados da tag no Flipper Zero, salvá-los e, em seguida, emulá-la.<sup>[[1]](#references)</sup>

#### IDs em cartões

Às vezes, um cartão tem todo o seu ID, ou parte dele, impresso na parte externa.

- **EM Marin**

Por exemplo, o cartão EM-Marin ilustrado expõe os três últimos de seus cinco bytes de ID. Se não for possível ler a tag, os dois bytes ausentes poderão ser obtidos por brute-force.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Da mesma forma, o cartão HID ilustrado imprime apenas dois dos três bytes de ID.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emular/Gravar

Após ler uma tag ou inserir manualmente seu ID, o Flipper Zero pode emular a credencial salva. Para tags graváveis compatíveis, ele também pode gravar os dados salvos em um cartão compatível.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: Explorando os Protocolos RFID](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
