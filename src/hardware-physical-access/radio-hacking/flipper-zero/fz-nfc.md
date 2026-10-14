# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Introdução <a href="#id-9wrzi" id="id-9wrzi"></a>

Para informações sobre RFID e NFC, consulte a página a seguir:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Cartões NFC compatíveis <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Além de cartões NFC, o Flipper Zero é compatível com **outros tipos de cartões de alta frequência**, como vários cartões **Mifare** Classic e Ultralight e **NTAG**.

A lista de recursos abaixo descreve o firmware documentado pelo artigo original e não deve ser considerada a matriz de compatibilidade completa e atual. O firmware do Flipper adicionou protocolos e mudou o comportamento de NFC ao longo do tempo; consulte a documentação oficial atual para o firmware instalado.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Cartões bancários (EMV)** — apenas lê UID, SAK e ATQA, sem salvar.
- **Cartões desconhecidos** — lê UID, SAK e ATQA e emula um UID.

Para **cartões NFC dos tipos B, F e V**, o firmware documentado podia ler um UID sem salvá-lo.

### Cartões NFC do tipo A <a href="#uvusf" id="uvusf"></a>

#### Cartão bancário (EMV) <a href="#kzmrp" id="kzmrp"></a>

O firmware documentado podia ler UID, SAK, ATQA e os dados de aplicação disponíveis de um cartão bancário **sem salvá-los**.

Para esses cartões bancários, o firmware exibia os dados sem salvar nem emular o cartão.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Cartões desconhecidos <a href="#id-37eo8" id="id-37eo8"></a>

Quando o Flipper Zero **não consegue determinar o tipo de cartão NFC**, somente o **UID, SAK e ATQA** podem ser **lidos e salvos**.

Para um cartão NFC desconhecido, esse modo pode emular apenas o UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Cartões NFC dos tipos B, F e V <a href="#wyg51" id="wyg51"></a>

No firmware documentado pelo artigo original, só era possível ler e exibir o identificador dos cartões NFC dos tipos B, F e V, sem salvá-lo.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Ações

Para uma introdução sobre NFC, [**leia esta página**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Ler

O Flipper Zero pode ler cartões NFC, mas não implementa todos os protocolos de nível superior baseados em ISO 14443. Portanto, pode recuperar o UID, SAK e ATQA de baixo nível, mas não identificar o protocolo de aplicação. Em sistemas de controle de acesso básicos que autorizam apenas pelo UID, a ferramenta pode ler, inserir manualmente e emular esse identificador; sistemas com autenticação criptográfica exigem mais do que um UID copiado.<sup>[[1]](#references)</sup>

#### Ler o UID VS Ler os Dados Internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

No Flipper, a leitura de tags de 13,56 MHz pode ser dividida em duas partes:<sup>[[1]](#references)</sup>

- **Leitura de baixo nível** — lê apenas o UID, SAK e ATQA. O Flipper tenta deduzir o protocolo de nível superior com base nos dados lidos do cartão. Não é possível ter 100% de certeza, pois isso é apenas uma suposição baseada em determinados fatores.
- **Leitura de alto nível** — lê os dados da memória do cartão usando um protocolo específico de alto nível. Isso inclui ler os dados de um Mifare Ultralight, ler os setores de um Mifare Classic ou ler os atributos do cartão no PayPass/Apple Pay.

### Leitura específica

Caso o Flipper Zero não consiga identificar o tipo de cartão com os dados de baixo nível, em `Extra Actions` você pode selecionar `Read Specific Card Type` e **indicar manualmente o tipo de cartão que deseja ler**.

#### Cartões bancários EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Firmwares mais antigos do Flipper e cartões EMV compatíveis podiam expor mais do que o UID, possivelmente incluindo o PAN, a data de validade, o nome do titular do cartão ou o histórico de transações, quando esses registros eram disponibilizados pelo cartão. A disponibilidade varia conforme o cartão, a aplicação e o firmware. O CVV da tarja magnética impresso no cartão não é exposto dessa forma, e a leitura desses registros não clona os recursos criptográficos de transação necessários para realizar um pagamento por aproximação.<sup>[[1]](#references)</sup>

## References

- [1] [Explorando protocolos RFID com Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Documentação do Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
