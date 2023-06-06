# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução <a href="#9wrzi" id="9wrzi"></a>

Para informações sobre RFID e NFC, consulte a seguinte página:

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## Cartões NFC suportados <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
Além dos cartões NFC, o Flipper Zero suporta **outro tipo de cartões de alta frequência** como vários **Mifare** Classic e Ultralight e **NTAG**.
{% endhint %}

Novos tipos de cartões NFC serão adicionados à lista de cartões suportados. O Flipper Zero suporta os seguintes **tipos de cartões NFC tipo A** (ISO 14443A):

* ﻿**Cartões bancários (EMV)** - apenas lê UID, SAK e ATQA sem salvar.
* ﻿**Cartões desconhecidos** - lê (UID, SAK, ATQA) e emula um UID.

Para **cartões NFC tipo B, tipo F e tipo V**, o Flipper Zero é capaz de ler um UID sem salvá-lo.

### Cartões NFC tipo A <a href="#uvusf" id="uvusf"></a>

#### Cartão bancário (EMV) <a href="#kzmrp" id="kzmrp"></a>

O Flipper Zero só pode ler um UID, SAK, ATQA e dados armazenados em cartões bancários **sem salvar**.

Tela de leitura de cartão bancárioPara cartões bancários, o Flipper Zero só pode ler dados **sem salvá-los e emulá-los**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Cartões desconhecidos <a href="#37eo8" id="37eo8"></a>

Quando o Flipper Zero é **incapaz de determinar o tipo de cartão NFC**, então apenas um **UID, SAK e ATQA** podem ser **lidos e salvos**.

Tela de leitura de cartão desconhecidoPara cartões NFC desconhecidos, o Flipper Zero só pode emular um UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### Cartões NFC tipos B, F e V <a href="#wyg51" id="wyg51"></a>

Para **cartões NFC tipos B, F e V**, o Flipper Zero só pode **ler e exibir um UID** sem salvá-lo.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Ações

Para uma introdução sobre NFC, [**leia esta página**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Leitura

O Flipper Zero pode **ler cartões NFC**, no entanto, ele **não entende todos os protocolos** baseados em ISO 14443. No entanto, como o **UID é um atributo de baixo nível**, você pode se encontrar em uma situação em que o **UID já foi lido, mas o protocolo de transferência de dados de alto nível ainda é desconhecido**. Você pode ler, emular e inserir manualmente o UID usando o Flipper para os leitores primitivos que usam o UID para autorização.

#### Leitura do UID vs Leitura dos Dados Internos <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

No Flipper, a leitura de tags de 13,56 MHz pode ser dividida em duas partes:

* **Leitura de
