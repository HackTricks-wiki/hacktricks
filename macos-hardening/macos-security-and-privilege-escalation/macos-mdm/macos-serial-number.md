<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Dispositivos Apple fabricados após 2010 geralmente têm números de série alfanuméricos de **12 caracteres**, com os **três primeiros dígitos representando o local de fabricação**, os **dois seguintes indicando o ano** e a **semana** de fabricação, os **próximos três dígitos fornecendo um identificador único** e os **últimos quatro dígitos representando o número do modelo**.

Exemplo de número de série: **C02L13ECF8J2**

## **3 - Locais de fabricação**

| Código | Fábrica |
| :--- | :--- |
| FC | Fountain Colorado, EUA |
| F | Fremont, Califórnia, EUA |
| XA, XB, QP, G8 | EUA |
| RN | México |
| CK | Cork, Irlanda |
| VM | Foxconn, Pardubice, República Tcheca |
| SG, E | Cingapura |
| MB | Malásia |
| PT, CY | Coreia |
| EE, QT, UV | Taiwan |
| FK, F1, F2 | Foxconn - Zhengzhou, China |
| W8 | Xangai, China |
| DL, DM | Foxconn - China |
| DN | Foxconn, Chengdu, China |
| YM, 7J | Hon Hai/Foxconn, China |
| 1C, 4H, WQ, F7 | China |
| C0 | Tech Com - Subsidiária da Quanta Computer, China |
| C3 | Foxxcon, Shenzhen, China |
| C7 | Pentragon, Changhai, China |
| RM | Remanufaturado |

## 1 - Ano de fabricação

| Código | Lançamento |
| :--- | :--- |
| C | 2010/2020 \(1º semestre\) |
| D | 2010/2020 \(2º semestre\) |
| F | 2011/2021 \(1º semestre\) |
| G | 2011/2021 \(2º semestre\) |
| H | 2012/... \(1º semestre\) |
| J | 2012 \(2º semestre\) |
| K | 2013 \(1º semestre\) |
| L | 2013 \(2º semestre\) |
| M | 2014 \(1º semestre\) |
| N | 2014 \(2º semestre\) |
| P | 2015 \(1º semestre\) |
| Q | 2015 \(2º semestre\) |
| R | 2016 \(1º semestre\) |
| S | 2016 \(2º semestre\) |
| T | 2017 \(1º semestre\) |
| V | 2017 \(2º semestre\) |
| W | 2018 \(1º semestre\) |
| X | 2018 \(2º semestre\) |
| Y | 2019 \(1º semestre\) |
| Z | 2019 \(2º semestre\) |

## 1 - Semana de fabricação

O quinto caractere representa a semana em que o dispositivo foi fabricado. Existem 28 caracteres possíveis neste local: **os dígitos de 1 a 9 são usados para representar as primeiras nove semanas**, e os **caracteres C a Y, excluindo as vogais A, E, I, O e U, e a letra S, representam as semanas de dez a vinte e sete**. Para dispositivos fabricados no **segundo semestre do ano, adicione 26** ao número representado pelo quinto caractere do número de série. Por exemplo, um produto com um número de série cujos quarto e quinto dígitos são "JH" foi fabricado na 40ª semana de 2012.

## 3 - Código único

Os próximos três dígitos são um código identificador que **serve para diferenciar cada dispositivo Apple do mesmo modelo** que é fabricado no mesmo local e durante a mesma semana do mesmo ano, garantindo que cada dispositivo tenha um número de série diferente.

## 4 - Número de série

Os últimos quatro dígitos do número de série representam o **modelo do produto**.

## Referência

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>
