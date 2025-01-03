# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButton é um nome genérico para uma chave de identificação eletrônica embalada em um **recipiente metálico em forma de moeda**. Também é chamada de **Dallas Touch** Memory ou memória de contato. Embora muitas vezes seja erroneamente chamada de chave “magnética”, não há **nada magnético** nela. Na verdade, um **microchip** completo operando em um protocolo digital está escondido dentro.

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### O que é iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalmente, iButton implica a forma física da chave e do leitor - uma moeda redonda com dois contatos. Para a moldura que a envolve, existem muitas variações, desde o suporte plástico mais comum com um buraco até anéis, pingentes, etc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando a chave chega ao leitor, os **contatos se tocam** e a chave é alimentada para **transmitir** sua ID. Às vezes, a chave **não é lida** imediatamente porque o **PSD de contato de um intercomunicador é maior** do que deveria ser. Assim, os contornos externos da chave e do leitor não conseguem se tocar. Se esse for o caso, você terá que pressionar a chave contra uma das paredes do leitor.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

As chaves Dallas trocam dados usando o protocolo 1-wire. Com apenas um contato para transferência de dados (!!) em ambas as direções, do mestre para o escravo e vice-versa. O protocolo 1-wire funciona de acordo com o modelo Master-Slave. Nesta topologia, o Master sempre inicia a comunicação e o Slave segue suas instruções.

Quando a chave (Slave) entra em contato com o intercomunicador (Master), o chip dentro da chave é ativado, alimentado pelo intercomunicador, e a chave é inicializada. Em seguida, o intercomunicador solicita a ID da chave. A seguir, examinaremos esse processo em mais detalhes.

Flipper pode funcionar tanto em modos Master quanto Slave. No modo de leitura da chave, o Flipper atua como um leitor, ou seja, funciona como um Master. E no modo de emulação da chave, o Flipper finge ser uma chave, estando no modo Slave.

### Chaves Dallas, Cyfral & Metakom

Para informações sobre como essas chaves funcionam, consulte a página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Ataques

iButtons podem ser atacados com Flipper Zero:

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referências

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
