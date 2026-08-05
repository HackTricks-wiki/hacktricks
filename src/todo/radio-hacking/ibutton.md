# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introdução

iButton é um nome genérico para uma chave de identificação eletrônica acondicionada em um **recipiente metálico em forma de moeda**. Também é chamada de memória **Dallas Touch** ou memória de contato. Embora muitas vezes seja chamada incorretamente de chave “magnética”, não há **nada magnético** nela. Na verdade, há um **microchip** completo, que opera em um protocolo digital, escondido em seu interior.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### O que é iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Normalmente, iButton se refere ao formato físico da chave e do leitor - uma moeda redonda com dois contatos. Quanto à estrutura que o envolve, há muitas variações, desde o suporte plástico mais comum com um orifício até anéis, pingentes etc.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando a chave alcança o leitor, os **contatos se tocam** e a chave recebe energia para **transmitir** seu ID. Às vezes, a chave **não é lida** imediatamente porque o **PSD de contato de um interfone é maior** do que deveria. Assim, os contornos externos da chave e do leitor não conseguem se tocar. Nesse caso, será necessário pressionar a chave contra uma das paredes do leitor.

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

As chaves Dallas trocam dados usando o protocolo 1-wire. Com apenas um contato para a transferência de dados (!!) em ambas as direções, do master para o slave e vice-versa. O protocolo 1-wire funciona de acordo com o modelo Master-Slave. Nessa topologia, o Master sempre inicia a comunicação e o Slave segue suas instruções.

Quando a chave (Slave) entra em contato com o interfone (Master), o chip dentro da chave é ligado, alimentado pelo interfone, e a chave é inicializada. Em seguida, o interfone solicita o ID da chave. A seguir, veremos esse processo com mais detalhes.

O Flipper pode funcionar tanto nos modos Master quanto Slave. No modo de leitura de chaves, o Flipper atua como um leitor, ou seja, funciona como um Master. Já no modo de emulação de chaves, o Flipper finge ser uma chave e está no modo Slave.

### Chaves Dallas, Cyfral e Metakom

Para obter informações sobre como essas chaves funcionam, consulte a página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataques

iButtons podem ser atacados com o Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## Referências

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
