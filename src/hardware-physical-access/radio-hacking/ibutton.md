# iButton

{{#include ../../banners/hacktricks-training.md}}

## Introdução

iButton é um nome genérico para uma chave de identificação eletrônica acondicionada em um **invólucro metálico em forma de moeda**. Também é chamada de memória Dallas Touch ou memória de contato. Embora muitas vezes seja incorretamente chamada de chave “magnética”, ela **não contém nada magnético**. Na verdade, há um **microchip** completo que opera usando um protocolo digital escondido em seu interior.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### O que é iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

O nome iButton descreve o invólucro durável em forma de moeda e a disposição dos contatos. Os suportes incluem chaveiros de plástico, anéis e pingentes.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

Quando os dois contatos encostam no leitor, o dispositivo recebe energia e troca dados. Se a geometria rebaixada dos contatos impedir que os contatos externos de aterramento encostem, inclinar a chave contra a lateral do leitor pode restabelecer o contato.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **Protocolo 1-Wire** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

As chaves Dallas/Maxim usam o protocolo 1-Wire: um único contato de dados transporta a comunicação bidirecional e também pode fornecer energia parasita, enquanto a carcaça metálica serve como contato de retorno. O controlador inicia as transações e o dispositivo responde.<sup>[[2]](#references)</sup>

Quando a chave (Slave) encosta no interfone (Master), o chip dentro da chave é ligado pela energia fornecida pelo interfone, e a chave é inicializada. Em seguida, o interfone solicita o ID da chave. A seguir, veremos esse processo em mais detalhes.

O Flipper pode atuar como controlador ao ler uma chave e como dispositivo emulado ao apresentar um identificador armazenado a um leitor.<sup>[[1]](#references)</sup>

### Chaves Dallas, Cyfral e Metakom

Para saber como essas chaves funcionam, consulte a página [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Ataques

É possível atacar iButtons com o Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Domando o iButton com o Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — Comunicação 1-Wire por software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
