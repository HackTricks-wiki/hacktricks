# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Vir agtergrond oor iButton-tegnologie, sien:

{{#ref}}
../ibutton.md
{{#endref}}

## Ontwerp

In die volgende prent wys die **blou** area hoe om ’n fisiese iButton teen die Flipper Zero se kontakte te plaas om dit te lees. Die **groen** area wys watter kontakte tydens emulering aan ’n leser moet raak.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Lees

In Lees-modus wag die Flipper Zero totdat ’n sleutel aan sy kontakte raak, bespeur die protokol en vertoon die protokol bo die sleutel-ID. Die ingeboude toepassing ondersteun Dallas-, Cyfral- en Metakom-toegangsbeheersleutels.<sup>[[2]](#references)</sup>

### Voeg handmatig by

Jy kan sleuteldata vir die Dallas-, Cyfral- en Metakom-protokolle handmatig invoer.<sup>[[2]](#references)</sup>

### Emuleer

Jy kan ’n gestoorde sleutel emuleer, ongeag of dit van ’n fisiese sleutel gelees of handmatig ingevoer is.<sup>[[2]](#references)</sup>

> [!TIP]
> As die ingeboude kontakte nie by die leser kan uitkom nie, koppel die data- en grondkontakte deur die GPIO-pinne.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Tem iButton-sleutels met Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero-dokumentasie - Lees iButton-sleutels](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

