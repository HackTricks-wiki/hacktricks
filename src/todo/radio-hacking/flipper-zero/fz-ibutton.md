# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding

Vir agtergrond oor iButton-tegnologie, sien:

{{#ref}}
../ibutton.md
{{#endref}}

## Ontwerp

In die volgende prent wys die **blou** area hoe om 'n fisiese iButton teen die Flipper Zero se kontakte te plaas om dit te lees. Die **groen** area wys watter kontakte tydens emulasie aan 'n leser moet raak.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Lees

In Lees-modus wag die Flipper Zero dat 'n sleutel aan sy kontakte raak, bespeur die protokol en vertoon die protokol bo die sleutel-ID. Die ingeboude toepassing ondersteun Dallas-, Cyfral- en Metakom-toegangsbeheersleutels.<sup>[[2]](#references)</sup>

### Voeg handmatig by

Jy kan sleuteldata vir die Dallas-, Cyfral- en Metakom-protokolle handmatig invoer.<sup>[[2]](#references)</sup>

### Emuleer

Jy kan 'n gestoorde sleutel emuleer, ongeag of dit van 'n fisiese sleutel gelees of handmatig ingevoer is.<sup>[[2]](#references)</sup>

> [!TIP]
> As die ingeboude kontakte nie die leser kan bereik nie, verbind die data- en grondkontakte deur die GPIO-pennetjies.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - Reading iButton keys](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
