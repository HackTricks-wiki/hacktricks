# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Pour plus d'informations sur ce qu'est un iButton, consultez :


{{#ref}}
../ibutton.md
{{#endref}}

## Conception

La partie **bleue** de l'image suivante indique où vous devez **placer le véritable iButton** pour que le Flipper puisse **le lire**. La partie **verte** indique où vous devez **toucher le lecteur** avec le Flipper Zero pour **émuler correctement un iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Lire

En mode Read, le Flipper attend que la clé iButton soit mise en contact et peut traiter trois types de clés : **Dallas, Cyfral et Metakom**. Le Flipper **détermine lui-même le type de la clé**. Le nom du protocole de la clé s'affiche à l'écran au-dessus du numéro d'ID.<sup>[[1]](#references)</sup>

### Ajouter manuellement

Il est possible **d'ajouter manuellement** un iButton de type : **Dallas, Cyfral et Metakom**

### **Émuler**

Il est possible **d'émuler** des iButtons enregistrés (lus ou ajoutés manuellement).

> [!TIP]
> Si vous ne parvenez pas à établir les contacts attendus entre le Flipper Zero et le lecteur, vous pouvez **utiliser le GPIO externe :**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Références

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
