# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Pour plus d'infos sur ce qu'est un iButton, consultez :

{{#ref}}
../ibutton.md
{{#endref}}

## Design

La partie **bleue** de l'image suivante est comment vous devez **placer le vrai iButton** pour que le Flipper puisse **le lire.** La partie **verte** est comment vous devez **toucher le lecteur** avec le Flipper zero pour **émuler correctement un iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Lire

En mode Lecture, le Flipper attend que la clé iButton soit touchée et peut digérer l'un des trois types de clés : **Dallas, Cyfral, et Metakom**. Le Flipper **déterminera le type de clé lui-même**. Le nom du protocole de clé sera affiché à l'écran au-dessus du numéro d'identification.

### Ajouter manuellement

Il est possible d'**ajouter manuellement** un iButton de type : **Dallas, Cyfral, et Metakom**

### **Émuler**

Il est possible d'**émuler** des iButtons sauvegardés (lus ou ajoutés manuellement).

> [!NOTE]
> Si vous ne pouvez pas faire en sorte que les contacts attendus du Flipper Zero touchent le lecteur, vous pouvez **utiliser le GPIO externe :**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Références

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
