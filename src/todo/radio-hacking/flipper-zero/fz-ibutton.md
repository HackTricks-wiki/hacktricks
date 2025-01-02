# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Per ulteriori informazioni su cos'è un iButton, controlla:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

La parte **blu** dell'immagine seguente è come dovresti **mettere il vero iButton** affinché il Flipper possa **leggerlo.** La parte **verde** è come devi **toccare il lettore** con il Flipper zero per **emulare correttamente un iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

In modalità Read, il Flipper sta aspettando che la chiave iButton venga toccata ed è in grado di elaborare uno dei tre tipi di chiavi: **Dallas, Cyfral e Metakom**. Il Flipper **determinerà il tipo di chiave da solo**. Il nome del protocollo della chiave verrà visualizzato sullo schermo sopra il numero ID.

### Add manually

È possibile **aggiungere manualmente** un iButton di tipo: **Dallas, Cyfral e Metakom**

### **Emulate**

È possibile **emulare** i iButton salvati (letto o aggiunto manualmente).

> [!NOTE]
> Se non riesci a far toccare i contatti previsti del Flipper Zero al lettore, puoi **utilizzare il GPIO esterno:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
