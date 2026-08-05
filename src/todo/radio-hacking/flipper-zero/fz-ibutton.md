# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introduzione

Per maggiori informazioni su cosa sia un iButton, consulta:


{{#ref}}
../ibutton.md
{{#endref}}

## Design

La parte **blu** dell'immagine seguente mostra come dovresti **posizionare il vero iButton** affinché Flipper possa **leggerlo.** La parte **verde** mostra come devi **toccare il reader** con Flipper Zero per **emulare correttamente un iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Azioni

### Lettura

In modalità Lettura, Flipper attende che il dispositivo iButton venga avvicinato e può interpretare tre tipi di chiavi: **Dallas, Cyfral e Metakom**. Flipper **determinerà autonomamente il tipo di chiave**. Il nome del protocollo della chiave verrà visualizzato sullo schermo sopra il numero ID.<sup>[[1]](#references)</sup>

### Aggiunta manuale

È possibile **aggiungere manualmente** un iButton di tipo: **Dallas, Cyfral e Metakom**

### **Emulazione**

È possibile **emulare** gli iButton salvati (letti o aggiunti manualmente).

> [!TIP]
> Se non riesci a fare in modo che i contatti previsti di Flipper Zero tocchino il reader, puoi **usare il GPIO esterno:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Riferimenti

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
