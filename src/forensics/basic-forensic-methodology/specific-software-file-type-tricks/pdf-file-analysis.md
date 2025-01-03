# Analisi dei file PDF

{{#include ../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli controlla:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Il formato PDF è noto per la sua complessità e il potenziale di nascondere dati, rendendolo un punto focale per le sfide forensi CTF. Combina elementi di testo semplice con oggetti binari, che potrebbero essere compressi o crittografati, e può includere script in linguaggi come JavaScript o Flash. Per comprendere la struttura del PDF, si può fare riferimento al [materiale introduttivo di Didier Stevens](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), o utilizzare strumenti come un editor di testo o un editor specifico per PDF come Origami.

Per un'esplorazione o manipolazione approfondita dei PDF, sono disponibili strumenti come [qpdf](https://github.com/qpdf/qpdf) e [Origami](https://github.com/mobmewireless/origami-pdf). I dati nascosti all'interno dei PDF potrebbero essere celati in:

- Livelli invisibili
- Formato di metadati XMP di Adobe
- Generazioni incrementali
- Testo dello stesso colore dello sfondo
- Testo dietro immagini o immagini sovrapposte
- Commenti non visualizzati

Per un'analisi personalizzata dei PDF, si possono utilizzare librerie Python come [PeepDF](https://github.com/jesparza/peepdf) per creare script di parsing su misura. Inoltre, il potenziale del PDF per la memorizzazione di dati nascosti è così vasto che risorse come la guida della NSA sui rischi e le contromisure dei PDF, sebbene non più ospitata nella sua posizione originale, offrono ancora preziose informazioni. Una [copia della guida](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) e una raccolta di [trucchi sul formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) di Ange Albertini possono fornire ulteriori letture sull'argomento.

{{#include ../../../banners/hacktricks-training.md}}
