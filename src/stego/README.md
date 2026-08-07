# Stego

{{#include ../banners/hacktricks-training.md}}

Questa sezione si concentra sulla **ricerca e sull'estrazione di dati nascosti** da file (immagini/audio/video/documenti/archivi) e sulla steganografia basata sul testo.

Se stai cercando attacchi crittografici, vai alla sezione **Crypto**.

## Punto di ingresso

Affronta la steganografia come un problema di analisi forense: identifica il contenitore reale, esamina le posizioni con il più alto potenziale informativo (metadati, dati aggiunti, file incorporati) e solo dopo applica tecniche di estrazione a livello di contenuto.

### Workflow e triage

Un workflow strutturato che dà priorità all'identificazione del contenitore, all'ispezione di metadati/stringhe, al carving e alla selezione del ramo specifico del formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Immagini

Dove si trova la maggior parte dello stego nei CTF: LSB/bit-planes (PNG/BMP), anomalie nei chunk e nei formati dei file, strumenti per JPEG e trucchi con GIF multi-frame.

{{#ref}}
images/README.md
{{#endref}}

### Audio

I messaggi negli spettrogrammi, l'embedding LSB nei sample e i toni dei tastierini telefonici (DTMF) sono pattern ricorrenti.

{{#ref}}
audio/README.md
{{#endref}}

### Testo

Se il testo viene visualizzato normalmente ma si comporta in modo inatteso, considera gli omoglifi Unicode, i caratteri a larghezza zero o la codifica basata sugli spazi bianchi.

{{#ref}}
text/README.md
{{#endref}}

### Documenti

I PDF e i file Office sono innanzitutto contenitori; gli attacchi ruotano solitamente attorno a file/stream incorporati, grafi di oggetti/relazioni ed estrazione ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Steganografia per malware e delivery

La delivery dei payload utilizza frequentemente file dall'aspetto valido (ad es., GIF/PNG) che contengono payload testuali delimitati da marker, invece di nascondere dati a livello dei pixel.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
