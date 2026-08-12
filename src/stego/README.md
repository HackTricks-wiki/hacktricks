# Stego

{{#include ../banners/hacktricks-training.md}}

Questa sezione si concentra sul **trovare ed estrarre dati nascosti** da immagini, audio, video, documenti, archivi e testo. La steganografia nasconde l'esistenza di una comunicazione incorporando dati all'interno di altri dati.<sup>[[1]](#references)</sup>

Se sei qui per gli attacchi crittografici, vai alla sezione **Crypto**.

## Punto di ingresso

Affronta la steganografia come un problema di analisi forense: identifica il contenitore reale, esamina le posizioni ad alto valore informativo (metadati, dati aggiunti, file incorporati) e solo dopo applica tecniche di estrazione a livello di contenuto.

### Workflow e triage

Un workflow strutturato che dà priorità all'identificazione del contenitore, all'ispezione di metadati/stringhe, al carving e alla diramazione specifica per formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Immagini

Dove si trova la maggior parte della stego nei CTF: LSB/bit-plane (PNG/BMP), anomalie nei chunk/formati dei file, strumenti per JPEG e trucchi con GIF multi-frame.

{{#ref}}
images/README.md
{{#endref}}

### Audio

I messaggi negli spettrogrammi, l'embedding LSB nei sample e i toni dei tasti telefonici (DTMF) sono pattern ricorrenti.

{{#ref}}
audio/README.md
{{#endref}}

### Testo

Se il testo viene visualizzato normalmente ma si comporta in modo imprevisto, considera gli omoglifi Unicode, i caratteri a larghezza zero o la codifica basata sugli spazi bianchi.

{{#ref}}
text/README.md
{{#endref}}

### Documenti

I PDF e i file Office sono innanzitutto contenitori; gli attacchi ruotano solitamente attorno a file/stream incorporati, grafi di oggetti/relazioni ed estrazione ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Steganografia per malware e delivery

La delivery del payload può utilizzare file dall'aspetto valido, come immagini GIF o PNG, che trasportano payload testuali delimitati da marker invece di nascondere i dati nei pixel.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glossario NIST CSRC - Steganografia](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
