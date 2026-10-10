# Stego

{{#include ../banners/hacktricks-training.md}}

Questa sezione si concentra sulla **ricerca e l'estrazione di dati nascosti** da immagini, audio, video, documenti, archivi e testo. La steganografia nasconde l'esistenza di una comunicazione incorporando dati all'interno di altri dati.<sup>[[1]](#references)</sup>

Se cerchi attacchi crittografici, vai alla sezione **Crypto**.

## Punto di ingresso

Affronta la steganografia come un problema di analisi forense: identifica il contenitore effettivo, esamina le posizioni con maggiori probabilità di contenere informazioni rilevanti (metadati, dati aggiunti, file incorporati) e solo dopo applica tecniche di estrazione a livello di contenuto.

### Flusso di lavoro e triage

Un flusso di lavoro strutturato che dà priorità all'identificazione del contenitore, all'ispezione di metadati e stringhe, al carving e all'analisi specifica per formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Immagini

È qui che si trova la maggior parte della stego nei CTF: LSB/piani di bit (PNG/BMP), anomalie di chunk e formati di file, strumenti per JPEG e trucchi con GIF multiframe.

{{#ref}}
images/README.md
{{#endref}}

### Audio

I messaggi negli spettrogrammi, l'incorporamento LSB nei campioni e i toni dei tastierini telefonici (DTMF) sono schemi ricorrenti.

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

### Malware e steganografia per la distribuzione dei payload

La distribuzione dei payload può avvenire tramite file apparentemente validi, come immagini GIF o PNG, che contengono payload testuali delimitati da marker invece di nascondere dati nei pixel.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glossario NIST CSRC - Steganografia](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
