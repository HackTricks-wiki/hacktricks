# Stego

{{#include ../banners/hacktricks-training.md}}

Questa sezione è focalizzata su **trovare ed estrarre dati nascosti** da file (immagini/audio/video/documenti/archivi) e dalla steganografia basata su testo.

Se sei qui per attacchi crittografici, vai alla sezione **Crypto**.

## Punto di ingresso

Affronta la steganografia come un problema forense: identifica il contenitore reale, enumera le posizioni ad alto segnale (metadati, dati aggiunti, file incorporati) e solo dopo applica tecniche di estrazione a livello di contenuto.

### Workflow & triage

Un flusso di lavoro strutturato che dà priorità all'identificazione del contenitore, all'ispezione di metadati/stringhe, al carving e alle diramazioni specifiche per formato.
{{#ref}}
workflow/README.md
{{#endref}}

### Images

Dove risiede la maggior parte dello stego nei CTF: LSB/bit-planes (PNG/BMP), stranezze di chunk/formato file, tooling per JPEG e trucchi con GIF multi-frame.
{{#ref}}
images/README.md
{{#endref}}

### Audio

Messaggi nello spettrogramma, embedding LSB sui sample e toni del tastierino telefonico (DTMF) sono pattern ricorrenti.
{{#ref}}
audio/README.md
{{#endref}}

### Text

Se il testo viene visualizzato normalmente ma si comporta in modo inaspettato, considera Unicode homoglyphs, zero-width characters, oppure whitespace-based encoding.
{{#ref}}
text/README.md
{{#endref}}

### Documents

I PDF e i file Office sono prima di tutto contenitori; gli attacchi solitamente ruotano attorno a file/stream incorporati, grafi di oggetti/relazioni e all'estrazione ZIP.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

La consegna del payload usa frequentemente file dall'aspetto valido (es. GIF/PNG) che contengono payload testuali delimitati da marker, anziché nascondere a livello di pixel.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
