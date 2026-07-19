# Bypass del KYC usando l'AI

{{#include ../banners/hacktricks-training.md}}

I modelli generativi possono essere utilizzati per **bypassare i workflow KYC basati su browser, la verifica dell'età e i workflow biometrici di liveness**. Il punto debole spesso **non è il transport o il cloud liveness provider**, ma il **confine di trust della camera**: un browser desktop generalmente si fida di qualsiasi dispositivo che `getUserMedia()` espone come webcam.

## Catena di attacco pratica

1. **Generare media conformi alle challenge** con un modello video-to-video partendo da un source actor e da un'immagine di riferimento della vittima.
2. **Iniettare lo stream falsificato prima della firma o dell'upload**, ad esempio tramite una camera virtuale Linux creata con `v4l2loopback` e alimentata da OBS o FFmpeg.
3. Lasciare che il browser e il vendor SDK (WebRTC, AWS, ecc.) **catturino, firmino e carichino i frame controllati dall'attaccante come se provenissero da una webcam reale**.

Questo è importante durante gli assessment perché i chunk WebSocket firmati o il framing proprietario dell'SDK possono rendere **impraticabile il tampering a livello di rete**, mentre **l'iniezione a livello della camera** continua a funzionare.

## Approcci di testing ad alto valore

- **Accettazione delle webcam virtuali**: se il workflow funziona da un browser desktop, verificare se OBS, `v4l2loopback` o le camere virtuali del vendor vengono accettate come periferiche normali.
- **Redirezione delle API della camera su mobile**: i workflow mobile nativi possono comunque essere vulnerabili quando Frida aggancia le API della camera e sostituisce i buffer del sensore con frame provenienti da un MP4 o da una camera virtuale basata su emulator.
- **Indebolimento dei constraint**: le pagine che richiedono `deviceId`, `frameRate`, `width`, `height` o `facingMode` esatti possono talvolta essere bypassate effettuando il monkeypatch di `navigator.mediaDevices.getUserMedia` e sostituendo i constraint rigidi con intervalli più ampi.
- **Generazione a bassa qualità più post-processing**: generare il video più economico che il modello riesce a renderizzare in modo affidabile, quindi usare l'upscaling di FFmpeg o l'interpolazione dei frame per soddisfare i requisiti di cattura.
- **Challenge attive prevedibili**: sequenze ripetute di movimenti della testa o di flash luminosi possono essere registrate e riprodotte tramite un workflow generativo.
- **Replay detection debole**: semplici perturbazioni della scena, come ritagli o variazioni di posizione, modifiche agli overlay o lievi movimenti, possono essere sufficienti quando la logica anti-replay verifica soltanto una similarità superficiale tra i frame.

## Differenze di trust tra mobile e desktop

Le app mobile native possono aumentare il costo per l'attaccante tramite:

- **attestation del sensore o del Secure Element** per i buffer della camera;
- segnali di **execution-integrity** come **Play Integrity** o **App Attest**;
- **correlazione del movimento** tra il video e la telemetria dell'accelerometro o del giroscopio.

I workflow web desktop generalmente non dispongono di una catena di trust equivalente per la camera, quindi sono in genere il percorso di minore resistenza.

## Note per la revisione delle difese

Durante la revisione di un'integrazione KYC o di liveness, verificare se:

- consente un **fallback tramite browser desktop** per un workflow il cui threat model prevedeva soltanto la cattura da mobile;
- si basa principalmente sulla **liveness algoritmica** senza una forte escalation verso un operatore umano per le sessioni sospette;
- utilizza **challenge stabili o prevedibili** che possono essere preregistrate e immesse in una pipeline di generazione;
- rileva il **monkeypatching di `getUserMedia`**, le camere virtuali, la telemetria hardware incoerente del browser o l'assenza di device attestation.

## Riferimenti

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
