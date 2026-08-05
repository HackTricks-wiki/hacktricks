# Bypass del KYC usando l'AI

{{#include ../banners/hacktricks-training.md}}

I modelli generativi possono essere utilizzati per **bypassare i workflow KYC, di verifica dell'età e di liveness biometrica basati sul browser**. Il punto debole spesso **non** è il trasporto o il cloud provider di liveness, ma il **confine di fiducia della camera**: un browser desktop generalmente si fida di qualunque dispositivo esposto come webcam da `getUserMedia()`.<sup>[[1]](#references)</sup>

## Catena di Attacco Pratica

1. **Generare media conformi alle challenge** con un modello video-to-video usando un attore sorgente e un'immagine di riferimento della vittima.
2. **Iniettare lo stream contraffatto prima della firma o dell'upload**, ad esempio tramite una camera virtuale Linux creata con `v4l2loopback` e alimentata da OBS o FFmpeg.
3. Lasciare che il browser e l'SDK del vendor (WebRTC, AWS, ecc.) **acquisiscano, firmino e carichino i frame controllati dall'attaccante come se provenissero da una webcam reale**.

Questo è importante durante gli assessment perché i chunk WebSocket firmati o il framing proprietario dell'SDK possono rendere **impraticabile la manomissione a livello di rete**, mentre **l'iniezione a livello di camera** continua a funzionare.<sup>[[1]](#references)</sup>

## Vettori di Test ad Alto Valore

- **Accettazione delle webcam virtuali**: se il flusso funziona da un browser desktop, verificare se OBS, `v4l2loopback` o le camere virtuali del vendor vengono accettate come normali periferiche.
- **Redirezione delle API della camera su mobile**: i flussi mobile nativi possono essere vulnerabili quando Frida effettua hook sulle API della camera e sostituisce i buffer del sensore con frame provenienti da un MP4 o da una camera virtuale basata su emulator.
- **Indebolimento dei constraint**: le pagine che richiedono `deviceId`, `frameRate`, `width`, `height` o `facingMode` esatti possono talvolta essere bypassate tramite monkeypatch di `navigator.mediaDevices.getUserMedia` e sostituendo i constraint rigidi con intervalli più ampi.
- **Generazione a bassa qualità con post-processing**: generare il video meno costoso che il modello riesce a renderizzare in modo affidabile, quindi usare l'upscaling di FFmpeg o l'interpolazione dei frame per soddisfare i requisiti di acquisizione.
- **Challenge attive prevedibili**: vale la pena registrare e riprodurre sequenze ripetute di movimenti della testa o flash luminosi tramite un workflow generativo.
- **Replay detection debole**: semplici alterazioni della scena, come ritagli o spostamenti della posizione, modifiche agli overlay o un leggero movimento, possono essere sufficienti quando la logica anti-replay verifica solo la similarità superficiale dei frame.<sup>[[1]](#references)</sup>

## Differenze di Fiducia tra Mobile e Desktop

Le app mobile native possono aumentare il costo per l'attaccante con:

- **attestation del sensore o del Secure Element** per i buffer della camera;
- segnali di **integrità dell'esecuzione**, come **Play Integrity** o **App Attest**;
- **correlazione del movimento** tra il video e i dati di telemetria dell'accelerometro o del giroscopio.

I flussi web desktop generalmente non dispongono di una catena di fiducia equivalente per la camera, quindi rappresentano in genere il percorso di minor resistenza.<sup>[[1]](#references)</sup>

## Note per la Revisione delle Difese

Durante la revisione di un'integrazione KYC o di liveness, verificare se:

- consente un **fallback tramite browser desktop** per un workflow la cui threat model prevedeva solo l'acquisizione mobile;
- si basa principalmente sulla **liveness algoritmica** senza una forte escalation umana per le sessioni sospette;
- utilizza **challenge stabili o prevedibili** che possono essere pre-registrate e inserite in una pipeline di generazione;
- rileva il **monkeypatch di `getUserMedia`**, le camere virtuali, dati di telemetria hardware del browser incoerenti o l'assenza di device attestation.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
