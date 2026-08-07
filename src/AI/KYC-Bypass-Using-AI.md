# Bypass del KYC usando l'AI

{{#include ../banners/hacktricks-training.md}}

I modelli generativi possono essere utilizzati per **bypassare i flussi KYC basati sul browser, la verifica dell'età e la verifica biometrica della vitalità**. Il punto debole spesso **non** è il transport o il provider cloud di liveness, ma il **confine di fiducia della fotocamera**: un browser desktop solitamente si fida di qualunque dispositivo che `getUserMedia()` esponga come webcam.<sup>[[1]](#references)</sup>

## Catena d'attacco pratica

1. **Generare contenuti conformi alla challenge** con un modello video-to-video, usando un attore sorgente e un'immagine di riferimento della vittima.<sup>[[1]](#references)</sup>
2. **Iniettare lo stream contraffatto prima della firma o dell'upload**, ad esempio tramite una virtual camera Linux creata con `v4l2loopback` e alimentata da OBS o FFmpeg.<sup>[[3]](#references)</sup>
3. Lasciare che il browser e il vendor SDK (WebRTC, AWS, ecc.) **acquisiscano, firmino e carichino i frame controllati dall'attaccante come se provenissero da una webcam reale**.<sup>[[2]](#references)</sup>

Questo è importante durante gli assessment perché i chunk WebSocket firmati o il framing proprietario dell'SDK possono rendere **impraticabile la manomissione a livello di rete**, mentre **l'iniezione a livello di fotocamera** continua a funzionare.<sup>[[1]](#references)</sup>

## Prospettive di test ad alto valore

- **Accettazione di webcam virtuali**: se il flusso funziona da un browser desktop, verificare se OBS, `v4l2loopback` o le virtual camera del vendor vengono accettate come normali periferiche.<sup>[[1]](#references)</sup>
- **Redirezione delle API della fotocamera su mobile**: i flussi mobile nativi possono essere ancora vulnerabili quando Frida applica hook alle API della fotocamera e sostituisce i buffer del sensore con frame provenienti da un MP4 o da una virtual camera basata su emulatore.
- **Indebolimento dei constraint**: le pagine che richiedono `deviceId`, `frameRate`, `width`, `height` o `facingMode` esatti possono talvolta essere bypassate applicando monkeypatch a `navigator.mediaDevices.getUserMedia` e sostituendo i constraint rigidi con intervalli più ampi.<sup>[[4]](#references)</sup>
- **Generazione a bassa qualità più post-processing**: generare il video meno costoso che il modello riesce a renderizzare in modo affidabile, quindi usare l'upscaling di FFmpeg o l'interpolazione dei frame per soddisfare i requisiti di acquisizione.
- **Challenge attive prevedibili**: vale la pena registrare e riprodurre sequenze ripetute di movimenti della testa o flash luminosi tramite un workflow generativo.
- **Rilevamento debole dei replay**: semplici perturbazioni della scena, come ritagli o spostamenti della posizione, modifiche degli overlay o movimenti lievi, possono essere sufficienti quando la logica anti-replay verifica solo una similarità superficiale tra i frame.<sup>[[1]](#references)</sup>

## Differenze di fiducia tra mobile e desktop

Le app mobile native possono aumentare il costo per l'attaccante tramite:<sup>[[1]](#references)</sup>

- **attestation del sensore o del Secure Element** per i buffer della fotocamera;
- segnali di **integrità dell'esecuzione**, come **Play Integrity** o **App Attest**;
- **correlazione dei movimenti** tra il video e i dati di telemetria dell'accelerometro o del giroscopio.

I flussi web desktop solitamente non dispongono di una catena di fiducia equivalente per la fotocamera, quindi rappresentano generalmente il percorso di minor resistenza.<sup>[[1]](#references)</sup>

## Note per la revisione delle difese

Durante la revisione di un'integrazione KYC o di liveness, verificare se:<sup>[[1]](#references)</sup>

- consente un **fallback tramite browser desktop** per un workflow che era stato sottoposto a threat modeling solo per l'acquisizione mobile;
- si basa principalmente sulla **liveness algoritmica** senza una forte escalation umana per le sessioni sospette;
- utilizza **challenge stabili o prevedibili** che possono essere preregistrate e inserite in una pipeline di generazione;
- rileva il **monkeypatching di `getUserMedia`**, le virtual camera, dati di telemetria hardware incoerenti del browser o l'assenza di device attestation.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Synacktiv - Bypass della verifica dell'età KYC usando modelli video generativi](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
