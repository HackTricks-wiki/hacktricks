# Bypass del KYC usando l'AI

{{#include ../banners/hacktricks-training.md}}

I modelli generativi possono essere utilizzati per **bypassare i workflow KYC basati sul browser, la verifica dell'età e i workflow di liveness biometrica**. Il punto debole spesso **non è il trasporto o il provider cloud di liveness**, ma il **confine di fiducia della fotocamera**: un browser desktop di solito si fida di qualsiasi dispositivo che `getUserMedia()` espone come webcam.<sup>[[1]](#references)</sup>

## Catena di attacco pratica

1. **Generare media conformi alle challenge** con un modello video-to-video, usando un attore sorgente e un'immagine di riferimento della vittima.<sup>[[1]](#references)</sup>
2. **Iniettare lo stream contraffatto prima della firma o dell'upload**, ad esempio tramite una fotocamera virtuale Linux creata con `v4l2loopback` e alimentata da OBS o FFmpeg.<sup>[[3]](#references)</sup>
3. Lasciare che il browser e il vendor SDK (WebRTC, AWS, ecc.) **acquisiscano, firmino e carichino i frame controllati dall'attaccante come se provenissero da una webcam reale**.<sup>[[2]](#references)</sup>

Questo è importante durante gli assessment perché i chunk WebSocket firmati o il framing proprietario dell'SDK possono rendere **impraticabile la manomissione a livello di rete**, mentre **l'iniezione a livello di fotocamera** continua a funzionare.<sup>[[1]](#references)</sup>

## Aspetti di testing ad alto valore

- **Accettazione delle webcam virtuali**: se il flusso funziona da un browser desktop, verificare se OBS, `v4l2loopback` o le fotocamere virtuali del vendor vengono accettate come periferiche normali.<sup>[[1]](#references)</sup>
- **Redirezione delle API della fotocamera su mobile**: i flussi nativi possono essere ancora vulnerabili quando la strumentazione runtime, come Frida, aggancia le API della fotocamera e sostituisce i buffer del sensore con frame provenienti da un file MP4 o da una fotocamera virtuale basata sull'emulatore. Ciò richiede il controllo dell'ambiente di esecuzione del client e dovrebbe essere valutato insieme ai segnali di root/jailbreak e di integrità dell'applicazione.<sup>[[1]](#references)</sup>
- **Indebolimento dei constraint**: le pagine che richiedono `deviceId`, `frameRate`, `width`, `height` o `facingMode` esatti possono talvolta essere bypassate facendo monkeypatch di `navigator.mediaDevices.getUserMedia` e sostituendo i constraint rigidi con intervalli più ampi.<sup>[[4]](#references)</sup>
- **Generazione a bassa qualità più post-processing**: verificare se un video generato a basso costo può essere upscalato o sottoposto a interpolazione dei frame con FFmpeg in misura sufficiente a soddisfare i constraint di acquisizione.<sup>[[1]](#references)</sup>
- **Challenge attive prevedibili**: vale la pena registrare e riprodurre sequenze ripetute di movimenti della testa o flash luminosi tramite un workflow generativo.
- **Rilevamento debole del replay**: semplici alterazioni della scena, come spostamenti del crop o della posizione, modifiche dell'overlay o lievi movimenti, possono essere sufficienti quando la logica anti-replay controlla solo una similarità superficiale dei frame.<sup>[[1]](#references)</sup>

## Differenze di fiducia tra mobile e desktop

Le app mobile native possono aumentare il costo per l'attaccante tramite:<sup>[[1]](#references)</sup>

- **segnali di provenienza o attestazione supportati dall'hardware**, inclusa l'evidenza supportata dal Secure Element quando la piattaforma e lo stack di acquisizione la espongono effettivamente;
- segnali di **integrità dell'esecuzione**, come **Play Integrity** o **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **correlazione del movimento** tra video e telemetria dell'accelerometro o del giroscopio.

I flussi web desktop di solito non dispongono di un equivalente chain of trust della fotocamera, quindi generalmente rappresentano il percorso di minore resistenza.<sup>[[1]](#references)</sup>

## Note per la revisione difensiva

Durante la revisione di un'integrazione KYC o di liveness, verificare se:<sup>[[1]](#references)</sup>

- consente un **fallback tramite browser desktop** per un workflow il cui threat modeling era stato eseguito solo per l'acquisizione mobile;
- si basa principalmente sulla **liveness algoritmica** senza un forte intervento umano per le sessioni sospette;
- utilizza **challenge stabili o prevedibili** che possono essere preregistrate e inserite in una pipeline di generazione;
- rileva il **monkeypatch di `getUserMedia`**, le fotocamere virtuali, dati hardware incoerenti del browser o l'assenza di attestazione del dispositivo.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypass della verifica dell'età KYC usando modelli video generativi](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — API Play Integrity](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
