# KYC-omseiling deur AI

{{#include ../banners/hacktricks-training.md}}

Generative models kan gebruik word om **blaaiergebaseerde KYC-, ouderdomsverifikasie- en biometriese liveness-werkvloeie te omseil**. Die swak punt is dikwels **nie** die transportlaag of die cloud liveness-provider nie, maar die **kamera-vertrouensgrens**: 'n desktop-blaaier vertrou gewoonlik enige toestel wat `getUserMedia()` as 'n webcam beskikbaar stel.<sup>[[1]](#references)</sup>

## Praktiese Aanvalsketting

1. **Genereer media wat aan die uitdaging voldoen** met 'n video-to-video-model vanaf 'n bronakteur en 'n verwysingsbeeld van die slagoffer.<sup>[[1]](#references)</sup>
2. **Injecteer die vervalste stroom voor signing of upload**, byvoorbeeld deur 'n Linux-virtuele kamera wat met `v4l2loopback` geskep is en deur OBS of FFmpeg gevoer word.<sup>[[3]](#references)</sup>
3. Laat die blaaier en vendor SDK (WebRTC, AWS, ens.) **die aanvaller-beheerde rame vaslê, sign en upload asof dit van 'n regte webcam afkomstig is**.<sup>[[2]](#references)</sup>

Dit is belangrik tydens assesserings omdat signed WebSocket chunks of proprietary SDK framing **network-layer tampering** onprakties kan maak, terwyl **camera-layer injection** steeds werk.<sup>[[1]](#references)</sup>

## Hoëwaarde-toetshoeke

- **Aanvaarding van virtuele webcams**: as die vloei vanaf 'n desktop-blaaier werk, toets of OBS, `v4l2loopback` of vendor-virtuele kameras as normale peripherals aanvaar word.<sup>[[1]](#references)</sup>
- **Kamera-API-herleiding op mobile**: native mobile-vloeie kan steeds kwesbaar wees wanneer Frida camera APIs hook en sensorbuffers vervang met rame vanaf 'n MP4 of emulator-backed virtuele kamera.
- **Verswakking van constraints**: bladsye wat 'n presiese `deviceId`, `frameRate`, `width`, `height` of `facingMode` vereis, kan soms omseil word deur `navigator.mediaDevices.getUserMedia` te monkeypatch en streng constraints met breër reekse te vervang.<sup>[[4]](#references)</sup>
- **Lae-gehalte-generering plus post-processing**: genereer die goedkoopste video wat die model betroubaar kan render, en gebruik dan FFmpeg-upscaling of frame interpolation om aan capture-vereistes te voldoen.
- **Voorspelbare aktiewe uitdagings**: herhaalde kopbewegings- of ligflitsreekse is die moeite werd om op te neem en deur 'n generative workflow te replay.
- **Swak replay-detection**: eenvoudige scene-perturbasies, soos crop- of posisieverskuiwings, overlay-veranderings of geringe beweging, kan genoeg wees wanneer die anti-replay-logika slegs oppervlakkige frame-similarity nagaan.<sup>[[1]](#references)</sup>

## Mobiele teenoor Desktop-vertroueverskille

Native mobile-apps kan die aanvaller se koste verhoog met:<sup>[[1]](#references)</sup>

- **sensor- of Secure Element-attestation** vir kamerabuffers;
- **execution-integrity**-seine soos **Play Integrity** of **App Attest**;
- **bewegingskorrelasie** tussen video en accelerometer- of gyroscope-telemetrie.

Desktop-webvloeie het gewoonlik nie 'n ekwivalente camera chain of trust nie, en is dus oor die algemeen die pad van die minste weerstand.<sup>[[1]](#references)</sup>

## Notas vir Defensiewe Hersiening

Wanneer 'n KYC- of liveness-integrasie hersien word, verifieer of dit:<sup>[[1]](#references)</sup>

- 'n **desktop-blaaier-fallback** toelaat vir 'n workflow wat slegs vir mobile capture threat-modeled is;
- hoofsaaklik op **algorithmic liveness** staatmaak sonder sterk human escalation vir verdagte sessies;
- **stabiele of voorspelbare uitdagings** gebruik wat vooraf opgeneem en in 'n generation pipeline gevoer kan word;
- **`getUserMedia`-monkeypatching**, virtuele kameras, inkonsekwente browser hardware telemetry of ontbrekende device attestation opspoor.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
