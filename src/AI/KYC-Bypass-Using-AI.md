# KYC-omseiling met AI

{{#include ../banners/hacktricks-training.md}}

Generatiewe modelle kan gebruik word om **blaaiergebaseerde KYC-, ouderdomsverifikasie- en biometriese liveness-werkvloeie te omseil**. Die swak punt is dikwels **nie die vervoerlaag of die cloud liveness-verskaffer nie, maar die kamera-vertrouensgrens**: ’n rekenaarblaaier vertrou gewoonlik enige toestel wat `getUserMedia()` as ’n webcam beskikbaar stel.<sup>[[1]](#references)</sup>

## Praktiese Aanvalsketting

1. **Genereer uitdagingvoldoenende media** met ’n video-tot-video-model vanaf ’n bronakteur en ’n slagoffer-verwysingsbeeld.
2. **Spuit die vervalste stroom in voordat dit onderteken of opgelaai word**, byvoorbeeld deur ’n Linux-virtuele kamera wat met `v4l2loopback` geskep en deur OBS of FFmpeg gevoed word.
3. Laat die blaaier en verskaffer-SDK (WebRTC, AWS, ens.) die **aanvallerbeheerde rame vaslê, onderteken en oplaai asof dit van ’n regte webcam afkomstig is**.

Dit is belangrik tydens assesserings omdat ondertekende WebSocket-stukke of eie SDK-raamwerk **netwerklaag-peutery** onprakties kan maak, terwyl **kamera-laaginspuiting** steeds werk.<sup>[[1]](#references)</sup>

## Toetsbenaderings met hoë waarde

- **Aanvaarding van virtuele webcams**: as die vloei vanaf ’n rekenaarblaaier werk, toets of OBS, `v4l2loopback` of verskaffer-virtuele kameras as normale randtoestelle aanvaar word.
- **Herleiding van kamera-API’s op mobiele toestelle**: inheemse mobiele vloeie kan steeds kwesbaar wees wanneer Frida kamera-API’s hook en sensorbuffers vervang met rame uit ’n MP4 of ’n emulatorgesteunde virtuele kamera.
- **Verswakking van beperkings**: bladsye wat ’n presiese `deviceId`, `frameRate`, `width`, `height` of `facingMode` vereis, kan soms omseil word deur `navigator.mediaDevices.getUserMedia` te monkeypatch en streng beperkings met breër reekse te vervang.
- **Laegehalte-generering plus naverwerking**: genereer die goedkoopste video wat die model betroubaar kan lewer, en gebruik dan FFmpeg-opskaling of raaminterpolasie om aan die vasleggingsvereistes te voldoen.
- **Voorspelbare aktiewe uitdagings**: herhaalde kopbewegings- of ligflitsreekse is die moeite werd om op te neem en deur ’n generatiewe werkvloei te herspeel.
- **Swak herspeelbespeuring**: eenvoudige toneelwysigings, soos sny- of posisieverskuiwings, wysigings aan oorlegsels of geringe beweging, kan voldoende wees wanneer die anti-herspeellogika slegs oppervlakkige raamooreenkoms nagaan.<sup>[[1]](#references)</sup>

## Verskille in Mobiele en Werkskermvertroue

Inheemse mobiele toepassings kan die aanvaller se koste verhoog met:

- **attestering van sensors of ’n Secure Element** vir kamerabuffers;
- **uitvoeringsintegriteit**-seine soos **Play Integrity** of **App Attest**;
- **bewegingskorrelasie** tussen video en versnellingsmeter- of giroskooptelemetrie.

Werkskermwebvloeie het gewoonlik nie ’n ekwivalente kamera-vertrouensketting nie, en is dus oor die algemeen die pad van die minste weerstand.<sup>[[1]](#references)</sup>

## Aantekeninge vir Verdedigingshersiening

Wanneer ’n KYC- of liveness-integrasie hersien word, verifieer of dit:

- ’n **werkskermblaaier-terugval** toelaat vir ’n werkvloei wat slegs vir mobiele vaslegging bedreigingsgemodelleer is;
- hoofsaaklik op **algoritmiese liveness** staatmaak sonder sterk menslike eskalasie vir verdagte sessies;
- **stabiele of voorspelbare uitdagings** gebruik wat vooraf opgeneem en in ’n generasiepyplyn ingevoer kan word;
- **`getUserMedia`-monkeypatching**, virtuele kameras, teenstrydige blaaier-hardewaretelemetrie of ontbrekende toestelattestering bespeur.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
