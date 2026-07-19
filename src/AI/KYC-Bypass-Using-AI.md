# KYC-omseiling met AI

{{#include ../banners/hacktricks-training.md}}

Generatiewe modelle kan gebruik word om **blaaier-gebaseerde KYC-, ouderdomsverifikasie- en biometriese liveness-werkvloeie te omseil**. Die swak punt is dikwels **nie** die transportlaag of die cloud-liveness-verskaffer nie, maar die **kamera-vertrouensgrens**: ’n desktop-blaaier vertrou gewoonlik enige toestel wat `getUserMedia()` as ’n webcam blootstel.

## Praktiese Aanvalsketting

1. **Genereer media wat aan die uitdaging voldoen** met ’n video-to-video-model vanaf ’n bronpersoon en ’n slagoffer se verwysingsbeeld.
2. **Injekteer die vervalste stroom voor ondertekening of oplaai**, byvoorbeeld deur ’n Linux-virtuele kamera te skep met `v4l2loopback` en dit deur OBS of FFmpeg te voer.
3. Laat die blaaier en vendor SDK (WebRTC, AWS, ens.) **die aanvaller-beheerde rame vaslê, onderteken en oplaai asof dit van ’n werklike webcam afkomstig is**.

Dit is belangrik tydens assessments omdat ondertekende WebSocket-brokkies of eie SDK-framing **manipulasie op netwerkvlak** onprakties kan maak, terwyl **injektie op kamerasvlak** steeds werk.

## Waardevolle Toetsingshoeke

- **Aanvaarding van virtuele webcams**: as die vloei vanaf ’n desktop-blaaier werk, toets of OBS, `v4l2loopback` of vendor-virtuele kameras as normale randtoestelle aanvaar word.
- **Kamera-API-herleiding op mobiele toestelle**: native mobiele vloei kan steeds kwesbaar wees wanneer Frida kamera-API’s hook en sensorbuffers vervang met rame uit ’n MP4 of ’n emulator-gesteunde virtuele kamera.
- **Verswakking van beperkings**: bladsye wat ’n presiese `deviceId`, `frameRate`, `width`, `height` of `facingMode` vereis, kan soms omseil word deur `navigator.mediaDevices.getUserMedia` te monkeypatch en streng beperkings met breër reekse te vervang.
- **Lae-gehalte-generering plus naverwerking**: genereer die goedkoopste video wat die model betroubaar kan lewer, en gebruik daarna FFmpeg-upscaling of raaminterpolasie om aan vasleggingsvereistes te voldoen.
- **Voorspelbare aktiewe uitdagings**: herhaalde kopbewegings- of ligflitsreekse is die moeite werd om op te neem en deur ’n generatiewe workflow te herhaal.
- **Swak replay-detectie**: eenvoudige toneelversteurings, soos crop- of posisieverskuiwings, veranderinge aan overlays of geringe beweging, kan voldoende wees wanneer die anti-replay-logika slegs oppervlakkige raam-ooreenkoms kontroleer.

## Vertrouensverskille tussen Mobile en Desktop

Native mobiele apps kan die aanvaller se koste verhoog met:

- **attestasie van sensors of Secure Elements** vir kamerabuffers;
- **uitvoeringsintegriteit**-seine soos **Play Integrity** of **App Attest**;
- **bewegingskorrelasie** tussen video- en versnellingsmeter- of giroskoop-telemetrie.

Desktop-webvloeie het gewoonlik nie ’n ekwivalente ketting van vertroue vir kameras nie, en is dus oor die algemeen die pad van die minste weerstand.

## Notas vir Defensive Review

Wanneer ’n KYC- of liveness-integrasie hersien word, verifieer of dit:

- ’n **desktop-blaaier-fallback** toelaat vir ’n workflow wat slegs vir mobiele vaslegging threat-modeled is;
- hoofsaaklik op **algoritmiese liveness** staatmaak sonder sterk menslike eskalasie vir verdagte sessies;
- **stabiele of voorspelbare uitdagings** gebruik wat vooraf opgeneem en in ’n generasie-pipeline gevoer kan word;
- **`getUserMedia`-monkeypatching**, virtuele kameras, inkonsekwente blaaier-hardewaretelemetrie of ontbrekende toestelattestasie opspoor.

## Verwysings

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
