# KYC-omseiling met AI

{{#include ../banners/hacktricks-training.md}}

Generatiewe modelle kan gebruik word om **blaaiergebaseerde KYC-, ouderdomsverifikasie- en biometriese liveness-werkvloeie te omseil**. Die swak punt is dikwels **nie die transportlaag of die cloud liveness-provider nie, maar die kamera-vertrouensgrens**: ’n desktop-blaaier vertrou gewoonlik enige toestel wat `getUserMedia()` as ’n webcam beskikbaar stel.<sup>[[1]](#references)</sup>

## Praktiese aanvalsketting

1. **Genereer media wat aan die challenge voldoen** met ’n video-to-video-model vanaf ’n bronakteur en ’n slagoffer-verwysingsbeeld.<sup>[[1]](#references)</sup>
2. **Injecteer die vervalste stroom voordat dit onderteken of opgelaai word**, byvoorbeeld deur ’n Linux-virtuele kamera te skep met `v4l2loopback` en dit deur OBS of FFmpeg te voer.<sup>[[3]](#references)</sup>
3. Laat die blaaier en vendor SDK (WebRTC, AWS, ens.) **die aanvaller-beheerde rame vaslê, onderteken en oplaai asof dit van ’n werklike webcam afkomstig is**.<sup>[[2]](#references)</sup>

Dit is belangrik tydens assessments omdat ondertekende WebSocket-brokkies of proprietary SDK-framing **netwerklaag-peutering** onprakties kan maak, terwyl **kamera-laaginjectie** steeds werk.<sup>[[1]](#references)</sup>

## Waardevolle toetshoeke

- **Aanvaarding van virtuele webcams**: indien die vloei vanuit ’n desktop-blaaier werk, toets of OBS, `v4l2loopback` of vendor-virtuele kameras as normale randtoestelle aanvaar word.<sup>[[1]](#references)</sup>
- **Kamera-API-herleiding op mobiele toestelle**: native-vloeie kan steeds kwesbaar wees wanneer runtime-instrumentasie soos Frida kamera-API’s hook en sensorbuffers vervang met rame uit ’n MP4-lêer of emulator-gesteunde virtuele kamera. Dit vereis beheer oor die kliënt se uitvoeringsomgewing en behoort saam met root/jailbreak- en application-integrity-seine geassesseer te word.<sup>[[1]](#references)</sup>
- **Verswakking van constraints**: bladsye wat ’n presiese `deviceId`, `frameRate`, `width`, `height` of `facingMode` vereis, kan soms omseil word deur `navigator.mediaDevices.getUserMedia` te monkeypatch en streng constraints met breër reekse te vervang.<sup>[[4]](#references)</sup>
- **Laegehalte-generering plus post-processing**: toets of goedkoop gegenereerde video met FFmpeg opgeskaal of met frame-interpolasie verwerk kan word om voldoende aan capture-constraints te voldoen.<sup>[[1]](#references)</sup>
- **Voorspelbare aktiewe challenges**: herhaalde kopbewegings- of ligflitsreekse is die moeite werd om op te neem en deur ’n generatiewe werkvloei te herhaal.
- **Swak replay-detectie**: eenvoudige toneelveranderings, soos crop- of posisieverskuiwings, overlay-veranderings of geringe beweging, kan voldoende wees wanneer die anti-replay-logika slegs oppervlakkige frame-ooreenkoms nagaan.<sup>[[1]](#references)</sup>

## Vertrouensverskille tussen mobiele toestelle en desktops

Native mobiele apps kan die aanvaller se koste verhoog met:<sup>[[1]](#references)</sup>

- **hardware-gesteunde herkoms- of attestation-seine**, insluitend Secure Element-gesteunde bewyse waar die platform en capture stack dit werklik beskikbaar stel;
- **uitvoeringsintegriteit-seine** soos **Play Integrity** of **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **bewegingskorrelasie** tussen video en versnellingsmeter- of giroskooptelemetrie.

Desktop-webvloeie het gewoonlik nie ’n ekwivalente kamera-vertrouensketting nie en is dus oor die algemeen die pad van die minste weerstand.<sup>[[1]](#references)</sup>

## Notas vir defensiewe hersiening

Wanneer ’n KYC- of liveness-integrasie hersien word, verifieer of dit:<sup>[[1]](#references)</sup>

- ’n **desktop-blaaier-fallback** toelaat vir ’n werkvloei wat slegs vir mobiele capture threat-modeled is;
- hoofsaaklik op **algoritmiese liveness** steun sonder sterk menslike eskalasie vir verdagte sessies;
- **stabiele of voorspelbare challenges** gebruik wat vooraf opgeneem en in ’n generasiepyplyn gevoer kan word;
- **`getUserMedia`-monkeypatching**, virtuele kameras, inkonsekwente blaaier-hardewaretelemetrie of ontbrekende device-attestation opspoor.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Omseil ouderdomsverifikasie met generatiewe videomodelle](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
