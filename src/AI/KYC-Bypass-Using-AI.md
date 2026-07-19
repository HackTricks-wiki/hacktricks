# Zaobilaženje KYC-a pomoću AI-ja

{{#include ../banners/hacktricks-training.md}}

Generativni modeli mogu da se koriste za **zaobilaženje KYC procedura, provere starosti i biometrijskih procedura provere živosti zasnovanih na browseru**. Slaba tačka često **nije transport ili cloud provajder za proveru živosti, već granica poverenja kamere**: desktop browser obično veruje bilo kom uređaju koji `getUserMedia()` izloži kao web-kameru.

## Praktični lanac napada

1. **Generisati medij usklađen sa izazovom** pomoću video-to-video modela, koristeći izvornog aktera i referentnu sliku žrtve.
2. **Ubaciti falsifikovani stream pre potpisivanja ili upload-a**, na primer putem Linux virtuelne kamere kreirane pomoću `v4l2loopback` i napajane iz OBS-a ili FFmpeg-a.
3. Dozvoliti browseru i SDK-u provajdera (WebRTC, AWS itd.) da **snime, potpišu i upload-uju frejmove pod kontrolom napadača kao da potiču sa stvarne web-kamere**.

Ovo je važno tokom procena zato što potpisani WebSocket delovi ili proprietary SDK framing mogu učiniti **manipulaciju na mrežnom sloju** nepraktičnom, dok **ubacivanje na sloju kamere** i dalje funkcioniše.

## Najvredniji uglovi za testiranje

- **Prihvatanje virtuelne web-kamere**: ako tok funkcioniše iz desktop browsera, testirati da li se OBS, `v4l2loopback` ili virtuelne kamere provajdera prihvataju kao normalni periferni uređaji.
- **Preusmeravanje Camera API-ja na mobilnim uređajima**: nativni mobilni tokovi i dalje mogu biti ranjivi kada Frida hook-uje Camera API-je i zamenjuje senzorske baferе frejmovima iz MP4 fajla ili virtuelne kamere zasnovane na emulatoru.
- **Ublažavanje ograničenja**: stranice koje zahtevaju tačan `deviceId`, `frameRate`, `width`, `height` ili `facingMode` ponekad mogu da se zaobiđu monkeypatching-om funkcije `navigator.mediaDevices.getUserMedia` i zamenom strogih ograničenja širim opsezima.
- **Generisanje niskog kvaliteta uz post-processing**: generisati najjeftiniji video koji model može pouzdano da renderuje, a zatim koristiti FFmpeg upscaling ili interpolaciju frejmova za ispunjavanje zahteva snimanja.
- **Predvidljivi aktivni izazovi**: sekvence ponovljenih pokreta glave ili bljeskova svetla vredi snimiti i reprodukovati kroz generativni workflow.
- **Slaba detekcija replay-a**: jednostavne izmene scene, poput crop-a ili pomeranja položaja, promena overlay-a ili blagog pokreta, mogu biti dovoljne kada anti-replay logika proverava samo površinsku sličnost frejmova.

## Razlike u poverenju između mobilnih i desktop uređaja

Nativne mobilne aplikacije mogu povećati trošak napadača pomoću:

- **attestation-a senzora ili Secure Element-a** za baferе kamere;
- signala **integriteta izvršavanja**, kao što su **Play Integrity** ili **App Attest**;
- **korelacije pokreta** između videa i telemetrije akcelerometra ili žiroskopa.

Desktop web tokovima obično nedostaje ekvivalentan lanac poverenja kamere, pa su oni uglavnom put najmanjeg otpora.

## Napomene za odbrambeni pregled

Prilikom pregleda KYC integracije ili integracije provere živosti, proveriti da li ona:

- dozvoljava **fallback na desktop browser** za workflow koji je modeliran pretnjama samo za mobilno snimanje;
- uglavnom zavisi od **algoritamske provere živosti** bez snažne eskalacije ka ljudskom proveravaču za sumnjive sesije;
- koristi **stabilne ili predvidljive izazove** koji mogu unapred da se snime i proslede u generativni pipeline;
- detektuje **monkeypatching funkcije `getUserMedia`**, virtuelne kamere, nedoslednu telemetriju browser hardvera ili nedostatak device attestation-a.

## Reference

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
