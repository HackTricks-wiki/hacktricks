# Zaobilaženje KYC-a pomoću AI-ja

{{#include ../banners/hacktricks-training.md}}

Generativni modeli mogu da se koriste za **zaobilaženje KYC procesa zasnovanih na browseru, verifikacije uzrasta i workflow-a za proveru biometrijske živosti**. Slaba tačka često **nije** transport ili cloud liveness provajder, već **granica poverenja kamere**: desktop browser obično veruje bilo kom uređaju koji `getUserMedia()` izloži kao web kameru.<sup>[[1]](#references)</sup>

## Praktični lanac napada

1. **Generisati medij usklađen sa izazovom** pomoću video-to-video modela, koristeći izvornog aktera i referentnu sliku žrtve.
2. **Ubaciti falsifikovani stream pre potpisivanja ili upload-a**, na primer putem Linux virtuelne kamere kreirane pomoću `v4l2loopback`, kojoj se prosleđuje sadržaj iz OBS-a ili FFmpeg-a.
3. Dozvoliti browseru i vendor SDK-u (WebRTC, AWS itd.) da **snime, potpišu i upload-uju frejmove pod kontrolom napadača kao da potiču sa stvarne web kamere**.

Ovo je važno tokom procena zato što potpisani WebSocket chunk-ovi ili proprietary SDK framing mogu učiniti **manipulaciju na mrežnom sloju** nepraktičnom, dok **ubacivanje na sloju kamere** i dalje funkcioniše.<sup>[[1]](#references)</sup>

## Najvažniji uglovi za testiranje

- **Prihvatanje virtuelne web kamere**: ako workflow funkcioniše iz desktop browsera, testirajte da li se OBS, `v4l2loopback` ili vendor virtuelne kamere prihvataju kao normalni periferni uređaji.
- **Preusmeravanje Camera API-ja na mobilnim uređajima**: native mobilni workflow-i i dalje mogu biti ranjivi kada Frida hook-uje Camera API-je i zamenjuje senzorske buffere frejmovima iz MP4 fajla ili virtuelne kamere zasnovane na emulatoru.
- **Slabljenje ograničenja**: stranice koje zahtevaju tačan `deviceId`, `frameRate`, `width`, `height` ili `facingMode` ponekad se mogu zaobići monkeypatch-ovanjem `navigator.mediaDevices.getUserMedia` i zamenom strogih ograničenja širim opsezima.
- **Generisanje niskog kvaliteta uz post-processing**: generisati najjeftiniji video koji model može pouzdano da renderuje, a zatim koristiti FFmpeg upscaling ili interpolaciju frejmova kako bi se ispunili zahtevi za snimanje.
- **Predvidivi aktivni izazovi**: sekvence ponovljenih pokreta glave ili bljeskova svetla vredi snimiti i ponovo reprodukovati kroz generativni workflow.
- **Slaba detekcija replay-a**: jednostavne izmene scene, kao što su crop ili pomeranje pozicije, izmene overlay-a ili blago kretanje, mogu biti dovoljne kada anti-replay logika proverava samo površinsku sličnost frejmova.<sup>[[1]](#references)</sup>

## Razlike u poverenju između mobilnih i desktop uređaja

Native mobilne aplikacije mogu povećati cenu napadača pomoću:

- **attestation-a senzora ili Secure Element-a** za buffere kamere;
- signala **integriteta izvršavanja**, kao što su **Play Integrity** ili **App Attest**;
- **korelacije pokreta** između videa i telemetrije akcelerometra ili žiroskopa.

Desktop web workflow-i obično nemaju ekvivalentan lanac poverenja kamere, pa su generalno put najmanjeg otpora.<sup>[[1]](#references)</sup>

## Napomene za bezbednosni pregled

Prilikom pregleda KYC ili liveness integracije proverite da li ona:

- dozvoljava **fallback na desktop browser** za workflow koji je modeliran za pretnje samo pri mobilnom snimanju;
- uglavnom se oslanja na **algoritamsku proveru živosti** bez snažne eskalacije ka čoveku za sumnjive sesije;
- koristi **stabilne ili predvidive izazove** koji se mogu unapred snimiti i proslediti u generativni pipeline;
- detektuje **monkeypatching funkcije `getUserMedia`**, virtuelne kamere, nedoslednu telemetriju browser hardvera ili nedostatak device attestation-a.<sup>[[1]](#references)</sup>

## Reference

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
