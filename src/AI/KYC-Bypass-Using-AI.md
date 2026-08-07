# Zaobilaženje KYC-a pomoću AI-ja

{{#include ../banners/hacktricks-training.md}}

Generativni modeli mogu se koristiti za **zaobilaženje browser-based KYC, provere uzrasta i biometrijskih liveness procedura**. Slaba tačka često **nije transport ili cloud liveness provajder, već granica poverenja kamere**: desktop browser obično veruje bilo kom uređaju koji `getUserMedia()` izloži kao webcam.<sup>[[1]](#references)</sup>

## Praktični lanac napada

1. **Generisati medije usklađene sa izazovom** pomoću video-to-video modela, koristeći izvornog aktera i referentnu sliku žrtve.<sup>[[1]](#references)</sup>
2. **Ubrizgati falsifikovani stream pre potpisivanja ili upload-a**, na primer putem Linux virtuelne kamere kreirane pomoću `v4l2loopback` i napajane iz OBS-a ili FFmpeg-a.<sup>[[3]](#references)</sup>
3. Omogućiti browser-u i vendor SDK-u (WebRTC, AWS itd.) da **snime, potpišu i upload-uju frejmove pod kontrolom napadača kao da potiču sa stvarne webcam kamere**.<sup>[[2]](#references)</sup>

Ovo je važno tokom assessment-a zato što potpisani WebSocket chunk-ovi ili proprietary SDK framing mogu učiniti **mrežno manipulisanje** nepraktičnim, dok **ubrizgavanje na sloju kamere** i dalje funkcioniše.<sup>[[1]](#references)</sup>

## Najvažniji uglovi testiranja

- **Prihvatanje virtuelne webcam kamere**: ako flow funkcioniše iz desktop browser-a, testirati da li se OBS, `v4l2loopback` ili vendor virtuelne kamere prihvataju kao normalni periferni uređaji.<sup>[[1]](#references)</sup>
- **Preusmeravanje Camera API-ja na mobilnim uređajima**: native mobilni flow-ovi i dalje mogu biti ranjivi kada Frida hook-uje camera API-je i zamenjuje senzorske buffere frejmovima iz MP4 fajla ili virtuelne kamere zasnovane na emulatoru.
- **Slabljenje ograničenja**: stranice koje zahtevaju tačan `deviceId`, `frameRate`, `width`, `height` ili `facingMode` ponekad se mogu zaobići monkeypatching-om `navigator.mediaDevices.getUserMedia` i zamenom strogih ograničenja širim opsezima.<sup>[[4]](#references)</sup>
- **Generisanje niskog kvaliteta uz post-processing**: generisati najjeftiniji video koji model može pouzdano da renderuje, a zatim koristiti FFmpeg upscaling ili interpolaciju frejmova kako bi se ispunili zahtevi za capture.
- **Predvidivi aktivni izazovi**: ponovljene sekvence pomeranja glave ili bljeskanja svetla vredi snimiti i ponovo reprodukovati kroz generativni workflow.
- **Slaba detekcija replay-a**: jednostavne promene scene, kao što su pomeranje crop-a ili pozicije, izmene overlay-a ili blago kretanje, mogu biti dovoljne kada anti-replay logika proverava samo površnu sličnost frejmova.<sup>[[1]](#references)</sup>

## Razlike u poverenju između mobilnih i desktop uređaja

Native mobilne aplikacije mogu povećati trošak napadača pomoću:<sup>[[1]](#references)</sup>

- **attestation-a senzora ili Secure Element-a** za camera buffere;
- signala **execution-integrity**, kao što su **Play Integrity** ili **App Attest**;
- **korelacije kretanja** između videa i telemetrije akcelerometra ili žiroskopa.

Desktop web flow-ovi obično nemaju ekvivalentan lanac poverenja kamere, pa su generalno put najmanjeg otpora.<sup>[[1]](#references)</sup>

## Napomene za defensive review

Prilikom pregleda KYC ili liveness integracije proveriti da li ona:<sup>[[1]](#references)</sup>

- dozvoljava **fallback za desktop browser** u workflow-u koji je threat-modelovan samo za mobilni capture;
- uglavnom zavisi od **algorithmic liveness-a** bez snažne eskalacije ka ljudskom proveravaču za sumnjive sesije;
- koristi **stabilne ili predvidive izazove** koji se mogu unapred snimiti i proslediti u generation pipeline;
- detektuje **`getUserMedia` monkeypatching**, virtuelne kamere, nedoslednu telemetriju browser hardvera ili nedostatak device attestation-a.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
