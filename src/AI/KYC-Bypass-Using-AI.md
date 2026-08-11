# Zaobilaženje KYC-a pomoću AI-ja

{{#include ../banners/hacktricks-training.md}}

Generativni modeli mogu da se koriste za **zaobilaženje KYC procedura, provere uzrasta i biometrijskih liveness procesa zasnovanih na browseru**. Slaba tačka često **nije transport ili cloud liveness provider, već granica poverenja kamere**: desktop browser obično veruje svakom uređaju koji `getUserMedia()` izloži kao web kameru.<sup>[[1]](#references)</sup>

## Praktičan lanac napada

1. **Generisati medijski sadržaj usklađen sa izazovom** pomoću video-to-video modela, koristeći izvornog aktera i referentnu sliku žrtve.<sup>[[1]](#references)</sup>
2. **Ubaciti falsifikovani stream pre potpisivanja ili upload-a**, na primer putem Linux virtuelne kamere kreirane pomoću `v4l2loopback` i napajane iz OBS-a ili FFmpeg-a.<sup>[[3]](#references)</sup>
3. Omogućiti browseru i vendor SDK-u (WebRTC, AWS itd.) da **snime, potpišu i upload-uju frejmove pod kontrolom napadača kao da potiču sa prave web kamere**.<sup>[[2]](#references)</sup>

Ovo je važno tokom procena zato što potpisani WebSocket delovi ili framing proprietarnog SDK-a mogu učiniti **manipulaciju na mrežnom sloju** nepraktičnom, dok **ubacivanje na sloju kamere** i dalje funkcioniše.<sup>[[1]](#references)</sup>

## Najvredniji uglovi testiranja

- **Prihvatanje virtuelne web kamere**: ako proces funkcioniše iz desktop browsera, proverite da li se OBS, `v4l2loopback` ili virtuelne kamere vendora prihvataju kao normalni periferni uređaji.<sup>[[1]](#references)</sup>
- **Preusmeravanje Camera API-ja na mobilnim uređajima**: native procesi i dalje mogu biti ranjivi kada runtime instrumentacija, kao što je Frida, hook-uje Camera API-je i zamenjuje baferе senzora frejmovima iz MP4 fajla ili virtuelne kamere zasnovane na emulatoru. Ovo zahteva kontrolu nad klijentskim execution okruženjem i treba ga procenjivati zajedno sa root/jailbreak signalima i signalima integriteta aplikacije.<sup>[[1]](#references)</sup>
- **Slabljenje ograničenja**: stranice koje zahtevaju tačan `deviceId`, `frameRate`, `width`, `height` ili `facingMode` ponekad se mogu zaobići monkeypatching-om funkcije `navigator.mediaDevices.getUserMedia` i zamenom strogih ograničenja širim opsezima.<sup>[[4]](#references)</sup>
- **Generisanje niskog kvaliteta uz post-processing**: testirajte da li se jeftino generisani video može dovoljno kvalitetno uvećati ili interpolirati po frejmovima pomoću FFmpeg-a kako bi zadovoljio capture ograničenja.<sup>[[1]](#references)</sup>
- **Predvidivi aktivni izazovi**: ponavljajuće sekvence pomeranja glave ili bljeskanja svetla vredi snimiti i ponovo reprodukovati kroz generativni workflow.
- **Slaba detekcija replay-a**: jednostavne izmene scene, kao što su pomeranje crop-a ili pozicije, promene overlay-a ili blago kretanje, mogu biti dovoljne kada anti-replay logika proverava samo površnu sličnost frejmova.<sup>[[1]](#references)</sup>

## Razlike u poverenju između mobilnih i desktop uređaja

Native mobilne aplikacije mogu povećati trošak napadača pomoću:<sup>[[1]](#references)</sup>

- **signala porekla ili attestation signala zasnovanih na hardveru**, uključujući dokaze podržane Secure Element-om, kada ih platforma i capture stack zaista izlažu;
- **signala integriteta izvršavanja**, kao što su **Play Integrity** ili **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **korelacije kretanja** između videa i telemetrije akcelerometra ili žiroskopa.

Desktop web procesima obično nedostaje ekvivalentan lanac poverenja kamere, pa oni generalno predstavljaju put najmanjeg otpora.<sup>[[1]](#references)</sup>

## Napomene za odbrambeni pregled

Prilikom pregleda KYC ili liveness integracije proverite da li ona:<sup>[[1]](#references)</sup>

- omogućava **fallback za desktop browser** u procesu koji je threat-modelovan samo za mobilni capture;
- uglavnom zavisi od **algoritamskog liveness-a** bez snažne eskalacije ka ljudima za sumnjive sesije;
- koristi **stabilne ili predvidive izazove** koji se mogu unapred snimiti i proslediti u generation pipeline;
- detektuje **monkeypatching funkcije `getUserMedia`**, virtuelne kamere, nedoslednu telemetriju browser hardvera ili nedostatak device attestation-a.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Zaobilaženje provere uzrasta pomoću generativnih video modela](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
