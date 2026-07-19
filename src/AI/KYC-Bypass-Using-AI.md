# KYC Bypass kwa Kutumia AI

{{#include ../banners/hacktricks-training.md}}

Generative models zinaweza kutumiwa **kupita workflows za KYC, uthibitishaji wa umri, na biometric liveness zinazotegemea browser**. Sehemu dhaifu mara nyingi **si transport au cloud liveness provider**, bali ni **camera trust boundary**: desktop browser kwa kawaida huamini kifaa chochote ambacho `getUserMedia()` huonyesha kama webcam.

## Practical Attack Chain

1. **Tengeneza media inayotii challenge** kwa kutumia video-to-video model kutoka kwa source actor na victim reference image.
2. **Ingiza stream iliyoghushiwa kabla ya signing au upload**, kwa mfano kupitia Linux virtual camera iliyoundwa na `v4l2loopback` na kupewa data na OBS au FFmpeg.
3. Ruhusu browser na vendor SDK (WebRTC, AWS, n.k.) **kucapture, kusign, na kuupload frames zinazodhibitiwa na attacker kana kwamba zilitoka kwenye webcam halisi**.

Hili ni muhimu wakati wa assessments kwa sababu signed WebSocket chunks au proprietary SDK framing zinaweza kufanya **network-layer tampering** isiwe practical, huku **camera-layer injection** ikiendelea kufanya kazi.

## High-Value Testing Angles

- **Virtual webcam acceptance**: ikiwa flow inafanya kazi kutoka kwenye desktop browser, test kama OBS, `v4l2loopback`, au vendor virtual cameras zinakubaliwa kama peripherals za kawaida.
- **Camera API redirection on mobile**: native mobile flows bado zinaweza kuwa vulnerable wakati Frida hooks camera APIs na kubadilisha sensor buffers kwa frames kutoka kwenye MP4 au emulator-backed virtual camera.
- **Constraint weakening**: pages zinazohitaji `deviceId`, `frameRate`, `width`, `height`, au `facingMode` maalum wakati mwingine zinaweza kupitwa kwa monkeypatching `navigator.mediaDevices.getUserMedia` na kubadilisha strict constraints kuwa broad ranges.
- **Low-quality generation plus post-processing**: generate video ya gharama nafuu zaidi ambayo model inaweza ku-render kwa kutegemewa, kisha tumia FFmpeg upscaling au frame interpolation kutimiza capture requirements.
- **Predictable active challenges**: sequences za head-movement au light-flash zinazojirudia zinafaa kurekodiwa na kuchezwa tena kupitia generative workflow.
- **Weak replay detection**: scene perturbations rahisi, kama crop au position shifts, overlay changes, au motion ndogo, zinaweza kutosha wakati anti-replay logic hukagua tu superficial frame similarity.

## Mobile vs. Desktop Trust Differences

Native mobile apps zinaweza kuongeza gharama ya attacker kupitia:

- **sensor au Secure Element attestation** kwa camera buffers;
- ishara za **execution-integrity** kama **Play Integrity** au **App Attest**;
- **motion correlation** kati ya video na accelerometer au gyroscope telemetry.

Desktop web flows kwa kawaida hazina camera chain of trust inayolingana, hivyo kwa jumla ndiyo njia yenye resistance ndogo zaidi.

## Defensive Review Notes

Unapokagua KYC au liveness integration, thibitisha kama:

- inaruhusu **desktop-browser fallback** kwa workflow iliyofanyiwa threat modeling kwa mobile capture pekee;
- inategemea zaidi **algorithmic liveness** bila human escalation imara kwa sessions zinazotia shaka;
- inatumia **stable au predictable challenges** zinazoweza kurekodiwa mapema na kuingizwa kwenye generation pipeline;
- inatambua **`getUserMedia` monkeypatching**, virtual cameras, browser hardware telemetry isiyolingana, au ukosefu wa device attestation.

## References

- [Synacktiv - KYC: Kupita uthibitishaji wa umri kwa kutumia generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
