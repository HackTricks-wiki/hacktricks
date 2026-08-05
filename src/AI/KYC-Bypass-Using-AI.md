# KYC Bypass Using AI

{{#include ../banners/hacktricks-training.md}}

Generative models zinaweza kutumiwa **kuzunguka browser-based KYC, uthibitishaji wa umri, na workflows za biometric liveness**. Kitu dhaifu mara nyingi **si transport wala cloud liveness provider**, bali ni **camera trust boundary**: desktop browser kwa kawaida huamini kifaa chochote ambacho `getUserMedia()` hukiwasilisha kama webcam.<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. **Tengeneza media inayokidhi challenge** kwa kutumia video-to-video model kutoka kwa source actor na victim reference image.
2. **Inject forged stream kabla ya signing au upload**, kwa mfano kupitia Linux virtual camera iliyoundwa kwa `v4l2loopback` na kulishwa na OBS au FFmpeg.
3. Ruhusu browser na vendor SDK (WebRTC, AWS, n.k.) **kukamata, kusaini, na kupakia frames zinazodhibitiwa na attacker kana kwamba zilitoka kwenye webcam halisi**.

Hili ni muhimu wakati wa assessments kwa sababu signed WebSocket chunks au proprietary SDK framing zinaweza kufanya **network-layer tampering** isiwe rahisi, huku **camera-layer injection** ikiendelea kufanya kazi.<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: ikiwa flow inafanya kazi kutoka kwenye desktop browser, jaribu kama OBS, `v4l2loopback`, au vendor virtual cameras zinakubaliwa kama peripherals za kawaida.
- **Camera API redirection on mobile**: native mobile flows bado zinaweza kuwa vulnerable wakati Frida hooks camera APIs na kubadilisha sensor buffers kwa frames kutoka kwenye MP4 au virtual camera inayotegemea emulator.
- **Constraint weakening**: pages zinazohitaji `deviceId`, `frameRate`, `width`, `height`, au `facingMode` mahususi wakati mwingine zinaweza kuzuiwa kwa monkeypatching `navigator.mediaDevices.getUserMedia` na kubadilisha strict constraints kuwa broader ranges.
- **Low-quality generation plus post-processing**: tengeneza video ya gharama ya chini zaidi ambayo model inaweza ku-render kwa uhakika, kisha tumia FFmpeg upscaling au frame interpolation kutimiza capture requirements.
- **Predictable active challenges**: sequences za head-movement au light-flash zinazorudiwa zinafaa kurekodiwa na replay kupitia generative workflow.
- **Weak replay detection**: scene perturbations rahisi, kama crop au position shifts, overlay changes, au motion kidogo, zinaweza kutosha wakati anti-replay logic hukagua tu superficial frame similarity.<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile apps zinaweza kuongeza gharama kwa attacker kupitia:

- **sensor au Secure Element attestation** kwa camera buffers;
- **execution-integrity** signals kama **Play Integrity** au **App Attest**;
- **motion correlation** kati ya video na accelerometer au gyroscope telemetry.

Desktop web flows kwa kawaida hazina camera chain of trust inayolingana, hivyo kwa ujumla huwa njia yenye upinzani mdogo zaidi.<sup>[[1]](#references)</sup>

## Defensive Review Notes

Wakati wa kukagua KYC au liveness integration, thibitisha kama:

- inaruhusu **desktop-browser fallback** kwa workflow iliyofanyiwa threat modeling kwa mobile capture pekee;
- inategemea zaidi **algorithmic liveness** bila human escalation thabiti kwa sessions zinazotiliwa shaka;
- inatumia **stable au predictable challenges** zinazoweza kurekodiwa mapema na kuingizwa kwenye generation pipeline;
- inagundua **`getUserMedia` monkeypatching**, virtual cameras, browser hardware telemetry isiyolingana, au ukosefu wa device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
