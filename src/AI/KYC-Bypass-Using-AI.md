# KYC Bypass Using AI

{{#include ../banners/hacktricks-training.md}}

Generative models zinaweza kutumika **kubypass KYC inayotegemea browser, uthibitishaji wa umri, na workflows za biometric liveness**. Sehemu dhaifu mara nyingi **si transport au cloud liveness provider, bali camera trust boundary**: browser ya desktop kwa kawaida huamini kifaa chochote ambacho `getUserMedia()` huonyesha kama webcam.<sup>[[1]](#references)</sup>

## Mlolongo wa Mashambulizi wa Kivitendo

1. **Tengeneza media inayokidhi challenge** kwa video-to-video model kutoka kwa source actor na victim reference image.<sup>[[1]](#references)</sup>
2. **Inject forged stream kabla ya signing au upload**, kwa mfano kupitia Linux virtual camera iliyoundwa na `v4l2loopback` na kulishwa na OBS au FFmpeg.<sup>[[3]](#references)</sup>
3. Ruhusu browser na vendor SDK (WebRTC, AWS, n.k.) **zikamate, zisaini, na zipakie attacker-controlled frames kana kwamba zimetoka kwenye webcam halisi**.<sup>[[2]](#references)</sup>

Hili ni muhimu wakati wa assessments kwa sababu signed WebSocket chunks au proprietary SDK framing zinaweza kufanya **network-layer tampering** isiwe ya kivitendo, ilhali **camera-layer injection** bado inafanya kazi.<sup>[[1]](#references)</sup>

## Njia Muhimu za Testing

- **Virtual webcam acceptance**: ikiwa flow inafanya kazi kutoka kwenye browser ya desktop, test kama OBS, `v4l2loopback`, au vendor virtual cameras zinakubaliwa kama peripherals za kawaida.<sup>[[1]](#references)</sup>
- **Camera API redirection kwenye mobile**: mobile flows za native bado zinaweza kuwa vulnerable wakati Frida inafanya hooks kwenye camera APIs na kubadilisha sensor buffers kwa frames kutoka kwenye MP4 au virtual camera inayotegemea emulator.
- **Constraint weakening**: pages zinazohitaji `deviceId`, `frameRate`, `width`, `height`, au `facingMode` halisi wakati mwingine zinaweza kubypass kwa kufanya monkeypatching ya `navigator.mediaDevices.getUserMedia` na kubadilisha strict constraints kwa broader ranges.<sup>[[4]](#references)</sup>
- **Low-quality generation pamoja na post-processing**: generate video ya bei nafuu zaidi ambayo model inaweza ku-render kwa uaminifu, kisha tumia FFmpeg upscaling au frame interpolation kutimiza capture requirements.
- **Predictable active challenges**: sequences zinazorudiwa za kugeuza kichwa au kuwasha flash zinafaa kurekodiwa na kureplayed kupitia generative workflow.
- **Weak replay detection**: scene perturbations rahisi, kama crop au position shifts, mabadiliko ya overlay, au motion kidogo, zinaweza kutosha wakati anti-replay logic inakagua tu superficial frame similarity.<sup>[[1]](#references)</sup>

## Tofauti za Trust Kati ya Mobile na Desktop

Native mobile apps zinaweza kuongeza gharama ya attacker kupitia:<sup>[[1]](#references)</sup>

- **sensor au Secure Element attestation** kwa camera buffers;
- **execution-integrity** signals kama **Play Integrity** au **App Attest**;
- **motion correlation** kati ya video na accelerometer au gyroscope telemetry.

Desktop web flows kwa kawaida hazina camera chain of trust inayolingana, hivyo kwa ujumla huwa njia yenye upinzani mdogo zaidi.<sup>[[1]](#references)</sup>

## Maelezo ya Defensive Review

Unapokagua KYC au liveness integration, thibitisha kama:<sup>[[1]](#references)</sup>

- inaruhusu **desktop-browser fallback** kwa workflow iliyofanyiwa threat modeling kwa mobile capture pekee;
- inategemea zaidi **algorithmic liveness** bila human escalation thabiti kwa sessions zenye mashaka;
- inatumia **challenges thabiti au zinazotabirika** ambazo zinaweza kurekodiwa mapema na kuingizwa kwenye generation pipeline;
- inagundua **`getUserMedia` monkeypatching**, virtual cameras, browser hardware telemetry isiyolingana, au device attestation inayokosekana.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
