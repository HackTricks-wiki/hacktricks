# KYC Bypass Using AI

{{#include ../banners/hacktricks-training.md}}

Generative models zinaweza kutumika **kupita workflows za KYC za browser, uthibitishaji wa umri, na biometric liveness**. Sehemu dhaifu mara nyingi **si transport au cloud liveness provider**, bali ni **camera trust boundary**: browser ya desktop kwa kawaida huamini kifaa chochote ambacho `getUserMedia()` hufichua kama webcam.<sup>[[1]](#references)</sup>

## Mlolongo wa Shambulio kwa Vitendo

1. **Tengeneza media inayotii challenge** kwa kutumia video-to-video model kutoka kwa source actor na victim reference image.<sup>[[1]](#references)</sup>
2. **Ingiza stream iliyoghushiwa kabla ya signing au upload**, kwa mfano kupitia Linux virtual camera iliyoundwa kwa `v4l2loopback` na kupewa data na OBS au FFmpeg.<sup>[[3]](#references)</sup>
3. Ruhusu browser na vendor SDK (WebRTC, AWS, n.k.) **zikamate, zisaini, na zipakie frames zinazodhibitiwa na attacker kana kwamba zimetoka kwenye webcam halisi**.<sup>[[2]](#references)</sup>

Hili ni muhimu wakati wa assessments kwa sababu signed WebSocket chunks au proprietary SDK framing zinaweza kufanya **network-layer tampering** isiwe ya vitendo, ilhali **camera-layer injection** bado inafanya kazi.<sup>[[1]](#references)</sup>

## Maeneo ya Upimaji yenye Thamani Kubwa

- **Kukubaliwa kwa virtual webcam**: ikiwa flow inafanya kazi kutoka kwenye desktop browser, pima kama OBS, `v4l2loopback`, au vendor virtual cameras zinakubaliwa kama peripherals za kawaida.<sup>[[1]](#references)</sup>
- **Camera API redirection kwenye mobile**: native flows bado zinaweza kuwa vulnerable wakati runtime instrumentation kama Frida inahook camera APIs na kubadilisha sensor buffers kwa frames kutoka kwenye MP4 file au emulator-backed virtual camera. Hili linahitaji udhibiti wa client execution environment na linapaswa kutathminiwa pamoja na root/jailbreak na application-integrity signals.<sup>[[1]](#references)</sup>
- **Kupunguza ukali wa constraints**: pages zinazohitaji `deviceId`, `frameRate`, `width`, `height`, au `facingMode` maalum zinaweza wakati mwingine kupitwa kwa monkeypatching `navigator.mediaDevices.getUserMedia` na kubadilisha strict constraints kwa broader ranges.<sup>[[4]](#references)</sup>
- **Generation yenye quality ya chini pamoja na post-processing**: pima kama video generated ya gharama ndogo inaweza kuupscaled au kufanyiwa frame interpolation kwa FFmpeg kwa kiwango cha kutosha kutimiza capture constraints.<sup>[[1]](#references)</sup>
- **Active challenges zinazotabirika**: sequences za kurudia za kusogeza kichwa au kuwasha mwanga zinafaa kurekodiwa na kurudiwa kupitia generative workflow.
- **Replay detection dhaifu**: scene perturbations rahisi, kama crop au position shifts, mabadiliko ya overlay, au motion ndogo, zinaweza kutosha wakati anti-replay logic inakagua tu superficial frame similarity.<sup>[[1]](#references)</sup>

## Tofauti za Trust Kati ya Mobile na Desktop

Native mobile apps zinaweza kuongeza gharama ya attacker kupitia:<sup>[[1]](#references)</sup>

- **hardware-backed provenance au attestation signals**, ikiwa ni pamoja na evidence inayoungwa mkono na Secure Element pale ambapo platform na capture stack huifichua;
- **execution-integrity** signals kama **Play Integrity** au **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **motion correlation** kati ya video na telemetry ya accelerometer au gyroscope.

Desktop web flows kwa kawaida hazina camera chain of trust inayolingana, kwa hiyo kwa ujumla ndiyo njia yenye upinzani mdogo zaidi.<sup>[[1]](#references)</sup>

## Vidokezo vya Defensive Review

Wakati wa kukagua KYC au liveness integration, thibitisha kama:<sup>[[1]](#references)</sup>

- inaruhusu **desktop-browser fallback** kwa workflow iliyofanyiwa threat modeling kwa mobile capture pekee;
- inategemea zaidi **algorithmic liveness** bila human escalation imara kwa suspicious sessions;
- inatumia **challenges thabiti au zinazotabirika** ambazo zinaweza kurekodiwa mapema na kuingizwa kwenye generation pipeline;
- inatambua **`getUserMedia` monkeypatching**, virtual cameras, browser hardware telemetry isiyolingana, au device attestation inayokosekana.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Kupita uthibitishaji wa umri kwa kutumia generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
