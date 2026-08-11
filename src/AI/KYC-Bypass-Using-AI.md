# AI का उपयोग करके KYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative models का उपयोग **browser-based KYC, age-verification और biometric liveness workflows को bypass करने** के लिए किया जा सकता है। कमजोर बिंदु अक्सर **transport या cloud liveness provider नहीं, बल्कि camera trust boundary** होती है: desktop browser आमतौर पर उस डिवाइस पर भरोसा करता है जिसे `getUserMedia()` webcam के रूप में expose करता है।<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. **Challenge-compliant media generate करें** और इसके लिए source actor तथा victim reference image से video-to-video model का उपयोग करें।<sup>[[1]](#references)</sup>
2. **Signing या upload से पहले forged stream inject करें**, उदाहरण के लिए `v4l2loopback` से बनाई गई Linux virtual camera के माध्यम से, जिसे OBS या FFmpeg feed कर रहा हो।<sup>[[3]](#references)</sup>
3. Browser और vendor SDK (WebRTC, AWS, आदि) को **attacker-controlled frames को ऐसे capture, sign और upload करने दें जैसे वे real webcam से आए हों**।<sup>[[2]](#references)</sup>

Assessments के दौरान यह महत्वपूर्ण है क्योंकि signed WebSocket chunks या proprietary SDK framing **network-layer tampering** को अव्यावहारिक बना सकते हैं, जबकि **camera-layer injection** फिर भी काम कर सकता है।<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: यदि flow desktop browser से काम करता है, तो जाँचें कि OBS, `v4l2loopback` या vendor virtual cameras को normal peripherals के रूप में स्वीकार किया जाता है या नहीं।<sup>[[1]](#references)</sup>
- **Camera API redirection on mobile**: native flows तब भी vulnerable हो सकते हैं जब Frida जैसे runtime instrumentation camera APIs पर hooks लगाकर sensor buffers को MP4 file या emulator-backed virtual camera के frames से replace करें। इसके लिए client execution environment पर control आवश्यक है और इसका assessment root/jailbreak तथा application-integrity signals के साथ किया जाना चाहिए।<sup>[[1]](#references)</sup>
- **Constraint weakening**: जिन pages में exact `deviceId`, `frameRate`, `width`, `height` या `facingMode` आवश्यक होते हैं, उन्हें कभी-कभी `navigator.mediaDevices.getUserMedia` को monkeypatch करके और strict constraints को broader ranges से replace करके bypass किया जा सकता है।<sup>[[4]](#references)</sup>
- **Low-quality generation plus post-processing**: जाँचें कि inexpensive generated video को FFmpeg की सहायता से capture constraints पूरा करने योग्य स्तर तक upscale या frame-interpolate किया जा सकता है या नहीं।<sup>[[1]](#references)</sup>
- **Predictable active challenges**: बार-बार दोहराए जाने वाले head-movement या light-flash sequences को record करके generative workflow के माध्यम से replay करना उपयोगी हो सकता है।
- **Weak replay detection**: crop या position shifts, overlay changes या slight motion जैसे simple scene perturbations पर्याप्त हो सकते हैं, यदि anti-replay logic केवल superficial frame similarity जाँचता हो।<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile apps attacker की लागत निम्नलिखित उपायों से बढ़ा सकते हैं:<sup>[[1]](#references)</sup>

- **hardware-backed provenance या attestation signals**, जिनमें Secure Element-backed evidence भी शामिल है, जहाँ platform और capture stack वास्तव में इसे expose करते हों;
- **execution-integrity** signals जैसे **Play Integrity** या **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- video और accelerometer या gyroscope telemetry के बीच **motion correlation**।

Desktop web flows में आमतौर पर camera chain of trust का equivalent नहीं होता, इसलिए वे सामान्यतः सबसे आसान path होते हैं।<sup>[[1]](#references)</sup>

## Defensive Review Notes

KYC या liveness integration की समीक्षा करते समय जाँचें कि क्या यह:<sup>[[1]](#references)</sup>

- ऐसे workflow के लिए **desktop-browser fallback** की अनुमति देता है जिसे केवल mobile capture के लिए threat-modeled किया गया था;
- suspicious sessions के लिए strong human escalation के बिना मुख्यतः **algorithmic liveness** पर निर्भर करता है;
- **stable या predictable challenges** का उपयोग करता है जिन्हें पहले से record करके generation pipeline में feed किया जा सकता है;
- **`getUserMedia` monkeypatching**, virtual cameras, inconsistent browser hardware telemetry या missing device attestation को detect करता है।<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Generative video models का उपयोग करके age verification bypass करना](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
