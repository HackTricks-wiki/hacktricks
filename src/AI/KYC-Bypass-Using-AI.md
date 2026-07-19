# AI का उपयोग करके KYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative models का उपयोग **browser-based KYC, age-verification और biometric liveness workflows को bypass करने** के लिए किया जा सकता है। कमजोर बिंदु अक्सर **transport या cloud liveness provider नहीं, बल्कि camera trust boundary** होता है: desktop browser आमतौर पर `getUserMedia()` द्वारा webcam के रूप में उपलब्ध कराए गए किसी भी device पर भरोसा करता है।

## Practical Attack Chain

1. **Challenge-compliant media generate करें** — source actor और victim reference image से video-to-video model का उपयोग करके।
2. **Signing या upload से पहले forged stream inject करें**, उदाहरण के लिए `v4l2loopback` से बनाए गए Linux virtual camera के माध्यम से, जिसे OBS या FFmpeg feed कर रहा हो।
3. Browser और vendor SDK (WebRTC, AWS, आदि) को **attacker-controlled frames को वास्तविक webcam से आए frames की तरह capture, sign और upload करने दें**।

Assessments के दौरान यह महत्वपूर्ण है क्योंकि signed WebSocket chunks या proprietary SDK framing **network-layer tampering को impractical** बना सकते हैं, जबकि **camera-layer injection** फिर भी काम कर सकता है।

## High-Value Testing Angles

- **Virtual webcam acceptance**: यदि flow desktop browser से काम करता है, तो जांचें कि OBS, `v4l2loopback` या vendor virtual cameras को normal peripherals के रूप में स्वीकार किया जाता है या नहीं।
- **Camera API redirection on mobile**: native mobile flows तब भी vulnerable हो सकते हैं जब Frida camera APIs पर hooks लगाकर sensor buffers को MP4 के frames या emulator-backed virtual camera से replace कर दे।
- **Constraint weakening**: exact `deviceId`, `frameRate`, `width`, `height` या `facingMode` की आवश्यकता वाली pages को कभी-कभी `navigator.mediaDevices.getUserMedia` को monkeypatch करके और strict constraints को broader ranges से replace करके bypass किया जा सकता है।
- **Low-quality generation plus post-processing**: model द्वारा reliably render किए जा सकने वाले सबसे सस्ते video को generate करें, फिर capture requirements पूरी करने के लिए FFmpeg upscaling या frame interpolation का उपयोग करें।
- **Predictable active challenges**: repeated head-movement या light-flash sequences को record करना और generative workflow के माध्यम से replay करना उपयोगी हो सकता है।
- **Weak replay detection**: साधारण scene perturbations, जैसे crop या position shifts, overlay changes या slight motion, पर्याप्त हो सकते हैं जब anti-replay logic केवल superficial frame similarity की जांच करता हो।

## Mobile vs. Desktop Trust Differences

Native mobile apps attacker की cost बढ़ा सकते हैं:

- camera buffers के लिए **sensor या Secure Element attestation**;
- **Play Integrity** या **App Attest** जैसे **execution-integrity** signals;
- video और accelerometer या gyroscope telemetry के बीच **motion correlation**।

Desktop web flows में आमतौर पर camera chain of trust का equivalent नहीं होता, इसलिए वे सामान्यतः least resistance का रास्ता होते हैं।

## Defensive Review Notes

KYC या liveness integration की review करते समय जांचें कि क्या वह:

- ऐसे workflow के लिए **desktop-browser fallback** की अनुमति देता है जिसे केवल mobile capture के लिए threat-modeled किया गया था;
- suspicious sessions के लिए strong human escalation के बिना मुख्यतः **algorithmic liveness** पर निर्भर करता है;
- **stable या predictable challenges** का उपयोग करता है जिन्हें पहले से record करके generation pipeline में feed किया जा सकता है;
- **`getUserMedia` monkeypatching**, virtual cameras, inconsistent browser hardware telemetry या missing device attestation का पता लगाता है।

## References

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
