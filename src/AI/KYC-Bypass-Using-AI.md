# KYC Bypass Using AI

{{#include ../banners/hacktricks-training.md}}

Generative models can be used to **bypass browser-based KYC, age-verification, and biometric liveness workflows**. The weak point is often **not** the transport or the cloud liveness provider, but the **camera trust boundary**: a desktop browser usually trusts whatever device `getUserMedia()` exposes as a webcam.<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. **Generate challenge-compliant media** with a video-to-video model from a source actor and a victim reference image.<sup>[[1]](#references)</sup>
2. **Inject the forged stream before signing or upload**, for example through a Linux virtual camera created with `v4l2loopback` and fed by OBS or FFmpeg.<sup>[[3]](#references)</sup>
3. Let the browser and vendor SDK (WebRTC, AWS, etc.) **capture, sign, and upload the attacker-controlled frames as if they came from a real webcam**.<sup>[[2]](#references)</sup>

This is important during assessments because signed WebSocket chunks or proprietary SDK framing may make **network-layer tampering** impractical, while **camera-layer injection** still works.<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: if the flow works from a desktop browser, test whether OBS, `v4l2loopback`, or vendor virtual cameras are accepted as normal peripherals.<sup>[[1]](#references)</sup>
- **Camera API redirection on mobile**: native flows may still be vulnerable when runtime instrumentation such as Frida hooks camera APIs and replaces sensor buffers with frames from an MP4 file or emulator-backed virtual camera. This requires control of the client execution environment and should be assessed together with root/jailbreak and application-integrity signals.<sup>[[1]](#references)</sup>
- **Constraint weakening**: pages that require exact `deviceId`, `frameRate`, `width`, `height`, or `facingMode` can sometimes be bypassed by monkeypatching `navigator.mediaDevices.getUserMedia` and replacing strict constraints with broader ranges.<sup>[[4]](#references)</sup>
- **Low-quality generation plus post-processing**: test whether inexpensive generated video can be upscaled or frame-interpolated with FFmpeg sufficiently to meet capture constraints.<sup>[[1]](#references)</sup>
- **Predictable active challenges**: repeated head-movement or light-flash sequences are worth recording and replaying through a generative workflow.
- **Weak replay detection**: simple scene perturbations, such as crop or position shifts, overlay changes, or slight motion, can be enough when the anti-replay logic only checks superficial frame similarity.<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile apps can raise the attacker's cost with:<sup>[[1]](#references)</sup>

- **hardware-backed provenance or attestation signals**, including Secure Element-backed evidence where the platform and capture stack actually expose it;
- **execution-integrity** signals such as **Play Integrity** or **App Attest**;<sup>[[5]](#references)[[6]](#references)</sup>
- **motion correlation** between video and accelerometer or gyroscope telemetry.

Desktop web flows usually lack an equivalent camera chain of trust, so they are generally the path of least resistance.<sup>[[1]](#references)</sup>

## Defensive Review Notes

When reviewing a KYC or liveness integration, verify whether it:<sup>[[1]](#references)</sup>

- allows a **desktop-browser fallback** for a workflow that was only threat-modeled for mobile capture;
- relies mostly on **algorithmic liveness** without strong human escalation for suspicious sessions;
- uses **stable or predictable challenges** that can be pre-recorded and fed into a generation pipeline;
- detects **`getUserMedia` monkeypatching**, virtual cameras, inconsistent browser hardware telemetry, or missing device attestation.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)

{{#include ../banners/hacktricks-training.md}}
