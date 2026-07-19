# KYC Bypass Using AI

{{#include ../banners/hacktricks-training.md}}

Generative models can be used to **bypass browser-based KYC, age-verification, and biometric liveness workflows**. The weak point is often **not** the transport or the cloud liveness provider, but the **camera trust boundary**: a desktop browser usually trusts whatever device `getUserMedia()` exposes as a webcam.

## Practical Attack Chain

1. **Generate challenge-compliant media** with a video-to-video model from a source actor and a victim reference image.
2. **Inject the forged stream before signing or upload**, for example through a Linux virtual camera created with `v4l2loopback` and fed by OBS or FFmpeg.
3. Let the browser and vendor SDK (WebRTC, AWS, etc.) **capture, sign, and upload the attacker-controlled frames as if they came from a real webcam**.

This is important during assessments because signed WebSocket chunks or proprietary SDK framing may make **network-layer tampering** impractical, while **camera-layer injection** still works.

## High-Value Testing Angles

- **Virtual webcam acceptance**: if the flow works from a desktop browser, test whether OBS, `v4l2loopback`, or vendor virtual cameras are accepted as normal peripherals.
- **Camera API redirection on mobile**: native mobile flows may still be vulnerable when Frida hooks camera APIs and replaces sensor buffers with frames from an MP4 or emulator-backed virtual camera.
- **Constraint weakening**: pages that require exact `deviceId`, `frameRate`, `width`, `height`, or `facingMode` can sometimes be bypassed by monkeypatching `navigator.mediaDevices.getUserMedia` and replacing strict constraints with broader ranges.
- **Low-quality generation plus post-processing**: generate the cheapest video the model can render reliably, then use FFmpeg upscaling or frame interpolation to satisfy capture requirements.
- **Predictable active challenges**: repeated head-movement or light-flash sequences are worth recording and replaying through a generative workflow.
- **Weak replay detection**: simple scene perturbations, such as crop or position shifts, overlay changes, or slight motion, can be enough when the anti-replay logic only checks superficial frame similarity.

## Mobile vs. Desktop Trust Differences

Native mobile apps can raise the attacker's cost with:

- **sensor or Secure Element attestation** for camera buffers;
- **execution-integrity** signals such as **Play Integrity** or **App Attest**;
- **motion correlation** between video and accelerometer or gyroscope telemetry.

Desktop web flows usually lack an equivalent camera chain of trust, so they are generally the path of least resistance.

## Defensive Review Notes

When reviewing a KYC or liveness integration, verify whether it:

- allows a **desktop-browser fallback** for a workflow that was only threat-modeled for mobile capture;
- relies mostly on **algorithmic liveness** without strong human escalation for suspicious sessions;
- uses **stable or predictable challenges** that can be pre-recorded and fed into a generation pipeline;
- detects **`getUserMedia` monkeypatching**, virtual cameras, inconsistent browser hardware telemetry, or missing device attestation.

## References

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
