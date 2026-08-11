# AIを使用したKYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative models can be used to **ブラウザベースのKYC、年齢確認、生体 liveness ワークフローを bypass する**ことができます。弱点は、多くの場合、**transport や cloud liveness provider ではなく、camera trust boundary にあります**。デスクトップブラウザは通常、`getUserMedia()` が webcam として公開するデバイスを、そのまま信頼します。<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. **challenge に準拠した media を生成する**。source actor と victim reference image を使用し、video-to-video model で生成します。<sup>[[1]](#references)</sup>
2. **signing または upload の前に偽造した stream を inject する**。たとえば、`v4l2loopback` で作成した Linux virtual camera に、OBS または FFmpeg から入力します。<sup>[[3]](#references)</sup>
3. ブラウザと vendor SDK（WebRTC、AWS など）に、**攻撃者が制御する frames を、実際の webcam から取得されたかのように capture、sign、upload させる**。<sup>[[2]](#references)</sup>

これは assessment で重要です。signed WebSocket chunks や proprietary SDK framing により、**network-layer tampering** は実行が難しい場合がありますが、**camera-layer injection** は依然として機能する可能性があるためです。<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: デスクトップブラウザから flow が機能する場合、OBS、`v4l2loopback`、または vendor virtual cameras が通常の peripherals として受け入れられるかをテストします。<sup>[[1]](#references)</sup>
- **Camera API redirection on mobile**: Frida などの runtime instrumentation が camera APIs に hook し、sensor buffers を MP4 ファイルまたは emulator-backed virtual camera の frames に置き換える場合、native flow も脆弱である可能性があります。これには client execution environment の制御が必要であり、root/jailbreak および application-integrity signals と併せて assessment する必要があります。<sup>[[1]](#references)</sup>
- **Constraint weakening**: 正確な `deviceId`、`frameRate`、`width`、`height`、または `facingMode` を要求するページでは、`navigator.mediaDevices.getUserMedia` を monkeypatching し、strict constraints をより広い ranges に置き換えることで bypass できる場合があります。<sup>[[4]](#references)</sup>
- **Low-quality generation plus post-processing**: 安価に生成した video を、FFmpeg で upscale または frame-interpolated することで capture constraints を満たせるかをテストします。<sup>[[1]](#references)</sup>
- **Predictable active challenges**: 繰り返し行われる head-movement や light-flash sequences は、recording して generative workflow を通じて replay できる可能性があります。
- **Weak replay detection**: crop や position shifts、overlay changes、わずかな motion などの単純な scene perturbations は、anti-replay logic が表面的な frame similarity のみを確認する場合に十分となる可能性があります。<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile apps は、次の要素によって攻撃者のコストを高められます。<sup>[[1]](#references)</sup>

- **hardware-backed provenance または attestation signals**。platform と capture stack が実際に公開している場合は、Secure Element-backed evidence を含みます。
- **execution-integrity** signals。**Play Integrity** や **App Attest** などです。<sup>[[5]](#references)[[6]](#references)</sup>
- video と accelerometer または gyroscope telemetry 間の **motion correlation**。

Desktop web flows には、通常、同等の camera chain of trust がないため、一般的に最も容易な path となります。<sup>[[1]](#references)</sup>

## Defensive Review Notes

KYC または liveness integration を review する際は、次の点を確認します。<sup>[[1]](#references)</sup>

- mobile capture のみを対象に threat-modeling された workflow に対して、**desktop-browser fallback** を許可していないか。
- suspicious sessions に対する強力な human escalation なしに、主に **algorithmic liveness** に依存していないか。
- pre-record して generation pipeline に入力できる、**stable または predictable な challenges** を使用していないか。
- **`getUserMedia` monkeypatching**、virtual cameras、整合しない browser hardware telemetry、または device attestation の欠如を検出しているか。<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: generative video models を使用した年齢確認の Bypass](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
