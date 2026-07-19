# AIを使用したKYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative modelsは、**browser-based KYC、年齢確認、biometric liveness workflowをbypass**するために使用できます。弱点は、多くの場合、**transportやcloud liveness providerではなく、camera trust boundary**にあります。desktop browserは通常、`getUserMedia()`がwebcamとして公開するデバイスをそのまま信頼します。

## Practical Attack Chain

1. source actorとvictim reference imageを使用し、video-to-video modelで**challengeに準拠したmediaを生成**する。
2. **signingまたはuploadの前に偽装streamをinject**する。たとえば、`v4l2loopback`で作成したLinux virtual cameraに、OBSまたはFFmpegから映像を入力する。
3. browserとvendor SDK（WebRTC、AWSなど）に、**攻撃者が制御するframeを実際のwebcamから取得したものとしてcapture、sign、upload**させる。

これはassessment中に重要です。signed WebSocket chunksやproprietary SDK framingによって**network-layer tampering**が実用的でなくても、**camera-layer injection**は機能する可能性があるためです。

## High-Value Testing Angles

- **Virtual webcam acceptance**: desktop browserからflowが動作する場合、OBS、`v4l2loopback`、またはvendor virtual cameraが通常のperipheralとして受け入れられるかをテストする。
- **Camera API redirection on mobile**: Fridaでcamera APIをhookし、sensor bufferをMP4のframeまたはemulator-backed virtual cameraのframeに置き換えると、native mobile flowでも脆弱な可能性がある。
- **Constraint weakening**: 正確な`deviceId`、`frameRate`、`width`、`height`、または`facingMode`を要求するpageは、`navigator.mediaDevices.getUserMedia`をmonkeypatchし、strict constraintをより広いrangeに置き換えることでbypassできる場合がある。
- **Low-quality generation plus post-processing**: modelが安定してrenderできる最も低コストのvideoを生成し、その後FFmpegのupscalingまたはframe interpolationを使用してcapture要件を満たす。
- **Predictable active challenges**: head-movementまたはlight-flash sequenceが繰り返される場合、recordしてgenerative workflowを通じてreplayする価値がある。
- **Weak replay detection**: cropやposition shift、overlayの変更、わずかなmotionなどの単純なscene perturbationで、anti-replay logicが表面的なframe similarityのみをチェックしている場合には十分なことがある。

## Mobile vs. Desktop Trust Differences

Native mobile appは、以下によって攻撃者のコストを高められます。

- camera bufferに対する**sensorまたはSecure Element attestation**;
- **Play Integrity**や**App Attest**などの**execution-integrity** signal;
- videoとaccelerometerまたはgyroscope telemetry間の**motion correlation**。

Desktop web flowには通常、同等のcamera chain of trustがないため、一般的に最も容易な経路になります。

## Defensive Review Notes

KYCまたはliveness integrationをreviewする際は、以下を確認します。

- mobile captureのみを想定してthreat-modelingされたworkflowに対し、**desktop-browser fallback**を許可していないか。
- suspicious sessionに対する強力なhuman escalationなしに、主に**algorithmic liveness**に依存していないか。
- pre-recordしてgeneration pipelineに入力できる**stableまたはpredictable challenge**を使用していないか。
- **`getUserMedia` monkeypatching**、virtual camera、矛盾したbrowser hardware telemetry、または欠落したdevice attestationを検出しているか。

## References

- [Synacktiv - KYC: Generative video modelsを使用した年齢確認のBypass](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
