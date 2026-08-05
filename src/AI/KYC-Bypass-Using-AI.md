# AIを使用したKYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative modelsは、**browser-based KYC、年齢確認、biometric liveness workflowsをbypass**するために使用できます。弱点は、多くの場合**transportやcloud liveness providerではなく、camera trust boundary**にあります。desktop browserは通常、`getUserMedia()`がwebcamとして公開するデバイスをそのまま信頼します。<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. source actorとvictim reference imageから、video-to-video modelを使用して**challenge-compliant mediaを生成**する。
2. **signingまたはuploadの前に偽装streamをinject**する。例えば、`v4l2loopback`で作成したLinux virtual cameraに、OBSまたはFFmpegから映像を入力する。
3. browserとvendor SDK（WebRTC、AWSなど）に、**attacker-controlled framesを実際のwebcamから取得したものとしてcapture、sign、upload**させる。

これはassessmentにおいて重要です。signed WebSocket chunksやproprietary SDK framingにより、**network-layer tampering**は実用的でない場合がありますが、**camera-layer injection**は依然として機能するためです。<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: desktop browserからflowが動作する場合、OBS、`v4l2loopback`、またはvendor virtual camerasが通常のperipheralsとして受け入れられるかをtestする。
- **Camera API redirection on mobile**: native mobile flowsでは、Fridaがcamera APIsをhookし、sensor buffersをMP4またはemulator-backed virtual cameraからのframesに置き換えることで、依然としてvulnerableになる可能性がある。
- **Constraint weakening**: 正確な`deviceId`、`frameRate`、`width`、`height`、または`facingMode`を要求するpagesは、`navigator.mediaDevices.getUserMedia`をmonkeypatchし、strict constraintsをより広いrangesに置き換えることでbypassできる場合がある。
- **Low-quality generation plus post-processing**: modelが確実にrenderできる最も低コストのvideoを生成し、その後FFmpeg upscalingまたはframe interpolationを使用してcapture requirementsを満たす。
- **Predictable active challenges**: 繰り返し行われるhead-movementまたはlight-flash sequencesは、recordしてgenerative workflow経由でreplayする価値がある。
- **Weak replay detection**: cropまたはposition shifts、overlay changes、わずかなmotionなどの単純なscene perturbationsは、anti-replay logicが表面的なframe similarityのみをcheckしている場合、十分なことがある。<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile appsは、以下によってattackerのコストを高められます。

- camera buffersに対する**sensorまたはSecure Element attestation**；
- **Play Integrity**または**App Attest**などの**execution-integrity** signals；
- videoとaccelerometerまたはgyroscope telemetry間の**motion correlation**。

Desktop web flowsには通常、同等のcamera chain of trustがないため、一般的に最も抵抗の少ないpathとなります。<sup>[[1]](#references)</sup>

## Defensive Review Notes

KYCまたはliveness integrationをreviewする際は、以下を確認してください。

- mobile captureのみを対象にthreat-modelingされたworkflowに対して、**desktop-browser fallback**を許可しているか。
- suspicious sessionsに対する強力なhuman escalationなしに、主に**algorithmic liveness**に依存しているか。
- pre-recordしてgeneration pipelineに入力できる、**stableまたはpredictable challenges**を使用しているか。
- **`getUserMedia` monkeypatching**、virtual cameras、一貫性のないbrowser hardware telemetry、または欠落したdevice attestationをdetectしているか。<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - generative video modelsを使用した年齢確認のKYC Bypass](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
