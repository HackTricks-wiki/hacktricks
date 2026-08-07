# AIを使用したKYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative modelsは、**browser-based KYC、age-verification、biometric livenessのworkflowをbypassする**ために使用できます。弱点は、多くの場合、**transportやcloud liveness providerではなく、camera trust boundary**にあります。通常、desktop browserは、`getUserMedia()`がwebcamとして公開するデバイスをそのまま信頼します。<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. **challengeに準拠したmediaを生成**します。source actorとvictimのreference imageから、video-to-video modelを使用します。<sup>[[1]](#references)</sup>
2. **signingまたはuploadの前に偽造したstreamをinject**します。たとえば、`v4l2loopback`で作成したLinux virtual cameraに、OBSまたはFFmpegから入力します。<sup>[[3]](#references)</sup>
3. Browserとvendor SDK（WebRTC、AWSなど）に、**attackerが制御するframesを、real webcamから取得されたかのようにcapture、sign、uploadさせます**。<sup>[[2]](#references)</sup>

これはassessmentにおいて重要です。signed WebSocket chunksやproprietary SDK framingによって**network-layer tampering**が実用的でなくなる場合でも、**camera-layer injection**は機能する可能性があるためです。<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: desktop browserからworkflowが動作する場合、OBS、`v4l2loopback`、またはvendor virtual camerasが通常のperipheralsとして受け入れられるかをテストします。<sup>[[1]](#references)</sup>
- **Camera API redirection on mobile**: native mobile flowでも、Fridaがcamera APIsにhooksし、sensor buffersをMP4またはemulator-backed virtual cameraからのframesに置き換える場合は、なお脆弱な可能性があります。
- **Constraint weakening**: `deviceId`、`frameRate`、`width`、`height`、または`facingMode`を正確に要求するpagesは、`navigator.mediaDevices.getUserMedia`をmonkeypatchし、strict constraintsをより広いrangesに置き換えることで、bypassできる場合があります。<sup>[[4]](#references)</sup>
- **Low-quality generation plus post-processing**: modelが安定してrenderできる最も低コストのvideoを生成し、その後FFmpegのupscalingまたはframe interpolationを使用してcapture requirementsを満たします。
- **Predictable active challenges**: head-movementまたはlight-flash sequencesが繰り返される場合は、それらをrecordし、generative workflowを通じてreplayする価値があります。
- **Weak replay detection**: cropやposition shifts、overlay changes、またはわずかなmotionなどの単純なscene perturbationsでも、anti-replay logicが表面的なframe similarityのみをチェックしている場合には十分なことがあります。<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile appsは、以下によってattackerのコストを高められます。<sup>[[1]](#references)</sup>

- camera buffersに対する**sensorまたはSecure Element attestation**;
- **Play Integrity**または**App Attest**などの**execution-integrity** signals;
- videoとaccelerometerまたはgyroscope telemetry間の**motion correlation**。

Desktop web flowsには通常、同等のcamera chain of trustがないため、一般に最も抵抗の少ないpathとなります。<sup>[[1]](#references)</sup>

## Defensive Review Notes

KYCまたはliveness integrationをreviewする際は、以下を確認します。<sup>[[1]](#references)</sup>

- mobile captureのみを対象にthreat-modelingされていたworkflowに対して、**desktop-browser fallback**を許可しているか;
- suspicious sessionsに対する強力なhuman escalationなしに、主に**algorithmic liveness**に依存しているか;
- pre-recordしてgeneration pipelineに入力できる、**stableまたはpredictableなchallenges**を使用しているか;
- **`getUserMedia` monkeypatching**、virtual cameras、矛盾したbrowser hardware telemetry、または欠落したdevice attestationを検出しているか。<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
