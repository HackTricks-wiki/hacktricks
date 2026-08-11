# AI를 사용한 KYC 우회

{{#include ../banners/hacktricks-training.md}}

생성형 모델은 **브라우저 기반 KYC, 연령 확인 및 생체 liveness workflow를 우회**하는 데 사용될 수 있습니다. 취약한 지점은 **전송 계층이나 cloud liveness provider가 아닌 경우가 많으며**, 바로 **카메라 trust boundary**입니다. 데스크톱 브라우저는 일반적으로 `getUserMedia()`가 webcam으로 노출하는 장치를 그대로 신뢰합니다.<sup>[[1]](#references)</sup>

## 실용적인 공격 체인

1. source actor와 victim reference image를 사용하여 video-to-video model로 **challenge에 부합하는 media 생성**<sup>[[1]](#references)</sup>
2. 서명 또는 upload 전에 **위조된 stream 주입**. 예를 들어 `v4l2loopback`으로 생성한 Linux virtual camera에 OBS 또는 FFmpeg를 연결할 수 있습니다.<sup>[[3]](#references)</sup>
3. 브라우저와 vendor SDK(WebRTC, AWS 등)가 **공격자가 제어하는 frame을 실제 webcam에서 나온 것처럼 capture, sign 및 upload**하도록 함.<sup>[[2]](#references)</sup>

서명된 WebSocket chunk 또는 proprietary SDK framing으로 인해 **network-layer tampering**이 실용적이지 않을 수 있는 반면, **camera-layer injection**은 여전히 작동할 수 있으므로 평가 중에 중요합니다.<sup>[[1]](#references)</sup>

## 가치가 높은 테스트 관점

- **Virtual webcam acceptance**: 데스크톱 브라우저에서 flow가 작동한다면 OBS, `v4l2loopback` 또는 vendor virtual camera가 일반 peripheral로 허용되는지 테스트합니다.<sup>[[1]](#references)</sup>
- **모바일에서 Camera API redirection**: Frida와 같은 runtime instrumentation이 camera API를 hook하고 sensor buffer를 MP4 파일 또는 emulator-backed virtual camera의 frame으로 교체하는 경우 native flow도 여전히 취약할 수 있습니다. 이를 위해서는 client execution environment에 대한 제어가 필요하며, root/jailbreak 및 application-integrity signal과 함께 평가해야 합니다.<sup>[[1]](#references)</sup>
- **Constraint weakening**: 정확한 `deviceId`, `frameRate`, `width`, `height` 또는 `facingMode`를 요구하는 페이지는 `navigator.mediaDevices.getUserMedia`를 monkeypatch하고 엄격한 constraint를 더 넓은 range로 교체하여 우회할 수 있는 경우가 있습니다.<sup>[[4]](#references)</sup>
- **Low-quality generation plus post-processing**: 저렴하게 생성한 video를 FFmpeg로 upscaling하거나 frame-interpolation하여 capture constraint를 충족할 수 있는지 테스트합니다.<sup>[[1]](#references)</sup>
- **Predictable active challenges**: 반복적인 head-movement 또는 light-flash sequence는 기록한 후 generative workflow를 통해 replay할 가치가 있습니다.
- **Weak replay detection**: anti-replay logic이 피상적인 frame similarity만 확인하는 경우 crop 또는 position shift, overlay 변경 또는 약간의 motion과 같은 단순한 scene perturbation만으로도 충분할 수 있습니다.<sup>[[1]](#references)</sup>

## 모바일과 데스크톱의 Trust 차이

Native mobile app은 다음과 같은 방식으로 공격자의 비용을 높일 수 있습니다:<sup>[[1]](#references)</sup>

- **hardware-backed provenance 또는 attestation signal**. 여기에는 platform과 capture stack이 실제로 노출하는 경우 Secure Element-backed evidence가 포함됩니다.
- **execution-integrity** signal. 예를 들어 **Play Integrity** 또는 **App Attest**가 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>
- video와 accelerometer 또는 gyroscope telemetry 간의 **motion correlation**

데스크톱 web flow에는 일반적으로 이에 상응하는 camera chain of trust가 없으므로, 대체로 가장 저항이 적은 경로입니다.<sup>[[1]](#references)</sup>

## 방어 검토 참고 사항

KYC 또는 liveness integration을 검토할 때 다음 사항을 확인합니다:<sup>[[1]](#references)</sup>

- mobile capture만을 대상으로 threat-modeling한 workflow에 **desktop-browser fallback**을 허용하는지 여부
- 의심스러운 session에 대한 강력한 human escalation 없이 주로 **algorithmic liveness**에 의존하는지 여부
- 사전에 기록하여 generation pipeline에 입력할 수 있는 **stable 또는 predictable challenge**를 사용하는지 여부
- **`getUserMedia` monkeypatching**, virtual camera, 일관되지 않은 browser hardware telemetry 또는 누락된 device attestation을 탐지하는지 여부<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - 생성형 video model을 사용한 KYC: 연령 확인 우회](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
