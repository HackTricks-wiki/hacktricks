# AI를 사용한 KYC 우회

{{#include ../banners/hacktricks-training.md}}

Generative models는 **browser 기반 KYC, 연령 확인 및 biometric liveness workflow를 우회**하는 데 사용될 수 있습니다. 취약한 지점은 흔히 **전송 계층이나 cloud liveness provider가 아니라 카메라 trust boundary**입니다. desktop browser는 일반적으로 `getUserMedia()`가 webcam으로 노출하는 모든 장치를 신뢰합니다.<sup>[[1]](#references)</sup>

## 실전 공격 체인

1. source actor와 victim reference image를 사용해 video-to-video model로 **challenge를 충족하는 미디어를 생성**합니다.<sup>[[1]](#references)</sup>
2. **서명 또는 upload 전에 위조된 stream을 주입**합니다. 예를 들어 `v4l2loopback`으로 생성한 Linux virtual camera에 OBS 또는 FFmpeg를 연결할 수 있습니다.<sup>[[3]](#references)</sup>
3. browser와 vendor SDK(WebRTC, AWS 등)가 **공격자가 제어하는 프레임을 실제 webcam에서 전송된 것처럼 capture, sign 및 upload**하도록 합니다.<sup>[[2]](#references)</sup>

이는 assessment 중 중요합니다. 서명된 WebSocket chunks 또는 proprietary SDK framing으로 인해 **network-layer tampering**이 비현실적일 수 있지만, **camera-layer injection**은 여전히 작동할 수 있기 때문입니다.<sup>[[1]](#references)</sup>

## 가치가 높은 테스트 관점

- **Virtual webcam acceptance**: desktop browser에서 flow가 작동한다면 OBS, `v4l2loopback` 또는 vendor virtual camera가 일반 peripheral로 허용되는지 테스트합니다.<sup>[[1]](#references)</sup>
- **모바일에서의 Camera API redirection**: Frida가 camera API를 hook하고 sensor buffer를 MP4 또는 emulator 기반 virtual camera의 프레임으로 교체하는 경우, native mobile flow도 여전히 취약할 수 있습니다.
- **Constraint weakening**: 정확한 `deviceId`, `frameRate`, `width`, `height` 또는 `facingMode`를 요구하는 페이지는 `navigator.mediaDevices.getUserMedia`를 monkeypatch하고 strict constraints를 더 넓은 범위로 교체하여 우회할 수 있는 경우가 있습니다.<sup>[[4]](#references)</sup>
- **Low-quality generation plus post-processing**: model이 안정적으로 render할 수 있는 가장 저렴한 video를 생성한 다음 FFmpeg upscaling 또는 frame interpolation을 사용해 capture 요구사항을 충족합니다.
- **예측 가능한 active challenge**: 반복적인 머리 움직임 또는 light-flash sequence는 기록한 후 generative workflow를 통해 replay할 가치가 있습니다.
- **Weak replay detection**: crop 또는 position shift, overlay 변경, 약간의 motion과 같은 단순한 scene perturbation만으로도 충분할 수 있습니다. anti-replay logic이 표면적인 frame similarity만 검사하는 경우가 그렇습니다.<sup>[[1]](#references)</sup>

## Mobile과 Desktop의 Trust 차이

Native mobile app은 다음을 통해 공격자의 비용을 높일 수 있습니다.<sup>[[1]](#references)</sup>

- camera buffer에 대한 **sensor 또는 Secure Element attestation**;
- **Play Integrity** 또는 **App Attest**와 같은 **execution-integrity** signal;
- video와 accelerometer 또는 gyroscope telemetry 간의 **motion correlation**.

Desktop web flow에는 일반적으로 이에 상응하는 camera chain of trust가 없으므로, 대체로 저항이 가장 적은 경로입니다.<sup>[[1]](#references)</sup>

## 방어 검토 참고 사항

KYC 또는 liveness integration을 검토할 때 다음 사항을 확인해야 합니다.<sup>[[1]](#references)</sup>

- mobile capture만을 대상으로 threat modeling한 workflow에 대해 **desktop-browser fallback**을 허용하는지;
- 의심스러운 session에 대한 강력한 human escalation 없이 **algorithmic liveness**에 대부분 의존하는지;
- 사전에 기록하여 generation pipeline에 입력할 수 있는 **stable 또는 predictable challenge**를 사용하는지;
- **`getUserMedia` monkeypatching**, virtual camera, 일관성이 없는 browser hardware telemetry 또는 누락된 device attestation을 탐지하는지.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
