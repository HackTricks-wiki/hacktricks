# AI를 사용한 KYC Bypass

{{#include ../banners/hacktricks-training.md}}

Generative model은 **browser 기반 KYC, age-verification 및 biometric liveness workflow를 우회**하는 데 사용될 수 있습니다. 취약한 지점은 **transport나 cloud liveness provider가 아니라 camera trust boundary**인 경우가 많습니다. 일반적으로 desktop browser는 `getUserMedia()`가 webcam으로 노출하는 장치를 신뢰합니다.<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. **challenge-compliant media를 생성**합니다. source actor와 victim reference image를 사용하여 video-to-video model로 생성할 수 있습니다.
2. **signing 또는 upload 전에 forged stream을 주입**합니다. 예를 들어 `v4l2loopback`으로 생성한 Linux virtual camera에 OBS 또는 FFmpeg의 출력을 전달합니다.
3. Browser와 vendor SDK(WebRTC, AWS 등)가 **attacker가 제어하는 frame을 실제 webcam에서 가져온 것처럼 capture, sign 및 upload하도록** 합니다.

signed WebSocket chunk나 proprietary SDK framing으로 인해 **network-layer tampering**이 실용적이지 않을 수 있는 반면, **camera-layer injection**은 여전히 작동할 수 있으므로 이는 assessment에서 중요합니다.<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**: desktop browser에서 flow가 작동한다면 OBS, `v4l2loopback` 또는 vendor virtual camera가 일반적인 peripheral로 허용되는지 테스트합니다.
- **Camera API redirection on mobile**: Frida가 camera API를 hook하고 sensor buffer를 MP4 또는 emulator 기반 virtual camera의 frame으로 교체하면 native mobile flow도 여전히 취약할 수 있습니다.
- **Constraint weakening**: 정확한 `deviceId`, `frameRate`, `width`, `height` 또는 `facingMode`를 요구하는 page는 `navigator.mediaDevices.getUserMedia`를 monkeypatch하고 엄격한 constraint를 더 넓은 범위로 교체하여 우회할 수 있는 경우가 있습니다.
- **Low-quality generation plus post-processing**: model이 안정적으로 render할 수 있는 가장 저렴한 video를 생성한 다음, FFmpeg upscaling 또는 frame interpolation을 사용하여 capture requirement를 충족합니다.
- **Predictable active challenges**: 반복되는 head-movement 또는 light-flash sequence는 기록한 후 generative workflow를 통해 replay할 가치가 있습니다.
- **Weak replay detection**: anti-replay logic이 피상적인 frame similarity만 검사하는 경우 crop 또는 position shift, overlay 변경, 약간의 motion과 같은 단순한 scene perturbation만으로도 충분할 수 있습니다.<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile app은 다음과 같은 기능을 통해 attacker의 비용을 높일 수 있습니다.

- camera buffer에 대한 **sensor 또는 Secure Element attestation**;
- **Play Integrity** 또는 **App Attest**와 같은 **execution-integrity** signal;
- video와 accelerometer 또는 gyroscope telemetry 간의 **motion correlation**.

Desktop web flow에는 일반적으로 이에 상응하는 camera chain of trust가 없으므로, 대체로 가장 저항이 적은 경로입니다.<sup>[[1]](#references)</sup>

## Defensive Review Notes

KYC 또는 liveness integration을 검토할 때 다음 사항을 확인합니다.

- mobile capture만을 대상으로 threat-modeling한 workflow에 대해 **desktop-browser fallback**을 허용하는지;
- 의심스러운 session에 대한 강력한 human escalation 없이 **algorithmic liveness**에 대부분 의존하는지;
- 사전 녹화하여 generation pipeline에 주입할 수 있는 **stable 또는 predictable challenge**를 사용하는지;
- **`getUserMedia` monkeypatching**, virtual camera, 일관되지 않은 browser hardware telemetry 또는 누락된 device attestation을 탐지하는지.<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Generative video model을 사용한 KYC age verification Bypass](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
