# 使用 AI 绕过 KYC

{{#include ../banners/hacktricks-training.md}}

生成式模型可用于**绕过基于 browser 的 KYC、年龄验证和生物特征活体检测流程**。弱点通常**不在传输层或 cloud liveness provider**，而在于**camera trust boundary**：桌面 browser 通常会信任 `getUserMedia()` 暴露的任何设备，并将其视为 webcam。<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. 使用 video-to-video model，根据源人物和受害者参考图像，**生成符合 challenge 要求的媒体内容**。
2. **在签名或上传之前注入伪造的视频流**，例如通过 `v4l2loopback` 创建 Linux virtual camera，再由 OBS 或 FFmpeg 提供视频流。
3. 让 browser 和 vendor SDK（WebRTC、AWS 等）**将攻击者控制的帧采集、签名并上传，就像这些帧来自真实 webcam 一样**。

这在 assessment 期间很重要，因为已签名的 WebSocket chunks 或 proprietary SDK framing 可能使**network-layer tampering**变得不切实际，而**camera-layer injection**仍然有效。<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam acceptance**：如果该流程可通过桌面 browser 使用，则测试 OBS、`v4l2loopback` 或 vendor virtual cameras 是否会被接受为普通 peripheral。
- **Camera API redirection on mobile**：当 Frida hook camera APIs，并将 sensor buffers 替换为来自 MP4 或 emulator-backed virtual camera 的帧时，native mobile 流程仍可能存在漏洞。
- **Constraint weakening**：要求精确 `deviceId`、`frameRate`、`width`、`height` 或 `facingMode` 的页面，有时可以通过 monkeypatching `navigator.mediaDevices.getUserMedia`，用更宽泛的范围替换严格 constraints 来绕过。
- **Low-quality generation plus post-processing**：生成 model 能够稳定渲染的最低成本视频，然后使用 FFmpeg upscaling 或 frame interpolation 来满足 capture 要求。
- **Predictable active challenges**：值得记录并通过 generative workflow 重放重复的头部移动或闪光序列。
- **Weak replay detection**：当 anti-replay logic 仅检查表面的帧相似度时，简单的 scene perturbations，例如裁剪或位置偏移、overlay 变化或轻微运动，可能就足够绕过检测。<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

Native mobile apps 可以通过以下方式提高攻击者成本：

- 用于 camera buffers 的 **sensor 或 Secure Element attestation**；
- **execution-integrity** 信号，例如 **Play Integrity** 或 **App Attest**；
- 视频与加速度计或陀螺仪 telemetry 之间的**运动相关性**。

Desktop web 流程通常缺少等效的 camera chain of trust，因此通常是阻力最小的路径。<sup>[[1]](#references)</sup>

## Defensive Review Notes

审查 KYC 或 liveness integration 时，确认其是否：

- 允许针对仅为 mobile capture 进行 threat modeling 的流程使用**桌面 browser fallback**；
- 主要依赖**algorithmic liveness**，但缺少针对可疑 session 的强人工升级机制；
- 使用可**预录制并输入 generation pipeline** 的稳定或可预测 challenges；
- 检测 **`getUserMedia` monkeypatching**、virtual cameras、不一致的 browser hardware telemetry 或缺失的 device attestation。<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - 使用 generative video models 绕过年龄验证](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
