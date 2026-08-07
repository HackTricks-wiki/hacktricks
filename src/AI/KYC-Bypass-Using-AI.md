# 使用 AI 绕过 KYC

{{#include ../banners/hacktricks-training.md}}

生成式模型可用于**绕过基于浏览器的 KYC、年龄验证和生物特征活体检测流程**。弱点通常**不在传输层或 cloud liveness provider，而在摄像头信任边界**：桌面浏览器通常会信任 `getUserMedia()` 暴露的任何设备作为 webcam。<sup>[[1]](#references)</sup>

## Practical Attack Chain

1. 使用来自源演员和受害者参考图像的视频到视频模型，**生成符合挑战要求的媒体内容**。<sup>[[1]](#references)</sup>
2. **在签名或上传之前注入伪造的视频流**，例如通过 `v4l2loopback` 创建 Linux virtual camera，并由 OBS 或 FFmpeg 提供视频流。<sup>[[3]](#references)</sup>
3. 让浏览器和 vendor SDK（WebRTC、AWS 等）**捕获、签名并上传攻击者控制的帧，使其看起来像是来自真实 webcam**。<sup>[[2]](#references)</sup>

这在评估期间非常重要，因为带签名的 WebSocket 数据块或专有 SDK framing 可能使**网络层篡改**难以实施，而**摄像头层注入**仍然有效。<sup>[[1]](#references)</sup>

## High-Value Testing Angles

- **Virtual webcam 接受情况**：如果该流程可通过桌面浏览器运行，应测试 OBS、`v4l2loopback` 或 vendor virtual cameras 是否会被接受为普通外设。<sup>[[1]](#references)</sup>
- **移动端的 Camera API 重定向**：当 Frida hook camera APIs，并将传感器缓冲区替换为来自 MP4 或 emulator-backed virtual camera 的帧时，原生移动端流程仍可能存在漏洞。
- **约束弱化**：要求精确 `deviceId`、`frameRate`、`width`、`height` 或 `facingMode` 的页面，有时可通过 monkeypatch `navigator.mediaDevices.getUserMedia`，并将严格约束替换为更宽泛的范围来绕过。<sup>[[4]](#references)</sup>
- **低质量生成与后处理**：生成模型能够稳定渲染的最低成本视频，然后使用 FFmpeg upscaling 或 frame interpolation 满足采集要求。
- **可预测的 active challenges**：当头部移动或闪光序列重复出现时，值得录制这些序列，并通过生成式工作流重放。
- **薄弱的 replay detection**：当 anti-replay 逻辑只检查表面上的帧相似度时，简单的场景扰动（例如裁剪或位置偏移、overlay 变化或轻微运动）可能就足够绕过检测。<sup>[[1]](#references)</sup>

## Mobile vs. Desktop Trust Differences

原生移动应用可以通过以下方式提高攻击者的成本：<sup>[[1]](#references)</sup>

- 对摄像头缓冲区进行**传感器或 Secure Element attestation**；
- 使用 **Play Integrity** 或 **App Attest** 等**执行完整性**信号；
- 对视频与加速度计或陀螺仪 telemetry 之间进行**运动相关性分析**。

桌面 Web 流程通常缺少等效的摄像头信任链，因此通常是阻力最小的路径。<sup>[[1]](#references)</sup>

## Defensive Review Notes

审查 KYC 或 liveness integration 时，应确认其是否：<sup>[[1]](#references)</sup>

- 允许针对原本只为移动端采集设计的流程使用**桌面浏览器 fallback**；
- 主要依赖**算法活体检测**，但没有针对可疑会话的强人工升级机制；
- 使用可被预先录制并输入生成 pipeline 的**稳定或可预测 challenges**；
- 能检测 **`getUserMedia` monkeypatching**、virtual cameras、不一致的浏览器硬件 telemetry 或缺失的 device attestation。<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - 使用生成式视频模型绕过年龄验证](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
