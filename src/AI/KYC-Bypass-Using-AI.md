# 使用 AI 绕过 KYC

{{#include ../banners/hacktricks-training.md}}

生成式模型可用于**绕过基于浏览器的 KYC、年龄验证和生物特征活体检测流程**。弱点通常**不在传输层或云端活体检测提供商**，而在于**摄像头信任边界**：桌面浏览器通常会信任 `getUserMedia()` 暴露的任何设备作为网络摄像头。<sup>[[1]](#references)</sup>

## 实际攻击链

1. 使用 video-to-video 模型，根据源演员和受害者参考图像，**生成符合挑战要求的媒体内容**。<sup>[[1]](#references)</sup>
2. **在签名或上传前注入伪造的视频流**，例如通过 `v4l2loopback` 创建 Linux 虚拟摄像头，再由 OBS 或 FFmpeg 提供输入。<sup>[[3]](#references)</sup>
3. 让浏览器和供应商 SDK（WebRTC、AWS 等）**将攻击者控制的帧捕获、签名并上传，使其看起来像是来自真实网络摄像头**。<sup>[[2]](#references)</sup>

这在评估期间非常重要，因为已签名的 WebSocket 数据块或专有 SDK 帧格式可能使**网络层篡改**难以实施，而**摄像头层注入**仍然有效。<sup>[[1]](#references)</sup>

## 高价值测试角度

- **虚拟网络摄像头接受情况**：如果该流程可通过桌面浏览器运行，应测试 OBS、`v4l2loopback` 或供应商虚拟摄像头是否会被当作普通外设接受。<sup>[[1]](#references)</sup>
- **移动端摄像头 API 重定向**：当运行时 instrumentation（例如 Frida）hook 摄像头 API，并将传感器缓冲区替换为来自 MP4 文件或由 emulator 提供的虚拟摄像头的帧时，原生流程仍可能存在漏洞。这需要控制客户端执行环境，并应结合 root/jailbreak 和应用完整性信号一并评估。<sup>[[1]](#references)</sup>
- **放宽约束**：要求精确 `deviceId`、`frameRate`、`width`、`height` 或 `facingMode` 的页面，有时可以通过 monkeypatch `navigator.mediaDevices.getUserMedia`，将严格约束替换为更宽泛的范围来绕过。<sup>[[4]](#references)</sup>
- **低质量生成结合后处理**：测试是否可以使用 FFmpeg 对成本较低的生成视频进行放大或帧插值，使其足以满足捕获约束。<sup>[[1]](#references)</sup>
- **可预测的主动挑战**：重复的头部移动或闪光序列值得录制，并通过生成式工作流进行重放。
- **薄弱的重放检测**：当反重放逻辑只检查表面的帧相似度时，简单的场景扰动（例如裁剪或位置偏移）、叠加层变化或轻微动作可能就足够实现绕过。<sup>[[1]](#references)</sup>

## 移动端与桌面端的信任差异

原生移动应用可以通过以下方式提高攻击者的成本：<sup>[[1]](#references)</sup>

- **硬件支持的来源或 attestation 信号**，包括平台和捕获栈实际能够提供的由 Secure Element 支持的证据；
- **执行完整性**信号，例如 **Play Integrity** 或 **App Attest**；<sup>[[5]](#references)[[6]](#references)</sup>
- **视频与加速度计或陀螺仪遥测之间的运动关联**。

桌面 Web 流程通常缺乏等效的摄像头信任链，因此通常是阻力最小的路径。<sup>[[1]](#references)</sup>

## 防御审查说明

审查 KYC 或活体检测集成时，应确认其是否：<sup>[[1]](#references)</sup>

- 为原本仅针对移动端捕获进行威胁建模的流程，提供了**桌面浏览器 fallback**；
- 主要依赖**算法活体检测**，却没有针对可疑会话实施强有力的人工升级处理；
- 使用了**稳定或可预测的挑战**，使其能够被预先录制并输入生成管线；
- 检测 **`getUserMedia` monkeypatch**、虚拟摄像头、不一致的浏览器硬件遥测或缺失的设备 attestation。<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - KYC：使用生成式视频模型绕过年龄验证](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [2] [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [3] [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [4] [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)
- [5] [Android Developers — Play Integrity API](https://developer.android.com/google/play/integrity)
- [6] [Apple Developer — App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)
{{#include ../banners/hacktricks-training.md}}
