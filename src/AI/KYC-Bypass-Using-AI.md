# 使用 AI 绕过 KYC

{{#include ../banners/hacktricks-training.md}}

生成式模型可用于**绕过基于浏览器的 KYC、年龄验证和生物识别活体检测流程**。弱点通常**不在传输层或云端活体检测提供商**，而在于**摄像头信任边界**：桌面浏览器通常会信任 `getUserMedia()` 暴露的任何设备，将其视为摄像头。

## 实际攻击链

1. 使用视频到视频模型，根据源人物和受害者参考图像，**生成符合挑战要求的媒体内容**。
2. **在签名或上传之前注入伪造的视频流**，例如通过 `v4l2loopback` 创建 Linux 虚拟摄像头，再由 OBS 或 FFmpeg 提供视频流。
3. 让浏览器和供应商 SDK（WebRTC、AWS 等）**将攻击者控制的帧捕获、签名并上传，使其看起来像来自真实摄像头**。

这在评估期间非常重要，因为已签名的 WebSocket 数据块或专有 SDK 封装可能使**网络层篡改**变得不切实际，而**摄像头层注入**仍然有效。

## 高价值测试角度

- **虚拟摄像头接受情况**：如果流程可通过桌面浏览器运行，应测试 OBS、`v4l2loopback` 或供应商虚拟摄像头是否会被接受为普通外设。
- **移动端摄像头 API 重定向**：当 Frida hook 摄像头 API，并使用 MP4 或基于模拟器的虚拟摄像头中的帧替换传感器缓冲区时，原生移动端流程仍可能存在漏洞。
- **弱化约束**：要求精确 `deviceId`、`frameRate`、`width`、`height` 或 `facingMode` 的页面，有时可通过 monkeypatch `navigator.mediaDevices.getUserMedia`，将严格约束替换为更宽泛的范围来绕过。
- **低质量生成加后处理**：生成模型能够可靠渲染的最低成本视频，然后使用 FFmpeg 放大或进行帧插值，以满足采集要求。
- **可预测的主动挑战**：重复的头部移动或闪光序列值得录制，并通过生成式工作流进行重放。
- **薄弱的重放检测**：当反重放逻辑只检查表层帧相似度时，简单的场景扰动（例如裁剪或位置偏移）、叠加层变化或轻微运动可能就足够绕过检测。

## 移动端与桌面端的信任差异

原生移动应用可以通过以下机制提高攻击者的成本：

- 对摄像头缓冲区进行**传感器或 Secure Element 证明**；
- 使用 **Play Integrity** 或 **App Attest** 等**执行完整性**信号；
- 对视频与加速度计或陀螺仪遥测数据之间进行**运动关联**。

桌面 Web 流程通常缺少等效的摄像头信任链，因此通常是阻力最小的攻击路径。

## 防御审查要点

审查 KYC 或活体检测集成时，应确认其是否：

- 为原本仅针对移动端采集进行威胁建模的流程，允许使用**桌面浏览器回退方案**；
- 主要依赖**算法活体检测**，但未针对可疑会话实施强有力的人工升级处理；
- 使用**稳定或可预测的挑战**，使其能够被预先录制并输入生成管线；
- 检测 **`getUserMedia` monkeypatch**、虚拟摄像头、不一致的浏览器硬件遥测数据或缺失的设备证明。

## 参考资料

- [Synacktiv - KYC: Bypass age verification using generative video models](https://www.synacktiv.com/en/publications/kyc-bypass-age-verification-using-generative-video-models.html)
- [Amazon Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- [v4l2loopback](https://github.com/v4l2loopback/v4l2loopback)
- [MDN - MediaDevices.getUserMedia()](https://developer.mozilla.org/en-US/docs/Web/API/MediaDevices/getUserMedia)

{{#include ../banners/hacktricks-training.md}}
