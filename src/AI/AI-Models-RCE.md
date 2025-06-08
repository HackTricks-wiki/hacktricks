# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

机器学习模型通常以不同格式共享，例如 ONNX、TensorFlow、PyTorch 等。这些模型可以加载到开发者的机器或生产系统中使用。通常情况下，模型不应包含恶意代码，但在某些情况下，模型可以被用来在系统上执行任意代码，作为预期功能或由于模型加载库中的漏洞。

在撰写时，这里有一些此类漏洞的示例：

| **框架 / 工具**            | **漏洞 (如果有 CVE)**                                                                                                         | **RCE 向量**                                                                                                                         | **参考**                                   |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *不安全的反序列化在* `torch.load` **(CVE-2025-32434)**                                                              | 恶意 pickle 在模型检查点中导致代码执行（绕过 `weights_only` 保护）                                                                    | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + 恶意模型下载导致代码执行；管理 API 中的 Java 反序列化 RCE                                                                      | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (不安全的 YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | 从 YAML 加载模型使用 `yaml.unsafe_load`（代码执行） <br> 使用 **Lambda** 层加载模型运行任意 Python 代码                              | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite 解析)                                                                                          | 精心制作的 `.tflite` 模型触发整数溢出 → 堆损坏（潜在 RCE）                                                                            | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | 通过 `joblib.load` 加载模型执行攻击者的 `__reduce__` 负载                                                                           | |
| **NumPy** (Python)          | **CVE-2019-6446** (不安全的 `np.load`) *有争议*                                                                              | `numpy.load` 默认允许 pickle 对象数组 – 恶意 `.npy/.npz` 触发代码执行                                                                | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (目录遍历) <br> **CVE-2024-5187** (tar 遍历)                                                    | ONNX 模型的外部权重路径可以逃逸目录（读取任意文件） <br> 恶意 ONNX 模型 tar 可以覆盖任意文件（导致 RCE）                               | |
| ONNX Runtime (设计风险)  | *(无 CVE)* ONNX 自定义操作 / 控制流                                                                                    | 带有自定义操作符的模型需要加载攻击者的本地代码；复杂的模型图滥用逻辑以执行意外计算                                                      | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (路径遍历)                                                                                          | 使用启用 `--model-control` 的模型加载 API 允许相对路径遍历以写入文件（例如，覆盖 `.bashrc` 以实现 RCE）                               | |
| **GGML (GGUF 格式)**      | **CVE-2024-25664 … 25668** (多个堆溢出)                                                                         | 格式错误的 GGUF 模型文件导致解析器中的堆缓冲区溢出，使得在受害者系统上执行任意代码                                                      | |
| **Keras (旧格式)**   | *(无新 CVE)* 旧版 Keras H5 模型                                                                                         | 恶意 HDF5 (`.h5`) 模型中的 Lambda 层代码在加载时仍然执行（Keras 安全模式不覆盖旧格式 – “降级攻击”）                                     | |
| **其他** (一般)        | *设计缺陷* – Pickle 序列化                                                                                         | 许多 ML 工具（例如，基于 pickle 的模型格式，Python `pickle.load`）将执行嵌入模型文件中的任意代码，除非采取缓解措施                     | |

此外，还有一些基于 Python pickle 的模型，例如 [PyTorch](https://github.com/pytorch/pytorch/security) 使用的模型，如果不使用 `weights_only=True` 加载，则可能会在系统上执行任意代码。因此，任何基于 pickle 的模型可能特别容易受到此类攻击，即使它们未在上表中列出。

{{#include ../banners/hacktricks-training.md}}
