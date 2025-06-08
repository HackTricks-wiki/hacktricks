# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning मॉडल आमतौर पर विभिन्न प्रारूपों में साझा किए जाते हैं, जैसे ONNX, TensorFlow, PyTorch, आदि। इन मॉडलों को डेवलपर्स की मशीनों या प्रोडक्शन सिस्टम में लोड किया जा सकता है। आमतौर पर, मॉडलों में दुर्भावनापूर्ण कोड नहीं होना चाहिए, लेकिन कुछ मामलों में मॉडल का उपयोग सिस्टम पर मनमाना कोड निष्पादित करने के लिए किया जा सकता है, जो कि एक इच्छित विशेषता के रूप में या मॉडल लोडिंग लाइब्रेरी में एक भेद्यता के कारण हो सकता है।

लेखन के समय, इस प्रकार की भेद्यताओं के कुछ उदाहरण हैं:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |

इसके अलावा, कुछ पायथन पिकल आधारित मॉडल जैसे कि [PyTorch](https://github.com/pytorch/pytorch/security) द्वारा उपयोग किए जाने वाले, सिस्टम पर मनमाना कोड निष्पादित करने के लिए उपयोग किए जा सकते हैं यदि उन्हें `weights_only=True` के साथ लोड नहीं किया गया। इसलिए, कोई भी पिकल आधारित मॉडल इस प्रकार के हमलों के प्रति विशेष रूप से संवेदनशील हो सकता है, भले ही वे ऊपर की तालिका में सूचीबद्ध न हों।

{{#include ../banners/hacktricks-training.md}}
