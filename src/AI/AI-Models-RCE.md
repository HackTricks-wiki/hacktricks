# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Modeli za Machine Learning kawaida hushirikiwa katika mifumo tofauti, kama ONNX, TensorFlow, PyTorch, n.k. Hizi modeli zinaweza kupakuliwa kwenye mashine za waendelezaji au mifumo ya uzalishaji ili kuzitumia. Kawaida, modeli hazipaswi kuwa na msimbo mbaya, lakini kuna baadhi ya kesi ambapo modeli inaweza kutumika kutekeleza msimbo wa kiholela kwenye mfumo kama kipengele kilichokusudiwa au kwa sababu ya udhaifu katika maktaba ya kupakia modeli.

Wakati wa kuandika, haya ni baadhi ya mifano ya aina hii ya udhaifu:

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

Zaidi ya hayo, kuna baadhi ya modeli zinazotegemea python pickle kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security) ambazo zinaweza kutumika kutekeleza msimbo wa kiholela kwenye mfumo ikiwa hazijapakiwa na `weights_only=True`. Hivyo, modeli yoyote inayotegemea pickle inaweza kuwa na hatari maalum kwa aina hii ya mashambulizi, hata kama hazijatajwa katika jedwali hapo juu.

{{#include ../banners/hacktricks-training.md}}
