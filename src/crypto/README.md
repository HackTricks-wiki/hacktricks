# Mật mã học

{{#include ../banners/hacktricks-training.md}}

Phần này tập trung vào mật mã học thực tiễn dùng trong kiểm thử bảo mật và CTF: nhận diện các mẫu phổ biến, chọn công cụ phù hợp và áp dụng những tấn công đã biết.

Để tìm hiểu các kỹ thuật ẩn dữ liệu bên trong tệp, xem phần **Stego**.

## Cách sử dụng phần này

Bắt đầu bằng cách xác định primitive và các tham số của nó. Sau đó, xác định những gì kẻ tấn công kiểm soát hoặc quan sát được, chẳng hạn như một oracle, một giá trị bị leak hoặc việc tái sử dụng nonce, trước khi chọn tấn công.

### Quy trình CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Mật mã khóa đối xứng

{{#ref}}
symmetric/README.md
{{#endref}}

### Hash, MAC và KDF

{{#ref}}
hashes/README.md
{{#endref}}

### Mật mã khóa công khai

{{#ref}}
public-key/README.md
{{#endref}}

### TLS và chứng chỉ

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Mật mã học trong malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Linh tinh

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Thiết lập nhanh

Tạo môi trường Python cô lập và cài đặt các package thường dùng. Tài liệu PyCryptodome khuyến nghị cài đặt `pycryptodome` bằng `pip`; SageMath có hướng dẫn cài đặt riêng cho từng nền tảng được hỗ trợ.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath thường hữu ích cho các phép tính đại số, lattice, RSA và đường cong elliptic.<sup>[[2]](#references)</sup>

## References

- [1] [Tài liệu PyCryptodome - Cài đặt](https://www.pycryptodome.org/src/installation)
- [2] [Tài liệu SageMath - Hướng dẫn cài đặt](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
