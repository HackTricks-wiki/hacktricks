# Sao chép một website

{{#include ../../banners/hacktricks-training.md}}

Trong một đợt đánh giá phishing, đôi khi việc **clone/dump hoàn toàn một website** có thể hữu ích.

Lưu ý rằng bạn cũng có thể thêm một số payload vào website đã clone, chẳng hạn như BeEF hook để "điều khiển" tab của người dùng.

Có nhiều công cụ bạn có thể dùng cho mục đích này:

## wget

Lệnh sau sử dụng các chế độ mirror, page-requisite, link-conversion và extension-adjustment của Wget, sau đó phục vụ các tệp đã tải xuống từ thư mục hiện tại bằng mô-đun `http.server` của Python trên cổng 8000.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```

## goclone

Kho lưu trữ goclone mô tả tiện ích này là công cụ tải một website về thư mục cục bộ mà vẫn giữ nguyên cấu trúc liên kết tương đối, đồng thời hướng dẫn cách gọi `goclone <url>`.<sup>[[3]](#references)</sup>

```bash
#https://github.com/imthaghost/goclone
goclone <url>
```

## Bộ công cụ Social Engineering

Kho lưu trữ Social-Engineer Toolkit (SET) mô tả SET là một framework kiểm thử xâm nhập mã nguồn mở dành cho các hoạt động đánh giá social engineering được ủy quyền.<sup>[[4]](#references)</sup>

```bash
#https://github.com/trustedsec/social-engineer-toolkit
```

## References

- [1] [Sổ tay GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Tài liệu Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Kho lưu trữ goclone](https://github.com/imthaghost/goclone)
- [4] [Kho lưu trữ Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
