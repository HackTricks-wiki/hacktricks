# Bảo mật Image, ký và secrets

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Bảo mật container bắt đầu trước khi workload được khởi chạy. Image quyết định những binary, trình thông dịch, thư viện, script khởi động và cấu hình nhúng nào sẽ được đưa vào production. Nếu image bị cài backdoor, lỗi thời hoặc được build với secrets nhúng sẵn, thì các biện pháp hardening ở runtime sau đó đã phải hoạt động trên một artifact bị xâm phạm. <sup>[[1]](#references)</sup>

Đó là lý do provenance của image, quét lỗ hổng, xác minh chữ ký và xử lý secrets cần được xem xét cùng với namespaces và seccomp. Chúng bảo vệ một giai đoạn khác trong vòng đời, nhưng các lỗi ở đây thường xác định attack surface mà runtime sau đó phải hạn chế.

## Registry Image Và Mức Độ Tin Cậy

Image có thể đến từ các registry công khai như Docker Hub hoặc từ registry riêng do một tổ chức vận hành. Câu hỏi về bảo mật không chỉ đơn giản là image được lưu ở đâu, mà là nhóm có thể xác định provenance và tính toàn vẹn của image hay không. Việc kéo các image chưa được ký hoặc không được theo dõi chặt chẽ từ các nguồn công khai làm tăng nguy cơ nội dung độc hại hoặc bị sửa đổi lọt vào production. Ngay cả registry nội bộ cũng cần có quyền sở hữu, quy trình xem xét và chính sách tin cậy rõ ràng.

Trước đây, Docker Content Trust sử dụng các khái niệm Notary và TUF để yêu cầu image được ký. Docker đang ngừng triển khai này, vì vậy các môi trường triển khai mới nên dùng quy trình ký và xác minh hiện hành thay vì bắt đầu triển khai DCT mới. Bài học lâu dài vẫn hữu ích: cần xác minh được danh tính và tính toàn vẹn của image, thay vì mặc định tin tưởng. <sup>[[2]](#references)</sup>

Ví dụ về quy trình Docker Content Trust trước đây:

```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```

Mục đích của ví dụ không phải là mọi nhóm đều phải tiếp tục sử dụng cùng một bộ công cụ, mà là việc ký và quản lý khóa là những công việc vận hành, không phải lý thuyết trừu tượng.

## Quét lỗ hổng

Quét image giúp trả lời hai câu hỏi khác nhau. Thứ nhất, image có chứa các package hoặc thư viện đã biết là có lỗ hổng không? Thứ hai, image có mang theo phần mềm không cần thiết làm mở rộng bề mặt tấn công không? Một image chứa đầy công cụ gỡ lỗi, shell, trình thông dịch và package lỗi thời vừa dễ bị khai thác hơn, vừa khó đánh giá hơn. <sup>[[3]](#references)</sup>

Một số công cụ quét thường được sử dụng gồm:

```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```

Kết quả từ các công cụ này cần được diễn giải cẩn thận. Lỗ hổng trong một package không được sử dụng không có mức độ rủi ro giống với một đường dẫn RCE bị lộ, nhưng cả hai vẫn cần được cân nhắc khi đưa ra quyết định hardening.

## Secrets trong quá trình build

Một trong những sai lầm lâu đời nhất trong các build pipeline của container là nhúng secrets trực tiếp vào image hoặc truyền chúng qua build arguments hay environment variables. Tùy thuộc vào cơ chế, những giá trị đó có thể tồn tại trong metadata của image hoặc các layer có thể khôi phục, xuất hiện trong build logs hoặc bị lộ qua các lệnh kiểm tra như `docker inspect`. Secrets trong quá trình build nên được mount tạm thời trong lúc build thay vì được sao chép vào filesystem của image. <sup>[[4]](#references)</sup>

BuildKit cải thiện mô hình này bằng cách cho phép xử lý secrets chuyên dụng trong quá trình build. Thay vì ghi secret vào một layer, bước build có thể sử dụng nó tạm thời:

```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```

Điều này quan trọng vì các layer của image là những artifact tồn tại lâu dài. Khi một secret đã được đưa vào một layer đã commit, việc xóa tệp đó ở một layer khác về sau không thực sự loại bỏ thông tin bị lộ ban đầu khỏi lịch sử image.

## Secrets khi chạy

Các secret cần thiết cho workload đang chạy cũng nên tránh những cách làm tùy tiện như dùng biến môi trường thuần bất cứ khi nào có thể. Volume, các tích hợp quản lý secret chuyên dụng, Docker secrets và Kubernetes Secrets là những cơ chế phổ biến. Không cơ chế nào loại bỏ mọi rủi ro, đặc biệt nếu attacker đã thực thi được mã trong workload, nhưng chúng vẫn tốt hơn việc lưu thông tin xác thực vĩnh viễn trong image hoặc để lộ chúng một cách dễ dãi qua các công cụ kiểm tra. <sup>[[5]](#references)</sup>

Một khai báo secret theo kiểu Docker Compose đơn giản trông như sau:

```yaml
version: "3.7"
services:
  my_service:
    image: centos:7
    entrypoint: "cat /run/secrets/my_secret"
    secrets:
      - my_secret
secrets:
  my_secret:
    file: ./my_secret_file.txt
```

Trong Kubernetes, các đối tượng Secret, volume được chiếu, token service account và danh tính workload trên cloud tạo nên một mô hình rộng hơn và mạnh mẽ hơn, nhưng chúng cũng tạo thêm nhiều cơ hội vô tình để lộ thông tin qua các mount trên host, RBAC quá rộng hoặc thiết kế Pod yếu.

## Lạm dụng

Khi đánh giá mục tiêu, mục đích là xác định liệu secret có được đóng gói sẵn trong image, bị rò rỉ vào các layer hay được mount vào những vị trí runtime dễ đoán hay không:

```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```

Các lệnh này giúp phân biệt ba vấn đề khác nhau: leak trong cấu hình ứng dụng, leak ở image layer và các tệp secret được inject lúc runtime. Nếu một secret xuất hiện trong `/run/secrets`, một projected volume hoặc đường dẫn cloud identity token, bước tiếp theo là tìm hiểu liệu nó chỉ cấp quyền truy cập cho workload hiện tại hay cho một control plane lớn hơn nhiều.

### Ví dụ đầy đủ: Secret được nhúng trong filesystem của image

Nếu một build pipeline sao chép các tệp `.env` hoặc thông tin xác thực vào image cuối cùng, post-exploitation sẽ trở nên đơn giản:

```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```

Tác động phụ thuộc vào ứng dụng, nhưng các signing key, JWT secret hoặc thông tin xác thực cloud được nhúng trong đó có thể dễ dàng biến việc xâm phạm container thành xâm phạm API, di chuyển ngang hoặc giả mạo token ứng dụng được tin cậy.

### Full Example: Build-Time Secret Leakage Check

Nếu mối lo ngại là lịch sử image đã ghi lại một layer chứa secret:

```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```

Loại rà soát này hữu ích vì secret có thể đã bị xóa khỏi chế độ xem filesystem cuối cùng nhưng vẫn còn trong một layer trước đó hoặc metadata build.

## Checks

Các kiểm tra này nhằm xác định liệu image và quy trình xử lý secret có khả năng làm tăng attack surface trước khi chạy hay không.

```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```

Điều gì đáng chú ý ở đây:

- Lịch sử build đáng ngờ có thể làm lộ thông tin xác thực đã sao chép, dữ liệu SSH hoặc các bước build không an toàn.
- Secrets trong các đường dẫn volume được chiếu có thể dẫn đến quyền truy cập cluster hoặc cloud, chứ không chỉ quyền truy cập ứng dụng cục bộ.
- Số lượng lớn file cấu hình chứa thông tin xác thực dạng plaintext thường cho thấy image hoặc mô hình triển khai đang mang theo nhiều dữ liệu tin cậy hơn mức cần thiết.

## Mặc định khi chạy

| Runtime / nền tảng | Trạng thái mặc định | Hành vi mặc định | Cách làm suy yếu phổ biến |
| --- | --- | --- | --- |
| Docker / BuildKit | Hỗ trợ mount secret an toàn trong quá trình build, nhưng không tự động bật | Secrets có thể được mount tạm thời trong quá trình `build`; việc ký image và quét cần được lựa chọn rõ ràng trong workflow | sao chép secrets vào image, truyền secrets bằng `ARG` hoặc `ENV`, tắt kiểm tra provenance |
| Podman / Buildah | Hỗ trợ các bản build gốc OCI và workflow nhận biết secret | Có sẵn các workflow build mạnh mẽ, nhưng operator vẫn phải chủ động chọn chúng | nhúng secrets vào Containerfile, dùng build context quá rộng, dùng bind mount với quyền quá thoáng trong quá trình build |
| Kubernetes | Các đối tượng Secret gốc và volume được chiếu | Phân phối secret lúc chạy là tính năng cốt lõi, nhưng mức độ lộ phụ thuộc vào RBAC, thiết kế pod và mount từ host | mount Secret quá rộng, sử dụng sai token service account, truy cập `hostPath` vào các volume do kubelet quản lý |
| Registry | Tính toàn vẹn là tùy chọn trừ khi được thực thi | Cả registry công khai lẫn riêng tư đều phụ thuộc vào chính sách, việc ký và quyết định admission | tự do pull image chưa được ký, kiểm soát admission yếu, quản lý khóa kém |

## References

- [1] [Đặc tả định dạng Image của Open Container Initiative](https://github.com/opencontainers/image-spec/blob/main/spec.md)
- [2] [Tài liệu Docker - Content trust trong Docker](https://docs.docker.com/engine/security/trust/)
- [3] [Tài liệu Docker - Docker Scout](https://docs.docker.com/scout/)
- [4] [Tài liệu Docker - Build secrets](https://docs.docker.com/build/building/secrets/)
- [5] [Tài liệu Kubernetes - Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
{{#include ../../../banners/hacktricks-training.md}}
