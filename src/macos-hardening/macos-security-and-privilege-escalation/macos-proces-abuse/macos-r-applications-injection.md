# Chèn mã vào ứng dụng R trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Khi khởi động, R nạp các tệp profile của site và người dùng chứa mã R. `R_PROFILE` chọn profile của site, còn `R_PROFILE_USER` chọn profile của người dùng, cho phép môi trường được kế thừa chuyển hướng một trong hai thao tác tìm kiếm này đến tệp mà kẻ tấn công có thể đọc được.<sup>[[1]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` bỏ qua user profile, `--no-site-file` bỏ qua site profile, còn `--vanilla` bao gồm cả hai biện pháp bảo vệ. R xử lý trước các tệp môi trường được chọn bằng `R_ENVIRON` và `R_ENVIRON_USER`, nhưng các tệp đó chỉ thiết lập biến; các biến profile mới là primitive thực thi mã tùy ý trực tiếp.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` và đường dẫn thư viện

R attach các package được phân tách bằng dấu phẩy trong `R_DEFAULT_PACKAGES` khi khởi động. `Rscript` ưu tiên `R_SCRIPT_DEFAULT_PACKAGES`. Kết hợp một trong hai biến này với `R_LIBS`, `R_LIBS_USER` hoặc `R_LIBS_SITE` có thể khiến R tìm và load một package đã cài đặt do attacker kiểm soát; hook `.onLoad` hoặc `.onAttach` của package sẽ tự động thực thi.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Điều này đòi hỏi một R package đã cài đặt và có cấu trúc hợp lệ, không chỉ là một tệp `.R` rời. `--vanilla` không xóa các biến được kế thừa trực tiếp, vì vậy một wrapper đáng tin cậy phải bỏ đặt hoặc thay thế các biến package mặc định và đường dẫn thư viện, đồng thời vô hiệu hóa các tệp profile.

## References

- [1] [Khởi tạo khi bắt đầu một phiên R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Cài đặt và quản trị R: Các package bổ trợ](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
