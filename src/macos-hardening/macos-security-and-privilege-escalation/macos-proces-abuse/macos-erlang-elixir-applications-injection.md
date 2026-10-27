# Injection vào ứng dụng Erlang và Elixir trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` và `ERL_ZFLAGS`

Trình khởi chạy `erl` thêm `ERL_AFLAGS` vào đầu dòng lệnh và `ERL_FLAGS` / `ERL_ZFLAGS` vào cuối. Vì `-eval` đánh giá một biểu thức Erlang trong quá trình khởi tạo VM, các biến này có thể cung cấp khả năng thực thi mã không cần tệp trước khi workload dự kiến chạy.<sup>[[1]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix và nhiều bản phát hành Elixir cuối cùng đều khởi chạy Erlang VM và có thể kế thừa các flag này. Hãy xác nhận wrapper phát hành cụ thể: wrapper có thể tạo lại hoặc lọc sạch các đối số VM, trong khi một số công cụ hỗ trợ rõ ràng `ERL_AFLAGS`, `ERL_ZFLAGS` hoặc `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

Không giống hầu hết các kỹ thuật dựa trên tệp, payload `-eval` không cần tệp do attacker kiểm soát. Wrapper đáng tin cậy nên xóa cả ba biến flag của Erlang (và `ELIXIR_ERL_OPTIONS` đối với Elixir) trước khi khởi chạy runtime; đừng cố dùng allowlist cho từng VM flag riêng lẻ trừ khi đã hiểu rõ parser và thứ tự xử lý.

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Bản phát hành Elixir và các tùy chọn môi trường VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
