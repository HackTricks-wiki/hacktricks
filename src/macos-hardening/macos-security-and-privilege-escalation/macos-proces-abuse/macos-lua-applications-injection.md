# Tiêm mã vào ứng dụng Lua trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## `LUA_INIT`

Trước khi xử lý các tùy chọn dòng lệnh hoặc script đích, trình thông dịch Lua độc lập sẽ thực thi `LUA_INIT_<major>_<minor>` hoặc, nếu biến có phiên bản không tồn tại, `LUA_INIT`. Giá trị bắt đầu bằng `@` sẽ chỉ định một tệp; mọi giá trị khác sẽ được đánh giá trực tiếp dưới dạng mã Lua. Điều này cho phép thực thi lúc khởi động thông qua cả tệp lẫn không cần tệp.<sup>[[1]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Tên có phiên bản cụ thể thay đổi tùy theo trình thông dịch, ví dụ `LUA_INIT_5_4`. `lua -E` bỏ qua mọi biến môi trường, bao gồm mã khởi động và đường dẫn module Lua.

## References

- [1] [Trình thông dịch độc lập Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
{{#include ../../../banners/hacktricks-training.md}}
