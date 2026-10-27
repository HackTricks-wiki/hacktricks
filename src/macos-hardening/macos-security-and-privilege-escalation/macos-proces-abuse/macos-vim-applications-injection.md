# Injection vào ứng dụng Vim/Neovim trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Ngôn ngữ scripting riêng của Vim (Vimscript) có thể chạy **các lệnh Ex và lệnh shell tùy ý khi khởi động** thông qua các biến môi trường. Nếu một tiến trình có đặc quyền cao hơn (quy trình bảo trì/root, `sudo vim …`, trình chỉnh sửa được một công cụ khác khởi chạy, `crontab -e`, `visudo`, `git`/`less` gọi trình chỉnh sửa, …) khởi chạy Vim/Neovim với môi trường chịu ảnh hưởng của attacker, attacker có thể thực thi mã trong ngữ cảnh đó.

## `VIMINIT`

Trong quá trình khởi tạo, Vim đọc và thực thi các lệnh Ex trong **`VIMINIT`**. Lệnh Ex bao gồm `:!cmd` (chạy lệnh shell) và `:call system(...)`, vì vậy chỉ một biến duy nhất cũng cho phép thực thi tùy ý trước khi bất kỳ tệp nào được chỉnh sửa.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

`:qa!` được truyền qua stdin trong ví dụ đầu tiên chỉ đóng trình soạn thảo sau khi payload chạy; trong tình huống thực tế, nạn nhân có thể mở Vim theo cách bình thường.

`VIMINIT` được phân tích thành **một dòng lệnh Ex**. Phân tách chuỗi lệnh bằng `|` (hoặc ký tự xuống dòng thực sự). Biến này được ưu tiên hơn vimrc và `EXINIT` của người dùng, nên payload không cần tệp cấu hình độc hại và chạy trước cấu hình người dùng thông thường.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Nếu `VIMINIT` chưa được đặt, Vim (và các binary tương thích `vi`/`ex`) sẽ dùng **`EXINIT`** thay thế; biến này được thực thi theo cùng cách. Đây là biến thể cổ điển từ thời vi của cùng một primitive.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Vô hiệu hóa khởi động và khả năng khai thác

Kỹ thuật này phụ thuộc vào **quá trình khởi động bình thường**. `vim -u NONE` / `nvim -u NONE` bỏ qua bước khởi tạo môi trường/người dùng (và plugins), còn `-u <file>` dùng file đó thay thế. Vim `-es`/`-Es` và Neovim `-es`, `-Es` hoặc `-l` cũng bỏ qua các bước khởi tạo này. Đừng nhầm `--headless` với chế độ an toàn: khi khởi động bình thường ở chế độ headless, Neovim vẫn xử lý `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Do đó, hãy xác thực toàn bộ chuỗi khởi chạy: biến phải được giữ nguyên qua wrapper, chính sách `sudo`, trình chạy job và lựa chọn editor; lệnh cuối cùng không được ép dùng `-u NONE`/`NORC` hoặc chế độ batch. Payload đáng tin cậy có thể tự kết thúc bằng `|qall!`, việc này cũng giúp kiểm thử các wrapper không cấp TTY dễ dàng hơn.<sup>[[1]](#references)[[2]](#references)</sup>

## Chiếm quyền module Lua trong thư mục hiện tại của Neovim

Một kỹ thuật injection riêng của Neovim ảnh hưởng đến các bản dựng mà `package.path`/`package.cpath` của Lua vẫn chứa các mẫu thư mục hiện tại như `./?.lua` hoặc `./?.so`. Chỉ khởi chạy Neovim là chưa đủ: config hoặc plugin phải gọi `require("name")`, và loader nào chạy trước đó cũng không được phân giải tên này. Một kích hoạt phổ biến là **kiểm tra dependency tùy chọn**, chẳng hạn `pcall(require, "optional_dep")`; đặt `optional_dep.lua` trong thư mục làm việc do attacker kiểm soát sẽ khiến file này được thực thi mà không cần bật tính năng cấu hình cục bộ `'exrc'` riêng biệt. Các module lõi `vim.*` và module đã tìm thấy trên `'runtimepath'` thường không thể bị shadow, vì vậy hãy liệt kê các lệnh gọi `require()` thực sự bị thiếu/tùy chọn thay vì đoán tên module.<sup>[[3]](#references)</sup>

Cách sau tái hiện kỹ thuật loader bằng một marker vô hại:<sup>[[3]](#references)</sup>

```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```

Kiểm tra bản build đang chạy thay vì chỉ dựa vào chuỗi phiên bản:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream đang theo dõi việc loại bỏ cơ chế dự phòng thư mục hiện tại trong quá trình khởi động trình soạn thảo thông thường, đồng thời vẫn giữ hành vi của Lua-script (`nvim -l`). Cho đến khi bản build đã cài đặt không còn cung cấp cơ chế này, hãy đặt đoạn sau ở **đầu** `init.lua` (đoạn này cố ý loại bỏ các mẫu module Lua/C có đường dẫn tương đối tới thư mục hiện tại, vì vậy không áp dụng cho các quy trình cần đến chúng):<sup>[[3]](#references)</sup>

```lua
local function drop_cwd(path)
  local keep = {}
  for entry in path:gmatch("[^;]+") do
    if not entry:match("^%./") then keep[#keep + 1] = entry end
  end
  return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```

## Ghi chú và lưu ý

- **Neovim** tôn trọng cả `VIMINIT` và phương án dự phòng `EXINIT`, nhưng cấu hình người dùng thông thường của nó là `init.vim` hoặc `init.lua`.<sup>[[2]](#references)</sup>
- Đường dẫn biến môi trường không cần tệp có quyền ghi. Việc chiếm quyền local rc và module ở thư mục hiện tại là các primitive riêng biệt, dựa trên tệp.<sup>[[1]](#references)[[3]](#references)</sup>
- Cấu hình riêng của dự án là bề mặt khác với modelines. Khi bật `'exrc'` của Vim, local vimrc/exrc thuộc sở hữu của người dùng khác sẽ chạy với các hạn chế `'secure'`; tuy nhiên, giải nén một archive thường khiến tệp được cài cắm thuộc sở hữu của nạn nhân, vô hiệu hóa cơ chế bảo vệ dựa trên quyền sở hữu đó. Neovim cũng tìm `.nvim.lua`, `.nvimrc` hoặc `.exrc` khi bật `'exrc'`—đừng nhầm cơ chế yêu cầu bật này với phương án dự phòng `require()` ở thư mục hiện tại nêu trên.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Các biến chọn editor chỉ chọn chương trình được khởi chạy; chúng không đảm bảo `VIMINIT` sẽ đến được tiến trình cuối cùng. Kiểm tra chính xác môi trường và đối số tại ranh giới exec của Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Tăng cường bảo mật

- Chủ động loại bỏ các biến trước khi khởi chạy editor có đặc quyền hoặc được tự động hóa: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` rất quan trọng khi bên gọi cần bỏ qua mọi nguồn khởi động của người dùng.<sup>[[1]](#references)[[2]](#references)</sup>
- Đặt `EDITOR`/`VISUAL` thành đường dẫn tuyệt đối đáng tin cậy, tránh chạy editor tương tác với quyền root và môi trường người dùng được kế thừa, đồng thời đảm bảo các wrapper không thể khôi phục `VIMINIT`/`EXINIT` sau khi đã làm sạch.<sup>[[1]](#references)[[2]](#references)</sup>
- Với Neovim, cập nhật lên bản build loại bỏ các template tìm kiếm Lua/C ở thư mục hiện tại trong chế độ editor, hoặc xóa chúng trước khi tải plugin. Kiểm tra mã plugin để tìm các lệnh gọi `pcall(require, ...)` tùy chọn khi mở repository không đáng tin cậy.<sup>[[3]](#references)</sup>
- Xem việc kiểm soát môi trường editor, thư mục làm việc hoặc cấu hình khởi động của mục tiêu là một primitive có khả năng thực thi mã trong ngữ cảnh bảo mật của editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Tài liệu Vim — `starting.txt` (khởi tạo, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Tài liệu Neovim — khởi động và khởi tạo](https://neovim.io/doc/user/starting/)
- [3] [Vấn đề Neovim #38966 — phương án dự phòng thư mục hiện tại trong `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}
