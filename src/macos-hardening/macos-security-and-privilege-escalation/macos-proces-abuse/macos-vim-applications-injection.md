# Injection vào ứng dụng Vim/Neovim trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Ngôn ngữ scripting của Vim (Vimscript) có thể chạy **các lệnh Ex và lệnh shell tùy ý khi khởi động** thông qua các biến môi trường. Nếu một tiến trình có đặc quyền cao hơn (quy trình bảo trì/root, `sudo vim …`, trình soạn thảo được một công cụ khác khởi chạy, `crontab -e`, `visudo`, `git`/`less` gọi trình soạn thảo, …) khởi chạy Vim/Neovim với môi trường chịu ảnh hưởng của attacker, attacker có thể thực thi mã trong ngữ cảnh đó.

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

`:qa!` được đưa vào stdin trong ví dụ đầu tiên chỉ đóng editor sau khi payload chạy; trong tình huống thực tế, nạn nhân có thể mở Vim theo cách thông thường.

`VIMINIT` được phân tích thành **một dòng lệnh Ex duy nhất**. Dùng `|` (hoặc ký tự xuống dòng) để phân tách chuỗi lệnh. Biến này được ưu tiên hơn vimrc của người dùng và `EXINIT`, nên payload không cần tệp cấu hình độc hại và chạy trước cấu hình người dùng thông thường.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Nếu `VIMINIT` chưa được đặt, Vim (và các binary tương thích `vi`/`ex`) sẽ dùng **`EXINIT`** thay thế; biến này được thực thi theo cùng cách. Đây là biến thể từ thời vi cổ điển của cùng một primitive.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## rc cục bộ của project với Vim `exrc`

Đây là một phương án thay thế dựa trên file cho `VIMINIT`. Nếu nạn nhân đã bật `set exrc` trong cấu hình người dùng, Vim cũng sẽ nạp `.vimrc` (sau đó là `_vimrc` hoặc `.exrc`) từ **working directory** của nó, chứ không chỉ từ thư mục chứa file đang chỉnh sửa. Đặt một `.vimrc` cục bộ trong project và khiến nạn nhân khởi động Vim từ project đó. Trên Unix, Vim áp dụng các hạn chế `secure` đối với rc cục bộ thuộc sở hữu của người khác, nhưng một archive do nạn nhân giải nén thường khiến file được đặt có quyền sở hữu của nạn nhân và vượt qua bước kiểm tra này.<sup>[[1]](#references)</sup>

Marker độc lập này cho thấy trigger khi khởi động mà không sửa đổi cấu hình người dùng thực tế:<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim thì khác: các bản dựng hiện tại yêu cầu phải tin cậy các tệp `.nvim.lua`, `.nvimrc` hoặc `.exrc` trong dự án trước khi thực thi. Mức độ tin cậy gắn với hash nội dung của tệp, vì vậy nếu sửa một tệp đã được tin cậy thì cần xác nhận tin cậy lại. Kẻ tấn công chỉ có thể đặt tệp vào repository không thể mặc định rằng tệp sẽ được thực thi âm thầm thông qua `exrc`; hãy phân biệt đường thực thi cần người dùng bật và xác nhận tin cậy này với đường Lua `require()` trong thư mục hiện tại ở bên dưới.<sup>[[4]](#references)[[5]](#references)</sup>

Để biết về vimrc **user** có thể ghi, thay vì vimrc trong dự án, xem [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration).

## Ngăn khởi động và khả năng khai thác

Kỹ thuật này phụ thuộc vào **khởi động thông thường**. `vim -u NONE` / `nvim -u NONE` bỏ qua bước khởi tạo môi trường/người dùng (và plugins), trong khi `-u <file>` sử dụng tệp đó thay thế. Vim `-es`/`-Es` và Neovim `-es`, `-Es` hoặc `-l` cũng bỏ qua các bước khởi tạo này. Đừng nhầm `--headless` với chế độ an toàn: khi khởi động headless thông thường, Neovim vẫn xử lý `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Do đó, hãy kiểm tra toàn bộ chuỗi khởi chạy: biến phải được giữ nguyên qua wrapper, chính sách `sudo`, job runner và lựa chọn editor; lệnh cuối cùng cũng không được ép dùng `-u NONE`/`NORC` hoặc chế độ batch. Payload đáng tin cậy có thể tự kết thúc bằng `|qall!`, nhờ đó cũng dễ kiểm thử các wrapper không cung cấp TTY hơn.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim: chiếm dụng module Lua trong thư mục hiện tại

Một kỹ thuật injection riêng của Neovim ảnh hưởng đến các bản dựng mà `package.path`/`package.cpath` trong Lua vẫn chứa các mẫu đường dẫn thư mục hiện tại như `./?.lua` hoặc `./?.so`. Chỉ khởi động Neovim là chưa đủ: config hoặc plugin phải gọi `require("name")`, và loader trước đó chưa được phân giải tên đó. Một trigger thường gặp là **kiểm tra dependency tùy chọn**, chẳng hạn `pcall(require, "optional_dep")`; đặt `optional_dep.lua` trong thư mục làm việc do kẻ tấn công kiểm soát sẽ khiến tệp được thực thi mà không cần bật tính năng cấu hình cục bộ riêng biệt `'exrc'`. Các module lõi `vim.*` và những module đã tìm thấy trên `'runtimepath'` thường không thể bị shadow, vì vậy hãy liệt kê các lệnh gọi `require()` thực tế cho module còn thiếu/tùy chọn thay vì đoán tên.<sup>[[3]](#references)</sup>

Ví dụ sau tái hiện kỹ thuật loader bằng một marker vô hại:<sup>[[3]](#references)</sup>

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

Kiểm tra bản dựng đang chạy thay vì chỉ dựa vào chuỗi phiên bản:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream đang theo dõi việc loại bỏ cơ chế dự phòng dùng thư mục hiện tại trong quá trình khởi động editor bình thường, đồng thời vẫn giữ hành vi của Lua-script (`nvim -l`). Cho đến khi bản build đã cài đặt không còn cung cấp cơ chế này, hãy đặt đoạn này ở **đầu** `init.lua` (nó cố ý loại bỏ các mẫu Lua/C module dùng đường dẫn tương đối từ thư mục hiện tại, vì vậy đừng áp dụng nếu quy trình của bạn cần chúng):<sup>[[3]](#references)</sup>

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

- **Neovim** sử dụng cả `VIMINIT` lẫn phương án dự phòng `EXINIT`, nhưng cấu hình người dùng thông thường của nó là `init.vim` hoặc `init.lua`.<sup>[[2]](#references)</sup>
- Đường dẫn biến môi trường không cần tệp có quyền ghi. Việc chiếm quyền qua tệp rc cục bộ và module trong thư mục hiện tại là các primitive riêng biệt, dựa trên tệp.<sup>[[1]](#references)[[3]](#references)</sup>
- Tệp rc cục bộ của dự án khác với modelines và phương án dự phòng `require()` trong thư mục hiện tại nêu trên. Vim và Neovim có các bước kiểm tra khác nhau; xem quy trình `exrc` cục bộ của dự án ở trên.<sup>[[1]](#references)[[4]](#references)</sup>
- Các biến chọn editor chỉ quyết định chương trình nào được khởi chạy; chúng không đảm bảo `VIMINIT` sẽ được chuyển đến tiến trình cuối cùng. Hãy kiểm tra chính xác môi trường và đối số tại ranh giới thực thi Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Gia cố bảo mật

- Chủ động xóa các biến trước khi khởi chạy editor với quyền cao hoặc khởi chạy tự động: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` rất quan trọng khi bên gọi cần bỏ qua mọi nguồn khởi động của người dùng.<sup>[[1]](#references)[[2]](#references)</sup>
- Đặt `EDITOR`/`VISUAL` thành các đường dẫn tuyệt đối đáng tin cậy, tránh chạy editor tương tác với quyền root cùng môi trường người dùng được kế thừa, và bảo đảm các wrapper không thể khôi phục `VIMINIT`/`EXINIT` sau khi đã lọc bỏ.<sup>[[1]](#references)[[2]](#references)</sup>
- Với Neovim, hãy cập nhật lên bản build loại bỏ các mẫu tìm kiếm Lua/C trong thư mục hiện tại khi ở chế độ editor, hoặc loại bỏ chúng trước khi tải plugin. Kiểm tra mã plugin để tìm các lời gọi `pcall(require, ...)` tùy chọn khi mở repository không đáng tin cậy.<sup>[[3]](#references)</sup>
- Xem quyền kiểm soát môi trường editor, thư mục làm việc hoặc cấu hình khởi động của mục tiêu là một primitive có khả năng thực thi mã trong ngữ cảnh bảo mật của editor.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Tài liệu Vim — `starting.txt` (khởi tạo, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Tài liệu Neovim — khởi động và khởi tạo](https://neovim.io/doc/user/starting/)
- [3] [Vấn đề Neovim #38966 — phương án dự phòng thư mục hiện tại trong `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Tùy chọn Neovim — `exrc` cục bộ của dự án và yêu cầu tin cậy](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Chỉnh sửa trong Neovim — tệp đáng tin cậy và `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}
