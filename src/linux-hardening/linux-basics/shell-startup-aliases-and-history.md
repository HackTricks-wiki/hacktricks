# Shell khởi động, alias và lịch sử

{{#include ../../banners/hacktricks-training.md}}

Một lệnh trong shell có thể hoạt động khác với tệp thực thi cùng tên nếu alias, function, tệp khởi động hoặc biến môi trường thay đổi cách lệnh chạy. Hãy kiểm tra những yếu tố này trước khi tin vào đầu ra của lệnh hoặc cho rằng script sử dụng cùng PATH như một phiên tương tác.

## Kiểm tra shell hiện tại

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` và `command -V` cho biết một tên được phân giải thành alias, hàm, lệnh dựng sẵn hay tệp. `command -v` và `which` có thể không cho kết quả giống nhau đối với alias và hàm. Lịch sử shell có thể làm lộ các lệnh hoặc thông tin xác thực, nhưng có thể không đầy đủ, bị vô hiệu hóa hoặc được lưu trong bộ nhớ cho đến khi phiên kết thúc.

`.bashrc` bị sửa đổi có thể định nghĩa một alias `sudo` giả lập lời nhắc nhập mật khẩu, ghi lại câu trả lời rồi chuyển câu trả lời đó cho lệnh thực. Cách này có thể che giấu việc chặn thông tin xác thực mà không thay đổi tệp thực thi `sudo` hoặc `PATH`.<sup>[[5]](#references)</sup> Shell phải đọc tệp khởi động đã sửa đổi và mở rộng alias.<sup>[[7]](#references)</sup> Theo mặc định, Bash không tương tác sẽ không mở rộng alias trừ khi `expand_aliases` được bật.<sup>[[6]](#references)</sup>

## Kiểm tra các tệp khởi động và lịch sử

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Một file khởi động mà người dùng có quyền ghi có thể thực thi lệnh trong lần khởi chạy shell sau đó. File khởi động toàn hệ thống hoặc file khởi động của người dùng có đặc quyền nhạy cảm hơn nếu tài khoản có đặc quyền thấp hơn có thể sửa đổi chúng. Bash không tương tác cũng có thể đọc file được chỉ định bởi `BASH_ENV`; trang [biến môi trường](linux-environment-variables.md#bash_env--env) giải thích hành vi đó và các hook của trình thông dịch khác. Hãy xác minh những file mà shell thực tế đọc trong các phiên đăng nhập, tương tác và không tương tác trước khi khẳng định đây là một đường dẫn duy trì quyền truy cập.

Cũng kiểm tra các file được một file khởi động toàn cục nạp bằng `source`. Ví dụ, dòng `source /opt/app/venv/bin/activate` trong `/etc/bash.bashrc` sẽ chạy file kích hoạt dưới dạng mã shell khi shell thực sự đọc file khởi động đó. Kiểm tra file kích hoạt, quyền trên symlink và thư mục cha, cùng ACL; người dùng có đặc quyền thấp hơn chỉ có thể ảnh hưởng đến shell có đặc quyền nếu shell đó hoặc một tác vụ có đặc quyền sau này nạp file này. Nếu quyền ghi phụ thuộc vào `sudoedit`, trước tiên hãy xác minh chính xác quy tắc sudoers và gói sudo đã cài đặt, bao gồm cả các bản vá của nhà cung cấp; chỉ riêng chuỗi phiên bản upstream không chứng minh được [khả năng bị khai thác bằng cách chèn đối số vào sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Kiểm tra history, dotfiles và bản sao lưu để tìm bí mật như mô tả trong [người dùng và phiên](../user-information/user-and-session-triage.md). Nếu một script có đặc quyền phân giải lệnh bằng tên, hãy kết hợp việc rà soát này với [hướng dẫn chiếm quyền PATH](linux-environment-variables.md#path).

## Chuyển hướng startup và file đã biên dịch của Zsh

Với các thiết lập `RCS` mặc định, zsh đọc `$ZDOTDIR/.zshenv` trước các lần gọi thông thường, bao gồm `zsh -c` và các script; nếu `ZDOTDIR` chưa được đặt, nó sẽ dùng `$HOME`. Khi trình chạy lệnh chấp nhận một map môi trường, hãy kiểm tra xem nó có chuyển tiếp một trong hai biến này vào tiến trình zsh có đặc quyền hay không. Khi đó, một `.zshenv` có thể ghi được có thể chạy **trước** phần thân lệnh mà trình chạy kiểm tra hoặc đưa vào danh sách cho phép. Điều này đòi hỏi tiến trình có đặc quyền phải kế thừa thư mục được chuyển hướng; `zsh -f` bỏ qua các file khởi động của người dùng, nhưng không bỏ qua `zshenv` toàn cục (thường là `/etc/zshenv`, nhưng đường dẫn thay đổi tùy bản phân phối). [Trang chèn mã zsh trên macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) có ví dụ tối giản về `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Một file `.zshenv.zwc` hoặc `.zshrc.zwc` mới hơn và hợp lệ sẽ được thực thi thay cho file khởi động dạng văn bản thuần. Nếu bạn có thể ghi vào thư mục khởi động, việc biên dịch một file đã sửa đổi rồi khôi phục file văn bản thuần trông có vẻ vô hại có thể để lại mã thực thi trong bản đã biên dịch. Đây là che giấu, không phải mã hóa. Bài kiểm tra dùng môi trường tạm thời bên dưới cho thấy vì sao chỉ kiểm tra file văn bản là chưa đủ; bài kiểm tra không động đến thư mục home thực.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Với một mục tiêu thực tế, hãy xác định `ZDOTDIR`/`HOME` thực tế, kiểm tra cả tệp văn bản lẫn tệp `.zwc`, đồng thời kiểm tra dấu thời gian, quyền sở hữu và các thư mục cha có quyền ghi. Tệp `.zwc` phải khớp với tệp nguồn và mới hơn thì mới được ưu tiên.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Các tệp khởi động và thoát của Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Khuyến cáo về việc chèn mã vào môi trường khởi động shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Các lệnh tích hợp của shell Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Tệp .zshrc.zwc Bạn Quên Kiểm Tra](https://dfir.ch/posts/compiled_zsh/)
- [5] [Chiến dịch gián điệp sử dụng AI nhắm vào hạ tầng Linux của chính phủ](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Hướng dẫn Bash: Bí danh](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Hướng dẫn Bash: Các tệp khởi động của Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
