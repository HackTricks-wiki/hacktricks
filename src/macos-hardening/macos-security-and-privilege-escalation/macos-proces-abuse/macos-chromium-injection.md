# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

基于 Chromium 的浏览器，如 Google Chrome、Microsoft Edge、Brave 等。这些浏览器建立在 Chromium 开源项目上，这意味着它们共享一个共同的基础，因此具有相似的功能和开发选项。

#### `--load-extension` 标志

`--load-extension` 标志用于从命令行或脚本启动基于 Chromium 的浏览器。此标志允许在启动时**自动加载一个或多个扩展**到浏览器中。

#### `--use-fake-ui-for-media-stream` 标志

`--use-fake-ui-for-media-stream` 标志是另一个可以用于启动基于 Chromium 的浏览器的命令行选项。此标志旨在**绕过正常的用户提示，这些提示请求访问来自摄像头和麦克风的媒体流的权限**。使用此标志时，浏览器会自动授予任何请求访问摄像头或麦克风的网站或应用程序权限。

### 工具

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### 示例
```bash
# Intercept traffic
voodoo intercept -b chrome
```
在工具链接中找到更多示例

## 参考

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
