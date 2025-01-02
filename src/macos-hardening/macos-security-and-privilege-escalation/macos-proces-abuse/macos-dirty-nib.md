# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

**有关该技术的更多详细信息，请查看原始帖子：** [**https://blog.xpnsec.com/dirtynib/**](https://blog.xpnsec.com/dirtynib/) 和以下帖子 [**https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/**](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)**。** 这里是一个总结：

### 什么是 Nib 文件

Nib（NeXT Interface Builder 的缩写）文件是苹果开发生态系统的一部分，旨在定义应用程序中的 **UI 元素** 及其交互。它们包含序列化对象，如窗口和按钮，并在运行时加载。尽管它们仍在使用，苹果现在提倡使用 Storyboards 以更全面地可视化 UI 流。

主 Nib 文件在应用程序的 `Info.plist` 文件中的值 **`NSMainNibFile`** 中引用，并由在应用程序的 `main` 函数中执行的 **`NSApplicationMain`** 函数加载。

### Dirty Nib 注入过程

#### 创建和设置 NIB 文件

1. **初始设置**：
- 使用 XCode 创建一个新的 NIB 文件。
- 向界面添加一个对象，将其类设置为 `NSAppleScript`。
- 通过用户定义的运行时属性配置初始 `source` 属性。
2. **代码执行工具**：
- 该设置便于按需运行 AppleScript。
- 集成一个按钮以激活 `Apple Script` 对象，特别触发 `executeAndReturnError:` 选择器。
3. **测试**：

- 一个简单的 Apple Script 用于测试：

```bash
set theDialogText to "PWND"
display dialog theDialogText
```

- 通过在 XCode 调试器中运行并点击按钮进行测试。

#### 目标应用程序（示例：Pages）

1. **准备**：
- 将目标应用程序（例如，Pages）复制到一个单独的目录（例如，`/tmp/`）。
- 启动应用程序以绕过 Gatekeeper 问题并进行缓存。
2. **覆盖 NIB 文件**：
- 用制作的 DirtyNIB 文件替换现有的 NIB 文件（例如，关于面板 NIB）。
3. **执行**：
- 通过与应用程序交互（例如，选择 `关于` 菜单项）触发执行。

#### 概念验证：访问用户数据

- 修改 AppleScript 以访问和提取用户数据，例如照片，而无需用户同意。

### 代码示例：恶意 .xib 文件

- 访问并查看 [**恶意 .xib 文件的示例**](https://gist.github.com/xpn/16bfbe5a3f64fedfcc1822d0562636b4)，演示执行任意代码。

### 其他示例

在帖子 [https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/) 中，您可以找到有关如何创建脏 NIB 的教程。&#x20;

### 解决启动限制

- 启动限制阻碍应用程序从意外位置（例如，`/tmp`）执行。
- 可以识别未受启动限制保护的应用程序，并将其作为 NIB 文件注入的目标。

### 其他 macOS 保护

从 macOS Sonoma 开始，应用程序包内的修改受到限制。然而，早期的方法包括：

1. 将应用程序复制到不同的位置（例如，`/tmp/`）。
2. 重命名应用程序包内的目录以绕过初始保护。
3. 在应用程序运行以注册 Gatekeeper 后，修改应用程序包（例如，用 Dirty.nib 替换 MainMenu.nib）。
4. 将目录重命名回去并重新运行应用程序以执行注入的 NIB 文件。

**注意**：最近的 macOS 更新通过防止在 Gatekeeper 缓存后修改应用程序包内的文件来减轻此漏洞，使其无效。

{{#include ../../../banners/hacktricks-training.md}}
