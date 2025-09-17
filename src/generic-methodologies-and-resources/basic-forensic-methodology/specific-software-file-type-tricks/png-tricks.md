# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** are highly regarded in **CTF challenges** for their **lossless compression**, making them ideal for embedding hidden data. Tools like **Wireshark** enable the analysis of PNG files by dissecting their data within network packets, revealing embedded information or anomalies.

For checking PNG file integrity and repairing corruption, **pngcheck** is a crucial tool, offering command-line functionality to validate and diagnose PNG files ([pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)). When files are beyond simple fixes, online services like [OfficeRecovery's PixRecovery](https://online.officerecovery.com/pixrecovery/) provide a web-based solution for **repairing corrupted PNGs**, aiding in the recovery of crucial data for CTF participants.

These strategies underscore the importance of a comprehensive approach in CTFs, utilizing a blend of analytical tools and repair techniques to uncover and recover hidden or lost data.

---

## Android steganographic APK loader + dynamic code loading and hidden WebView clicker

Recent large-scale Android ad/click-fraud campaigns have delivered second-stage APK modules steganographically inside PNG images, reconstructed them on-device, and dynamically loaded them to run hidden WebView-based clickers. This subsection generalizes the forensic and detection techniques you can apply.

High-level flow:
- Encrypted remote config (e.g., Firebase Remote Config) returns a URL to a ZIP with multiple PNGs and other parameters.
- App attribution-gates behavior (organic vs non-organic installs) and only proceeds for monetizable installs.
- C2 delivers a ZIP of 3–4 PNGs. Each PNG hides a chunk of an APK via digital steganography.
- The app extracts and joins the chunks into a FatModule APK/DEX, then loads it dynamically (DexClassLoader). The module orchestrates fraud via hidden WebViews that render pages and auto-click viewable ads.
- Strong anti-analysis: debugger/emulator/root checks, encrypted strings, packed native code.

### 1) PNG steganography triage and extraction
Common encodings used in-the-wild:
- Appended payload after IEND (polyglot PNG+ZIP/DEX tail).
- Custom ancillary chunks (non-critical chunk type like abcd) carrying opaque data.
- Classic LSB stego on pixel data (rarer for APKs due to size).

Initial triage:
- pngcheck -v sample.png
- binwalk -eM sample.png
- exiftool sample.png   # list chunks/metadata
- zsteg -a sample.png   # brute stego hunts (LSB, etc.)

Quick extractor for “data after IEND” (typical for multi-part APK-in-PNG):

```python
# extract_trailer_after_IEND.py
import sys
IEND = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"

for path in sys.argv[1:]:
    b = open(path,'rb').read()
    off = b.rfind(IEND)
    if off == -1:
        print(f"[!] IEND not found: {path}")
        continue
    trailer = b[off+len(IEND):]
    if not trailer:
        print(f"[-] No trailer: {path}")
        continue
    # Heuristics: ZIP local header (PK\x03\x04) or DEX magic (dex\n035/037)
    if trailer[:4] in (b'PK\x03\x04',) or trailer[:4] == b'dex\n':
        out = path + '.part'
        open(out,'wb').write(trailer)
        print(f"[+] Wrote {out} ({len(trailer)} bytes)")
    else:
        # sometimes chunk is raw – still dump for manual analysis
        out = path + '.blob'
        open(out,'wb').write(trailer)
        print(f"[?] Wrote opaque {out} ({len(trailer)} bytes)")
```

Usage:

```bash
python3 extract_trailer_after_IEND.py part1.png part2.png part3.png part4.png
# Reassemble in the correct order (based on file naming or config)
cat part1.png.part part2.png.part part3.png.part part4.png.part > FatModule.apk
# Some cases require central directory rebuild (repair truncated ZIP)
zip -FF FatModule.apk --out FatModule_fixed.apk
zipinfo -1 FatModule_fixed.apk | head
```

If the payload is inside a custom ancillary chunk, use exiftool -v or a PNG chunk parser to dump unknown chunk types and concatenate in the order indicated by embedded indexes or filenames. For LSB cases, zsteg will hint the encoding to extract raw bytes that you can later join.

# PNG Tricks



**PNG files** are highly regarded in **CTF challenges** for their **lossless compression**, making them ideal for embedding hidden data. Tools like **Wireshark** enable the analysis of PNG files by dissecting their data within network packets, revealing embedded information or anomalies.

For checking PNG file integrity and repairing corruption, **pngcheck** is a crucial tool, offering command-line functionality to validate and diagnose PNG files ([pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)). When files are beyond simple fixes, online services like [OfficeRecovery's PixRecovery](https://online.officerecovery.com/pixrecovery/) provide a web-based solution for **repairing corrupted PNGs**, aiding in the recovery of crucial data for CTF participants.

These strategies underscore the importance of a comprehensive approach in CTFs, utilizing a blend of analytical tools and repair techniques to uncover and recover hidden or lost data.

---

## Android steganographic APK loader + dynamic code loading and hidden WebView clicker

Recent large-scale Android ad/click-fraud campaigns have delivered second-stage APK modules steganographically inside PNG images, reconstructed them on-device, and dynamically loaded them to run hidden WebView-based clickers. This subsection generalizes the forensic and detection techniques you can apply.

High-level flow:
- Encrypted remote config (e.g., Firebase Remote Config) returns a URL to a ZIP with multiple PNGs and other parameters.
- App attribution-gates behavior (organic vs non-organic installs) and only proceeds for monetizable installs.
- C2 delivers a ZIP of 3–4 PNGs. Each PNG hides a chunk of an APK via digital steganography.
- The app extracts and joins the chunks into a FatModule APK/DEX, then loads it dynamically (DexClassLoader). The module orchestrates fraud via hidden WebViews that render pages and auto-click viewable ads.
- Strong anti-analysis: debugger/emulator/root checks, encrypted strings, packed native code.

### 1) PNG steganography triage and extraction
Common encodings used in-the-wild:
- Appended payload after IEND (polyglot PNG+ZIP/DEX tail).
- Custom ancillary chunks (non-critical chunk type like abcd) carrying opaque data.
- Classic LSB stego on pixel data (rarer for APKs due to size).

Initial triage:
- pngcheck -v sample.png
- binwalk -eM sample.png
- exiftool sample.png   # list chunks/metadata
- zsteg -a sample.png   # brute stego hunts (LSB, etc.)

Quick extractor for “data after IEND” (typical for multi-part APK-in-PNG):

```python
# extract_trailer_after_IEND.py
import sys
IEND = b"\x00\x00\x00\x00IEND\xaeB\x60\x82"

for path in sys.argv[1:]:
    b = open(path,'rb').read()
    off = b.rfind(IEND)
    if off == -1:
        print(f"[!] IEND not found: {path}")
        continue
    trailer = b[off+len(IEND):]
    if not trailer:
        print(f"[-] No trailer: {path}")
        continue
    # Heuristics: ZIP local header (PK\x03\x04) or DEX magic (dex\n035/037)
    if trailer[:4] in (b'PK\x03\x04',) or trailer[:4] == b'dex\n':
        out = path + '.part'
        open(out,'wb').write(trailer)
        print(f"[+] Wrote {out} ({len(trailer)} bytes)")
    else:
        # sometimes chunk is raw – still dump for manual analysis
        out = path + '.blob'
        open(out,'wb').write(trailer)
        print(f"[?] Wrote opaque {out} ({len(trailer)} bytes)")
```

Usage:

```bash
python3 extract_trailer_after_IEND.py part1.png part2.png part3.png part4.png
# Reassemble in the correct order (based on file naming or config)
cat part1.png.part part2.png.part part3.png.part part4.png.part > FatModule.apk
# Some cases require central directory rebuild (repair truncated ZIP)
zip -FF FatModule.apk --out FatModule_fixed.apk
zipinfo -1 FatModule_fixed.apk | head
```

If the payload is inside a custom ancillary chunk, use exiftool -v or a PNG chunk parser to dump unknown chunk types and concatenate in the order indicated by embedded indexes or filenames. For LSB cases, zsteg will hint the encoding to extract raw bytes that you can later join.

Related ZIP header tricks seen in Android droppers:
{{#ref}}
zips-tricks.md
{{#endref}}

### 2) Detecting and hooking dynamic code loading
Malware reconstructs an APK/DEX and loads it at runtime. Hunt for:
- dalvik.system.DexClassLoader, PathClassLoader
- System.load/System.loadLibrary/Runtime.load
- Code that reads PNGs then writes temporary APK/DEX files before loading

Frida snippet to log Dex/native code loads:

```js
Java.perform(() => {
  const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
  const SystemJ = Java.use('java.lang.System');
  const Runtime = Java.use('java.lang.Runtime');

  DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
    console.log(`[DexClassLoader] dex=${dexPath} odex=${optDir} jni=${libPath}`);
    return this.$init(dexPath, optDir, libPath, parent);
  };
  SystemJ.load.overload('java.lang.String').implementation = function(p) {
    console.log('[System.load] ' + p); return this.load(p);
  };
  SystemJ.loadLibrary.overload('java.lang.String').implementation = function(n) {
    console.log('[System.loadLibrary] ' + n); return this.loadLibrary(n);
  };
  Runtime.load.overload('java.lang.String').implementation = function(p){
    console.log('[Runtime.load] ' + p); return this.load(p);
  };
});
```

More background on risks and auditing dynamic loaders:
{{#ref}}
../../../../mobile-pentesting/android-app-pentesting/insecure-in-app-update-rce.md
{{#endref}}

### 3) Hidden WebView telemetry and click automation
Fraud modules launch WebViews without UI (off-screen/zero-size/not attached), collect device/browser telemetry, then render "cashout" pages and trigger viewability-aware auto-clicks.

Hunting hooks (Frida) for WebView usage:

```js
Java.perform(() => {
  const WebView = Java.use('android.webkit.WebView');
  // constructors
  WebView.$init.overload('android.content.Context').implementation = function(ctx){
    console.log('[WebView.<init>](context)');
    return this.$init(ctx);
  };
  WebView.$init.overload('android.content.Context','android.util.AttributeSet').implementation = function(ctx, a){
    console.log('[WebView.<init>](context, attrs)');
    return this.$init(ctx, a);
  };
  // sinks
  WebView.loadUrl.overload('java.lang.String').implementation = function(u){
    console.log('[WebView.loadUrl] ' + u);
    return this.loadUrl(u);
  };
  WebView.loadDataWithBaseURL.implementation = function(b,u,m,e,h){
    console.log('[WebView.loadDataWithBaseURL] base=' + b + ' url=' + u);
    return this.loadDataWithBaseURL(b,u,m,e,h);
  };
  WebView.evaluateJavascript.implementation = function(js, cb){
    console.log('[WebView.evaluateJavascript] ' + js.substring(0,100));
    return this.evaluateJavascript(js, cb);
  };
});
```

Example JS used by clickers to mimic human behavior (only click viewable ad elements):

```js
(function(){
  function clickVisible(el){
    const r = el.getBoundingClientRect();
    const vh = Math.max(document.documentElement.clientHeight, window.innerHeight||0);
    const vw = Math.max(document.documentElement.clientWidth,  window.innerWidth||0);
    if (r.width < 20 || r.height < 20) return false;
    if (r.bottom <= 0 || r.right <= 0 || r.top >= vh || r.left >= vw) return false; // not in viewport
    const x = Math.floor(r.left + r.width/2), y = Math.floor(r.top + r.height/2);
    const ev = new MouseEvent('click', {bubbles:true, cancelable:true, clientX:x, clientY:y});
    el.dispatchEvent(ev); return true;
  }
  const candidates = Array.from(document.querySelectorAll('a, iframe, button, [role=\"button\"], [onclick]'));
  for (const el of candidates){ if (clickVisible(el)) break; }
})();
```

For richer analysis attach a custom WebViewClient in a test harness or hook shouldOverrideUrlLoading/onPageFinished to log redirect chains and parameter churn that “sanitize” referrers.

WebView security background and attack surface:
{{#ref}}
../../../../mobile-pentesting/android-app-pentesting/webview-attacks.md
{{#endref}}

### 4) Anti-analysis gates to expect (and bypass)
- Debugger detection: android.os.Debug.isDebuggerConnected(), tracing /proc
- Emulator heuristics: Build.* contains sdk/generic/ranchu/goldfish; /dev/qemu_pipe; default MAC/id patterns
- Root checks: su binaries, Magisk/Zygisk artifacts, getprop flags
- String encryption, packed JNI libs to delay analysis

Useful bypass references:
{{#ref}}
../../../../mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass.md
{{#endref}}

### 5) DFIR Indicators of Compromise (IoCs) and detections
Network:
- Encrypted Firebase Remote Config fetch followed by C2 returning a ZIP of PNGs.
- Hidden WebView traffic to H5 game/news pages with special parameters and multi-hop redirects before ad requests/clicks.
- Promo/C2 hubs linked across clusters (pivot on shared infra or params).

Host/process:
- Code that reads multiple PNGs, extracts chunks and writes an APK/DEX it then loads via DexClassLoader.
- Hidden WebViews launched without UI; frequent evaluateJavascript() with click/telemetry payloads.
- Emulator/root/debugger checks, encrypted strings; packed native libraries.

Detection ideas:
- Instrument for image-to-binary reconstruction followed by dynamic code loading.
- Alert on WebView activity when the app is backgrounded or no visible UI is present.
- Detect odd redirect parameter churn and viewability-gated click automation patterns (evaluateJavascript bursts).

## References

- [Satori Threat Intelligence Alert: SlopAds Covers Fraud with Layers of Obfuscation](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-slopads-covers-fraud-with-layers-of-obfuscation/)
- [Firebase Remote Config](https://firebase.google.com/docs/remote-config)
- [Android – Dynamic Code Loading risks](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading)
- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)
- [binwalk](https://github.com/ReFirmLabs/binwalk)
- [zsteg](https://github.com/zed-0xff/zsteg)




### 2) Detecting and hooking dynamic code loading
Malware reconstructs an APK/DEX and loads it at runtime. Hunt for:
- dalvik.system.DexClassLoader, PathClassLoader
- System.load/System.loadLibrary/Runtime.load
- Code that reads PNGs then writes temporary APK/DEX files before loading

Frida snippet to log Dex/native code loads:

```js
Java.perform(() => {
  const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
  const SystemJ = Java.use('java.lang.System');
  const Runtime = Java.use('java.lang.Runtime');

  DexClassLoader.$init.implementation = function(dexPath, optDir, libPath, parent) {
    console.log(`[DexClassLoader] dex=${dexPath} odex=${optDir} jni=${libPath}`);
    return this.$init(dexPath, optDir, libPath, parent);
  };
  SystemJ.load.overload('java.lang.String').implementation = function(p) {
    console.log('[System.load] ' + p); return this.load(p);
  };
  SystemJ.loadLibrary.overload('java.lang.String').implementation = function(n) {
    console.log('[System.loadLibrary] ' + n); return this.loadLibrary(n);
  };
  Runtime.load.overload('java.lang.String').implementation = function(p){
    console.log('[Runtime.load] ' + p); return this.load(p);
  };
});
```

More background on risks and auditing dynamic loaders:
{{#ref}}
../../../../mobile-pentesting/android-app-pentesting/insecure-in-app-update-rce.md
{{#endref}}

### 3) Hidden WebView telemetry and click automation
Fraud modules launch WebViews without UI (off-screen/zero-size/not attached), collect device/browser telemetry, then render "cashout" pages and trigger viewability-aware auto-clicks.

Hunting hooks (Frida) for WebView usage:

```js
Java.perform(() => {
  const WebView = Java.use('android.webkit.WebView');
  // constructors
  WebView.$init.overload('android.content.Context').implementation = function(ctx){
    console.log('[WebView.<init>](context)');
    return this.$init(ctx);
  };
  WebView.$init.overload('android.content.Context','android.util.AttributeSet').implementation = function(ctx, a){
    console.log('[WebView.<init>](context, attrs)');
    return this.$init(ctx, a);
  };
  // sinks
  WebView.loadUrl.overload('java.lang.String').implementation = function(u){
    console.log('[WebView.loadUrl] ' + u);
    return this.loadUrl(u);
  };
  WebView.loadDataWithBaseURL.implementation = function(b,u,m,e,h){
    console.log('[WebView.loadDataWithBaseURL] base=' + b + ' url=' + u);
    return this.loadDataWithBaseURL(b,u,m,e,h);
  };
  WebView.evaluateJavascript.implementation = function(js, cb){
    console.log('[WebView.evaluateJavascript] ' + js.substring(0,100));
    return this.evaluateJavascript(js, cb);
  };
});
```

Example JS used by clickers to mimic human behavior (only click viewable ad elements):

```js
(function(){
  function clickVisible(el){
    const r = el.getBoundingClientRect();
    const vh = Math.max(document.documentElement.clientHeight, window.innerHeight||0);
    const vw = Math.max(document.documentElement.clientWidth,  window.innerWidth||0);
    if (r.width < 20 || r.height < 20) return false;
    if (r.bottom <= 0 || r.right <= 0 || r.top >= vh || r.left >= vw) return false; // not in viewport
    const x = Math.floor(r.left + r.width/2), y = Math.floor(r.top + r.height/2);
    const ev = new MouseEvent('click', {bubbles:true, cancelable:true, clientX:x, clientY:y});
    el.dispatchEvent(ev); return true;
  }
  const candidates = Array.from(document.querySelectorAll('a, iframe, button, [role="button"], [onclick]'));
  for (const el of candidates){ if (clickVisible(el)) break; }
})();
```

For richer analysis attach a custom WebViewClient in a test harness or hook shouldOverrideUrlLoading/onPageFinished to log redirect chains and parameter churn that “sanitize” referrers.

WebView security background and attack surface:
{{#ref}}
../../../../mobile-pentesting/android-app-pentesting/webview-attacks.md
{{#endref}}

### 4) Anti-analysis gates to expect (and bypass)
- Debugger detection: android.os.Debug.isDebuggerConnected(), tracing /proc
- Emulator heuristics: Build.* contains sdk/generic/ranchu/goldfish; /dev/qemu_pipe; default MAC/id patterns
- Root checks: su binaries, Magisk/Zygisk artifacts, getprop flags
- String encryption, packed JNI libs to delay analysis

Useful bypass references:
{{#ref}}
../../../../mobile-pentesting/android-app-pentesting/android-anti-instrumentation-and-ssl-pinning-bypass.md
{{#endref}}

### 5) DFIR Indicators of Compromise (IoCs) and detections
Network:
- Encrypted Firebase Remote Config fetch followed by C2 returning a ZIP of PNGs.
- Hidden WebView traffic to H5 game/news pages with special parameters and multi-hop redirects before ad requests/clicks.
- Promo/C2 hubs linked across clusters (pivot on shared infra or params).

Host/process:
- Code that reads multiple PNGs, extracts chunks and writes an APK/DEX it then loads via DexClassLoader.
- Hidden WebViews launched without UI; frequent evaluateJavascript() with click/telemetry payloads.
- Emulator/root/debugger checks, encrypted strings; packed native libraries.

Detection ideas:
- Instrument for image-to-binary reconstruction followed by dynamic code loading.
- Alert on WebView activity when the app is backgrounded or no visible UI is present.
- Detect odd redirect parameter churn and viewability-gated click automation patterns (evaluateJavascript bursts).

## References

- [Satori Threat Intelligence Alert: SlopAds Covers Fraud with Layers of Obfuscation](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-slopads-covers-fraud-with-layers-of-obfuscation/)
- [Firebase Remote Config](https://firebase.google.com/docs/remote-config)
- [Android – Dynamic Code Loading risks](https://developer.android.com/privacy-and-security/risks/dynamic-code-loading)
- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)
- [binwalk](https://github.com/ReFirmLabs/binwalk)
- [zsteg](https://github.com/zed-0xff/zsteg)

{{#include ../../../banners/hacktricks-training.md}}
