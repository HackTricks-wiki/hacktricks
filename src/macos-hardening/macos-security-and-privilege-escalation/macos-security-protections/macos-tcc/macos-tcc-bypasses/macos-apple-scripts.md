# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

It's a scripting language used for task automation **interacting with remote processes**. It makes pretty easy to **ask other processes to perform some actions**. **Malware** may abuse these features to abuse functions exported by other processes.\
For example, a malware could **inject arbitrary JS code in browser opened pages**. Or **auto click** some allow permissions requested to the user;

```applescript
tell window 1 of process "SecurityAgent"
     click button "Always Allow" of group 1
end tell
```

Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Find more info about malware using applescripts [**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple scripts may be easily "**compiled**". These versions can be easily "**decompiled**" with `osadecompile`

However, this scripts can also be **exported as "Read only"** (via the "Export..." option):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>

```
file mal.scpt
mal.scpt: AppleScript compiled
```

and tin this case the content cannot be decompiled even with `osadecompile`

However, there are still some tools that can be used to understand this kind of executables, [**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). The tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) with [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) will be very useful to understand how the script works.

{{#include ../../../../../banners/hacktricks-training.md}}



