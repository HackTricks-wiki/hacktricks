# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Bu, **uzaktan süreçlerle etkileşimde bulunan** görev otomasyonu için kullanılan bir betik dilidir. **Diğer süreçlerden bazı eylemleri gerçekleştirmelerini istemek** oldukça kolay hale getirir. **Kötü amaçlı yazılımlar**, diğer süreçler tarafından dışa aktarılan işlevleri kötüye kullanmak için bu özellikleri istismar edebilir.\
Örneğin, bir kötü amaçlı yazılım **tarayıcıda açılan sayfalara rastgele JS kodu enjekte edebilir**. Veya **kullanıcıdan istenen bazı izinleri otomatik olarak tıklayabilir**;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Burada bazı örnekler var: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Kötü amaçlı yazılımlar hakkında daha fazla bilgi için applescripts kullanarak [**buradan**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) ulaşabilirsiniz.

Apple scriptleri kolayca "**derlenebilir**". Bu versiyonlar kolayca "**açıklanabilir**" `osadecompile` ile

Ancak, bu scriptler **"Sadece okunur" olarak dışa aktarılabilir** ( "Dışa Aktar..." seçeneği aracılığıyla): 

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
ve bu durumda içerik `osadecompile` ile bile decompile edilemez

Ancak, bu tür yürütülebilir dosyaları anlamak için kullanılabilecek bazı araçlar hala mevcuttur, [**daha fazla bilgi için bu araştırmayı okuyun**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) aracı ve [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) scriptin nasıl çalıştığını anlamak için çok faydalı olacaktır.

{{#include ../../../../../banners/hacktricks-training.md}}
