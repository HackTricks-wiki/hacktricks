# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Ni lugha ya skripti inayotumika kwa ajili ya automatisering ya kazi **kuhusiana na michakato ya mbali**. Inafanya iwe rahisi **kuomba michakato mingine kutekeleza vitendo vingine**. **Malware** inaweza kutumia vipengele hivi kuharibu kazi zinazotolewa na michakato mingine.\
Kwa mfano, malware inaweza **kuingiza msimbo wa JS wa kiholela katika kurasa zilizofunguliwa na kivinjari**. Au **kubonyeza kiotomatiki** baadhi ya ruhusa zinazohitajika kwa mtumiaji;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Hapa kuna mifano: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Pata maelezo zaidi kuhusu malware ukitumia applescripts [**hapa**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Apple scripts zinaweza "kuandikwa" kwa urahisi. Matoleo haya yanaweza "kufutwa" kwa urahisi kwa kutumia `osadecompile`

Hata hivyo, scripts hizi zinaweza pia **kuzuiliwa kama "Soma tu"** (kupitia chaguo la "Export..."): 

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
na katika kesi hii maudhui hayawezi kufanywa decompile hata na `osadecompile`

Hata hivyo, bado kuna zana ambazo zinaweza kutumika kuelewa aina hii ya executable, [**soma utafiti huu kwa maelezo zaidi**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). Zana [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) pamoja na [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) itakuwa muhimu sana kuelewa jinsi script inavyofanya kazi.

{{#include ../../../../../banners/hacktricks-training.md}}
