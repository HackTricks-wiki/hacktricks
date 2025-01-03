{{#include ../../banners/hacktricks-training.md}}

# Mwongozo wa Decompilation ya Wasm na Uundaji wa Wat

Katika ulimwengu wa **WebAssembly**, zana za **decompiling** na **compiling** ni muhimu kwa waendelezaji. Mwongo huu unawasilisha baadhi ya rasilimali za mtandaoni na programu za kushughulikia **Wasm (WebAssembly binary)** na **Wat (WebAssembly text)**.

## Zana za Mtandaoni

- Ili **decompile** Wasm hadi Wat, zana inayopatikana kwenye [Wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) inasaidia.
- Kwa **compiling** Wat kurudi kwa Wasm, [Wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) inatumika.
- Chaguo kingine cha decompilation kinaweza kupatikana kwenye [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Suluhisho za Programu

- Kwa suluhisho thabiti zaidi, [JEB by PNF Software](https://www.pnfsoftware.com/jeb/demo) inatoa vipengele vingi.
- Mradi wa chanzo wazi [wasmdec](https://github.com/wwwg/wasmdec) pia unapatikana kwa kazi za decompilation.

# Rasilimali za Decompilation ya .Net

Decompiling assemblies za .Net inaweza kufanywa kwa zana kama:

- [ILSpy](https://github.com/icsharpcode/ILSpy), ambayo pia inatoa [plugin kwa Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), ikiruhusu matumizi ya cross-platform.
- Kwa kazi zinazohusisha **decompilation**, **modification**, na **recompilation**, [dnSpy](https://github.com/0xd4d/dnSpy/releases) inapendekezwa sana. **Kulia-bofya** njia na kuchagua **Modify Method** inaruhusu mabadiliko ya msimbo.
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) ni chaguo jingine kwa decompiling assemblies za .Net.

## Kuimarisha Debugging na Logging na DNSpy

### Logging ya DNSpy

Ili kuandika taarifa kwenye faili kwa kutumia DNSpy, jumuisha kipande hiki cha msimbo wa .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### Debugging ya DNSpy

Kwa debugging bora na DNSpy, mfululizo wa hatua unashauriwa kubadilisha **Assembly attributes** kwa ajili ya debugging, kuhakikisha kuwa optimizations ambazo zinaweza kuzuia debugging zimezimwa. Mchakato huu unajumuisha kubadilisha mipangilio ya `DebuggableAttribute`, recompiling assembly, na kuokoa mabadiliko.

Zaidi ya hayo, ili debug programu ya .Net inayotumiwa na **IIS**, kutekeleza `iisreset /noforce` kunaanzisha upya IIS. Ili kuunganisha DNSpy kwenye mchakato wa IIS kwa ajili ya debugging, mwongo huu unashauri kuchagua mchakato wa **w3wp.exe** ndani ya DNSpy na kuanza kikao cha debugging.

Kwa mtazamo wa kina wa moduli zilizoloadiwa wakati wa debugging, kufikia dirisha la **Modules** ndani ya DNSpy kunashauriwa, kisha kufungua moduli zote na kupanga assemblies kwa urahisi wa urambazaji na debugging.

Mwongo huu unajumuisha kiini cha WebAssembly na decompilation ya .Net, ukitoa njia kwa waendelezaji kuhamasika katika kazi hizi kwa urahisi.

## **Java Decompiler**

Ili decompile bytecode ya Java, zana hizi zinaweza kuwa na msaada mkubwa:

- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Debugging DLLs**

### Kutumia IDA

- **Rundll32** inaloadiwa kutoka njia maalum za toleo la 64-bit na 32-bit.
- **Windbg** inachaguliwa kama debugger na chaguo la kusimamisha wakati wa kupakia/kutoa maktaba limewezeshwa.
- Mipangilio ya utekelezaji inajumuisha njia ya DLL na jina la kazi. Mpangilio huu unasimamisha utekelezaji wakati wa kupakia kila DLL.

### Kutumia x64dbg/x32dbg

- Kama IDA, **rundll32** inaloadiwa na marekebisho ya mistari ya amri ili kubainisha DLL na kazi.
- Mipangilio inarekebishwa ili kuvunja kwenye kuingia kwa DLL, ikiruhusu kuweka breakpoint kwenye kiingilio kinachotakiwa cha DLL.

### Picha

- Mahali pa kusimamisha utekelezaji na mipangilio yanaonyeshwa kupitia picha za skrini.

## **ARM & MIPS**

- Kwa emulation, [arm_now](https://github.com/nongiach/arm_now) ni rasilimali muhimu.

## **Shellcodes**

### Mbinu za Debugging

- **Blobrunner** na **jmp2it** ni zana za kugawa shellcodes katika kumbukumbu na kuzi-debug na Ida au x64dbg.
- Blobrunner [releases](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [compiled version](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** inatoa emulation na ukaguzi wa shellcode kwa kutumia GUI, ikionyesha tofauti katika kushughulikia shellcode kama faili dhidi ya shellcode ya moja kwa moja.

### Deobfuscation na Uchambuzi

- **scdbg** inatoa maarifa kuhusu kazi za shellcode na uwezo wa deobfuscation.
%%%bash
scdbg.exe -f shellcode # Taarifa za msingi
scdbg.exe -f shellcode -r # Ripoti ya uchambuzi
scdbg.exe -f shellcode -i -r # Hooks za mwingiliano
scdbg.exe -f shellcode -d # Dump shellcode iliyotafsiriwa
scdbg.exe -f shellcode /findsc # Pata ofset ya kuanzia
scdbg.exe -f shellcode /foff 0x0000004D # Tekeleza kutoka ofset
%%%

- **CyberChef** kwa ajili ya kuondoa shellcode: [CyberChef recipe](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**

- Obfuscator inayobadilisha maagizo yote kuwa `mov`.
- Rasilimali muhimu ni pamoja na [YouTube explanation](https://www.youtube.com/watch?v=2VF_wPkiBJY) na [PDF slides](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** inaweza kubadilisha obfuscation ya movfuscator, ikihitaji utegemezi kama `libcapstone-dev` na `libz3-dev`, na kufunga [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**

- Kwa binaries za Delphi, [IDR](https://github.com/crypto2011/IDR) inapendekezwa.

# Kozi

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Binary deobfuscation\)

{{#include ../../banners/hacktricks-training.md}}
