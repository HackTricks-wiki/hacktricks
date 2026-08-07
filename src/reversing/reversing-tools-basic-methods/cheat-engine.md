# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内に重要な値が保存されている場所を見つけ、変更するための便利なプログラムです。\
ダウンロードして実行すると、ツールの使い方に関する **tutorial** が表示されます。ツールの使い方を学びたい場合は、tutorial を完了することを強くおすすめします。

## 何を検索していますか？

![Cheat Engine - 何を検索していますか？: 何を検索していますか？](<../../images/image (762).png>)

このツールは、プログラムの **メモリ内のどこにある値**（通常は数値）が **保存されているか**を見つけるのに非常に便利です。\
**通常、数値**は **4bytes** 形式で保存されますが、**double** や **float** 形式で見つかる場合もあります。また、**数値以外のもの**を探したいこともあるでしょう。そのため、何を **検索するか**を必ず **選択**する必要があります。

![Cheat Engine - 何を検索していますか？: 通常、数値は4bytes形式で保存されますが、doubleやfloat形式で見つかる場合もあり、数値以外のものを探したい場合もあります。](<../../images/image (324).png>)

また、**検索**の **種類**を **変更**することもできます。

![Cheat Engine - 何を検索していますか？: 検索の種類を変更することもできます](<../../images/image (311).png>)

メモリをスキャンしている間、**ゲームを停止する**ためのチェックボックスを有効にすることもできます。

![Cheat Engine - 何を検索していますか？: メモリをスキャンしている間、ゲームを停止することもできます](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ では、**ゲームを停止する**など、さまざまな目的のために異なる **hotkeys** を設定できます（メモリをスキャンしたいときに非常に便利です）。その他のオプションも利用できます。

![何を検索していますか？ - Hotkeys: Edit -- Settings -- Hotkeys では、ゲームを停止するなど、さまざまな目的のために異なる hotkeys を設定できます（メモリをスキャンしたいときに非常に便利です）。](<../../images/image (864).png>)

## 値の変更

探している **値**が保存されている場所を **見つけた**ら（詳細は次の手順で説明します）、その値をダブルクリックし、さらに値自体をダブルクリックすることで **変更**できます。

![Hotkeys - 値の変更: 探している値が保存されている場所を見つけたら（詳細は次の手順で説明します）、その値をダブルクリックし、さらに値自体をダブルクリックすることで変更できます](<../../images/image (563).png>)

最後に、チェックを **有効化**してメモリに変更を適用します。

![Hotkeys - 値の変更: 最後にチェックを有効化してメモリに変更を適用します](<../../images/image (385).png>)

**メモリ**への **変更**はすぐに **適用**されます（ゲームが再びこの値を使用するまで、ゲーム内の値は **更新されない**ことに注意してください）。

## 値の検索

ここでは、改善したい重要な値（ユーザーの体力など）があり、その値をメモリ内から探していると仮定します。

### 既知の変更による検索

値 100 を探していると仮定し、その値を検索する **scan**を実行すると、多数の一致が見つかります。

![値の検索 - 既知の変更による検索: 値100を探していると仮定し、その値を検索するscanを実行すると、多数の一致が見つかります](<../../images/image (108).png>)

次に、**値が変化する**ような操作を行い、ゲームを **停止**して **next scan**を実行します。

![値の検索 - 既知の変更による検索: 次に、値が変化するような操作を行い、ゲームを停止してnext scanを実行します](<../../images/image (684).png>)

Cheat Engine は、**100 から新しい値に変化した値**を検索します。これで、探していた値の **address**が **見つかりました**。これを変更できます。\
_まだ複数の値が残っている場合は、その値をもう一度変更し、別の「next scan」を実行してaddressを絞り込んでください。_

### Unknown Value、既知の変更

**値がわからない**ものの、**どのように変更させるか**（さらに変更量も）わかっている場合は、その数値を検索できます。

まず、タイプ "**Unknown initial value**" の scan を実行します。

![既知の変更による検索 - Unknown Value、既知の変更: まず、タイプ「Unknown initial value」のscanを実行します](<../../images/image (890).png>)

次に値を変更し、**値**が **どのように変化したか**を指定します（この例では 1 減少しました）。その後、**next scan**を実行します。

![既知の変更による検索 - Unknown Value、既知の変更: 次に値を変更し、値がどのように変化したかを指定します（この例では1減少しました）。その後next scanを実行します](<../../images/image (371).png>)

指定した方法で変更されたすべての値が表示されます。

![既知の変更による検索 - Unknown Value、既知の変更: 指定した方法で変更されたすべての値が表示されます](<../../images/image (569).png>)

値を見つけたら、変更できます。

**変更の種類**には多数の候補があるため、結果を絞り込むためにこれらの **手順**を何度でも実行できます。

![既知の変更による検索 - Unknown Value、既知の変更: 変更の種類には多数の候補があるため、結果を絞り込むためにこれらの手順を何度でも実行できます](<../../images/image (574).png>)

### Random Memory Address - Finding the code

これまで、値を保存している address を見つける方法を学びました。しかし、**ゲームを実行するたびに、そのaddressがメモリ内の異なる場所に存在する可能性が高い**です。そこで、常にそのaddressを見つけられる方法を確認します。

前述のテクニックを使い、現在のゲームが重要な値を保存している address を見つけます。次に（必要であればゲームを停止してから）、見つかった **address**を **right click**し、"**Find out what accesses this address**" または "**Find out what writes to this address**" を選択します。

![Unknown Value、既知の変更 - Random Memory Address - Finding the code: 前述のテクニックを使い、現在のゲームが重要な値を保存しているaddressを見つけます。次に...](<../../images/image (1067).png>)

**最初のオプション**は、どの **code**の **部分**がこの **address**を **使用しているか**を確認するのに役立ちます（ゲームの **code**をどこで変更できるかを知るなど、他の目的にも役立ちます）。\
**2 番目のオプション**はより **具体的**で、このケースでは値が **どこから書き込まれているか**を知りたいので、より役立ちます。

いずれかのオプションを選択すると、**debugger**がプログラムに **attach**され、新しい **empty window**が表示されます。次に **ゲームをプレイ**し、その **値**を **変更**します（ゲームを再起動しないでください）。**window**には、**値**を **変更しているaddress**が表示されます。

![Unknown Value、既知の変更 - Random Memory Address - Finding the code: いずれかのオプションを選択すると、debuggerがプログラムにattachされ、新しいempty windowが表示されます。次に...](<../../images/image (91).png>)

値を変更している address が見つかったので、これで **codeを自由に変更**できます（Cheat Engine では、非常に簡単に NOPs に変更できます）。

![Unknown Value、既知の変更 - Random Memory Address - Finding the code: 値を変更しているaddressが見つかったので、これでcodeを自由に変更できます（Cheat Engineでは、非常に簡単にNOPsに変更できます）。](<../../images/image (1057).png>)

これで、数値に影響を与えないように変更したり、常に有利な方向に作用するように変更したりできます。

### Random Memory Address - Finding the pointer

前の手順に従い、関心のある値が保存されている場所を見つけます。次に "**Find out what writes to this address**" を使って、この値を書き込んでいる address を確認し、それをダブルクリックして disassembly view を表示します。

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: 前の手順に従い、関心のある値が保存されている場所を見つけます。次に「Find out...」を使います](<../../images/image (1039).png>)

次に、**"\[]" の間にある hex value**（この場合は $edx の値）を **検索する新しい scan**を実行します。

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: 次に、「 ()」の間にあるhex value（この場合は$edxの値）を検索する新しいscanを実行します](<../../images/image (994).png>)

(_複数表示された場合は、通常、最も小さい address を選択します_)\
これで、**関心のある値を変更する pointer が見つかりました**。

"**Add Address Manually**" をクリックします。

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: 「Add Address Manually」をクリックします](<../../images/image (990).png>)

次に "Pointer" チェックボックスをクリックし、見つかった address をテキストボックスに追加します（この例では、前の画像で見つかった address は "Tutorial-i386.exe"+2426B0 でした）。

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: 次に「Pointer」チェックボックスをクリックし、見つかったaddressをテキストボックスに追加します（この例では...](<../../images/image (392).png>)

（入力した pointer address から、最初の "Address" が自動的に入力されることに注目してください）

OK をクリックすると、新しい pointer が作成されます。

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: OKをクリックすると、新しいpointerが作成されます](<../../images/image (308).png>)

これで、その値が保存されている **memory address**が異なっていても、値を変更するたびに重要な値を **変更**できます。

### Code Injection

Code injection は、target process に code の一部を inject し、その後 code の実行経路を自分で記述した code に reroute する technique です（ポイントを減らす代わりに増やす、といった処理）。

たとえば、プレイヤーの life を 1 減らしている address を見つけたとします。

![Random Memory Address - Finding the pointer - Code Injection: プレイヤーのlifeを1減らしているaddressを見つけたとします](<../../images/image (203).png>)

Show disassembler をクリックして **disassemble code**を表示します。\
次に **CTRL+a** をクリックして Auto assemble window を開き、_**Template --> Code Injection**_ を選択します。

![Random Memory Address - Finding the pointer - Code Injection: 次にCTRL+aをクリックしてAuto assemble windowを開き、Template -- Code Injectionを選択します](<../../images/image (902).png>)

**変更したい instruction の address**を入力します（通常は自動入力されます）。

![Random Memory Address - Finding the pointer - Code Injection: 変更したいinstructionのaddressを入力します（通常は自動入力されます）](<../../images/image (744).png>)

template が生成されます。

![Random Memory Address - Finding the pointer - Code Injection: templateが生成されます](<../../images/image (944).png>)

"**newmem**" セクションに新しい assembly code を挿入し、実行したくない場合は "**originalcode**" から元の code を削除します**。** この例では、inject された code により 1 減らす代わりに 2 ポイント増加します。

![Random Memory Address - Finding the pointer - Code Injection: 「newmem」セクションに新しいassembly codeを挿入し、実行したくない場合は「originalcode」から元のcodeを削除します](<../../images/image (521).png>)

**execute などをクリックすれば、code が program に inject され、機能の behaviour が変わります！**

## Cheat Engine 7.x (2023-2025) の Advanced features

Cheat Engine は version 7.0 以降も進化を続けており、modern software（ゲームだけではありません！）を分析する際に非常に便利な、quality-of-life 機能や *offensive-reversing* 機能がいくつも追加されています。以下は、red-team/CTF 作業で最もよく使用する追加機能をまとめた **非常に簡潔な field guide** です。<sup>[[1]](#references)</sup>

### Pointer Scanner 2 の improvements
* `Pointers must end with specific offsets` と新しい **Deviation** slider（≥7.4）により、update 後に rescan する際の false positives を大幅に減らせます。multi-map comparison（`.PTR` → *Compare results with other saved pointer map*）と組み合わせて、わずか数分で **単一の resilient base-pointer** を取得できます。
* Bulk-filter shortcut：最初の scan 後に `Ctrl+A → Space` を押してすべてを mark し、その後 `Ctrl+I`（invert）を押すと、rescan に失敗した address の選択を解除できます。

### Ultimap 3 – Intel PT tracing
*7.5 以降、旧 Ultimap は **Intel Processor-Trace (IPT)** を基盤として再実装されています*。これにより、**single-stepping**なしで target が実行する *すべての branch* を記録できるようになりました（user-mode only であり、ほとんどの anti-debug gadget を発動させません）。
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
数秒後にキャプチャを停止し、**right-click → Save execution list to file** を選択します。ブランチアドレスと `Find out what addresses this instruction accesses` セッションを組み合わせると、高頻度で実行されるゲームロジックのホットスポットを非常に高速に特定できます。

### 1-byte `jmp` / auto-patch templates
Version 7.5では、SEH handlerをインストールし、元の場所にINT3を配置する *one-byte* JMP stub（0xEB）が導入されました。これは、5-byte relative jumpでpatchできない命令に対して **Auto Assembler → Template → Code Injection** を使用すると自動的に生成されます。これにより、packedまたはサイズ制約のあるroutine内でも「tight」なhookが可能になります。<sup>[[1]](#references)</sup>

### Kernel-level stealth with DBVM (AMD & Intel)
*DBVM* はCE内蔵のType-2 hypervisorです。最近のbuildではついに **AMD-V/SVM support** が追加され、Ryzen/EPYC hosts上で `Driver → Load DBVM` を実行できるようになりました。DBVMを使用すると、次の操作が可能です。
1. Ring-3/anti-debug checksから見えないhardware breakpointsを作成する。
2. user-mode driverが無効でも、pageableまたはprotectedなkernel memory regionsを読み書きする。
3. VM-EXIT-less timing-attack bypassesを実行する（例：hypervisorから `rdtsc` をqueryする）。

**Tip:** Windows 11でHVCI/Memory-Integrityが有効になっている場合、DBVMはloadを拒否します → 無効にするか、専用のVM-hostをbootしてください。

### Remote / cross-platform debugging with **ceserver**
CEには現在、*ceserver* の完全なrewriteが同梱されており、TCP経由で **Linux, Android, macOS & iOS** targetsにattachできます。人気のあるforkでは *Frida* が統合され、dynamic instrumentationとCEのGUIを組み合わせられます。phone上で実行されているUnityまたはUnreal gamesをpatchする必要がある場合に最適です：
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida bridgeについては、GitHubの`bb33bb/frida-ceserver`を参照してください。<sup>[[1]](#references)[[2]](#references)</sup>

### その他の注目すべき機能
* **Patch Scanner**（MemView → Tools）– executable sections内の予期しないコード変更を検出します。malware analysisに便利です。
* **Structure Dissector 2** – アドレスをドラッグして`Ctrl+D`を押し、*Guess fields*を選択すると、C-structuresを自動評価できます。
* **.NET & Mono Dissector** – Unity gameのサポートが改善され、CE Lua consoleから直接メソッドを呼び出せます。
* **Big-Endian custom types** – byte orderを反転してscan/editできます（console emulatorsやnetwork packet buffersに便利です）。
* AutoAssembler/Lua windowsの**Autosave & tabs**に加え、複数行のinstruction rewrite用の`reassemble()`も利用できます。<sup>[[1]](#references)</sup>

### InstallationとOPSECに関する注意事項（2024-2025）
* 公式installerにはInnoSetupの**ad-offers**（`RAV`など）が含まれています。PUPsを避けるには、**必ず*Decline*をクリックする**か、sourceからcompileしてください。AVsは`cheatengine.exe`を*HackTool*として検出しますが、これは想定内です。
* Modern anti-cheat drivers（EAC/Battleye、ACE-BASE.sys、mhyprot2.sys）は、名前を変更してもCEのwindow classを検出します。reversing用のcopyは**使い捨てのVM内**で実行するか、network playを無効にしてから実行してください。
* user-mode accessだけが必要な場合は、Windows 11 24H2 Secure-BootでBSODを引き起こす可能性があるCEのunsigned driverのloadingを避けるため、**`Settings → Extra → Kernel mode debug = off`**を選択してください。

---

## References

- [1] [Cheat Engine 7.5 release notes (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver cross-platform bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
