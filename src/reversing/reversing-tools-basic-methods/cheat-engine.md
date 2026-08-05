# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中のゲームのメモリ内で重要な値が保存されている場所を見つけ、それを変更するための便利なプログラムです。\
ダウンロードして実行すると、ツールの使用方法に関する **tutorial** が表示されます。ツールの使い方を学びたい場合は、これを完了することを強くおすすめします。<sup>[[3]](#references)</sup>

## 何を検索しますか？

![Cheat Engine - 何を検索しますか？: 何を検索しますか？](<../../images/image (762).png>)

このツールは、プログラムの **メモリ内のどこに値**（通常は数値）**が保存されているか**を見つけるのに非常に便利です。\
**通常、数値**は **4bytes** 形式で保存されますが、**double** や **float** 形式で見つかることもあり、**数値とは異なるもの**を探したい場合もあります。そのため、何を **検索するか**を確実に **選択**する必要があります。

![Cheat Engine - 何を検索しますか？: 通常、数値は4bytes形式で保存されますが、doubleやfloat形式で見つかることもあり、数値とは異なるものを探したい場合もあります...](<../../images/image (324).png>)

また、**検索**の **種類**を **変更**することもできます。

![Cheat Engine - 何を検索しますか？: さまざまな種類の検索を指定することもできます](<../../images/image (311).png>)

メモリのスキャン中に **ゲームを停止する**ためのチェックボックスを選択することもできます。

![Cheat Engine - 何を検索しますか？: メモリのスキャン中にゲームを停止するためのチェックボックスを選択することもできます](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ では、**ゲームを停止する**など、さまざまな目的のために異なる **hotkeys** を設定できます（メモリをスキャンしたい場合などに非常に便利です）。その他のオプションも利用できます。

![何を検索しますか？ - Hotkeys: Edit -- Settings -- Hotkeys では、ゲームを停止するなど、さまざまな目的のために異なるhotkeysを設定できます（特定の時点でメモリをスキャンしたい場合などに非常に便利です）...](<../../images/image (864).png>)

## 値の変更

探している **値**が **保存されている場所を見つけたら**（詳細は次の手順で説明します）、その値をダブルクリックし、さらに値自体をダブルクリックすることで **変更**できます。

![Hotkeys - 値の変更: 探している値が保存されている場所を見つけたら（詳細は次の手順で説明します）、その値をダブルクリックし、さらに値自体をダブルクリックすることで変更できます](<../../images/image (563).png>)

最後にチェックを **有効にする**と、メモリへの変更が実行されます。

![Hotkeys - 値の変更: 最後にチェックを有効にすると、メモリへの変更が実行されます](<../../images/image (385).png>)

**メモリ**への **変更**はすぐに **適用**されます（ゲームが再びこの値を使用するまで、**ゲーム内の値は更新されない**ことに注意してください）。

## 値の検索

ここでは、改善したい重要な値（ユーザーのライフなど）が存在し、その値をメモリ内で探していると仮定します。

### 既知の変化を利用する

値 100 を探していると仮定し、その値を検索する **scan** を実行すると、多数の一致が見つかります。

![値の検索 - 既知の変化を利用する: 値100を探していると仮定し、その値を検索するscanを実行すると、多数の一致が見つかります](<../../images/image (108).png>)

次に、**値が変化する**ような操作を行い、ゲームを **停止**して **next scan** を実行します。

![値の検索 - 既知の変化を利用する: 次に、値が変化するような操作を行い、ゲームを停止してnext scanを実行します](<../../images/image (684).png>)

Cheat Engine は、**100 から新しい値へ変化した値**を検索します。これで、探していた値の **address** が **見つかりました**。これを変更できるようになります。\
_まだ複数の値が残っている場合は、その値をさらに変更する操作を行い、もう一度「next scan」を実行してaddressを絞り込んでください。_

### Unknown Value, known change

**値がわからない**ものの、**どのように変化させられるか**（変化量まで含めて）がわかっている場合は、その数値を探すことができます。

まず、タイプ "**Unknown initial value**" の scan を実行します。

![既知の変化を利用する - Unknown Value, known change: まず、タイプ「Unknown initial value」のscanを実行します](<../../images/image (890).png>)

次に値を変化させ、**値**が **どのように変化したか**を指定します（この例では 1 減少しました）。その後、**next scan** を実行します。

![既知の変化を利用する - Unknown Value, known change: 次に値を変化させ、値がどのように変化したかを指定します（この例では1減少しました）。その後、next scanを実行します](<../../images/image (371).png>)

指定した方法で **変更されたすべての値**が表示されます。

![既知の変化を利用する - Unknown Value, known change: 指定した方法で変更されたすべての値が表示されます](<../../images/image (569).png>)

値を見つけたら、変更できます。

変更方法には **多くの種類**があるため、結果を絞り込むために、これらの **手順を何度でも**実行できます。

![既知の変化を利用する - Unknown Value, known change: 変更方法には多くの種類があるため、結果を絞り込むために、これらの手順を何度でも実行できます](<../../images/image (574).png>)

### Random Memory Address - コードの特定

ここまでで、値を保存している address を見つける方法を学びました。しかし、**ゲームを実行するたびに、そのaddressがメモリ内の異なる場所にある可能性が高い**です。そこで、常にその address を見つけられる方法を確認します。

これまでに説明した手法を使って、現在のゲームが重要な値を保存している address を見つけます。次に（必要であればゲームを停止してから）、見つかった **address**を **right click** し、"**Find out what accesses this address**" または "**Find out what writes to this address**" を選択します。

![Unknown Value, known change - Random Memory Address - コードの特定: これまでに説明した手法を使って、現在のゲームが重要な値を保存しているaddressを見つけます。次に...](<../../images/image (1067).png>)

**最初のオプション**は、この **address**を **使用している** **code**の **部分**を知るのに役立ちます（ゲームの **code**のどこを変更できるかを知るなど、他の目的にも役立ちます）。\
**2 番目のオプション**は、より **具体的**で、この場合は **値がどこから書き込まれているか**を知りたいので、こちらの方が役立ちます。

いずれかのオプションを選択すると、**debugger** がプログラムに **attach**され、新しい **空のウィンドウ**が表示されます。ここで、ゲームを **プレイ**してその **値**を **変更**します（ゲームを再起動してはいけません）。すると、**値を変更しているaddress**で **ウィンドウ**が **埋められる**はずです。

![Unknown Value, known change - Random Memory Address - コードの特定: いずれかのオプションを選択すると、debuggerがプログラムにattachされ、新しい空のウィンドウが表示されます。次に...](<../../images/image (91).png>)

値を変更している address が見つかったので、**code を自由に変更**できます（Cheat Engine では NOPs への変更をすばやく実行できます）。

![Unknown Value, known change - Random Memory Address - コードの特定: 値を変更しているaddressが見つかったので、codeを自由に変更できます（Cheat Engine...](<../../images/image (1057).png>)

これで、code が数値に影響を与えないように変更したり、常に有利な方向に影響するように変更したりできます。

### Random Memory Address - pointer の特定

前の手順に従い、対象の値がある場所を見つけます。次に、"**Find out what writes to this address**" を使って、この値を書き込んでいる address を特定し、それをダブルクリックして disassembly view を表示します。

![Random Memory Address - コードの特定 - Random Memory Address - pointerの特定: 前の手順に従い、対象の値がある場所を見つけます。次に、"Find out...](<../../images/image (1039).png>)

次に、"\[]" の間にある hex value（この場合は $edx の値）を **検索する**新しい scan を実行します。

![Random Memory Address - コードの特定 - Random Memory Address - pointerの特定: 次に、"()"の間にあるhex value（この場合は$edxの値）を検索する新しいscanを実行します](<../../images/image (994).png>)

(_複数表示された場合は、通常、最も小さい address を選択します_)\
これで、**対象の値を変更する pointer が見つかりました**。

"**Add Address Manually**" をクリックします。

![Random Memory Address - コードの特定 - Random Memory Address - pointerの特定: "Add Address Manually"をクリックします](<../../images/image (990).png>)

次に、"Pointer" チェックボックスをクリックし、見つかった address をテキストボックスに追加します（この例では、前の画像で見つかった address は "Tutorial-i386.exe"+2426B0 でした）。

![Random Memory Address - コードの特定 - Random Memory Address - pointerの特定: 次に、"Pointer"チェックボックスをクリックし、見つかったaddressをテキストボックスに追加します（この例では...](<../../images/image (392).png>)

（最初の "Address" に、入力した pointer address から自動的に値が設定されることに注目してください）

OK をクリックすると、新しい pointer が作成されます。

![Random Memory Address - コードの特定 - Random Memory Address - pointerの特定: OKをクリックすると、新しいpointerが作成されます](<../../images/image (308).png>)

これで、その値を変更するたびに、**値が存在するメモリ address が異なっていても、重要な値を変更できます**。

### Code Injection

Code injection は、対象プロセスに code の一部を注入し、その後 code の実行経路を自分で記述した code に向け直す technique です（ポイントを消費する代わりに付与するような処理など）。

たとえば、プレイヤーのライフを 1 減らしている address を見つけたとします。

![Random Memory Address - pointerの特定 - Code Injection: プレイヤーのライフを1減らしているaddressを見つけたとします](<../../images/image (203).png>)

Show disassembler をクリックして **disassemble code** を表示します。\
次に **CTRL+a** をクリックして Auto assemble ウィンドウを開き、_**Template --> Code Injection**_ を選択します。

![Random Memory Address - pointerの特定 - Code Injection: 次にCTRL+aをクリックしてAuto assembleウィンドウを開き、Template -- Code Injectionを選択します](<../../images/image (902).png>)

**変更したい命令の address**を入力します（通常は自動入力されます）。

![Random Memory Address - pointerの特定 - Code Injection: 変更したい命令のaddressを入力します（通常は自動入力されます）](<../../images/image (744).png>)

template が生成されます。

![Random Memory Address - pointerの特定 - Code Injection: templateが生成されます](<../../images/image (944).png>)

"**newmem**" セクションに新しい assembly code を挿入し、元の code を実行したくない場合は "**originalcode**" から削除します**。**この例では、注入した code によって 1 減らす代わりに 2 ポイントが加算されます。

![Random Memory Address - pointerの特定 - Code Injection: "newmem"セクションに新しいassembly codeを挿入し、元のcodeを実行したくない場合は"originalcode"から削除します...](<../../images/image (521).png>)

**execute などをクリックすると、code がプログラムに注入され、機能の動作が変更されます。**

## Cheat Engine 7.x の Advanced features (2023-2025)

Cheat Engine は version 7.0 以降も進化を続けており、modern software（ゲームに限りません！）を分析する際に非常に便利な quality-of-life および *offensive-reversing* features がいくつか追加されています。以下は、red-team/CTF 作業で使用する可能性が最も高い追加機能をまとめた **非常に簡潔な field guide** です。<sup>[[1]](#references)</sup>

### Pointer Scanner 2 improvements
* `Pointers must end with specific offsets` と新しい **Deviation** slider（≥7.4）により、update 後に rescan した際の false positives を大幅に減らせます。multi-map comparison（`.PTR` → *Compare results with other saved pointer map*）と組み合わせることで、数分以内に **単一の resilient base-pointer** を取得できます。
* Bulk-filter shortcut: 最初の scan 後に `Ctrl+A → Space` を押してすべてを mark し、その後 `Ctrl+I`（invert）を押して rescan に失敗した address の選択を解除します。

### Ultimap 3 – Intel PT tracing
*7.5 以降、旧 Ultimap は **Intel Processor-Trace (IPT)** の上に再実装されました。これにより、**single-stepping** なしで target が実行する *すべての branch* を記録できるようになりました（user-mode only であり、ほとんどの anti-debug gadget は作動しません）。
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
数秒後にキャプチャを停止し、**右クリック → Save execution list to file** を選択します。branch address と `Find out what addresses this instruction accesses` セッションを組み合わせることで、高頻度で実行されるゲームロジックのホットスポットを非常に高速に特定できます。

### 1-byte `jmp` / auto-patch templates
Version 7.5 では、SEH handler をインストールし、元の位置に INT3 を配置する *one-byte* JMP stub（0xEB）が導入されました。これは、5-byte の relative jump で patch できない命令に対して **Auto Assembler → Template → Code Injection** を使用すると自動的に生成されます。これにより、packed またはサイズに制約のある routine 内でも “tight” hook が可能になります。

### Kernel-level stealth with DBVM (AMD & Intel)
*DBVM* は CE に組み込まれた Type-2 hypervisor です。最近の build では **AMD-V/SVM support** が追加され、Ryzen/EPYC host 上で `Driver → Load DBVM` を実行できるようになりました。DBVM を使用すると、次の操作が可能です。

1. Ring-3/anti-debug check から見えない hardware breakpoint を作成する。
2. user-mode driver が無効化されている場合でも、pageable または protected な kernel memory region を読み書きする。
3. VM-EXIT-less timing-attack bypass を実行する（例：hypervisor から `rdtsc` を query する）。

**Tip:** Windows 11 で HVCI/Memory-Integrity が有効になっている場合、DBVM は load を拒否します → 無効化するか、専用の VM-host を boot してください。

### Remote / cross-platform debugging with **ceserver**
CE には現在、*ceserver* の全面的な rewrite が同梱されており、TCP 経由で **Linux、Android、macOS、iOS** の target に attach できます。人気の fork では *Frida* が統合され、dynamic instrumentation と CE の GUI を組み合わせられます。phone 上で実行されている Unity または Unreal game を patch する必要がある場合に最適です。
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Frida bridge については、GitHub の `bb33bb/frida-ceserver` を参照してください。<sup>[[2]](#references)</sup>

### その他の注目すべき機能
* **Patch Scanner**（MemView → Tools）– 実行可能セクション内の予期しないコード変更を検出します。マルウェア解析に便利です。
* **Structure Dissector 2** – アドレスをドラッグして `Ctrl+D` を押し、*Guess fields* を選択すると、C 構造体を自動的に推測・評価できます。
* **.NET & Mono Dissector** – Unity ゲームのサポートが改善され、CE Lua コンソールからメソッドを直接呼び出せます。
* **Big-Endian custom types** – バイト順を反転してスキャン・編集できます（コンソールエミュレーターやネットワークパケットバッファーに便利です）。
* AutoAssembler/Lua ウィンドウの **Autosave & tabs** に加え、複数行の命令を書き換えるための `reassemble()`。

### Installation & OPSEC に関する注意事項（2024-2025）
* 公式インストーラーには InnoSetup の **広告オファー**（`RAV` など）が含まれています。PUPs を避けるため、**必ず *Decline* をクリックする**か、ソースからコンパイルしてください。AV は引き続き `cheatengine.exe` を *HackTool* として検出しますが、これは想定された動作です。
* 最新の anti-cheat ドライバー（EAC/Battleye、ACE-BASE.sys、mhyprot2.sys）は、名前を変更しても CE のウィンドウクラスを検出します。reversing 用のコピーは **使い捨て VM 内**、またはネットワークプレイを無効にした後で実行してください。
* user-mode access だけが必要な場合は、CE の unsigned driver の読み込みを避けるため、**`Settings → Extra → Kernel mode debug = off`** を選択してください。このドライバーは、Windows 11 24H2 の Secure-Boot 環境で BSOD を引き起こす可能性があります。

---

## References

- [1] [Cheat Engine 7.5 のリリースノート（GitHub）](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [frida-ceserver クロスプラットフォーム bridge](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)
- [3] Cheat Engine チュートリアル。Cheat Engine の始め方を学ぶために最後まで完了してください。

{{#include ../../banners/hacktricks-training.md}}
