# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) は、実行中の game の memory 内で重要な値が保存されている場所を見つけ、変更するための便利な program です。\
ダウンロードして実行すると、tool の使い方を説明する **tutorial** が表示されます。tool の使い方を学びたい場合は、tutorial を完了することを強く推奨します。

## 何を検索しますか？

![Cheat Engine - 何を検索しますか？: 何を検索しますか？](<../../images/image (762).png>)

この tool は、program の **memory 内のどこに値**（通常は number）が**保存されているか**を見つけるのに非常に便利です。\
**通常、number** は **4bytes** 形式で保存されますが、**double** や **float** 形式で見つかる場合もあります。また、**number 以外のもの**を探したい場合もあるでしょう。そのため、何を**検索するか**を確実に**選択**する必要があります。

![Cheat Engine - 何を検索しますか？: 通常、number は 4bytes 形式で保存されますが、double や float 形式で見つかる場合もあります。また、別のものを探したい場合もあります...](<../../images/image (324).png>)

また、**search** の種類を**変更**することもできます。

![Cheat Engine - 何を検索しますか？: また、異なる種類の search を指定できます](<../../images/image (311).png>)

memory を scan している間、**game を停止する**ための box に check を入れることもできます。

![Cheat Engine - 何を検索しますか？: memory を scan している間、game を停止するための box に check を入れることもできます](<../../images/image (1052).png>)

### Hotkeys

_**Edit --> Settings --> Hotkeys**_ では、**game の停止**など、さまざまな目的に異なる **hotkeys** を設定できます（memory を scan したい場合などに非常に便利です）。その他の options も利用できます。

![何を検索しますか？ - Hotkeys: Edit -- Settings -- Hotkeys では、game の停止など、さまざまな目的に異なる hotkeys を設定できます（memory を scan したい場合などに非常に便利です）](<../../images/image (864).png>)

## 値の変更

探している**値**が保存されている場所を**見つけた**ら（詳細は以下の steps で説明します）、その値を double click し、続けて値自体を double click することで**変更**できます。

![Hotkeys - 値の変更: 探している値が保存されている場所を見つけたら（詳細は以下の steps で説明します）、その値を double click し、続けて値自体を double click することで変更できます](<../../images/image (563).png>)

最後に **check** を付けると、memory に変更が適用されます。

![Hotkeys - 値の変更: 最後に check を付けると、memory に変更が適用されます](<../../images/image (385).png>)

memory への**変更**は直ちに**適用**されます（ただし、game が再びこの値を使用するまで、game 内の値は**更新されない**ことに注意してください）。

## 値の検索

ここでは、改善したい重要な値（user の life など）があり、その値を memory 内から探していると仮定します。

### 既知の変化による検索

値 100 を探していると仮定します。その値を検索するために **scan** を実行すると、多くの一致が見つかります。

![値の検索 - 既知の変化による検索: 値 100 を探していると仮定し、その値を検索するために scan を実行すると、多くの一致が見つかります](<../../images/image (108).png>)

次に、**値が変化する**ような操作を行い、game を**停止**して**次の scan**を実行します。

![値の検索 - 既知の変化による検索: 次に、値が変化するような操作を行い、game を停止して次の scan を実行します](<../../images/image (684).png>)

Cheat Engine は、**100 から新しい値へ変化した値**を検索します。これで、探していた値の**address**を**見つける**ことができました。これを変更できるようになります。\
_まだ複数の値が残っている場合は、その値を再度変更し、別の "next scan" を実行して address を絞り込みます。_

### 不明な値、既知の変化

**値自体は分からない**ものの、**どのように変化させられるか**（変化量も含めて）分かっている場合は、その number を探すことができます。

まず、"**Unknown initial value**" タイプの scan を実行します。

![既知の変化による検索 - 不明な値、既知の変化: まず、" Unknown initial value " タイプの scan を実行します](<../../images/image (890).png>)

次に、値を変化させ、**値がどのように変化したか**を指定します（この例では 1 減少しました）。その後、**next scan** を実行します。

![既知の変化による検索 - 不明な値、既知の変化: 次に値を変化させ、値がどのように変化したかを指定します（この例では 1 減少しました）。その後、next scan を実行します](<../../images/image (371).png>)

選択した方法で変更された**すべての値**が表示されます。

![既知の変化による検索 - 不明な値、既知の変化: 選択した方法で変更されたすべての値が表示されます](<../../images/image (569).png>)

値を見つけたら、変更できます。

変更方法には**多くの種類**があるため、結果を絞り込むためにこれらの**手順を何度でも**実行できます。

![既知の変化による検索 - 不明な値、既知の変化: 変更方法には多くの種類があるため、結果を絞り込むためにこれらの手順を何度でも実行できます](<../../images/image (574).png>)

### ランダムな Memory Address - code の検索

ここまでで、値を保存している address の見つけ方を学びました。しかし、**game を実行するたびに、その address が memory 上の異なる場所にある可能性が高い**です。そこで、常にその address を見つけられる方法を確認しましょう。

前述した tricks を使い、現在の game が重要な値を保存している address を見つけます。次に（必要であれば game を停止してから）、見つかった **address** を **right click** し、"**Find out what accesses this address**" または "**Find out what writes to this address**" を選択します。

![不明な値、既知の変化 - ランダムな Memory Address - code の検索: 前述した tricks を使い、現在の game が重要な値を保存している address を見つけます。次に...](<../../images/image (1067).png>)

**最初の option** は、どの **code の部分**がこの **address**を**使用しているか**を確認するのに役立ちます（game の **code を変更できる場所**を知るなど、他の用途にも便利です）。\
**2 番目の option** はより**具体的**で、この場合は値が**どこから書き込まれているか**を知りたいので、こちらの方が役立ちます。

いずれかの option を選択すると、**debugger** が program に**attach**され、新しい**空の window**が表示されます。ここで **game をプレイ**し、その**値を変更**します（game は restart しないでください）。すると、**値を変更している address** で **window** が埋められます。

![不明な値、既知の変化 - ランダムな Memory Address - code の検索: いずれかの option を選択すると、debugger が program に attach され、新しい空の window が表示されます。次に...](<../../images/image (91).png>)

値を変更している address が見つかったので、これで**自由に code を変更**できます（Cheat Engine を使えば、NOPs への変更もすぐに行えます）。

![不明な値、既知の変化 - ランダムな Memory Address - code の検索: 値を変更している address が見つかったので、これで自由に code を変更できます（Cheat Engine...](<../../images/image (1057).png>)

これで、code が number に影響を与えないように変更したり、常に有利な方向に影響するように変更したりできます。

### ランダムな Memory Address - pointer の検索

前の steps に従い、対象の値がある場所を見つけます。次に、"**Find out what writes to this address**" を使って、この値を書き込んでいる address を確認し、それを double click して disassembly view を開きます。

![ランダムな Memory Address - code の検索 - ランダムな Memory Address - pointer の検索: 前の steps に従い、対象の値がある場所を見つけます。次に、" Find out...](<../../images/image (1039).png>)

次に、**"\[]" の間にある hex value**（この場合は $edx の値）を**検索する新しい scan**を実行します。

![ランダムな Memory Address - code の検索 - ランダムな Memory Address - pointer の検索: 次に、" ()" の間にある hex value（この場合は $edx の値）を検索する新しい scan を実行します](<../../images/image (994).png>)

(_複数表示された場合は、通常、最も小さい address のものが必要です_)\
これで、対象の値を変更する **pointer を見つけました**。

"**Add Address Manually**" を click します。

![ランダムな Memory Address - code の検索 - ランダムな Memory Address - pointer の検索: " Add Address Manually " を click します](<../../images/image (990).png>)

次に、"Pointer" check box を click し、見つかった address を text box に追加します（この例では、前の画像で見つかった address は "Tutorial-i386.exe"+2426B0 でした）。

![ランダムな Memory Address - code の検索 - ランダムな Memory Address - pointer の検索: 次に、"Pointer" check box を click し、見つかった address を text box に追加します（この例では...](<../../images/image (392).png>)

（入力した pointer address に基づき、最初の "Address" が自動的に入力されることに注目してください）

OK を click すると、新しい pointer が作成されます。

![ランダムな Memory Address - code の検索 - ランダムな Memory Address - pointer の検索: OK を click すると、新しい pointer が作成されます](<../../images/image (308).png>)

これで、値がある memory address が変わっても、その値を変更するたびに**重要な値を変更**できます。

### Code Injection

Code injection は、target process に code の一部を inject し、その後 code の実行を自分で書いた code を通るように reroute する technique です（life を減らす代わりに points を与えるなど）。

たとえば、player の life を 1 減らしている address を見つけたとします。

![ランダムな Memory Address - pointer の検索 - Code Injection: player の life を 1 減らしている address を見つけたとします](<../../images/image (203).png>)

Show disassembler を click して **disassemble code** を表示します。\
次に **CTRL+a** を click して Auto assemble window を開き、_**Template --> Code Injection**_ を選択します。

![ランダムな Memory Address - pointer の検索 - Code Injection: 次に CTRL+a を click して Auto assemble window を開き、Template -- Code Injection を選択します](<../../images/image (902).png>)

**変更したい instruction の address**を入力します（通常は自動入力されます）。

![ランダムな Memory Address - pointer の検索 - Code Injection: 変更したい instruction の address を入力します（通常は自動入力されます）](<../../images/image (744).png>)

template が生成されます。

![ランダムな Memory Address - pointer の検索 - Code Injection: template が生成されます](<../../images/image (944).png>)

"**newmem**" section に新しい assembly code を挿入し、元の code を実行したくない場合は "**originalcode**" から削除します**。**この例では、injected code が 1 減らす代わりに 2 points を加えます。

![ランダムな Memory Address - pointer の検索 - Code Injection: " newmem " section に新しい assembly code を挿入し、元の code を実行したくない場合は " originalcode " から削除します。](<../../images/image (521).png>)

**execute などを click すれば、program に code が inject され、機能の挙動が変わります！**

## AOB signatures を使用した relocation-safe code injection

`game.exe+123456` に hook する script は、ASLR や software update の後に動作しなくなる可能性があります。**Array of Bytes (AOB) signature** は、周辺の machine code から instruction を見つけます。`aobscanmodule` を使って検索対象を 1 つの module に限定します。signature は、1 つの match だけが返るのに十分な長さにします。relocation bytes、addresses、その他変化する可能性のある bytes には wildcard を使用します。restore する必要がある instruction 全体を wildcard にしてはいけません。<sup>[[4]](#references)</sup>

Memory View で instruction を選択し、**Tools → Auto Assemble → Template → AOB Injection** を使用します。生成された `[DISABLE]` block は重要です。上書きされたすべての byte を restore し、allocation を free する必要があります。<sup>[[4]](#references)</sup>

<details>
<summary>最小限の x64 AOB injection skeleton</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

scriptを有効にする前に、以下を確認してください。

1. AOBが返すアドレスが**1つ**であること。複数返る場合は、両側に安定した命令を追加します。
2. jumpが完全な命令を置き換えていること。命令を途中で分割してはいけません。
3. allocated caveが生成されたjumpから到達可能であること。x64では、遠い位置へのallocationに14バイトのjumpが必要になる場合があります。
4. injected codeが、元のfunctionが想定するregister、flags、stack alignmentを保持していること。
5. disable blockが元のバイト列を正確に復元すること。tableを保存する前に、enableとdisableを何度かテストします。

## Reliable pointer workflow

1回の実行で見つかったpointerは候補にすぎません。複数回の新規実行でpointer mapを作成し、それらすべてに対してrescanします。captureの間にtargetを再起動し、ASLRとheap allocationが変化するようにします。baseがmoduleまたは別の安定したsymbolであるpathを優先します。1つのsave、level、またはobject instanceでしか機能しないpathは除外します。

**pointer must end with specific offsets** filterとそのdeviation optionは、build間で近くのfieldが移動した場合に有用なpathを維持できます。7.5 releaseでは、このdeviation controlも追加されました。これはfilterであり、pointer chainが安定していることの証明ではありません。<sup>[[1]](#references)</sup>

pointer scanningではstructureの移動が多すぎる場合、そのstructureにaccessするinstructionをhookします。registerからlive object pointerをallocated symbolに取り込みます。これはentity listやmanaged objectで、より信頼性が高いことがよくあります。

## Tracing code instead of scanning values

valueが直接変更される場合は、**Find out what writes to this address**を使用します。所有するobjectが必要な場合、またはwriteがcopied dataを介して行われる場合は、**Find out what accesses this address**を使用します。targetでは1つのactionだけを実行します。その後、hit countとregister stateを比較します。

**Ultimap 2**は、対応するIntel CPU上でIntel Processor Traceを使用します。すべてのinstructionをstep実行する場合よりも中断を少なくして、実行されたcontrol flowを記録します。対象のactionの実行中に実行されたcodeでfilterし、idle capture中にも実行されたcodeを除外します。Intel PTはstealth featureではありません。targetはtracing、timingの変化、またはCheat Engine自体を検出できます。<sup>[[1]](#references)</sup>

Cheat Engine 7.5では、Windowsが提供するIntel PT interfaceも追加されました。古いDBVM-backed Ultimap modeとIntel PT modeでは、hardwareとOSの要件が異なります。DBVMに対応するCPUがIntel PTにも対応しているとは限りません。<sup>[[1]](#references)</sup>

## Debugger and breakpoint selection

動作する中で、最も侵襲性の低いdebuggerを選択します。

- **Windows debugger**は単純ですが、通常のdebug eventを生成します。Anti-debugging checkで検出される可能性があります。
- **VEH debugger**はvectored exception handlerを通じてbreakpointを処理します。基本的なdebugger checkの一部を回避できますが、不可視ではありません。
- **Hardware breakpoint**はinstruction byteをpatchしませんが、x86/x64で使用できるdebug-register slotの数は少数です。
- **Software breakpoint**は1バイトを`INT3`に置き換えます。検出しやすく、integrity checkと競合する可能性があります。
- **DBVM debugger**は一部のoperationをguest OSより下の層に移します。より強い権限を持つため、設定を誤るとhostをcrashさせる可能性があります。

Cheat Engine 7.5では、通常のrelative jumpを配置する十分な空きがない場合に、exception handlerと`INT3`を基にした1バイトjumpを使用できます。これはsoftware breakpointと同じように扱ってください。exception flowを確認し、anti-tamper checkを回避できるとは考えないでください。<sup>[[1]](#references)</sup>

DBVMはhypervisorであり、一般的な不可視化switchではありません。使う場合は、破棄可能なlabに限定してください。control interfaceをuntrusted codeに公開しないでください。Kernel anti-cheatやendpoint productは、driver、hypervisor state、または変更されたmemoryを検出できる場合があります。

## Managed runtimes and recent 7.6/7.7 features

Mono、IL2CPP、.NET、Javaのtargetでは、利用可能な場合はblind scanよりもruntime metadataを優先します。**Mono → Activate mono features**または対応するruntime information windowを開きます。まずclass、field、またはmethodを特定します。その後、managed methodがJIT compileされた時点でnative disassemblyを使用します。

7.6 lineでは、executable-memory-only signature用の`AOBSCANEX`、`gdbserver` debugger interface、Java metadata inspection、高速化されたIL2CPP enumeration、ARM memory taggingで使用されるupper pointer byteを無視するpointer-scan optionが追加されました。7.7 lineでは、native Linux build、`HOOK`/`UNHOOK`、`aobscanfunction`、改善されたgeneric Mono method lookup、強化されたPDB structure support、基本的なUnreal Engine structure dissectionが追加されました。<sup>[[3]](#references)</sup>

これらの追加機能により、次のworkflowが利用できます。

1. metadataからmanaged methodまたはstatic fieldをresolveします。
2. そのmethod用に生成されたnative codeをtraceまたはdisassembleします。
3. `AOBSCANEX`または`aobscanfunction`を使用して、安定したexecutable signatureを特定します。
4. reversible hookを生成します。original instructionを保持し、disable pathをvalidateします。
5. targetを更新するたびにsignatureを再確認します。matchに成功しても、周辺のlogicが同じ意味を持つとは限りません。

## Remote targets with `ceserver`

`ceserver`は、process enumeration、memory access、debuggingをCheat Engine GUIに公開します。Official buildはLinuxとAndroidに対応しています。target上で一致するarchitectureを実行し、**Network** tabから接続します。Androidでは、default portのforwardingによりnetworkへの公開を避けられます。<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
サードパーティ製の `frida-ceserver` bridge は、iOS targets に対して Cheat Engine互換のインターフェースを提供できます。これは公式の `ceserver` ではなく、サポートされる操作が異なる場合があります。<sup>[[2]](#references)</sup>

この protocol が debugger-level access を許可すると仮定してください。loopback に bind するか、SSH/ADB tunnel の背後に配置してください。TCP 52736 を信頼できない network に公開しないでください。session が終了したら server を停止してください。

## Operational safety

自分が所有している、またはテストする権限を持つ software のみに attach してください。online game や production endpoint のそばで Cheat Engine を実行しないでください。Memory writes、injected code、drivers、DBVM によって target が crash したり、破損したりする可能性があります。<sup>[[3]](#references)</sup>

build は公式サイトから download するか、公開されている source を compile してください。Security products は、memory editors、debuggers、drivers を hack tools として分類することがよくあります。host protection をグローバルに無効化しないでください。専用の VM または lab host を使用し、実行前に artifact を検証してください。<sup>[[3]](#references)</sup>



## References

- [1] [Cheat Engine 7.5 リリースノート](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [remote targets 用 frida-ceserver bridge](https://github.com/gmh5225/frida-ceserver)
- [3] [Cheat Engine 公式リリースニュース](https://www.cheatengine.org/)
- [4] [Cheat Engine Wiki: Auto Assembler AOBs](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
