# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

macOSに不慣れな場合は、macOSの基本を学び始めるべきです：

- 特殊なmacOS **ファイルと権限：**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- 一般的なmacOS **ユーザー**

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- k**ernel**の**アーキテクチャ**

{{#ref}}
mac-os-architecture/
{{#endref}}

- 一般的なmacOS n**etworkサービスとプロトコル**

{{#ref}}
macos-protocols.md
{{#endref}}

- **オープンソース** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz`をダウンロードするには、[https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/)のようなURLを[https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)に変更します。

### MacOS MDM

企業の**macOS**システムは、**MDMで管理される**可能性が非常に高いです。したがって、攻撃者の視点からは、**それがどのように機能するか**を知ることが興味深いです：

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - 検査、デバッグ、ファジング

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections

{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### ファイル権限

**rootとして実行されているプロセスが**ユーザーによって制御可能なファイルを書き込むと、ユーザーはこれを悪用して**権限を昇格させる**ことができます。\
これは以下の状況で発生する可能性があります：

- 使用されたファイルはすでにユーザーによって作成されている（ユーザーが所有）
- 使用されたファイルはグループのためにユーザーによって書き込み可能
- 使用されたファイルはユーザーが所有するディレクトリ内にある（ユーザーがファイルを作成できる）
- 使用されたファイルはrootが所有するディレクトリ内にあるが、ユーザーはグループのために書き込みアクセスを持っている（ユーザーがファイルを作成できる）

**rootによって使用される**ファイルを**作成する**ことができると、ユーザーはその**内容を利用する**ことができたり、別の場所を指す**シンボリックリンク/ハードリンク**を作成することができます。

この種の脆弱性については、**脆弱な`.pkg`インストーラーを確認することを忘れないでください**：

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### ファイル拡張子とURLスキームアプリハンドラー

ファイル拡張子によって登録された奇妙なアプリは悪用される可能性があり、異なるアプリケーションが特定のプロトコルを開くために登録されることがあります。

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP 権限昇格

macOSでは、**アプリケーションやバイナリが**フォルダや設定にアクセスする権限を持つことができ、他のものよりも特権的になります。

したがって、macOSマシンを成功裏に侵害したい攻撃者は、**TCC権限を昇格させる**必要があります（または、ニーズに応じて**SIPをバイパスする**必要があります）。

これらの権限は通常、アプリケーションが署名されている**権利**の形で与えられるか、アプリケーションがいくつかのアクセスを要求し、**ユーザーがそれらを承認した後**に**TCCデータベース**に見つけることができます。プロセスがこれらの権限を取得する別の方法は、**その権限を持つプロセスの子**であることです。これらの権限は通常**継承されます**。

これらのリンクをたどって、TCCでの[**権限昇格の異なる方法**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses)、[**TCCをバイパスする方法**](macos-security-protections/macos-tcc/macos-tcc-bypasses/)や、過去に[**SIPがバイパスされた方法**](macos-security-protections/macos-sip.md#sip-bypasses)を見つけてください。

## macOS 伝統的権限昇格

もちろん、レッドチームの視点からは、rootに昇格することにも興味があるはずです。以下の投稿をチェックして、いくつかのヒントを得てください：

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS コンプライアンス

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## 参考文献

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
