# macOSのセキュリティと特権昇格

{{#include ../../banners/hacktricks-training.md}}

## 基本的なMacOS

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

企業では、**macOS**システムはMDMで**管理される**可能性が非常に高いです。したがって、攻撃者の視点からは、**それがどのように機能するか**を知ることが興味深いです：

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - 検査、デバッグ、ファジング

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOSのセキュリティ保護

{{#ref}}
macos-security-protections/
{{#endref}}

## 攻撃面

### ファイル権限

**rootとして実行されているプロセスが**ユーザーによって制御可能なファイルを書き込むと、ユーザーはこれを悪用して**特権を昇格**させることができます。\
これは以下の状況で発生する可能性があります：

- 使用されたファイルがすでにユーザーによって作成されている（ユーザーが所有）
- 使用されたファイルがグループのためにユーザーによって書き込み可能
- 使用されたファイルがユーザーが所有するディレクトリ内にある（ユーザーがファイルを作成できる）
- 使用されたファイルがrootが所有するディレクトリ内にあるが、ユーザーがグループのために書き込みアクセスを持っている（ユーザーがファイルを作成できる）

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

## macOS TCC / SIP特権昇格

macOSでは、**アプリケーションとバイナリがフォルダーや設定にアクセスする権限を持つ**ことがあり、これにより他のものよりも特権が高くなります。

したがって、macOSマシンを成功裏に侵害したい攻撃者は、**TCC特権を昇格させる**必要があります（または、ニーズに応じて**SIPをバイパスする**必要があります）。

これらの特権は通常、アプリケーションが署名されている**権利**の形で与えられるか、アプリケーションがいくつかのアクセスを要求し、**ユーザーがそれらを承認した後**に**TCCデータベース**に見つけることができます。プロセスがこれらの特権を取得する別の方法は、**その特権を持つプロセスの子プロセス**であることです。これらは通常**継承されます**。

これらのリンクをたどって、[**TCCで特権を昇格させる**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses)、[**TCCをバイパスする**](macos-security-protections/macos-tcc/macos-tcc-bypasses/)方法や、過去に[**SIPがバイパスされた**](macos-security-protections/macos-sip.md#sip-bypasses)方法を見つけてください。

## macOSの伝統的な特権昇格

もちろん、レッドチームの視点からは、rootに昇格することにも興味があるはずです。以下の投稿をチェックして、いくつかのヒントを得てください：

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOSコンプライアンス

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## 参考文献

- [**OS Xインシデントレスポンス：スクリプティングと分析**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
