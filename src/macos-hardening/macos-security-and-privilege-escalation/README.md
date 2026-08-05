# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

macOSに詳しくない場合は、まずmacOSの基本を学ぶことから始めてください。

- macOSの特殊な **ファイルと権限:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- macOSで一般的な **ユーザー**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- k**ernel** の **アーキテクチャ**


{{#ref}}
mac-os-architecture/
{{#endref}}

- macOSで一般的な **ネットワークサービスとプロトコル**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz` をダウンロードするには、[https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) のようなURLを [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) に変更します。

### MacOS MDM

企業では **macOS** システムが **MDMで管理されている可能性が非常に高くなります**。したがって、攻撃者の観点からは、**その仕組みを理解すること**が重要です。


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspecting, Debugging and Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Security Protections


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

**rootとして実行されているプロセスが、ユーザーによって制御可能なファイルに書き込む**場合、ユーザーはこれを悪用して**権限を昇格**できる可能性があります。\
これは、以下の状況で発生する可能性があります。

- 使用されるファイルがすでにユーザーによって作成されている（ユーザーが所有している）
- グループにより、使用されるファイルに対してユーザーが書き込み可能である
- 使用されるファイルがユーザー所有のディレクトリ内にある（ユーザーがファイルを作成できる）
- 使用されるファイルがroot所有のディレクトリ内にあるが、グループによりユーザーがそのディレクトリへの書き込み権限を持っている（ユーザーがファイルを作成できる）

**rootによって使用されるファイルを作成**できると、ユーザーはその**内容を悪用**したり、別の場所を指す**symlinks/hardlinks**を作成したりできます。

この種の脆弱性については、**脆弱な `.pkg` installers**を忘れずに**確認**してください。


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

ファイル拡張子に登録された奇妙なアプリが悪用される可能性があり、特定のプロトコルを開くように別のアプリケーションを登録することもできます。


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

macOSでは、**アプリケーションとバイナリがフォルダや設定にアクセスする権限を持つことができ**、他のものより高い権限を持つ場合があります。

したがって、macOSマシンの侵害を成功させたい攻撃者は、**TCC権限を昇格**させる必要があります（必要に応じて**SIPをバイパス**することもあります）。

これらの権限は通常、アプリケーションが署名される際の**entitlements**として付与されます。また、アプリケーションがアクセスを要求し、**ユーザーが承認した後**に、**TCC databases**で確認できる場合もあります。プロセスがこれらの権限を取得する別の方法は、それらの**権限**を持つプロセスの**child**になることです。通常、権限は**継承**されるためです。

以下のリンクから、[**escalate privileges in TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses)、[**bypass TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html)、および過去に[**SIP has been bypassed**](macos-security-protections/macos-sip.md#sip-bypasses)された方法を確認してください。

## macOS Traditional Privilege Escalation

もちろん、red teamsの観点ではrootへの昇格にも関心を持つべきです。ヒントについては、以下の投稿を確認してください。


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
