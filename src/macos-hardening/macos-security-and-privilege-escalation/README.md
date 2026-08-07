# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic MacOS

macOS に詳しくない場合は、まず macOS の基本を学ぶことから始めてください。

- 特殊な macOS **ファイルと権限:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- 一般的な macOS **ユーザー**


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

- 一般的な macOS **ネットワークサービスとプロトコル**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- `tar.gz` をダウンロードするには、[https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) のような URL を [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz) に変更します。

### MacOS MDM

企業では、**macOS** システムが **MDM で管理されている可能性が非常に高い**です。そのため、攻撃者の視点からは、**その仕組みを知ることが重要です**。


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

**root として実行されるプロセスが、ユーザーによって制御可能なファイルに書き込む**場合、そのユーザーはこれを悪用して **privilege escalation** を行える可能性があります。\
これは次のような状況で発生します。

- 使用されるファイルが、すでにユーザーによって作成されている（ユーザーが所有している）
- 使用されるファイルが、グループ権限によってユーザーから書き込み可能になっている
- 使用されるファイルが、ユーザー所有のディレクトリ内にある（ユーザーがファイルを作成できる）
- 使用されるファイルが、root 所有のディレクトリ内にあるが、グループ権限によってユーザーがそのディレクトリへの書き込み権限を持っている（ユーザーがファイルを作成できる）

**root によって使用されるファイルを作成**できる場合、ユーザーはその**内容を悪用**したり、さらにはそのファイルを別の場所に向ける **symlinks/hardlinks** を作成したりできます。

この種の脆弱性については、**脆弱な `.pkg` installer** を忘れずに**確認**してください。


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

ファイル拡張子に登録された不審なアプリが悪用される可能性があり、特定のプロトコルを開くように異なるアプリケーションを登録することもできます。


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

macOS では、**アプリケーションやバイナリに権限を付与**して、他のものよりも高い権限でフォルダーや設定にアクセスできるようにすることができます。

そのため、macOS マシンの侵害に成功したい攻撃者は、**TCC privileges を escalate**（必要に応じて **SIP を bypass**）する必要があります。

これらの権限は通常、アプリケーションに署名された **entitlements** として付与されます。また、アプリケーションがアクセスを要求し、**ユーザーが承認した後**に **TCC databases** で確認できる場合もあります。プロセスがこれらの権限を取得する別の方法は、通常、同じ **privileges** を持つプロセスの **child** になることです。これは権限が通常 **継承される**ためです。<sup>[[5]](#references)</sup>

以下のリンクから、[**TCC で privileges を escalate する方法**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses)、[**TCC を bypass する方法**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html)、および過去に [**SIP がどのように bypass されたか**](macos-security-protections/macos-sip.md#sip-bypasses) を確認できます。

## macOS Traditional Privilege Escalation

もちろん、red team の観点では root への privilege escalation にも関心があるはずです。ヒントについては、次の post を確認してください。


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
