# 他の組織にデバイスを登録する

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>でAWSハッキングをゼロからヒーローまで学ぶ</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## イントロ

[**以前にコメントしたように**](./#what-is-mdm-mobile-device-management)**、組織にデバイスを登録しようとするためには、その組織に属するシリアル番号だけが必要です**。デバイスが登録されると、新しいデバイスに証明書、アプリケーション、WiFiパスワード、VPN構成などがインストールされます。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険なエントリーポイントとなり得ます。

**以下は、研究の要約です [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)。詳細な技術的詳細については、そちらをご確認ください！**

## DEPおよびMDMバイナリ解析の概要

この研究は、macOS上のデバイス登録プログラム（DEP）およびモバイルデバイス管理（MDM）に関連するバイナリに焦点を当てています。主要なコンポーネントには次のものがあります：

- **`mdmclient`**：macOSバージョン10.13.4より前でMDMサーバーと通信し、DEPチェックインをトリガーします。
- **`profiles`**：構成プロファイルを管理し、macOSバージョン10.13.4以降でDEPチェックインをトリガーします。
- **`cloudconfigurationd`**：DEP API通信を管理し、デバイス登録プロファイルを取得します。

DEPチェックインでは、`CPFetchActivationRecord`および`CPGetActivationRecord`関数がプライベート構成プロファイルフレームワークからActivation Recordを取得するために使用され、`CPFetchActivationRecord`はXPCを介して`cloudconfigurationd`と連携します。

## TeslaプロトコルおよびAbsintheスキームのリバースエンジニアリング

DEPチェックインには、`cloudconfigurationd`が暗号化された署名付きのJSONペイロードを_iprofiles.apple.com/macProfile_に送信します。ペイロードにはデバイスのシリアル番号とアクション「RequestProfileConfiguration」が含まれます。使用される暗号化スキームは内部的に「Absinthe」と呼ばれます。このスキームを解明するには複雑な手順が必要であり、Activation Recordリクエストに任意のシリアル番号を挿入するための代替手法を探ることにつながりました。

## DEPリクエストのプロキシ

Charles Proxyなどのツールを使用して_iprofiles.apple.com_へのDEPリクエストを傍受および変更しようとする試みは、ペイロードの暗号化とSSL/TLSセキュリティ対策によって妨げられました。ただし、`MCCloudConfigAcceptAnyHTTPSCertificate`構成を有効にすると、サーバー証明書の検証をバイパスできますが、ペイロードの暗号化により、復号鍵なしでシリアル番号を変更することはできません。

## DEPとやり取りするシステムバイナリのインストゥルメンテーション

`cloudconfigurationd`などのシステムバイナリのインストゥルメンテーションには、macOSでシステム整合性保護（SIP）を無効にする必要があります。SIPを無効にすると、LLDBのようなツールを使用してシステムプロセスにアタッチし、DEP APIとやり取りで使用されるシリアル番号を変更する可能性があります。この方法は、権限とコード署名の複雑さを回避できるため、好ましい方法です。

**バイナリインストゥルメンテーションの悪用:**
`cloudconfigurationd`でJSONシリアライズ前にDEPリクエストペイロードを変更することが効果的であることが示されました。このプロセスには以下が含まれます：

1. LLDBを`cloudconfigurationd`にアタッチする。
2. システムシリアル番号が取得されるポイントを特定する。
3. ペイロードが暗号化および送信される前に、メモリに任意のシリアル番号を挿入する。

この方法により、任意のシリアル番号の完全なDEPプロファイルを取得することが可能であり、潜在的な脆弱性が示されました。

### Pythonを使用したインストゥルメンテーションの自動化

LLDB APIを使用して、Pythonを使用して悪用プロセスを自動化し、任意のシリアル番号をプログラムで挿入し、対応するDEPプロファイルを取得することが可能になりました。

### DEPおよびMDMの脆弱性の潜在的な影響

研究は重要なセキュリティ上の懸念を示しました：

1. **情報漏洩**：DEPに登録されたシリアル番号を提供することで、DEPプロファイルに含まれる機密組織情報を取得できます。
2. **ローグDEP登録**：適切な認証がない場合、DEPに登録されたシリアル番号を持つ攻撃者は、組織のMDMサーバーにローグデバイスを登録し、機密データやネットワークリソースにアクセスする可能性があります。

結論として、DEPとMDMは企業環境でAppleデバイスを管理するための強力なツールを提供しますが、セキュリティ上の攻撃ベクトルを示す可能性があり、これらを保護し、監視する必要があります。
