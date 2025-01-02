# 他の組織へのデバイスの登録

{{#include ../../../banners/hacktricks-training.md}}

## はじめに

[**以前にコメントしたように**](./#what-is-mdm-mobile-device-management)**、**デバイスを組織に登録するためには、**その組織に属するシリアル番号のみが必要です**。デバイスが登録されると、いくつかの組織が新しいデバイスに機密データをインストールします：証明書、アプリケーション、WiFiパスワード、VPN設定[など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険な入り口となる可能性があります。

**以下は、研究の要約です[https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe)。さらなる技術的詳細については確認してください！**

## DEPとMDMバイナリ分析の概要

この研究は、macOS上のデバイス登録プログラム（DEP）およびモバイルデバイス管理（MDM）に関連するバイナリに深く掘り下げています。主要なコンポーネントは以下の通りです：

- **`mdmclient`**：MDMサーバーと通信し、macOSバージョン10.13.4以前でのDEPチェックインをトリガーします。
- **`profiles`**：構成プロファイルを管理し、macOSバージョン10.13.4以降でのDEPチェックインをトリガーします。
- **`cloudconfigurationd`**：DEP API通信を管理し、デバイス登録プロファイルを取得します。

DEPチェックインは、プライベート構成プロファイルフレームワークからの`CPFetchActivationRecord`および`CPGetActivationRecord`関数を利用してアクティベーションレコードを取得し、`CPFetchActivationRecord`がXPCを介して`cloudconfigurationd`と調整します。

## TeslaプロトコルとAbsintheスキームのリバースエンジニアリング

DEPチェックインは、`cloudconfigurationd`が暗号化された署名付きJSONペイロードを_iprofiles.apple.com/macProfile_に送信することを含みます。ペイロードにはデバイスのシリアル番号と「RequestProfileConfiguration」というアクションが含まれています。使用される暗号化スキームは内部的に「Absinthe」と呼ばれています。このスキームを解明することは複雑で、多くのステップを含み、アクティベーションレコードリクエストに任意のシリアル番号を挿入するための代替手法を探ることにつながりました。

## DEPリクエストのプロキシ

Charles Proxyのようなツールを使用して_iprofiles.apple.com_へのDEPリクエストを傍受し、変更しようとする試みは、ペイロードの暗号化とSSL/TLSセキュリティ対策によって妨げられました。しかし、`MCCloudConfigAcceptAnyHTTPSCertificate`構成を有効にすることで、サーバー証明書の検証をバイパスすることが可能ですが、ペイロードの暗号化された性質により、復号化キーなしでシリアル番号を変更することは依然として不可能です。

## DEPと相互作用するシステムバイナリの計測

`cloudconfigurationd`のようなシステムバイナリを計測するには、macOSでシステム整合性保護（SIP）を無効にする必要があります。SIPが無効になっている場合、LLDBのようなツールを使用してシステムプロセスにアタッチし、DEP APIとの相互作用で使用されるシリアル番号を変更する可能性があります。この方法は、権限やコード署名の複雑さを回避できるため、好ましいです。

**バイナリ計測の悪用：**
`cloudconfigurationd`でJSONシリアル化の前にDEPリクエストペイロードを変更することが効果的であることが証明されました。このプロセスには以下が含まれます：

1. `cloudconfigurationd`にLLDBをアタッチします。
2. システムシリアル番号が取得されるポイントを特定します。
3. ペイロードが暗号化されて送信される前に、メモリに任意のシリアル番号を注入します。

この方法により、任意のシリアル番号に対して完全なDEPプロファイルを取得できることが示され、潜在的な脆弱性が明らかになりました。

### Pythonによる計測の自動化

悪用プロセスは、LLDB APIを使用してPythonで自動化され、任意のシリアル番号をプログラム的に注入し、対応するDEPプロファイルを取得することが可能になりました。

### DEPとMDMの脆弱性の潜在的影響

この研究は、重要なセキュリティ上の懸念を浮き彫りにしました：

1. **情報漏洩**：DEPに登録されたシリアル番号を提供することで、DEPプロファイルに含まれる機密の組織情報を取得できます。

{{#include ../../../banners/hacktricks-training.md}}
