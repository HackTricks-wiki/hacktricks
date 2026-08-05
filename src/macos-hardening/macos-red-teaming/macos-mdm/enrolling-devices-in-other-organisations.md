# 他の組織にデバイスを登録する

{{#include ../../../banners/hacktricks-training.md}}

## 概要

[**前述のとおり**](#what-is-mdm-mobile-device-management)**、**デバイスを組織に登録するには、**その組織に属するシリアル番号だけが必要です**。デバイスが登録されると、複数の組織が新しいデバイスに機密データをインストールします。証明書、アプリケーション、WiFiパスワード、VPN設定[など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)です。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険なエントリーポイントになる可能性があります。

**以下は、調査内容 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) の概要です。さらに技術的な詳細については、そちらを確認してください！**<sup>[[1]](#references)</sup>

## DEPとMDMのバイナリ分析の概要

この調査では、macOS上のDevice Enrollment Program (DEP)およびMobile Device Management (MDM)に関連するバイナリを詳しく分析しています。主なコンポーネントは次のとおりです。

- **`mdmclient`**: MDMサーバーと通信し、10.13.4より前のmacOSバージョンでDEP check-inを実行します。
- **`profiles`**: Configuration Profilesを管理し、macOS 10.13.4以降でDEP check-inを実行します。
- **`cloudconfigurationd`**: DEP API通信を管理し、Device Enrollment profilesを取得します。

DEP check-inでは、private Configuration Profiles frameworkの`CPFetchActivationRecord`および`CPGetActivationRecord`関数を使用してActivation Recordを取得します。`CPFetchActivationRecord`はXPCを介して`cloudconfigurationd`と連携します。<sup>[[1]](#references)</sup>

## Tesla ProtocolとAbsinthe Schemeのリバースエンジニアリング

DEP check-inでは、`cloudconfigurationd`が暗号化および署名されたJSON payloadを_iprofiles.apple.com/macProfile_に送信します。payloadには、デバイスのシリアル番号と`RequestProfileConfiguration`というアクションが含まれます。使用される暗号化スキームは、内部では「Absinthe」と呼ばれています。このスキームの解明は複雑で、多数の手順を必要とするため、Activation Record requestに任意のシリアル番号を挿入する代替手法の調査につながりました。<sup>[[1]](#references)</sup>

## DEP Requestsのプロキシ

Charles Proxyなどのツールを使用して_iprofiles.apple.com_へのDEP requestsを傍受・変更する試みは、payloadの暗号化とSSL/TLSのセキュリティ対策によって妨げられました。ただし、`MCCloudConfigAcceptAnyHTTPSCertificate` configurationを有効にすると、server certificate validationをバイパスできます。しかし、payloadが暗号化されているため、decryption keyなしではシリアル番号を変更できません。<sup>[[1]](#references)</sup>

## DEPとやり取りするSystem BinariesへのInstrumentation

`cloudconfigurationd`などのsystem binariesをinstrumentationするには、macOSでSystem Integrity Protection (SIP)を無効にする必要があります。SIPを無効にすると、LLDBなどのツールを使用してsystem processesにattachし、DEP API interactionsで使用されるシリアル番号を変更できる可能性があります。この方法は、entitlementsとcode signingの複雑さを回避できるため、より望ましいものです。

**Binary Instrumentationの悪用:**
`cloudconfigurationd`でJSON serializationが行われる前にDEP request payloadを変更することで、効果的な結果が得られました。手順は次のとおりです。

1. LLDBを`cloudconfigurationd`にattachする。
2. system serial numberが取得される箇所を特定する。
3. payloadが暗号化されて送信される前に、メモリへ任意のシリアル番号をinjectする。

この方法により、任意のシリアル番号に対応する完全なDEP profilesを取得でき、潜在的な脆弱性が示されました。<sup>[[1]](#references)</sup>

### PythonによるInstrumentationの自動化

このexploit processはLLDB APIを使用するPythonで自動化され、任意のシリアル番号をプログラムからinjectし、対応するDEP profilesを取得できるようになりました。<sup>[[1]](#references)</sup>

### DEPとMDMの脆弱性による潜在的な影響

この調査では、重大なセキュリティ上の懸念が明らかになりました。

1. **Information Disclosure**: DEPに登録されたシリアル番号を提供することで、DEP profileに含まれる組織の機密情報を取得できます。<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
