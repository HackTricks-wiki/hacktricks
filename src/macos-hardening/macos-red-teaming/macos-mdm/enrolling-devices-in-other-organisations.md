# 他の組織へのデバイスの登録

{{#include ../../../banners/hacktricks-training.md}}

## 概要

[**以前説明したように**](#what-is-mdm-mobile-device-management)**、**デバイスを組織に登録するには、**その組織に属するシリアル番号だけが必要です**。デバイスが登録されると、多くの組織は新しいデバイスに機密データ（証明書、アプリケーション、WiFiパスワード、VPN設定[など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)）をインストールします。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険なentrypointになる可能性があります。

**以下は、調査 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) の概要です。さらに技術的な詳細については、こちらを確認してください！**<sup>[[1]](#references)</sup>

## DEPおよびMDMバイナリ分析の概要

この調査では、macOS上のDevice Enrollment Program (DEP)およびMobile Device Management (MDM)に関連するバイナリを詳しく分析しています。主なコンポーネントは以下のとおりです。

- **`mdmclient`**: MDMサーバーと通信し、10.13.4より前のmacOSバージョンでDEP check-inをトリガーします。
- **`profiles`**: Configuration Profilesを管理し、macOS 10.13.4以降でDEP check-inをトリガーします。
- **`cloudconfigurationd`**: DEP APIとの通信を管理し、Device Enrollment profilesを取得します。

DEP check-inでは、private Configuration Profiles frameworkの`CPFetchActivationRecord`および`CPGetActivationRecord`関数を使用してActivation Recordを取得します。`CPFetchActivationRecord`は、XPCを介して`cloudconfigurationd`と連携します。<sup>[[1]](#references)</sup>

## Tesla ProtocolおよびAbsinthe SchemeのReverse Engineering

DEP check-inでは、`cloudconfigurationd`が暗号化および署名されたJSON payloadを _iprofiles.apple.com/macProfile_ に送信します。payloadには、デバイスのシリアル番号とアクション`RequestProfileConfiguration`が含まれます。使用されている暗号化方式は、内部では「Absinthe」と呼ばれています。この方式の解明は複雑で、多数の手順を必要とするため、Activation Record requestに任意のシリアル番号を挿入する別の方法の調査につながりました。<sup>[[1]](#references)</sup>

## DEP RequestsのProxying

Charles Proxyなどのツールを使用して _iprofiles.apple.com_ へのDEP requestsを傍受および変更する試みは、payloadの暗号化とSSL/TLSのセキュリティ対策によって妨げられました。しかし、`MCCloudConfigAcceptAnyHTTPSCertificate` configurationを有効にすると、サーバー証明書の検証をbypassできます。ただし、payloadは暗号化されているため、復号キーなしでシリアル番号を変更することは依然としてできません。<sup>[[1]](#references)</sup>

## DEPとやり取りするSystem BinariesのInstrumenting

`cloudconfigurationd`などのsystem binariesをinstrumentするには、macOSでSystem Integrity Protection (SIP)を無効にする必要があります。SIPを無効にすると、LLDBなどのツールを使用してsystem processesにattachし、DEP API interactionsで使用されるシリアル番号を変更できる可能性があります。この方法は、entitlementsとcode signingの複雑さを回避できるため、より望ましいものです。<sup>[[1]](#references)</sup>

**Binary InstrumentationのExploiting:**
`cloudconfigurationd`でJSON serializationを行う前にDEP request payloadを変更することで、効果的な結果が得られました。手順は以下のとおりです。

1. LLDBを`cloudconfigurationd`にattachする。
2. system serial numberが取得される箇所を特定する。
3. payloadが暗号化されて送信される前に、memoryへ任意のシリアル番号をinjectする。

この方法により、任意のシリアル番号に対応する完全なDEP profilesを取得でき、潜在的な脆弱性が実証されました。<sup>[[1]](#references)</sup>

### PythonによるInstrumentationの自動化

Exploitation processはLLDB APIを使用してPythonで自動化され、任意のシリアル番号をprogrammaticallyにinjectし、対応するDEP profilesを取得できるようになりました。<sup>[[1]](#references)</sup>

### DEPおよびMDM Vulnerabilitiesの潜在的な影響

この調査では、重大なセキュリティ上の懸念が明らかになりました。

1. **Information Disclosure**: DEPに登録されたシリアル番号を提供することで、DEP profileに含まれる機密性の高い組織情報を取得できます。<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
