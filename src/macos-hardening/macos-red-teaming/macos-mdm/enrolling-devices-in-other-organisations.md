# 他の組織にデバイスを登録する

{{#include ../../../banners/hacktricks-training.md}}

## 概要

[**以前説明したように**](#what-is-mdm-mobile-device-management)**、**デバイスを組織に登録するには、**その組織に属するシリアル番号だけが必要です**。デバイスが登録されると、多くの組織は新しいデバイスに機密データ（証明書、アプリケーション、WiFiパスワード、VPN設定[など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)）をインストールします。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険なentrypointになる可能性があります。

**以下は、調査 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) の概要です。さらに詳しいtechnical detailsについては、そちらを確認してください！**<sup>[1]</sup>

## DEPとMDM Binary Analysisの概要

この調査では、macOS上のDevice Enrollment Program（DEP）およびMobile Device Management（MDM）に関連するbinariesを詳しく分析しています。主なcomponentsは次のとおりです。

- **`mdmclient`**: MDM serversと通信し、10.13.4より前のmacOS versionsでDEP check-inをtriggerします。
- **`profiles`**: Configuration Profilesを管理し、macOS versions 10.13.4以降でDEP check-inをtriggerします。
- **`cloudconfigurationd`**: DEP API communicationsを管理し、Device Enrollment profilesを取得します。

DEP check-inでは、private Configuration Profiles frameworkの`CPFetchActivationRecord`および`CPGetActivationRecord` functionsを使用してActivation Recordを取得します。`CPFetchActivationRecord`は、XPCを介して`cloudconfigurationd`と連携します。<sup>[1]</sup>

## Tesla ProtocolとAbsinthe SchemeのReverse Engineering

DEP check-inでは、`cloudconfigurationd`が暗号化および署名されたJSON payloadを_iprofiles.apple.com/macProfile_に送信します。payloadには、デバイスのシリアル番号と`RequestProfileConfiguration`というactionが含まれます。使用されるencryption schemeは、内部では「Absinthe」と呼ばれています。このschemeを解明するには多数のstepsが必要で複雑なため、Activation Record requestに任意のシリアル番号を挿入するalternative methodsの調査につながりました。<sup>[1]</sup>

## DEP RequestsのProxying

Charles Proxyなどのtoolsを使用して、_iprofiles.apple.com_へのDEP requestsをinterceptしてmodifyする試みは、payloadの暗号化とSSL/TLS security measuresによって妨げられました。ただし、`MCCloudConfigAcceptAnyHTTPSCertificate` configurationを有効にすると、server certificate validationをbypassできます。しかし、payloadは暗号化されているため、decryption keyなしではシリアル番号をmodifyできません。<sup>[1]</sup>

## DEPとやり取りするSystem BinariesのInstrumenting

`cloudconfigurationd`などのsystem binariesをinstrumentするには、macOSでSystem Integrity Protection（SIP）を無効にする必要があります。SIPを無効にすると、LLDBなどのtoolsを使用してsystem processesにattachし、DEP API interactionsで使用されるシリアル番号をmodifyできる可能性があります。このmethodは、entitlementsとcode signingの複雑さを回避できるため、より望ましい方法です。

**Binary InstrumentationのExploiting:**
JSON serializationの前に`cloudconfigurationd`内のDEP request payloadをmodifyすることで、効果的に機能しました。このprocessでは、次の手順を実行します。

1. LLDBを`cloudconfigurationd`にattachする。
2. system serial numberが取得される箇所を特定する。
3. payloadが暗号化されて送信される前に、memoryへ任意のシリアル番号をinjectする。

このmethodにより、任意のシリアル番号に対応する完全なDEP profilesを取得でき、潜在的なvulnerabilityが示されました。<sup>[1]</sup>

### PythonによるInstrumentationの自動化

このexploitation processは、LLDB APIを使用するPythonによって自動化されました。これにより、任意のシリアル番号をprogrammaticallyにinjectし、対応するDEP profilesを取得できるようになりました。<sup>[1]</sup>

### DEPおよびMDM Vulnerabilitiesの潜在的な影響

この調査では、重大なsecurity concernsが明らかになりました。

1. **Information Disclosure**: DEPに登録されたシリアル番号を提供することで、DEP profileに含まれる組織の機密情報を取得できます。<sup>[1]</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)

{{#include ../../../banners/hacktricks-training.md}}
