# 他の組織へのデバイスの登録

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Apple Automated Device Enrollment（旧称 DEP）は、組織に割り当てられたデバイスを識別することから始まります。ここで要約する2018年の研究では、割り当てられたシリアル番号を知っているだけで、一部の組織の enrollment profile を取得できました。これは、それらの組織が十分な追加認証を要求していなかったためです。これは過去の発見であり、現在のすべての MDM にシリアル番号だけで参加できるという主張ではありません。Profiles には、証明書、アプリケーション、Wi-Fi secrets、VPN 設定、その他の機密構成が含まれている場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

**以下は研究 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) の概要です。詳細な技術情報については、こちらを確認してください！**<sup>[[1]](#references)</sup>

## DEP と MDM のバイナリ分析の概要

この研究では、当時の macOS バージョンに関連する DEP および MDM のバイナリを分析しました。コンポーネント名と役割は、リリースによって変更される可能性があります。

- **`mdmclient`**: MDM サーバーと通信し、10.13.4 より前の macOS バージョンで DEP check-in をトリガーします。
- **`profiles`**: Configuration Profiles を管理し、macOS バージョン 10.13.4 以降で DEP check-in をトリガーします。
- **`cloudconfigurationd`**: DEP API 通信を管理し、Device Enrollment profiles を取得します。

DEP check-in では、private Configuration Profiles framework の `CPFetchActivationRecord` および `CPGetActivationRecord` 関数を使用して Activation Record を取得します。`CPFetchActivationRecord` は XPC 経由で `cloudconfigurationd` と連携します。<sup>[[1]](#references)</sup>

## Tesla Protocol と Absinthe Scheme の Reverse Engineering

DEP check-in では、`cloudconfigurationd` が暗号化および署名された JSON payload を _iprofiles.apple.com/macProfile_ に送信します。payload にはデバイスのシリアル番号と、`RequestProfileConfiguration` という action が含まれます。使用される暗号化スキームは、内部では「Absinthe」と呼ばれています。このスキームの解明は複雑で、多数の手順を必要とするため、Activation Record request に任意のシリアル番号を挿入する別の方法が検討されました。<sup>[[1]](#references)</sup>

## DEP Requests の Proxying

Charles Proxy などのツールを使用して _iprofiles.apple.com_ 宛ての DEP requests を傍受・変更する試みは、payload の暗号化と SSL/TLS security measures によって妨げられました。しかし、`MCCloudConfigAcceptAnyHTTPSCertificate` configuration を有効にすると、server certificate validation を bypass できます。ただし、payload は暗号化されているため、復号キーなしでシリアル番号を変更することは依然としてできません。<sup>[[1]](#references)</sup>

## DEP と通信する System Binaries の Instrumentation

`cloudconfigurationd` などの system binaries を instrument するには、macOS で System Integrity Protection（SIP）を無効化する必要があります。SIP を無効化すると、LLDB などのツールを使用して system processes に attach し、DEP API interactions で使用されるシリアル番号を変更できる可能性があります。この方法は、entitlements と code signing の複雑さを避けられるため、より望ましいものです。<sup>[[1]](#references)</sup>

**Binary Instrumentation の Exploitation:**
`cloudconfigurationd` で JSON serialization が行われる前に DEP request payload を変更する方法は効果的でした。このプロセスには以下が含まれます。

1. LLDB を `cloudconfigurationd` に attach する。
2. system serial number が取得される場所を特定する。
3. payload が暗号化されて送信される前に、メモリへ任意のシリアル番号を inject する。

この方法により、研究者は指定された、割り当て済みのシリアル番号に対応する DEP profiles を取得できました。割り当てられていない任意のシリアル番号が有効になるわけではありません。<sup>[[1]](#references)</sup>

### Python による Instrumentation の自動化

Exploitation process は LLDB API を使用する Python で自動化され、任意のシリアル番号をプログラムから inject し、対応する DEP profiles を取得できるようになりました。<sup>[[1]](#references)</sup>

### DEP と MDM の Vulnerabilities による潜在的な影響

この研究では、重大な security concerns が明らかになりました。

1. **Information Disclosure**: DEP に登録されたシリアル番号を提供することで、DEP profile に含まれる機密性の高い組織情報を取得できます。<sup>[[1]](#references)</sup>

## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
{{#include ../../../banners/hacktricks-training.md}}
