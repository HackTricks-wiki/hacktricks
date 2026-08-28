# 他の組織へのデバイス登録

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Apple Automated Device Enrollment（旧称 DEP）は、組織に割り当てられたデバイスを識別することから始まります。ここで要約する2018年の調査では、割り当てられたシリアル番号を知っているだけで、一部の組織の enrollment profile を取得できました。これは、それらの組織が十分な追加認証を要求していなかったためです。これは歴史的な発見であり、現在のすべての MDM にシリアル番号だけで参加できるという主張ではありません。プロファイルには、証明書、アプリケーション、Wi-Fi の秘密情報、VPN 設定、その他の機密構成が含まれている場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

**以下は調査 [https://duo.com/labs/research/mdm-me-maybe](https://duo.com/labs/research/mdm-me-maybe) の要約です。詳細な technical details については、こちらを確認してください！**<sup>[[1]](#references)</sup>

## DEP と MDM のバイナリ分析の概要

この調査では、当時の macOS バージョンに関連する DEP および MDM のバイナリを分析しました。コンポーネント名と役割は、リリースによって変更される場合があります。

- **`mdmclient`**: MDM サーバーと通信し、10.13.4 より前の macOS バージョンで DEP check-in をトリガーします。
- **`profiles`**: Configuration Profiles を管理し、macOS バージョン 10.13.4 以降で DEP check-in をトリガーします。
- **`cloudconfigurationd`**: DEP API 通信を管理し、Device Enrollment プロファイルを取得します。

DEP check-in は、private Configuration Profiles framework の `CPFetchActivationRecord` および `CPGetActivationRecord` 関数を使用して Activation Record を取得します。`CPFetchActivationRecord` は、XPC を介して `cloudconfigurationd` と連携します。<sup>[[1]](#references)</sup>

## Tesla Protocol と Absinthe Scheme のリバースエンジニアリング

DEP check-in では、`cloudconfigurationd` が暗号化および署名された JSON payload を _iprofiles.apple.com/macProfile_ に送信します。payload には、デバイスのシリアル番号と `"RequestProfileConfiguration"` アクションが含まれます。使用される暗号化 scheme は、内部的には「Absinthe」と呼ばれています。この scheme の解明は複雑で多数の手順を伴うため、Activation Record request に任意のシリアル番号を挿入する別の方法が検討されました。<sup>[[1]](#references)</sup>

## DEP Request のプロキシ

Charles Proxy などのツールを使用して _iprofiles.apple.com_ への DEP request を傍受・変更する試みは、payload の暗号化と SSL/TLS の security measures によって妨げられました。ただし、`MCCloudConfigAcceptAnyHTTPSCertificate` configuration を有効にすると、サーバー証明書の validation を bypass できます。しかし、payload が暗号化されているため、復号 key なしではシリアル番号を変更できません。<sup>[[1]](#references)</sup>

## DEP とやり取りするシステムバイナリへの Instrumentation

`cloudconfigurationd` などのシステムバイナリに Instrumentation を行うには、macOS で System Integrity Protection (SIP) を無効化する必要があります。SIP を無効化すると、LLDB などのツールを使用してシステムプロセスに attach し、DEP API とのやり取りで使用されるシリアル番号を変更できる可能性があります。この方法は、entitlements と code signing の複雑さを回避できるため、より適しています。<sup>[[1]](#references)</sup>

**Binary Instrumentation の悪用:**
`cloudconfigurationd` で JSON serialization が行われる前に DEP request payload を変更する方法が有効であることが確認されました。手順は次のとおりです。

1. LLDB を `cloudconfigurationd` に attach する。
2. システムのシリアル番号が取得される箇所を特定する。
3. payload が暗号化されて送信される前に、メモリへ任意のシリアル番号を inject する。

この方法により、指定した、組織に割り当てられたシリアル番号の DEP プロファイルを取得できました。割り当てられていない任意のシリアル番号を有効にするものではありません。<sup>[[1]](#references)</sup>

### Python による Instrumentation の自動化

この exploitation process は LLDB API を使用する Python によって自動化され、任意のシリアル番号を programmatically に inject して、対応する DEP プロファイルを取得することが可能になりました。<sup>[[1]](#references)</sup>

## 2025年の再検証: VM からの Rogue Enrollment

Black Hat Asia 2025 の調査では、元の trust-boundary の問題が **MDM layer** で依然として重要になり得ることが示されました。`cloudconfigurationd` に LLDB で patch を適用する代わりに、研究者は OpenCore を使用して QEMU/KVM 上で macOS を実行し、VM の SMBIOS を通じて候補となる identity を指定しました。変更されていない macOS enrollment stack が、暗号化された Apple との exchange を実行しました。したがって、publicly leaked したシリアル番号や有効に見える候補は、対応する物理 Mac を所有していなくてもテストできます。ただし、成功するには、そのシリアル番号が組織に割り当てられており、かつ組織の enrollment path の認証が不十分である必要があります。<sup>[[3]](#references)</sup>

認可された lab device では、関連する OpenCore の `PlatformInfo` 値に product model と serial が含まれます（実際の deployment では、ROM と UUID も内部的に整合させます）。<sup>[[3]](#references)</sup>
```xml
<key>SystemProductName</key>
<string>iMacPro1,1</string>
<key>SystemSerialNumber</key>
<string>AUTHORIZED_TEST_SERIAL</string>
```
同じ調査で、private file `/var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck` 内に `CheckProfilesFetchRateLimit` state があることも特定されました。この check は client 側で維持されていたため、保存されている time values を変更することで回避できました。これらの path は undocumented で、version に依存しますが、現在の macOS build を評価する際の reversing pivot として役立ちます。<sup>[[3]](#references)</sup>
```bash
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.profilesDEPTimerCheck 2>/dev/null
sudo plutil -p /var/db/ConfigurationProfiles/Settings/.cloudConfigRecordFound 2>/dev/null
```
2つ目の artifact では、cached activation record が開示される可能性があります。これには、フローが直接の `ConfigurationURL` を使用するのか、認証付きの `ConfigurationWebURL` を使用するのかも含まれます。案内されているフローと、MDM固有の legacy enrollment endpoint の両方をテストしてください。メインの web flow でのみ SSO を有効にしても、並行して存在する直接 endpoint は保護されません。プロトコルの完全なシーケンスについては、[macOS MDM overview](README.md) を参照してください。<sup>[[3]](#references)</sup>

### Enrollment 後の Secret Hunting

rogue enrollment は単なる入口にすぎません。enrollment 後は、配布されたすべての profile、bootstrap policy、package-repository configuration、agent installation script、self-service item を調査してください。2025年の research では、Wi-Fi credentials、共有された local-administrator passwords、署名付き cloud-storage URLs、webhook URLs、security-agent activation data、MDM/API credentials の例が確認されました。配布された script 内の tenant API credential により、1つの rogue endpoint が他の managed devices の制御へとつながる可能性があるため、稼働中の filesystem と、downloaded/cached policy content の両方を検索してください。<sup>[[3]](#references)</sup>

有用な review targets には次のものがあります：<sup>[[3]](#references)</sup>

- インストール済みの `.mobileconfig` payload と Configuration Profiles database。
- account の作成や EDR/VPN agent のインストールを行う PreStage/bootstrap scripts と packages。
- Munki またはその他の package repository URLs、特に bearer/SAS-style signatures を含む query strings。
- self-service catalogs と、それを支える policy APIs。enrollment SSO policy を適用しない可能性がある legacy routes も含みます。
- `password`、`token`、`secret`、`Authorization`、webhook hostnames、vendor API endpoints を対象とした shell history と cached policy output。

### Trust Boundary の Hardening

serial number は inventory/routing attribute として扱い、**possession の証明とはみなさないでください**。enrollment と self service には user authentication を必須とし、device ごとに unique な local administrator passwords を生成してください。また、tenant API credentials や再利用可能な infrastructure secrets を profiles や scripts に埋め込まないでください。避けられない bootstrap token は短期間のみ有効にし、provisioning 対象の単一の action と device に限定してください。<sup>[[3]](#references)</sup>

macOS 14 以降を実行する Apple-silicon Macs では、Managed Device Attestation により identity を Secure Enclave に cryptographically bind できます。Apple-rooted attestation には、fresh nonce に加えて serial number、UDID、OS version、SIP state、secure-boot state を含めることができ、ACME はその後 hardware-bound client identity を発行できます。その identity を使用して MDM channel を保護し、高価値な certificates、VPN access、その他の resources へのアクセスを制御してください。ただし、device attestation が証明するのは operator ではなく device であるため、個別の user authentication も維持してください。<sup>[[4]](#references)</sup>

## DEP と MDM Vulnerabilities の潜在的な影響

research では、重大な security concerns が明らかになりました：

1. **Information Disclosure**: DEP-registered serial number を提供することで、DEP profile に含まれる機密性の高い organizational information を取得できます。<sup>[[1]](#references)</sup>



## References

- [1] [Duo Labs — MDM Me Maybe: Device Enrollment Program Security](https://duo.com/labs/research/mdm-me-maybe)
- [2] [Apple Platform Deployment — Automated Device Enrollment](https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web)
- [3] [Black Hat Asia 2025 — Impostor Syndrome: Rogue Device Enrolments を使用した Apple MDMs の Hacking](https://i.blackhat.com/Asia-25/Asia-25-Molnar-Impostor-Syndrome-Hacking-Apple-MDMs.pdf)
- [4] [Apple Platform Security — Managed Device Attestation](https://support.apple.com/guide/security/managed-device-attestation-sec8a37b4cb2/web)
{{#include ../../../banners/hacktricks-training.md}}
