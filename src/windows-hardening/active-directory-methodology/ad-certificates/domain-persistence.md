# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)で共有されたドメイン持続性技術の概要です**。詳細については確認してください。

## 盗まれたCA証明書を使用した証明書の偽造 - DPERSIST1

証明書がCA証明書であることをどのように判断できますか？

いくつかの条件が満たされる場合、証明書がCA証明書であることが判断できます：

- 証明書はCAサーバーに保存されており、その秘密鍵はマシンのDPAPIによって保護されているか、オペレーティングシステムがサポートしている場合はTPM/HSMなどのハードウェアによって保護されています。
- 証明書の発行者（Issuer）および対象（Subject）フィールドがCAの識別名と一致します。
- "CA Version"拡張がCA証明書にのみ存在します。
- 証明書にはExtended Key Usage (EKU)フィールドがありません。

この証明書の秘密鍵を抽出するには、CAサーバー上の`certsrv.msc`ツールが、組み込みGUIを介してサポートされている方法です。それにもかかわらず、この証明書はシステム内に保存されている他の証明書とは異ならないため、[THEFT2技術](certificate-theft.md#user-certificate-theft-via-dpapi-theft2)などの方法を使用して抽出できます。

証明書と秘密鍵は、次のコマンドを使用してCertipyでも取得できます：
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
CA証明書とそのプライベートキーを`.pfx`形式で取得した後、[ForgeCert](https://github.com/GhostPack/ForgeCert)のようなツールを使用して、有効な証明書を生成できます：
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> 証明書の偽造の対象となるユーザーは、プロセスが成功するためにアクティブであり、Active Directoryで認証できる必要があります。krbtgtのような特別なアカウントのために証明書を偽造することは効果がありません。

この偽造された証明書は、指定された終了日まで**有効**であり、**ルートCA証明書が有効である限り**（通常は5年から**10年以上**）有効です。また、**マシン**にも有効であるため、**S4U2Self**と組み合わせることで、攻撃者はCA証明書が有効である限り、**任意のドメインマシンで持続性を維持**できます。\
さらに、この方法で**生成された証明書は**、CAがそれらを認識していないため、**取り消すことができません**。

## 悪意のあるCA証明書の信頼 - DPERSIST2

`NTAuthCertificates`オブジェクトは、Active Directory（AD）が利用する`cacertificate`属性内に1つ以上の**CA証明書**を含むように定義されています。**ドメインコントローラー**による検証プロセスは、認証する**証明書**の発行者フィールドに指定された**CA**に一致するエントリを`NTAuthCertificates`オブジェクトで確認することを含みます。一致が見つかれば、認証が進行します。

自己署名のCA証明書は、攻撃者がこのADオブジェクトを制御している場合、`NTAuthCertificates`オブジェクトに追加できます。通常、**Enterprise Admin**グループのメンバーと、**forest rootのドメイン**内の**Domain Admins**または**Administrators**のみがこのオブジェクトを変更する権限を与えられます。彼らは、`certutil.exe`を使用して`NTAuthCertificates`オブジェクトを編集することができ、コマンド`certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`を使用するか、[**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool)を使用します。

この機能は、ForgeCertを使用して動的に証明書を生成する以前に説明した方法と組み合わせて使用される場合に特に関連性があります。

## 悪意のある誤設定 - DPERSIST3

AD CSコンポーネントの**セキュリティ記述子の変更**を通じた**持続性**の機会は豊富です。「[ドメイン昇格](domain-escalation.md)」セクションで説明されている変更は、権限のある攻撃者によって悪意を持って実施される可能性があります。これには、以下のような敏感なコンポーネントへの「制御権」（例：WriteOwner/WriteDACLなど）の追加が含まれます：

- **CAサーバーのADコンピュータ**オブジェクト
- **CAサーバーのRPC/DCOMサーバー**
- **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`**内の任意の**子孫ADオブジェクトまたはコンテナ**（例えば、証明書テンプレートコンテナ、認証局コンテナ、NTAuthCertificatesオブジェクトなど）
- デフォルトまたは組織によってAD CSを制御する権利が委任された**ADグループ**（組み込みのCert Publishersグループおよびそのメンバーなど）

悪意のある実装の例としては、ドメイン内で**権限のある**攻撃者が、デフォルトの**`User`**証明書テンプレートに**`WriteOwner`**権限を追加し、攻撃者がその権利の主体となることが含まれます。これを利用するために、攻撃者はまず**`User`**テンプレートの所有権を自分に変更します。その後、**`mspki-certificate-name-flag`**が**1**に設定され、**`ENROLLEE_SUPPLIES_SUBJECT`**が有効になり、ユーザーがリクエストにおいて代替名を提供できるようになります。続いて、攻撃者は**テンプレート**を使用して**登録**し、代替名として**ドメイン管理者**の名前を選択し、取得した証明書をDAとして認証に利用します。

{{#include ../../../banners/hacktricks-training.md}}
