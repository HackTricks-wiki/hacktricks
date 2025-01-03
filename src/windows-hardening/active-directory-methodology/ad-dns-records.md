# AD DNS レコード

{{#include ../../banners/hacktricks-training.md}}

デフォルトでは、Active Directory の **すべてのユーザー** がドメインまたはフォレスト DNS ゾーン内の **すべての DNS レコードを列挙** できます。これはゾーン転送に似ています（ユーザーは AD 環境内の DNS ゾーンの子オブジェクトをリストできます）。

ツール [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) は、内部ネットワークの偵察目的でゾーン内の **すべての DNS レコードの列挙** と **エクスポート** を可能にします。
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
詳細については、[https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)をお読みください。

{{#include ../../banners/hacktricks-training.md}}
