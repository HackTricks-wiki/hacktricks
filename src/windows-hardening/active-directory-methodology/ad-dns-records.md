# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

デフォルトでは、Active Directoryの**すべてのユーザー**がドメインまたはフォレストDNSゾーン内の**すべてのDNSレコードを列挙**できます。これはゾーン転送に似ています（ユーザーはAD環境内のDNSゾーンの子オブジェクトをリストできます）。

ツール[**adidnsdump**](https://github.com/dirkjanm/adidnsdump)は、内部ネットワークの偵察目的でゾーン内の**すべてのDNSレコードの列挙**と**エクスポート**を可能にします。
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
詳細については、[https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)をお読みください。

{{#include ../../banners/hacktricks-training.md}}
