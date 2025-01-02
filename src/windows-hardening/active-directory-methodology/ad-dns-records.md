# AD DNS 记录

{{#include ../../banners/hacktricks-training.md}}

默认情况下，**Active Directory 中的任何用户**都可以**枚举域或森林 DNS 区域中的所有 DNS 记录**，类似于区域传输（用户可以列出 AD 环境中 DNS 区域的子对象）。

工具 [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) 使得**枚举**和**导出**区域中的**所有 DNS 记录**成为可能，以便于内部网络的侦查。
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
有关更多信息，请阅读 [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
