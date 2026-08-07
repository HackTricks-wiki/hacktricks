# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## 基本 Payload

- **简单列表：** 每行只包含一个条目的列表
- **运行时文件：** 在运行时读取的列表（不会加载到内存中），用于支持大型列表
- **大小写修改：** 对字符串列表应用一些更改（不变、转换为小写、转换为大写、Proper name——首字母大写，其余字母小写——、Proper Name——首字母大写，其余字母保持不变）。
- **数字：** 使用 Z 步长或随机方式生成从 X 到 Y 的数字。
- **Brute Forcer：** 字符集、最小和最大长度。

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)：通过向 burpcollab 发送 DNS requests 来执行命令并获取输出的 Payload。

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
