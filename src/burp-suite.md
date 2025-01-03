{{#include ./banners/hacktricks-training.md}}

# 基本有效载荷

- **简单列表：** 仅包含每行一个条目的列表
- **运行时文件：** 在运行时读取的列表（不加载到内存中）。用于支持大列表。
- **大小写修改：** 对字符串列表应用一些更改（不变，转为小写，转为大写，转为专有名词 - 首字母大写，其余小写 -，转为专有名词 - 首字母大写，其余保持不变）。
- **数字：** 使用 Z 步长或随机生成从 X 到 Y 的数字。
- **暴力破解：** 字符集，最小和最大长度。

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : 用于执行命令并通过 DNS 请求获取输出的有效载荷到 burpcollab。

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ./banners/hacktricks-training.md}}
