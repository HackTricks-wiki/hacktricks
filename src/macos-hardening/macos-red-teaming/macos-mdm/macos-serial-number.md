# macOS 序列号

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

不要假设每台 Mac 都拥有可解码的 12 字符序列号。Apple 的旧格式会编码制造和配置信息，但 Apple 从 2021 年开始在新产品中引入随机序列号。随机格式不会公开制造或配置详情。<sup>[[1]](#references)</sup>

### 旧版 12 字符格式

对于许多在随机格式过渡前、即 2010 年至过渡期间制造的设备，12 字符格式仍可提供有用的库存线索：<sup>[[3]](#references)</sup>

- 第 1–3 个字符标识制造地点。
- 第 4–5 个字符编码生产年份的上半年或下半年以及周数。
- 第 6–8 个字符用于区分在同一地点、同一时间生产的设备。
- 第 9–12 个字符标识型号或配置代码。

例如，`C02L13ECF8J2` 遵循这种旧版结构。社区维护的工厂映射包括：`FC`、`F`、`XA`、`XB`、`QP` 和 `G8` 等前缀代表美国地点；`RN` 代表墨西哥；`CK` 代表 Cork；`VM` 代表捷克共和国的一处 Foxconn 工厂；`SG` 或 `E` 代表新加坡；`MB` 代表马来西亚；`PT` 或 `CY` 代表韩国；`EE`、`QT` 或 `UV` 代表台湾。许多前缀（包括 `FK`、`F1`、`F2`、`W8`、`DL`、`DM`、`DN`、`YM`、`7J`、`1C`、`4H`、`WQ`、`F7`、`C0`、`C3` 和 `C7`）与中国工厂有关；`RM` 与翻新设备有关。<sup>[[3]](#references)</sup>

第 4 个字符的日期代码从 `C`（2010 年上半年）到 `Z`（2019 年下半年），之后会重复使用该序列。对于第 5 个字符，数字 `1`–`9` 表示第 1–9 周；排除元音字母和 `S` 后的字母 `C`–`Y` 表示第 10–27 周；当第 4 个字符表示某一年的下半年时，加上 26。<sup>[[3]](#references)</sup>

这些映射对于旧版设备的初步分析很有用，但不能作为来源、生产时间或真实性的权威证明。请通过 Apple 的库存数据确认结果。

为了可靠识别设备，应从设备中获取序列号，并使用 Apple 的保修覆盖范围或技术规格查询，而不是尝试根据字符位置推断型号。<sup>[[2]](#references)</sup>

### 获取序列号

图形界面会在 **Apple 菜单 > 关于本机** 中显示序列号。<sup>[[2]](#references)</sup>在 shell 中，以下任一命令都可以读取平台序列号：
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
将序列号视为标识符，而不是认证器：在做出 enrollment 或所有权决策前，通过相关的 Apple 或 MDM inventory workflow 确认设备。

## References

- [1] [MacRumors - Apple 开始过渡到随机序列号](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - 查找 Mac 机型名称和序列号](https://support.apple.com/en-us/102767)
- [3] [Beetstech - 解读 Apple 序列号背后的含义](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
