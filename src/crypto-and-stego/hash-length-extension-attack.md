# Hash Length Extension Attack

{{#include ../banners/hacktricks-training.md}}

## 攻击概述

想象一个服务器，它通过将一个**秘密**附加到一些已知的明文数据上并对该数据进行**签名**。如果你知道：

- **秘密的长度**（这也可以从给定的长度范围进行暴力破解）
- **明文数据**
- **算法（并且它对这种攻击是脆弱的）**
- **填充是已知的**
- 通常使用默认填充，因此如果满足其他三个要求，这也是
- 填充根据秘密+数据的长度而变化，这就是为什么需要秘密的长度

那么，**攻击者**可以**附加****数据**并为**之前的数据 + 附加的数据**生成一个有效的**签名**。

### 如何？

基本上，脆弱的算法首先通过**哈希一个数据块**来生成哈希，然后，从**之前**创建的**哈希**（状态）中，他们**添加下一个数据块**并**哈希它**。

然后，想象秘密是“secret”，数据是“data”，"secretdata"的MD5是6036708eba0d11f6ef52ad44e8b74d5b。\
如果攻击者想要附加字符串“append”，他可以：

- 生成64个“A”的MD5
- 将之前初始化的哈希状态更改为6036708eba0d11f6ef52ad44e8b74d5b
- 附加字符串“append”
- 完成哈希，结果哈希将是“secret” + “data” + “padding” + “append”的**有效哈希**

### **工具**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

### 参考文献

你可以在[https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)找到对这个攻击的详细解释。

{{#include ../banners/hacktricks-training.md}}
