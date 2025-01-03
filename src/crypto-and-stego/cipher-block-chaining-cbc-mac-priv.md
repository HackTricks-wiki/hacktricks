{{#include ../banners/hacktricks-training.md}}

# CBC

如果**cookie**仅仅是**用户名**（或者cookie的第一部分是用户名），并且你想要冒充用户名“**admin**”。那么，你可以创建用户名**"bdmin"**并**暴力破解**cookie的**第一个字节**。

# CBC-MAC

**密码块链消息认证码**（**CBC-MAC**）是一种用于密码学的方法。它通过逐块加密消息来工作，每个块的加密与前一个块相链接。这个过程创建了一个**块链**，确保即使改变原始消息的一个比特，也会导致最后一个加密数据块的不可预测变化。要进行或逆转这样的变化，需要加密密钥，以确保安全性。

要计算消息m的CBC-MAC，可以在零初始化向量下以CBC模式加密m，并保留最后一个块。下图勾勒了使用秘密密钥k和块密码E计算由块组成的消息的CBC-MAC的过程![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5)：

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Vulnerability

在CBC-MAC中，通常**使用的IV是0**。\
这是一个问题，因为两个已知消息（`m1`和`m2`）独立生成两个签名（`s1`和`s2`）。所以：

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

然后，由m1和m2连接而成的消息（m3）将生成两个签名（s31和s32）：

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**这可以在不知道加密密钥的情况下计算。**

想象一下你在**8字节**块中加密名称**Administrator**：

- `Administ`
- `rator\00\00\00`

你可以创建一个名为**Administ**（m1）的用户名并获取签名（s1）。\
然后，你可以创建一个用户名，称为`rator\00\00\00 XOR s1`的结果。这将生成`E(m2 XOR s1 XOR 0)`，即s32。\
现在，你可以将s32用作完整名称**Administrator**的签名。

### Summary

1. 获取用户名**Administ**（m1）的签名，即s1
2. 获取用户名**rator\x00\x00\x00 XOR s1 XOR 0**的签名，即s32**。**
3. 将cookie设置为s32，它将是用户**Administrator**的有效cookie。

# Attack Controlling IV

如果你可以控制使用的IV，攻击可能会非常简单。\
如果cookie仅仅是加密的用户名，要冒充用户“**administrator**”，你可以创建用户“**Administrator**”，你将获得它的cookie。\
现在，如果你可以控制IV，你可以改变IV的第一个字节，使得**IV\[0] XOR "A" == IV'\[0] XOR "a"**，并为用户**Administrator**重新生成cookie。这个cookie将有效地**冒充**用户**administrator**，使用初始**IV**。

## References

更多信息请参见[https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}
