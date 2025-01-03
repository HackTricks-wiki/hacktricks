{{#include ../banners/hacktricks-training.md}}

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

# CBC - 密码块链接

在 CBC 模式下，**前一个加密块用作 IV**，与下一个块进行异或操作：

![https://defuse.ca/images/cbc_encryption.png](https://defuse.ca/images/cbc_encryption.png)

要解密 CBC，需进行**相反的** **操作**：

![https://defuse.ca/images/cbc_decryption.png](https://defuse.ca/images/cbc_decryption.png)

注意需要使用**加密** **密钥**和**IV**。

# 消息填充

由于加密是在**固定** **大小** **块**中进行的，通常需要在**最后** **块**中进行**填充**以完成其长度。\
通常使用**PKCS7**，它生成的填充**重复**所需的**字节** **数**以**完成**块。例如，如果最后一个块缺少 3 个字节，填充将是 `\x03\x03\x03`。

让我们看更多的例子，使用**2 个长度为 8 字节的块**：

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

注意在最后一个例子中，**最后一个块是满的，因此只生成了一个填充块**。

# 填充 oracle

当应用程序解密加密数据时，它会首先解密数据；然后会移除填充。在清理填充的过程中，如果**无效填充触发可检测的行为**，则存在**填充 oracle 漏洞**。可检测的行为可以是**错误**、**缺少结果**或**响应变慢**。

如果你检测到这种行为，你可以**解密加密数据**，甚至**加密任何明文**。

## 如何利用

你可以使用 [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) 来利用这种漏洞，或者直接进行
```
sudo apt-get install padbuster
```
为了测试一个网站的cookie是否存在漏洞，你可以尝试：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**编码 0** 意味着使用 **base64**（但还有其他可用的编码，请查看帮助菜单）。

您还可以 **利用此漏洞加密新数据。例如，假设 cookie 的内容是 "**_**user=MyUsername**_**"，那么您可以将其更改为 "\_user=administrator\_"，并在应用程序中提升权限。您还可以使用 `paduster` 指定 -plaintext** 参数来实现这一点：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
如果网站存在漏洞，`padbuster`将自动尝试查找何时发生填充错误，但您也可以使用**-error**参数指示错误消息。
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## 理论

**总结**来说，您可以通过猜测可以用于创建所有**不同填充**的正确值来开始解密加密数据。然后，填充oracle攻击将从末尾到开头解密字节，猜测哪个将是**创建1、2、3等填充的正确值**。

![](<../images/image (629) (1) (1).png>)

想象一下，您有一些加密文本，占据**2个块**，由**E0到E15**的字节组成。\
为了**解密**最后一个**块**（**E8**到**E15**），整个块通过“块密码解密”，生成**中间字节I0到I15**。\
最后，每个中间字节与之前的加密字节（E0到E7）进行**异或**运算。因此：

- `C15 = D(E15) ^ E7 = I15 ^ E7`
- `C14 = I14 ^ E6`
- `C13 = I13 ^ E5`
- `C12 = I12 ^ E4`
- ...

现在，可以**修改`E7`直到`C15`为`0x01`**，这也将是一个正确的填充。因此，在这种情况下：`\x01 = I15 ^ E'7`

因此，找到E'7后，可以**计算I15**：`I15 = 0x01 ^ E'7`

这使我们能够**计算C15**：`C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

知道**C15**后，现在可以**计算C14**，但这次是通过暴力破解填充`\x02\x02`。

这个暴力破解与之前的复杂度相同，因为可以计算出值为0x02的`E''15`：`E''7 = \x02 ^ I15`，因此只需找到生成**`C14`等于`0x02`的**`E'14`。\
然后，按照相同的步骤解密C14：**`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**按照这个链条，直到您解密整个加密文本。**

## 漏洞检测

注册一个账户并使用该账户登录。\
如果您**多次登录**并始终获得**相同的cookie**，那么应用程序中可能**存在问题**。每次登录时**返回的cookie应该是唯一的**。如果cookie**总是**相同的，它可能始终有效，并且**无法使其失效**。

现在，如果您尝试**修改**该**cookie**，您会看到应用程序返回一个**错误**。\
但是，如果您暴力破解填充（例如使用padbuster），您可以获得另一个有效的cookie，适用于不同的用户。这个场景很可能对padbuster存在漏洞。

## 参考

- [https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

<figure><img src="/..https:/pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{{#include ../banners/hacktricks-training.md}}
