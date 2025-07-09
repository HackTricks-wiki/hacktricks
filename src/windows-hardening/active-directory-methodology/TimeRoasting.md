## TimeRoasting

timeRoasting，主要原因是微软在其对NTP服务器的扩展中留下的过时身份验证机制，称为MS-SNTP。在该机制中，客户端可以直接使用任何计算机帐户的相对标识符（RID），域控制器将使用计算机帐户的NTLM哈希（由MD4生成）作为生成响应数据包的**消息认证码（MAC）**的密钥。

攻击者可以利用该机制在不进行身份验证的情况下获取任意计算机帐户的等效哈希值。显然，我们可以使用像Hashcat这样的工具进行暴力破解。

具体机制可以在[官方Windows文档的MS-SNTP协议](https://winprotocoldoc.z19.web.core.windows.net/MS-SNTP/%5bMS-SNTP%5d.pdf)的3.1.5.1节“身份验证请求行为”中查看。

在文档中，3.1.5.1节涵盖了身份验证请求行为。
![](../../images/Pasted%20image%2020250709114508.png)
可以看出，当ExtendedAuthenticatorSupported ADM元素设置为`false`时，原始Markdown格式得以保留。

>原文引用：
>>如果ExtendedAuthenticatorSupported ADM元素为false，则客户端必须构造一个客户端NTP请求消息。客户端NTP请求消息的长度为68字节。客户端按照2.2.1节的描述设置客户端NTP请求消息的认证字段，将RID值的最低有效31位写入认证器的密钥标识符子字段的最低有效31位，然后将密钥选择器值写入密钥标识符子字段的最高有效位。

在文档第4节协议示例第3点

>原文引用：
>>3. 在接收到请求后，服务器验证接收到的消息大小为68字节。如果不是，服务器要么丢弃请求（如果消息大小不等于48字节），要么将其视为未认证请求（如果消息大小为48字节）。假设接收到的消息大小为68字节，服务器从接收到的消息中提取RID。服务器使用它调用NetrLogonComputeServerDigest方法（如[MS-NRPC]第3.5.4.8.2节所指定）来计算加密校验和，并根据接收到的消息中密钥标识符子字段的最高有效位选择加密校验和，如3.2.5节所述。然后，服务器向客户端发送响应，将密钥标识符字段设置为0，将加密校验和字段设置为计算出的加密校验和。

根据上述微软官方文档的描述，用户不需要任何身份验证；他们只需填写RID以发起请求，然后就可以获得加密校验和。加密校验和在文档的3.2.5.1.1节中进行了说明。

>原文引用：
>>服务器从客户端NTP请求消息的认证器字段的密钥标识符子字段的最低有效31位中检索RID。服务器使用NetrLogonComputeServerDigest方法（如[MS-NRPC]第3.5.4.8.2节所指定）使用以下输入参数计算加密校验和：
>>>![](../../images/Pasted%20image%2020250709115757.png)

加密校验和是使用MD5计算的，具体过程可以参考文档内容。这为我们执行烤制攻击提供了机会。

## how to attack

引用至 https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-timeroasting/

[SecuraBV/Timeroast](https://github.com/SecuraBV/Timeroast) - Tom Tervoort的Timeroasting脚本
```
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt
```

