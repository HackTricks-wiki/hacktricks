# Nmap Summary \(ESP\)

```text
nmap -sV -sC -O -n -oA nmapscan 192.168.0.1/24
```

 **-iL** lista\_IPs

**-iR** numero --&gt; Número de Ips aleatorias, se pueden excluir posibles Ips con **--exclude &lt;Ips&gt;** o **--excludefile &lt;fichero&gt;**

**Descubrimiento de equipos:**

Podemos usar máscaras/24

**-sL**: No es invasivo, lista los objetivos realizando peticiones de DNS para resolver nombres. Sirve para saber si por ejemplo www.prueba.es/24 todas las Ips son objetivos nuestros.

Por defecto Nmap lanza una fase de descubrimiento que consta de: -PA80 -PS443 -PE -PP

**-Pn** No ping --&gt; útil **si se sabe que todos están activos** \(sino lo estuviera alguno se podría perder mucho tiempo, pero también saca falsos negativos esta opción diciendo que no esta activo\), impide la fase de descubirmiento

**-sn** No port scan: Tras completar fase de reconocimiento **no analiza puertos.** Es relativamente sigilosa, y permite un pequeño reconocimiento de la red. Con privilegios envía un ACK \(-PA\) al 80, un SYN\(-PS\) al 443 y un echo request y un Timestamp request, sin privilegios siempre completa conexiones. Si el objetivo es de la red, solo usa ARP\(-PR\). Si se usa con otra opción solo se lanzan los paquetes de la otra opción.

**-PR** Ping ARP: Se usa por defecto cuando se analizan equipos de nuestra red, es más rápido que usar pings. Si no se quiere usar paquetes ARP hay que usar --send-ip.

**-PS&lt;puertos&gt;** SYN: envía paquetes de SYN a los que si responde SYN/ACK es que esta abierto\(al que se reponde con RST para no acabar la conexión\), si responde RST esta cerrado y si no responde es inalcanzable. En caso de no tener privilegios automáticamente se usa una conexión total. Si no se dan puertos, lo lanza al 80.

**-PA&lt;puertos&gt;** ACK: Como la anterior pero con ACK, combinando ambas se obtienen mejores resultados.

**-PU&lt;puertos&gt;** UDP: El objetivo es el contrario, se envían a puertos que se espera que estén cerrados. Algunos firewall solo revisan conexiones TCP. Si está cerrado se responde con port unreachable, si se responde con otro icmp o no se responde se deja como destino inalcanzable.

**-PE, -PP, -PM** PINGS ICMP:echo replay, timestamp y addresmask. Se lanzan para descubrir si el objetivo esta activo

**-PY&lt;puertos&gt;** SCTP: Envía sondas SCTP INIT al 80 por defecto, se puede responder INIT-ACK\(abierto\) o ABORT\(cerrado\) o nada o ICMP inalcanzable\(inactivo\)

-**PO&lt;protocolos&gt;:** Se indica un protocolo en las cabeceras, por defecto 1\(ICMP\), 2\(IGMP\) y 4\(Encap IP\). Para los protocolos ICMP, IGMP, TCP \(6\) Y UDP \(17\) se envían las cabeceras del protocolo, para el resto solo se envía la cabecera IP. EL objetivo de esto es que por la malformación de las cabeceras, se responda Protocolo inalcanzable o respuestas del mismo protocolo para saber si está levantado.

**-n** No DNS

**-R** DNS siempre

**Técnicas de escaneo de puertos:**

**-sS** --&gt; No completa la conexión por lo que no deja rastro, muy buena si se puede usar. \(privilegios\) Es la que se usa por defecto

**-sT** --&gt; Completa la conexión, por lo que sí que deja rastro, pero seguro que se puede usar. Por defecto sin privilegios.

**-sU** --&gt; Más lenta, para UDP. Ppalmente: DNS\(53\), SNMP\(161,162\), DHCP\(67 y 68\), \(-sU53,161,162,67,68\): abierto\(respuesta\), cerrado\(puerto inalcanzable\), filtrado \(otro ICMP\), abierto/filtrado \(nada\). En caso de tener abierto/filtrado, -sV envía numerosas peticiones para detectar alguna de las versiones que nmap soporta pudiendo detectar el auténtico estado. Aumenta mucho el tiempo.

**-sY** --&gt; Protocolo SCTP no llega a establecer la conexión, por lo que no hay registros, funciona como -PY

**-sN,-sX,-sF** --&gt; Null, Fin, Xmas, sirven pueden penetrar algunos firewall y sacar información. Se basan en que los equipos que cumplan el estándar deberán responder con RST todas las peticiones que no tengan levantadas los lags de SYN, RST o ACK: abierto/filtrado\(nada\), cerrados\(RST\), filtrado \(ICMP inalcanzable\). No fiable en WIndows, CIsco, BSDI y OS/400. En unix sí.

**-sM Maimon scan:** Envía flags FIN y ACK, usado para BSD, actualmente devolverá todo como cerrado.

**-sA, sW** --&gt; ACK y Window, sirve para detectar firewalls, para saber si los puertos están filtrados o no. El -sW sí distingue entre abiertos/cerrados ya que los abiertos responden con un valor de window distinto: abiertos\(RST con ventana distinto de 0\), cerrado \(RST ventana = 0\), filtrado \(ICMP inalcanzable o nada\). No todos los equipos funcionan así, así que si sale todo cerrado, es que no funciona, si salen unos pocos abiertos es que funciona bien, y si salen muchos abiertos y pocos cerrados, es que funciona al revés.

**-sI Idle scan** --&gt; Para los casos en los que hay un firewall activo pero que sabemos que este no filtra a una determinada Ip \(o cuando queremos simplemente anonimato\) podemos usar el escáner zombie \(sirve para todos los puertos\), para buscar posibles zombies podemos usar el scrpit ipidseq o el exploit auxiliary/scanner/ip/ipidseq. Este escaner se basa en el número IPID de los paquetes IP

**--badsum --&gt;** Envían la suma mal, los equipos descartarían los paquetes, pero los firewall podrían responder algo, sirve para detectar firewalls

**-sZ** --&gt; Escaner “raro” de SCTP, al enviar sondas con fragmentos cookie echo deben ser eliminadas si esta abierto o respondidas con ABORT si cerrado. Puede traspasar firewalls que no traspasa el init, lo malo es que no distingue entre filtrado y abierto.

**-sO** --&gt; Protocol Ip scan: Envía cabeceras mal y vacías en las que a veces no se distingue ni el protocolo. Si llega ICMP unreachable protocol esta cerrado, si llega unreachable port esta abierto, si llega otro error, filtrado, si no llega nada, abierto\|filtrado

**-b&lt;servidor&gt;** FTPhost--&gt; Sirve para escanear un host desde otro, eso lo hace conectándose el ftp de otra máquina y pidiendole que envía archivos a los puertos que se quiera escanear de otra máquina, según las respuestas sabremos si están abiertos o no. \[&lt;usuario&gt;:&lt;contraseña&gt;@\]&lt;servidor&gt;\[:&lt;puerto&gt;\] Casi todos los servidores ftps ya no dejan hacer esto y por lo tanto ya tiene poca utilidad práctica,

**Centrar análisis:**

**-p:** Sirve para dar los puertos a escanear. Para seleccionar los 65335: **-p-** o **-p all**. Nmap tiene una clasificaación interna según su popularidad. Por defecto usa los 1000 ppales. Con **-F** \(fast scan\) analiza los 100 ppales. Con **--top-ports &lt;numero&gt;** Analiza ese numero de ppales \(de 1 hasta los 65335\). Comprueba los puertos en orden aleatorio, para que eso no pase **-r**. También podemos seleccionar puertos: 20-30,80,443,1024- Esto ultimo significa que mire en adelante del 1024. También podemos agrupar los puertos por protocolos: U:53,T:21-25,80,139,S:9. También podemos escoger un rango dentro de los puertos populares de nmap: -p \[-1024\] analiza hasta el 1024 de los incluidos en nmap-services. **--port-ratio &lt;ratio&gt;** Analiza los puertos más comúnes que un ratio que debe estar entre 0 y 1

**-sV** Escaneado de versión, se puede regular la intensidad de 0 a 9, por defecto 7.

**--version-intensity &lt;numero&gt;** Regulamos la intensidad, de forma que cuanto más bajo solo lanzará las sondas más probables, pero no todas. Con esto podemos acortar considerablemente el tiempo de escaneo UDP

**-O** Deteccion de os

**--osscan-limit** Para escanear bien un host se necesita que al menos haya 1 puerto abierto y otro cerrado, si no se da esta condición y hemos puesto esto, no intenta hacer predicción de os \(ahorra tiempo\)

**--osscan-guess** Cuando la detección de os no es perfecta esto hace que se esfuerce más

**Scripts**

--script _&lt;filename&gt;_\|_&lt;category&gt;_\|_&lt;directory&gt;_\|_&lt;expression&gt;_\[,...\]

Para usar los de por efecto vale con -sC o --script=default

Los tipos que hay son de: auth, broadcast, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, and vuln

* **Auth:** ejecuta todos sus _scripts_ disponibles para autenticación
* **Default:** ejecuta los _scripts_ básicos por defecto de la herramienta
* **Discovery:** recupera información del _target_ o víctima
* **External:** _script_ para utilizar recursos externos
* **Intrusive:** utiliza _scripts_ que son considerados intrusivos para la víctima o _target_
* **Malware:** revisa si hay conexiones abiertas por códigos maliciosos o _backdoors_ \(puertas traseras\)
* **Safe:** ejecuta _scripts_ que no son intrusivos
* **Vuln:** descubre las vulnerabilidades más conocidas
* **All:** ejecuta absolutamente todos los _scripts_ con extensión NSE disponibles

Para buscar scripts:

 **nmap --script-help="http-\*" -&gt; Los que empiecen por http-**

 **nmap --script-help="not intrusive" -&gt; Todos menos esos**

 **nmap --script-help="default or safe" -&gt; Los que estan en uno o en otro o en ambos**

 **nmap --script-help="default and safe" --&gt; Los que estan en ambos**

 **nmap --script-help="\(default or safe or intrusive\) and not http-\*"**

--script-args _&lt;n1&gt;_=_&lt;v1&gt;_,_&lt;n2&gt;_={_&lt;n3&gt;_=_&lt;v3&gt;_},_&lt;n4&gt;_={_&lt;v4&gt;_,_&lt;v5&gt;_}

--script-args-file _&lt;filename&gt;_

--script-help _&lt;filename&gt;_\|_&lt;category&gt;_\|_&lt;directory&gt;_\|_&lt;expression&gt;_\|all\[,...\]

--script-trace ---&gt; Da info de como va elscript

--script-updatedb

**Para usar un script solo hay que poner: namp --script Nombre\_del\_script objetivo** --&gt; Al poner el script se ejecutará tanto el script como el escaner, asi que tambien se pueden poner opciones del escaner, podemos añadir **“safe=1”** para que se ejecuten solo los que sean seguros.

**Control tiempo**

**Nmap puede modificar el tiempo en segundos, minutos, ms:** --host-timeout arguments 900000ms, 900, 900s, and 15m all do the same thing.

Nmap divide el numero total de host a escanear en grupos y analiza esos grupos en bloques de forma que hasta que no han sido analizados todos, no pasa al siguiente bloque \(y el usuario tampoco recibe ninguna actualización hasta que se haya analizado el bloque\) de esta forma, es más óptimo para nmap usar grupos grandes. Por defecto en clase C usa 256.

Se puede cambiar con**--min-hostgroup** _**&lt;numhosts&gt;**_**;** **--max-hostgroup** _**&lt;numhosts&gt;**_ \(Adjust parallel scan group sizes\)

Se puede controlar el numero de escaners en paralelo pero es mejor que no \(nmpa ya incorpora control automatico en base al estado de la red\): **--min-parallelism** _**&lt;numprobes&gt;**_**;** **--max-parallelism** _**&lt;numprobes&gt;**_

Podemos modificar el rtt timeout, pero no suele ser necesario: **--min-rtt-timeout** _**&lt;time&gt;**_**,** **--max-rtt-timeout** _**&lt;time&gt;**_**,** **--initial-rtt-timeout** _**&lt;time&gt;**_

Podemos modificar el numero de intentos:**--max-retries** _**&lt;numtries&gt;**_

Podemos modificar el tiempo de escaneado de un host: **--host-timeout** _**&lt;time&gt;**_

Podemos modificar el tiempo entre cada prueba para que vaya despacio: **--scan-delay** _**&lt;time&gt;**_**;** **--max-scan-delay** _**&lt;time&gt;**_

Podemos modificar el numero de paquetes por segundo: **--min-rate** _**&lt;number&gt;**_**;** **--max-rate** _**&lt;number&gt;**_

Muchos puertos tardan mucho en responder al estar filtrados o cerrados, si solo nos interesan los abiertos, podemos ir más rápido con: **--defeat-rst-ratelimit**

Para definir lo agresivo que queremos que sea nmap: -T paranoid\|sneaky\|polite\|normal\|aggressive\|insane

-T \(0-1\)

-T0 --&gt; Solo se escanea 1 puerto a la vez y se espera 5min hasta el siguiente

-T1 y T2 --&gt; Muy parecidos pero solo esperan 15 y 0,4seg respectivamente enttre cada prueba

-T3 --&gt; Funcionamiento por defecto, incluye en paralelo

-T4 --&gt; --max-rtt-timeout 1250ms --min-rtt-timeout 100ms --initial-rtt-timeout 500ms --max-retries 6 --max-scan-delay 10ms

-T5 --&gt; --max-rtt-timeout 300ms --min-rtt-timeout 50ms --initial-rtt-timeout 250ms --max-retries 2 --host-timeout 15m --max-scan-delay 5ms

**Firewall/IDS**

No dejan pasar a puertos y analizan paquetes.

**-f** Para fragmentar paquetes, por defecto los fragmenta en 8bytes después de la cabecera, para especificar ese tamaño usamos ..mtu \(con esto, no usar -f\), el offset debe ser multiplo de 8. **Escaners de version y scripts no soportan la fragmentacion**

**-D decoy1,decoy2,ME** Nmap envia escaneres pero con otras direcciones IPs como origen, de esta forma te esconden a ti. Si pones el ME en la lista, nmap te situara ahi, mejor poner 5 o 6 antes de ti para que te enmascaren completamente. Se pueden generar iPs aleatorias con RND:&lt;numero&gt; Para generar &lt;numero&gt; de Ips aleatorias. No funcionan con detector de versiones sin conexion de TCP. Si estas dentro de una red, te interesa usar Ips que esten activas, pues sino será muy facil averiguar que tu eres la unica activa.

Para usar Ips aleatorias: nmap-D RND: 10 Ip\_objetivo

**-S IP** Para cuando Nmap no pilla tu dirección Ip se la tienes que dar con eso. También sirve para hacer pensar que hay otro objetivo escaneandoles.

**-e &lt;interface&gt;** Para elegir la interfaz

Muchos administradores dejan puertos de entrada abiertos para que todo funcione correctamente y les es más fácil que buscar otra solución. Estos pueden ser los puertos DNS o los de FTP... para busca esta vulnerabilidad nmap incorpora: **--source-port** _**&lt;portnumber&gt;**_**;-g** _**&lt;portnumber&gt;**_ _Son equivalentes_

**--data** _**&lt;hex string&gt;**_ Para enviar texto hexadecimal: --data 0xdeadbeef and --data \xCA\xFE\x09

**--data-string** _**&lt;string&gt;**_ Para enviar un texto normal: --data-string "Scan conducted by Security Ops, extension 7192"

**--data-length** _**&lt;number&gt;**_ Nmap envía solo cabeceras, con esto logramos que añada a estar un numero de bytes mas \(que se generaran aleatoriamente\)

Para configurar el paquete IP completamente usar **--ip-options**

If you wish to see the options in packets sent and received, specify --packet-trace. For more information and examples of using IP options with Nmap, see [http://seclists.org/nmap-dev/2006/q3/52](http://seclists.org/nmap-dev/2006/q3/52).

**--ttl** _**&lt;value&gt;**_

**--randomize-hosts** Para que el ataque sea menos obvio

**--spoof-mac** _**&lt;MAC address, prefix, or vendor name&gt;**_ Para cambiar la mac ejemplos: Apple, 0, 01:02:03:04:05:06, deadbeefcafe, 0020F2, and Cisco

**--proxies** _**&lt;Comma-separated list of proxy URLs&gt;**_ Para usar proxies, a veces un proxy no mantiene tantas conexiones abiertas como nmap quiere por lo que habria que modificar el paralelismo: --max-parallelism

**-sP** Para descubrir host en la red en la que estamos por ARP

Muchos administradores crean una regla en el firewall que permite pasar todos los paquetes que provienen de un puerto en particular \(como el 20,53 y 67\), podemos decire a nmap que mande nuestros paquetes desde esos puertos: **nmap --source-port 53 Ip**

**Salidas**

**-oN file** Salida normal

**-oX file** Salida XML

**-oS file** Salida de script kidies

**-oG file** Salida grepable

**-oA file** Todos menos -oS

**-v level** verbosity

**-d level** debugin

**--reason** Porqué del host y estado

**--stats-every time** Cada ese tiempo nos dice como va

**--packet-trace** Para ver que paquetes salen se pueden especificar filtros como: --version-trace o --script-trace

**--open** muestra los abiertos, abiertos\|filtrados y los no filtrados

**--resume file** Saca un resumen

**Miscelanea**

**-6** Permite ipv6

**-A** es lo mismo que -O -sV -sC --traceroute

**Run time**

Mientras corre nmap podemos cambiar opciones:

v / V Increase / decrease the verbosity level

d / D Increase / decrease the debugging Level

p / P Turn on / off packet tracing

? Print a runtime interaction help screen

**Vulscan**

Script de nmap que mira las versiones de los servicios obtenidos en una base de datos offline \(que descarga de otras muy importantes\) y devuelve las posibles vulnerabilidades

Las BD que usa son:

1. Scipvuldb.csv \| [http://www.scip.ch/en/?vuldb](http://www.scip.ch/en/?vuldb)
2. Cve.csv \| [http://cve.mitre.org](http://cve.mitre.org/)
3. Osvdb.csv \| [http://www.osvdb.org](http://www.osvdb.org/)
4. Securityfocus.csv \| [http://www.securityfocus.com/bid/](http://www.securityfocus.com/bid/)
5. Securitytracker.csv \| [http://www.securitytracker.com](http://www.securitytracker.com/)
6. Xforce.csv \| [http://xforce.iss.net](http://xforce.iss.net/)
7. Exploitdb.csv \| [http://www.exploit-db.com](http://www.exploit-db.com/)
8. Openvas.csv \| [http://www.openvas.org](http://www.openvas.org/)

Para descargarlo e instalarlo en la carpeta de Nmap:

wget http://www.computec.ch/projekte/vulscan/download/nmap\_nse\_vulscan-2.0.tar.gz && tar -czvf nmap\_nse\_vulscan-2.0.tar.gz vulscan/ && sudo cp -r vulscan/ /usr/share/nmap/scripts/

También habría que descargar los paquetes de las BD y añadirlos a /usr/share/nmap/scripts/vulscan/

Uso:

Para usar todos: sudo nmap -sV --script=vulscan HOST\_A\_ESCANEAR

Para usar una BD específica: sudo nmap -sV --script=vulscan --script-args vulscandb=cve.csv HOST\_A\_ESCANEAR

