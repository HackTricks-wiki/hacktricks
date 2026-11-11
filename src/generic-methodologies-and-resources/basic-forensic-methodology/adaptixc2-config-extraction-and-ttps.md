# Вилучення конфігурації AdaptixC2 і TTPs

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 — це модульний open-source фреймворк для post-exploitation/C2 із Windows-маяками x86/x64 (EXE/DLL/service EXE/raw shellcode) і підтримкою BOF.<sup>[[1]](#references)</sup> На цій сторінці описано:
- Як вбудовано конфігурацію, запаковану RC4, і як вилучити її з маяків
- Мережеві індикатори та індикатори профілю для HTTP/SMB/TCP-слухачів
- Поширені TTPs завантажувачів і закріплення в системі, які спостерігалися в реальних атаках, із посиланнями на відповідні сторінки про техніки Windows

В останніх upstream-релізах також з’явилися DNS/DoH-слухачі маяків і окрема родина Gopher-агентів/слухачів, тож сучасна інфраструктура Adaptix може використовувати більше поверхонь, ніж початкові HTTP/SMB/TCP, навіть якщо конкретний зразок досі використовує класичний агент-маяк.<sup>[[2]](#references)</sup>

## Профілі маяків і поля

AdaptixC2 підтримує три основні типи маяків:<sup>[[1]](#references)</sup>
- BEACON_HTTP: веб-C2 із налаштовуваними серверами/портами/SSL, методом, URI, заголовками, user-agent і власною назвою параметра
- BEACON_SMB: peer-to-peer C2 через іменований канал (інтрамережа)
- BEACON_TCP: прямі сокети, за потреби з доданим на початку маркером для маскування початку протоколу

Це структури маяків, задокументовані у відкритих аналізах Adaptix на початку його існування, і вони досі є найпоширенішою відправною точкою для вилучення даних зі зразків.<sup>[[1]](#references)</sup> Однак сучасні upstream-збірки також постачають серверні розширення `BeaconDNS` і Gopher, тож не варто припускати, що кожне активне розгортання Adaptix використовує лише інфраструктуру HTTP/SMB/TCP.<sup>[[2]](#references)</sup>

Наведений нижче опис полів і зразки JSON стосуються формату HTTP, проаналізованого у 2025 році; це не специфікація парсера для новіших upstream-збірок. Типові поля в цих зразках (після розшифрування):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – використовуються для розбору розмірів відповідей
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Останні збірки BeaconHTTP також підтримують вибір оператором ротації між кількома URI, user-agent, заголовками Host і серверами — послідовно або випадково.<sup>[[2]](#references)</sup> З погляду пошуку загроз це означає, що один заражений хост може використовувати кілька шляхів зворотного зв’язку та комбінацій заголовків, не залишаючи родину маяків, запакованих класичним RC4.

Приклад стандартного HTTP-профілю (зі збірки маяка):<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["172.16.196.1"],
  "ports": [4443],
  "http_method": "POST",
  "uri": "/uri.php",
  "parameter": "X-Beacon-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 2,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

Виявлений шкідливий HTTP-профіль (реальна атака):<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["tech-system[.]online"],
  "ports": [443],
  "http_method": "POST",
  "uri": "/endpoint/api",
  "parameter": "X-App-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 4,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

## Пакування зашифрованої конфігурації та шлях завантаження

Коли оператор натискає Create у builder, AdaptixC2 компілює зашифрований профіль у beacon. Не припускайте, що він розташований у кінці PE або shellcode: знайдіть байти профілю, просканувавши секції або простеживши виклик `getProfile()` у зразку. Формат пакування такий:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
- 4 байти: розмір конфігурації (uint32, little-endian)
- N байтів: зашифровані RC4 дані конфігурації
- 16 байтів: ключ RC4

Завантажувач beacon копіює 16-байтовий ключ із кінця та розшифровує блок із N байтів за допомогою RC4 на місці:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Практичні наслідки:<sup>[[1]](#references)</sup>
- Уся структура часто міститься в секції PE .rdata.
- Вилучення детерміноване: прочитати розмір, прочитати шифротекст цього розміру, прочитати 16-байтовий ключ, розташований одразу після нього, а потім виконати RC4-дешифрування.

## Робочий процес вилучення конфігурації (захисники)

Щоб виконати загальний первинний аналіз зразка перед вилученням beacon, див. [Malware Analysis](malware-analysis.md).

Напишіть екстрактор, що відтворює логіку beacon:<sup>[[1]](#references)</sup>
1) Знайдіть blob у PE (зазвичай у .rdata). Практичний підхід — просканувати .rdata на наявність правдоподібного формату [розмір|шифротекст|16-байтовий ключ] і спробувати виконати RC4.
2) Прочитайте перші 4 байти → розмір (uint32 LE).
3) Прочитайте наступні N=size байтів → шифротекст.
4) Прочитайте останні 16 байтів → ключ RC4.
5) Виконайте RC4-дешифрування шифротексту. Потім розберіть відкритий профіль так:
   - скалярні значення u32/boolean, як зазначено вище
   - рядки з префіксом довжини (довжина u32, за якою йдуть байти; наприкінці може бути NUL)
   - масиви: servers_count, за яким іде відповідна кількість пар [рядок, порт u32]

Python proof-of-concept для застарілого HTTP (самостійний, без зовнішніх залежностей), призначений для попередньо вилученого blob у порядку полів 2025 року. Для останніх стандартних збірок використовуйте наведений нижче парсер поточної схеми:<sup>[[1]](#references)[[11]](#references)</sup>

```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ K)
    return bytes(out)

class P:
    def __init__(self, buf: bytes):
        self.b = buf; self.o = 0
    def u32(self) -> int:
        v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
    def u8(self) -> int:
        v = self.b[self.o]; self.o += 1; return v
    def s(self) -> str:
        L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
        return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    cfg = {}
    cfg['agent_type']    = p.u32()
    cfg['use_ssl']       = bool(p.u8())
    n                    = p.u32()
    cfg['servers']       = []
    cfg['ports']         = []
    for _ in range(n):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method']   = p.s()
    cfg['uri']           = p.s()
    cfg['parameter']     = p.s()
    cfg['user_agent']    = p.s()
    cfg['http_headers']  = p.s()
    cfg['ans_pre_size']  = p.u32()
    cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
    cfg['kill_date']     = p.u32()
    cfg['working_time']  = p.u32()
    cfg['sleep_delay']   = p.u32()
    cfg['jitter_delay']  = p.u32()
    cfg['listener_type'] = 0
    cfg['download_chunk_size'] = 0x19000
    return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```

### Розбір поточних штатних HTTP- і DNS-профілів

Поточна upstream-версія спочатку містить шість little-endian значень `u32`: watermark/type агента, kill date, working time, sleep, jitter і watermark/type listener-а. Далі йдуть специфічні для HTTP дані, що починаються з однобайтового SSL flag. На відміну від застарілого прикладу, тут є списки URI, user-agent і Host header із лічильниками, за якими йдуть режим ротації та налаштування proxy. Тому застарілий parser починає зчитувати SSL flag із поля kill date і видає хибні результати для цих збірок. Довжини рядків і цілі значення в цьому профілі закодовані у форматі little-endian; упаковані рядки, якщо вони непорожні, закінчуються NUL.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

Використайте наведені вище helpers `P` і `rc4` із цим parser-ом для розшифрованого plaintext **штатного HTTP**. Не розголошуйте RC4 key у публічних звітах: HTTP-профіль може містити ім’я користувача та пароль для proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Розбір plaintext-профілю поточного штатного HTTP</summary>

```python
def parse_current_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    keys = ('agent_type', 'kill_date', 'working_time',
            'sleep_delay', 'jitter_delay', 'listener_type')
    cfg = {key: p.u32() for key in keys}
    cfg['use_ssl'] = bool(p.u8())
    count = p.u32()
    if not 0 < count <= 128:
        raise ValueError('implausible server count')
    cfg['servers'] = []
    cfg['ports'] = []
    for _ in range(count):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method'] = p.s()
    def strings():
        n = p.u32()
        if n > 128:
            raise ValueError('implausible string count')
        return [p.s() for _ in range(n)]
    cfg['uris'] = strings()
    cfg['parameter'] = p.s()
    cfg['user_agents'] = strings()
    cfg['http_headers'] = p.s()
    cfg['ans_pre_size'] = p.u32()
    cfg['ans_size'] = p.u32() + cfg['ans_pre_size']
    cfg['host_headers'] = strings()
    cfg['rotation_mode'] = p.u32()  # 0=sequential, 1=random
    cfg['proxy_type'] = p.u32()     # 0=none, 1=HTTP, 2=HTTPS
    cfg['proxy_host'] = p.s()
    cfg['proxy_port'] = p.u32()
    cfg['proxy_username'] = p.s()
    cfg['proxy_password'] = p.s()
    if p.o != len(plain):
        raise ValueError('unexpected trailing bytes or wrong schema')
    return cfg
```

</details>

Для стандартного DNS beacon прочитайте ті самі шість поширених полів `u32`, а потім рядки `domain`, `resolvers`, `doh_resolvers` і `qtype` із префіксом довжини. Прочитайте `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` і `dns_mode` як `u32`, а потім — рядок DoH user-agent із префіксом довжини. `dns_mode` розрізняє UDP, DoH і два напрямки fallback. Це окремий формат: не намагайтеся обробляти DNS plaintext через HTTP parser.<sup>[[12]](#references)[[13]](#references)</sup>

Поради:
- Для автоматизації використовуйте PE parser, щоб прочитати .rdata, а потім застосуйте sliding window: для кожного зміщення o спробуйте size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = наступні 16 байтів; розшифруйте за допомогою RC4 і перевірте, чи рядкові поля декодуються як UTF-8 і чи є довжини адекватними.
- Обробляйте профілі SMB/TCP, дотримуючись тих самих домовленостей щодо префіксів довжини.

## Власні профілі listener: не зашивайте в код лише класичну схему HTTP

Зовнішній формат пакування (`u32 size | RC4 ciphertext | 16-byte key`) можна повторно використовувати, тож налаштовані зловмисником listeners можуть використовувати той самий процес вилучення, водночас повністю змінюючи структуру розшифрованих полів.

Нещодавній показовий приклад — кампанія Tropic Trooper у березні 2026 року: вилучений Adaptix beacon не містив стандартного профілю HTTP/TCP. Натомість розшифрований blob зберігав параметри транспорту GitHub, зокрема:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (наприклад, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Практична стратегія для parser:
- Спершу виявляйте зовнішній RC4 blob звичним способом.
- Після розшифрування визначайте варіант за sentinel-рядками й адекватністю полів, а не намагайтеся одразу застосувати HTTP parser.
- До корисних sentinel-рядків належать `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, рядки у стилі named pipe або очевидно коректні масиви серверів/портів.
- Якщо HTTP parser не спрацьовує, але plaintext містить узгоджені UTF-8-рядки з префіксами довжини, збережіть зразок і спробуйте альтернативні схеми, замість того щоб відкидати його як хибне спрацювання.

У цій кампанії власний listener використовував GitHub issues як транспорт C2, а beacon звертався до `ipinfo.io`, щоб дізнатися свою зовнішню IP-адресу, оскільки GitHub API не показує оператору адресу джерела запиту жертви безпосередньо.<sup>[[5]](#references)</sup>

## Мережеві ознаки та пошук

HTTP:<sup>[[1]](#references)</sup>
- Типовий випадок: POST-запити до URI, вибраних оператором (наприклад, /uri.php, /endpoint/api)
- Власний параметр header використовується для beacon ID (наприклад, X‑Beacon‑Id, X‑App‑Id)
- User-agent, що імітують Firefox 20 або сучасні збірки Chrome
- Періодичність запитів можна визначити за sleep_delay/jitter_delay
- Новіші збірки можуть змінювати URI, user-agent, Host headers і сервери між callback-запитами. Тому кластеризуйте за рідковживаними назвами headers, шаблонами розміру відповідей, повторним використанням TLS і часом запитів, а не покладайтеся на одну пару шлях/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listeners на іменованих каналах SMB для intranet C2, коли вихідний вебтрафік обмежений
- TCP beacons можуть додавати кілька байтів перед трафіком, щоб приховати початок протоколу

Поточні типові налаштування upstream teamserver
- `profile.yaml` наразі містить teamserver `0.0.0.0:4321`, endpoint `/endpoint`, назви файлів сертифіката/ключа `server.rsa.crt` і `server.rsa.key`, а також extenders для HTTP, SMB, TCP, DNS, Beacon agent і Gopher.<sup>[[2]](#references)</sup>
- Для маршрутів без відповідності типовий обробник помилок повертає `Server: AdaptixC2` і `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Типове тіло відповіді 404 містить `AdaptixC2 404` і `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Масштабне сканування інтернету у 2026 році виявило багато відкритих teamservers на порту `4321` і багато beacon listeners на `43211`, тож обидва порти корисні для початкового пошуку, але їх не слід вважати вичерпним переліком.<sup>[[4]](#references)</sup>

Мережеві ознаки DNS/DoH listener:<sup>[[4]](#references)</sup>
- Поточний BeaconDNS extender відповідає авторитетно (`AA=true`)
- На запити, що не відповідають формату протоколу beacon, — зокрема, на імена з менш ніж 5 мітками перед налаштованим доменом — зазвичай повертається `TXT "OK"`
- Якщо базовий TTL залишити нульовим, listener використовує базове значення 10 секунд і додає до нього jitter до 59 секунд
- Тому активні зондування з короткими мітками корисні, коли HTTP listener не відкритий

## TTPs завантажувачів і закріплення, виявлені під час інцидентів

Завантажувачі PowerShell у пам’яті:<sup>[[1]](#references)</sup>
- Завантажують Base64/XOR payloads (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Виділяють unmanaged memory, копіюють shellcode, змінюють захист на 0x40 (PAGE_EXECUTE_READWRITE) через VirtualProtect.<sup>[[7]](#references)</sup>
- Виконують через динамічний виклик .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Троянізоване підписане ПЗ / завантажувачі staged shellcode:<sup>[[5]](#references)</sup>
- В одному ланцюжку Tropic Trooper 2026 року використовувався троянізований виконуваний файл SumatraPDF (завантажувач TOSHIS), який перенаправляв `_security_init_cookie` на шкідливий код замість внесення змін у точку входу PE
- Завантажувач знаходив API за допомогою хешування Adler-32, завантажував PDF-приманку, отримував shellcode другого етапу, розшифровував його за допомогою AES-128-CBC через WinCrypt (`CryptDeriveKey` із зашитим seed) і рефлексивно виконував Adaptix beacon у пам’яті
- Згодом закріплення було перенесено на scheduled tasks із нешкідливими на вигляд назвами, такими як `\MSDNSvc` або `\MicrosoftUDN`, налаштовані на повторний запуск агента приблизно кожні дві години

Перегляньте ці сторінки щодо виконання в пам’яті та особливостей AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Виявлені механізми закріплення:<sup>[[1]](#references)</sup>
- Ярлик (.lnk) у папці Startup для повторного запуску завантажувача під час входу в систему
- Ключі реєстру Run (HKCU/HKLM ...\CurrentVersion\Run), часто з нешкідливими на вигляд назвами на кшталт "Updater" для запуску loader.ps1.<sup>[[10]](#references)</sup>
- Перехоплення порядку пошуку DLL: розміщення msimg32.dll у %APPDATA%\Microsoft\Windows\Templates для вразливих процесів

Детальний розбір технік і перевірки:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ідеї для пошуку
- Переходи RW→RX, ініційовані PowerShell: VirtualProtect для PAGE_EXECUTE_READWRITE у powershell.exe.<sup>[[8]](#references)</sup>
- Шаблони динамічного виклику (GetDelegateForFunctionPointer)
- Неочікувані HTTPS-відповіді 404 із `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` або `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-відповіді з `AA=true` і `TXT "OK"` на короткі запити до підозрілих доменів.<sup>[[4]](#references)</sup>
- Трафік GitHub API до `/repos/<owner>/<repo>/issues`, після якого йдуть запити до `ipinfo.io` з того самого ланцюжка завантажувача/beacon.<sup>[[5]](#references)</sup>
- Файли .lnk у папках Startup користувача або спільних папках Startup.<sup>[[1]](#references)</sup>
- Підозрілі ключі Run (наприклад, "Updater") і назви завантажувачів на кшталт update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Троянізовані PE-зразки, які перенаправляють `_security_init_cookie` на код завантажувача перед показом документа-приманки.<sup>[[5]](#references)</sup>
- Записувані користувачем шляхи DLL у %APPDATA%\Microsoft\Windows\Templates, що містять msimg32.dll.<sup>[[1]](#references)</sup>

## Примітки щодо полів OpSec

- KillDate: timestamp, після якого агент самостійно припиняє роботу.<sup>[[1]](#references)</sup>
- WorkingTime: години, протягом яких агент має бути активним, щоб його активність не вирізнялася на тлі робочого процесу.<sup>[[1]](#references)</sup>

Ці поля можна використовувати для кластеризації та пояснення періодів низької активності.

## YARA та статичні ознаки

Unit 42 опублікувала базові правила YARA для beacons (C/C++ і Go) та констант хешування API у завантажувачах.<sup>[[1]](#references)</sup> Розгляньте можливість доповнити їх правилами для виявлення формату [size|ciphertext|16-byte-key] біля кінця PE .rdata, типових рядків профілю HTTP, а також новіших маркерів сервера/listener, таких як `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` і `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: новий фреймворк із відкритим вихідним кодом, що використовується в реальних атаках (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Документація Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: масштабне виявлення ознак фреймворку C2 із відкритим вихідним кодом (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper переходить на AdaptixC2 і власний Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – документація Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – документація Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Константи захисту пам’яті – документація Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – ключі Run реєстру/папка Startup](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Генерація профілю AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Parser профілю beacon AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Генерація DNS-профілю AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Пакування профілю AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
{{#include ../../banners/hacktricks-training.md}}
