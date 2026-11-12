# Вилучення конфігурації AdaptixC2 і TTP

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 — це модульний open-source фреймворк для post-exploitation/C2 із Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) і підтримкою BOF.<sup>[[1]](#references)</sup> На цій сторінці описано:
- Як конфігурація, запакована за допомогою RC4, вбудовується та як вилучити її з beacons
- Мережеві індикатори й індикатори профілю для HTTP/SMB/TCP listeners
- Поширені TTP завантажувачів і закріплення в системі, які спостерігаються в реальних атаках, із посиланнями на відповідні сторінки про техніки Windows

У нових upstream-релізах також з’явилися DNS/DoH beacon listeners і окреме сімейство Gopher agent/listener, тому сучасна інфраструктура Adaptix може охоплювати більше, ніж початкові HTTP/SMB/TCP поверхні, навіть якщо конкретний зразок і досі використовує класичний beacon agent.<sup>[[2]](#references)</sup>

## Профілі та поля Beacon

AdaptixC2 підтримує три основні типи beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: веб-C2 із конфігурованими серверами/портами/SSL, методом, URI, headers, user-agent і власною назвою параметра
- BEACON_SMB: peer-to-peer C2 через іменований канал (intranet)
- BEACON_TCP: прямі sockets, за потреби з доданим на початку маркером для обфускації початку протоколу

Це формати beacon, описані у відкритих аналізах Adaptix на початку; вони досі є найпоширенішою відправною точкою для вилучення даних зі зразка.<sup>[[1]](#references)</sup> Водночас сучасні upstream-збірки також містять розширення `BeaconDNS` і Gopher на стороні сервера, тому не варто вважати, що кожне активне розгортання Adaptix використовує лише HTTP/SMB/TCP інфраструктуру.<sup>[[2]](#references)</sup>

Наведений нижче опис полів і приклади JSON стосуються формату HTTP, проаналізованого у 2025 році; це не специфікація парсера для новіших upstream-збірок. Типові поля в цих прикладах (після розшифрування):<sup>[[1]](#references)[[11]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (масив рядків), ports (масив u32)
- http_method, uri, parameter, user_agent, http_headers (рядки з префіксом довжини)
- ans_pre_size (u32), ans_size (u32) – використовуються для розбору розмірів відповідей
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Нові збірки BeaconHTTP також підтримують вибір оператором ротації між кількома URI, user-agent, Host headers і серверами, послідовно або випадково.<sup>[[2]](#references)</sup> Для пошуку загроз це означає, що один заражений хост може використовувати кілька шляхів зворотного зв’язку й комбінацій заголовків, не виходячи за межі класичного сімейства beacon, запакованого за допомогою RC4.

Приклад стандартного HTTP-профілю (зі збірки beacon):<sup>[[1]](#references)</sup>

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

Коли оператор натискає Create у builder, AdaptixC2 компілює зашифрований профіль у beacon. Не припускайте, що він розташований у кінці PE чи shellcode: знайдіть байти профілю скануванням секцій або простеживши виклик `getProfile()` у зразку. Формат пакування:<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>
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
- Вилучення детерміноване: прочитати розмір, прочитати ciphertext цього розміру, прочитати 16-байтовий ключ, розміщений одразу після нього, а потім розшифрувати за допомогою RC4.

## Процес вилучення конфігурації (захисники)

Щоб виконати загальний первинний аналіз зразка до вилучення beacon, див. [Malware Analysis](malware-analysis.md).

Створіть екстрактор, що імітує логіку beacon:<sup>[[1]](#references)</sup>
1) Знайдіть blob у PE (зазвичай у .rdata). Практичний підхід — просканувати .rdata на наявність правдоподібної структури [size|ciphertext|16-byte key] і спробувати виконати RC4.
2) Прочитайте перші 4 байти → розмір (uint32 LE).
3) Прочитайте наступні N=size байтів → ciphertext.
4) Прочитайте останні 16 байтів → ключ RC4.
5) Розшифруйте ciphertext за допомогою RC4. Потім розберіть відкритий профіль так:
   - скаляри u32/boolean, як зазначено вище
   - рядки з префіксом довжини (довжина u32, за якою йдуть байти; наприкінці може бути NUL)
   - масиви: servers_count, за яким ідуть стільки пар [рядок, порт u32]

Legacy HTTP proof-of-concept на Python (самостійний, без зовнішніх залежностей) для попередньо вилученого blob у порядку полів 2025 року. Для актуальних стандартних збірок використовуйте наведений нижче парсер поточної схеми:<sup>[[1]](#references)[[11]](#references)</sup>

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

### Розбір поточних стандартних HTTP- і DNS-профілів

Спочатку поточна upstream-версія пакує шість значень `u32` у little-endian: watermark/тип агента, дату завершення роботи, робочий час, затримку, jitter і watermark/тип listener-а. Далі йдуть специфічні для HTTP дані, починаючи з однобайтового прапорця SSL. На відміну від прикладу для legacy-версії, тут є списки URI, user-agent і Host-заголовків із лічильниками, а за ними — режим ротації та налаштування proxy. Тому legacy-парсер починає читати прапорець SSL із поля дати завершення роботи й повертає хибні результати для цих збірок. Довжини рядків і цілі значення в цьому профілі закодовані в little-endian; упаковані рядки, якщо вони непорожні, завершуються NUL.<sup>[[11]](#references)[[12]](#references)[[14]](#references)</sup>

За допомогою наведених вище helper-функцій `P` і `rc4` застосуйте цей парсер до розшифрованого plaintext стандартного HTTP. Не розголошуйте RC4-ключ у публічних звітах: HTTP-профіль може містити ім’я користувача й пароль proxy.<sup>[[11]](#references)[[12]](#references)</sup>

<details>
<summary>Розбір поточного стандартного HTTP plaintext-профілю</summary>

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

Для штатного DNS beacon прочитайте ті самі шість спільних полів `u32`, а потім рядки `domain`, `resolvers`, `doh_resolvers` і `qtype`, довжина яких задається префіксом. Прочитайте `pkt_size`, `label_size`, `ttl`, `burst_enabled`, `burst_sleep`, `burst_jitter` і `dns_mode` як `u32`, а потім — рядок DoH user-agent із префіксом довжини. `dns_mode` розрізняє UDP, DoH і два напрямки fallback. Це окремий формат: не намагайтеся обробляти DNS plaintext за допомогою HTTP parser.<sup>[[12]](#references)[[13]](#references)</sup>

Поради:
- Для автоматизації використовуйте PE parser, щоб прочитати .rdata, а потім застосуйте sliding window: для кожного зсуву o спробуйте size = u32(.rdata[o:o+4]), ct = .rdata[o+4:o+4+size], candidate key = наступні 16 байтів; виконайте RC4-дешифрування та перевірте, чи рядкові поля декодуються як UTF-8, а їхні довжини є правдоподібними.
- Розбирайте SMB/TCP profiles за тими самими правилами для полів із префіксом довжини.

## Профілі custom listener: не закладайте в код лише класичну HTTP-схему

Зовнішній формат пакування (`u32 size | RC4 ciphertext | 16-byte key`) можна використовувати повторно, тож у listener, налаштованих акторами, можна зберегти той самий процес вилучення, повністю змінивши формат розшифрованих полів.

Показовий нещодавній приклад — кампанія Tropic Trooper у березні 2026 року: вилучений Adaptix beacon не містив стандартного HTTP/TCP profile. Натомість у розшифрованому blob зберігалися параметри GitHub transport, зокрема:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (наприклад, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Практична стратегія парсингу:
- Спочатку виявляйте зовнішній RC4 blob звичайним способом.
- Після розшифрування визначайте схему за рядками-сигнатурами та правдоподібністю полів, а не намагайтеся одразу застосувати HTTP parser.
- Корисні сигнатури: `api.github.com`, `/issues?state=open`, HTTP verbs/URIs, рядки у форматі named pipe або явно коректні масиви серверів/портів.
- Якщо HTTP parser завершується помилкою, але plaintext містить узгоджені UTF-8 рядки з префіксом довжини, збережіть зразок і спробуйте інші схеми, замість того щоб відкидати його як хибне спрацювання.

У цій кампанії custom listener використовував GitHub issues як C2 transport, а beacon звертався до `ipinfo.io`, щоб дізнатися свою зовнішню IP-адресу, оскільки GitHub API не показує оператору адресу джерела запиту жертви безпосередньо.<sup>[[5]](#references)</sup> Опис окремого handshake через issue та файл у репозиторії дивіться в [GitHub Issues and Repository Files as a C2 Channel](../github-issues-and-repository-files-c2.md).

## Мережеве fingerprinting і пошук загроз

HTTP:<sup>[[1]](#references)</sup>
- Поширений варіант: POST-запити до вибраних оператором URI (наприклад, /uri.php, /endpoint/api)
- Для beacon ID використовується параметр custom header (наприклад, X‑Beacon‑Id, X‑App‑Id)
- User-agent імітують Firefox 20 або сучасні версії Chrome
- Періодичність запитів можна визначити за sleep_delay/jitter_delay
- Новіші збірки можуть змінювати URI, user-agent, Host headers і сервери між callback-запитами, тому групуйте їх за рідковживаними назвами заголовків, шаблонами розмірів відповідей, повторним використанням TLS і часовими інтервалами, а не покладайтеся на одну пару шлях/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- SMB named-pipe listeners для intranet C2, коли вихідний вебтрафік обмежено
- TCP beacons можуть додавати кілька байтів перед трафіком, щоб приховати початок протоколу

Поточні типові налаштування upstream teamserver
- `profile.yaml` наразі містить такі стандартні налаштування teamserver: `0.0.0.0:4321`, endpoint `/endpoint`, імена файлів сертифіката/ключа `server.rsa.crt` і `server.rsa.key`, а також extenders для HTTP, SMB, TCP, DNS, Beacon agent і Gopher.<sup>[[2]](#references)</sup>
- Для маршрутів без відповідності типовий обробник помилок повертає `Server: AdaptixC2` і `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Типове тіло відповіді 404 містить `AdaptixC2 404` і `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- Загальноінтернетне сканування у 2026 році виявило багато відкритих teamserver на порту `4321` і багато beacon listeners на порту `43211`. Обидва порти корисні як початкові точки пошуку, але не вважайте їх вичерпним переліком.<sup>[[4]](#references)</sup>

Сигнатури DNS/DoH listener:<sup>[[4]](#references)</sup>
- Поточний BeaconDNS extender відповідає авторитетно (`AA=true`)
- На запити, які не відповідають формату протоколу beacon, зокрема імена менш ніж із 5 міток перед налаштованим доменом, зазвичай надходить відповідь `TXT "OK"`
- Якщо базовий TTL залишено рівним нулю, listener використовує базове значення 10 секунд і додає до нього випадкове значення до 59 секунд
- Тому короткі мітки в активних пробах корисні, коли HTTP listener не виявлено

## TTP завантажувачів і механізмів закріплення, виявлені під час інцидентів

Завантажувачі PowerShell, що працюють у пам’яті:<sup>[[1]](#references)</sup>
- Завантажують Base64/XOR payloads (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Виділяють unmanaged memory, копіюють shellcode, змінюють захист на 0x40 (PAGE_EXECUTE_READWRITE) через VirtualProtect.<sup>[[7]](#references)</sup>
- Виконують через .NET dynamic invocation: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Троянізоване підписане ПЗ / поетапні завантажувачі shellcode:<sup>[[5]](#references)</sup>
- У ланцюжку атак Tropic Trooper 2026 року використовувався троянізований виконуваний файл SumatraPDF (завантажувач TOSHIS), який перенаправляв `_security_init_cookie` на шкідливий код замість модифікації точки входу PE
- Завантажувач знаходив API за допомогою хешування Adler-32, завантажував PDF-приманку, отримував shellcode другого етапу, розшифровував його за допомогою AES-128-CBC через WinCrypt (`CryptDeriveKey` із зашитого seed) і виконував Adaptix beacon у пам’яті методом reflectively execution
- Згодом закріплення перенесли на scheduled tasks із назвами, що виглядали легітимно, наприклад `\MSDNSvc` або `\MicrosoftUDN`; вони були налаштовані на повторний запуск агента приблизно кожні дві години

Щодо виконання в пам’яті та особливостей AMSI/ETW дивіться ці сторінки:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Виявлені механізми закріплення:<sup>[[1]](#references)</sup>
- Ярлик (.lnk) у Startup folder для повторного запуску завантажувача під час входу в систему
- Registry Run keys (HKCU/HKLM ...\CurrentVersion\Run), часто з назвами, що звучать невинно, наприклад "Updater", для запуску loader.ps1.<sup>[[10]](#references)</sup>
- Перехоплення порядку пошуку DLL: розміщення msimg32.dll у %APPDATA%\Microsoft\Windows\Templates для вразливих процесів

Поглиблений розгляд технік і перевірки:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ідеї для пошуку загроз
- PowerShell, що виконує переходи RW→RX: VirtualProtect для PAGE_EXECUTE_READWRITE у powershell.exe.<sup>[[8]](#references)</sup>
- Шаблони dynamic invocation (GetDelegateForFunctionPointer)
- Неуспішні HTTPS-запити з відповідями 404, що містять `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` або `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-відповіді з `AA=true` і `TXT "OK"` на короткі запити до підозрілих доменів.<sup>[[4]](#references)</sup>
- Трафік GitHub API до `/repos/<owner>/<repo>/issues`, за яким ідуть запити до `ipinfo.io` від того самого ланцюжка завантажувача/beacon.<sup>[[5]](#references)</sup>
- Startup .lnk у папках Startup користувача або спільних папках Startup.<sup>[[1]](#references)</sup>
- Підозрілі Run keys (наприклад, "Updater") і назви завантажувачів на кшталт update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Троянізовані PE-зразки, які перенаправляють `_security_init_cookie` на код завантажувача перед показом документа-приманки.<sup>[[5]](#references)</sup>
- Доступні для запису користувачем шляхи DLL у %APPDATA%\Microsoft\Windows\Templates, що містять msimg32.dll.<sup>[[1]](#references)</sup>

## Примітки щодо полів OpSec

- KillDate: часова позначка, після якої агент самостійно припиняє роботу.<sup>[[1]](#references)</sup>
- WorkingTime: години, протягом яких агент має бути активним, щоб його активність зливалася з робочою діяльністю.<sup>[[1]](#references)</sup>

Ці поля можна використовувати для кластеризації та пояснення періодів без активності.

## YARA та статичні індикатори

Unit 42 опублікувала базові YARA-правила для beacons (C/C++ і Go) та констант хешування API у завантажувачах.<sup>[[1]](#references)</sup> Розгляньте можливість доповнити їх правилами, що шукають формат [size|ciphertext|16-byte-key] біля кінця PE .rdata, типові рядки HTTP profile, а також нові маркери server/listener, такі як `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` і `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>



## References

- [1] [AdaptixC2: Новий фреймворк з відкритим вихідним кодом, що використовується в реальних атаках (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 на GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Документація Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: Масштабне fingerprinting фреймворку C2 з відкритим вихідним кодом (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper переходить на AdaptixC2 і custom beacon listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer – Microsoft Docs](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Константи захисту пам’яті – Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod – PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 – Registry Run Keys/Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [11] [Генерація profile для AdaptixC2 (pl_main.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_main.go)
- [12] [Парсер beacon profile для AdaptixC2 (AgentConfig.cpp)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/src_beacon/beacon/AgentConfig.cpp)
- [13] [Генерація DNS profile для AdaptixC2 (pl_utils.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_utils.go)
- [14] [Пакування profile в AdaptixC2 (pl_packer.go)](https://github.com/Adaptix-Framework/AdaptixC2/blob/main/AdaptixServer/extenders/beacon_agent/pl_packer.go)
