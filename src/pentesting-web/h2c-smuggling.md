# Upgrade Header Smuggling

{{#include ../banners/hacktricks-training.md}}

### H2C Smuggling <a href="#h2c-smuggling" id="h2c-smuggling"></a>

#### HTTP/2 Over Cleartext (H2C) <a href="#http2-over-cleartext-h2c" id="http2-over-cleartext-h2c"></a>

H2C, or **HTTP/2 over cleartext**, can be negotiated by upgrading an HTTP/1.1 connection to the HTTP/2 binary protocol. Both HTTP/1.1 and HTTP/2 can use persistent connections; the security-relevant change is that, after the upgrade, subsequent HTTP/2 streams may pass through a proxy-created tunnel.<sup>[[1]](#references)[[2]](#references)</sup>

The crux of the smuggling issue arises with the use of a **reverse proxy**. Ordinarily, the proxy processes and forwards each HTTP request and returns the backend response. When it accepts an `Upgrade`, however, it may switch to blindly forwarding bytes between the client and backend. A compliant H2C upgrade request includes these three headers:<sup>[[1]](#references)[[2]](#references)</sup>

```
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

The vulnerability arises when, after upgrading a connection, the reverse proxy ceases to manage individual requests, assuming its job of routing is complete post-connection establishment. Exploiting H2C Smuggling allows for circumvention of reverse proxy rules applied during request processing, such as path-based routing, authentication, and WAF processing, assuming an H2C connection is successfully initiated.<sup>[[1]](#references)[[2]](#references)</sup>

#### Vulnerable Proxies <a href="#vulnerable-proxies" id="vulnerable-proxies"></a>

The vulnerability depends on how the reverse proxy handles `Upgrade` and `Connection`. The cited research found the following proxies forwarded the relevant headers by default in the tested configurations:<sup>[[1]](#references)[[2]](#references)</sup>

- HAProxy
- Traefik
- Nuster

Conversely, the following services did not forward both headers by default in the tested configurations, but an unsafe configuration can still pass them through:

- AWS ALB/CLB
- NGINX
- Apache
- Squid
- Varnish
- Kong
- Envoy
- Apache Traffic Server<sup>[[1]](#references)</sup>

#### Exploitation <a href="#exploitation" id="exploitation"></a>

Not all proxies forward the headers required for a compliant H2C upgrade. The tested default configurations of AWS ALB/CLB, NGINX, and Apache Traffic Server blocked the compliant form. Also test the noncompliant `Connection: Upgrade` variant, which omits `HTTP2-Settings` from the `Connection` header, because some proxy/backend combinations process it differently.<sup>[[1]](#references)[[2]](#references)</sup>

> [!CAUTION]
> Irrespective of the specific **path** designated in the `proxy_pass` URL (e.g., `http://backend:9999/socket.io`), the established connection defaults to `http://backend:9999`. This allows for interaction with any path within that internal endpoint, leveraging this technique. Consequently, the specification of a path in the `proxy_pass` URL does not restrict access.

The tools [**h2csmuggler by BishopFox**](https://github.com/BishopFox/h2csmuggler) and [**h2csmuggler by assetnote**](https://github.com/assetnote/h2csmuggler) facilitate attempts to **circumvent proxy-imposed protections** by establishing an H2C connection, thereby enabling access to resources shielded by the proxy.<sup>[[2]](#references)[[1]](#references)</sup>

For additional information on this vulnerability, particularly concerning NGINX, refer to [**this detailed resource**](../network-services-pentesting/pentesting-web/nginx.md#proxy_set_header-upgrade-and-connection).

## Websocket Smuggling

WebSocket smuggling creates a tunneled connection through a proxy whose frontend and backend disagree about whether a WebSocket upgrade succeeded. The tunnel can bypass path or authentication controls enforced only by the frontend.<sup>[[3]](#references)</sup>

### Scenario 1

In this scenario, a backend that offers a public WebSocket API alongside an inaccessible internal REST API is targeted by a malicious client seeking access to the internal REST API. The attack unfolds in several steps:

1. The client initiates by sending an Upgrade request to the reverse proxy with an incorrect `Sec-WebSocket-Version` protocol version in the header. The proxy, failing to validate the `Sec-WebSocket-Version` header, believes the Upgrade request to be valid and forwards it to the backend.
2. The backend responds with a status code `426`, indicating the incorrect protocol version in the `Sec-WebSocket-Version` header. The reverse proxy, overlooking the backend's response status, assumes readiness for WebSocket communication and relays the response to the client.
3. Consequently, the reverse proxy is misled into believing a WebSocket connection has been established between the client and backend, while in reality, the backend had rejected the Upgrade request. Despite this, the proxy maintains an open TCP or TLS connection between the client and backend, allowing the client unrestricted access to the private REST API through this connection.

The cited research reproduced this scenario with Varnish and Envoy 1.8.0; later Envoy versions changed the upgrade mechanism. Test other proxies rather than assuming that they share the same behavior.<sup>[[3]](#references)</sup>

![https://github.com/0ang3el/websocket-smuggle/raw/master/img/2-4.png](https://github.com/0ang3el/websocket-smuggle/raw/master/img/2-4.png)

### Scenario 2

This scenario involves a backend with both a public WebSocket API and a public REST API for health checking, along with an inaccessible internal REST API. The attack, more complex, involves the following steps:

1. The client sends a POST request to trigger the health check API, including an additional HTTP header `Upgrade: websocket`. NGINX, serving as the reverse proxy, interprets this as a standard Upgrade request based solely on the `Upgrade` header, neglecting the request's other aspects, and forwards it to the backend.
2. The backend executes the health-check API and requests an external resource controlled by the attacker, which returns an HTTP response with status code `101`. When the backend forwards that response, NGINX incorrectly treats it as confirmation that the original client connection was upgraded.

![https://github.com/0ang3el/websocket-smuggle/raw/master/img/3-4.png](https://github.com/0ang3el/websocket-smuggle/raw/master/img/3-4.png)

> **Warning:** This technique's complexity increases as it requires the ability to interact with an endpoint capable of returning a status code 101.

Ultimately, NGINX is tricked into believing a WebSocket connection exists between the client and the backend. In reality, no such connection exists; the health check REST API was the target. Nevertheless, the reverse proxy maintains the connection open, enabling the client to access the private REST API through it.

![https://github.com/0ang3el/websocket-smuggle/raw/master/img/3-5.png](https://github.com/0ang3el/websocket-smuggle/raw/master/img/3-5.png)

This scenario additionally requires an SSRF-like endpoint whose upstream response is relayed to the proxy. Susceptibility depends on the proxy's upgrade validation and the application's response-forwarding behavior.<sup>[[3]](#references)</sup>

#### Labs

Check the labs to test both scenarios in [https://github.com/0ang3el/websocket-smuggle.git](https://github.com/0ang3el/websocket-smuggle.git)<sup>[[3]](#references)</sup>

## References

- [1] [H2C Smuggling: Request Smuggling Via HTTP/2 Cleartext (Assetnote)](https://blog.assetnote.io/2021/03/18/h2c-smuggling/)
- [2] [H2C Smuggling: Request Smuggling Via HTTP/2 Cleartext (BishopFox)](https://bishopfox.com/blog/h2c-smuggling-request)
- [3] [Websocket smuggling research and labs (0ang3el/websocket-smuggle)](https://github.com/0ang3el/websocket-smuggle.git)

{{#include ../banners/hacktricks-training.md}}
