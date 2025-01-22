# IBM Aspera HSTS as tethered node in AoC

The procedure is documented in AoC manual:

<https://ibmaspera.com/help/attach_cloud_local_storage>

<https://www.ibm.com/docs/en/aspera-on-cloud?topic=admin-attach-cloud-local-storage>

The procedure below is similar, but uses a `nginx` reverse proxy as front end to node api.

## Configuration as tethered node in AoC

### Pre-requisites

In order to tether a self-managed node to Aspera on Cloud, the following are requited:

- A self-managed system with admin access, typically a Linux Virtual Machine
- A public IP address where this machine is reachable on a minimum of 2 TCP ports and 1 UDP port
- A DNS A record (FQDN) for that IP address (or use freedns, see below)
- A TLS certificate for that FQDN (or use letsencypt see below: requires port TCP/443)
- The installation package for HSTS: for example:

  `ibm-aspera-hsts-4.4.5.1646-linux-64-release.rpm`

- An evaluation license file. For example:

  `87650-AsperaEnterprise-unlim.eval.aspera-license`

To download the RPM, one can use the following technique:

- Go to <https://ibm.com/aspera>
- Navigate to **Download and Documentation**, and then **Server**
- Select **Download Now** for HSTS
- That bring to [Fix Central](https://www.ibm.com/support/fixcentral/swg/selectFixes?parent=ibm%7EOther%20software&product=ibm/Other+software/IBM+Aspera+High-Speed+Transfer+Server&release=All&platform=Linux+x86_64&function=all)
- click on the desirec HSTS version, and then make sure to select **HTTP Download**
- then **right click** on the RPM link, and do **Copy link location**
- This represents a temporary direct download URL

Then, on Linux execute:

```bash
wget [paste the link here]
```

Alternatively, if wget is not available:

```bash
curl -o [paste only the file name of RPM] [paste the full link here]
```

For the license file, you can directly `vi` on linux, and paste inside.
Alternatively, use `scp` to transfer those files.

You will set the path to those two files in the variables in next section.

### DNS record

A FQDN (DNS A Record) is required for the public address.

If none is defined, it is possible to use a free service like [freedns](https://freedns.afraid.org/) for that.

### Installation and configuration of tethered node

We assume here that a compatible Virtual Machine (or physical) is installed with a RHEL-compatible Linux distribution: RHEL, Rocky Linux, Alma Linux, etc...

> **Note:** The following commands are executed as `root` inside `root`'s home (`/root`).
> To impersonate root, execute: `sudo -i`
>
> **Note:** We need to generate some secrets of given length.
> Several tools can be used for random.
> For example we will use `tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40` to generate a 40 character random string.
> We could also use `openssl rand -base64 40|head -c 40` for the same.

#### Parameters

For convenience, let's create a shell config file `/root/aspera_vars.sh` with parameters used:

```bash
test $(id -u) = 0 || echo "ERROR: execute as root"
aspera_cert_email=_your_email_here_
aspera_fqdn=_your_server_fqdn_here_
aspera_rpm=_path_to_hsts_rpm_
aspera_eval_lic=_path_to_license_file_
aspera_os_user=xfer
aspera_home=/home/$aspera_os_user
aspera_storage_root=$aspera_home/aoc
aspera_node_port=9092
aspera_node_user=node_admin
aspera_node_pass=$(tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40)
set|grep ^aspera_ > /root/aspera_vars.sh
PATH=/opt/aspera/bin:/usr/local/bin:$PATH
echo 'PATH=/opt/aspera/bin:/usr/local/bin:$PATH' >> /root/aspera_vars.sh
```

Once created, edit the generated file `/root/aspera_vars.sh` and customize with your own values.

```bash
vi /root/aspera_vars.sh
```

Especially:

- `aspera_cert_email` : place your email, this is used by Letsencrypt to notify yu when the certificate will expire.
- `aspera_fqdn` : Place your server's DNS address. For example, I used Techzone and Freedns, and my address is: `itzvsi-f0pjbk8h.mojok.org`
- `aspera_rpm` : path to the HSTS RPM that you downloaded, e.g. `./ibm-aspera-hsts-4.4.5.1646-linux-64-release.rpm`
- `aspera_eval_lic` : Path to the Aspera HSTS license file, e.g. `./87650-AsperaEnterprise-unlim.eval.aspera-license`
- Other parameters should remain as is.

Once modified, reload the values:

```bash
source /root/aspera_vars.sh
```

At any time, if you open a new terminal, you can reload the configuration variables with above command.

#### General system settings

Install time synchroinization (chrony) and set timezone according to your preference.

```bash
dnf install -y chrony
systemctl enable --now chronyd
timedatectl set-timezone Europe/Paris
```

#### Install the Aspera CLI

Not mandatory per se, but convenient.

This can alternatively be installed on the laptop instead. <https://github.com/IBM/aspera-cli>

```bash
dnf module -y reset ruby
dnf module -y enable ruby:3.3
dnf install -y ruby-devel
gem install aspera-cli
```

Check availability with:

```bash
ascli -v
```

#### Install the HSTS software

```bash
dnf install -y perl
rpm -Uvh $aspera_rpm
```

> **Note:** `perl` is still required by HSTS installer, and also later by `nginx`.

#### Install the license file

It goes to `/opt/aspera/etc/aspera-license`.
This file must be world-readable, or at least readable by `asperadaemons` and transfer users.

```bash
cp $aspera_eval_lic /opt/aspera/etc/aspera-license
chmod a+r /opt/aspera/etc/aspera-license
```

#### Declare Aspera shell

> **Note:** Optional, but removes some warnings.

As Aspera uses SSH by default, a protection is provided with a secure shell: `aspshell`.
This shell can be declared as legitimate shell to avoid warning messages (optinal):

```bash
grep -qxF '/bin/aspshell' /etc/shells || echo '/bin/aspshell' >> /etc/shells
```

#### Aspera logs

> **Note:** Optional. By default logs go to `/var/log/messages` using syslog facility `local2`. This is not mandatory, but it is convenient.

Configure logging per process for Aspera.

```bash
sed -i -Ee 's/(;cron.none)(\s+\/var\/log\/messages)/\1;local2.none\2/' /etc/rsyslog.conf
echo 'local2.* -/var/log/aspera.log' > /etc/rsyslog.d/99aspera_log.conf
cat << EOF > /etc/logrotate.d/aspera
/var/log/aspera.log
{
  rotate 5
  weekly
  postrotate
    /usr/bin/killall -HUP rsyslogd
  endscript
}
EOF
for d in asperanoded asperaredisd asperacentral asperawatchd asperawatchfolderd asperarund asperahttpd http-gateway ascli async faspio-gateway;do
  l=/var/log/${d}.log
  echo 'if $programname == '"'$d'"' then { action(type="omfile" file="'${l}'") stop }' > /etc/rsyslog.d/00${d}_log.conf
  sed -i -e '/aspera.log/ a '${l} /etc/logrotate.d/aspera
done
systemctl restart rsyslog
```

#### Create transfer user

When used with AoC, only one transfer user is used: `xfer`.
Optionally we can create a group.
We make sure to block direct login with that user.
Create this user:

```bash
groupadd asperausers
useradd --create-home --no-user-group --gid asperausers --shell /bin/aspshell $aspera_os_user
passwd --lock $aspera_os_user
chage --mindays 0 --maxdays 99999 --inactive -1 --expiredate -1 $aspera_os_user
```

#### Configure token encryption key

For a PoC, it can be easier to use a static token encryption key:

```bash
asconfigurator -x 'set_node_data;token_dynamic_key,false'
asconfigurator -x "set_node_data;token_encryption_key,$(tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40)"
```

If you prefer to use dynamic keys (**skip** this part if you like KISS):

```bash
asconfigurator -x 'set_node_data;token_dynamic_key,true'
asconfigurator -x 'set_node_data;token_encryption_key,AS_NULL'
tr -dc 'A-Za-z0-9'</dev/urandom|head -c 40|askmscli -rs redis-primary-key
askmscli --init-keystore --user=$aspera_os_user
```

#### Configure the transfer user for use with tokens

```bash
mkdir -p $aspera_home/.ssh
cp /opt/aspera/var/aspera_tokenauth_id_rsa.pub $aspera_home/.ssh/authorized_keys
chmod -R go-rwx $aspera_home/.ssh
chown -R $aspera_os_user: $aspera_home
```

#### Define storage location root

Create some main storage location, and restrict to that:

```bash
mkdir -p $aspera_storage_root
chown $aspera_os_user: $aspera_storage_root
asconfigurator -x "set_user_data;user_name,xfer;absolute,AS_NULL;file_restriction,|file:///$aspera_storage_root/*"
```

#### Other configuration for AoC

Aspera on Cloud requires activity logging:

```bash
asconfigurator -x 'set_server_data;activity_logging,true;activity_event_logging,true;activity_file_event_logging,true;activity_bandwidth_logging,true'
asconfigurator -x 'set_node_data;pre_calculate_job_size,yes;async_activity_logging,true'
asconfigurator -x "set_server_data;files_recursive_counts_workers,3"
```

#### Node API user

Let's create a node API user and save the credentials:

```bash
/opt/aspera/bin/asnodeadmin -a -u $aspera_node_user -p $aspera_node_pass -x $aspera_os_user
```

#### SSH confguration

Let's configure SSH to also listen on port 33001:

```bash
sed -i '/^#Port 22$/a Port 33001' /etc/ssh/sshd_config
sed -i '/^#UseDNS yes$/a UseDNS no' /etc/ssh/sshd_config
sed -i '/^HostKey .*ecdsa_key$/s/^/#/ ' /etc/ssh/sshd_config
sed -i '/^HostKey .*ed25519_key$/s/^/#/ ' /etc/ssh/sshd_config
systemctl restart sshd
```

#### Public IP and DNS

In order to work with Aspera on Cloud, it is required to have a public IP address on which the following ports are open:

| Port | Usage |
|------|-------|
| TCP/33001 | FASP Session (SSH) |
| UDP/33001 | FASP Data |
| TCP/443   | Node API (HTTPS) |
| TCP/80    | Useful for Letsencrypt |

Once the DNS name is known:

```bash
echo $aspera_fqdn > /etc/hostname
hostname $aspera_fqdn
hostname
```

#### Certificate

A TLS certificate is required for above FQDN.

If you don't have one, then it is possible to generate one with below procedure using Letsencrypt:

Install `certbot`:

```bash
dnf install -y python3.12
python3 -m venv /opt/certbot/
/opt/certbot/bin/pip install --upgrade pip
/opt/certbot/bin/pip install certbot
ln -s /opt/certbot/bin/certbot /usr/bin/certbot
```

Generate a certificate:

```bash
certbot certonly --agree-tos --email $aspera_cert_email --domain $aspera_fqdn --non-interactive --standalone
```

> **Note:** For above command to work, port TCP/443 must be reachable and FQDN reachable. Certificate and key is placed here: `/etc/letsencrypt/live/$aspera_fqdn/`

#### Nginx

Per se, nginx is not required, but that simplifies the installation of certificates.

```bash
dnf install -y nginx
```

Since we use nginx as reverse proxy, we can make node api listen locally only:

```bash
asconfigurator -x "set_server_data;listen,127.0.0.1:${aspera_node_port}s"
systemctl restart asperanoded
```

> **Note:** `s` is for HTTPS

Create a configuration file for nginx:

- This one uses the Letsencrypt certificate. If you used another method, then reference the actual location of the certificte and key in parameters `ssl_certificate`

```bash
cat<<EOF > /etc/nginx/conf.d/aspera.conf
server {
  set                        \$node_port $aspera_node_port;
  listen                     443 ssl;
  listen                     [::]:443 ssl;
  server_name                _;
  root                       /usr/share/nginx/html;
  ssl_certificate            /etc/letsencrypt/live/$aspera_fqdn/fullchain.pem;
  ssl_certificate_key        /etc/letsencrypt/live/$aspera_fqdn/privkey.pem;
  ssl_session_cache          builtin:1000 shared:SSL:10m;
  ssl_protocols              TLSv1.2 TLSv1.3;
  ssl_ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS;
  ssl_prefer_server_ciphers  on;
  access_log                 /var/log/nginx/global.access.log;
  proxy_set_header           Host              \$host;
  proxy_set_header           X-Real-IP         \$remote_addr;
  proxy_set_header           X-Forwarded-For   \$proxy_add_x_forwarded_for;
  proxy_set_header           X-Forwarded-Proto \$scheme;
  proxy_set_header           Origin            https://\$http_host;
  proxy_read_timeout         90;
  proxy_buffering            off;
  proxy_request_buffering    off;
  server_tokens              off;
  # HSTS: node API
  location / {
    proxy_pass               https://127.0.0.1:\$node_port;
    proxy_hide_header        Access-Control-Allow-Origin;
    add_header               Access-Control-Allow-Origin *;
    access_log               /var/log/nginx/node.access.log;
  }
}
EOF
```

Then start and enable it permanently (on reboot):

```bash
systemctl enable --now nginx
```

### Creation of access key and node using AoC webUI

Go to Admin app, in nodes and storage.
Add new node.
`Attach my Aspera server`

- Name: anything
- URL: value of: `https://$aspera_fqdn`
- `Create new access key`
- Node username: `$aspera_node_user`
- Node password: `$aspera_node_pass`
- Storage: Local Storage
- Path: `$aspera_storage_root/`

### Creation of access key and node using `ascli`

#### Configure `ascli`

Configure access to node api:

```bash
ascli config preset update node_admin --url=https://$aspera_fqdn --username=$aspera_node_user --password=$aspera_node_pass
ascli config preset set default node node_admin
```

#### Create the access key

```bash
ascli node access_keys create @json:'{"storage":{"type":"local","path":"'$aspera_storage_root'"}}' --show-secrets=yes | tee my_ak.txt
```

The access key credentials are displayed and saved in file: `my_ak.txt`

#### Create the node

Use the AoC web UI and select "Use my own key".

Configure access to AoC:

(`sedemo` is the name of the AoC tenancy (organization))

```bash
ascli config wizard sedemo aoc
```
