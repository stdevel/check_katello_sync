# check_katello_sync
`check_katello_sync` is a Nagios/Icinga plugin for checking product synchronization within Katello/Red Hat Satellite 6.x. It also supports performance data, enabling visualizing results with tools such as Grafana.

The script checks the synchronization of one or multiple product of an organization.

To gather information a valid username / password combination to your management system is required. The login credentials **are prompted** when running the script. To automate this you have two options:

## Setting shell variables
The following shell variables are used:
* **SATELLITE_LOGIN** - a username
* **SATELLITE_PASSWORD** - the appropriate password

You might also want to set the HISTFILE variable (*depending on your shell*) to hide the command including the password in the history:
```
$ HISTFILE="" SATELLITE_LOGIN=mylogin SATELLITE_PASSWORD=mypass ./check_katello_sync.py -s giertz.stankowic.loc
```

## Using an authfile
A better possibility is to create a authfile with permisions **0600** or **0400**. Just enter the username in the first line and the password in the second line and hand the path to the script:
```
$ ./check_katello_sync.py -a giertz.auth -s giertz.stankowic.loc
```

# Requirements
The plugin requires Python 2.6 or newer - it also requires the `requests` and `simplejson` modules.
The plugin requires API version 2 - the script checks the API version and aborts if you are using a historic version of Foreman/Katello.

# Usage
By default, the script checks the synchronization of all products of an particular organization. It is possible to control this behaviour by specifying additional parameters (*see below*).
The script also support performance data for data visualization.

The following parameters can be specified:

| Parameter | Description |
|:----------|:------------|
| `-h` / `--help` | shows help and quits |
| `-d` / `--debug` | enable debugging outputs (*default: no*) |
| `-P` / `--show-perfdata` | enables performance data (*default: no*) |
| `-a` / `--authfile` | defines an auth file to use instead of shell variables |
| `-s` / `--server` | defines the server to use (*default: localhost*) |
| `--insecure` | Disables SSL verification (*default: no*) |
| `-o` / `--organization` | specifies the organization to check (*name or ID*) |
| `-w` / `--outdated-warning` | defines outdated products warning threshold in days (*default: 2*) |
| `-c` / `--outdated-critical` | defines outdated products critical threshold in days (*default: 5*) |
| `-i` / `--include` | specifies particular products to check (*default: no*) |
| `-e` / `--exclude` | specifies particular products to ignore (*default: no*) |

## Examples
The following example checks all products of an particular organization on a Foreman/Katello server:
```
$ ./check_katello_sync.py -s st-katello01.stankowic.loc -o Stankowic
Satellite Username: admin
Satellite Password:
CRITICAL: Products outdated more than 5 days: Stankowic_Puppet. Products outdated up to 2 days: Stankowic_Docker. Products synchronized: owncloud-el7-x86_64, katello-client-el7-x86_64, icinga2-el7-x86_64, grafana-el7-x86_64, gitlab-ci-el7-x86_64, EPEL_7_x86_64, CentOS_7_x86_64 |
```

Ignoring some products synchronized manually, authentication using authfile:
```
$ ./check_katello_sync.py -s st-katello01.stankowic.loc -a giertz.auth -o Stankowic -e Stankowic_Puppet -e Stankowic_Docker
OK: Products synchronized: owncloud-el7-x86_64, katello-client-el7-x86_64, icinga2-el7-x86_64, grafana-el7-x86_64, gitlab-ci-el7-x86_64, EPEL_7_x86_64, CentOS_7_x86_64 |
```

Only checking some particular products, enabling performance data:
```
$ ./check_katello_sync.py -s st-katello01.stankowic.loc -a shittyrobots.auth -o Stankowic -i gitlab-ci-el7-x86_64 -P
OK: Products synchronized: gitlab-ci-el7-x86_64 | 'prod_total'=9;;;; 'prod_warn'=0;2;2;; 'prod_crit'=0;5;5;;
```

The same, specifying custom thresholds:
```
$ ./check_katello_sync.py -s st-katello01.stankowic.loc -a pinkepank.auth -o Stankowic -i gitlab-ci-el7-x86_64 -P -w 2 -c 4
OK: Products synchronized: gitlab-ci-el7-x86_64 | 'prod_total'=9;;;; 'prod_warn'=0;2;2;; 'prod_crit'=0;4;4;;
```

# Installation
Just deploy the Python script on your Icinga host or node. This repository also includes a [NRPE](check_katello_sync.cfg) and [Icinga2 configuration](check_katello_sync-icinga2.conf). If you're using a RPM-based Linux distro, you can use the [RPM spec file](nagios-plugins-katello-sync.spec) to create a RPM pacakge.

## Icinga2 configuration idea
I'm using the following snippet to check the products of my Foreman/Katello servers:

```
apply Service "DIAG: Katello product synchronization" {
  import "generic-service"
  check_command = "check_katello_sync"
  vars.katello_perfdata = true
  vars.katello_host = "st-katello01.stankowic.loc"
  assign where host.vars.os == "Linux" && host.vars.app == "katello"
  ignore where host.vars.noagent
}
```

Systems running the Foreman/Katello application (*implemented by the vars.app tag*) will be checked. Make sure the particular host configuration contains an authfile and organization:
```
object Host "st-katello01.stankowic.loc" {
  import "linux-host"
...
  vars.app = "katello"
  vars.katello_authfile = "/usr/lib64/nagios/plugins/katello.auth"
  vars.katello_organization = "Stankowic"
```

The authfile needs to have file permissions **0600** or **0400** and should be owned by the ``icinga`` user:
```
# chmod 0600 /usr/lib64/nagios/plugins/katello.auth
# chown icinga: /usr/lib64/nagios/plugins/katello.auth
```

To include or exclude products, you can utilize the **products_include** or **products_exclude** variables. When using the include variable, only defined products will be checked. Specifying the exclude variable will check all products except those mentioned in the variable.

To exclude particular products, alter your configuration like this:
```
  vars.products_exclude = ["Stankowic_Docker", "Stankowic_Puppet"]
```

To only check particular products, use this one:
```
  vars.products_include = ["CentOS_7_x86_64"]
