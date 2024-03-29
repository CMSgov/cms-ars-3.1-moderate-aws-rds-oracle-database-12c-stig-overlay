# cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
**CMS’ ISPG (Information Security and Privacy Group) decided to discontinue funding the customization of MITRE’s Security Automation Framework (SAF) for CMS after September 2023. This repo is now in archive mode, but still accessible. For more information about SAF with current links, see https://security.cms.gov/learn/security-automation-framework-saf**

InSpec profile overlay to validate the secure configuration of AWS RDS Oracle Database 12c against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Oracle Database 12c STIG Version 1 Release 12 tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html) for CMS systems categorized as Moderate.

## Getting Started

### InSpec (CINC-auditor) setup
For maximum flexibility/accessibility, we’re moving to “cinc-auditor”, the open-source packaged binary version of Chef InSpec, compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef’s always-open-source InSpec source code. For more information: https://cinc.sh/

It is intended and recommended that CINC-auditor and this profile overlay be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

__For the best security of the runner, always install on the runner the _latest version_ of CINC-auditor.__ 

__The simplest way to install CINC-auditor is to use this command for a UNIX/Linux/MacOS runner platform:__
```
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```

__or this command for Windows runner platform (Powershell):__
```
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```
To confirm successful install of cinc-auditor:
```
cinc-auditor -v
```
> sample output:  _4.24.32_

Latest versions and other installation options are available at https://cinc.sh/start/auditor/.

### Oracle 12c client setup

To run the Oracle 12c profile against an AWS RDS Instance, InSpec expects the Oracle 12c sqlplus client to be readily available on the same runner system it is installed on.
 
For example, to install the Oracle 12c sqlplus client on a Linux runner host:

Download the two 12.2 packages from the OTN website:
https://www.oracle.com/database/technologies/instant-client/linux-x86-64-downloads.html
```
oracle-instantclient12.2-basic-12.2.0.1.0-1.x86_64.rpm
oracle-instantclient12.2-sqlplus-12.2.0.1.0-1.x86_64.rpm
```
Install using:
```
sudo yum install libaio
sudo rpm -ivh oracle-instantclient12.2-basic-12.2.0.1.0-1.x86_64.rpm
sudo rpm -ivh oracle-instantclient12.2-sqlplus-12.2.0.1.0-1.x86_64.rpm
```
you will have sqlplus64 installed in:
```
cd /usr/bin
ls -l sql*

lrwxrwxrwx. 1 root root 41 Jan 25 16:59 sqlplus64 -> /usr/lib/oracle/12.2/client64/bin/sqlplus
```
Edit your .bashrc file, to add these as shown below:
```
###Sqlplus Client###

export ORACLE_HOME=/usr/lib/oracle/12.2/client64

export LD_LIBRARY_PATH=${ORACLE_HOME}/lib

export PATH=${ORACLE_HOME}/bin:$PATH

Save and source the .bashrc:

source .bashrc
```
Validate sqlplus is installed successfully using:
```
$ which sqlplus

/usr/lib/oracle/12.2/client64/bin/sqlplus

$ sqlplus –version

SQL*Plus: Release 12.2.0.1.0 Production
```

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# Description: Username Oracle DB (e.g., 'system')
user: ''

# Description: Password Oracle DB (e.g., 'xvIA7zonxGM=1')
password: ''

# Description: Hostname Oracle DB (e.g., 'localhost')
host: ''

# Description: Service name Oracle DB (e.g., 'ORCLCDB')
service: ''

# Description: Location of sqlplus tool (e.g., '/opt/oracle/product/12.2.0.1/dbhome_1/bin/sqlplus')
sqlplus_bin: ''

# Description: Set to true if standard auditing is used
standard_auditing_used: false 

# Description: Set to true if unified auditing is used
unified_auditing_used: false

# Description: List of allowed database links
allowed_db_links: []

# Description: List of allowed database admins
allowed_dbadmin_users: []

# Description: List of users allowed access to PUBLIC
users_allowed_access_to_public: []

# Description: List of users allowed the dba role
allowed_users_dba_role: []

# Description: List of users allowed the system tablespace
allowed_users_system_tablespace: []

# Description: List of application owners
allowed_application_owners: []

# Description: List of allowed unlocked Oracle db accounts
allowed_unlocked_oracledb_accounts: []

# Description: List of users allowed access to the dictionary table
users_allowed_access_to_dictionary_table: []

# Description: List of users allowed admin privileges
allowed_users_with_admin_privs: []

# Description: List of users allowed audit access
allowed_audit_users: []

# Description: List of allowed dba object owners
allowed_dbaobject_owners: []

# Description: List of allowed Oracle db components
allowed_oracledb_components: []

# Description: List of Oracle db components allowed to be intregrated into the dbms
allowed_oracledb_components_integrated_into_dbms: []

# Description: List of allowed Oracle dba's
oracle_dbas: []

# Description: Org-specific profiles used to manage emergency or temporary accounts
emergency_profile_list: []

```

## Running This Overlay Directly from Github

```
# How to run
cinc-auditor exec https://github.com/CMSgov/cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay/archive/master.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Overlay from a local Archive copy

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this overlay and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/CMSgov/cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay.git
cinc-auditor archive cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
cinc-auditor exec <name of generated archive> --input-file <path_to_your_attributes_file/name_of_your_attributes_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
git pull
cd ..
cinc-auditor archive cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay --overwrite
cinc-auditor exec <name of generated archive> --input-file <path_to_your_attributes_file/name_of_your_attributes_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Eugene Aronne - [ejaronne](https://github.com/ejaronne)

## Special Thanks
* Aaron Lippold - [aaronlippold](https://github.com/aaronlippold)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/CMSgov/cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
