# cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
InSpec profile overlay to validate the secure configuration of AWS RDS Oracle Database 12c against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Oracle Database 12c STIG Version 1 Release 12 tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html) for CMS systems categorized as Moderate.

## Getting Started

It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

Git is required to download the latest InSpec profiles using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site. 

The following inputs must be configured in an inputs file for the profile to run correctly. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```
# description: Username Oracle DB (e.g., 'system')
user: ''

# description: Password Oracle DB (e.g., 'xvIA7zonxGM=1')
password: ''

# description: Hostname Oracle DB (e.g., 'localhost')
host: ''

# description: Service name Oracle DB (e.g., 'ORCLCDB')
service: ''

# description: Location of sqlplus tool (e.g., '/opt/oracle/product/12.2.0.1/dbhome_1/bin/sqlplus')
sqlplus_bin: ''

# description: Set to true if standard auditing is used
standard_auditing_used: false 

# description: Set to true if unified auditing is used
unified_auditing_used: false

# description: List of allowed database links
allowed_db_links: []

# description: List of allowed database admins
allowed_dbadmin_users: []

# description: List of users allowed access to PUBLIC
users_allowed_access_to_public: []

# description: List of users allowed the dba role
allowed_users_dba_role: []

# description: List of users allowed the system tablespace
allowed_users_system_tablespace: []

# description: List of application owners
allowed_application_owners: []

# description: List of allowed unlocked Oracle db accounts
allowed_unlocked_oracledb_accounts: []

# description: List of users allowed access to the dictionary table
users_allowed_access_to_dictionary_table: []

# description: List of users allowed admin privileges
allowed_users_with_admin_privs: []

# description: List of users allowed audit access
allowed_audit_users: []

# description: List of allowed dba object owners
allowed_dbaobject_owners: []

# description: List of allowed Oracle db components
allowed_oracledb_components: []

# description: List of Oracle db components allowed to be intregrated into the dbms
allowed_oracledb_components_integrated_into_dbms: []

# description: List of allowed Oracle dba's
oracle_dbas: []

# description: Org-specific profiles used to manage emergency or temporary accounts
emergency_profile_list: []

```

## Running This Overlay
When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/CMSgov/cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay.git
git clone https://github.com/mitre/aws-rds-oracle-database-12c-stig-baseline.git
cd cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
bundle install
cd ..
inspec exec cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay --input-file <path_to_your_attributes_file/name_of_your_attributes_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd profiles/aws-rds-oracle-database-12c-stig-baseline
git pull
cd ../cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
git pull
bundle install
cd ..
inspec exec cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay --input-file <path_to_your_attributes_file/name_of_your_attributes_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://mitre.github.io/heimdall-lite/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Getting Help
To report a bug or feature request, please open an [issue](https://github.com/CMSgov/cms-ars-3.1-moderate-oracle-database-12c-stig-overlay/issues/new).

## Authors
* Mohamed El-Sharkawi  
* Eugene Aronne

## Special Thanks
* Aaron Lippold

## License
* This project is licensed under the terms of the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0).

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.
