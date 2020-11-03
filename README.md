# cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
InSpec profile overlay to validate the secure configuration of AWS RDS Oracle Database 12c against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Oracle Database 12c STIG Version 1 Release 12 tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html) for CMS systems categorized as Moderate.

## Getting Started

It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

This overlay also requires the AWS Command Line Interface (CLI) which is available at the [AWS CLI](https://aws.amazon.com/cli/) site.

Git is required to download the latest InSpec profiles using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site. 

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

## Configuring Your Environment
Prior to running this overlay, certain credentials and permissions need to be established for the AWS CLI to work properly. 

1. The IAM account used to run this profile against the AWS environment needs to be attached through a group or role with at least `AWS IAM "ReadOnlyAccess" Managed Policy`. 

2. If running in an AWS Multi-Factor Authentication (MFA) environment, derived credentials are needed to use the AWS CLI. Default `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` will not satisfy the MFA Policies in the CMS AWS environments. To do this, the AWS CLI environment needs to have the right system environment variables set with your AWS region and credentials and session key. InSpec supports the following standard AWS variables:

- `AWS_REGION`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

The environment variables can be set using the following commands.

````
# Set required ENV variables
$ export AWS_ACCESS_KEY_ID=<key-id>
$ export AWS_SECRET_ACCESS_KEY=<access-key>
$ export AWS_SESSION_TOKEN=<session_token>
$ export AWS_REGION='<region>'
````

More information about these credentials and permissions can be found in the [AWS](https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html) documentation and [AWS Profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html) documentation.

A useful bash script for automating this process is [here](https://gist.github.com/dinvlad/d1bc0a45419abc277eb86f2d1ce70625)

Furthermore, to generate credentials using an AWS Profile you will need to use the following AWS CLI commands.

  a. `aws sts get-session-token --serial-number arn:aws:iam::<$YOUR-MFA-SERIAL> --token-code <$YOUR-CURRENT-MFA-TOKEN> --profile=<$YOUR-AWS-PROFILE>` 

  b. Then export the `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` that was generated by the above command.

## Running This Overlay Directly from Github

```
# How to run
inspec exec https://github.com/CMSgov/cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay/archive/master.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --target aws:// --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
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
inspec exec cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay --input-file <path_to_your_attributes_file/name_of_your_attributes_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay
git pull
cd ..
inspec exec cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay --input-file <path_to_your_attributes_file/name_of_your_attributes_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json> 
```

## Using Heimdall for Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Eugene Aronne - [ejaronne](https://github.com/ejaronne)

## Special Thanks
* Aaron Lippold - [aaronlippold](https://github.com/aaronlippold)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/CMSgov/cms-ars-3.1-moderate-aws-rds-oracle-database-12c-stig-overlay/issues/new).

### NOTICE

© 2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

### NOTICE
DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
