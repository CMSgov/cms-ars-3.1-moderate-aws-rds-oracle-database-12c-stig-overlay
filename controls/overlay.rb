#encoding: utf-8
include_controls 'oracle-database-12c-stig-baseline' do
  control 'V-61409' do
    title 'Audit trail data must be retained online for ninety (90) days and archived 
    for old records for one (1) year.'
    desc 'Review and verify the implementation of an audit trail retention policy.
    
    Verify that audit data is maintained online for ninety (90) days and archived for 
    old records for one (1) year to provide support for after-the-fact investigations 
    of security incidents.

    If not, this is a finding.'
    desc 'check', 'Develop, document and implement an audit retention policy and 
    procedures.

    It is recommended that the most recent ninety days of audit logs remain 
    available online.

    After thirty ninety days, the audit logs may be maintained off-line.

    Online maintenance provides for a more timely capability and inclination to         
    investigate suspicious activity.'
  end

  control 'V-61447' do
  desc 'Multi-tier systems may be configured with the database and connecting 
        middle-tier system located on an internal network, with the database 
        located on an internal network behind a firewall and the middle-tier 
        system located in a DMZ. In cases where either or both systems are located 
        in the DMZ (or on networks external to CMS), network communications between 
        the systems must be encrypted.'
  desc 'fix', 'Configure communications between the DBMS and remote 
       applications/application servers to use CMS-approved encryption.'	
  end

  control 'V-61453' do
    desc 'Data export from production databases may include sensitive data. Application 
         developers do not have a need to know to sensitive data. Any access they may 
         have to production data would be considered unauthorized access and subject 
         the sensitive data to unlawful or unauthorized disclosure. See CMS ARS 3.1 
         for a definition of Sensitive Information.'
  end

  control 'V-61455' do
    title 'Application user privilege assignment must be reviewed every 90 days or more 
          frequently to ensure compliance with least privilege and documented policy.'
    desc 'Users granted privileges not required to perform their assigned functions are 
         able to make unauthorized modifications to the production data or database. 
         Every 90 days or more frequent periodic review of privilege assignments assures 
         that organizational and/or functional changes are reflected appropriately.'
  end

  control 'V-61491' do
    title 'The DBMS host platform and other dependent applications must be configured in 
          compliance with applicable CMS ARS requirements.'
    desc 'fix', 'Configure all related application components and the DBMS host platform 
         in accordance with the applicable CMS ARS.

         Regularly audit the security configuration of related applications and the host 
         platform to confirm continued compliance with security requirements.'
  end

  control 'V-61523' do
    desc 'Remote administration may expose configuration and sensitive data to unauthorized 
         viewing during transit across the network or allow unauthorized administrative 
         access to the DBMS to remote users.

         For the purposes of this STIG, "Remote" means "outside the CMS network." However, 
         use of an approved and properly configured VPN counts as inside the CMS network.'

    desc 'check', 'Review the System Security Plan for authorization, assignments and usage 
         procedures for remote DBMS administration.

         If remote administration of the DBMS is not documented or poorly documented, this 
         is a finding.

         If remote administration of the DBMS is not authorized and not disabled, this is 
         a finding.
         
         If remote administration is to be performed from outside the CMS network, but is not 
         done via an approved and properly configured VPN, this is a finding.'
  end

  control 'V-61545' do
    desc 'Preventing the disclosure of transmitted information requires that applications take 
         measures to employ some form of cryptographic mechanism in order to protect the 
         information during transmission. This is usually achieved through the use of Transport 
         Layer Security (TLS), SSL VPN, or IPSEC tunnel.

         Alternative physical protection measures include Protected Distribution Systems (PDS). 
         PDS are used to transmit unencrypted classified NSI through an area of lesser 
         classification or control. Inasmuch as the classified NSI is unencrypted, the PDS must 
         provide adequate electrical, electromagnetic, and physical safeguards to deter 
         exploitation. Refer to NSTSSI No. 7003 for additional details on a PDS.

         Information in transmission is particularly vulnerable to attack. If the DBMS does not 
         employ cryptographic mechanisms preventing unauthorized disclosure of information 
         during transit, the information may be compromised.

         SHA-1 is in the process of being removed from service it\'s use is to be limited during 
         the transition to SHA-2.  Use of SHA-1 for digital signature generation is prohibited.  
         Allowable uses during the transition include CHECKSUM usage and verification of legacy 
         certificate signatures.  SHA-1 is considered a temporary solution during legacy 
         application transitionary periods and should not be engineered into new applications. 
         SHA-2 is the path forward.'
  end

  control 'V-61555' do
    desc 'This requirement is related to remote access, but more specifically to the networking 
         protocols allowing systems to communicate. Remote access is any access to an organizational 
         information system by a user (or an information system) communicating through an external, 
         non-organization  controlled network (e.g., the Internet). Examples of remote access methods 
         include dial-up, broadband, and wireless.
         
         Some networking protocols allowing remote access may not meet security requirements to 
         protect data and components. Bluetooth and peer-to-peer networking are examples of less than 
         secure networking protocols.

         Applications implementing or utilizing remote access network protocols need to ensure the 
         application is developed and implemented in accordance with CMS requirements. In situations 
         where it has been determined that specific operational requirements outweigh the risks of 
         enabling an insecure network protocol, the organization may pursue a risk acceptance.

         Using protocols deemed nonsecure would compromise the ability of the DBMS to operate in a 
         secure fashion. The database must be able to disable network protocols deemed nonsecure.'

    desc 'check', 'Review DBMS settings to determine if the database is utilizing any network 
         protocols deemed nonsecure.  If the DBMS is not using any network protocols deemed nonsecure, 
         this is not a finding.

         If the database is utilizing protocols specified as nonsecure, verify the protocols are 
         explicitly identified in the System Security Plan and that they are in support of specific 
         operational requirements. If they are not identified in the SSP or are not supporting specific 
         operational requirements, this is a finding.

         If nonsecure network protocols are not being used but are not disabled in the DBMS\'s 
         configuration, this is a finding.

         After determining the site-specific operational requirements and which protocols are explicitly 
         defined in the System Security Plan, check the $TNS_ADMIN setting for the location of the Oracle 
         listener.ora file.  The listener.ora file is a configuration file for Oracle Net Listener that 
         identifies the following:

         A unique name for the listener, typically LISTENER
         A protocol address that it is accepting connection requests on, and
         A service it is listening for.
         
         If the listener.ora file shows a PROTOCOL= statement and the PROTOCOL is deemed nonsecure, 
         that is a finding.

         LISTENER=
           (DESCRIPTION=
             (ADDRESS_LIST=
               (ADDRESS=(PROTOCOL=tcp)(HOST=sale-server)(PORT=1521))
               (ADDRESS=(PROTOCOL=ipc)(KEY=extproc))))
         SID_LIST_LISTENER=
           (SID_LIST=
             (SID_DESC=
               (GLOBAL_DBNAME=sales.us.example.com)
               (ORACLE_HOME=/oracle12c)
               (SID_NAME=sales))
             (SID_DESC=
               (SID_NAME=plsextproc)
               (ORACLE_HOME=/oracle12c)
               (PROGRAM=extproc)))

         Protocol Parameters

         The Oracle Listener and the Oracle Connection Manager are identified by protocol addresses. 
         The information below contains the "Protocol-Specific Parameters" used by the Oracle protocol 
         support.

         Protocol-Specific Parameters
         Protocol: IPC     Parameter: PROTOCOL  Notes: Specify ipc as the value.
         Protocol: IPC     Parameter: KEY       Notes: Specify a unique name for the service. Oracle 
                                                       recommends using the service name or SID of the 
                                                       service.
         Example: (PROTOCOL=ipc)(KEY=sales)

         Protocol: Named Pipes  Parameter: PROTOCOL  Notes: Specify nmp as the value.
         Protocol: Named Pipes  Parameter: SERVER    Notes: Specify the name of the Oracle server.
         Protocol: Named Pipes  Parameter: PIPE      Notes: Specify the pipe name used to connect to the 
                                                     database server.
                                                     This is the same PIPE keyword specified on the server 
                                                     with Named Pipes.  This name can be any name.

         Example: (Protocol=nmp) (SERVER=USDOD) (PIPE=dbpipe01)
            
         Protocol: SDP     Parameter: PROTOCOL  Notes: Specify sdp as the value.
         Protocol: SDP     Parameter: HOST      Notes: Specify the host name or IP address of the computer.
         Protocol: SDP     Parameter: PORT      Notes: Specify the listening port number.

         Example: (PROTOCOL=sdp)(HOST=sales-server)(PORT=1521)
                  (PROTOCOL=sdp)(HOST=192.168.2.204)(PORT=1521)

         Protocol: TCP/IP  Parameter: PROTOCOL  Notes: Specify TCP as the value.
         Protocol: TCP/IP  Parameter: HOST      Notes: Specify the host name or IP address of the computer.
         Protocol: TCP/IP  Parameter: PORT      Notes: Specify the listening port number.
         Example: (PROTOCOL=tcp)(HOST=sales-server)(PORT=1521)
                  (PROTOCOL=tcp)(HOST=192.168.2.204)(PORT=1521)
 
        Protocol: TCP/IP with TLS  Parameter: PROTOCOL  Notes: Specify tcps as the value.
        Protocol: TCP/IP with TLS  Parameter: HOST      Notes: Specify the host name or IP address of the computer.
        Protocol: TCP/IP with TLS  Parameter: PORT      Notes: Specify the listening port number.
                                                        Example:(PROTOCOL=tcps)(HOST=sales-server) (PORT=2484)
                                                                (PROTOCOL=tcps)(HOST=192.168.2.204)(PORT=2484)'
    desc 'fix', 'Disable any network protocol listed as nonsecure in the PPSM documentation.

         To disable the protocol deemed not secure, stop the listener by issuing the following command as the 
         Oracle Software owner, typically Oracle.
          $ lsnrctl stop
         This will stop the listener.  Edit the LISTENER.ORA file and remove the protocols deemed not secure 
         and restart the listener.

         For example, if TCP was deemed as not secure, the listener.ora would need to be changed and the tcp 
         entry would need to be removed.  That would only allow the listener to listen for an IPC connection.

         LISTENER=
           (DESCRIPTION=
           (ADDRESS_LIST=
             (ADDRESS=(PROTOCOL=tcp)(HOST=sale-server)(PORT=1521)) - remove this line and properly balance the parentheses -
             (ADDRESS=(PROTOCOL=ipc)(KEY=extproc))))
         SID_LIST_LISTENER=
           (SID_LIST=
             (SID_DESC=
               (GLOBAL_DBNAME=sales.us.example.com)
               (ORACLE_HOME=/oracle12c)
               (SID_NAME=sales))
             (SID_DESC=
               (SID_NAME=plsextproc)
               (ORACLE_HOME=/oracle12c)
               (PROGRAM=extproc)))

          Revise the client side TNSNAMES.ORA to align the PROTOCOL value in the PROTOCOL portion of the connect 
          string.  For example, if TCP was deemed as not secure and the listener.ora was changed to listen for an 
          IPC connection the code below would be required:

          net_service_name=
          (DESCRIPTION=
          (ADDRESS=(PROTOCOL=tcp)(HOST=sales1-svr)(PORT=1521))
          (ADDRESS=(PROTOCOL=tcp)(HOST=sales2-svr)(PORT=1521))
          (CONNECT_DATA=
          (SERVICE_NAME=sales.us.example.com)))'
  end

  control 'V-61561' do
    desc 'check', 'If the organization has a policy, consistently enforced, forbidding the creation of emergency 
         or temporary accounts, this is not a finding.

         If all user accounts are authenticated by the OS or an enterprise-level authentication/access mechanism, 
         and not by Oracle, this is not a finding.

         Check DBMS settings, OS settings, and/or enterprise-level authentication/access mechanisms settings to 
         determine if the site utilizes a mechanism whereby temporary or emergency accounts can be terminated after 
         an organization-defined time period. If not, this is a finding.

         Check the profiles to see what the password_life_time is set to in the table dba_profiles. 
         The password_life_time is a value stored in the LIMIT column, and identified by the value PASSWORD_LIFE_TIME 
         in the RESOURCE_NAME column.

         SQL>select
         profile,
         resource_name,
         resource_type,
         limit
         from dba_profiles
         where upper(resource_name) like "PASSWORD_LIFE_TIME";

         Verify that the user in question is assigned to a profile with the PASSWORD_LIFE_TIME set to 60 days.  
         If not, this is a finding.'
    desc 'fix', 'If using database mechanisms to satisfy this requirement, use a profile with a distinctive name 
         (for example, TEMPORARY_USERS), so that temporary users can be easily identified.  Whenever a temporary user 
         account is created, assign it to this profile.

         Create a job to lock accounts under this profile that are more than 60 days old, where n is the 
         organization-defined time period.'
  end
  
  control 'V-61605' do
    title 'The DBMS must limit the number of consecutive failed logon attempts to 5.'
    desc 'check', '(This addresses both O121-C2-005000 and O121-C2-005200.)

         The limit on the number of consecutive failed logon attempts is defined in the profile 
         assigned to a user.

         To see what profile is assigned to a user, enter the following query:
         SQL>SELECT profile FROM dba_users WHERE username = "&USERNAME"
         This will return the profile name assigned to that user.

         Now check the values assigned to the profile returned from the query above:
         SQL>SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE LIKE "&PROFILE_NAME"

         Check the settings for FAILED_LOGIN_ATTEMPTS - this is the number of consecutive failed logon 
         attempts before locking the Oracle user account. If the value is greater than 5, this is a finding.'
    desc 'fix', '(This addresses both O121-C2-005000 and O121-C2-005200.)

         Configure the DBMS settings to specify the maximum number of consecutive failed logon 
         attempts to 5 (or less):
         ALTER PROFILE ORA_STIG_PROFILE LIMIT FAILED_LOGIN_ATTEMPTS 5;

         (ORA_STIG_PROFILE is available in DBA_PROFILES, starting with Oracle 12.1.0.2.  Note: It remains 
         necessary to create a customized replacement for the password validation function, 
         ORA12C_STRONG_VERIFY_FUNCTION, if relying on this technique to verify password complexity.)'
  end

  control 'V-61607' do
    desc 'check', '(This addresses both O121-C2-005000 and O121-C2-005200.)

         The limit on the number of consecutive failed logon attempts is defined in the profile 
         assigned to a user.

         To see what profile is assigned to a user, enter the following query:

         SQL>SELECT profile FROM dba_users WHERE username = "<username>"

         This will return the profile name assigned to that user.

         The user profile, ORA_STIG_PROFILE, has been provided (starting with Oracle 12.1.0.2) to satisfy 
         the STIG requirements pertaining to the profile parameters. Oracle recommends that this profile be 
         customized with any site-specific requirements and assigned to all users where applicable.  
         Note: It remains necessary to create a customized replacement for the password validation function, 
         ORA12C_STRONG_VERIFY_FUNCTION, if relying on this technique to verify password complexity.

         Now check the values assigned to the profile returned from the query above:

         column profile format a20
         column limit format a20
         SQL>SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE = "ORA_STIG_PROFILE";

         Check the settings for failed_login_attempts - this is the number of consecutive failed logon 
         attempts before locking the Oracle user account. If the value is greater than 5, this is a finding.'

    desc 'fix', '(This addresses both O121-C2-005000 and O121-C2-005200.)
         Configure the DBMS settings to specify the maximum number of consecutive failed logon 
         attempts to 5 (or less):
         ALTER PROFILE ORA_STIG_PROFILE LIMIT FAILED_LOGIN_ATTEMPTS 53;'
  end

  control 'V-61621' do
    desc 'Audit records can be generated from various components within the information system. (e.g., 
         network interface, hard disk, modem, etc.). From an application perspective, certain specific 
         application functionalities may be audited as well.

         The list of audited events is the set of events for which audits are to be generated. This set 
         of events is typically a subset of the list of all events for which the system is capable of 
         generating audit records (i.e., auditable events, timestamps, source and destination addresses, 
         user/process identifiers, event descriptions, success/fail indications, file names involved, 
         and access control or flow control rules invoked).

         Organizations define which application components shall provide auditable events.
         
         The DBMS must provide auditing for the list of events defined by the organization or risk 
         negatively impacting forensic investigations into malicious behavior in the information system. 
         Audit records can be generated from various components within the information system, such as 
         network interfaces, hard disks, modems, etc. From an application perspective, certain specific 
         application functionalities may be audited, as well.

         The list of audited events is the set of events for which audits are to be generated. This set 
         of events is typically a subset of the list of all events for which the system is capable of 
         generating audit records (i.e., auditable events, timestamps, source and destination addresses, 
         user/process identifiers, event descriptions, success/fail indications, file names involved, 
         and access control or flow control rules invoked).
         
         Organizations may define the organizational personnel accountable for determining which 
         application components shall provide auditable events.

         Auditing provides accountability for changes made to the DBMS configuration or its objects 
         and data. It provides a means to discover suspicious activity and unauthorized changes. Without 
         auditing, a compromise may go undetected and without a means to determine accountability.

         The following defines the minimum set of auditable events. Most can be audited via Oracle 
         settings; some - marked here with an asterisk - cannot, and may require OS settings.
         - Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, 
         security levels, or categories of information (e.g. classification levels).
         - Successful and unsuccessful logon attempts, privileged activities or other system level access
         - Starting and ending time for user access to the system, concurrent logons from different 
         workstations.
         - Successful and unsuccessful accesses to objects.
         - All program initiations.
         - *All direct access to the information system.
         - All account creations, modifications, disabling, and terminations.
         - *All kernel module loads, unloads, and restarts.'
  end

  control 'V-61625' do
    title 'The DBMS must generate audit records for the selected list of auditable events, to the extent 
    such information is available.'

    desc 'Audit records can be generated from various components within the information system, such as 
    network interfaces, hard disks, modems, etc. From an application perspective, certain specific 
    application functionalities may be audited, as well.

    The list of audited events is the set of events for which audits are to be generated. This set of 
    events is typically a subset of the list of all events for which the system is capable of generating 
    audit records (i.e., auditable events, timestamps, source and destination addresses, user/process 
    identifiers, event descriptions, success/fail indications, file names involved, and access control 
    or flow control rules invoked).

    Organizations may define the organizational personnel accountable for determining which application 
    components shall provide auditable events.

    Auditing provides accountability for changes made to the DBMS configuration or its objects and data. 
    It provides a means to discover suspicious activity and unauthorized changes. Without auditing, a 
    compromise may go undetected and without a means to determine accountability.

    The following is the minimum set of auditable events. Most can be audited via Oracle settings; 
    some - marked here with an asterisk - cannot, and may require OS settings.
    - Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, 
    security levels, or categories of information (e.g. classification levels).
    - Successful and unsuccessful logon attempts, privileged activities or other system level access
    - Starting and ending time for user access to the system, concurrent logons from different workstations.
    - Successful and unsuccessful accesses to objects.
    - All program initiations.
    - *All direct access to the information system.
    - All account creations, modifications, disabling, and terminations.
    - *All kernel module loads, unloads, and restarts.'
    
    desc 'check', 'Check DBMS settings to determine if auditing is being performed on the 
    events on the list of auditable events that lie within the scope of Oracle audit capabilities:
    - Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, 
    security levels, or categories of 
    information (e.g., classification levels).
    - Successful and unsuccessful logon attempts, privileged activities or other system-level access
    - Starting and ending time for user access to the system, concurrent logons from different workstations.
    - Successful and unsuccessful accesses to objects.
    - All program initiations.
    - All account creations, modifications, disabling, and terminations.

    If auditing is not being performed for any of these events, this is a finding.

    Notes on Oracle audit capabilities follow.

    Unified Audit supports named audit policies, which are defined using the CREATE AUDIT POLICY statement. 
    A policy specifies the actions that should be audited and the objects to which it should apply. 
    If no specific objects are included in the policy definition, it applies to all objects.

    A named policy is enabled using the AUDIT POLICY statement. It can be enabled for all users, for 
    specific users only, or for all except a specified list of users. The policy can audit successful actions, 
    unsuccessful actions, or both.

    Verifying existing audit policy: existing Unified Audit policies are listed in the view AUDIT_UNIFIED_POLICIES. 
    The AUDIT_OPTION column contains one of the actions specified in a CREATE AUDIT POLICY statement. 
    The AUDIT_OPTION_TYPE column contains "STANDARD ACTION" for a policy that applies to all objects or 
    "OBJECT ACTION" for a policy that audits actions on a specific object.

    select POLICY_NAME from SYS.AUDIT_UNIFIED_POLICIES where AUDIT_OPTION="GRANT" and 
    AUDIT_OPTION_TYPE="STANDARD ACTION";

    To find policies that audit privilege grants on specific objects:

    select POLICY_NAME,OBJECT_SCHEMA,OBJECT_NAME from SYS.AUDIT_UNIFIED_POLICIES where AUDIT_OPTION="GRANT" 
    and AUDIT_OPTION_TYPE="OBJECT ACTION";

    The view AUDIT_UNIFIED_ENABLED_POLICIES shows which Unified Audit policies are enabled. The ENABLED_OPT 
    and USER_NAME columns show the users for whom the policy is enabled or "ALL USERS". The SUCCESS and FAILURE 
    columns indicate if the policy is enabled for successful or unsuccessful actions, respectively.

    select POLICY_NAME,ENABLED_OPT,USER_NAME,SUCCESS,FAILURE from SYS.AUDIT_UNIFIED_ENABLED_POLICIES where 
    POLICY_NAME="POLICY1";'

    desc 'fix', 'Configure the DBMS\'s auditing settings to include auditing of events on the selected list 
    of auditable events.

    1) Successful and unsuccessful attempts to access, modify, or delete privileges, security objects, security 
    levels, or categories of information (e.g., classification levels)

    To audit granting and revocation of any privilege:
    create audit policy policy1 actions grant;
    create audit policy policy2 actions revoke;

    To audit grants of object privileges on a specific object:
    create audit policy policy3 actions grant on <schema>.<object>;

    If Oracle Label Security is enabled, this will audit all OLS administrative actions:
    create audit policy policy4 actions component = OLS all;

    2) Successful and unsuccessful logon attempts, privileged activities or other system-level access
 
    To audit all user logon attempts:
    create audit policy policy5 actions logon;

    To audit only logon attempts using administrative privileges (e.g. AS SYSDBA):
    audit policy policy5 by SYS, SYSOPER, SYSBACKUP, SYSDG, SYSKM;

    3) Starting and ending time for user access to the system, concurrent logons from different 
    workstations

    This policy will audit all logon and logoff events. An individual session is identified in the 
    UNIFIED_AUDIT_TRAIL by the tuple (DBID, INSTANCE_ID, SESSIONID) and the start and end time will be 
    indicated by the EVENT_TIMESTAMP of the logon and logoff events:

    create audit policy policy6 actions logon, logoff;

    4) Successful and unsuccessful accesses to objects

    To audit all accesses to a specific table:
    create audit policy policy7 actions select, insert, delete, alter on <schema>.<object>; 

    Different actions are defined for other object types. To audit all supported actions on a specific object:
    create audit policy policy8 actions all on <schema>.<object>;

    5) All program initiations

    To audit execution of any PL/SQL program unit:
    create audit policy policy9 actions EXECUTE;

    To audit execution of a specific function, procedure, or package:
    create audit policy policy10 actions EXECUTE on <schema>.<object>;

    6) All direct access to the information system

    [Not applicable to Database audit. Monitor using OS auditing.]

    7) All account creations, modifications, disabling, and terminations

    To audit all user administration actions:
    create audit policy policy11 actions create user, alter user, drop user, change password;

    8) All kernel module loads, unloads, and restarts

    [Not applicable to Database audit. Monitor using OS auditing.]

    9) All database parameter changes

    To audit any database parameter changes, dynamic or static:
    create audit policy policy12 actions alter database, alter system, create spfile;

    Applying the Policy

    The following command will enable the policy in all database sessions and audit both 
    successful and unsuccessful actions: audit policy policy1; 

    To audit only unsuccessful actions, add the WHENEVER NOT SUCCESSFUL modifier:
    audit policy policy1 whenever not successful;

    Either command above can be limited to only database sessions started by a specific user as 
    follows:
    audit policy policy1 by <user>;
    audit policy policy1 by <user> whenever not successful;'
  end
  
  control 'V-61675' do
    desc 'check', 'Review organization\'s access control policies and procedures addressing remote 
    access to the information system.

    If remote connections are not allowed by the organization, this is NA. (Note that "remote" means 
    "from outside the CMS network" and that connections via approved Virtual Private Networks (VPNs) 
    are considered to be inside the CMS network.)

    Review the DBMS, OS, and/or enterprise account management settings to verify access controls and 
    auditing settings exist and they enforce the requirements for remote access defined by the organization.

    If access controls and auditing do not exist or do not fully enforce the requirements defined in the 
    organization\'s policies and procedures, this is a finding.'
  end

  control 'V-61687' do
    desc 'check', 'Review the DBMS settings for functions, ports, protocols, and services that are not 
    approved.

    If any are found, this is a finding.

    - - - - -
    In the Oracle database, the communications with the database and incoming requests are performed by 
    the Oracle Listener.  The Oracle Listener listens on a specific port or ports for connections to a 
    specific database.  The Oracle Listener has configuration files located in the $ORACLE_HOME/network/admin 
    directory.  To check the ports and protocols in use, go to that directory and review the SQLNET.ora, 
    LISTENER.ora, and the TNSNAMES.ora. If protocols or ports are in use that are not authorized, this 
    is a finding.'
  end

  control 'V-61693' do
    desc 'Information system backup is a critical step in maintaining data assurance and availability.

    User-level information is data generated by information system and/or application users. In order to 
    assure availability of this data in the event of a system failure, CMS is required to ensure user-generated 
    data is backed up at a defined frequency. This includes data stored on file systems, within databases or 
    within any other storage media.

    Applications performing backups must be capable of backing up user-level information per the CMS-defined 
    frequency.

    Databases that do not backup information regularly risk the loss of that information in the event of a system 
    failure. Most databases contain functionality to allow regular backups; it is important that this 
    functionality is enabled and configured correctly to prevent data loss.'
  end

  control 'V-61695' do
    desc 'Information system backup is a critical step in maintaining data assurance and availability.

    User-level information is data generated by information system and/or application users. In order to 
    assure availability of this data in the event of a system failure, CMS organizations are required 
    to ensure user-generated data is backed up at a defined frequency. This includes data stored on file 
    systems, within databases or within any other storage media.

    Applications performing backups must be capable of backing up user-level information per the CMS-defined 
    frequency.

    Database backups provide the required means to restore databases after compromise or loss. Backups help 
    reduce the vulnerability to unauthorized access or hardware loss.'
  end

  control 'V-61697' do
    desc 'Information system backup is a critical step in maintaining data assurance and availability.

    User-level information is data generated by information system and/or application users. In order to 
    assure availability of this data in the event of a system failure, CMS organizations are required 
    to ensure user-generated data is backed up at a defined frequency. This includes data stored on 
    file systems, within databases or within any other storage media.

    Applications performing backups must be capable of backing up user-level information per the CMS-
    defined frequency.

    Database backups provide the required means to restore databases after compromise or loss. Backups 
    help reduce the vulnerability to unauthorized access or hardware loss.'
  end

  control 'V-61699' do
    desc 'Information system backup is a critical step in maintaining data assurance and availability.

    User-level information is data generated by information system and/or application users. In order 
    to assure availability of this data in the event of a system failure, CMS organizations are 
    required to ensure user-generated data is backed up at a defined frequency. This includes data 
    stored on file systems, within databases or within any other storage media.

    Applications performing backups must be capable of backing up user-level information per the CMS-defined 
    frequency.

    Lost or compromised DBMS backup and restoration files may lead to not only the loss of data, but also 
    the unauthorized access to sensitive data. Backup files need the same protections against unauthorized 
    access when stored on backup media as when online and actively in use by the database system. In 
    addition, the backup media needs to be protected against physical loss. Most DBMS\'s maintain online 
    copies of critical control files to provide transparent or easy recovery from hard disk loss or other 
    interruptions to database operation.'
  end

  control 'V-61703' do
    desc 'check', 'Review DBMS settings, OS settings, and/or enterprise-level authentication/access 
    mechanism settings to determine whether users logging on to privileged accounts via a network are 
    required to use multifactor authentication.

    If users logging on to privileged accounts via a network are not required to use multifactor 
    authentication, this is a finding.

    Use authentication to prove the identities of users who are attempting to log on to the database. 
    Authenticating user identity is imperative in distributed environments, without which there can be 
    little confidence in network security. Passwords are the most common means of authentication. Oracle 
    Database enables strong authentication with Oracle authentication adapters that support various 
    third-party authentication services, including TLS with digital certificates, as well as Smart Cards (PIV).

    If the $ORACLE_HOME/network/admin/sqlnet.ora contains entries similar to the following, TLS is enabled. 
    (Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the 
    supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or 
    differently located sqlnet.ora files.)

    SQLNET.AUTHENTICATION_SERVICES= (BEQ, TCPS)
    SSL_VERSION = 1.2 or 1.1
    SSL_CLIENT_AUTHENTICATION = TRUE
    WALLET_LOCATION =
    (SOURCE =
    (METHOD = FILE)
    (METHOD_DATA =
    (DIRECTORY = /u01/app/oracle/product/12.1.0/dbhome_1/owm/wallets)
    )
    )

    SSL_CIPHER_SUITES= (SSL_RSA_WITH_AES_256_CBC_SHA384)
    ADR_BASE = /u01/app/oracle

    Note: "SSL_VERSION = 1.2 or 1.1" is the actual value, not a suggestion to use one or the other.'
  
    desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to require 
    multifactor authentication for network users logging on to privileged accounts. 

    If appropriate, enable support for Transport Layer Security (TLS) protocols and multifactor 
    authentication through the use of Smart Cards (PIV).'
  end

  control 'V-61705' do
    desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to 
    require multifactor authentication for network users logging on to privileged accounts.

    If appropriate, enable support for Transport Layer Security (TLS) protocols and multifactor 
    authentication through the use of Smart Cards (PIV).'
  end

  control 'V-61707' do
    desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to require 
    multifactor authentication for local users logging on to privileged accounts.

    If appropriate, enable support for Transport Layer Security (TLS) protocols and multifactor 
    authentication through the use of Smart Cards (PIV).'
  end

  control 'V-61709' do
    desc 'fix', 'Configure DBMS, OS and/or enterprise-level authentication/access mechanism to require 
    multifactor authentication for local users logging on to non-privileged accounts.

    If appropriate, enable support for Transport Layer Security (TLS) protocols and multifactor 
    authentication through the use of Smart Cards (PIV).'
  end

  control 'V-61711' do
  desc 'Review DBMS settings, OS settings, and/or enterprise-level authentication/access mechanism 
  settings to determine whether shared accounts exist. If group accounts do not exist, this is NA.

  Review DBMS settings to determine if individual authentication is required before shared authentication.

  If shared authentication does not require prior individual authentication, this is a finding.
  
  (Oracle Access Manager may be helpful in meeting this requirement. Notes on Oracle Access Manager follow.)

  Oracle Access Manager is used when there is a need for multifactor authentication of applications 
  front-ending Oracle Datasets that may use group accounts. Oracle Access Manager supports using PKI-based 
  smart cards (PIV) for multifactor authentication. When a user authenticates to a smart card application, 
  the smart card engine produces a certificate-based authentication token. Can configure a certificate-based 
  authentication scheme in Oracle Access Manager that uses information from the smart card certificate. 
  Certificate-based authentication works with any smart card or similar device that presents an X.509 certificate.

  Check:
  First, check that the Authentication Module is set up properly:
  1) Go to Oracle Access Manager Home Screen and click the Policy Configuration tab.  Select the X509Scheme.
  2) Make sure the Authentication Module option is set to X509Plugin.

  Second, check that the Authentication policy is using the x509Scheme:
  1) Go to Oracle Access Manager Home Screen and click the Policy Configuration tab.
  2) Select Application Domains.  Select Search.
  3) Select the application domain protecting the Oracle Database.
  4) Select the Authentication Polices tab and Click Protected Resource Policy.
  5) Make sure the Authentication Scheme is set to x509Scheme.'
  end

  control 'V-61713' do
    desc 'An authentication process resists replay attacks if it is impractical to achieve a successful 
    authentication by recording and replaying a previous authentication message.

    Techniques used to address this include protocols using nonces (e.g., numbers generated for a 
    specific one-time use) or challenges (e.g., TLS, WS_Security), and time synchronous or challenge-
    response one-time authenticators.

    Replay attacks, if successfully used against a database account, could result in unfettered access 
    to the database settings and data. A successful replay attack against a privileged database account 
    could result in a complete compromise of the database.

    Oracle Database enables you to encrypt data that is sent over a network.  There is no distinction 
    between privileged and non-privileged accounts.

    Encryption of network data provides data privacy so that unauthorized parties are not able to view 
    plaintext data as it passes over the network. Oracle Database also provides protection against two 
    forms of active attacks.

    Data modification attack: An unauthorized party intercepting data in transit, altering it, and 
    retransmitting it is a data modification attack. For example, intercepting a $100 bank deposit, 
    changing the amount to $10,000, and retransmitting the higher amount is a data modification attack.

    Replay attack:  Repetitively retransmitting an entire set of valid data is a replay attack, such 
    as intercepting a $100 bank withdrawal and retransmitting it ten times, thereby receiving $1,000.

    AES and Triple-DES operate in outer Cipher Block Chaining (CBC) mode.

    The DES algorithm uses a 56-bit key length.

    SHA-1 is in the process of being removed from service within CMS and it\'s use is to be limited 
    during the transition to SHA-2.  Use of SHA-1 for digital signature generation is prohibited.  
    Allowable uses during the transition include CHECKSUM usage and verification of legacy certificate 
    signatures.  SHA-1 is considered a temporary solution during legacy application transitionary periods 
    and should not be engineered into new applications. SHA-2 is the path forward for CMS.'
  end

  control 'V-61715' do
    desc 'An authentication process resists replay attacks if it is impractical to achieve a successful 
    authentication by recording and replaying a previous authentication message.

    Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific 
    one-time use) or challenges (e.g., TLS, WS_Security), and time synchronous or challenge-response 
    one-time authenticators.

    Replay attacks, if successfully used against a database account, could result in access to database 
    data.  A successful replay attack against a non-privileged database account could result in a compromise 
    of data stored on the database.

    Oracle Database enables you to encrypt data that is sent over a network.  There is no distinction between 
    privileged and non-privileged accounts.

    Encryption of network data provides data privacy so that unauthorized parties are not able to view 
    plaintext data as it passes over the network. Oracle Database also provides protection against two 
    forms of active attacks.

    Data modification attack:  An unauthorized party intercepting data in transit, altering it, and retransmitting 
    it is a data modification attack. For example, intercepting a $100 bank deposit, changing the amount to $10,000, 
    and retransmitting the higher amount is a data modification attack.

    Replay attack:  Repetitively retransmitting an entire set of valid data is a replay attack, such as intercepting 
    a $100 bank withdrawal and retransmitting it ten times, thereby receiving $1,000.

    AES and Triple-DES operate in outer Cipher Block Chaining (CBC) mode.

    The DES algorithm uses a 56-bit key length.

    SHA-1 is in the process of being removed from service within CMS and it\'s use is to be limited during the 
    transition to SHA-2.  Use of SHA-1 for digital signature generation is prohibited.  Allowable uses during 
    the transition include CHECKSUM usage and verification of legacy certificate signatures.  SHA-1 is considered 
    a temporary solution during legacy application transitionary periods and should not be engineered into new 
    applications. SHA-2 is the path forward for CMS.'  
  end

  control 'V-61717' do
    title 'The DBMS must disable user accounts after 60 days of inactivity.'
    desc 'check', 'If all user accounts are managed and authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, this is not a finding.

    For accounts managed by Oracle, check DBMS settings to determine if accounts can be automatically disabled 
    by the system after 60 days of inactivity. Also, ask the DBA if an alternative method, such as a stored 
    procedure run daily, to disable Oracle-managed accounts inactive for more than 60 days, has been deployed.

    If the ability to disable accounts after 60 days of inactivity, by either of these means, does not exist, 
    this is a finding.

    - - - - -

    Check to see what profile each user is associated with, if any, with this query:

    select username, profile from dba_users order by 1,2;

    Then check the profile to see what the password_life_time is set to in the table dba_profiles; the 
    password_life_time is a value stored in the LIMIT column, and identified by the value PASSWORD_LIFE_TIME 
    in the RESOURCE_NAME column.
    SQL>select profile, resource_name, resource_type, limit from dba_profiles where upper(resource_name) = "PASSWORD_LIFE_TIME";'

    desc 'fix', 'For accounts managed by Oracle, determine if it is practical and acceptable to require a 
    password change every 60 days (as specified in SRG-APP-000174-DB-000080).  If it is, issue the statement:

    ALTER PROFILE PPPPPP LIMIT PASSWORD_LIFE_TIME 60;
    (See the Oracle-provided $ORACLE_HOME/rdbms/admin/secconf.sql script for examples.)

    If password changes every 60 days or fewer are unacceptable or impractical, implement an alternative method, 
    such as a stored procedure run daily, to disable accounts inactive for more than 60 days.'
  end
  
  control 'V-61719' do
    desc 'check', 'If all user accounts are authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, this is not a finding.

    For each profile that can be applied to accounts where authentication is under Oracle\'s control, 
    determine the password verification function, if any, that is in use:

    SELECT * FROM SYS.DBA_PROFILES 
    WHERE RESOURCE_NAME = "PASSWORD_VERIFY_FUNCTION"
    [AND PROFILE NOT IN (<list of non-applicable profiles>)]
    ORDER BY PROFILE;

    Bearing in mind that a profile can inherit from another profile, and the root profile is called 
    DEFAULT, determine the name of the password verification function effective for each profile.

    If, for any profile, the function name is null, this is a finding.

    For each password verification function, examine its source code.
    
    If it does not enforce the CMS-defined minimum length (15 unless otherwise specified), this is 
    a finding.'
    desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access 
    mechanism, and not by Oracle, no fix to the DBMS is required.

    If any user accounts are managed by Oracle:  Develop, test and implement a password verification function 
    that enforces CMS requirements.

    (Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION, in the script file 
<   oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point for a customized function.)'
  end

  control 'V-61721' do
    desc 'check', '"If all user accounts are authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, this is not a finding.

    For each profile that can be applied to accounts where authentication is under Oracle\'s control, 
    determine the password reuse rule, if any, that is in effect:

    SELECT * FROM SYS.DBA_PROFILES 
    WHERE RESOURCE_NAME IN ("PASSWORD_REUSE_MAX", "PASSWORD_REUSE_TIME")
    [AND PROFILE NOT IN (<list of non-applicable profiles>)]
    ORDER BY PROFILE, RESOURCE_NAME;
    Bearing in mind that a profile can inherit from another profile, and the root profile is 
    called DEFAULT, determine the value of the PASSWORD_REUSE_MAX effective for each profile.

    If, for any profile, the PASSWORD_REUSE_MAX value does not enforce the CMS-defined minimum 
    number of password changes before a password may be repeated (five or greater), this is a finding.

    PASSWORD_REUSE_MAX is effective if and only if PASSWORD_REUSE_TIME is specified, so if both are 
    UNLIMITED, this is a finding."'
    desc 'fix', '"If all user accounts are authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

    If any user accounts are managed by Oracle:  For each profile, set the PASSWORD_REUSE_MAX to 
    enforce the CMS-defined minimum number of password changes before a password may be 
    repeated (six or greater).

    PASSWORD_REUSE_MAX is effective if and only if PASSWORD_REUSE_TIME is specified, so ensure also 
    that it has a meaningful value.  Since the minimum password lifetime is 1 day, the smallest 
    meaningful value is the same as the PASSWORD_REUSE_MAX value.

    Using PPPPPP as an example, the statement to do this is:
    ALTER PROFILE PPPPPP LIMIT PASSWORD_REUSE_MAX 6 PASSWORD_REUSE_TIME 6;"'
  end

  control 'V-61723' do
    desc 'fix', '"If all user accounts are authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

    If any user accounts are managed by Oracle:  Develop, test and implement a password verification 
    function that enforces CMS requirements.

    (Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION, in the script file
    <oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point for a customized function.)"'
  end

  control 'V-61725' do
    desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, no fix to the DBMS is required.

    If any user accounts are managed by Oracle:  Develop, test and implement a password verification function 
    that enforces CMS requirements.

    (Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION, in the script file
    <oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point for a customized function.)"'
  end

  control 'V-61727' do
    desc 'fix', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access 
    mechanism, and not by Oracle, no fix to the DBMS is required.

    If any user accounts are managed by Oracle:  Develop, test and implement a password verification function 
    that enforces CMS requirements.

    (Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION, in the script file 
    <oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point for a customized function.)'
  end

  control 'V-61729' do
    desc 'fix', '"If all user accounts are authenticated by the OS or an enterprise-level authentication/access 
    mechanism, and not by Oracle, no fix to the DBMS is required.

    If any user accounts are managed by Oracle:  Develop, test and implement a password verification function 
    that enforces CMS requirements.

    (Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION, in the script file 
    <oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point for a customized function.)"'
  end

  control 'V-61731' do
    desc 'check', 'If all user accounts are managed and authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, this is not a finding.

    For each profile that can be applied to accounts where authentication is under Oracle\'s control, 
    determine the password verification function, if any, that is in use:

    SELECT * FROM SYS.DBA_PROFILES
    WHERE RESOURCE_NAME = "PASSWORD_VERIFY_FUNCTION"
    [AND PROFILE NOT IN (<list of non-applicable profiles>)] ORDER BY PROFILE;

    Bearing in mind that a profile can inherit from another profile, and the root profile is called DEFAULT, 
    determine the name of the password verification function effective for each profile.

    If, for any profile, the function name is null, this is a finding.
    
    For each password verification function, examine its source code.

    If it does not enforce the organization-defined minimum number of characters by which the password must differ 
    from the previous password (six of the characters unless otherwise specified), this is a finding.'

    desc 'fix', 'If any user accounts are managed by Oracle:  Develop, test and implement a password 
    verification function that enforces CMS requirements.

    (Oracle supplies a sample function called ORA12C_STRONG_VERIFY_FUNCTION, in the script file 
    <oracle_home>/RDBMS/ADMIN/utlpwdmg.sql.  This can be used as the starting point for a customized function.)'
  end

  control 'V-61735' do
    title 'Procedures for establishing temporary passwords that meet CMS password requirements for new accounts 
    must be defined, documented, and implemented.'

    desc 'check', 'If all user accounts are authenticated by the OS or an enterprise-level authentication/access 
    mechanism, and not by Oracle, this is not a finding.

    Where accounts are authenticated using passwords, review procedures and implementation evidence for creation 
    of temporary passwords.

    If the procedures or evidence do not exist or do not enforce passwords to meet CMS password requirements, this 
    is a finding.'

    desc 'fix', 'Implement procedures for assigning temporary passwords to user accounts.

    Procedures should include instructions to meet current CMS password length and complexity requirements and 
    provide a secure method to relay the temporary password to the user.'
  end

  control 'V-61739' do
    desc 'check', 'If all user accounts are authenticated by the OS or an enterprise-level 
    authentication/access mechanism, and not by Oracle, this is not a finding.

    Review DBMS settings to determine if passwords must be changed periodically. If not, this is a finding:

    SELECT p1.profile,
    CASE p1.limit WHEN \'UNLIMITED\' THEN \'UNLIMITED\' ELSE
    CASE p2.limit WHEN \'UNLIMITED\' THEN \'UNLIMITED\' ELSE
    CASE p3.limit WHEN \'UNLIMITED\' THEN \'UNLIMITED\' ELSE
    CASE p4.limit WHEN \'UNLIMITED\' THEN \'UNLIMITED\' ELSE
    TO_CHAR(DECODE(p1.limit, \'DEFAULT\', p3.limit, p1.limit) + DECODE(p2.limit, \'DEFAULT\', p4.limit, p2.limit))
    END
    END
    END
    END effective_life_time
    FROM dba_profiles p1, dba_profiles p2, dba_profiles p3, dba_profiles p4
    WHERE p1.profile=p2.profile
    AND p3.profile=\'DEFAULT\'
    AND p4.profile=\'DEFAULT\'
    AND p1.resource_name=\'PASSWORD_LIFE_TIME\'
    AND p2.resource_name=\'PASSWORD_GRACE_TIME\'
    AND p3.resource_name=\'PASSWORD_LIFE_TIME\' -- from DEFAULT profile
    AND p4.resource_name=\'PASSWORD_GRACE_TIME\' -- from DEFAULT profile
    order by 1;

    If the ‚Äúeffective_life_time‚Äù is greater than ‚Äú60‚Äù for any profile applied to user accounts, and the 
    need for this has not been documented and approved by the ISSO, this is a finding.

    If the value is greater than 60 for any profile applied to user accounts, and the DBMS is configured to use 
    Password Lifetime to disable inactive accounts, this is a finding.'

    desc 'fix', 'For user accounts managed by Oracle: Modify DBMS settings to force users to periodically change 
    their passwords. For example, using PPPPPP to stand for a profile name:

    ALTER PROFILE PPPPPP LIMIT PASSWORD_LIFE_TIME 60 PASSWORD_GRACE_TIME 0;
    Do this for each profile applied to user accounts.
    
    Where a password lifetime longer than ‚Äú60‚Äù is needed, document the reasons and obtain ISSO approval.'
  end

  control 'V-61745' do
    title 'Processes (services, applications, etc.) that connect to the DBMS independently of individual users, 
    must use valid, current CMS-issued PKI certificates for authentication to the  DBMS.'

    desc 'Just as individual users must be authenticated, and just as they must use PKI-based authentication, 
    so must any processes that connect to the DBMS.

    The CMS standard for authentication of a process or device communicating with another process or device is 
    the presentation of a valid, current, CMS-issued Public Key Infrastructure (PKI) certificate that has 
    previously been verified as Trusted by an administrator of the other process or device.

    This applies both to processes that run on the same server as the DBMS and to processes running on other computers.

    The Oracle-supplied accounts, SYS, SYSBACKUP, SYSDG, and SYSKM, are exceptions.  These cannot currently use 
    certificate-based authentication.  For this reason among others, use of these accounts should be restricted to 
    where it is truly needed.'

    desc 'check', 'Review configuration to confirm that accounts used by processes to connect to the DBMS are 
    authenticated using valid, current CMS-issued PKI certificates.

    If any such account (other than SYS, SYSBACKUP, SYSDG, and SYSKM) is not certificate-based, this is a finding.'

    desc 'fix', 'For each such account, use CMS certificate-based authentication.'
  end

  control 'V-61749' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not 
    mandatory in CMS ARS 3.1'
  end

  control 'V-61755' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not                               
    mandatory in CMS ARS 3.1'
  end
  
  control 'V-61757' do
    title 'The DBMS must terminate the network connection associated with a communications session at the end of 
    the session or 30 minutes of inactivity.'

    desc 'check', 'Review DBMS settings, OS settings, and vendor documentation to verify network connections 
    are terminated when a database communications session is ended or after 30 minutes of inactivity.

    If the network connection is not terminated, this is a finding.

    The defined duration for these timeouts 30 minutes, except to fulfill documented and validated mission 
    requirements.'

    desc 'fix', 'Configure DBMS and/or OS settings to disconnect network sessions when database communication 
    sessions have ended or after the CMS-defined period of inactivity.

    To configure this in Oracle, modify each relevant profile.  The resource name is IDLE_TIME, which is 
    expressed in minutes.  Using PPPPPP as an example of a profile, set the timeout to 30 minutes with:
    ALTER PROFILE PPPPPP LIMIT IDLE_TIME 30;'
  end

  control 'V-61765' do
    impact 'none'
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not selected in CMS ARS 3.1'
  end
  
  control 'V-61777' do
    title 'The DBMS must automatically terminate emergency accounts after 60 days for each type of account.'

    desc 'Emergency application accounts are typically created due to an unforeseen operational event or could 
    ostensibly be used in the event of a vendor support visit where a support representative requires a temporary 
    unique account in order to perform diagnostic testing or conduct some other support-related activity. 
    When these types of accounts are created, there is a risk that the temporary account may remain in place 
    and active after the support representative has left.

    In the event emergency application accounts are required, the application must ensure accounts that are 
    designated as temporary in nature shall automatically terminate these accounts after an organization-defined 
    time period.  Such a process and capability greatly reduces the risk that accounts will be misused, hijacked, 
    or application data compromised.

    Note that user authentication and account management must be done via an enterprise-wide mechanism whenever 
    possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, 
    Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly 
    managed by Oracle.

    If it is possible for any temporary emergency accounts to be created and managed by Oracle, then the DBMS or 
    application must provide or utilize a mechanism to automatically terminate such accounts after 60 days.

    Emergency database accounts must be automatically terminated after an organization-defined time period in 
    order to mitigate the risk of the account being misused.'

    desc 'check', 'If the organization has a policy, consistently enforced, forbidding the creation of emergency 
    or temporary accounts, this is not a finding.

    Check DBMS settings, OS settings, and/or enterprise-level authentication/access mechanisms settings to 
    determine if emergency accounts are being automatically terminated by the system after 60 days. Check also 
    for custom code (scheduled jobs, procedures, triggers, etc.) for achieving this. 

    If emergency accounts are not being terminated after 60 days, this is a finding.'

    desc 'fix', 'Create a profile specifically for emergency or temporary accounts.  When creating the accounts, 
    assign them to this profile.  Configure DBMS, OS, and/or enterprise-level authentication/access mechanisms, 
    or implement custom code, to terminate accounts with this profile after 60 days.'
  end

  control 'V-61815' do
    desc 'fix', 'Configure DBMS settings to restrict functionality that could be used to initiate DoS attacks.

    Securing the Network Connection:
    Protecting the network and its traffic from inappropriate access or modification is the essence of network 
    security. You should consider all paths the data travels, and assess the threats on each path and node. Then, 
    take steps to lessen or eliminate those threats and the consequences of a security breach. In addition, 
    monitor and audit to detect either increased threat levels or penetration attempts.

    The following practices improve network security:

    1. Disable the Default Listener.
    All listeners have a unique name instead of the name LISTENER and have startup protection.

    LISTENER=(DESCRIPTION =(ADDRESS = (PROTOCOL = TCP)(HOST=)(PORT = 0)))
    
    This configuration prevents the default listener from starting.

    2. Prevent online administration by requiring the administrator to have the write privilege on the 
    listener.ora file on the server.

    a. Add or alter this line in the listener.ora file:

    ADMIN_RESTRICTIONS_LISTENER=ON

    b. Use RELOAD to reload the configuration.

    3. Set Protection against crafted network packets on database level.

    SEC_PROTOCOL_ERROR_TRACE_ACTION specifies the action that the database should take when bad packets are 
    received from a possibly malicious client.

    SEC_PROTOCOL_ERROR_TRACE_ACTION = { NONE | TRACE | LOG | ALERT } (TRACE is the default)

    NONE: The database server ignores the bad packets and does not generate any trace files or log messages. 
    (Not recommended)

    TRACE: A detailed trace file is generated when bad packets are received, which can be used to debug any 
    problems in client/server communication.

    LOG: A minimal log message is printed in the alert logfile and in the server trace file. A minimal amount 
    of disk space is used.

    ALERT: An alert message is sent to a DBA or monitoring console.

    SEC_PROTOCOL_ERROR_FURTHER_ACTION specifies the further execution of a server process when receiving bad 
    packets from a possibly malicious client.

    SEC_PROTOCOL_ERROR_FURTHER_ACTION = { CONTINUE | (DELAY,integer) | (DROP,integer) } (DROP,3 is the default)

    CONTINUE: The server process continues execution. The database server may be subject to a Denial of Service (DoS) 
    if bad packets continue to be sent by a malicious client. (Not recommended)

    (DELAY, integer) :The client experiences a delay of integer seconds before the server process accepts the 
    next request from the same client connection. Malicious clients are prevented from excessive consumption 
    of server resources while legitimate clients experience degradation in performance but can continue to function.

    (DROP, integer) : The server forcefully terminates the client connection after integer bad packets. The server 
    protects itself at the expense of the client (for example, a client transaction may be lost). The client may 
    reconnect and attempt the same operation.

    SEC_MAX_FAILED_LOGIN_ATTEMPTS specifies the number of authentication attempts that can be made by a client on a 
    connection to the server process. After the specified number of failure attempts, the connection will be 
    automatically dropped by the server process.

    SEC_MAX_FAILED_LOGIN_ATTEMPTS = n (3 is the default) Values range from 1 to unlimited. (A value of 1 to 3 is 
    recommended)

    For more information about the parameters in listener.ora, 
    see https://docs.oracle.com/database/121/NETRF/listener.htm#NETRF008
    
    4. When a host computer has multiple IP addresses associated with multiple network interface controller (NIC) 
    cards, configure the listener to the specific IP address.

    You can restrict the listener to listen on a specific IP address. Oracle recommends that you specify the specific 
    IP addresses on these types of computers, rather than allowing the listener to listen on all IP addresses. 
    Restricting the listener to specific IP addresses helps to prevent an intruder from stealing a TCP end point from 
    under the listener process.

    5. Restrict the privileges of the listener, so that it cannot read or write files in the database or the Oracle 
    server address space.

    The default configuration for external procedures does not require a network listener to work with Oracle Database 
    and the extproc agent. The extproc agent is spawned directly by Oracle Database and eliminates the risks that the 
    extproc agent might be spawned by Oracle Listener unexpectedly. This default configuration is recommended for maximum 
    security. For more information about securing external procedures see
    https://docs.oracle.com/database/121/DBSEG/app_devs.htm#DBSEG656
    However, the extproc agent can be configured to be spawned by a listener. In that case (not recommended) the listener 
    should have restricted privileges.

    6. Use a firewall, IAW CMS network policy and guidance.
    
    Appropriately placed and configured firewalls can prevent outside access to your databases.

    7. Prevent unauthorized administration of the Oracle listener.

    Local administration of the listener is secure by default through the local operating system. Therefore configuring 
    a password is neither required nor recommended for secure local administration. However, a password can be configured 
    for the listener to provide security for administrative operations, such as starting or stopping the listener, 
    viewing a list of supported services, or saving changes to the Listener Control configuration.

    By default, Oracle Net Listener permits only local administration for security reasons. As a policy, the listener 
    can be administered only by the user who started it. This is enforced through local operating system authentication. 
    For example, if user1 starts the listener, then only user1 can administer it. Any other user trying to administer 
    the listener gets an error. The super user is the only exception.

    Oracle recommends that you perform listener administration in the default mode (secure by means of local operating 
    system authentication), and access the system remotely using a remote logon. Oracle Enterprise Manager Cloud 
    Control can also be used for remote administration.

    8. Encrypt network traffic.  (Mandatory for sensitive data and optional for non-sensitive, as covered in other 
    STIG requirements.)

    Where applicable, use Oracle network data encryption to encrypt network traffic among clients, databases, 
    and application servers.

    9. Set Connect Rate to organization defined limit. (Also required by O121-C2-019100/SRG-APP-000245-DB-000132)

    The connection rate limiter feature in Oracle Net Listener enables a database administrator to limit the number of 
    new connections handled by the listener. When this feature is enabled, Oracle Net Listener imposes a user-specified 
    maximum limit on the number of new connections handled by the listener every second.

    CONNECTION_RATE_LISTENER=10
    LISTENER=
    (ADDRESS_LIST=
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1521)(RATE_LIMIT=yes))
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1522)(RATE_LIMIT=yes))
    (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1526))  
    )

    10. Setup Valid Node Checking.
    (See also O121-BP-025600.)

    Valid node checking is a security feature that protects DBMS instances from malevolent or errant Oracle Net 
    connections over TCP/IP, without the need for a firewall or IP address filtering at the operating system-level. 
    The feature is controlled by the three parameters; tcp.validnode_checking, tcp.invited_nodes, and tcp.excluded_nodes.

    Modify the sqlnet.ora file manually
    TCP.VALIDNODE_CHECKING=yes
    (Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental 
    file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)

    If this parameter is set to yes, then incoming connections are allowed only if they originate from a node that conforms 
    to the list specified by TCP.INVITED_NODES or TCP.EXCLUDED_NODES parameters.

    The TCP.INVITED_NODES and TCP.EXCLUDED_NODES parameters are valid only when the TCP.VALIDNODE_CHECKING parameter is 
    set to yes (no is the default).

    The TCP.INVITED_NODES and TCP.EXCLUDED_NODES parameters are valid only when the TCP.VALIDNODE_CHECKING parameter 
    is set to yes.

    Modify the listener.ora file manually

    TCP.EXCLUDED_NODES Syntax:
    TCP.EXCLUDED_NODES=(hostname | ip_address, hostname | ip_address, ...)

    Example:
    TCP.EXCLUDED_NODES=(finance.us.example.com, mktg.us.example.com, 192.0.2.25, 172.30.*, 2001:DB8:200C:417A/32)

    TCP.INVITED_NODES Syntax:
    TCP.INVITED_NODES=(hostname | ip_address, hostname | ip_address, ...)

    Example:
    TCP.INVITED_NODES=(sales.us.example.com, hr.us.example.com, 192.0.*, 2001:DB8:200C:433B/32)

    Usage Notes:

    Use TCP.INVITED_NODES to specify which clients are allowed access to the database. This list takes precedence 
    over the TCP.EXCLUDED_NODES parameter if both lists are present. These parameters can use wildcards for IPv4 
    addresses and CIDR notation for IPv4 and IPv6 addresses.

    11. Apply Listener Security Patches.
    (See also O121-C1-011100/SRG-APP-000133-DB-000205.)

    Critical Patch Updates are cumulative. Therefore, the latest patch will contain all previous security patches 
    for the Listener.

    12. Ensure that listener logging is turned on.

    Listener logging is on by default. If logging is not on, configure logging for all listeners in order to capture 
    Listener commands and brute force password attacks.

    13. Monitor the listener logfile.

    The logfile may contain TNS-01169, TNS-01189, TNS-01190, or TNS-12508 errors, which may signify attacks or 
    inappropriate activity. Monitor the logfile and generate an alert whenever these errors are encountered.'
  end

  control 'V-61967' do
    desc 'fix', 'Limit concurrent connections for each system account to a number less than or equal to the 
    organization-defined number of sessions using the following SQL. Create profiles that conform to the 
    requirements. Assign users to the appropriate profile.

    The user profile, ORA_STIG_PROFILE, has been provided (starting with Oracle 12.1.0.2) to satisfy the STIG 
    requirements pertaining to the profile parameters. Oracle recommends that this profile be customized with 
    any site-specific requirements and assigned to all users where applicable.  Note: It remains necessary to 
    create a customized replacement for the password validation function, ORA12C_STRONG_VERIFY_FUNCTION, if 
    relying on this technique to verify password complexity.

    The defaults for ORA_STIG_PROFILE are set as follows:
    Resource Name                   Limit
    -------------                   ------
    COMPOSITE_LIMIT                 DEFAULT
    SESSIONS_PER_USER               DEFAULT
    CPU_PER_SESSION                 DEFAULT
    CPU_PER_CALL                    DEFAULT
    LOGICAL_READS_PER_SESSION       DEFAULT
    LOGICAL_READS_PER_CALL          DEFAULT
    IDLE_TIME                          15
    CONNECT_TIME                    DEFAULT
    PRIVATE_SGA                     DEFAULT
    FAILED_LOGIN_ATTEMPTS               3 
    PASSWORD_LIFE_TIME                 60
    PASSWORD_REUSE_TIME               365
    PASSWORD_REUSE_MAX                 10
    PASSWORD_VERIFY_FUNCTION    ORA12C_STRONG_VERIFY_FUNCTION
    PASSWORD_LOCK_TIME              UNLIMITED
    PASSWORD_GRACE_TIME                 5

    Change the value of SESSIONS_PER_USER (along with the other parameters, where relevant) from UNLIMITED to 
    CMS-compliant, site-specific requirements and then assign users to the profile.
    ALTER PROFILE ORA_STIG_PROFILE LIMIT SESSIONS_PER_USER <site-specific value>;

    To assign the user to the profile do the following:
    ALTER USER <username> PROFILE ORA_STIG_PROFILE;'
  end
end
