# Office 365 Health Check

Office 365 Health Check is a series of Pester tests used to determine a gauge
as to the health of an Office 365 environment.

Tests are implemented to test what could be considered as good practise. Every
organization has its own unique requirements, so recommendations should be
reviewed before implementation. 

## Implemented Tests

### Tenant Details

* Provisioning Errors should be empty
* Technical Contact should be a distribution group or shared mailbox
* Self-Service Password Reset should be enabled
* Users should be allowed to create Groups
* Admin Groups should have limited membership
* Administrators should have MFA enabled

### Azure AD/DirSync

The DirSync tests follow two paths, based on whether DirSync is either enabled
or disabled in the tenant.

#### DirSync is Enabled

* DirSync is enabled
* DirSync should have run recently
* No users should have DirSync provisioning errors
* Password Hash Synchronization should be enabled
* DirSync deletion threshold should be appropriate

#### DirSync is Disabled

* DirSync is Disabled

### Per-Domain Tests

* Domain is verified
* If Federated:
  * Domain has a valid federation signing certificate
* If Managed:
  * n/a

### Per-Licence Tests

* Consumed units should not exceed ActiveUnits
* Should have no WarningUnits
* Should have no SuspendedUnits

### Exchange Online Tests

* Should be no outstanding migration batches

## Proposed Tests

* Nothing - suggest something!

## System Requirements

The following are the versions of the development system. Older versions of
various components may work.

* Pester 4.1.1
* PowerShell 5.1
* AzureAD Module 2.0.0.131
* MSOnline Module 1.1.166.0

## How to use it

```ps
Set-Location .\Office365HealthCheck
Connect-AzureAD
Connect-MsolService
Connect-EXOPSSession
Invoke-Pester
```

## How to extend it

I like to run this with [Erwan Quélin](https://github.com/equelin)'s fantastic
[Format-Pester](https://github.com/equelin/Format-Pester) module to convert
the Pester test output into a nice Word document.

```ps
Invoke-Pester | Format-Pester -Format word -GroupResultsBy Result-Describe-Context
```

## More Information

* Author: Chris Brown ([@chrisbrownie](https://github.com/chrisbrownie))
* [Blog Post](https://flamingkeys.com/office-365-health-check)

## License

Office 365 Health Check is released under the MIT license (MIT). Full text of the license is available [here](https://github.com/chrisbrownie/Office365HealthCheck/blob/master/LICENSE).
