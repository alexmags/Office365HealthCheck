
#Requires -Modules @{ModuleName="Pester";ModuleVersion="4.0.0"}
#Requires -Modules @{ModuleName="AzureAD";ModuleVersion="2.0.0.0"}
#Requires -Modules @{ModuleName="MSOnline";ModuleVersion="1.1.0.0"}

Import-Module -Name Pester

# First check and make sure we're connected to the required services:
try {
    Get-AzureADTenantDetail -ErrorAction Stop | Out-Null
}
catch {
    throw "You must run Connect-AzureAD before executing these tests."
}

try {
    Get-MsolCompanyInformation -ErrorAction Stop | Out-Null
}
catch {
    throw "You must run Connect-MsolService before executing these tests."
}

# Make sure the EXO module is present
if (
    -not (Get-Module | Where-Object { ($_.Name -ilike "tmp_*") -and ($_.Description -ilike "Implicit remoting for https://outlook.office365.com/PowerShell-LiveId*") })
) {
    # EXO module is not present
    throw "You must run Connect-EXOPSSession before executing these tests."
}
    

$Settings = @{
    "LastDirSyncThreshold"     = 120 # DirSync should have run in the last 2 hours
    "DirSyncDeletionThreshold" = 500
    "AzureADNonMFARoles"       = @( # Azure AD roles that do not require MFA
        "Directory Synchronization Accounts"
    )
    "AdminGroupThreshold"      = 10 # Should be fewer than this many members in Admin Groups
    "AdminGroups"              = @( # Admin Groups to check membership count of
        "Company Administrator",
        "Lync Service Administrator",
        "Security Administrator",
        "CRM Service Administrator",
        "SharePoint Service Administrator",
        "Power BI Service Administrator",
        "Privileged Role Administrator",
        "Exchange Service Administrator"
    )
}

$AzureADTenantDetails = Get-AzureADTenantDetail
$AzureADDomains = Get-AzureADDomain
$MsolCompanyInformation = Get-MsolCompanyInformation
$MsolAccountSku = Get-MsolAccountSku

Describe -Tag "Tenant" -Name "Tenant Checks" {
    Context "Tenant Details" {
        It "Provisioning Errors Should be Empty" {
            $AzureADTenantDetails.ProvisioningErrors | Should -Be $null
        }
        It "Technical Contact Email Should be a Distribution Group" {
            # Check that at least one member of TechnicalNotificationMails is a Group or Distribution Group

            $SupportedRecipientTypes = @(
                "MailUniversalDistributionGroup",
                "DynamicDistributionGroup",
                "GroupMailbox",
                "MailNonUniversalGroup",
                "MailUniversalSecurityGroup",
                "RemoteSharedMailbox",
                "RemoteTeamMailbox",
                "SharedMailbox",
                "TeamMailbox"
            )

            $FoundAGroup = $false
            foreach ($TechnicalNotificationMail in $AzureADTenantDetails.TechnicalNotificationMails) {
                Remove-Variable TechnicalNotificationMailRecipient -ErrorAction SilentlyContinue
                $TechnicalNotificationMailRecipient = Get-Recipient $TechnicalNotificationMail -RecipientTypeDetails $SupportedRecipientTypes -ErrorAction SilentlyContinue
                if ($TechnicalNotificationMailRecipient) {
                    $FoundAGroup = $true
                }
            }
            $FoundAGroup | Should -Be $true
        }

        It "Self-Service Password Reset should be Enabled" {
            $MsolCompanyInformation.SelfServePasswordResetEnabled | Should -Be $true
        }

        It "Users should be Allowed to Create Groups" {
            $MsolCompanyInformation.UsersPermissionToCreateGroupsEnabled | Should -Be $true
        }

        It "Admin Groups should have limited membership" {
            $results = @()
            Get-AzureADDirectoryRole | 
                Where-Object { $settings.AdminGroups -contains $_.DisplayName } | 
                ForEach-Object {
                $results += New-Object -TypeName PSObject -Property @{
                    "Group"   = $_.DisplayName
                    "Members" = ($_ | Get-AzureADDirectoryRoleMember | Measure-Object).Count
                }
            }
            $results | 
                Where-Object { $_.Members -ge $settings.AdminGroupThreshold } |
                Should -Be $null

        }

        It "Administrators should have MFA enabled" {
            # Get all Azure AD admin roles, except those in "AzureADNonMFARoles"
            $AdminsWithoutMfa = @()
            Get-AzureADDirectoryRole | 
                Where-Object {$settings.AzureADNonMFARoles -notcontains $_.DisplayName } |
                ForEach-Object {

                # Get all the members of the role
                $RoleMemberIds = $_ | Get-AzureADDirectoryRoleMember | Select-Object -ExpandProperty ObjectId
                foreach ($RoleMemberId in $RoleMemberIds) {
                    $AdminsWithoutMfa += Get-MsolUser -ObjectId $RoleMemberId -ErrorAction SilentlyContinue | Where-Object { $_.StrongAuthenticationRequirements.State -ne "Enforced" }
                }

            }

            $AdminsWithoutMfa | Select-Object -ExpandProperty UserPrincipalName -Unique | Should -Be $null
        }

    }

    Context "DirSync" {
        if ($MsolCompanyInformation.DirectorySynchronizationEnabled) {
            # DirSync is enabled
            It "DirSync is Enabled" {
                $MsolCompanyInformation.DirectorySynchronizationEnabled | Should -Be $true
            }
            It "DirSync should have run recently" {
                $DirSyncLowWaterMark = (Get-Date).ToUniversalTime().AddMinutes(0 - $Settings.LastDirSyncThreshold)
                Get-Date $AzureADTenantDetails.CompanyLastDirSyncTime | Should -BeGreaterThan $DirSyncLowWaterMark
            }

            It "No users should have DirSync provisioning errors" {
                Get-MsolHasObjectsWithDirSyncProvisioningErrors | Should -Be $false
            }

            It "Password Hash Synchronization should be enabled" {
                $MsolCompanyInformation.PasswordSynchronizationEnabled | Should -Be $true
            }

            It "DirSync deletion threshold should be appropriate" {
                Get-MsolDirSyncConfiguration | Select-Object -ExpandProperty AccidentalDeletionThreshold | Should -BeLessThan ($Settings.DirSyncDeletionThreshold + 1)
            }
        }
        else {
            # DirSync is disabled
            It "DirSync is Disabled" {
                $MsolCompanyInformation.DirectorySynchronizationEnabled | Should -Be $false
            }
        }
    }
    
    foreach ($domain in ($AzureADDomains)) {
        Context "Domain: $($Domain.Name)" {
            It "Domain is verified" {
                $Domain.IsVerified | Should -Be $true
            }
            
        
            switch ($domain.AuthenticationType) {
                "Federated" {
                    if ($Domain.IsRoot) {
                        $DomainFederationSettings = Get-MsolDomainFederationSettings -DomainName $Domain.Name
                        It "Domain has a valid federation signing certificate" {
                            Remove-Variable certString -ErrorAction SilentlyContinue
                            Remove-Variable certByteArray -ErrorAction SilentlyContinue
                            Remove-Variable cert -ErrorAction SilentlyContinue
                            
                            $certString = $DomainFederationSettings.SigningCertificate
                            $certByteArray = ([System.Text.Encoding]::ASCII).GetBytes($certString)
                            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certByteArray)
                            $cert | Should -Not -BeNullOrEmpty
                        }
                    }
                }
                "Managed" {

                }
                default {
                    Write-Warning "Domain Authentication mechanism of '$($Domain.AuthenticationType)' is unsupported by this test."
                }
            }
        }
    }

    foreach ($sku in $MsolAccountSku) {
        Context "SKU: $($sku.AccountSkuId)" {
            It "ConsumedUnits should not exceed ActiveUnits" {
                [int]($sku.ActiveUnits + 1) | Should -BeGreaterThan $sku.ConsumedUnits
            }

            It "Should have no WarningUnits" {
                $sku.WarningUnits | Should -Be 0
            }

            It "Should have no SuspendedUnits" {
                $sku.SuspendedUnits | Should -Be 0
            }
        }
    }
}

Describe -Tag "EXO" -Name "Exchange Online Checks" {
    Context "Recipients" {
        It "Should be no outstanding migration batches" {
            Get-MigrationBatch | Should -Be $null
        }
    }
}
