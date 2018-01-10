
Import-Module -Name Pester

# First check and make sure we're connected to the required services:
try {
    Get-AzureADTenantDetail -ErrorAction Stop | Out-Null
    Get-MsolCompanyInformation -ErrorAction Stop | Out-Null
}
catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
    throw "You must run Connect-AzureAD before executing these tests. Trying to do that now ..."
    Connect-AzureAD    
}
catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
    throw "You must run Connect-MsolService before executing these tests. Trying to do that now ..."
    Connect-MsolService
}

$Settings = @{
    "LastDirSyncThreshold"     = 120 # DirSync should have run in the last 2 hours
    "DirSyncDeletionThreshold" = 500
}

$AzureADTenantDetails = Get-AzureADTenantDetail
$AzureADDomains = Get-AzureADDomain
$MsolCompanyInformation = Get-MsolCompanyInformation
$MsolAccountSku = Get-MsolAccountSku

Describe "Tenant Checks" {
    Context "Tenant Details" {
        It "Provisioning Errors Should be Empty" {
            $AzureADTenantDetails.ProvisioningErrors | Should -Be $null
        }
        It "Technical Contact Email Should be a Distribution Group" {
            $false | Should -Be $true
        }

        It "Self-Service Password Reset should be Enabled" {
            $MsolCompanyInformation.SelfServePasswordResetEnabled | Should -Be $true
        }

        It "Users Should be Allowed to Create Groups" {
            $MsolCompanyInformation.UsersPermissionToCreateGroupsEnabled | Should -Be $true
        }
    }

    Context "DirSync" {
        if ($MsolCompanyInformation.DirectorySynchronizationEnabled) {
            # DirSync is enabled
            It "DirSync is Enabled" {
                $MsolCompanyInformation.DirectorySynchronizationEnabled | Should -Be $true
            }
            It "DirSync has run recently" {
                $DirSyncLowWaterMark = (Get-Date).ToUniversalTime().AddMinutes(0 - $Settings.LastDirSyncThreshold)
                Get-Date $AzureADTenantDetails.CompanyLastDirSyncTime | Should -BeGreaterThan $DirSyncLowWaterMark
            }

            It "No users have DirSync Provisioning Errors" {
                Get-MsolHasObjectsWithDirSyncProvisioningErrors | Should -Be $false
            }

            It "Password Hash Synchronization is enabled" {
                $MsolCompanyInformation.PasswordSynchronizationEnabled | Should -Be $true
            }

            It "DirSync Deletion Threshold is appropriate" {
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
                        It "Has a valid federation signing certificate" {
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