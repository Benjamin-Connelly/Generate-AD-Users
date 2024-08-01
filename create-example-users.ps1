## example-users.ps1
##
## Blame: @Benjamin-Connelly 2024
##
## Owner: Everyone. This program is free software you can redistribute it and/or modify it as much as you would like.
##
## Usage: Run ./example-users.ps1 on your Domain Controller in an admin PowerShell.
##
## Purpose: Create a user-specified number of random Active Directory accounts and assign them to randomized groups and subgroups, or clean up the domain.
##
## How: This script uses the ActiveDirectory module
##

# Import the Active Directory module
Import-Module ActiveDirectory

# Function to create users and groups
function Create-UsersAndGroups {
    # Prompt for Active Directory domain name
    $adDomain = Read-Host "Enter the Active Directory domain name (e.g., ad.example.com)"

    # Prompt for email domain
    $emailDomain = Read-Host "Enter the email domain name (e.g., example.com)"
    $emailDomain = $emailDomain.TrimStart('@')  # Remove leading @ if present

    # Prompt for number of users
    $numAccounts = Read-Host "Enter the number of accounts to create (max 400)"
    $numAccounts = [math]::Min([int]$numAccounts, 400)

    # Prompt for password length
    $passwordLength = Read-Host "Enter the desired password length (max 128 characters)"
    $passwordLength = [math]::Min([int]$passwordLength, 128)

    # Prompt for CSV file creation
    $createCsv = Read-Host "Would you like to create a CSV file with user information? (Y/N)"
    $createCsv = $createCsv.ToUpper() -eq "Y"

    # List of common US first names (mixed gender)
    $firstNames = @("James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda", "William", "Elizabeth", "David", "Barbara", "Richard", "Margaret", "Joseph", "Susan", "Thomas", "Dorothy", "Charles", "Lisa")

    # List of common US last names
    $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin")

    # List of main groups
    $mainGroups = @(
        "IT Department", "Human Resources", "Finance", "Sales", "Marketing",
        "Customer Service", "Research and Development", "Operations", "Legal",
        "Executive Management", "Facilities Management", "Quality Assurance",
        "Project Management", "Accounting", "Procurement", "Training and Development",
        "Production", "Logistics", "Business Analysis", "Data Management"
    )

    # Extract domain components for AD
    $adDomainComponents = $adDomain.Split('.')
    $dcPath = ($adDomainComponents | ForEach-Object { "DC=$_" }) -join ','

    # Create OU for new users if it doesn't exist
    $ouPath = "OU=NewUsers,$dcPath"
    if (-not (Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $ouPath})) {
        New-ADOrganizationalUnit -Name "NewUsers" -Path $dcPath -ProtectedFromAccidentalDeletion $false
        Write-Host "Created OU: NewUsers"
    } else {
        Write-Host "OU: NewUsers already exists"
    }

    # Create users
    $createdCount = 0
    $userInfo = @()
    while ($createdCount -lt $numAccounts) {
        $firstName = $firstNames | Get-Random
        $lastName = $lastNames | Get-Random
        $baseAccountName = "$($firstName.ToLower()).$($lastName.ToLower())"
        $samAccountName = $baseAccountName
        $suffix = 1

        # Keep trying with incremented suffixes until we find a unique username and CN
        while ($true) {
            $fullName = "$firstName $lastName"
            if ($suffix -gt 1) {
                $fullName += " $suffix"
            }
            $cnExists = Get-ADUser -Filter {Name -eq $fullName} -ErrorAction SilentlyContinue
            $samExists = Get-ADUser -Filter {SamAccountName -eq $samAccountName} -ErrorAction SilentlyContinue

            if (-not $cnExists -and -not $samExists) {
                break
            }

            $suffix++
            $samAccountName = "${baseAccountName}${suffix}"
        }

        $emailAddress = "$samAccountName@$emailDomain"
        $upn = "$samAccountName@$adDomain"
        $distinguishedName = "CN=$fullName,$ouPath"
        $password = Get-RandomPassword -length $passwordLength

        try {
            New-ADUser -Name $fullName `
                       -GivenName $firstName `
                       -Surname $lastName `
                       -SamAccountName $samAccountName `
                       -UserPrincipalName $upn `
                       -EmailAddress $emailAddress `
                       -Enabled $true `
                       -ChangePasswordAtLogon $true `
                       -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
                       -Path $ouPath `
                       -ErrorAction Stop

            Write-Host "Created user: $fullName ($samAccountName) with email: $emailAddress and password: $password"
            $createdCount++

            if ($createCsv) {
                $userInfo += [PSCustomObject]@{
                    FirstName = $firstName
                    LastName = $lastName
                    FullName = $fullName
                    SamAccountName = $samAccountName
                    Email = $emailAddress
                    Password = $password
                }
            }
        } catch {
            Write-Host "Failed to create user: $samAccountName. Error: $_"
        }
    }

    # Create main groups and subgroups
    foreach ($group in $mainGroups) {
        if (-not (Get-ADGroup -Filter {Name -eq $group} -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $group -GroupScope Global -Path $ouPath
            Write-Host "Created main group: $group"
        } else {
            Write-Host "Main group $group already exists"
        }

        $subgroups = Get-Subgroups -mainGroup $group
        foreach ($subgroup in $subgroups) {
            if (-not (Get-ADGroup -Filter {Name -eq $subgroup} -ErrorAction SilentlyContinue)) {
                New-ADGroup -Name $subgroup -GroupScope Global -Path $ouPath
                Write-Host "Created subgroup: $subgroup"
            } else {
                Write-Host "Subgroup $subgroup already exists"
            }
        }
    }

    # Randomly assign users to groups and subgroups
    $users = Get-ADUser -Filter * -SearchBase $ouPath
    foreach ($user in $users) {
        $mainGroupCount = Get-Random -Minimum 1 -Maximum 3
        $selectedMainGroups = $mainGroups | Get-Random -Count $mainGroupCount

        foreach ($mainGroup in $selectedMainGroups) {
            Add-ADGroupMember -Identity $mainGroup -Members $user
            Write-Host "Added $($user.Name) to main group: $mainGroup"

            $subgroups = Get-Subgroups -mainGroup $mainGroup
            $subgroup = $subgroups | Get-Random
            Add-ADGroupMember -Identity $subgroup -Members $user
            Write-Host "Added $($user.Name) to subgroup: $subgroup"
        }
    }

    # Create CSV file if requested
    if ($createCsv) {
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        $csvPath = Join-Path $desktopPath "ADUserInfo.csv"
        $userInfo | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "CSV file with user information has been created at: $csvPath"
    }

    Write-Host "User creation and group assignment completed."
}

# Function to clean up the domain
function Clean-Domain {
    $confirmation = Read-Host "Are you sure you want to clean up the domain? This action will delete all users, groups, and OUs created by this script. (Y/N)"
    if ($confirmation -eq "Y") {
        # Get the domain
        $domain = Get-ADDomain
        $ouPath = "OU=NewUsers,$($domain.DistinguishedName)"

        # Delete users in the NewUsers OU
        Get-ADUser -Filter * -SearchBase $ouPath | ForEach-Object {
            Remove-ADUser -Identity $_ -Confirm:$false
            Write-Host "Deleted user: $($_.SamAccountName)"
        }

        # Delete groups in the NewUsers OU
        Get-ADGroup -Filter * -SearchBase $ouPath | ForEach-Object {
            Remove-ADGroup -Identity $_ -Confirm:$false
            Write-Host "Deleted group: $($_.Name)"
        }

        # Delete the NewUsers OU
        try {
            Get-ADOrganizationalUnit -Identity $ouPath | Set-ADObject -ProtectedFromAccidentalDeletion:$false -PassThru | Remove-ADOrganizationalUnit -Confirm:$false
            Write-Host "Deleted OU: NewUsers"
        } catch {
            Write-Host "Failed to delete OU: NewUsers. Error: $_"
        }

        Write-Host "Domain cleanup completed."
    } else {
        Write-Host "Operation cancelled. No changes were made."
    }
}

# Function to generate subgroups
function Get-Subgroups {
    param (
        [string]$mainGroup
    )
    $subgroups = @(
        "$mainGroup - Team Leaders",
        "$mainGroup - Staff",
        "$mainGroup - Interns",
        "$mainGroup - Contractors"
    )
    return $subgroups
}

# Function to generate a random password
function Get-RandomPassword {
    param (
        [int]$length
    )
    $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lowercase = "abcdefghijklmnopqrstuvwxyz"
    $numbers = "0123456789"
    $symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    $allChars = $uppercase + $lowercase + $numbers + $symbols

    $password = ""
    for ($i = 0; $i -lt $length; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    return $password
}

# Main script execution
$choice = Read-Host "Choose an option:
1. Create users
2. Clean up domain
Enter your choice (1 or 2)"

switch ($choice) {
    "1" { Create-UsersAndGroups }
    "2" { Clean-Domain }
    default { Write-Host "Invalid choice. Script terminated." }
}
