# Active Directory User and Group Management Script

## Overview

This PowerShell script automates the creation of Active Directory users and groups, as well as provides a cleanup function. It's designed to be run on a Domain Controller with administrative privileges.

## Features

- Create up to 400 unique Active Directory users
- Generate random, unique passwords for each user
- Assign users to randomly selected groups and subgroups
- Create a CSV file with user information (optional)
- Clean up all created users, groups, and organizational units

## Prerequisites

- Windows Server version ≥ 2012(r2) with Active Directory Domain Services installed. 
- PowerShell 5.1 or higher
- Active Directory module for Windows PowerShell
- Domain Administrator privileges

## Usage

1. Download the script to your Domain Controller.
2. Open PowerShell as an administrator.
3. Navigate to the directory containing the script.
4. Run the script:

   ```powershell
   .\example-users.ps1

5. Choose an option:
   1. Create users
   2. Clean up domain

6. Create Users Option
    - If you choose to create users, the script will prompt you for the following information:

   1. Active Directory domain name
   2. Email domain name
   3. Number of accounts to create (max 400)
   4. Desired password length (max 128 characters)
   5. Whether to create a CSV file with user information

### Processing

**The script will then:**

- Create a new Organizational Unit named "NewUsers"
- Create the specified number of users with unique names
- Create 20 main groups and 4 subgroups for each main group
- Randomly assign users to groups and subgroups

### Clean Up Domain Option

This option will remove all users, groups, and the Organizational Unit created by this script. Use with caution!

## Notes

The script uses a predefined list of common first and last names to generate usernames.
Usernames are in the format firstname.lastname with a number appended if duplicates exist.
The script checks for both SamAccountName and CN (full name) uniqueness before creating a user.
Passwords are randomly generated based on the specified length.

### Security Considerations

This script is intended for testing or development environments.
If you choose to create a CSV file with user information, ensure it's properly secured or deleted after use, as it contains sensitive information (including passwords).

**License:**
This program is free software; you can redistribute it and/or modify it under the terms of your choice.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**Author**
@Benjamin-Connelly 2024

**Disclaimer:**
Use this script at your own risk. The author is not responsible for any unintended consequences of running this script in your environment.
