# Update-PMSInstall

* Plex Service updater *

I'm lifting this from the same script that evansconforti first authored on Plex Forums (https://forums.plex.tv/discussion/136596/utility-plex-service-updater/p1). We worked together to modify it and I thought I would move it over to GIT for better versioning and sharing. My first git project so please bear with me.

I am posting a Windows PowerShell module that I use on my Plex Media Server with Plex Service. It's not much, but it sure beats manually stopping services, updating PMS and starting services.
 
(This module is not signed, so you need to change the PowerShell execution policy to unrestricted.)

Q&A

Q: How do you check the current PowerShell execution policy?
A: Open PowerShell as an Administrator, and run the following command: Get-ExecutionPolicy -Scope CurrentUser
Q: How do you set the current users PowerShell execution policy?
A:  Open PowerShell as an Administrator, and run the following command: Set-ExecutionPolicy -Scope CurrentUser Unrestricted
Q: How do you install the module?
A: Create a folder called Update-PMSInstall in the %ProgramFiles%\WindowsPowerShell\Modules directory, and then copy the module Update-PMSInstall.psm1 into the %ProgramFiles%\WindowsPowerShell\Modules\Update-PMSInstall directory.
Q: How do you use this module?
A: First import the module by launch PowerShell as an Administrator and running the following command:
Import-Module Update-PMSInstall
Then for local execution type either:
Update-PMSInstall or Update-PMSInstall -UserName [<UserName>]
or remote execution type either:
Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PMSInstall}
 or
Invoke-Command -ComputerName Server1 -Credential [<Administrator>] -ScriptBlock ${function:Update-PMSInstall -UserName [<UserName>]}
Q:  How often will you update the module?
A: That is entirely up to you! Please share your updates here.

Requirements

Save module as Update-PMSInstall.psm1
Save it to the %ProgramFiles%\WindowsPowerShell\Modules\Update-PMSInstall directory.
Windows 7 with PowerShell 4.0
Windows 8 with PowerShell 5.0
Windows 10 with PowerShell 5.0

Optional

Change the name Admin in the $UserName parameter. ($UserName = "Admin"). This prevents you from manually typing the username in this parameter each time.
Version Information
2016.6.4 (Updates by evansconforti)
Added check to see if account is disabled.
2016.4.15 (Updates by Justin.Wedepohl)
Added User check for current user if none specified.
Cleaned up console output.
2016.3.5 (Updates by Justin.Wedepohl)
Verify EXE exists before continuing.
Changed the 'Last 1' to 'First 1' in the EXE sort to return the newest executable.
Simplified User SID logic so it works for Local accounts and domain accounts.
Logic to pull non-default local app path if configured then default to AppData
2016.1.0 (Totally re-written)
2017.2.27
First GIT version
Moved away from using WMI to find User SID
Added new do loop to find PSM exe in all possible locations
Switched to $env:LOCALAPPDATA
increased message verbosity to include version numbers
added more comments

Issues

N/A

This script is free to use or edit, and should be used at your own risk!
