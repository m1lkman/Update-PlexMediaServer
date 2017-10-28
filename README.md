# Plex Media Server Updater PowerShell Module
Windows PowerShell module for automating Plex Media Server updates/upgrades when running with Cjmurph's Plex Media Server Service Wrapper. It automates checking latest PMS version, downloading the update, stopping services/processes, installing the update, and restarting services. It supports running interactively or silently (for automation) and downloading and installing PlexPass(Beta) updates using authorized PlexPass accounts or plex authentication tokens.
### Prerequisites
  One of the following Operating Systems with supported PowerShell version.
  * Windows 7/Windows Server 2008 with PowerShell 4.0 or later
  * Windows 8/Windows Server 2012 with PowerShell 5.0 or later
  * Windows 10/Windows Server 2016 with PowerShell 5.0 or later

  Plex Media Server 1.7 or later (https://www.plex.tv/downloads/)

  Cjmurph's Plex Media Server Service Wrapper (PMS as a Service) 1.0.3 or later (https://github.com/cjmurph/PmsService) 
### Installation
1. Save the module file (Update-PlexMediaServer.psm1) to a folder of the same name in one of your PowerShell module directories  (%ProgramFiles%\WindowsPowerShell\Modules\Update-PlexMediaServer or %UserProfile%\Documents\WindowsPowerShell\Modules by default). See [Installing a Powershell Module](https://msdn.microsoft.com/en-us/library/dd878350).
Or using git, execute the following commands:
```
cd %ProgramFiles%\WindowsPowerShell\Modules\

git clone https://github.com/m1lkman/Update-PlexMediaServer.git
```
2. Import the module by launching PowerShell as an Administrator and running the following command:
```
Import-Module Update-PlexMediaServer
```
(This module is not signed, so you need to change the PowerShell execution policy to unrestricted.)
### Parameters
All parameters can be specified either at the command-line or set in the Parameters section of script file itself if you prefer. Edit at your own risk. See examples below for use cases. Use Get-Help cmdlet for details about parameters and usage.
```
Get-Help Update-PlexMediaServer
```
### Examples
For local interactive execution type:
```
Update-PlexMediaServer
```
or remote execution type either:
```
Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PlexMediaServer}
```
or
```
Invoke-Command -ComputerName Server1 -Credential [<Administrator>] -ScriptBlock ${function:Update-PlexMediaServer -UserName [<UserName>]}
```
For local interactive execution checking for PlexPass(Beta) updates with secure password prompt
```
Update-PlexMediaServer -PlexLogin '<PlexLogin/PlexID>'
```
To silently check for PlexPass(Beta) updates using Plex authentiation token.
```
Update-PlexMediaServer -PlexToken <Token>
```
or silently check for PlexPass updates using Plex.tv login and password:
```
Update-PlexMediaServer -PlexLogin <Email/ID> -PlexPassword <Password>
```
To enable email notifications:
```
Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com
```
or enable email notifications with custom SMTP port and SSL authentiation:
```
Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL
```
Get Plex authenticaton token so you don't have to save your credentials in your scripts or scheduled tasks (will prompt if either value is missing when running interactively):
```
Get-PlexToken -PlexLogin <Email/ID> -Password <Password>
```
Get-PlexToken Syntax
```
Get-PlexToken [[-PlexLogin] <string[]>] [-Password <string[]>]
```
### Scheduled Task Example (putting it all together)
Here's the solution I use on my Plex server. I use Windows Task Scheduler to run every night at 2:00am to minimize impact to my family and friends. I use my plex authentication token to install the latest PlexPass updates and enable email notifications.

In Task Scheduler click on Create Task. Be sure to enable "Run whether user is logged on or not" and check "Run with highest privledges".

<img src="/../ScreenShots/Create%20Task.png"/>

Configure a new trigger to occur at a time and frequency when it's most likely that none of your users will be using the Plex Server. I use the following options for this example:

<img src="/../ScreenShots/New%20Trigger.png"/>

When setting up the action use the below to fill in the dialogs.

<img src="/../ScreenShots/Edit%20Action.png"/>

Program/script
```
powershell.exe
```
Add arguments
```
-Command "{& Update-PlexMediaServer -PlexToken abcdeabcdeabcdeabcde -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL}
```
### Q&A

* Q: How do you check the current PowerShell execution policy?
* A: Open PowerShell as an Administrator, and run the following command: Get-ExecutionPolicy -Scope CurrentUser
* Q: How do you set the current users PowerShell execution policy?
* A: Open PowerShell as an Administrator, and run the following command: Set-ExecutionPolicy -Scope CurrentUser Unrestricted
* Q: How do you install this module?
* A: Create a folder called Update-PlexMediaServer in the %ProgramFiles%\WindowsPowerShell\Modules directory, and then copy the module Update-PlexMediaServer.psm1 into the %ProgramFiles%\WindowsPowerShell\Modules\Update-PlexMediaServer directory.
* Q: How often will you update the module?
* A: That is entirely up to you! Create some issues or fork and fix/add whe you need.

## Version Information

  ```2.0``` 2017.10.13 (Updates by m1lkman)
  * Added logic to check plex.tv for latest PMS version and download if needed.
  * Added support for plex.tv login credentials or authentication token to validate PlexPass(Beta) PMS versions and downloads.
  * Added logic to validate checksum on downloaded updates
  * Updated logic to pull PMS user context from Plex Media Server.exe process
  * 'In Use" check exits if server is currently in use
  * Added Email notification function
  * Added Get-PlexToken function for fetching Plex authentication token via command-line
  * Added -force option to force install of PMS even when version isn't newer.
  
  2017.3.2 (Updates by m1lkman)
  * Corrected Logic for UserName briging back some origial code from eansconforti
  * New loop to execute update exe and monitor while running with logic for exitcode
  * Switched to $env:SystemDrive to build AppDataPath
  
  2017.2.27 (Updates by m1lkman)
  * Moved to GitHub [m1lkman](https://github.com/m1lkman/Update-PlexMediaServer.git)
  * Moved away from using WMI to find User SID
  * Added new do loop to find PSM exe in all possible locations
  * Switched to $env:LOCALAPPDATA
  * increased message verbosity to include version numbers added more comments
  
  2016.6.4 (Updates by evansconforti)
  * Added check to see if account is disabled.

  2016.4.15 (Updates by Justin.Wedepohl)
  * Added User check for current user if none specified.
  * Cleaned up console output.

  2016.3.5 (Updates by Justin.Wedepohl)
  * Verify EXE exists before continuing.
  * Changed the 'Last 1' to 'First 1' in the EXE sort to return the newest executable.
  * Simplified User SID logic so it works for Local accounts and domain accounts.
  * Logic to pull non-default local app path if configured then default to AppData

  2016.1.0 (Totally re-written from original script by evansconforti on plex forums)

## Authors

* **m1lk_man** - *Copied to GitHub* - [m1lkman](https://github.com/m1lkman)
* **evansconforti** - *Initial work on Plex Forums* - [Plex Service Updater](https://forums.plex.tv/discussion/136596/utility-plex-service-updater/p1)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This script is free to use or edit, and should be used at your own risk!

## Acknowledgments

* [evanscnforti](https://forums.plex.tv/profile/discussions/evansconforti) from Plex Forums for initial code
* The Plex Team
* cjmurph for creating [Plex Media Server Service Wrapper (PMS as a Service)](https://github.com/cjmurph/PmsService)
* mrworf for inspiring most of v2.0 updates with his excellent bash based update script for Linux [plexupdate](https://github.com/mrworf/plexupdate)
