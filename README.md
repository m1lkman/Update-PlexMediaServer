# Plex Media Server Updater PowerShell Module
Windows PowerShell module for automating Plex Media Server updates when running with Cjmurph's Plex Media Server Service Wrapper. This module automates checking latest Plex Media Server public or Beta(PlexPass) versions, downloading the update, stopping services/processes, installing the update, and restarting services. Supports interactive or silent execution (for automation), with logging, and email notification. Authentication is performed against Plex.tv server using either Plex Authentication Tokens (User or Server) or Plex.tv credentials.
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
Syntax
```
Update-PlexMediaServer [[-UseServerToken]] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-WhatIf] [-Confirm]  [<CommonParameters>]

Update-PlexMediaServer [[-UseServerToken]] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-Force] [-UpdateCleanup <int>] [-Quiet] [-WhatIf] [-Confirm]  [<CommonParameters>]

Update-PlexMediaServer [[-UseServerToken]] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-WhatIf] [-Confirm]  [<CommonParameters>]

Update-PlexMediaServer [-EmailNotify] [[-PlexPassword] <string>] -SmtpTo <string> -SmtpFrom <string> -SmtpUser <string> -SmtpPassword <string> -SmtpServer <string> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-AttachLog] [-IncludeLog] [-SmtpPort <int>] [-EnableSSL] [-WhatIf] [-Confirm]  [<CommonParameters>]

Update-PlexMediaServer [-PlexToken] <string> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-WhatIf] [-Confirm]  [<CommonParameters>]

Update-PlexMediaServer [-Credential] <pscredential> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-WhatIf] [-Confirm] [<CommonParameters>]

Update-PlexMediaServer [-PlexLogin] <string> [[-PlexPassword] <string>] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-WhatIf] [-Confirm] [<CommonParameters>]

Update-PlexMediaServer [-LogFile] <string> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-AttachLog] [-IncludeLog] [-WhatIf] [-Confirm] [<CommonParameters>]
```
### Examples
For local interactive default execution using Plex Server Online token (requires Plex Server is logged in and Claimed) to authenticate to Plex.tv for updates (will honor Plex Server Update Channel Setting):
```
Update-PlexMediaServer
```
or remote execution type either:
```
Invoke-Command -ComputerName Server1 [-Credential] <pscredential> -ScriptBlock {Update-PlexMediaServer}
```
or if Plex Media Server is running in a user context other than the credentials of PowerShell use -Username parameter:
```
Invoke-Command -ComputerName Server1 [-Credential] <pscredential> -ScriptBlock {Update-PlexMediaServer -UserName <UserName>}
```
For local interactive execution with password prompt
```
Update-PlexMediaServer -PlexLogin '<PlexLogin/PlexID>'
```
Execute silently using Plex Authentication Token (Use Get-PlexToken to find your token):
```
Update-PlexMediaServer -PlexToken <Token> -Quiet
```
Execute passively using Plex Server Online Authentication Token (requires Plex Server is logged in and Clamied).
```
Update-PlexMediaServer -UseServerToken -Passive
```
or silently check for PlexPass updates using Plex.tv login and password:
```
Update-PlexMediaServer -PlexLogin <Email/ID> -PlexPassword <Password> -Quiet
```
to disable PlexPass(Beta) updates and cleanup all Updates from the Updates folder except the latest 2:
```
Update-PlexMediaServer -DisablePlexPass -UpdateCleanup 2
```
To enable email notifications:
```
Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com
```
or enable email notifications with custom SMTP port and SSL authentication:
```
Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL
```
### Scheduled Task Example (putting it all together)
Here's the solution I use on my Plex server. I use Windows Task Scheduler to run every night at 2:00am to minimize impact to my family and friends. I use the default execution menthod leveraging my server's Online Authentication Token to install the latest PlexPass updates. I also enabled email notification with log included and update cleanup to remove all previous updates except the latest 2.

In Task Scheduler click on Create Task. Be sure to enable "Run whether user is logged on or not" and check "Run with highest privileges".

<img src="/../ScreenShots/Create%20Task.png"/>

Configure a new trigger to occur at a time and frequency when it's most likely that none of your users will be using the Plex Server. I use the following options for this example:

<img src="/../ScreenShots/New%20Trigger.png"/>

When setting up the action use the below to fill in the dialogs.

<img src="/../ScreenShots/New%20Action.png"/>

Program/script
```
powershell.exe
```
Add arguments
```
-Command "{& Update-PlexMediaServer -Quiet -EmailNotify -IncludeLog -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL -UpdateCleanup 2}
```

### Find Your Plex Authentication Token (Get-PlexToken)
Get Plex Authentication token so you don't have to save your credentials in your scripts or scheduled tasks (will prompt if either value is missing when running interactively):
```
Get-PlexToken -PlexLogin <Email/ID> -Password <Password>
```
Get-PlexToken Syntax
```
Get-PlexToken [[-PlexLogin] <string>] [[-PlexPassword] <string>] [-PassThru] [-Credential <pscredential>]  [<CommonParameters>]
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
```v2.0.3 2017.11.9 (Updates by m1lkman)```
  * Added IncludeLog parameter for including log text in notification (renamed EmailLog AttachLog)
  * Improved notification logic and general logging content
  
```v2.0.2 2017.11.8 (Updates by m1lkman)```
  * Corrected logging error causing large log file
  
```v2.0.1 2017.11.1 (Updates by m1lkman)```
  * Corrected some error handling when PMS exe was not detected
  * Added -UpdateCleanup parameter and logic to remove old updates from updates folder
  * Improved error capture for Send-ToEmail function to return exception with passthru

  ```v2.0.0 2017.10.31 (Updates by m1lkman)```
  * Significant updates to validate and download the latest version from Plex.tv (Public or PlexPass/Beta)
  * Supports authenticating against Plex.tv and local server using Plex.tv credentials or Tokens
  * Default execution leverages PMS Server Online Authentication token, honors Update Channel setting.
  * Added logic to validate checksum on downloaded updates
  * Updated logic to pull PMS user context from Plex Media Server.exe process
  * "In-Use Check" will exit when active Sessions are detected on Plex Media Server 
  * Validates PMS process and Plex Web availability after update
  * Added Email notification function
  * Added Get-PlexToken function for fetching Plex authentication token via command-line
  * Added -force option to force install of PMS even when version isn't newer.
  
  ```v1.0.0 2017.3.2 (Updates by m1lkman)```
  * Corrected Logic for UserName briging back some origial code from eansconforti
  * New loop to execute update exe and monitor while running with logic for exitcode
  * Switched to $env:SystemDrive to build AppDataPath
  
  ```2017.2.27 (Updates by m1lkman)```
  * Moved to GitHub [m1lkman](https://github.com/m1lkman/Update-PlexMediaServer.git)
  * Moved away from using WMI to find User SID
  * Added new do loop to find PSM exe in all possible locations
  * Switched to $env:LOCALAPPDATA
  * increased message verbosity to include version numbers added more comments
  
  ```2016.6.4 (Updates by evansconforti)```
  * Added check to see if account is disabled.

  ```2016.4.15 (Updates by Justin.Wedepohl)```
  * Added User check for current user if none specified.
  * Cleaned up console output.

  ```2016.3.5 (Updates by Justin.Wedepohl)```
  * Verify EXE exists before continuing.
  * Changed the 'Last 1' to 'First 1' in the EXE sort to return the newest executable.
  * Simplified User SID logic so it works for Local accounts and domain accounts.
  * Logic to pull non-default local app path if configured then default to AppData

  ```2016.1.0```
  (Totally re-written from original script by evansconforti on plex forums)

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
