# Plex Media Server Updater PowerShell Module
Windows PowerShell module for automating Plex Media Server updates when running with Cjmurph's Plex Media Server Service Wrapper. This module automates checking for the latest Plex Media Server public or beta channel (PlexPass) versions, checking if the server is "in-use", downloading the update, stopping services/processes, installing the update, and restarting services. Supports interactive or silent execution (for automation), with logging, and notifications. Authentication is performed against Plex.tv server using either Plex Authentication Tokens (User or Server) or Plex.tv credentials.
### Prerequisites
  Supported Operating Systems with supported PowerShell version.
  * Windows 7/Windows Server 2008 with PowerShell 4.0 or later
  * Windows 8/10/11/Windows Server 2012/2016/2019/2022 with PowerShell 5.0 or later
 
  Plex Media Server (https://www.plex.tv/downloads/)
  * 1.7 or later (windows-x86)
  * 1.29 or later (windows-x86_64)

  Cjmurph's [Plex Media Server Service Wrapper](https://github.com/cjmurph/PmsService)
  * 1.0.3 or later for PMS windows-x86 builds
  * 1.2.1 or later for PMS windows-x86_64 builds
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
Update-PlexMediaServer [[-UseServerToken]] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]

Update-PlexMediaServer [[-UseServerToken]] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-Force] [-UpdateCleanup <int>] [-Quiet] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]

Update-PlexMediaServer [[-UseServerToken]] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]

Update-PlexMediaServer [-EmailNotify] [[-PlexPassword] <string>] -SmtpTo <string> -SmtpFrom <string> -SmtpUser <string> -SmtpPassword <string> -SmtpServer <string> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-AttachLog] [-IncludeLog] [-SmtpPort <int>] [-EnableSSL] [-EmailIsBodyHtml] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]

Update-PlexMediaServer [-SlackNotify] -SlackChannel <string> -SlackToken <string> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]

Update-PlexMediaServer [-PlexToken] <string> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [[-Build] [-Hostname] [-ReportOnly]  [<CommonParameters>]

Update-PlexMediaServer [-Credential] <pscredential> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]

Update-PlexMediaServer [-PlexLogin] <string> [[-PlexPassword] <string>] [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-LogFile <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]

Update-PlexMediaServer [-LogFile] <string> [-DisablePlexPass] [-PlexServerPort <int>] [-UserName <string>] [-Force] [-UpdateCleanup <int>] [-Passive] [-Quiet] [-AttachLog] [-IncludeLog] [-Build] [-Hostname] [-ReportOnly] [<CommonParameters>]
```
### Examples
For local interactive default execution using Plex Server Online token (requires Plex Server is logged in and claimed) to authenticate to Plex.tv for updates (will honor Plex Server Update Channel Setting):
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
or silently check for beta channel (PlexPass) updates using Plex.tv login and password:
```
Update-PlexMediaServer -PlexLogin <Email/ID> -PlexPassword <Password> -Quiet
```
to disable beta channel (PlexPass) updates and cleanup all Updates from the Updates folder except the latest 2:
```
Update-PlexMediaServer -DisablePlexPass -UpdateCleanup 2
```
force checking for build windows-x86_64 even if windows-x86 build is installed, i.g. upgrade to 64-bit
```
Update-PlexMediaServer -Build 'windows-x86_64'
```
check plex running on localhost and bypass public IP reverse DNS lookup
```
Update-PlexMediaServer -PlexServerHostname 'localhost'
```
To enable email notifications:
```
Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com
```
or enable email notifications with custom SMTP port and SSL authentication:
```
Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL
```
#Slack channel notification:
```
Update-PlexMediaPlayer -SlackNotify -SlackChannel '#ChannelName' -SlackToken <Slack OAuth Token>
```
### Scheduled Task Example (putting it all together)
Here's the solution I use on my Plex server. I use Windows Task Scheduler to run every night at 2:00am to minimize impact to my family and friends. I use the default execution menthod leveraging my server's Online Authentication Token to install the latest beta channel (PlexPass) updates. I also enabled email notification with log included and update cleanup to remove all previous updates except the latest 2.

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

Note: [Plex Two Factor Authentication](https://support.plex.tv/articles/two-factor-authentication/) must be disabled (i.e. temporarily) 
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
* A: Create a folder called Update-PlexMediaServer in the %ProgramFiles%\WindowsPowerShell\Modules directory, copy the module Update-PlexMediaServer.psm1 into the %ProgramFiles%\WindowsPowerShell\Modules\Update-PlexMediaServer directory, and then run `Immport-Module .\Update-PlexMediaServer`.
* Q: How do I uninstall this module?
* A: Run `Remove-Module Update-PlexMedaiServer` and then delete the folder and it's contents you created.
* Q: How do I get a Plex authentication token? (I don't trust your Get-PlexToken code)
* A: Follow Plex's Support Article [Finding an authentication token / X-Plex-Token](https://support.plex.tv/articles/204059436-finding-an-authentication-token-x-plex-token/).
* Q: How often will you update the module?
* A: That is entirely up to you! Create some issues or fork and fix/add what you need.

## Version Information
```v2.0.6 2023.3.11 (Updates by m1lkman)```
  * Improved error handling

```v2.0.6 2023.3.11 (Updates by m1lkman)```
  * Fixed Token Regex verification (added - and _)
  * Fixed logic for searching registry for InstallLocation and PlexOnlineToken that were causing issues on systems that have had both x86 and x64 builds installed previously
  * Improved Update Channel detection logic
  * Improved some error messages
  * Added additional logic to uninstall x64 build first before installing x86 build if present
  * Improved exit code matching specifically for x64 installer
  * Other various cleanups, fixes, & improvements

```v2.0.5 2023.3.10 (Updates by m1lkman)```
  * Added support for windows-x86_64 PMS build. Update-PlexMediaServer will continue to update the currently installed Build unless forced by Build parameter (i.g. `-Build 'windows-x86_64'`)
  * Fix logic to detect active sessions for "in-use" check
  * Fix Invoke-WebRequest errors by adding UseBasicParsing parameter (Thanks [SAS-1](https://github.com/SAS-1))
  * Added logic to retry checking Plex Web after process restart to allow for 30 seconds while web server is launching
  * Added Hostname parameter for plex web checks to bypass detecting public hostname using reverse IP lookup (helps for when running multiple PMS instances behind a single public IP)
  * Added ReportOnly parameter, script will report if update is reqiured and exit
  * Add support for https url scheme when using custom port 443 `-PlexServerPort 443`
  * Other general improvments/fixes

```v2.0.4 2017.11.15 (Updates by m1lkman)```
  * Added new logic to detect Live TV and DVR sessions to "in-use" check
  * Improved logic for stopping PlexService Service 
  
```v2.0.3 2017.11.10 (Updates by m1lkman)```
  * Added -IncludeLog parameter for including log text in notification email (renamed EmailLog to AttachLog)
  * Added -EmailIsBodyHtml parameter to switch email to mobile friendly HTML format 
  * Improved notification logic and general logging content
  * Added support for #Slack notifications with -SlackNotify parameter (Slack OAuth token required)
  
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
* cjmurph for creating [Plex Media Server Service Wrapper (PMS as a Service)](https://github.com/cjmurph/PmsService)
* mrworf for inspiring most of v2.0 updates with his excellent bash based update script for Linux [plexupdate](https://github.com/mrworf/plexupdate)
* WahlNetwork for [Post-ToSlack Module](https://github.com/WahlNetwork/powershell-scripts/blob/master/Slack/Post-ToSlack.ps1)
* [The Plex Team](https://plex.tv/)
