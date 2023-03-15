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

### Authors
* **m1lkman** - [m1lkman](https://github.com/m1lkman)
* **evansconforti** - *Initial work on Plex Forums* - [Plex Service Updater](https://forums.plex.tv/t/utility-plex-service-updater/88636)
See also the list of [contributors](https://github.com/m1lkman/Update-PlexMediaServer/contributors) who participated in this project.
### License
This script is free to use or edit, and should be used at your own risk!
### Acknowledgments
* [evanscnforti](https://forums.plex.tv/u/evansconforti/) from Plex Forums for initial code
* cjmurph for creating [Plex Media Server Service Wrapper (PMS as a Service)](https://github.com/cjmurph/PmsService)
* mrworf for inspiring most of v2.0 updates with his excellent bash based update script for Linux [plexupdate](https://github.com/mrworf/plexupdate)
* WahlNetwork for [Post-ToSlack Module](https://github.com/WahlNetwork/powershell-scripts/blob/master/Slack/Post-ToSlack.ps1)
* [The Plex Team](https://plex.tv/)
