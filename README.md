# Plex Service updater (Update-PMSInstall.pms1)

a Windows PowerShell module for automating Plex Media Server updates/upgrade with Plex Service installed. It's not much, but it sure beats manually stopping services, updating PMS and starting services.

### Prerequisites

Windows 7 with PowerShell 4.0
Windows 8 with PowerShell 5.0
Windows 10 with PowerShell 5.

(This module is not signed, so you need to change the PowerShell execution policy to unrestricted.)

Optional

Change the name Admin in the $UserName parameter. ($UserName = ""). This prevents you from manually typing the username in this parameter each time.

```
$UserName = "PMSUser"
```
### Installing

Save module as Update-PMSInstall.psm1
Save it to the %ProgramFiles%\WindowsPowerShell\Modules\Update-PMSInstall directory.

## Q&A

* Q: How do you check the current PowerShell execution policy?
* A: Open PowerShell as an Administrator, and run the following command: Get-ExecutionPolicy -Scope CurrentUser
* Q: How do you set the current users PowerShell execution policy?
* A: Open PowerShell as an Administrator, and run the following command: Set-ExecutionPolicy -Scope CurrentUser Unrestricted
* Q: How do you install the module?
* A: Create a folder called Update-PMSInstall in the %ProgramFiles%\WindowsPowerShell\Modules directory, and then copy the module Update-PMSInstall.psm1 into the %ProgramFiles%\WindowsPowerShell\Modules\Update-PMSInstall directory.
* Q: How do you use this module?
* A: First import the module by launch PowerShell as an Administrator and running the following command:
Import-Module Update-PMSInstall
Then for local execution type either:
Update-PMSInstall or Update-PMSInstall -UserName [<UserName>]
or remote execution type either:
Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PMSInstall}
 or
Invoke-Command -ComputerName Server1 -Credential [<Administrator>] -ScriptBlock ${function:Update-PMSInstall -UserName [<UserName>]}
* Q:  How often will you update the module?
* A: That is entirely up to you! Please share your updates here.

## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **evansconforti** - *Initial work on Plex Forums* - [Plex Service Updater](https://forums.plex.tv/discussion/136596/utility-plex-service-updater/p1)
* **m1lk_man** - *Copied to GitHub* - [m1lkman](https://github.com/m1lkman)

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This script is free to use or edit, and should be used at your own risk!

## Acknowledgments

* evanscnforti from Plex Forums for initial code
* The Plex Team
* cmurph for creating [PMS as a Service](https://forums.plex.tv/discussion/93994/pms-as-a-service/p1)
