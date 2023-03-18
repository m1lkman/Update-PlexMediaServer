#Requires -Version 4.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
   Module for managing Plex Media Server updates running Plex Media Server Service Wrapper (PlexService).
.DESCRIPTION
   Windows PowerShell module for automating Plex Media Server updates when running with Cjmurph's Plex Media Server Service Wrapper. This module automates checking latest Plex Media Server public or Beta(PlexPass) versions, downloading the update, stopping services/processes, installing the update, and restarting services. Supports interactive or silent execution (for automation), with logging, and email notification. Authentication is performed against Plex.tv server using either Plex Authentication Tokens (User or Server) or Plex.tv credentials.
.PARAMETER UseServerToken
.PARAMETER PlexToken
.PARAMETER Credential
.PARAMETER PlexLogin
.PARAMETER PlexPassword
.PARAMETER DisablePlexPass
.PARAMETER PlexServerPort
.PARAMETER PlexServerHostName
.PARAMETER UserName
.PARAMETER LogFile
.PARAMETER Force
.PARAMETER ReportOnly
.PARAMETER Build
.PARAMETER UpdateCleanup
.PARAMETER Passive
.PARAMETER Quiet
.PARAMETER SlackNotify
.PARAMETER SlackChannel
.PARAMETER SlackToken
.PARAMETER EmailNotify
.PARAMETER AttachLog
.PARAMETER IncludeLog
.PARAMETER SmtpTo
.PARAMETER SmtpFrom
.PARAMETER SmtpUser
.PARAMETER SmtpPassword
.PARAMETER SmtpServer
.PARAMETER SmtpPort
.PARAMETER EnableSSL
.PARAMETER EmailIsBodyHtml
.INPUTS
.OUTPUTS
  Log file 
.EXAMPLE
Run Interactively and attempt to update from publicly available updates.
   Update-PlexMediaServer
.EXAMPLE
Force Upgrade/reinstall even if version is greater than or equal to
   Update-PlexMediaServer -Force
.EXAMPLE
Run Interactively and specify a user other than the context the script is executing in.
   Update-PlexMediaServer -UserName JDoe
.EXAMPLE
Run interactively and attempt to update from PlexPass(Beta) available updates. Will prompt for Plex.tv Email/Id and password.
   Update-PlexMediaServer -PlexPass
.EXAMPLE
Run silently and attempt to update from PlexPass(Beta) available updates.
    Update-PlexMediaServer -PlexToken <Token> -Silent
.EXAMPLE
Run Passive and update using Server Online Authentication Token.
   Update-PlexMediaServer -PlexServerToken -Passive
.EXAMPLE
   Update-PlexMediaServer -PlexLogin <Email/ID> -PlexPassword <Password>
.EXAMPLE
   Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock {Update-PlexMediaServer -UserName JDoe} 
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock {Update-PlexMediaServer -UserName JDoe} 
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock {Update-PlexMediaServer -UserName JDoe} 
.NOTES
.LINK
    https://github.com/m1lkman/Update-PlexMediaServer
#>Function Update-PlexMediaServer
{
    [CmdletBinding(PositionalBinding=$False,SupportsShouldProcess,DefaultParameterSetName="ServerAuth")]
    param(
        # passive - minimal UI no prompts
        [Parameter(Mandatory,ParameterSetName="Passive",HelpMessage="Displays minimal UI with no prompts")]
        
        [switch]$Passive,

        # quiet - no UI no prompts
        [Parameter(Mandatory,ParameterSetName="Silent",HelpMessage="Display no UI and no prompts")]
                
        [switch]$Silent,

        #  
        [Parameter(HelpMessage="Disables PlexPass(Beta) Updates")]
        
        [switch]$DisablePlexPass,

        #
        [Parameter(ValueFromPipelineByPropertyName=$true,
            HelpMessage="Specifiy Plex Media Server Hostname for Plex Web Checks. Bypasses detecting hostname using public IP reverse dns lookup.")]
        
        [String]$PlexServerHostName,

        #
        [Parameter(ValueFromPipelineByPropertyName=$true,
            HelpMessage="Enter non-standard Plex Media Server Port, default is 32400")]
        
        [int32]$PlexServerPort=32400,

        #
        [Parameter(ValueFromPipelineByPropertyName=$true,
            HelpMessage="Enable HTTPS for Plex Web Check")]
        
        [switch]$PlexServerSSL,

        # Logfile
        [Parameter(ValueFromPipelineByPropertyName=$true,
            HelpMessage="Enter Log File path, default is PSScriptRoot\Update-PlexMediaServer.log")]
        [ValidateNotNull()]

        [string]$LogFile="$PSScriptRoot\Update-PlexMediaServer.log",

        # Force update 
        [Parameter(HelpMessage="Forces Update installation regardless of installed version")]
        
        [switch]$Force,

        # Report update Only
        [Parameter(HelpMessage="Reports when update is required but does not downlaod and launch update")]
        
        [switch]$ReportOnly,

        # Notify Success
        [Parameter(HelpMessage="Exits with ExitCode '10' if update was insatalled successfully")]        
    
        [switch]$NotifySuccess,

        # Plex Server Build Build 
        [Parameter(HelpMessage="Forces Plex Media Server Build Architecture. If ommitted, Build Architecture is that of currently installed Plex Media Server Build.")]
        [ValidateSet('windows-x86','windows-x86_64')]
        
        [string]$Build,

        # Cleanup old updates 
        [Parameter(HelpMessage="Enables cleanup of old updates. Set number of Updates to keep in Updates folder.")]

        [int32]$UpdateCleanup,
        
        # For Email Notification configure all the below parameters in script or via command line 
        [Parameter(ParameterSetName="EmailNotify",
            Position=0,
            HelpMessage="Enables email notification")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        [Parameter(ParameterSetName="ServerAuth")]
        [Parameter(ParameterSetName="TokenAuth")]
        [Parameter(ParameterSetName="CredAuth")]
        [Parameter(ParameterSetName="TextAuth")]
        
        [switch]$EmailNotify,

        # Attach log file to notification if LogFile configured 
        [Parameter(ParameterSetName="EmailNotify",
            HelpMessage="Attach logfile with email notification")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        [Parameter(ParameterSetName="ServerAuth")]
        [Parameter(ParameterSetName="TokenAuth")]
        [Parameter(ParameterSetName="CredAuth")]
        [Parameter(ParameterSetName="TextAuth")]
        
        [switch]$AttachLog,
        
        # Include log file contents in notification if LogFile configured 
        [Parameter(ParameterSetName="EmailNotify",
            HelpMessage="Attach logfile with email notification")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        [Parameter(ParameterSetName="ServerAuth")]
        [Parameter(ParameterSetName="TokenAuth")]
        [Parameter(ParameterSetName="CredAuth")]
        [Parameter(ParameterSetName="TextAuth")]
        
        [switch]$IncludeLog,
        
        #
        [Parameter(Mandatory,
            ParameterSetName="EmailNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="Email notification recipient")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [string]$SmtpTo,
        
        #
        [Parameter(Mandatory,
            ParameterSetName="EmailNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="Email notification sender")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [string]$SmtpFrom,
        
        #
        [Parameter(Mandatory,
            ParameterSetName="EmailNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="SMTP Server Username")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [string]$SmtpUser,
        
        #
        [Parameter(Mandatory,
            ParameterSetName="EmailNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="SMTP Server Password")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [string]$SmtpPassword,
        
        #
        [Parameter(Mandatory,
            ParameterSetName="EmailNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="SMTP Server Name")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [string]$SmtpServer,
        
        #
        [Parameter(ParameterSetName="EmailNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="SMTP Server Port")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [int32]$SmtpPort,
        
        # Enable SSL for SMTP Authentication 
        [Parameter(ParameterSetName="EmailNotify",
            HelpMessage="Enables SSL for SMTP Authentication")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [switch]$EnableSSL,
        
        # Enable HTML Email Formating 
        [Parameter(ParameterSetName="EmailNotify",
            HelpMessage="Enables SSL for SMTP Authentication")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [switch]$EmailIsBodyHtml,
        
        # For Slack Notification configure all the below parameters in script or via command line 
        [Parameter(Mandatory,
            ParameterSetName="SlackNotify",
            Position=0,
            HelpMessage="Enables email notification")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [switch]$SlackNotify,
        
        #
        [Parameter(Mandatory,
            ParameterSetName="SlackNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="Slack Channel Name")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]
        
        [string]$SlackChannel,
        
        #
        [Parameter(Mandatory,
            ParameterSetName="SlackNotify",
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="Slack OAuth Token")]
        [Parameter(ParameterSetName="Passive")]
        [Parameter(ParameterSetName="Silent")]

        [string]$SlackToken
    )begin{
        Write-Debug ("ParameterSetName: {0}" -f $PSCmdlet.ParameterSetName)

        #validate Build variable
        if( -not [System.Environment]::Is64BitOperatingSystem -and $Build -eq 'windows-x86_64'){
            if($LogFile){Write-Log -Message "Exiting: Plex Media Server (x64) build is not supported on x86 Systems." -Path $LogFile -Level Info}
            if(-not $Silent){Write-Host "Exiting: Plex Media Server (x64) build is not supported on x86 Systems." -ForegroundColor Red}
            $Global:LASTEXITCODE=1
            break
        }
        # if([string]::IsNullOrEmpty($Build)){
        #     if([System.Environment]::Is64BitOperatingSystem){$Build='windows-x86_64'}else{$Build='windows-x86'}
        #     Write-Debug "Build: $Build"
        # }

        if($Logfile){if(Test-Path $LogFile){Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue | Out-Null}}
        if($LogFile){Write-Log -Message "Update-PlexMediaServer Starting" -Path $LogFile -Level Info}
        New-PSDrive HKCU -PSProvider Registry -Root Registry::HKEY_CURRENT_USER | Out-Null
        New-PSDrive HKLM -PSProvider Registry -Root Registry::HKEY_LOCAL_MACHINE | Out-Null
        New-PSDrive HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        # Current pages we need - Do not change unless Plex.tv changes again
        $UrlDownload='https://plex.tv/api/downloads/1.json?channel=plexpass'
        $UrlDownloadPublic='https://plex.tv/api/downloads/1.json'
    }process{
        Try{
            #Find Plex Media Server Installation
            if(-not $Silent){Write-Host "Validating Plex Media Server Installation" -ForegroundColor Cyan}
            if(Get-ItemProperty 'HKU:\*\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\WOW6432Node\Plex, Inc.\Plex Media Server' -OutVariable PlexMediaServerKeys -ErrorAction SilentlyContinue ){
                if($LogFile){Write-Log -Message "Plex Media Server Settings found in Registry [Count: $($PlexMediaServerKeys.Count)]" -Path $LogFile -Level Info}
                foreach($PlexMediaServerKey in $PlexMediaServerKeys){
                    if($LogFile){Write-Log -Message "Checking for Plex Server Settings in key $($PlexMediaServerKey.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))" -Path $LogFile -Level Info}
                    #Find Install Path
                    if(Get-ItemProperty "$($PlexMediaServerKey.InstallFolder)\Plex Media Server.exe" -OutVariable PlexMediaServerExe -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Plex Media Server Executable found in $($PlexMediaServerKey.InstallFolder)" -Path $LogFile -Level Info}
                        $InstallPath=(Split-Path -Path $PlexMediaServerExe)
                        if($LogFile){Write-Log -Message "InstallPath: $InstallPath" -Path $LogFile -Level Info}
                        $installedVersion,$installedBuild = $PlexMediaServerExe.VersionInfo.ProductVersion.Split('-')
                        if($LogFile){Write-Log -Message "Version: $installedVersion ($installedBuild)" -Path $LogFile -Level Info}
                        if((Get-FileBitness $PlexMediaServerExe.FullName) -eq 'I386'){
                            $CurrentBuild='windows-x86'
                        }else{
                            $CurrentBuild='windows-x86_64'
                        }
                        if($LogFile){Write-Log -Message "Build: $CurrentBuild" -Path $LogFile -Level Info}
                    }
                    #Find Server Token and maybe AppDataFolder if available
                    if($PlexMediaServerKey.PlexOnlineToken){
                        if((Get-RestMethod -Uri "https://plex.tv/api/v2/user?X-Plex-Token=$($PlexMediaServerKey.PlexOnlineToken)" -OutVariable PlexUser -PassThru -ErrorAction SilentlyContinue).exception){
                            if($PlexUser.exception.Response){
                                throw "Plex authentication token was not validated. Please verify or use Get-PlexToken to retrieve again. Server Response: $($PlexUser.Exception.message)"
                            }else{
                                throw "Unable to verify Plex authentication token. Unable to reach Plex.tv servers or they are unresponsive. Message: $($PlexUser.Exception.message)"
                            }
                        }else{
                            if($LogFile){Write-Log -Message "Plex Settings Key Found $($PlexMediaServerKey.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))" -Path $LogFile -Level Info}
                            $PlexMediaServerSettings=$PlexMediaServerKey
                            $PlexOnlineToken=$PlexMediaServerSettings.PlexOnlineToken
                            if($LogFile){Write-Log -Message "Plex Authentication Token $PlexOnlineToken Validated" -Path $LogFile -Level Info}
                            if($LogFile){Write-Log -Message "PlexOnlineToken: $PlexOnlineToken" -Path $LogFile -Level Info}
                            if($PlexMediaServerSettings.LocalAppDataPath){
                                $LocalAppDataPath=$PlexMediaServerSettings.LocalAppDataPath
                                if($LogFile){Write-Log -Message "LocalAppDataPath: $LocalAppDataPath" -Path $LogFile -Level Info}
                            }
                            switch($PlexMediaServerSettings.ButlerUpdateChannel){
                                ''{$ButlerUpdateChannel="Public"}
                                0{$ButlerUpdateChannel="Public"}
                                8{$ButlerUpdateChannel="Beta"}
                                default {if($LogFile){Write-Log -Message "Unknown Update Channel Value [$_]" -Path $LogFile -Level Info}}        
                            }
                            if($ButlerUpdateChannel){
                                if($LogFile){Write-Log -Message "ButlerUpdateChannel: $ButlerUpdateChannel" -Path $LogFile -Level Info}
                            }
                        }
                    }

                    #break from foreach if both found
                    if($InstallPath -and $PlexOnlineToken){Break}
                }
            }else{
                if($LogFile){Write-Log -Message "No Plex Plex Media Server Keys found in Registry" -Path $LogFile -Level Info}
            }

            #validate settings 
            if([string]::IsNullOrEmpty($PlexMediaServerSettings)){
                if($LogFile){Write-Log -Message "Plex Media Server installation not found in Registry" -Path $LogFile -Level Info}
                if($LogFile){Write-Log -Message "Plex Media Server may not be signed in and claimed. Please go to https://localhost:32400/web/index.html and complete initial setup." -Path $LogFile -Level Error}
                if(-not $Silent){Write-Host "...server may not be signed in and claimed. Please go to https://localhost:32400/web/index.html and complete initial setup." -NoNewline -ForegroundColor Red}
                throw "Plex Media Server may not be signed in and claimed. Please go to https://localhost:32400/web/index.html and complete initial setup."
            }

            #Locate Plex AppData Folder if not already found
            if([string]::IsNullOrEmpty($LocalAppDataPath)){
                if(Get-ItemProperty $env:SystemDrive'\Users\*\AppData\Local\Plex Media Server\.LocalAdminToken',$env:SystemRoot'\System32\config\systemprofile\AppData\Local\Plex Media Server\.LocalAdminToken' -OutVariable LocalAppDataPaths -ErrorAction SilentlyContinue ){
                    $LocalAppDataPath=($LocalAppDataPaths | Sort-Object -Property LastWriteTime | Select-Object -Last 1).FullName.Replace('\.LocalAdminToken','')
                    if($LogFile){Write-Log -Message "LocalAppDataPath: $LocalAppDataPath" -Path $LogFile -Level Info}
                }
            }

            #Locate PMS Executable if not already found
            if([string]::IsNullOrEmpty($InstallPath)){
                if(Get-ItemProperty $env:ProgramFiles'\Plex\Plex Media Server\Plex Media Server.exe',${env:ProgramFiles(x86)}'\Plex\Plex Media Server\Plex Media Server.exe' -OutVariable InstallPaths -ErrorAction SilentlyContinue ){
                    $InstallPath=($InstallPaths | Sort-Object -Property LastWriteTime | Select-Object -Last 1).FullName.Replace('\Plex Media Server.exe','')
                    if($LogFile){Write-Log -Message "Plex Media Server Executable found in $InstallPath" -Path $LogFile -Level Info}
                    if($LogFile){Write-Log -Message "InstallFolder: $InstallPath" -Path $LogFile -Level Info}
                }
            }
            
            #Locate Plex Media Server.exe Process and Get Current Version and determin username
            if(-not $Silent){Write-Host "...Server Status: " -NoNewline -ForegroundColor Cyan}
            if(Get-Process "Plex Media Server" -IncludeUserName -OutVariable PlexMediaServerProcess -ErrorAction SilentlyContinue){
                [bool]$PlexMediaServerRunning=$true
                if(-not $Silent){Write-Host "Running" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Plex Media Server process running $($PlexMediaServerProcess.Path) in user context $($PlexMediaServerProcess.UserName)" -Path $LogFile -Level Info}
                If (-not $UserName){$UserName=$PlexMediaServerProcess.UserName}
            }else{ # if process isn't running
            [bool]$PlexMediaServerRunning=$false
            if(-not $Silent){Write-Host "Not Running" -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Plex Media Server process not running" -Path $LogFile -Level Info}
                if(-not $UserName){$UserName=(New-Object System.Security.Principal.SecurityIdentifier($PlexMediaServerSettings.PSPath.Split('\')[2])).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]}
            }

            if(-not $Silent){Write-Host "...Installation Path: $InstallPath" -ForegroundColor Cyan}
            if(-not $Silent){Write-Host "...LocalAppData Path: $LocalAppDataPath" -ForegroundColor Cyan}
            if(-not $Silent){Write-Host "...User Context: $UserName" -ForegroundColor Cyan}
            if(-not $Silent){Write-Host "...Build: $CurrentBuild" -ForegroundColor Cyan}
            if(-not $Silent){Write-Host "...Update Channel: $ButlerUpdateChannel" -ForegroundColor Cyan}
            if(-not $Silent){Write-Host "...Authentication Token: Validated" -ForegroundColor Cyan}

            #Check Plex Media Server Service (PlexService)
            if(Get-ItemProperty $((Get-WmiObject win32_service -ErrorAction SilentlyContinue|?{$_.name -eq "PlexService"}).PathName).Replace("`"","") -OutVariable PlexServiceFile -ErrorAction SilentlyContinue){
                if(Get-Service PlexService -ErrorAction SilentlyContinue -OutVariable PlexService){
                    if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) installed (Version: $($PlexServiceFile.VersionInfo.FileVersion))." -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host "...PlexService: Installed" -ForegroundColor Cyan}
                    if(-not $Silent){Write-Host "...PlexService Status: $($PlexService.Status)" -ForegroundColor Cyan}
                    if(-not $Silent){Write-Host "...PlexServivce Version: $($PlexServiceFile.VersionInfo.FileVersion)" -ForegroundColor Cyan}
                }else{
                    if(-not $Silent){Write-Host "...PlexService: Not Installed" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Not Registered as a Service." -Path $LogFile -Level Info}
                }
            }Else{
                if(-not $Silent){Write-Host "...PlexService: Not Installed" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Not Installed." -Path $LogFile -Level Info}
            }

            #if build not set by parameter then set to currently installed build
            if([string]::IsNullOrEmpty($Build)){
                $Build=$CurrentBuild
                if($LogFile){Write-Log -Message "Plex Media Server Build $Build Detected" -Path $LogFile -Level Info}
            }else{
                if($LogFile){Write-Log -Message "Plex Media Server Build $Build Set by Parameter" -Path $LogFile -Level Info}
            }

            if($ButlerUpdateChannel -eq "Public" -or $PlexPassStatus -eq 'False'){$DisablePlexPass=$true}
            if($DisablePlexPass){$UrlDownload=$UrlDownloadPublic}

            #Get latest Plex Media Server release information from plex.tv
            if(-not $Silent){Write-Host "Checking for Plex Media Server Updates" -ForegroundColor Cyan}
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("X-Plex-Token", $PlexOnlineToken)
            if((Get-RestMethod -Uri $UrlDownload -Headers $headers -PassThru -OutVariable release).exception){
                throw "Unable to determin available version, version info missing in link. $($release.exception.message) Error: ($($release.exception.Response.StatusCode.value__))"
            }else{
                $releaseVersion,$releaseBuild = $release[0].computer.Windows.version.Split('-')
                $releaseUrl = ($release[0].computer.Windows.releases | Where-Object { $_.build -eq $Build }).url
                $releaseChecksum = ($release[0].computer.Windows.releases | Where-Object { $_.build -eq $Build }).checksum
                if($LogFile){Write-Log -Message "Update version $releaseVersion-$releaseBuild available for download." -Path $LogFile -Level Info}
            }

            #Determine if installed PMS version needs update
            $UpdateRequired=$false
            if([version]$releaseVersion -gt [version]$installedVersion){
                $UpdateRequired=$true
                if($LogFile){Write-Log -Message "New version available. Available Update version ($releaseVersion) greater than installed version ($installedVersion)." -Path $LogFile -Level Info}
                if(-not $Silent){Write-Host "...update available" -ForegroundColor Green}
                if($ReportOnly){
                    $Global:LASTEXITCODE=7
                    break
                }
                $ArgumentList = "/install" 
            }elseif([version]$releaseVersion -lt [version]$installedVersion){
                if($LogFile){Write-Log -Message "Available Update version ($releaseVersion) less than installed version ($installedVersion)." -Path $LogFile -Level Info}
                if($Force){
                    if(-not $Silent){Write-Host "Available Update version ($releaseVersion) less than installed version ($installedVersion)." -ForegroundColor Cyan}
                    $UpdateRequired=$true
                    $ArgumentList = "/install"
                    if($LogFile){Write-Log -Message "Proceeding with update. Force update enabled." -Path $LogFile -Level Info}
                }else{
                    if(-not $Silent){Write-Host "Available Update version ($releaseVersion) less than installed version ($installedVersion). Use -force to force installation." -ForegroundColor Cyan}
                    throw "Available Update version ($releaseVersion) less than installed version ($installedVersion)"
                }
            }else{
                if($LogFile){Write-Log -Message "Version up-to-date. Available Update version ($releaseVersion) equal to installed version ($installedVersion)." -Path $LogFile -Level Info}
                if($Force){
                    if(-not $Silent){Write-Host "...latest Version $installedVersion already installed. (-Force install enabled)" -ForegroundColor Cyan}
                    $UpdateRequired=$true
                    $ArgumentList = "/repair" 
                    if($LogFile){Write-Log -Message "Proceeding with update. Force update enabled." -Path $LogFile -Level Info}
                }else{
                    if(-not $Silent){Write-Host "...latest Version $installedVersion already installed. Use -Force to force installation." -ForegroundColor Cyan}
                    return $true
                }
            }

            if(-not $Silent){Write-Host "...Version: $releaseVersion ($releaseBuild)" -ForegroundColor Cyan}
            if(-not $Silent){Write-Host "...Build: $Build" -ForegroundColor Cyan}
            if($DisablePlexPass){
                if(-not $Silent){Write-Host "...Channel: Public" -ForegroundColor Cyan}
            }else{
                if(-not $Silent){Write-Host "...Channel: Beta" -ForegroundColor Cyan}
            }

            #Check if Update already downloaded and has valid checksum
            if($LogFile){Write-Log -Message "Checking default local application data path ($LocalAppDataPath) for Updates" -Path $LogFile -Level Info}                
            if((Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe") -and `
            ((Get-FileHash "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -Algorithm SHA1).Hash -ieq $releaseChecksum)){
                if($LogFile){Write-Log -Message "Latest update file found with matching checksum ($LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe)" -Path $LogFile -Level Info}
            }else{
                if(-not $Silent){Write-Host "Downloading Update" -ForegroundColor Cyan}
                #create destination directory if not present
                if(-Not (Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild")){New-Item "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild" -ItemType directory | Out-Null}
                if(Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe"){
                    if($LogFile){Write-Log -Message "Latest update file ($LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe) found but failed checksum. Re-downloading." -Path $LogFile -Level Info}
                }else{
                    if($LogFile){Write-Log -Message "Downloading Plex Media Server for Windows ($releaseVersion-$releaseBuild)" -Path $LogFile -Level Info}
                }
                if([int](Invoke-WebRequest -Headers $headers -Uri $releaseUrl -UseBasicParsing -OutFile "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -PassThru -OutVariable response).StatusCode -eq 200){
                    if($LogFile){Write-Log -Message "Download of $LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe completed. StatusCode: $([int]$response.StatusCode)" -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host "...completed" -ForegroundColor Cyan}
                    Write-Verbose "WebRequest result $([int]$response.StatusCode)"
                }else{
                    if($LogFile){Write-Log -Message "Exiting: Error downloading $releaseUrl. StatusDescription: $($response.StatusDescription) StatusCode: $($response.StatusCode)" -Path $LogFile -Level Info}
                    throw "Exiting: Error downloading $releaseUrl. StatusDescription: $($response.StatusDescription) StatusCode: $($response.StatusCode)"
                    $Global:LASTEXITCODE=4
                    break
                }
                if((Get-FileHash "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -Algorithm SHA1).Hash -ieq $releaseChecksum){
                    if(-not $Silent){Write-Host "...checksum validated" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Validated checksum ($LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe)" -Path $LogFile -Level Info}
                }else{
                    if($LogFile){Write-Log -Message "Exiting: Error downloading $releaseUrl. Checksum invalid." -Path $LogFile -Level Error}
                    throw "Exiting: Error downloading $releaseUrl. Checksum invalid."
                    $Global:LASTEXITCODE=4
                    break
                }
            }

            #Check if Server in use
            if(-not $Silent){Write-Host "Checking Active Sessions" -ForegroundColor Cyan}
            if(-not $PSBoundParameters.ContainsKey('PlexServerHostName')){
                if($LogFile){Write-Log -Message "Performaing Hostname reverse lookup" -Path $LogFile -Level Info}
                while($null -eq (Get-RestMethod -Uri http://ipinfo.io/json -ErrorAction SilentlyContinue -PassThru -OutVariable HostNameResponse | Select-Object -ExpandProperty hostname -ErrorAction SilentlyContinue -OutVariable hostname)){
                    if($LogFile){Write-Log -Message "Unable to determin Hostname, retrying. $($HostNameResponse.exception.message) Error: ($($HostNameResponse.exception.HResult))" -Path $LogFile -Level Info}
                    Start-Sleep -Milliseconds 5
                }
                $PlexServerHostName=$hostname
            }
            if($LogFile){Write-Log -Message "HostName is $PlexServerHostName" -Path $LogFile -Level Info}

            if($PlexServerSSL){$PlexServerScheme='https'}else{$PlexServerScheme='http'}
            $PlexServerUri="$($PlexServerScheme)://$($PlexServerHostName):$PlexServerPort/"
            $PlexServerPrefsUri="$($PlexServerScheme)://$($PlexServerHostName):$PlexServerPort/:/prefs/"
            $PlexServerLocationUri="$($PlexServerScheme)://$($PlexServerHostName):$PlexServerPort/servers/"
            $PlexServerSessionUri="$($PlexServerScheme)://$($PlexServerHostName):$PlexServerPort/status/sessions/"
            $PlexServerLiveTvSessionUri="$($PlexServerScheme)://$($PlexServerHostName):$PlexServerPort/livetv/sessions/"
            if($PlexOnlineToken){
                $PlexServerUri=$PlexServerUri + "?X-Plex-Token=$($PlexOnlineToken)"
                $PlexServerPrefsUri=$PlexServerPrefsUri + "?X-Plex-Token=$($PlexOnlineToken)"
                $PlexServerLocationUri=$PlexServerLocationUri + "?X-Plex-Token=$($PlexOnlineToken)"
                $PlexServerSessionUri=$PlexServerSessionUri + "?X-Plex-Token=$($PlexOnlineToken)"
                $PlexServerLiveTvSessionUri=$PlexServerLiveTvSessionUri + "?X-Plex-Token=$($PlexOnlineToken)"
            }

            if((Get-RestMethod -Uri $PlexServerSessionUri -ErrorAction SilentlyContinue -PassThru -OutVariable PlexWebSessions).Exception){
                if($PlexWebSessions.Exception.Response){
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerSessionUri. Message: $($PlexWebSessions.Exception.Message) (Error: $($PlexWebSessions.Exception.HResult)) StatusDescription: $($PlexWebSessions.Exception.Response.StatusDescription) (StatusCode: $($PlexWebSessions.Exception.Response.StatusCode.value__))" -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host $PlexWebSessions.Exception.message -ForegroundColor Red}
                    switch($PlexWebSessions.Exception.Response.StatusCode.value__){
                        401{
                            if(-not $Silent){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($PlexWebSessions.Exception.Response.StatusDescription) (StatusCode: $($PlexWebSessions.Exception.Response.StatusCode.value__))"}
                        }
                        201{
                            if(-not $Silent){Write-Host "Failed to log in. StatusDescription: $($PlexWebSessions.Exception.Response.StatusDescription) (StatusCode: $($PlexWebSessions.Exception.Response.StatusCode.value__))"}
                        }
                        else{
                            if(-not $Silent){Write-Host "Unknown Response. Message: $($PlexWebSessions.Exception.Response.StatusDescription) (Error: $($PlexWebSessions.Exception.Response.StatusCode.value__)" -ForegroundColor Red}
                        }
                    }
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerSessionUri" -Path $LogFile -Level Info}
                }
            }else{
                if([int]$PlexWebSessions[0].MediaContainer.size -eq 0){
                    if($LogFile){Write-Log -Message "No active sessions found." -Path $LogFile -Level Info}
                }else{
                    if($LogFile){Write-Log -Message "Active Sessions found: $([int]$PlexWebSessions[0].MediaContainer.size)" -Path $LogFile -Level Info}
                }
            }
            if((Get-RestMethod -Uri $PlexServerLiveTvSessionUri -ErrorAction SilentlyContinue -PassThru -OutVariable LiveTvSessions).Exception){
                if($LiveTvSessions.Exception.Response){
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerLiveTvSessionUri. Message: $($LiveTvSessions.Exception.Message) (Error: $($LiveTvSessions.Exception.HResult)) StatusDescription: $($LiveTvSessions.Exception.Response.StatusDescription) (StatusCode: $($LiveTvSessions.Exception.Response.StatusCode.value__))" -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host $LiveTvSessions.Exception.message -ForegroundColor Red}
                    switch($LiveTvSessions.Exception.Response.StatusCode.value__){
                        401{
                            if(-not $Silent){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($LiveTvSessions.Exception.Response.StatusDescription) (StatusCode: $($LiveTvSessions.Exception.Response.StatusCode.value__))"}
                        }
                        201{
                            if(-not $Silent){Write-Host "Failed to log in. StatusDescription: $($LiveTvSessions.Exception.Response.StatusDescription) (StatusCode: $($LiveTvSessions.Exception.Response.StatusCode.value__))"}
                        }
                        else{
                            if(-not $Silent){Write-Host "Unknown Response. Message: $($LiveTvSessions.Exception.Response.StatusDescription) (Error: $($LiveTvSessions.Exception.Response.StatusCode.value__)" -ForegroundColor Red}
                        }
                    }
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerLiveTvSessionUri" -Path $LogFile -Level Info}
                }
            }else{
                if([int]$LiveTvSessions[0].MediaContainer.Video.index -eq 0){
                    if($LogFile){Write-Log -Message "No active Live TV/DVR Sessions found" -Path $LogFile -Level Info}
                }else{
                    if($LogFile){Write-Log -Message "Active Live TV/DVR Sessions found: $([int]$LiveTvSessions[0].MediaContainer.Video.index)" -Path $LogFile -Level Info}
                }
            }
            if($PlexWebSessions[0].MediaContainer -or $LiveTvSessions[0].MediaContainer){
                if(-not $Silent){Write-Host "...Session(s): $([int]$PlexWebSessions[0].MediaContainer.size+[int]$LiveTvSessions[0].MediaContainer.Video.index)" -ForegroundColor Cyan}

                if(([int]$PlexWebSessions[0].MediaContainer.size -ne 0) -or ([int]$LiveTvSessions[0].MediaContainer.Video.index -ne 0)){
                    if(-not $Silent){Write-Host "...Streaming: $([int]$PlexWebSessions[0].MediaContainer.size)" -ForegroundColor Cyan}
                    if(-not $Silent){Write-Host "...Live TV/DVR: $([int]$LiveTvSessions[0].MediaContainer.Video.index)" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Server $($PlexWeb[0].MediaContainer.friendlyName) is currently being used by one or more users, skipping installation. Please run again later" -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host "Server $($PlexWeb[0].MediaContainer.friendlyName) is currently being used by one or more users, skipping installation. Please run again later" -ForegroundColor Cyan}
                    $Global:LASTEXITCODE=6
                    break
                }
            }else{
                if(-not $Silent){Write-Host "...unable to determine active Session(s), plex web unavailable or unreachable" -ForegroundColor Cyan}
            }

            if($Force){
                if(-not $Silent){Write-Host "Starting Update Process (Forced)" -ForegroundColor Cyan}
            }else{
                if(-not $Silent){Write-Host "Starting Update Process" -ForegroundColor Cyan}
            }

            #Stop Plex Media Server Service Wrapper (PlexService)
            if($PlexService -and $PlexMediaServerRunning){
                if($PlexService.status -ne 'Stopped'){
                    if($LogFile){Write-Log -Message "Found Plex Media Server Service Wrapper (PlexService) Running." -Path $LogFile -Level Info}
                    if($PlexService | Stop-Service -ErrorAction SilentlyContinue -PassThru){
                        if($LogFile){Write-Log -Message "Sent Plex Media Server Service Wrapper (PlexService) Stop-Service." -Path $LogFile -Level Info}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Plex Media Server Service Wrapper (PlexService) Stop-Process." -Path $LogFile -Level Info}
                    }
                    Start-Sleep -Seconds 1
                    While ($PlexService.Status -eq "Running"){
                        if($LogFile){Write-Log -Message "Service not responding to Stop-Service, Sending Plex Media Server Service Wrapper (PlexService) Stop-Process -Force." -Path $LogFile -Level Info}
                        if(Stop-Process -Name PlexService -ErrorAction SilentlyContinue -Force -PassThru){
                            if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Stop-Process -Force Successful." -Path $LogFile -Level Info}
                        }else{
                            if($LogFile){Write-Log -Message "Service hung. Retrying Plex Media Server Service Wrapper (PlexService) Stop-Process -Force." -Path $LogFile -Level Info}
                        }
                        Start-Sleep -Seconds 1
                    }
                    if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Stopped." -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host "...PlexService: Stopped" -ForegroundColor Cyan}
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server Service (PlexService) is Stopped." -Path $LogFile -Level Info}
                }
            }

            #Stop all Plex Media Server related processes
            if(Get-Process -Name 'Plex Media Server','Plex Media Scanner','Plex Tuner Service','Plex Relay','Plex Update Service','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue){
                if($LogFile){Write-Log -Message "Plex Media Server processes found running." -Path $LogFile -Level Info}
                while(Get-Process -Name 'Plex Media Server','Plex Media Scanner','Plex Relay','Plex Update Service','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue -OutVariable PMSProcesses){
                    if($LogFile){Write-Log -Message "Sent Plex Media Server processes Stop-Process. ($($PmsProcesses.ProcessName))" -Path $LogFile -Level Info}
                    $PMSProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                    if(-not $Silent){Write-Host "." -ForegroundColor Cyan -NoNewline}
                }
                if($LogFile){Write-Log -Message "Plex Media Server processes stopped." -Path $LogFile -Level Info}
                if(-not $Silent){Write-Host "Plex Media Server Processes: Stopped" -ForegroundColor Cyan}
            }else{
                if($LogFile){Write-Log -Message "No Plex Media Server processes currently running." -Path $LogFile -Level Info}
            }

            #Start install of PMS

            # x64 installer
            # /SILENT, /VERYSILENT - Instructs Setup to be silent or very silent.
            # /RESTARTEXITCODE=exit code Specifies a custom exit code that Setup is to return when the system needs to be restarted.
            # /SUPPRESSMSGBOXES - Instructs Setup to suppress message boxes.
            # /NOCANCEL - Prevents the user from cancelling during the installation process.
            # /NORESTART - Prevents Setup from restarting the system following a successful installation, or after a Preparing to Install failure that requests a restart.

            # x86 installer
            # /install | /repair | /uninstall | /layout - installs, repairs, uninstalls or creates a compelte local copy of bundle in directory. Install is the default
            # /passive | /quiet - displays minimal UI with no prompts or display no UI and no prompts. By default UI and all prompts are displayed.

            #Build ArgumentList
            switch ($Build) {
                windows-x86 {
                    if($Passive){
                        $ArgumentList = $ArgumentList + " /passive /norestart" 
                    }elseif($Silent){
                        $ArgumentList = $ArgumentList + " /quite /norestart"
                    }else{
                        $ArgumentList = $ArgumentList + " /norestart"
                    }
                }
                windows-x86_64 {
                    if($passive){
                        $ArgumentList = "/NORESTART /RESTARTEXITCODE=3010 /SILENT /SUPPRESSMSGBOXES"
                    }elseif($Silent){
                        $ArgumentList = "/NORESTART /RESTARTEXITCODE=3010 /SUPPRESSMSGBOXES /VERYSILENT "
                    }else{
                        $ArgumentList = "/NORESTART /RESTARTEXITCODE=3010"
                    }
                }
            }

            if($CurrentBuild -eq 'windows-x86_64' -and $build -eq 'windows-x86'){
                if($LogFile){Write-Log -Message "Uninstalling Plex Media Server (x64) before installing 'windows-x86' build" -Path $LogFile -Level Info}

                foreach($UninstallString in $(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName -like 'Plex Media Server*'}).UninstallString){
                    if($LogFile){Write-Log -Message "Uninstalling Plex Media Server (x64) update Process: $UninstallString $ArgumentList" -Path $LogFile -Level Info}
                    $Process = Start-Process -FilePath $UninstallString -ArgumentList $ArgumentList -PassThru
                    While(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
                        Start-Sleep -Seconds 4
                        if(-not $Silent){Write-Host "." -ForegroundColor Cyan -NoNewline}
                    }    
                }

                switch ($Process.ExitCode) {
                    0 {
                        if(-not $Silent){Write-Host "Uninstalling Plex Media Server (x64): Success" -ForegroundColor Cyan}
                        if($LogFile){Write-Log -Message "Successfully uninstalled with ExitCode $($Process.ExitCode)." -Path $LogFile -Level Info}    
                    }
                    2 {
                        if(-not $Silent){Write-Host "Uninstalling Plex Media Server (x64): Cancelled" -ForegroundColor Red}
                        if($LogFile){Write-Log -Message "Plex Media Server uninstall was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Info}    
                    }
                    1602 {
                        if(-not $Silent){Write-Host "Uninstalling Plex Media Server (x64): Cancelled" -ForegroundColor Red}
                        if($LogFile){Write-Log -Message "Plex Media Server uninstall was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Info}    
                    }
                    3010 {
                        if(-not $Silent){Write-Host "Uninstalling Plex Media Server (x64): Success (Restart Required)" -ForegroundColor Cyan}
                        if($LogFile){Write-Log -Message "Successfully uninstalled with ExitCode $($Process.ExitCode). Restart Required." -Path $LogFile -Level Info}    
                    }
                    Default {
                        if(-not $Silent){Write-Host "Uninstalling Plex Media Server (x64): Error" -ForegroundColor Red}
                        if($LogFile){Write-Log -Message "Plex Media Server failed to uninstall. Command '$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList' returned error code $($Process.ExitCode))." -Path $LogFile -Level Info}    
                    }
                }
            }

            if($LogFile){Write-Log -Message "Starting Plex Media Server update Process: $LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList" -Path $LogFile -Level Info}
            $Process = Start-Process -FilePath "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -ArgumentList $ArgumentList -PassThru
            While(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
                if(-not $Silent){Write-Host "." -ForegroundColor Cyan -NoNewline}
                Start-Sleep -Seconds 4
            }

            if(Get-ItemProperty 'HKU:\*\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\WOW6432Node\Plex, Inc.\Plex Media Server' -OutVariable PlexMediaServerKeys -ErrorAction SilentlyContinue ){
                if($LogFile){Write-Log -Message "Plex Media Server Settings found in Registry [Count: $($PlexMediaServerKeys.Count)]" -Path $LogFile -Level Info}
                $InstallPath=$null
                $PlexOnlineToken=$null
                foreach($PlexMediaServerKey in $PlexMediaServerKeys){
                    if($LogFile){Write-Log -Message "Checking for Plex Server Settings in key $($PlexMediaServerKey.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))" -Path $LogFile -Level Info}
                    #Find Install Path
                    if(Get-ItemProperty "$($PlexMediaServerKey.InstallFolder)\Plex Media Server.exe" -OutVariable PlexMediaServerExe -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Plex Media Server Executable found in $($PlexMediaServerKey.InstallFolder)" -Path $LogFile -Level Info}
                        $InstallPath=($PlexMediaServerKey.InstallFolder).Substring(0,($PlexMediaServerKey.InstallFolder).Length-1)
                        if($LogFile){Write-Log -Message "InstallPath: $InstallPath" -Path $LogFile -Level Info}
                        $installedVersion,$installedBuild = $PlexMediaServerExe.VersionInfo.ProductVersion.Split('-')
                        if($LogFile){Write-Log -Message "Version: $installedVersion ($installedBuild)" -Path $LogFile -Level Info}
                        if((Get-FileBitness $PlexMediaServerExe.FullName) -eq 'I386'){
                            $CurrentBuild='windows-x86'
                        }else{
                            $CurrentBuild='windows-x86_64'
                        }
                        if($LogFile){Write-Log -Message "Build: $CurrentBuild" -Path $LogFile -Level Info}
                    }
                    #Find Server Token and maybe AppDataFolder if available
                    if($PlexMediaServerKey.PlexOnlineToken){
                        if((Get-RestMethod -Uri "https://plex.tv/api/v2/user?X-Plex-Token=$($PlexMediaServerKey.PlexOnlineToken)" -OutVariable PlexUser -PassThru -ErrorAction SilentlyContinue).exception){
                            if($PlexUser.exception.Response){
                                throw "Plex authentication token was not validated. Please verify or use Get-PlexToken to retrieve again. Server Response: $($PlexUser.Exception.message)"
                            }else{
                                throw "Unable to verify Plex authentication token. Unable to reach Plex.tv servers or they are unresponsive. Message: $($PlexUser.Exception.message)"
                            }
                        }else{
                            if($LogFile){Write-Log -Message "Plex Settings Key Found $($PlexMediaServerKey.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))" -Path $LogFile -Level Info}
                            $PlexMediaServerSettings=$PlexMediaServerKey
                            $PlexOnlineToken=$PlexMediaServerSettings.PlexOnlineToken
                            if($LogFile){Write-Log -Message "Plex Authentication Token $PlexOnlineToken Validated" -Path $LogFile -Level Info}
                            if($LogFile){Write-Log -Message "PlexOnlineToken: $PlexOnlineToken" -Path $LogFile -Level Info}
                            if($PlexMediaServerSettings.LocalAppDataPath){
                                $LocalAppDataPath=$PlexMediaServerSettings.LocalAppDataPath
                                if($LogFile){Write-Log -Message "LocalAppDataPath: $LocalAppDataPath" -Path $LogFile -Level Info}
                            }
                            switch($PlexMediaServerSettings.ButlerUpdateChannel){
                                ''{$ButlerUpdateChannel="Public"}
                                0{$ButlerUpdateChannel="Public"}
                                8{$ButlerUpdateChannel="Beta"}
                                default {if($LogFile){Write-Log -Message "Unknown Update Channel Value [$_]" -Path $LogFile -Level Info}}        
                            }
                            if($ButlerUpdateChannel){
                                if($LogFile){Write-Log -Message "ButlerUpdateChannel: $ButlerUpdateChannel" -Path $LogFile -Level Info}
                            }
                        }
                    }

                    #break from foreach if both found
                    if($InstallPath -and $PlexOnlineToken){Break}
                }
            }else{
                if($LogFile){Write-Log -Message "No Plex Plex Media Server Keys found in Registry" -Path $LogFile -Level Info}
            }

            #validate settings 
            if([string]::IsNullOrEmpty($PlexMediaServerSettings)){
                if($LogFile){Write-Log -Message "Plex Media Server installation not found in Registry" -Path $LogFile -Level Info}
                if($LogFile){Write-Log -Message "Plex Media Server may not be signed in and claimed. Please go to https://localhost:32400/web/index.html and complete initial setup." -Path $LogFile -Level Error}
                if(-not $Silent){Write-Host "...server may not be signed in and claimed. Please go to https://localhost:32400/web/index.html and complete initial setup." -NoNewline -ForegroundColor Red}
                throw "Plex Media Server may not be signed in and claimed. Please go to https://localhost:32400/web/index.html and complete initial setup."
            }

            #Locate Plex AppData Folder if not already found
            if([string]::IsNullOrEmpty($LocalAppDataPath)){
                if(Get-ItemProperty $env:SystemDrive'\Users\*\AppData\Local\Plex Media Server\.LocalAdminToken',$env:SystemRoot'\System32\config\systemprofile\AppData\Local\Plex Media Server\.LocalAdminToken' -OutVariable LocalAppDataPaths -ErrorAction SilentlyContinue ){
                    $LocalAppDataPath=($LocalAppDataPaths | Sort-Object -Property LastWriteTime | Select-Object -Last 1).FullName.Replace('\.LocalAdminToken','')
                    if($LogFile){Write-Log -Message "LocalAppDataPath: $LocalAppDataPath" -Path $LogFile -Level Info}
                }
            }
            
            #Locate PMS Executable if not already found
            if([string]::IsNullOrEmpty($InstallPath)){
                if(Get-ItemProperty $env:ProgramFiles'\Plex\Plex Media Server\Plex Media Server.exe',${env:ProgramFiles(x86)}'\Plex\Plex Media Server\Plex Media Server.exe' -OutVariable InstallPaths -ErrorAction SilentlyContinue ){
                    $InstallPath=($InstallPaths | Sort-Object -Property LastWriteTime | Select-Object -Last 1).FullName.Replace('\Plex Media Server.exe','')
                    if($LogFile){Write-Log -Message "Plex Media Server Executable found in $InstallPath" -Path $LogFile -Level Info}
                    if($LogFile){Write-Log -Message "InstallFolder: $InstallPath" -Path $LogFile -Level Info}
                }
            }

            switch ($Process.ExitCode) {
                0 {
                    [bool]$UpdateSuccess=$true
                    if(-not $Silent){Write-Host "Installation: Success" -ForegroundColor Cyan}
                    if(-not $Silent){Write-Host "...Version Installed: $($(Get-ItemProperty -Path $PlexMediaServerExe).VersionInfo.FileVersion)" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Update successfully installed with ExitCode $($Process.ExitCode)." -Path $LogFile -Level Info}
                }
                2 {
                    [bool]$UpdateSuccess=$false
                    if(-not $Silent){Write-Host "Installation: Cancelled" -ForegroundColor Red}
                    if($LogFile){Write-Log -Message "Update was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Info}
                }
                1602 {
                    [bool]$UpdateSuccess=$false
                    if(-not $Silent){Write-Host "Installation: Cancelled" -ForegroundColor Red}
                    if($LogFile){Write-Log -Message "Update was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Info}
                }
                3010 {
                    [bool]$UpdateSuccess=$true
                    if(-not $Silent){Write-Host "Installation: Success (Restart Required)" -ForegroundColor Cyan}
                    if(-not $Silent){Write-Host "Version Installed: $($(Get-ItemProperty -Path $PlexMediaServerExe).VersionInfo.FileVersion)" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Update successfully installed with ExitCode $($Process.ExitCode). Restart Required." -Path $LogFile -Level Info}
                    [bool]$RestartRequired=$true
                }
                Default {
                    [bool]$UpdateSuccess=$false
                    if(-not $Silent){Write-Host "Installation: ERROR" -ForegroundColor Red}
                    if($LogFile){Write-Log -Message "Update failed to install. Command '$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList' returned error code $($Process.ExitCode))." -Path $LogFile -Level Info}
                }
            }

            #cleanup Run keys after install
            if($UpdateSuccess -and $PlexService){
                if(Get-ItemProperty 'HKU:\*\Software\Microsoft\Windows\CurrentVersion\Run' -Name "Plex Media Server" -OutVariable PlexMediaServerRunKeys -ErrorAction SilentlyContinue){
                    foreach ($PlexMediaServerRunKey in $PlexMediaServerRunKeys){
                        if($LogFile){Write-Log -Message "Removing $(($PlexMediaServerRunKey.PSPath.Replace('Microsoft.PowerShell.Core\Registry::HKEY_USERS','HKU:')))\Plex Media Server value." -Path $LogFile -Level Info}
                        Remove-ItemProperty ($PlexMediaServerRunKey.PSPath.Replace('Microsoft.PowerShell.Core\Registry::HKEY_USERS','HKU:')) -Name "Plex Media Server" -Force
                        if(-not $Silent){Write-Host "...Startup/Run Key: Removed" -ForegroundColor Cyan}
                    }
                }
            }

            # Update Cleanup
            if($UpdateCleanup){
                if(Get-ChildItem "$LocalAppDataPath\Plex Media Server\Updates" -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending -OutVariable PmsUpdates){
                    if($LogFile){Write-Log -Message "Checking Updates folder for Cleanup." -Path $LogFile -Level Info}
                    if($PmsUpdates.Count -gt $UpdateCleanup){
                        if($LogFile){Write-Log -Message "Cleanup threshold reached, executing cleanup of $($PmsUpdates.Count-$UpdateCleanup) update/s." -Path $LogFile -Level Info}
                        foreach($PmsUpdate in $PmsUpdates){
                            if($PmsUpdates.IndexOf($PmsUpdate) -lt $UpdateCleanup){continue}
                            try{
                                Remove-Item ("$LocalAppDataPath\Plex Media Server\Updates\" + ($PmsUpdate.FullName).Replace("$LocalAppDataPath\Plex Media Server\Updates\",'').split("\")[0]) -Recurse -Force -ErrorAction SilentlyContinue
                            }catch{
                                Write-Verbose "Error removing folder $("$LocalAppDataPath\Plex Media Server\Updates\" + ($PmsUpdate.FullName).Replace("$LocalAppDataPath\Plex Media Server\Updates\",'').split("\")[0]) Error: $($_.exception.GetType().Name)"
                                $return=$_.Exception
                            }
                            if($return){
                                if($LogFile){Write-Log -Message "Error removing folder $("$LocalAppDataPath\Plex Media Server\Updates\" + ($PmsUpdate.FullName).Replace("$LocalAppDataPath\Plex Media Server\Updates\",'').split("\")[0]) Error: $($return.GetType().Name)" -Path $LogFile -Level Info}
                                $return=$null
                            }else{
                                if($LogFile){Write-Log -Message "Removed folder $("$LocalAppDataPath\Plex Media Server\Updates\" + ($PmsUpdate.FullName).Replace("$LocalAppDataPath\Plex Media Server\Updates\",'').split("\")[0])" -Path $LogFile -Level Info}
                            }
                        }
                        Write-Host "...Updates Removed: $($PmsUpdates.Count-$UpdateCleanup)" -ForegroundColor Cyan
                    }else{
                        if($LogFile){Write-Log -Message "Update Count does not meet Cleanup threshold ($UpdateCleanup)" -Path $LogFile -Level Info}
                    }
                }else{
                    Write-Warning "Unable to determine Updates Count for cleanup"
                }
            }

            if($PlexMediaServerRunning){
                #Start Plex Media Server Service (PlexService)
                if($PlexService){
                    if($PlexService.status -eq 'Stopped'){
                        While ($PlexService.Status -eq "Stopped"){
                            $PlexService | Start-Service -WarningAction SilentlyContinue
                            if($LogFile){Write-Log -Message "Sent Plex Media Server Service Wrapper (PlexService) Start-Service." -Path $LogFile -Level Info}
                            Start-Sleep -Seconds 1
                        }
                        if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Started." -Path $LogFile -Level Info}
                        if(-not $Silent){Write-Host "...PlexService: Started" -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Plex Media Server Service (PlexService) already Started." -Path $LogFile -Level Info}
                    }
                }else{
                    if($UserName -eq $env:USERDOMAIN+'+\'+$env:USERNAME){
                        if(Start-Process -FilePath "$InstallPath\Plex Media Server.exe" -OutVariable PlexMediaServerProcess -PassThru){
                            if($LogFile){Write-Log -Message "Plex Media Server started (PID $($PlexMediaServerProcess.ID))" -Path $LogFile -Level Info}
                            if(-not $Silent){Write-Host "...Plex Media Server: Started" -ForegroundColor Cyan}
                        }
                    }else{
                        if($LogFile){Write-Log -Message "Plex Media Server: Not Started (Manual Launch Required). Unable to launch process as $UserName" -Path $LogFile -Level Info}
                        if(-not $Silent){Write-Host "...Plex Media Server: Not Started (Manual Launch Required)" -ForegroundColor Cyan}
                    }
                }
            }


            #Locate Plex Media Server.exe Process and Get Current Version and determin username
            if(-not $Silent){Write-Host "...Server Status: " -NoNewline -ForegroundColor Cyan}
            if(Get-Process "Plex Media Server" -IncludeUserName -OutVariable PlexMediaServerProcess -ErrorAction SilentlyContinue){
                [bool]$PlexMediaServerRunning=$true
                if(-not $Silent){Write-Host "Running" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Plex Media Server process running $($PlexMediaServerProcess.Path) in user context $($PlexMediaServerProcess.UserName)" -Path $LogFile -Level Info}
                If (-not $UserName){$UserName=$PlexMediaServerProcess.UserName}
            }else{ # if process isn't running
            [bool]$PlexMediaServerRunning=$false
            if(-not $Silent){Write-Host "Not Running" -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Plex Media Server process not running" -Path $LogFile -Level Info}
                if(-not $UserName){$UserName=(New-Object System.Security.Principal.SecurityIdentifier($PlexMediaServerSettings.PSPath.Split('\')[2])).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]}
            }

            #Verify Plex Web available
            [int]$loopcount=0
            do{
                if($loopcount -gt 0){Start-Sleep -s 3}
                if(-not $Silent){Write-Host "." -ForegroundColor Cyan -NoNewline}
                $loopcount++
            }until((Get-RestMethod -Uri $PlexServerUri -PassThru -OutVariable PlexWeb -ErrorAction SilentlyContinue).MediaContainer -or $loopcount -gt 10)
            if($PlexWeb[0].MediaContainer){
                if(-not $Silent){Write-Host "Plex Web: Available" -ForegroundColor Cyan}
                if($PlexWeb[0].MediaContainer){
                    if($LogFile){Write-Log -Message "Version: $($PlexWeb[0].MediaContainer.version.Split('-')[0]) ($($PlexWeb[0].MediaContainer.version.Split('-')[1]))" -Path $LogFile -Level Info}
                    if($LogFile){Write-Log -Message "Friendly Name: $($PlexWeb[0].MediaContainer.friendlyName)" -Path $LogFile -Level Info}
                    if($LogFile){Write-Log -Message "PlexUsername: $($PlexWeb[0].MediaContainer.myPlexUserName)" -Path $LogFile -Level Info}
                    if($LogFile){Write-Log -Message "Signin State: $($PlexWeb[0].MediaContainer.myPlexSigninState)" -Path $LogFile -Level Info}
                    if($LogFile){Write-Log -Message "Platform: $($PlexWeb[0].MediaContainer.platform)" -Path $LogFile -Level Info}
                    if($LogFile){Write-Log -Message "Platform Version: $($PlexWeb[0].MediaContainer.platformVersion)" -Path $LogFile -Level Info}
                    if($PlexWeb[0].MediaContainer.myPlexSubscription -eq 1){
                        if($LogFile){Write-Log -Message "PlexPass: True" -Path $LogFile -Level Info}
                        $PlexPassStatus="True"
                    }elseif($PlexWeb[0].MediaContainer.myPlexSubscription -eq 0){
                        if($LogFile){Write-Log -Message "PlexPass: False" -Path $LogFile -Level Info}
                        $PlexPassStatus="False"
                    }else{
                        if($LogFile){Write-Log -Message "PlexPass: Unknown" -Path $LogFile -Level Info}
                    }
                }else{
                    if($LogFile){Write-Log -Message "Data missing from server response $PlexServer" -Path $LogFile -Level Info}
                }
            }else{
                if(-not $Silent){Write-Host "Plex Web: Unavailable" -ForegroundColor Red}
                if($PlexWeb.Exception.Response){
                    if($LogFile){Write-Log -Message "Plex Web unavailable at $PlexServerUri. Message: $($PlexWeb.Exception.Message) (Error: $($PlexWeb.Exception.HResult)) StatusDescription: $($PlexWeb.exception.Response.StatusDescription) (StatusCode: $($PlexWeb.Exception.Response.StatusCode.value__))" -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host $PlexWeb.exception.message -ForegroundColor Red}
                    switch($PlexWeb.Exception.Response.StatusCode.value__){
                        401{
                            if(-not $Silent){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($PlexWeb.Exception.Response.StatusDescription) (StatusCode: $($PlexWeb.Exception.Response.StatusCode.value__))"}
                        }
                        201{
                            if(-not $Silent){Write-Host "Failed to log in. StatusDescription: $($PlexWeb.Exception.Response.StatusDescription) (StatusCode: $($PlexWeb.Exception.Response.StatusCode.value__))"}
                        }
                        else{
                            if(-not $Silent){Write-Host "Unknown Response. Message: $($PlexWeb.Exception.Response.StatusDescription) (Error: $($PlexWeb.Exception.Response.StatusCode.value__)" -ForegroundColor Red}
                        }
                    }
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerUri" -Path $LogFile -Level Info}
                }
            }

            if($SlackNotify){
                if(Post-ToSlack -Channel $SlackChannel -token $SlackToken -BotName "Update-PlexMediaServer Module" -Message "Plex Media Server $($PlexWeb[0].MediaContainer.friendlyName) was updated on computer $env:COMPUTERNAME.`r`n`r`nNew Version: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.ProductVersion)`r`nOld Version: $installedVersion-$installedBuild" -ErrorAction SilentlyContinue -OutVariable slackResponse){
                    if($LogFile){Write-Log -Message "Slack Notification sent successsfully." -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host "Slacck Notifcation: Sent" -ForegroundColor Cyan}
                }else{
                    if($LogFile){Write-Log -Message "Error sending Slack Notification. Error $($slackResponse.error)" -Path $LogFile -Level Info}
                    if(-not $Silent){Write-Host "Slack Notifcation: Error" -ForegroundColor Red}
                }
            }

            if($EmailNotify){
                if($LogFile){Write-Log -Message "Preparing Notification Email: $msg" -Path $LogFile -Level Info}
                $msg = "Plex Media Server $($PlexWeb[0].MediaContainer.friendlyName) was updated on computer $env:COMPUTERNAME.`r`n`r`nNew Version: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.ProductVersion)`r`nOld Version: $installedVersion-$installedBuild"
                if($IncludeLog -and $LogFile){
                    $logContent = Get-Content -Path $LogFile
                    $msg += "`r`n`r`n****  START LOG  ****`r`n"
                    Foreach ($Line in $logContent) {
                        $msg += $Line + "`r`n"
                    }
                    $msg += "****  END LOG  ****"
                }
                if($EmailIsBodyHtml){$msg = $msg.Replace("`r`n","</br>")}

                if($AttachLog -and $LogFile){
                    if($LogFile){Write-Log -Message "Sending Email Notification to $SmtpTo with log attached." -Path $LogFile -Level Info}
                    if(Send-ToEmail -SmtpFrom $SmtpFrom -SmtpTo $SmtpTo -Subject "Plex Media Server Updated on $env:COMPUTERNAME" `
                        -Body $msg -SmtpUser $SmtpUser -SmtpPassword $SmtpPassword -SmtpServer $SmtpServer -SmtpPort $SmtpPort `
                        -EnableSSL $EnableSSL -attachmentpath $LogFile -IsBodyHtml $EmailIsBodyHtml -PassThru -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Email Notification sent successsfully." -Path $LogFile -Level Info}
                        if(-not $Silent){Write-Host "Email Notification: Sent" -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Email Notification" -Path $LogFile -Level Info}
                        if(-not $Silent){Write-Host "Email Notification: Error" -ForegroundColor Red}
                    }
                }else{
                    if(Send-ToEmail -SmtpFrom $SmtpFrom -SmtpTo $SmtpTo -Subject "Plex Media Server updated on $env:COMPUTERNAME" `
                        -Body $msg -SmtpUser $SmtpUser -SmtpPassword $SmtpPassword -SmtpServer $SmtpServer -SmtpPort $SmtpPort `
                        -EnableSSL $EnableSSL -IsBodyHtml $EmailIsBodyHtml -PassThru -ErrorAction SilentlyContinue){
                            if($LogFile){Write-Log -Message "Email Notification sent successsfully." -Path $LogFile -Level Info}
                            if(-not $Silent){Write-Host "Email Notification: Sent" -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Email Notification" -Path $LogFile -Level Info}
                        if(-not $Silent){Write-Host "Email Notification: Error" -ForegroundColor Red}
                    }
                }
            }
        }Catch{
            if($LogFile){Write-Log -Message "Error occurred: $($_.Exception.Message)" -Path $LogFile -Level Info}
            $Global:LASTEXITCODE=1
            throw $_
        }finally{
            if($LogFile){Write-Log -Message "Update-PlexMediaServer Completed" -Path $LogFile -Level Info}
        }
        if($NotifySuccess -and $UpdateSuccess){$Global:LASTEXITCODE=10}
    }
}

function Get-PlexToken{
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param(
    #
    [Alias("PlexID")]
    [Parameter(
        ParameterSetName="Credential",
        Position=0,
        ValueFromPipelineByPropertyName=$true
    )]
    
    [string]$PlexLogin,

    #
    [Parameter(
        ParameterSetName="Credential",
        Position=1,
        ValueFromPipelineByPropertyName=$true
    )]
    
    [string]$PlexPassword,

    #
    [parameter(
        ParameterSetName="PSCredential",
        Position=0)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        [ValidateScript({
            if($_ -is [System.Management.Automation.PSCredential]){
                $true
            }else{
                $Script:Credential=Get-Credential -Credential $_ -Message "Enter your Plex.tv credentials:"
                $true
            }
        }
    )]

    [object]$Credential = [System.Management.Automation.PSCredential]::Empty,
    #
    [parameter(
        ValueFromPipelineByPropertyName=$true
    )]

    [Switch]$Plex2FA,

    #
    [parameter(
        ValueFromPipelineByPropertyName=$true
    )]
    [ValidateNotNullOrEmpty()]

    [String]$Product='Get-PlexToken',
    
    [parameter(
        ValueFromPipelineByPropertyName=$true
    )]
    [ValidateNotNullOrEmpty()]

    [String]$Version='v2.0.0',

    [parameter(
        ValueFromPipelineByPropertyName=$true
    )]

    [Switch]$PassThru

    )
    switch($PSCmdlet.ParameterSetName){
        "Credential"{Write-Debug "ParameterSetName: $_"}
        "PSCredential"{Write-Debug "ParameterSetName: $_"}
        default{Write-Debug "ParameterSetName: $_"}
    }

    [hashtable]$return=@{}

    if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
        $PlexLogin=$Credential.GetNetworkCredential().UserName
        $PlexPassword=$Credential.GetNetworkCredential().Password
    }

    while([string]::IsNullOrEmpty($PlexLogin)){
        $PlexLogin=Read-Host -Prompt "Enter Plex.tv Email or ID"
    }

    while([string]::IsNullOrEmpty($PlexPassword)){
        $PlexPassword=Read-Host -Prompt "Enter Plex.tv password"
    }

    if($Plex2FA){
        do{
            $AuthCode=Read-Host -Prompt "Enter Two-Factor auth code"
            if($AuthCode -notmatch '[0-9]{6}'){Write-Host "Format incorrect"}
        }until($AuthCode -match '[0-9]{6}')
        $PlexPassword=$PlexPassword+$AuthCode
    }

    $URL_LOGIN='https://plex.tv/users/sign_in.json'

    try {
		$response = Invoke-RestMethod -Uri $URL_LOGIN -Method POST -Headers @{
            'Authorization'            = ("Basic {0}" -f ([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $PlexLogin, $PlexPassword)))));
            'X-Plex-Client-Identifier' = "PowerShell";
            'X-Plex-Product'           = $Product;
            'X-Plex-Version'           = $Version;
            'X-Plex-Username'          = $PlexLogin;
		} -ErrorAction Stop

        Write-Verbose "Plex Authentication Token $($response.user.authToken) found for $($response.user.username)"
        $return.user=$response.user
        $return.Status=0
        if($PassThru){return $return}else{return $response.user.authToken}
        
    } catch {

        $return.Exception=$_.Exception
        $return.Status=1
        if($return.Exception.Response){
            Write-Verbose "Unable to retrieve Plex Token from $URL_LOGIN Message: $($return.Exception.Message) (Error: $($return.Exception.HResult))"
            switch($return.Exception.Response.StatusCode.value__){
                401{Write-Verbose "Username and/or password incorrect. StatusDescription: $($return.Exception.Response.StatusDescription) (StatusCode: $($return.Exception.Response.StatusCode.value__))"}
                201{Write-Verbose "Failed to log in.  StatusDescription: $($return.Exception.Response.StatusDescription) (StatusCode: $($return.Exception.Response.StatusCode.value__))"}
                else{Write-Error "StatusDescription: $($return.Exception.Response.StatusDescription) (StatusCode: $($return.Exception.Response.StatusCode.value__))"}
            }
            if($PassThru){return $return}else{return $false}
        }else{
            Write-Verbose "Error connecting to $URL_LOGIN Message: $($return.Exception.Message) (Error: $($return.Exception.HResult))"
            if($PassThru){return $return}else{return $false}
       }

    }
}

function Get-RestMethod{
    [CmdletBinding()]
    param(
    #
    [Parameter(
                ValueFromPipelineByPropertyName=$true)]

                [string]$Uri,

    [Parameter(
                ValueFromPipelineByPropertyName=$true)]

                [object]$Headers,

    #
    [Parameter(
                ValueFromPipelineByPropertyName=$true)]

                [string]$Method='Default',
    
    #
    [Parameter(
                ValueFromPipelineByPropertyName=$true)]
                
                [switch]$UseBasicParsing,

    #
    [Parameter(
                ValueFromPipelineByPropertyName=$true)]

                [int32]$TimeoutSec=30,

    #
    [parameter(
                Mandatory = $False)]

                [Switch]$PassThru
    )

    [hashtable]$return=@{}

    try {
        Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -UseBasicParsing:$UseBasicParsing -TimeoutSec $TimeoutSec -OutVariable response
    } catch {
        $return.exception=$_.Exception
        $return.Status=1
    }

    if($response){
        Write-Verbose "Successful response from Server $($Uri)"
        $return.response=$response
        $return.status=0
        if($PassThru){return $return}else{return $true}
    }else{
        if($return.exception.Response){
            Write-Verbose "Server at $($Uri) responded with an error. Message: $($return.exception.Message) (Error: $($return.exception.HResult)) StatusDescription: $($return.exception.Response.StatusDescription) (StatusCode: $($return.exception.Response.StatusCode.value__))"
            if($PassThru){return $return}else{return $false}
        }else{
            Write-Verbose "Error connecting to Server at $($Uri). Message: $($return.exception.Message) (Error: $($return.exception.HResult))"
            if($PassThru){return $return}else{return $false}
        }
    }
}

function Get-FileBitness {
    [CmdletBinding(SupportsShouldProcess=$True,DefaultParameterSetName="None")]
    PARAM(
    	[Parameter(
    		HelpMessage = "Enter binary file(s) to examine",
    		Position = 0,
    		Mandatory = $true,
    		ValueFromPipeline = $true,
    		ValueFromPipelineByPropertyName = $true
    	)]
    	[ValidateNotNullOrEmpty()]
    	[ValidateScript({Test-Path $_.FullName})]
    	[IO.FileInfo[]]
    	$Path
    )
    
    BEGIN {
        # PE Header machine offset
        [int32]$MACHINE_OFFSET = 4
        # PE Header pointer offset
        [int32]$PE_POINTER_OFFSET = 60
        # Initial byte array size
        [int32]$PE_HEADER_SIZE = 4096
    }
    
    PROCESS {
        # Create a location to place the byte data
        [byte[]]$BYTE_ARRAY = New-Object -TypeName System.Byte[] -ArgumentList @(,$PE_HEADER_SIZE)
        # Open the file for read access
        $FileStream = New-Object -TypeName System.IO.FileStream -ArgumentList ($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        # Read the requested byte length into the byte array
        $FileStream.Read($BYTE_ARRAY, 0, $BYTE_ARRAY.Length) | Out-Null
        #
        [int32]$PE_HEADER_ADDR = [System.BitConverter]::ToInt32($BYTE_ARRAY, $PE_POINTER_OFFSET)
        try {
    	    [int32]$machineUint = [System.BitConverter]::ToUInt16($BYTE_ARRAY, $PE_HEADER_ADDR + $MACHINE_OFFSET)
        } catch {
    	    $machineUint = 0xffff
        }
        switch ($machineUint) {
    	    0x0000 {return 'UNKNOWN'}
    	    0x0184 {return 'ALPHA'}
    	    0x01d3 {return 'AM33'}
    	    0x8664 {return 'AMD64'}
    	    0x01c0 {return 'ARM'}
    	    0x01c4 {return 'ARMNT'} # aka ARMV7
    	    0xaa64 {return 'ARM64'} # aka ARMV8
    	    0x0ebc {return 'EBC'}
    	    0x014c {return 'I386'}
    	    0x014d {return 'I860'}
    	    0x0200 {return 'IA64'}
    	    0x0268 {return 'M68K'}
    	    0x9041 {return 'M32R'}
    	    0x0266 {return 'MIPS16'}
    	    0x0366 {return 'MIPSFPU'}
    	    0x0466 {return 'MIPSFPU16'}
    	    0x01f0 {return 'POWERPC'}
    	    0x01f1 {return 'POWERPCFP'}
    	    0x01f2 {return 'POWERPCBE'}
    	    0x0162 {return 'R3000'}
    	    0x0166 {return 'R4000'}
    	    0x0168 {return 'R10000'}
    	    0x01a2 {return 'SH3'}
    	    0x01a3 {return 'SH3DSP'}
    	    0x01a6 {return 'SH4'}
    	    0x01a8 {return 'SH5'}
    	    0x0520 {return 'TRICORE'}
    	    0x01c2 {return 'THUMB'}
    	    0x0169 {return 'WCEMIPSV2'}
    	    0x0284 {return 'ALPHA64'}
    	    0xffff {return 'INVALID'}
        }
    }
    
    END {
        $FileStream.Close()
        $FileStream.Dispose()
    }
}

function Send-ToEmail([string]$SmtpFrom, [string]$SmtpTo, [string]$Subject, [string]$Body, [string]$attachmentpath, [string]$SmtpUser, [string]$SmtpPassword, [string]$SmtpServer, [string]$SmtpPort, [bool]$EnableSSL, [bool]$IsBodyHtml, [switch]$PassThru){
    
        $message = new-object Net.Mail.MailMessage;
        $message.From = "$SmtpFrom";
        $message.To.Add($SmtpTo);
        $message.Subject = $Subject;
        if($IsBodyHtml){
            $message.IsBodyHtml = $true;
            $message.Body = (ConvertTo-Html -Body $body | Out-String);
        }else{
            $message.Body = $Body;
        }
        if($attachmentpath){
            $attachment = New-Object Net.Mail.Attachment($attachmentpath)
            $message.Attachments.Add($attachment);
        }
    
        $smtp = new-object Net.Mail.SmtpClient("$SmtpServer", "$SmtpPort");
        if($EnableSSL){$smtp.EnableSSL = $true;}
        $smtp.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPassword);
        try{
            $smtp.send($message);
        }catch{
            if($PassThru){return $_.exception}else{return $false}
        }finally{
            if($attachmentpath){$attachment.Dispose();}
        }
        return $true
     }
    
 <# 
.Synopsis 
   Write-Log writes a message to a specified log file with the current time stamp. 
.DESCRIPTION 
   The Write-Log function is designed to add logging capability to other scripts. 
   In addition to writing output and/or verbose you can write to a log file for 
   later debugging. 
.NOTES 
   Created by: Jason Wasser @wasserja 
   Modified: 11/24/2015 09:30:19 AM   
 
   Changelog: 
    * Code simplification and clarification - thanks to @juneb_get_help 
    * Added documentation. 
    * Renamed LogPath parameter to Path to keep it standard - thanks to @JeffHicks 
    * Revised the Force switch to work as it should - thanks to @JeffHicks 
 
   To Do: 
    * Add error handling if trying to create a log file in a inaccessible location. 
    * Add ability to write $Message to $Verbose or $Error pipelines to eliminate 
      duplicates. 
.PARAMETER Message 
   Message is the content that you wish to add to the log file.  
.PARAMETER Path 
   The path to the log file to which you would like to write. By default the function will  
   create the path and file if it does not exist.  
.PARAMETER Level 
   Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational) 
.PARAMETER NoClobber 
   Use NoClobber if you do not wish to overwrite an existing file. 
.EXAMPLE 
   Write-Log -Message 'Log message'  
   Writes the message to c:\Logs\PowerShellLog.log. 
.EXAMPLE 
   Write-Log -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log 
   Writes the content to the specified log file and creates the path and file specified.  
.EXAMPLE 
   Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error 
   Writes the message to the specified log file as an error message, and writes the message to the error pipeline. 
.LINK 
   https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0 
#> 
function Write-Log 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path='C:\Logs\PowerShellLog.log', 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info", 
         
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
        # Set VerbosePreference to Continue so that verbose messages are displayed. 
#        $VerbosePreference = 'Continue' 
    } 
    Process 
    { 
         
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
            Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
                Write-Error $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
                Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
                Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
    }
    End 
    { 
    } 
}

function Post-ToSlack 
{
    <#  
            .SYNOPSIS
            Sends a chat message to a Slack organization
            .DESCRIPTION
            The Post-ToSlack cmdlet is used to send a chat message to a Slack channel, group, or person.
            Slack requires a token to authenticate to an org. Either place a file named token.txt in the same directory as this cmdlet,
            or provide the token using the -token parameter. For more details on Slack tokens, use Get-Help with the -Full arg.
            .NOTES
            Written by Chris Wahl for community usage
            Twitter: @ChrisWahl
            GitHub: chriswahl
            .EXAMPLE
            Post-ToSlack -channel '#general' -message 'Hello everyone!' -botname 'The Borg'
            This will send a message to the #General channel, and the bot's name will be The Borg.
            .EXAMPLE
            Post-ToSlack -channel '#general' -message 'Hello everyone!' -token '1234567890'
            This will send a message to the #General channel using a specific token 1234567890, and the bot's name will be default (PowerShell Bot).
            .LINK
            Validate or update your Slack tokens:
            https://api.slack.com/tokens
            Create a Slack token:
            https://api.slack.com/web
            More information on Bot Users:
            https://api.slack.com/bot-users
    #>

    Param(
        [Parameter(Mandatory = $true,Position = 0,HelpMessage = 'Slack channel')]
        [ValidateNotNullorEmpty()]
        [String]$Channel,
        [Parameter(Mandatory = $true,Position = 1,HelpMessage = 'Chat message')]
        [ValidateNotNullorEmpty()]
        [String]$Message,
        [Parameter(Mandatory = $false,Position = 2,HelpMessage = 'Slack API token')]
        [ValidateNotNullorEmpty()]
        [String]$token,
        [Parameter(Mandatory = $false,Position = 3,HelpMessage = 'Optional name for the bot')]
        [String]$BotName = 'PowerShell'
    )

    Process {

        # Static parameters
        if (!$token) 
        {
            $token = Get-Content -Path "$PSScriptRoot\token.txt"
        }
        $uri = 'https://slack.com/api/chat.postMessage'

        # Build the body as per https://api.slack.com/methods/chat.postMessage
        $body = @{
            token    = $token
            channel  = $Channel
            text     = $Message
            username = $BotName
            parse    = 'full'
        }

        # Call the API
        try 
        {
            Invoke-RestMethod -Uri $uri -Body $body
        }
        catch 
        {
            throw 'Unable to call the API'
        }

    } # End of process
} # End of function
