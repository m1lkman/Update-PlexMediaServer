#Requires -Version 4.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
   Module for managing Plex Media Server updates running Plex Media Server Service Wrapper (PmsService).
.DESCRIPTION
   Windows PowerShell module for managning and automating Plex Media Server updates when running with Cjmurph's Plex Media Server Service Wrapper. This module automates checking latest Plex Media Server public or Beta(PlexPass) versions, downloading the update, stopping services/processes, installing the update, and restarting services. Supports interactive or silent execution (for automation), with logging, and email notification. Authentication is performed against Plex.tv server using either Plex Authentication Tokens (User or Server) or Plex.tv credentials.
.EXAMPLE Run Interactively and attempt to update from publicly available updates.
   Update-PlexMediaServer
.EXAMPLE Force Upgrade/reinstall even if version is greater than or equal to
   Update-PlexMediaServer -force
.EXAMPLE Run Interactively and specify a user other than the context the script is executing in.
   Update-PlexMediaServer -UserName JDoe
.EXAMPLE Run interactively and attempt to update from PlexPass(Beta) available updates. Will prompt for Plex.tv Email/Id and password.
   Update-PlexMediaServer -PlexPass
.EXAMPLE Run silently and attempt to update from PlexPass(Beta) available updates.
   Update-PlexMediaServer -PlexToken <Token> -Quiet
.EXAMPLE Run Passive and update using Server Online Authentication Token.
   Update-PlexMediaServer -PlexServerToken -Passive
.EXAMPLE
   Update-PlexMediaServer -PlexLogin <Email/ID> -PlexPassword <Password>
.EXAMPLE
   Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock {:Update-PlexMediaServer -UserName JDoe} 
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock {Update-PlexMediaServer -UserName JDoe} 
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock {Update-PlexMediaServer -UserName JDoe} 
.NOTES

.LINK
    https://github.com/m1lkman/Update-PlexMediaServer
#>
Function Update-PlexMediaServer
{
    [CmdletBinding(SupportsShouldProcess,DefaultParameterSetName="ServerAuth")]
    param(
    # Plex Server Online Authentication Token
    [Parameter(
        ParameterSetName="ServerAuth",
        Position=0,
        Mandatory=$false,
        HelpMessage="Enables Plex Server Authentication Token Discovery")]
    [Parameter(
        ParameterSetName="SlackNotify",
        Position=0)]
    [Parameter(
        ParameterSetName="EmailNotify",
        Position=0)]
    [Parameter(
        ParameterSetName="Passive",
        Position=0)]
    [Parameter(
        ParameterSetName="Quiet",
        Position=0)]

        [switch]
        $UseServerToken,

    # Plex User Authentication Token
    [Parameter(
        ParameterSetName="TokenAuth",
        Position=0,
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Enter Plex Authentication Token (Use Get-PlexToken to get your token from Plex.tv")]
    [ValidateScript({
        if($_ -match "[0-9a-zA-Z-_]{20}"){
            $true
        }else{
            throw "Please provide a Plex Authentication Token matching the format abcde12345abcde12345 (20 alpha-numeric characters)."
        }
    })]
    [ValidateNotNull()]
    [Parameter(
        ParameterSetName="SlackNotify",
        Position=0)]
    [Parameter(
        ParameterSetName="EmailNotify",
        Position=0)]

        [string]
        $PlexToken,

    # Plex.tv Credentials with PSCredential
    [Parameter(
        ParameterSetName="CredAuth",
        Position=0,
        ValueFromPipelineByPropertyName=$true,
        Mandatory=$true,
        HelpMessage="PSCredential")]
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]    
    [Parameter(
        ParameterSetName="SlackNotify",
        Position=0)]
    [Parameter(
        ParameterSetName="EmailNotify",
        Position=0)]

        [object]
        $Credential=[System.Management.Automation.PSCredential]::Empty,

    # 
    [Alias("PlexID")]
    [Parameter(
        ParameterSetName="TextAuth",
        Position=0,
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Enter Plex.tv Email or ID")]
    [Parameter(
        ParameterSetName="SlackNotify",
        Position=0)]
    [Parameter(
        ParameterSetName="EmailNotify",
        Position=0)]
                        
        [string]
        $PlexLogin,

    # 
    [Parameter(
        ParameterSetName="TextAuth",
        Position=1,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Enter Plex.tv Password")]
    [Parameter(
        ParameterSetName="SlackNotify",
        Position=0)]
    [Parameter(
        ParameterSetName="EmailNotify",
        Position=1)]

        [string]
        $PlexPassword,

    #  
    [Parameter(
        HelpMessage="Disables PlexPass(Beta) Updates")]

        [switch]
        $DisablePlexPass,

    #
    [Parameter(
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Enter non-standard Plex Media Server Port, default is 32400")]

        [int32]
        $PlexServerPort=32400,

    #
    [Parameter(
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Specifiy Plex Media Server Hostname for Plex Web Checks. Bypasses detecting hostname using public IP reverse dns lookup.")]

        [String]
        $PlexServerHostName,

    # Specify Username if Plex Media Server is running in a user context other than context of script execution
    [Parameter(
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Specify Windows Username when script is executing in a user context other than Plex Media Server/Plex Media Server Service Wrapper")]

        [string]
        $UserName,

    # 
    [Parameter(
        ParameterSetName="LogFile",
        Position=0,
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Enter Log File path, default is PSScriptRoot\Update-PlexMediaServer.log")]
    [ValidateNotNull()]
    [Parameter(
        ParameterSetName="ServerAuth")]
    [Parameter(
        ParameterSetName="TokenAuth")]
    [Parameter(
        ParameterSetName="CredAuth")]
    [Parameter(
        ParameterSetName="TextAuth")]
    [Parameter(
        ParameterSetName="SlackNotify")]
    [Parameter(
        ParameterSetName="EmailNotify")]
    
        [string]
        $LogFile="$PSScriptRoot\Update-PlexMediaServer.log",

    # Force update 
    [Parameter(
        HelpMessage="Forces Update installation regardless of installed version")]

        [switch]
        $Force,
    # Report update Only
    [Parameter(
        HelpMessage="Reports when update is required but does not downlaod and launch update")]

        [switch]
        $ReportOnly,
    # Plex Server Build Build 
    [Parameter(
        HelpMessage="Forces Plex Media Server Build Architecture. If ommitted, Build Archtecture is that of OS architecture detected.")]

        [ValidateSet('windows-x86','windows-x86_64')]
        [string]
        $Build,

    # Cleanup old updates 
    [Parameter(
        HelpMessage="Enables cleanup of old updates. Set number of Updates to keep in Updates folder.")]

        [int32]
        $UpdateCleanup,

    # passive - minimal UI no prompts
    [Parameter(
        ParameterSetName="Passive",
        HelpMessage="Displays minimal UI with no prompts")]
#    [Parameter(
#        ParameterSetName="ServerAuth")]
    [Parameter(
        ParameterSetName="TokenAuth")]
    [Parameter(
        ParameterSetName="CredAuth")]
    [Parameter(
        ParameterSetName="TextAuth")]
    [Parameter(
        ParameterSetName="LogFile")]
    [Parameter(
        ParameterSetName="SlackNotify")]
    [Parameter(
        ParameterSetName="EmailNotify")]
                
        [switch]
        $Passive,

    # quiet - no UI no prompts
    [Parameter(
        ParameterSetName="Quiet",
        HelpMessage="Display no UI and no prompts")]
#    [Parameter(
#        ParameterSetName="ServerAuth")]
    [Parameter(
        ParameterSetName="TokenAuth")]
    [Parameter(
        ParameterSetName="CredAuth")]
    [Parameter(
        ParameterSetName="TextAuth")]
    [Parameter(
        ParameterSetName="LogFile")]
    [Parameter(
        ParameterSetName="SlackNotify")]
    [Parameter(
        ParameterSetName="EmailNotify")]
            
        [switch]
        $Quiet,

    # For Email Notification configure all the below parameters in script or via command line 
    [Parameter(
        ParameterSetName="SlackNotify",
        Position=0,
        Mandatory=$true,
        HelpMessage="Enables email notification")]
                                
        [switch]
        $SlackNotify,

    #
    [Parameter(
        ParameterSetName="SlackNotify",
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Slack Channel Name")]

        [string]
        $SlackChannel,
    #
    [Parameter(
        ParameterSetName="SlackNotify",
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Slack OAuth Token")]

        [string]
        $SlackToken,

    # For Email Notification configure all the below parameters in script or via command line 
    [Parameter(
        ParameterSetName="EmailNotify",
        Position=0,
        Mandatory=$true,
        HelpMessage="Enables email notification")]
                                
        [switch]
        $EmailNotify,

    # Attach log file to notification if LogFile configured 
    [Parameter(
        ParameterSetName="EmailNotify",
        HelpMessage="Attach logfile with email notification")]
    [Parameter(
        ParameterSetName="LogFile")]

        [switch]
        $AttachLog,

    # Include log file contents in notification if LogFile configured 
    [Parameter(
        ParameterSetName="EmailNotify",
        HelpMessage="Attach logfile with email notification")]
    [Parameter(
        ParameterSetName="LogFile")]

        [switch]
        $IncludeLog,

    #
    [Parameter(
        ParameterSetName="EmailNotify",
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Email notification recipient")]

        [string]
        $SmtpTo,

    #
    [Parameter(
        ParameterSetName="EmailNotify",
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="Email notification sender")]

        [string]
        $SmtpFrom,

    #
    [Parameter(
        ParameterSetName="EmailNotify",
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SMTP Server Username")]

        [string]
        $SmtpUser,

    #
    [Parameter(
        ParameterSetName="EmailNotify",
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SMTP Server Password")]

        [string]
        $SmtpPassword,

    #
    [Parameter(
        ParameterSetName="EmailNotify",
        Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SMTP Server Name")]

        [string]
        $SmtpServer,

    #
    [Parameter(
        ParameterSetName="EmailNotify",
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="SMTP Server Port")]

        [int32]
        $SmtpPort,

    # Enable SSL for SMTP Authentication 
    [Parameter(
        ParameterSetName="EmailNotify",
        HelpMessage="Enables SSL for SMTP Authentication")]

        [switch]
        $EnableSSL,
    # Enable HTML Email Formating 
    [Parameter(
        ParameterSetName="EmailNotify",
        HelpMessage="Enables SSL for SMTP Authentication")]

        [switch]
        $EmailIsBodyHtml
    )

    begin{
        switch($PSCmdlet.ParameterSetName){
            "ServerAuth"{Write-Debug "ParameterSetName: $_"}
            "TokenAuth"{Write-Debug "ParameterSetName: $_"}
            "CredAuth"{Write-Debug "ParameterSetName: $_"}
            "TextAuth"{Write-Debug "ParameterSetName: $_"}
            default{Write-Debug "ParameterSetName: $_"}
        }

        #validate Build variable
        if( -not [System.Environment]::Is64BitOperatingSystem -and $Build -eq 'windows-x86_64'){
            if($LogFile){Write-Log -Message "Exiting: Plex Media Server (x64) build is not supported on x86 Systems." -Path $LogFile -Level Info}
            if(-not $quiet){Write-Host "Exiting: Plex Media Server (x64) build is not supported on x86 Systems." -ForegroundColor Red}
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
    }
    process{

        Try{
            #Begin process ParameterSets
            if($PlexToken){#Plex Token specified via command-line
                if($LogFile){Write-Log -Message "Token Authentication enabled via command-line" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Verifying Authentication Token..." -ForegroundColor Cyan -NoNewline}
                if((Get-RestMethod -Uri "https://plex.tv/api/resources?X-Plex-Token=$PlexToken" -OutVariable response -PassThru -ErrorAction SilentlyContinue).exception){
                    if($response.exception.Response){
                        if($LogFile){Write-Log -Message "Plex authentication token was not validated. Please verify or use Get-PlexToken to retrieve again. Server Response: $($response.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Token Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Please verify specified Plex Autentication Token or use Get-PlexToken to retrieve one." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Unable to verify Plex authentication token. Unable to reach Plex.tv servers or they are unresponsive. Message: $($response.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are unresponsive. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    throw "Unable to verify Plex Login Token"
                }else{
                    if($LogFile){Write-Log -Message "Plex Authentication Token $PlexToken specified at command-line Validated" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Token Validated" -ForegroundColor Cyan}
                }
            }elseif($PlexLogin -and $PlexPassword){#Plex.tv credentials specified via command-line
                if($LogFile){Write-Log -Message "Credential Authentication enabled via command-line" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Verifying Plex.tv Login..." -ForegroundColor Cyan -NoNewline}
                if((Get-PlexToken -PlexLogin $PlexLogin -PlexPassword $PlexPassword -OutVariable PlexUser -PassThru -ErrorAction SilentlyContinue).exception){
                    if($PlexUser.exception.Response){
                        if($LogFile){Write-Log -Message "Unable to retrieve Plex authentication Token. Username and/or password are incorrect. Server Response: $($PlexUser.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Plex Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Username and/or password are incorrect. Unable to retrieve Plex Authentication Token." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Cannot verify Plex login credentials. Unable to reach Plex.tv servers or they are not responding. Message: $($PlexUser.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are not responding. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    throw "Unable to verify Plex Login Token"
                }else{
                    $PlexToken=$PlexUser.user.authToken
                    if($LogFile){Write-Log -Message "Plex authentication Token $($PlexUser.user.authToken) found for Plex user $($PlexUser.user.username)" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Credentials Validated" -ForegroundColor Cyan}
                }
            }elseif($Credential -ne [System.Management.Automation.PSCredential]::Empty){#Plex.tv credentials specified via command-line using PSCredential Object
                if($LogFile){Write-Log -Message "PSCredential Authentication enabled via command-line" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Verifying Plex.tv Credentials..." -ForegroundColor Cyan -NoNewline}
                if((Get-PlexToken -Credential $Credential -OutVariable PlexUser -PassThru -ErrorAction SilentlyContinue).exception){
                    if($PlexUser.exception.Response){
                        if($LogFile){Write-Log -Message "Unable to retrieve Plex authentication Token. Username and/or password are incorrect. Server Response: $($PlexUser.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Plex Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Username and/or password are incorrect. Unable to retrieve Plex Authentication Token." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Cannot verify Plex login credentials. Unable to reach Plex.tv servers or they are not responding. Message: $($PlexUser.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are not responding. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    throw "Unable to verify Credentials for Plex.tv Login"
                }else{
                    $PlexToken=$PlexUser.user.authToken
                    if($LogFile){Write-Log -Message "Plex authentication Token $($PlexUser.user.authToken) found for Plex user $($PlexUser.user.username)" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Credentials Validated" -ForegroundColor Cyan}
                }
            }elseif($UseServerToken){#Online Plex Server Token
                if($LogFile){Write-Log -Message "Server Online Token Authentication enabled via command-line" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Verifying Server Online Authentication Token..." -ForegroundColor Cyan -NoNewline}
                $UseServerToken=$true                
            }else{
                if(!($Passive -or $Quiet)){#interactive
                    if($PlexLogin -or $PlexPassword){
                        if(-not $quiet){Write-Host "Verifying Plex.tv Credentials..." -ForegroundColor Cyan -NoNewline}
                        if((Get-PlexToken -PlexLogin $PlexLogin -PlexPassword $PlexPassword -OutVariable PlexUser -PassThru -ErrorAction SilentlyContinue).exception){
                            if($PlexUser.exception.Response){
                                if($LogFile){Write-Log -Message "Unable to retrieve Plex authentication Token. Username and/or password are incorrect. Server Response: $($PlexUser.exception.message)" -Path $LogFile -Level Error}
                                if(-not $quiet){Write-Host "Plex Authentication Failed" -ForegroundColor Red}
                                if(-not $quiet){Write-Host "Username and/or password are incorrect. Unable to retrieve Plex Authentication Token." -ForegroundColor Cyan}
                            }else{
                                if($LogFile){Write-Log -Message "Cannot verify Plex login credentials. Unable to reach Plex.tv servers or they are not responding. Message: $($PlexUser.exception.message)" -Path $LogFile -Level Error}
                                if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                                if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are not responding. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                            }
                            throw "Unable to verify Plex.tv Credentials"
                        }else{
                            $PlexToken=$PlexUser.user.authToken
                            if($LogFile){Write-Log -Message "Plex authentication Token $($PlexUser.user.authToken) found for Plex user $($PlexUser.user.username)" -Path $LogFile -Level Info}
                            if(-not $quiet){Write-Host "Credentials Validated" -ForegroundColor Cyan}
                        }
                    }
                }else{#non-interactive
                    if($PlexLogin -or $PlexPassword){
                        if($LogFile){Write-Log -Message "Unable to determine Plex Authentication Token missing Plex.tv username or password from command line. Unable to prompt for information when running in non-interactive Quiet mode." -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Unable to determine Plex Authentication Token without additional imput in passive/quiet mode." -ForegroundColor Cyan}
                        if(-not $quiet){Write-Host "     1. Configure PlexToken variable in script. Use Get-PlexToken." -ForegroundColor Cyan}
                        if(-not $quiet){Write-Host "     2. Specify your token in the command line, i.e. -plextoken <Token>" -ForegroundColor Cyan}
                        if(-not $quiet){Write-Host "     3. Specify your plex.tv username/ID and password in the command line, i.e. -PlexLogin <email/id> -PlexPassword <password>" -ForegroundColor Cyan}
                        throw "Unable to determin Plex Authentication Token."
                    }
                }
                if($LogFile){Write-Log -Message "Server Online Token Authentication execution enabled" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Verifying Server Online Authentication Token..." -ForegroundColor Cyan -NoNewline}
                $UseServerToken=$true
            }

            #Begin Prcess Arguments
            if($Force){
                if($LogFile){Write-Log -Message "Force Update enabled via command-line (-Force)" -Path $LogFile -Level Info}
            }
            if($ReportOnly){
                if($LogFile){Write-Log -Message "Report Only enabled via command-line (-Force)" -Path $LogFile -Level Info}
            }
            if($EmailNotify){
                if($LogFile){Write-Log -Message "Email Notification enabled via command-line (-EmailNotify)" -Path $LogFile -Level Info}
            }
            if($AttachLog){
                if($LogFile){Write-Log -Message "Attach Log to Notification enabled via command-line (-AttachLog)" -Path $LogFile -Level Info}
            }
            if($IncludeLog){
                if($LogFile){Write-Log -Message "Include Log in Notification enabled via command-line (-IncludeLog)" -Path $LogFile -Level Info}
            }
            if($EmailIsBodyHtml){
                if($LogFile){Write-Log -Message "Email HTML Format for Notification enabled via command-line (-EmailIsBodyHtml)" -Path $LogFile -Level Info}
            }
            if($DisablePlexPass){
                if($LogFile){Write-Log -Message "PlexPass(Beta) Updates disabled via command-line (-DisablePlexPass)" -Path $LogFile -Level Info}
            }
            if($UpdatesCleanup){
                if($LogFile){Write-Log -Message "Update Cleanup enabled via command-line (-UpdateCleanup)" -Path $LogFile -Level Info}
            }

            if($PlexUser){
                if(-not $quiet){Write-Host "`t Username: $($PlexUser[0].user.username)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t authToken: $($PlexUser[0].user.authToken)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Subscription: $($PlexUser[0].user.subscription.status)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Plan: $($PlexUser[0].user.subscription.plan)" -ForegroundColor Cyan}
                $PlexPassStatus=$PlexUser[0].user.subscription.active
            }else{
                $PlexPassStatus="False"
            }

            #Find Plex Media Server Setttings Key
            $PMSSettingsKeys=Get-ItemProperty 'HKU:\*\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\WOW6432Node\Plex, Inc.\Plex Media Server' -ErrorAction SilentlyContinue
            if($PMSSettingsKeys){
                if($LogFile){Write-Log -Message "Plex Media Server Settings found in Registry [Count: $($PMSSettingsKeys.Count)]" -Path $LogFile -Level Info}
                foreach($Key in $PmsSettingsKeys){
                    if(Get-ItemProperty "$($Key.InstallFolder)\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Plex Media Server installation found in $($Key.InstallFolder)" -Path $LogFile -Level Info}
                        $InstallFolder=$Key.InstallFolder
                        if($LogFile){Write-Log -Message "InstallFolder: $InstallFolder" -Path $LogFile -Level Info}
                    }else{
                        if($LogFile){Write-Log -Message "Plex Settings not found in key $($Key.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))" -Path $LogFile -Level Info}
                    }
                    if([string]::IsNullOrEmpty($Key.PlexOnlineMail) -or [string]::IsNullOrEmpty($Key.PlexOnlineMail) -or [string]::IsNullOrEmpty($Key.PlexOnlineMail)){
                        if($LogFile){Write-Log -Message "Plex Settings found in key $($Key.PSPath.Replace('Microsoft.PowerShell.Core\Registry::','')) are missing values, Plex Media Server may not be logged in and claimed" -Path $LogFile -Level Info}
                    }else{
                        $PMSSettings=$Key
                        if($LogFile){Write-Log -Message "Plex Settings Key Found $($Key.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))" -Path $LogFile -Level Info}
                        switch($PmsSettings.ButlerUpdateChannel){
                            ''{$ButlerUpdateChannel="Public"}
                            0{$ButlerUpdateChannel="Public"}
                            8{$ButlerUpdateChannel="Beta"}
                            default {if($LogFile){Write-Log -Message "Unknown Update Channel Value [$_]" -Path $LogFile -Level Warn}}

                        }
                        if($LogFile){Write-Log -Message "UpdateChannel: $ButlerUpdateChannel" -Path $LogFile -Level Info}
                        $LocalAppDataPath=$PmsSettings.LocalAppDataPath
                        if($LogFile){Write-Log -Message "LocalAppDataPath: $LocalAppDataPath" -Path $LogFile -Level Info}
                        $PlexOnlineMail=$PmsSettings.PlexOnlineMail
                        if($LogFile){Write-Log -Message "PlexOnlineMail: $PlexOnlineMail" -Path $LogFile -Level Info}
                        $PlexOnlineUsername=$PmsSettings.PlexOnlineUsername
                        if($LogFile){Write-Log -Message "PlexOnlineUsername: $PlexOnlineUsername" -Path $LogFile -Level Info}
                        $PlexOnlineToken=$PmsSettings.PlexOnlineToken
                        if($LogFile){Write-Log -Message "PlexOnlineToken: $PlexOnlineToken" -Path $LogFile -Level Info}
                    }
                    if($InstallFolder -and $PlexOnlineToken){Break}
                }
            }else{
                if($LogFile){Write-Log -Message "Plex Media Server installation not found in Registry" -Path $LogFile -Level Warn}
            }

            if($UseServerToken){
                if((Get-RestMethod -Uri "https://plex.tv/api/resources?X-Plex-Token=$PlexOnlineToken" -OutVariable response -PassThru -ErrorAction SilentlyContinue).exception){
                    if($response.exception.Response){
                        if($LogFile){Write-Log -Message "Plex Server Online Authentication Token was not validated. Please verify Plex Server is logged in and clamed. Server Response: $($response.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Server Online Token Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Please verify Plex Server is logged in and claimed." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Unable to verify Plex Server Online Authentication Token. Unable to reach Plex.tv servers or they are unresponsive. Message: $($response.exception.message)" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Unable to validate Server Online Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are unresponsive. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    throw "Unable to verify Plex Server Online Authentication Token."
                }else{
                    if($LogFile){Write-Log -Message "Plex Server Online Authentication Token $PlexOnlineToken Validated" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Server Token Validated" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Username: $($PmsSettings.PlexOnlineUsername)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t authToken: $($PlexOnlineToken)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Update Channel: $ButlerUpdateChannel" -ForegroundColor Cyan}
                }
                $PlexToken=$PlexOnlineToken
                if($ButlerUpdateChannel -eq "Public"){$DisablePlexPass=$true}
            }

            if(-not $quiet){Write-Host "Checking Plex Media Server Status..." -ForegroundColor Cyan -NoNewline}
            if($PMSExeFile){
                $installedVersion,$installedBuild = $PMSExeFile.VersionInfo.ProductVersion.Split('-')
                if($LogFile){Write-Log -Message "Plex Media Server executable $PMSExeFile is version $installedVersion configured to run as user $UserName" -Path $LogFile -Level Info}
            }

            #Locate Plex Media Server.exe Process and Get Current Version and determin username
            if(Get-Process "Plex Media Server" -IncludeUserName -OutVariable PMSProcess -ErrorAction SilentlyContinue | Select-Object Path ){
                if($LogFile){Write-Log -Message "Plex Media Server process running $($PMSProcess.Path) in user context $($PMSProcess.UserName)" -Path $LogFile -Level Info}
                If (-not $UserName){$UserName=$PMSProcess.UserName}
            }else{ # if process isn't running
                if($LogFile){Write-Log -Message "Plex Media Server process not running" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Not Running" -ForegroundColor Red}
                if(-not $UserName){$UserName=(New-Object System.Security.Principal.SecurityIdentifier($PMSSettings.PSPath.Split('\')[2])).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]}
            }
            #Get User SID
            try{
                $UserSID = (New-Object System.Security.Principal.NTAccount("$env:DomainName", "$UserName")).Translate([System.Security.Principal.SecurityIdentifier]).Value
            }catch{
                if($LogFile){Write-Log -Message "Unable to translate User SID, $env:DomainName\$UserName may not exist." -Path $LogFile -Level Error}
                if(-not $quiet){Write-Host "Unable to translate User SID, $env:DomainName\$UserName may not exist." -ForegroundColor Red}
                throw "Unable to translate User SID, $env:DomainName\$UserName may not exist."
            }
            if($LogFile){Write-Log -Message "$UserName SID: $UserSID" -Path $LogFile -Level Info}
            if($PmsProcess){
                if(-not $quiet){Write-Host "Running" -ForegroundColor Cyan}
                [bool]$PMSRunning=$true
            }else{
                [bool]$PMSRunning=$false
            }

            #Sanity Check
            if(-not $PMSSettings -and -not $PMSProcess -and -not $PMSExeFile){
                if($LogFile){Write-Log -Message "Exiting: Plex Media Server does not appear to be running or installed." -Path $LogFile -Level Error}
                if(-not $quiet){Write-Host "Exiting: Plex Media Server does not appear to be installed." -ForegroundColor Red}
                throw "Plex Media Server does not appear to be running or installed."
            }

            if(-not $quiet){Write-Host "`t Version: $installedVersion" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t Build: $installedBuild" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t Path: $PMSExeFile" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t User Context: $UserName" -ForegroundColor Cyan}

            ### Validate Plex Web Availability ###
            if(-not $quiet){Write-Host "Checking Plex Web Status..." -ForegroundColor Cyan -NoNewline}
            if($PlexServerHostName){
                $hostname = $PlexServerHostName
            }else{
                while((Get-RestMethod -Uri http://ipinfo.io/json -ErrorAction SilentlyContinue -PassThru -OutVariable HostNameResponse | Select-Object -ExpandProperty hostname -ErrorAction SilentlyContinue -OutVariable hostname) -eq $null){
                    if($LogFile){Write-Log -Message "Unable to determin Hostname, retrying. $($HostNameResponse.exception.message) Error: ($($HostNameResponse.exception.HResult))" -Path $LogFile -Level Warn}
                    Start-Sleep -Milliseconds 5
                }
                if($LogFile){Write-Log -Message "HostName is $hostname" -Path $LogFile -Level Info}
            }

            if($PlexServerPort -eq 443){$PlexServerScheme='https'}else{$PlexServerScheme='http'}
            $PlexServerUri="$($PlexServerScheme)://$($hostname):$PlexServerPort/"
            $PlexServerPrefsUri="$($PlexServerScheme)://$($hostname):$PlexServerPort/:/prefs/"
            $PlexServerLocationUri="$($PlexServerScheme)://$($hostname):$PlexServerPort/servers/"
            $PlexServerSessionUri="$($PlexServerScheme)://$($hostname):$PlexServerPort/status/sessions/"
            $PlexServerLiveTvSessionUri="$($PlexServerScheme)://$($hostname):$PlexServerPort/livetv/sessions/"
            if($Plextoken){
                $PlexServerUri=$PlexServerUri + "?X-Plex-Token=$($PlexToken)"
                $PlexServerPrefsUri=$PlexServerPrefsUri + "?X-Plex-Token=$($PlexToken)"
                $PlexServerLocationUri=$PlexServerLocationUri + "?X-Plex-Token=$($PlexToken)"
                $PlexServerSessionUri=$PlexServerSessionUri + "?X-Plex-Token=$($PlexToken)"
                $PlexServerLiveTvSessionUri=$PlexServerLiveTvSessionUri + "?X-Plex-Token=$($PlexToken)"
            }

            #check Plex Server Availability
            if((Get-RestMethod -Uri $PlexServerUri -PassThru -OutVariable PlexWeb -ErrorAction SilentlyContinue).exception){
                if($PlexWeb.exception.Response){
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerUri. Message: $($PlexWeb.exception.Message) (Error: $($PlexWeb.exception.HResult)) StatusDescription: $($PlexWeb.exception.Response.StatusDescription) (StatusCode: $($PlexWeb.exception.Response.StatusCode.value__))" -Path $LogFile -Level Warn}
                    if(-not $quiet){Write-Host $PlexWeb.exception.message -ForegroundColor Red}
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerUri" -Path $LogFile -Level Warn}
                }
                switch($PlexWeb.exception.Response.StatusCode.value__){
                    401{
                        if(-not $quiet){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($PlexWeb.exception.Response.StatusDescription) (StatusCode: $($PlexWeb.exception.Response.StatusCode.value__))"}
                    }
                    201{
                        if(-not $quiet){Write-Host "Failed to log in. StatusDescription: $($PlexWeb.exception.Response.StatusDescription) (StatusCode: $($PlexWeb.exception.Response.StatusCode.value__))"}
                    }
                    else{
                        if(-not $quiet){Write-Host "Unknown Response. Message: $($PlexWeb.exception.Response.StatusDescription) (Error: $($PlexWeb.exception.Response.StatusCode.value__)" -ForegroundColor Red}
                    }
                }
                if(-not $quiet){Write-Host "Error Connecting" -ForegroundColor Red}
            }else{
                if(-not $quiet){Write-Host "Available" -ForegroundColor Cyan}
                if($PlexWeb[0].MediaContainer){
                    if(-not $quiet){Write-Host "`t Version: $($PlexWeb[0].MediaContainer.version)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Friendly Name: $($PlexWeb[0].MediaContainer.friendlyName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t PlexUsername: $($PlexWeb[0].MediaContainer.myPlexUserName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Signin State: $($PlexWeb[0].MediaContainer.myPlexSigninState)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Platform: $($PlexWeb[0].MediaContainer.platform)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Platform Version: $($PlexWeb[0].MediaContainer.platformVersion)" -ForegroundColor Cyan}
                    switch ($PlexWeb[0].MediaContainer.myPlexSubscription) {
                        0 {
                            if(-not $quiet){Write-Host "`t Plex Subscription: False" -ForegroundColor Cyan}
                            $PlexPassStatus="False"
                        }
                        1 { 
                            if(-not $quiet){Write-Host "`t Plex Subscription: True" -ForegroundColor Cyan}
                            $PlexPassStatus="True"
                        }
                        Default {if(-not $quiet){Write-Host "`t Plex Subscription: Unknown" -ForegroundColor Cyan}}
                    }
                }else{
                    if($LogFile){Write-Log -Message "Data missing from server response $PlexWeb" -Path $LogFile -Level Info}
                }
                if((Get-RestMethod -Uri $PlexServerPrefsUri -PassThru -OutVariable PlexWebPrefs -ErrorAction SilentlyContinue).exception){
                    if($PlexWebPrefs.exception.Response){
                        if($LogFile){Write-Log -Message "Plex Media Server Preferences unavailable at $PlexServerUri. Message: $($PlexWebPrefs.exception.Message) (Error: $($PlexWebPrefs.exception.HResult)) StatusDescription: $($PlexWebPrefs.exception.Response.StatusDescription) (StatusCode: $($PlexWebPrefs.exception.Response.StatusCode.value__))" -Path $LogFile -Level Warn}
                        if(-not $quiet){Write-Host $PlexWebPrefs.exception.message -ForegroundColor Red}
                    }else{
                        if($LogFile){Write-Log -Message "Plex Media Server Preferences unavailable at $PlexServerUri" -Path $LogFile -Level Warn}
                    }
                    switch($PlexWebPrefs.exception.Response.StatusCode.value__){
                        401{
                            if(-not $quiet){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($PlexWebPrefs.exception.Response.StatusDescription) (StatusCode: $($PlexWebPrefs.exception.Response.StatusCode.value__))"}
                        }
                        201{
                            if(-not $quiet){Write-Host "Failed to log in. StatusDescription: $($PlexWebPrefs.exception.Response.StatusDescription) (StatusCode: $($PlexWebPrefs.exception.Response.StatusCode.value__))"}
                        }
                        else{
                            if(-not $quiet){Write-Host "Unknown Response. Message: $($PlexWebPrefs.exception.Response.StatusDescription) (Error: $($PlexWebPrefs.exception.Response.StatusCode.value__)" -ForegroundColor Red}
                        }
                    }
                }elseif($PlexWebPrefs[0].MediaContainer.Setting){
                    switch(($PlexWebPrefs[0].MediaContainer.Setting | Where-Object {$_.id -eq 'ButlerUpdateChannel'}).Value){
                        ''{if(-not $ButlerUpdateChannel){$ButlerUpdateChannel="Public"}}
                        0{if(-not $ButlerUpdateChannel){$ButlerUpdateChannel="Public"}}
                        8{if(-not $ButlerUpdateChannel){$ButlerUpdateChannel="Beta"}}
                        default {if($LogFile){Write-Log -Message "Unknown Update Channel Value [$_]" -Path $LogFile -Level Info}}
                    }
                    if($ButlerUpdateChannel){if(-not $quiet){Write-Host "`t Update Channel: $ButlerUpdateChannel" -ForegroundColor Cyan}}
                }else{
                    if($LogFile){Write-Log -Message "Data missing from server response $PlexWebPrefs" -Path $LogFile -Level Warn}
                }
            }

            #Check Plex Media Server Service (PlexService)
            if(-not $quiet){Write-Host "Checking Plex Media Server Service Wrapper (PlexService) Status..." -ForegroundColor Cyan -NoNewline}
            if(Get-ItemProperty $((Get-WmiObject win32_service -ErrorAction SilentlyContinue|?{$_.name -eq "PlexService"}).PathName).Replace("`"","") -OutVariable PmsServiceFile -ErrorAction SilentlyContinue){
                if(Get-Service PlexService -ErrorAction SilentlyContinue -OutVariable PmsService){
                    if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) found installed (Version: $($PmsServiceFile.VersionInfo.FileVersion))." -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "$($PmsService.Status)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Path: $PmsServiceFile" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Version: $($PmsServiceFile.VersionInfo.FileVersion)" -ForegroundColor Cyan}
                }else{
                    if(-not $quiet){Write-Host "Not Installed" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Not Registered as a Service." -Path $LogFile -Level Error}
                }
            }Else{
                if(-not $quiet){Write-Host "Not Installed" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Not Installed." -Path $LogFile -Level Error}
            }

            #determine currently installed bitness of PMS exe
            if((Get-FileBitness $PMSExeFile.FullName) -eq 'I386'){
                $CurrentBuild='windows-x86'
            }else{
                $CurrentBuild='windows-x86_64'
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
            if(-not $quiet){Write-Host "Checking Available Updates..." -ForegroundColor Cyan -NoNewline}
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("X-Plex-Token", $PlexToken)
            if((Get-RestMethod -Uri $UrlDownload -Headers $headers -PassThru -OutVariable release).exception){
                if($LogFile){Write-Log -Message "Exiting: Unable to determin available version, version info missing in link. $($release.exception.message) Error: ($($release.exception.Response.StatusCode.value__))" -Path $LogFile -Level Error}
                Write-Warning "Version info missing in link. Please try https://plex.tv and confirm it works there before reporting this issue."
                throw "Unable to determine available version, version info from $UrlDownload"
            }else{
                $releaseVersion,$releaseBuild = $release[0].computer.Windows.version.Split('-')
                $releaseUrl = ($release[0].computer.Windows.releases | Where-Object { $_.build -eq $Build }).url
                $releaseChecksum = ($release[0].computer.Windows.releases | Where-Object { $_.build -eq $Build }).checksum
                if($LogFile){Write-Log -Message "Update version $releaseVersion-$releaseBuild available for download." -Path $LogFile -Level Info}
            }

            #Determine if installed PMS version needs update
            $UpdateRequired=$false
            if([Version]$installedVersion -eq [Version]$releaseVersion){
                if($LogFile){Write-Log -Message "Version up-to-date. Installed version ($installedVersion) equal to available version ($releaseVersion)." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Running the latest version $installedVersion." -ForegroundColor Cyan}
                if($force){
                    $UpdateRequired=$true
                    $ArgumentList = "/repair" 
                    if($LogFile){Write-Log -Message "Proceeding with update. Force update enabled." -Path $LogFile -Level Info}
                }else{
                    if(-not $quiet){Write-Host "Latest Version $installedVersion already installed. Use -force to force installation." -ForegroundColor Cyan}
                    return
                }
            }elseif([version]$installedVersion -lt [version]$releaseVersion){
                $UpdateRequired=$true
                if($LogFile){Write-Log -Message "New version available. Installed version ($installedVersion) less than available version ($releaseVersion)." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Update Available!!!" -ForegroundColor Green}
                $ArgumentList = "/install" 
            }else{
                if($LogFile){Write-Log -Message "Installed version ($installedVersion) less than available version ($releaseVersion)." -Path $LogFile -Level Warn}
                if(-not $quiet){Write-Host "Running later than Update version" -ForegroundColor Cyan}
                if($force){
                    $UpdateRequired=$true
                    $ArgumentList = "/install"
                    if($LogFile){Write-Log -Message "Proceeding with update. Force update enabled." -Path $LogFile -Level Info}
                }else{
                    if(-not $quiet){Write-Host "Later Version $installedVersion installed. Use -force to force installation." -ForegroundColor Cyan}
                    return
                }
            }
            if(-not $quiet){Write-Host "`t PlexPass(Beta): $PlexPassStatus" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t Update Version: $releaseVersion" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t Update Build: $releaseBuild" -ForegroundColor Cyan}

            if($ReportOnly){return}

            ### Begin Update ###

            #Locate Plex AppData Folder
            if([string]::IsNullOrEmpty($LocalAppDataPath)){
                If($(Get-ItemProperty "HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server" -Name "LocalAppDataPath" -ErrorAction SilentlyContinue| Select-Object -ExpandProperty LocalAppDataPath -OutVariable LocalAppDataPath )){
                    if($LogFile){Write-Log -Message "Checking custom local application data path ($LocalAppDataPath) for Updates" -Path $LogFile -Level Info}                
                }Else{
                    if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -eq 'NT AUTHORITY\SYSTEM'){
                        $LocalAppDataPath = "$env:SystemRoot\system32\config\systemprofile\AppData\Loca\Plex Media Server"
                    }else{
                        $LocalAppDataPath = "$env:SystemDrive\Users\$UserName\AppData\Loca\Plex Media Server"
                    }
                    if($LogFile){Write-Log -Message "LocalAppDataPath: $LocalAppDataPath" -Path $LogFile -Level Info}
                }
            }
            #Check if Update already downloaded and has valid checksum
            if($LogFile){Write-Log -Message "Checking default local application data path ($LocalAppDataPath) for Updates" -Path $LogFile -Level Info}                
            if((Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe") -and `
            ((Get-FileHash "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -Algorithm SHA1).Hash -ieq $releaseChecksum)){
                if($LogFile){Write-Log -Message "Latest update file found with matching checksum ($LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe)" -Path $LogFile -Level Info}
            }else{
                if(-not $quiet){Write-Host "Downloading Update..." -ForegroundColor Cyan -NoNewline}
                #create destination directory if not present
                if(-Not (Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild")){New-Item "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild" -ItemType directory | Out-Null}
                if(Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe"){
                    if($LogFile){Write-Log -Message "Latest update file ($LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe) found but failed checksum. Re-downloading." -Path $LogFile -Level Info}
                }else{
                    if($LogFile){Write-Log -Message "Downloading Plex Media Server for Windows ($releaseVersion-$releaseBuild)" -Path $LogFile -Level Info}
                }
                if([int](Invoke-WebRequest -Headers $headers -Uri $releaseUrl -UseBasicParsing -OutFile "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -PassThru -OutVariable response).StatusCode -eq 200){
                    if($LogFile){Write-Log -Message "Download of $LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe completed. StatusCode: $([int]$response.StatusCode)" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Completed" -ForegroundColor Cyan}
                    Write-Verbose "WebRequest result $([int]$response.StatusCode)"
                }else{
                    if($LogFile){Write-Log -Message "Exiting: Error downloading $releaseUrl. StatusDescription: $response.StatusDescription StatusCode: $response.StatusCode" -Path $LogFile -Level Error}
                    if(-not $quiet){Write-Host "ERROR OCCURRED!!!" -ForegroundColor Red}
                    Write-Error "Error occured downloading Update. Status Description $([string]$response.StatusDescription) Statuscode: $([int]$response.StatusCode)"
                    throw "Error downloading Update"
                }
            }

            #Check if Server in use
            if(-not $quiet){Write-Host "Checking Active Plex Sessions..." -ForegroundColor Cyan -NoNewline}
            #if((Get-Process -Name 'PlexTranscoder','PlexNewTranscoder' -ErrorAction SilentlyContinue){
            if((Get-RestMethod -Uri $PlexServerSessionUri -ErrorAction SilentlyContinue -PassThru -OutVariable PmsSessions).exception){
                if(-not $quiet){Write-Host $PlexServerSessions.exception.message -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Exception determining active sessions. $PmsSessions[0].exception.message" -Path $LogFile -Level Warn}
            }else{
                if($PmsSessions[0].MediaContainer.size -eq 0){
                    if($LogFile){Write-Log -Message "No active sessions found." -Path $LogFile -Level Info}
                }else{
                    if($LogFile){Write-Log -Message "Active Sessions found: $([int]$PmsSessions[0].MediaContainer.size)" -Path $LogFile -Level Info}
                }
            }
            if((Get-RestMethod -Uri $PlexServerLiveTvSessionUri -ErrorAction SilentlyContinue -PassThru -OutVariable LiveTvSessions).exception){
                if(-not $quiet){Write-Host $LiveTvSessions.exception.message -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Exception determining Live TV/DVR sessions. $LiveTvSessions.exception.message" -Path $LogFile -Level Warn}
            }else{
                if([int]$LiveTvSessions[0].MediaContainer.Video.index -eq 0){
                    if($LogFile){Write-Log -Message "No active Live TV/DVR Sessions found" -Path $LogFile -Level Info}
                }else{
                    if($LogFile){Write-Log -Message "Active Live TV/DVR Sessions found: $([int]$LiveTvSessions[0].MediaContainer.Video.index)" -Path $LogFile -Level Info}
                }
            }
            if(([int]$PmsSessions[0].MediaContainer.size -eq 0) -and ([int]$LiveTvSessions[0].MediaContainer.Video.index -eq 0)){
                if(-not $quiet){Write-Host "No Sessions" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Current Sessons: $([int]$PmsSessions[0].MediaContainer.size)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Current Live TV/DVR Sessons: $([int]$LiveTvSessions[0].MediaContainer.Video.index)" -ForegroundColor Cyan}
            }else{
                if($LogFile){Write-Log -Message "Server $($PlexWeb[0].MediaContainer.friendlyName) is currently being used by one or more users, skipping installation. Please run again later" -Path $LogFile -Level Warn}
                if(-not $quiet){Write-Host "`t Current Sessions: $([int]$PmsSessions[0].MediaContainer.size)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Current Live TV/DVR Sessions: $([int]$LiveTvSessions[0].MediaContainer.Video.index)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "Server $($PlexWeb[0].MediaContainer.friendlyName) is currently being used by one or more users, skipping installation. Please run again later" -ForegroundColor Cyan}
                return
            }

            #Stop Plex Media Server Service Wrapper (PlexService)
            if($PmsService){
                if($PmsService.status -ne 'Stopped'){
                    if($LogFile){Write-Log -Message "Found Plex Media Server Service Wrapper (PlexService) Running." -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Stopping Plex Media Server Service (PlexService)..." -ForegroundColor Cyan -NoNewline}

                    if($PmsService | Stop-Service -ErrorAction SilentlyContinue -PassThru){
                        if($LogFile){Write-Log -Message "Sent Plex Media Server Service Wrapper (PlexService) Stop-Service." -Path $LogFile -Level Info}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Plex Media Server Service Wrapper (PlexService) Stop-Process." -Path $LogFile -Level Error}
                    }
                    Start-Sleep -Seconds 1
                    While ($PmsService.Status -eq "Running"){
                        if($LogFile){Write-Log -Message "Service not responding to Stop-Service, Sending Plex Media Server Service Wrapper (PlexService) Stop-Process -Force." -Path $LogFile -Level Warn}
                        if(Stop-Process -Name PlexService -ErrorAction SilentlyContinue -Force -PassThru){
                            if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Stop-Process -Force Successful." -Path $LogFile -Level Info}
                        }else{
                            if($LogFile){Write-Log -Message "Service hung. Retrying Plex Media Server Service Wrapper (PlexService) Stop-Process -Force." -Path $LogFile -Level Info}
                        }
                        Start-Sleep -Seconds 1
                    }
                    if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Stopped." -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Stopped" -ForegroundColor Cyan}
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server Service (PlexService) is Stopped." -Path $LogFile -Level Info}
                }
            }

            #Stop all Plex Media Server related processes
            if(Get-Process -Name 'Plex Media Server','Plex Media Scanner','Plex Tuner Service','Plex Relay','Plex Update Service','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue){
                if($LogFile){Write-Log -Message "Plex Media Server processes found running." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Stopping Plex Media Server Processes..." -ForegroundColor Cyan -NoNewline}
                while(Get-Process -Name 'Plex Media Server','Plex Media Scanner','Plex Relay','Plex Update Service','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue -OutVariable PMSProcesses){
                    if($LogFile){Write-Log -Message "Sent Plex Media Server processes Stop-Process. ($($PmsProcesses.ProcessName))" -Path $LogFile -Level Info}
                    $PMSProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                    if(-not $quiet){Write-Host "." -ForegroundColor Cyan -NoNewline}
                }
                if($LogFile){Write-Log -Message "Plex Media Server processes stopped." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Stopped" -ForegroundColor Cyan}
            }else{
                if($LogFile){Write-Log -Message "No Plex Media Server processes currently running." -Path $LogFile -Level Info}
            }

            #Start Silent install of PMS

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
                    if($passive){
                        $ArgumentList = $ArgumentList + " /passive /norestart" 
                    }elseif($quiet){
                        $ArgumentList = $ArgumentList + " /quite /norestart"
                    }else{
                        $ArgumentList = $ArgumentList + " /norestart"
                    }
                }
                windows-x86_64 {
                    if($passive){
                        $ArgumentList = "/NORESTART /RESTARTEXITCODE=3010 /SILENT /SUPPRESSMSGBOXES"
                    }elseif($quiet){
                        $ArgumentList = "/NORESTART /RESTARTEXITCODE=3010 /SUPPRESSMSGBOXES /VERYSILENT "
                    }else{
                        $ArgumentList = "/NORESTART /RESTARTEXITCODE=3010"
                    }
                }
                Default {if($LogFile){Write-Log -Message "Unnkown Build Value" -Path $LogFile -Level Info}}
            }

            if($CurrentBuild -eq 'windows-x86_64' -and $build -eq 'windows-x86'){
                if(-not $quiet){Write-Host "Uninstalling Plex Media Server (x64)..." -ForegroundColor Cyan -NoNewline}
                if($LogFile){Write-Log -Message "Uninstalling Plex Media Server (x64) before installing 'windows-x86' build" -Path $LogFile -Level Info}

                foreach($UninstallString in $(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName -like 'Plex Media Server*'}).UninstallString){
                    if($LogFile){Write-Log -Message "Uninstalling Plex Media Server (x64) update Process: $UninstallString $ArgumentList" -Path $LogFile -Level Info}
                    $Process = Start-Process -FilePath $UninstallString -ArgumentList $ArgumentList -PassThru
                    While(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
                        Start-Sleep -Seconds 4
                        if(-not $quiet){Write-Host "." -ForegroundColor Cyan -NoNewline}
                    }    
                }

                if($Process.ExitCode -eq 0){
                    if(-not $quiet){Write-Host "Success" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Restart Required: False" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Successfully uninstalled with ExitCode $($Process.ExitCode)." -Path $LogFile -Level Info}
                }elseif($Process.ExitCode -eq 3010 ){
                    if(-not $quiet){Write-Host "Success" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Restart required: True" -ForegroundColor Cyan}
                    if($LogFile){Write-Log -Message "Successfully uninstalled with ExitCode $($Process.ExitCode). Restart Required." -Path $LogFile -Level Warn}
                }elseif($Process.ExitCode -eq 1602 ){
                    if(-not $quiet){Write-Host "Cancelled" -ForegroundColor red}
                    if(-not $quiet){Write-Host "`t Uninstall was cancelled by user. ExitCode: $($Process.ExitCode)" -ForegroundColor Red}
                    if(-not $quiet){Write-Host "`t Plex Media Server was not uninstalled." -ForegroundColor Red}
                    if($LogFile){Write-Log -Message "Uninstall was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Warn}
                }elseif($Process.ExitCode -eq 2 ){
                    if(-not $quiet){Write-Host "Cancelled" -ForegroundColor red}
                    if(-not $quiet){Write-Host "`t Uninstall was cancelled by user. ExitCode: $($Process.ExitCode)" -ForegroundColor Red}
                    if(-not $quiet){Write-Host "`t Plex Media Server was not uninstalled." -ForegroundColor Red}
                    if($LogFile){Write-Log -Message "Uninstall was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Warn}
                }else{
                    if(-not $quiet){Write-Host "ERROR!!!" -ForegroundColor Red}
                    if(-not $quiet){Write-Host "`t An Error occurred uninstalling Plex Media Server. Exit Code: $($Process.ExitCode)" -ForegroundColor Red}
                    if(-not $quiet){Write-Host "`t Plex Media Server was not uninstalled." -ForegroundColor Red}
                    if($LogFile){Write-Log -Message "Failed to uninstall update. Command '$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList' returned error code $($Process.ExitCode))." -Path $LogFile -Level Error}
                }
            }

            if(-not $quiet){Write-Host "Updating Plex Media Server..." -ForegroundColor Cyan -NoNewline}
            if($LogFile){Write-Log -Message "Starting Plex Media Server update Process: $LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList" -Path $LogFile -Level Info}
            $Process = Start-Process -FilePath "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -ArgumentList $ArgumentList -PassThru
            While(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
                Start-Sleep -Seconds 4
                if(-not $quiet){Write-Host "." -ForegroundColor Cyan -NoNewline}
            }

            #Find Plex Media Server Install Key if process not running
            $PMSSettingsKeys=Get-ItemProperty 'HKU:\*\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\Plex, Inc.\Plex Media Server','HKLM:\SOFTWARE\WOW6432Node\Plex, Inc.\Plex Media Server' -ErrorAction SilentlyContinue
            if($PMSSettingsKeys){
                if($LogFile){Write-Log -Message "Plex Media Server Settings found in Registry [Count: $($PMSSettingsKeys.Count)]" -Path $LogFile -Level Info}
                foreach($Key in $PmsSettingsKeys){
                    if(Get-ItemProperty "$($Key.InstallFolder)\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Plex Media Server installation found in $($Key.InstallFolder)" -Path $LogFile -Level Info}
                        $InstallFolder=$Key.InstallFolder
                        if($LogFile){Write-Log -Message "InstallFolder: $InstallFolder" -Path $LogFile -Level Info}
                        break
                    }else{
                        if($LogFile){Write-Log -Message "Plex Settings not found in key $($Key.PSPath.Replace('Microsoft.PowerShell.Core\Registry::',''))" -Path $LogFile -Level Warn}
                    }
                }
            }else{
                if($LogFile){Write-Log -Message "Plex Media Server installation not found in Registry" -Path $LogFile -Level Warn}
            }
            
            if($Process.ExitCode -eq 0){
                if(-not $quiet){Write-Host "Success" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Version Installed: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.FileVersion)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Restart Required: False" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Update successfully installed with ExitCode $($Process.ExitCode)." -Path $LogFile -Level Info}
            }elseif($Process.ExitCode -eq 3010 ){
                if(-not $quiet){Write-Host "Success" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Version Installed: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.FileVersion)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Restart required: True" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Update successfully installed with ExitCode $($Process.ExitCode). Restart Required." -Path $LogFile -Level Warn}
            }elseif($Process.ExitCode -eq 2 ){
                if(-not $quiet){Write-Host "Cancelled" -ForegroundColor red}
                if(-not $quiet){Write-Host "`t Update was cancelled by user. ExitCode: $($Process.ExitCode)" -ForegroundColor Red}
                if(-not $quiet){Write-Host "`t Plex Media Server was not updated." -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Update was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Warn}
            }elseif($Process.ExitCode -eq 1602 ){
                if(-not $quiet){Write-Host "Cancelled" -ForegroundColor red}
                if(-not $quiet){Write-Host "`t Update was cancelled by user. ExitCode: $($Process.ExitCode)" -ForegroundColor Red}
                if(-not $quiet){Write-Host "`t Plex Media Server was not updated." -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Update was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Warn}
            }else{
                if(-not $quiet){Write-Host "ERROR!!!" -ForegroundColor Red}
                if(-not $quiet){Write-Host "`t An Error occurred installing update. Exit Code: $($Process.ExitCode)" -ForegroundColor Red}
                if(-not $quiet){Write-Host "`t Plex Media Server was not update." -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Failed to install update. Command '$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList' returned error code $($Process.ExitCode))." -Path $LogFile -Level Error}
            }

            #cleanup Run keys after install
            if($(Get-ItemProperty "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Plex Media Server" -ErrorAction SilentlyContinue)){
                if($LogFile){Write-Log -Message "Removing HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Run\Plex Media Server value." -Path $LogFile -Level Info}
                Remove-ItemProperty "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Run\" -Name "Plex Media Server" -Force
                if(-not $quiet){Write-Host "`t Startup/Run Keys: Removed" -ForegroundColor Cyan}
            }
            If ($(Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Plex Media Server" -ErrorAction SilentlyContinue)) {
                if($LogFile){Write-Log -Message "Removing HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\Plex Media Server value." -Path $LogFile -Level Info}
                Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Plex Media Server" -Force
                if(-not $quiet){Write-Host "`t Startup/Run Keys: Removed" -ForegroundColor Cyan}
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
                                if($LogFile){Write-Log -Message "Error removing folder $("$LocalAppDataPath\Plex Media Server\Updates\" + ($PmsUpdate.FullName).Replace("$LocalAppDataPath\Plex Media Server\Updates\",'').split("\")[0]) Error: $($return.GetType().Name)" -Path $LogFile -Level Warn}
                                $return=$null
                            }else{
                                if($LogFile){Write-Log -Message "Removed folder $("$LocalAppDataPath\Plex Media Server\Updates\" + ($PmsUpdate.FullName).Replace("$LocalAppDataPath\Plex Media Server\Updates\",'').split("\")[0])" -Path $LogFile -Level Info}
                            }
                        }
                        Write-Host "`t Updates Removed: $($PmsUpdates.Count-$UpdateCleanup)" -ForegroundColor Cyan
                    }else{
                        if($LogFile){Write-Log -Message "Update Count does not meet Cleanup threshold ($UpdateCleanup)" -Path $LogFile -Level Info}
                    }
                }else{
                    Write-Warning "Unable to determine Updates Count for cleanup"
                }
            }
            
            #Start Plex Media Server Service (PlexService)
            if($PmsService.status -eq 'Stopped'){
                if(-not $quiet){Write-Host "Starting Plex Media Server Service (PlexService)..." -ForegroundColor Cyan -NoNewline}
                While ($PmsService.Status -eq "Stopped"){
                    $PmsService | Start-Service -WarningAction SilentlyContinue
                    if($LogFile){Write-Log -Message "Sent Plex Media Server Service Wrapper (PlexService) Start-Service." -Path $LogFile -Level Info}
                }
                if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Started." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Started" -ForegroundColor Cyan}
            }else{
                if($LogFile){Write-Log -Message "Plex Media Server Service (PlexService) already Started." -Path $LogFile -Level Info}
            }

            if(-not $quiet){Write-Host "Verifying Plex Media Server Process..." -ForegroundColor Cyan -NoNewline}
            #Verify Plex Media Server is Running
            if(Get-Process "Plex Media Server" -IncludeUserName -OutVariable PMSProcess -ErrorAction SilentlyContinue | Select-Object Path | Get-ItemProperty -OutVariable PMSExeFile ){
                if($LogFile){Write-Log -Message "Plex Media Server process running $($PMSProcess.Path) as User $($PMSProcess.UserName)" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Running" -ForegroundColor Cyan}
                $newInstalledVersion,$newInstalledBuild = $PMSExeFile.VersionInfo.ProductVersion.Split('-')
                if(-not $quiet){Write-Host "`t Version: $newInstalledVersion" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Build: $newInstalledBuild" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Path: $PMSExeFile" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t User Context: $($PMSProcess.UserName)" -ForegroundColor Cyan}
            }else{ # if process isn't running
                if($LogFile){Write-Log -Message "Plex Media Server Process not running" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Not Running" -ForegroundColor Red}
                Write-Verbose "Plex Media Server Process not running"
            }

            #Verify Plex Web available
            if(-not $quiet){Write-Host "Checking Plex Web Status..." -ForegroundColor Cyan -NoNewline}
            [int]$loopcount=0
            do{
                if($loopcount -gt 0){Start-Sleep -s 3}
                if(-not $quiet){Write-Host "." -ForegroundColor Cyan -NoNewline}
                $loopcount++
            }until((Get-RestMethod -Uri $PlexServerUri -PassThru -OutVariable PlexWeb -ErrorAction SilentlyContinue).MediaContainer -or $loopcount -gt 10)
            if($PlexWeb.exception){
                if($PlexWeb.exception.Response){
                    if($LogFile){Write-Log -Message "Plex Web unavailable at $PlexServerUri. Message: $($PlexWeb.exception.Message) (Error: $($PlexWeb.exception.HResult)) StatusDescription: $($PlexWeb.exception.Response.StatusDescription) (StatusCode: $($PlexWeb.exception.Response.StatusCode.value__))" -Path $LogFile -Level Warn}
                    if(-not $quiet){Write-Host $PlexWeb.exception.message -ForegroundColor Red}
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerUri" -Path $LogFile -Level Info}
                }
                switch($PlexWeb.exception.Response.StatusCode.value__){
                    401{
                        if(-not $quiet){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($PlexWeb.exception.Response.StatusDescription) (StatusCode: $($PlexWeb.exception.Response.StatusCode.value__))"}
                    }
                    201{
                        if(-not $quiet){Write-Host "Failed to log in. StatusDescription: $($PlexWeb.exception.Response.StatusDescription) (StatusCode: $($PlexWeb.exception.Response.StatusCode.value__))"}
                    }
                    else{
                        if(-not $quiet){Write-Host "Unknown Response. Message: $($PlexWeb.exception.Response.StatusDescription) (Error: $($PlexWeb.exception.Response.StatusCode.value__)" -ForegroundColor Red}
                    }
                }
                if(-not $quiet){Write-Host "Error Connecting" -ForegroundColor Red}
            }elseif($PlexWeb[0].MediaContainer){
                if(-not $quiet){Write-Host "Available" -ForegroundColor Cyan}
                if($PlexWeb[0].MediaContainer){
                    if(-not $quiet){Write-Host "`t Version: $($PlexWeb[0].MediaContainer.version)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Friendly Name: $($PlexWeb[0].MediaContainer.friendlyName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t PlexUsername: $($PlexWeb[0].MediaContainer.myPlexUserName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Signin State: $($PlexWeb[0].MediaContainer.myPlexSigninState)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Platform: $($PlexWeb[0].MediaContainer.platform)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Platform Version: $($PlexWeb[0].MediaContainer.platformVersion)" -ForegroundColor Cyan}
                    if($PlexWeb[0].MediaContainer.myPlexSubscription -eq 1){
                        if(-not $quiet){Write-Host "`t Plex Subscription: True" -ForegroundColor Cyan}
                        $PlexPassStatus="True"
                    }elseif($PlexWeb[0].MediaContainer.myPlexSubscription -eq 0){
                        if(-not $quiet){Write-Host "`t Plex Subscription: False" -ForegroundColor Cyan}
                        $PlexPassStatus="False"
                    }else{
                        if(-not $quiet){Write-Host "`t Plex Subscription: Unknown" -ForegroundColor Cyan}
                    }
                }else{
                    if($LogFile){Write-Log -Message "Data missing from server response $PlexServer" -Path $LogFile -Level Warn}
                }

            }else{
                if($LogFile){Write-Log -Message "Plex Web is not responding from $PlexServerUri" -Path $LogFile -Level Warn}
            }

            if($SlackNotify){
                if(-not $quiet){Write-Host "Sending Slack Notification to $SlackChannel..." -ForegroundColor Cyan -NoNewline}
                if(Post-ToSlack -Channel $SlackChannel -token $SlackToken -BotName "Update-PlexMediaServer Module" -Message "Plex Media Server $($PlexWeb[0].MediaContainer.friendlyName) was updated on computer $env:COMPUTERNAME.`r`n`r`nNew Version: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.ProductVersion)`r`nOld Version: $installedVersion-$installedBuild" -ErrorAction SilentlyContinue -OutVariable slackResponse){
                    if($LogFile){Write-Log -Message "Slack Notification sent successsfully." -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Sent" -ForegroundColor Cyan}
                }else{
                    if($LogFile){Write-Log -Message "Error sending Slack Notification. Error $($slackResponse.error)" -Path $LogFile -Level Error}
                    if(-not $quiet){Write-Host "Error Sending" -ForegroundColor Red}
                }
            }

            if($EmailNotify){
                if($LogFile){Write-Log -Message "Preparing Notification Email: $msg" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Sending Email Notification..." -ForegroundColor Cyan -NoNewline}
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
                        if(-not $quiet){Write-Host "Sent" -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Email Notification" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Error Sending" -ForegroundColor Red}
                    }
                }else{
                    if($LogFile){Write-Log -Message "Sending Email Notification to $SmtpTo." -Path $LogFile -Level Info}
                    if(Send-ToEmail -SmtpFrom $SmtpFrom -SmtpTo $SmtpTo -Subject "Plex Media Server updated on $env:COMPUTERNAME" `
                        -Body $msg -SmtpUser $SmtpUser -SmtpPassword $SmtpPassword -SmtpServer $SmtpServer -SmtpPort $SmtpPort `
                        -EnableSSL $EnableSSL -IsBodyHtml $EmailIsBodyHtml -PassThru -ErrorAction SilentlyContinue){
                            if($LogFile){Write-Log -Message "Email Notification sent successsfully." -Path $LogFile -Level Info}
                            if(-not $quiet){Write-Host "Sent" -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Email Notification" -Path $LogFile -Level Error}
                        if(-not $quiet){Write-Host "Error Sending" -ForegroundColor Red}
                    }
                }
            }
        }Catch{
            if($LogFile){Write-Log -Message "Error occurred: $($_.Exception.Message)" -Path $LogFile -Level Error}
            if(-not $quiet){Write-Host "Error occurred: $($_.Exception.Message)" -ForegroundColor Red}
            if ($Host.Name -eq 'Windows PowerShell ISE Host') {
                throw $_
            } else {
                return $_
            }
        }
    }
    end{
        if($LogFile){Write-Log -Message "Update-PlexMediaServer Completed" -Path $LogFile -Level Info}
    }
}

function Get-PlexToken{
    [CmdletBinding()]
    param(
    #
    [Parameter(
        Position=0,
        ValueFromPipelineByPropertyName=$true)]

        [string]$PlexLogin,

    #
    [Parameter(
        Position=1,
        ValueFromPipelineByPropertyName=$true)]

        [string]$PlexPassword,

    #
    [parameter()]

        [Switch]$Plex2FA,

    #
    [parameter()]

        [Switch]$PassThru,

    #
    [parameter(
        ParameterSetName="PSCredential",
        Position=0)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        [ValidateScript({
            if($_ -is [System.Management.Automation.PSCredential]){
                $True
            }else{
                $Script:Credential=Get-Credential -Credential $_ -Message "Enter your Plex.tv credentials:"
                $True
            }
        })]

        [object]$Credential = [System.Management.Automation.PSCredential]::Empty 
    )
    switch($PSCmdlet.ParameterSetName){
        "PSCredential"{Write-Debug "ParameterSetName: $_"}
        default{Write-Debug "ParameterSetName: $_"}
    }

    [hashtable]$return=@{}

    if($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
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
            'X-Plex-Product'           = 'Get-PlexToken';
            'X-Plex-Version'           = "2.0.0";
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
