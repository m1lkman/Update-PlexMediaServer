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
        if($_ -match "[0-9a-z]{20}"){
            $true
        }else{
            throw "Please provide a Plex Authentication Token matching the format abcde12345abcde12345 (20 alpha-numeric characters)."
        }
        })]
    [ValidateNotNull()]
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
        ParameterSetName="EmailNotify")]

        [string]
        $LogFile="$PSScriptRoot\Update-PlexMediaServer.log",

    # Force update 
    [Parameter(
        HelpMessage="Forces Update installation regardless of installed version")]

        [switch]
        $Force,

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
        ParameterSetName="EmailNotify")]
            
        [switch]
        $Quiet,

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
        $EnableSSL
    )

    begin{
        switch($PSCmdlet.ParameterSetName){
            "ServerAuth"{Write-Debug "ParameterSetName: $_"}
            "TokenAuth"{Write-Debug "ParameterSetName: $_"}
            "CredAuth"{Write-Debug "ParameterSetName: $_"}
            "TextAuth"{Write-Debug "ParameterSetName: $_"}
            default{Write-Debug "ParameterSetName: $_"}
            
        }

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
                        if($LogFile){Write-Log -Message "Plex authentication token was not validated. Please verify or use Get-PlexToken to retrieve again. Server Response: $($response.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Token Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Please verify specified Plex Autentication Token or use Get-PlexToken to retrieve one." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Unable to verify Plex authentication token. Unable to reach Plex.tv servers or they are unresponsive. Message: $($response.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are unresponsive. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    return
                }else{
                    if($LogFile){Write-Log -Message "Plex Authentication Token $PlexToken specified at command-line Validated" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Token Validated" -ForegroundColor Cyan}
                }
            }elseif($PlexLogin -and $PlexPassword){#Plex.tv credentials specified via command-line
                if($LogFile){Write-Log -Message "Credential Authentication enabled via command-line" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Verifying Plex.tv Login..." -ForegroundColor Cyan -NoNewline}
                if((Get-PlexToken -PlexLogin $PlexLogin -PlexPassword $PlexPassword -OutVariable PlexUser -PassThru -ErrorAction SilentlyContinue).exception){
                    if($PlexUser.exception.Response){
                        if($LogFile){Write-Log -Message "Unable to retrieve Plex authentication Token. Username and/or password are incorrect. Server Response: $($PlexUser.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Plex Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Username and/or password are incorrect. Unable to retrieve Plex Authentication Token." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Cannot verify Plex login credentials. Unable to reach Plex.tv servers or they are not responding. Message: $($PlexUser.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are not responding. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    trap {Unable to verify Plex Login Token}
                    return
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
                        if($LogFile){Write-Log -Message "Unable to retrieve Plex authentication Token. Username and/or password are incorrect. Server Response: $($PlexUser.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Plex Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Username and/or password are incorrect. Unable to retrieve Plex Authentication Token." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Cannot verify Plex login credentials. Unable to reach Plex.tv servers or they are not responding. Message: $($PlexUser.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are not responding. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    trap {Unable to verify Plex Login Token}
                    return
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
                                if($LogFile){Write-Log -Message "Unable to retrieve Plex authentication Token. Username and/or password are incorrect. Server Response: $($PlexUser.exception.message)" -Path $LogFile -Level Info}
                                if(-not $quiet){Write-Host "Plex Authentication Failed" -ForegroundColor Red}
                                if(-not $quiet){Write-Host "Username and/or password are incorrect. Unable to retrieve Plex Authentication Token." -ForegroundColor Cyan}
                            }else{
                                if($LogFile){Write-Log -Message "Cannot verify Plex login credentials. Unable to reach Plex.tv servers or they are not responding. Message: $($PlexUser.exception.message)" -Path $LogFile -Level Info}
                                if(-not $quiet){Write-Host "Unable to validate Token" -ForegroundColor Red}
                                if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are not responding. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                            }
                            return
                        }else{
                            $PlexToken=$PlexUser.user.authToken
                            if($LogFile){Write-Log -Message "Plex authentication Token $($PlexUser.user.authToken) found for Plex user $($PlexUser.user.username)" -Path $LogFile -Level Info}
                            if(-not $quiet){Write-Host "Credentials Validated" -ForegroundColor Cyan}
                        }
                    }
                }else{#non-interactive
                    if($PlexLogin -or $PlexPassword){
                        if($LogFile){Write-Log -Message "Unable to determine Plex Authentication Token missing Plex.tv username or password from command line. Unable to prompt for information when running in non-interactive Quiet mode." -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Unable to determine Plex Authentication Token without additional imput in passive/quiet mode." -ForegroundColor Cyan}
                        if(-not $quiet){Write-Host "     1. Configure PlexToken variable in script. Use Get-PlexToken." -ForegroundColor Cyan}
                        if(-not $quiet){Write-Host "     2. Specify your token in the command line, i.e. -plextoken <Token>" -ForegroundColor Cyan}
                        if(-not $quiet){Write-Host "     3. Specify your plex.tv username/ID and password in the command line, i.e. -PlexLogin <email/id> -PlexPassword <password>" -ForegroundColor Cyan}
                        trap {"Unable to determin Plex Authentication Token."}
                        return
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
            if($EmailNotify){
                if($LogFile){Write-Log -Message "Email Notification enabled via command-line (-EmailNotify)" -Path $LogFile -Level Info}
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

            #Find Plex Media Server Install Key if process not running
            $PMSInstallKeys=("HKLM:\Software\Wow6432Node\Plex, Inc.\Plex Media Server","HKLM:\Software\Plex, Inc.\Plex Media Server")
            foreach($Key in $PMSInstallKeys){
                if(Test-Path $Key -ErrorAction SilentlyContinue){
                    if(Get-ItemProperty "$(Get-ItemProperty $Key -Name "InstallFolder" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InstallFolder -OutVariable InstallFolder)\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                    if($LogFile){Write-Log -Message "Plex Media Server installation found in $Key" -Path $LogFile -Level Info}
                        Break
                    }else{
                        if($LogFile){Write-Log -Message "Plex Media Server installation not found in $Key" -Path $LogFile -Level Info}
                    }
                }
            }

            #Locate Plex Media Server.exe and Get Current Version and determin username
            if(Get-Process "Plex Media Server" -IncludeUserName -OutVariable PMSProcess -ErrorAction SilentlyContinue | Select-Object Path | Get-ItemProperty -OutVariable PMSExeFile -ErrorAction SilentlyContinue ){
                if($LogFile){Write-Log -Message "Plex Media Server process running $($PMSProcess.Path) in user context $($PMSProcess.UserName)" -Path $LogFile -Level Info}
                If (-not $UserName){$UserName=$PMSProcess.UserName}
            }else{ # if process isn't running
                if($LogFile){Write-Log -Message "Plex Media Server process not running" -Path $LogFile -Level Info}
                if(-not $UserName){$UserName=$env:USERNAME} 
            }

            #Get User SID
            try{
                $UserSID = (New-Object System.Security.Principal.NTAccount("$env:DomainName", "$UserName")).Translate([System.Security.Principal.SecurityIdentifier]).Value
            }catch{
                if(-not $quiet){Write-Host "Unable to translate User SID, $env:DomainName\$UserName may not exist." -ForegroundColor Red}
                Return
            }
            if($LogFile){Write-Log -Message "$UserName SID: $UserSID" -Path $LogFile -Level Info}

            #Find Plex Media Server Setttings Key
            $PMSSettingsKeys=("HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server","HKCU:\Software\Plex, Inc.\Plex Media Server","HKU:\S-1-5-18\Software\Plex, Inc.\Plex Media Server")
            foreach($Key in $PMSSettingsKeys){
                if(Test-Path $Key -ErrorAction SilentlyContinue){
                    if(Get-ItemProperty $Key -OutVariable PmsSettings -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Plex Settings Key Found $Key" -Path $LogFile -Level Info}
                        switch($PmsSettings.ButlerUpdateChannel){
                            0{$ButlerUpdateChannel="Public"}
                            8{$ButlerUpdateChannel="Beta"}
                        }
                        if($LogFile){Write-Log -Message "ButlerUpdateChannel: $ButlerUpdateChannel" -Path $LogFile -Level Info}
                        $LocalAppDataPath=$PmsSettings.LocalAppDataPath
                        if($LogFile){Write-Log -Message "LocalAppDataPath: $LocalAppDataPath" -Path $LogFile -Level Info}
                        $PlexOnlineToken=$PmsSettings.PlexOnlineToken
                        if($LogFile){Write-Log -Message "PlexOnlineToken: $PlexOnlineToken" -Path $LogFile -Level Info}
                        Break #break from foreach
                    }else{
                        if($LogFile){Write-Log -Message "Key not found $Key" -Path $LogFile -Level Info}
                    }
                }
            }

            if($UseServerToken){
                if((Get-RestMethod -Uri "https://plex.tv/api/resources?X-Plex-Token=$PlexOnlineToken" -OutVariable response -PassThru -ErrorAction SilentlyContinue).exception){
                    if($response.exception.Response){
                        if($LogFile){Write-Log -Message "Plex Server Online Authentication Token was not validated. Please verify or use Get-PlexToken to retrieve again. Server Response: $($response.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Server Online Token Authentication Failed" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Please verify specified Plex Server Online Autentication Token or use Get-PlexToken to retrieve one." -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Unable to verify Plex Server Online Authentication Token. Unable to reach Plex.tv servers or they are unresponsive. Message: $($response.exception.message)" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Unable to validate Server Online Token" -ForegroundColor Red}
                        if(-not $quiet){Write-Host "Cannot communicate with Plex.tv servers or they are unresponsive. Please check network connectivity and https://status.plex.tv/." -ForegroundColor Cyan}
                    }
                    return
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
            if($PmsProcess){
                if(-not $quiet){Write-Host "Running" -ForegroundColor Cyan}
                
            }else{
                if(-not $quiet){Write-Host "Not Running" -ForegroundColor Cyan}
            }

            #Sanity Check
            if(!($PMSProcess -and $PMSExeFile)){
                if($LogFile){Write-Log -Message "Exiting: Plex Media Server does not appear to be running or installed." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Exiting: Plex Media Server does not appear to be installed." -ForegroundColor Red}
                return
            }

            if(-not $quiet){Write-Host "`t Version: $installedVersion" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t Build: $installedBuild" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t Path: $PMSExeFile" -ForegroundColor Cyan}
            if(-not $quiet){Write-Host "`t User Context: $UserName" -ForegroundColor Cyan}

            ### Validate Plex Web Availability ###
            if(-not $quiet){Write-Host "Checking Plex Web Status..." -ForegroundColor Cyan -NoNewline}
            if(Get-RestMethod -Uri http://ipinfo.io/json -ErrorAction SilentlyContinue -PassThru -OutVariable HostNameResponse | Select-Object -ExpandProperty hostname -ErrorAction SilentlyContinue -OutVariable hostname){
                if($LogFile){Write-Log -Message "HostName is $hostname" -Path $LogFile -Level Info}
            }else{
                if($LogFile){Write-Log -Message "Unable to determin Hostname. $($HostNameResponse.exception.message) Error: ($($HostNameResponse.exception.HResult))" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Unable to determine HostName" -ForegroundColor Red}
                return
            }

            if($Plextoken){
                $PlexServerUri="http://$($hostname):$PlexServerPort/?X-Plex-Token=$($PlexToken)"                    
                $PlexServerSessionUri="http://$($hostname):$PlexServerPort/status/sessions/?X-Plex-Token=$($PlexToken)"                    
            }else{
                $PlexServerUri="http://$($hostname):$PlexServerPort/"
                $PlexServerSessionUri="http://$($hostname):$PlexServerPort/status/sessions"                    
            }

            #check Plex Server Availability
            if((Get-RestMethod -Uri $PlexServerUri -PassThru -OutVariable PlexServer -ErrorAction SilentlyContinue).exception){
                if($PlexServer.exception.Response){
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerUri. Message: $($PlexServer.exception.Message) (Error: $($PlexServer.exception.HResult)) StatusDescription: $($PlexServer.exception.Response.StatusDescription) (StatusCode: $($return.exception.Response.StatusCode.value__))" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host $PlexServer.exception.message -ForegroundColor Red}
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerUri" -Path $LogFile -Level Info}
                }
                switch($PlexServer.exception.Response.StatusCode.value__){
                    401{
                        if(-not $quiet){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($PlexServer.exception.Response.StatusDescription) (StatusCode: $($PlexServer.exception.Response.StatusCode.value__))"}
                    }
                    201{
                        if(-not $quiet){Write-Host "Failed to log in. StatusDescription: $($PlexServer.exception.Response.StatusDescription) (StatusCode: $($PlexServer.exception.Response.StatusCode.value__))"}
                    }
                    else{
                        if(-not $quiet){Write-Host "Unknown Response. Message: $($PlexServer.exception.Response.StatusDescription) (Error: $($PlexServer.exception.Response.StatusCode.value__)" -ForegroundColor Red}
                    }
                }
            }else{
                if(-not $quiet){Write-Host "Available" -ForegroundColor Cyan}
                if($PlexServer[0].MediaContainer){
                    if(-not $quiet){Write-Host "`t Friendly Name: $($PlexServer[0].MediaContainer.friendlyName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Username: $($PlexServer[0].MediaContainer.myPlexUserName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Signin State: $($PlexServer[0].MediaContainer.myPlexSigninState)" -ForegroundColor Cyan}
                    if($PlexServer[0].MediaContainer.myPlexSubscription -eq 1){
                        if(-not $quiet){Write-Host "`t Plex Subscription: True" -ForegroundColor Cyan}
                        $PlexPassStatus="True"
                    }elseif($PlexServer[0].MediaContainer.myPlexSubscription -eq 0){
                        if(-not $quiet){Write-Host "`t Plex Subscription: False" -ForegroundColor Cyan}
                        $PlexPassStatus="False"
                    }else{
                        if(-not $quiet){Write-Host "`t Plex Subscription: Unknown" -ForegroundColor Cyan}
                    }
                }else{
                    if($LogFile){Write-Log -Message "Data missing from server response $PlexServer" -Path $LogFile -Level Info}
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
                    if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Not Registered as a Service." -Path $LogFile -Level Info}
                }
            }Else{
                if(-not $quiet){Write-Host "Not Installed" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Not Installed." -Path $LogFile -Level Info}
            }

            #Get latest Plex Media Server release information from plex.tv
            if($DisablePlexPass){
                $PlexPassStatus="False"
                $UrlDownload=$UrlDownloadPublic
            }
            if(-not $quiet){Write-Host "Checking Available Updates..." -ForegroundColor Cyan -NoNewline}
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("X-Plex-Token", $PlexToken)
            if((Get-RestMethod -Uri $UrlDownload -Headers $headers -PassThru -OutVariable release).exception){
                if($LogFile){Write-Log -Message "Exiting: Unable to determin available version, version info missing in link. $($release.exception.message) Error: ($($release.exception.Response.StatusCode.value__))" -Path $LogFile -Level Info}
                Write-Warning "Version info missing in link. Please try https://plex.tv and confirm it works there before reporting this issue."
                return
            }else{
                $releaseVersion,$releaseBuild = $release[0].computer.Windows.version.Split('-')
                $releaseUrl = $release[0].computer.Windows.releases.url
                $releaseChecksum = $release[0].computer.Windows.releases.checksum
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
                if($LogFile){Write-Log -Message "Installed version ($installedVersion) less than available version ($releaseVersion)." -Path $LogFile -Level Info}
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

            ### Begin Update ###

            #Check if Update already downloaded and has valid checksum
            #Locate Plex AppData Folder
            if($LocalAppDataPath -eq ""){
                If($(Get-ItemProperty "HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server" -Name "LocalAppDataPath" | Select-Object -ExpandProperty LocalAppDataPath -OutVariable LocalAppDataPath )){
                    if($LogFile){Write-Log -Message "Checking custom local application data path ($LocalAppDataPath) for Updates" -Path $LogFile -Level Info}                
                }Else{
                    if($LogFile){Write-Log -Message "Checking default local application data path ($LocalAppDataPath) for Updates" -Path $LogFile -Level Info}                
                }
            }
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
                if([int](Invoke-WebRequest -Headers $headers -Uri $releaseUrl -OutFile "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -PassThru -OutVariable response).StatusCode -eq 200){
                    if($LogFile){Write-Log -Message "Download of $LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe completed. StatusCode: $([int]$response.StatusCode)" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "Completed" -ForegroundColor Cyan}
                    Write-Verbose "WebRequest result $([int]$response.StatusCode)"
                }else{
                    if($LogFile){Write-Log -Message "Exiting: Error downloading $releaseUrl. StatusDescription: $response.StatusDescription StatusCode: $response.StatusCode" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "ERROR OCCURRED!!!" -ForegroundColor Red}
                    Write-Error "Error occured downloading Update. Status Description $([string]$response.StatusDescription) Statuscode: $([int]$response.StatusCode)"
                    return
                }
            }

            #Check if Server in use
            if(-not $quiet){Write-Host "Checking Active Plex Sessions..." -ForegroundColor Cyan -NoNewline}
            #if((Get-Process -Name 'PlexTranscoder','PlexNewTranscoder' -ErrorAction SilentlyContinue){
            if((Get-RestMethod -Uri $PlexServerSessionUri -ErrorAction SilentlyContinue -PassThru -OutVariable PmsSessions).exception){
                if(-not $quiet){Write-Host $PlexServerSessions.exception.message -ForegroundColor Red}
            }else{
                if($PmsSessions[0].MediaContainer.size -eq 0){
                    if($LogFile){Write-Log -Message "Server not currently in use. No active sessions found." -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "No Sessions" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Current Sessons: $([int]$PmsSessions[0].MediaContainer.size)" -ForegroundColor Cyan}
                }else{
                    if($LogFile){Write-Log -Message "Server $($PlexServer[0].MediaContainer.friendlyName) is currently being used by one or more users, skipping installation. Please run again later" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "In Use" -ForegroundColor Red}
                    if(-not $quiet){Write-Host "`t Current Sessions: $([int]$PmsSessions[0].MediaContainer.size)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "Server $($PlexServer[0].MediaContainer.friendlyName) is currently being used by one or more users, skipping installation. Please run again later" -ForegroundColor Cyan}
                    return
                }
            }

            #Stop Plex Media Server Service (PlexService)
            if($PmsService.status -ne 'Stopped'){
                if($LogFile){Write-Log -Message "Found Plex Media Server Service Wrapper (PlexService) Running." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Stopping Plex Media Server Service (PlexService)..." -ForegroundColor Cyan -NoNewline}
                While ($PmsService.Status -eq "Running"){
                    if($PmsService | Stop-Service -Force -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Sent Plex Media Server Service Wrapper (PlexService) Stop-Service." -Path $LogFile -Level Info}
                    }else{
                        if($LogFile){Write-Log -Message "Service Hung, Sending Plex Media Server Service Wrapper (PlexService) Stop-Process." -Path $LogFile -Level Info}
                        if(Stop-Process -Name PlexService -ErrorAction SilentlyContinue -Force){
                            if($LogFile){Write-Log -Message "Service Hung, Sending Plex Media Server Service Wrapper (PlexService) Stop-Process." -Path $LogFile -Level Info}
                        }else{
                            if($LogFile){Write-Log -Message "Service Hung, Sending Plex Media Server Service Wrapper (PlexService) Stop-Process." -Path $LogFile -Level Info}
                        }
                    }
                }
                if($LogFile){Write-Log -Message "Plex Media Server Service Wrapper (PlexService) Stopped." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Stopped" -ForegroundColor Cyan}
            }else{
                if($LogFile){Write-Log -Message "Plex Media Server Service (PlexService) already Stopped." -Path $LogFile -Level Info}
            }

            #Stop all Plex Media Server related processes
            if(Get-Process -Name 'Plex Media Server','Plex Media Scanner','Plex Tuner Service','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue){
                if($LogFile){Write-Log -Message "Found Plex Media Server processes running." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Stopping Plex Media Server Processes..." -ForegroundColor Cyan -NoNewline}
                while(Get-Process -Name 'Plex Media Server','Plex Media Scanner','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue -OutVariable PMSProcesses){
                    $PMSProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                    if($LogFile){Write-Log -Message "Sent Plex Media Server processes Stop-Process." -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "." -ForegroundColor Cyan -NoNewline}
                }
                if($LogFile){Write-Log -Message "Plex Media Server processes stopped." -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Stopped" -ForegroundColor Cyan}
            }else{
                if($LogFile){Write-Log -Message "No Plex Media Server processes currently running." -Path $LogFile -Level Info}
            }

            if(-not $quiet){Write-Host "Updating Plex Media Server..." -ForegroundColor Cyan -NoNewline}
            #Start Silent install of PMS
            # /install | /repair | /uninstall | /layout - installs, repairs, uninstalls or creates a compelte local copy of bundle in directory. Install is the default
            # /passive | /quiet - displays minimal UI with no prompts or display no UI and no prompts. By default UI and all prompts are displayed.
            
            #Build ArgumentList
            if($passive){
                $ArgumentList = $ArgumentList + " /passive /norestart" 
            }elseif($quiet){
                $ArgumentList = $ArgumentList + " /quiet /norestart" 
            }else{
                $ArgumentList = $ArgumentList + " /norestart" 
            }

            if($LogFile){Write-Log -Message "Starting Plex Media Server update Process: $LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList" -Path $LogFile -Level Info}
            $Process = Start-Process -FilePath "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -ArgumentList $ArgumentList -PassThru
            While(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
                Start-Sleep -Seconds 4
                if(-not $quiet){Write-Host "." -ForegroundColor Cyan -NoNewline}
           }
            if($Process.ExitCode -eq 0){
                if(-not $quiet){Write-Host "Success" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Version Installed: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.FileVersion)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Restart Required: False" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Update successfully installed with ExitCode $($Process.ExitCode)." -Path $LogFile -Level Info}
            }elseif($Process.ExitCode -eq 3010 ){
                if(-not $quiet){Write-Host "Success" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Version Installed: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.FileVersion)" -ForegroundColor Cyan}
                if(-not $quiet){Write-Host "`t Restart zequired: True" -ForegroundColor Cyan}
                if($LogFile){Write-Log -Message "Update successfully installed with ExitCode $($Process.ExitCode). Restart Required." -Path $LogFile -Level Info}
            }elseif($Process.ExitCode -eq 1602 ){
                if(-not $quiet){Write-Host "Cancelled" -ForegroundColor red}
                if(-not $quiet){Write-Host "`t Update was cancelled by user. ExitCode: $($Process.ExitCode)" -ForegroundColor Red}
                if(-not $quiet){Write-Host "`t Plex Media Server was not updated." -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Update was cancelled by user. ExitCode: $($Process.ExitCode)." -Path $LogFile -Level Info}
            }else{
                if(-not $quiet){Write-Host "ERROR!!!" -ForegroundColor Red}
                if(-not $quiet){Write-Host "`t An Error occurred installing updated. Exit Code: $($Process.ExitCode)" -ForegroundColor Red}
                if(-not $quiet){Write-Host "`t Plex Media Server was not updated." -ForegroundColor Red}
                if($LogFile){Write-Log -Message "Failed to install update. Command '$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe $ArgumentList' returned error code $($Process.ExitCode))." -Path $LogFile -Level Info}
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
                if(-not $quiet){Write-Host "Not Running" -ForegroundColor Red}
                Write-Verbose "Plex Media Server Process not running"
            }

            #Verify Plex Web available
            if(-not $quiet){Write-Host "Verifying Plex Web Status..." -ForegroundColor Cyan -NoNewline}
            if((Get-RestMethod -Uri $PlexServerUri -PassThru -OutVariable PlexServer -ErrorAction SilentlyContinue).exception){
                if($PlexServer.exception.Response){
                    if($LogFile){Write-Log -Message "Plex Web unavailable at $PlexServerUri. Message: $($PlexServer.exception.Message) (Error: $($PlexServer.exception.HResult)) StatusDescription: $($PlexServer.exception.Response.StatusDescription) (StatusCode: $($return.exception.Response.StatusCode.value__))" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host $PlexServer.exception.message -ForegroundColor Red}
                }else{
                    if($LogFile){Write-Log -Message "Plex Media Server unavailable at $PlexServerUri" -Path $LogFile -Level Info}
                }
                switch($PlexServer.exception.Response.StatusCode.value__){
                    401{
                        if(-not $quiet){Write-Host "Username and/or password incorrect or invalid Plex Authentication token povided. StatusDescription: $($PlexServer.exception.Response.StatusDescription) (StatusCode: $($PlexServer.exception.Response.StatusCode.value__))"}
                    }
                    201{
                        if(-not $quiet){Write-Host "Failed to log in. StatusDescription: $($PlexServer.exception.Response.StatusDescription) (StatusCode: $($PlexServer.exception.Response.StatusCode.value__))"}
                    }
                    else{
                        if(-not $quiet){Write-Host "Unknown Response. Message: $($PlexServer.exception.Response.StatusDescription) (Error: $($PlexServer.exception.Response.StatusCode.value__)" -ForegroundColor Red}
                    }
                }
            }else{
                if(-not $quiet){Write-Host "Available" -ForegroundColor Cyan}
                if($PlexServer[0].MediaContainer){
                    if($LogFile){Write-Log -Message "Plex Web avaialble at $PlexServerUri. Friendly Name: $($PlexServer[0].MediaContainer.friendlyName) Username: $($PlexServer[0].MediaContainer.myPlexUserName) Signin State: $($PlexServer[0].MediaContainer.myPlexSigninState)" -Path $LogFile -Level Info}
                    if(-not $quiet){Write-Host "`t Friendly Name: $($PlexServer[0].MediaContainer.friendlyName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Username: $($PlexServer[0].MediaContainer.myPlexUserName)" -ForegroundColor Cyan}
                    if(-not $quiet){Write-Host "`t Signin State: $($PlexServer[0].MediaContainer.myPlexSigninState)" -ForegroundColor Cyan}
                    if($PlexServer[0].MediaContainer.myPlexSubscription -eq 1){
                        if(-not $quiet){Write-Host "`t Plex Subscription: True" -ForegroundColor Cyan}
                    }elseif($PlexServer[0].MediaContainer.myPlexSubscription -eq 0){
                        if(-not $quiet){Write-Host "`t Plex Subscription: False" -ForegroundColor Cyan}
                    }else{
                        if(-not $quiet){Write-Host "`t Plex Subscription: Unknown" -ForegroundColor Cyan}
                    }
                }else{
                    if($LogFile){Write-Log -Message "Data missing from server response $PlexServer" -Path $LogFile -Level Info}
                }
            }

            if($EmailNotify){
                if($LogFile){Write-Log -Message "Preparing Notification Email: $msg" -Path $LogFile -Level Info}
                if(-not $quiet){Write-Host "Sending Email Notification..." -ForegroundColor Cyan -NoNewline}
                $msg = "Plex Media Server $($PlexServer[0].MediaContainer.friendlyName) was updated on computer $env:COMPUTERNAME.`r`n`r`nNew Version: $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.ProductVersion)`r`nOld Version: $installedVersion-$installedBuild"
                if($IncludeLog -and $LogFile){
                    $logContent = Get-Content -Path $LogFile
                    $msg += "`r`n`r`n****  START LOG  ****`r`n"
                    Foreach ($Line in $logContent) {
                        $msg += $Line + "`r`n"
                    }
                    $msg += "****  END LOG  ****"
                }

                if($AttachLog -and $LogFile){
                    if($LogFile){Write-Log -Message "Sending Email Notification to $SmtpTo with log attached." -Path $LogFile -Level Info}
                    if(Send-ToEmail -SmtpFrom $SmtpFrom -SmtpTo $SmtpTo -Subject "Plex Media Server Updated on $env:COMPUTERNAME" `
                        -Body $msg -SmtpUser $SmtpUser -SmtpPassword $SmtpPassword -SmtpServer $SmtpServer -SmtpPort $SmtpPort `
                        -EnableSSL $EnableSSL -attachmentpath $LogFile -PassThru -ErrorAction SilentlyContinue){
                        if($LogFile){Write-Log -Message "Email Notification sent successsfully." -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Sent" -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Email Notification" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Error Sending" -ForegroundColor Red}
                    }
                }else{
                    if($LogFile){Write-Log -Message "Sending Email Notification to $SmtpTo." -Path $LogFile -Level Info}
                    if(Send-ToEmail -SmtpFrom $SmtpFrom -SmtpTo $SmtpTo -Subject "Plex Media Server updated on $env:COMPUTERNAME" `
                        -Body $msg -SmtpUser $SmtpUser -SmtpPassword $SmtpPassword -SmtpServer $SmtpServer -SmtpPort $SmtpPort `
                        -EnableSSL $EnableSSL -PassThru -ErrorAction SilentlyContinue){
                            if($LogFile){Write-Log -Message "Email Notification sent successsfully." -Path $LogFile -Level Info}
                            if(-not $quiet){Write-Host "Sent" -ForegroundColor Cyan}
                    }else{
                        if($LogFile){Write-Log -Message "Error sending Email Notification" -Path $LogFile -Level Info}
                        if(-not $quiet){Write-Host "Error Sending" -ForegroundColor Red}
                    }
                }
            }
        }Catch{
            Write-Warning "Error occurred: $_"
            return $_
            if ($Host.Name -eq 'Windows PowerShell ISE Host') {
                throw $LASTEXITCODE
            } else {
                exit $LASTEXITCODE
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
                ParameterSetName="Credential",
                Position=0,
                ValueFromPipelineByPropertyName=$true)]

                [string]$PlexLogin,

    #
    [Parameter(
                ParameterSetName="Credential",
                Position=1,
                ValueFromPipelineByPropertyName=$true)]

                [string]$PlexPassword,

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

    [hashtable]$return=@{}

    
    if($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $PlexLogin=$Credential.UserName
        $PlexPassword="$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)))"
    }

    if($PlexLogin -eq ""){
        $PlexLogin=Read-Host -Prompt "Enter Plex.tv Email or ID"
    }

    if($PlexPassword){
#        if($PlexPassword.GetType().Name -ne 'SecureString'){
#            Write-Output $PlexPassword.GetType().Name
            $Password=$PlexPassword | ConvertTo-SecureString -AsPlainText -Force
#        }
    }else{
        $Password=$(Read-Host -Prompt "Enter Plex.tv password" -AsSecureString)
    }

    $URL_LOGIN='https://plex.tv/users/sign_in.json'

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("X-Plex-Client-Identifier", '4a745ae7-1839-e44e-1e42-aebfa578c865')
    $headers.Add("X-Plex-Product", 'Plex SSO')
    $postParams= @{
        'user[login]'="$PlexLogin"
        'user[password]'="$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)))"
	    'user[remember_me]'=0
    }

    try {
        Invoke-RestMethod -Uri $URL_LOGIN -Headers $headers -Method Post -Body $postParams -TimeoutSec 30 -OutVariable response
    } catch {
        $return.exception=$_.Exception
        $return.Status=1
    }

    if($response){
        Write-Verbose "Plex Authentication Token $($response.user.authToken) found for $($response.user.username)"
        $return.response=$response
        $return.status=0
        if($PassThru){return $return}else{return $response.user.authToken}
    }else{
        if($return.exception.Response){
            Write-Verbose "Unable to retrieve Plex Token from $URL_LOGIN Message: $($return.exception.Message) (Error: $($return.exception.HResult))"
            switch($return.exception.Response.StatusCode.value__){
                401{Write-Verbose "Username and/or password incorrect. StatusDescription: $($return.exception.Response.StatusDescription) (StatusCode: $($return.exception.Response.StatusCode.value__))"}
                201{Write-Verbose "Failed to log in.  StatusDescription: $($return.exception.Response.StatusDescription) (StatusCode: $($return.exception.Response.StatusCode.value__))"}
                else{Write-Error "StatusDescription: $($return.exception.Response.StatusDescription) (StatusCode: $($return.exception.Response.StatusCode.value__))"}
            }
            if($PassThru){return $return}else{return $false}
        }else{
            Write-Verbose "Error connecting to $URL_LOGIN Message: $($return.exception.Message) (Error: $($return.exception.HResult))"
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
