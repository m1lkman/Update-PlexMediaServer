#Requires -Version 4.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
   Updates systems running Plex Media Server and Plex Server Service (PlexService).
.DESCRIPTION
   Use this script to autoatically download and update Plex Media Server that use the Plex Server Service created by cjmurph (https://github.com/cjmurph/PmsService).
.EXAMPLE Run Interactively and attempt to update from publicly available updates.
   Update-PlexMediaServer
.EXAMPLE Force Upgrade/reinstall even if version is greater than or equal to
   Update-PlexMediaServer -force
.EXAMPLE Run Interactively and specify a user other than the context the script is executing in.
   Update-PlexMediaServer -UserName JDoe
.EXAMPLE Run interactively and attempt to update from PlexPass(Beta) available updates. Will prompt for Plex.tv Email/Id and password.
   Update-PlexMediaServer -PlexPass
.EXAMPLE Run silently and attempt to update from PlexPass(Beta) available updates.
   Update-PlexMediaServer -PlexToken <Token> -quiet
.EXAMPLE
   Update-PlexMediaServer -PlexLogin <Email/ID> -PlexPassword <Password>
.EXAMPLE
   Update-PlexMediaServer -EmailNotify -SmtpTo Someone@gmail.com -SmtpFrom Someone@gmail.com -SmtpUser Username -SmtpPassword Password -SmtpServer smtp.server.com -SmtpPort Port -EnableSSL
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PlexMediaServer -UserName JDoe} 
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PlexMediaServer -UserName JDoe} 
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PlexMediaServer -UserName JDoe} 
.NOTES

.LINK
    https://github.com/m1lkman/Update-PlexMediaServer
#>
Function Update-PlexMediaServer
{
    [CmdletBinding()]
    param(
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # Specify User Name if Plex Media Server is running as a user different than script execution context
    [string]$UserName = "",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$PlexToken = "",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$PlexLogin = "",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$PlexPassword = "",
    [Parameter(Mandatory=$false)]
    # Force update 
    [switch]
    [boolean]$force,
    [Parameter(Mandatory=$false)]
    # passive 
    [switch]
    [boolean]$passive,
    [Parameter(Mandatory=$false)]
    # quiet 
    [switch]
    [boolean]$quiet,
    [Parameter(Mandatory=$false)]
    # For Email Notification configure all the below parameters in script or via command line 
    [switch]
    [boolean]$EmailNotify,
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$SmtpTo = "t",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$SmtpFrom = "justin.wedepohl@gmail.com",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$SmtpUser = "jwedepohl@comcast.net",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$SmtpPassword = "1Badd0g!",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [string]$SmtpServer = "smtp.comcast.net",
    [Parameter(ValueFromPipelineByPropertyName=$true)]
    # 
    [int]$SmtpPort = "587",
    [Parameter(Mandatory=$false)]
    # Enable SSL for SMTP Authentication 
    [switch]
    [boolean]$EnableSSL
    )

    begin{
        New-PSDrive HKCU -PSProvider Registry -Root Registry::HKEY_CURRENT_USER | Out-Null
        New-PSDrive HKLM -PSProvider Registry -Root Registry::HKEY_LOCAL_MACHINE | Out-Null
        New-PSDrive HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        # Current pages we need - Do not change unless Plex.tv changes again
        $URL_LOGIN='https://plex.tv/users/sign_in.json'
        $URL_DOWNLOAD='https://plex.tv/api/downloads/1.json?channel=plexpass'
        $URL_DOWNLOAD_PUBLIC='https://plex.tv/api/downloads/1.json'
    }
    process{

        Try{
            Write-Host "Collecting Plex Media Server Information..." -ForegroundColor Cyan -NoNewline
            #Locate Plex Media Server.exe and Get Current Version and determin user name
            do{
                if(Get-Process "Plex Media Server" -IncludeUserName -OutVariable PMSProcess -ErrorAction SilentlyContinue){
                    Get-ItemProperty $PMSProcess.Path -OutVariable PMSExeFile -ErrorAction SilentlyContinue | Out-Null
                    If (-Not $UserName) {$UserName = $PMSProcess.UserName}

                    #Get User SID
                    try{
                        $UserSID = (New-Object System.Security.Principal.NTAccount("$env:DomainName", "$UserName")).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }catch{
                        Write-Host "Unable to translate User SID, User Name may not exist." -ForegroundColor Red
                        Return
                    }
                }else{ # if process isn't running
                    Write-Verbose "Plex Media Server Process not running"
                    If (-Not $UserName) {$UserName = $env:USERNAME}

                    #Get User SID
                    try{
                        $UserSID = (New-Object System.Security.Principal.NTAccount("$env:DomainName", "$UserName")).Translate([System.Security.Principal.SecurityIdentifier]).Value
                    }catch{
                        Write-Host "Unable to translate User SID, User Name may not exist." -ForegroundColor Red
                        Return
                    }

                    #Determin Plex Media Server Executable location from Registy then default locations
                    if(Get-ItemProperty "$(Get-ItemProperty "HKLM:\Software\Wow6432Node\Plex, Inc.\Plex Media Server" -Name "InstallFolder" -ErrorAction SilentlyContinue | Select -ExpandProperty InstallFolder -OutVariable InstallFolder)\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                        Break
                    }elseif(Get-ItemProperty "$(Get-ItemProperty "HKLM:\Software\Plex, Inc.\Plex Media Server" -Name "InstallFolder" -ErrorAction SilentlyContinue | Select -ExpandProperty InstallFolder -OutVariable InstallFolder)\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                        Break
                    }elseif(Get-ItemProperty "$(Get-ItemProperty "HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server" -Name "InstallFolder" -ErrorAction SilentlyContinue | Select -ExpandProperty InstallFolder -OutVariable InstallFolder)\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                        Break
                    }elseif(Get-ItemProperty "$env:ProgramFiles\Plex\Plex Media Server\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                        Break
                    }elseif(Get-ItemProperty "${env:ProgramFiles(x86)}\Plex\Plex Media Server\Plex Media Server.exe" -OutVariable PMSExeFile -ErrorAction SilentlyContinue){
                        Break
                    }
                }
            }until($PMSExeFile -ne "")
            if($PMSExeFile -eq ""){
                Write-Host "Unable to find Plex Media Server Installed" -ForegroundColor Cyan
                Break
            }else{
                Write-Host "Completed" -ForegroundColor Cyan
                $installedVersion,$installedBuild = $PMSExeFile.VersionInfo.ProductVersion.Split('-')
                Write-Host "Detected Plex Media Server version: $installedVersion" -ForegroundColor Cyan
                Write-Host "Installed in folder $PMSExeFile" -ForegroundColor Cyan
                Write-Host "Plex Media Server User Context: $UserName" -ForegroundColor Cyan
            }

            #Check for Plex Token
            if(($PlexLogin -ne "") -or ($PlexPassword -ne "")){
                if($passive -or $quiet){
                    Write-Host "Unable to determine Plex Authentication Token." -ForegroundColor Cyan
                    Write-Host "     1. Configure PlexToken variable in script. Use Get-PlexToken." -ForegroundColor Cyan
                    Write-Host "     2. Specify your token in the command line, i.e. -plextoken <Token>" -ForegroundColor Cyan
                    Write-Host "     5. Specify your plex.tv username/ID and password in the command line, i.e. -PlexLogin <email/id> -PlexPassword <password>" -ForegroundColor Cyan
                    Return
                }else{
                    $PlexToken = Get-PlexToken -PlexLogin $PlexLogin -Password $PlexPassword
                }
            }
            $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $headers.Add("X-Plex-Token", $PlexToken)

            #Get latest Plex Media Server release information from plex.tv
            if($PlexPass){
                Write-Host "Checking https://Plex.tv for available PlexPass(Beta) updates..." -ForegroundColor Cyan -NoNewline
            }else{
                Write-Host "Checking https://Plex.tv for available Public updates..." -ForegroundColor Cyan -NoNewline
            }
            $release = Invoke-RestMethod -Headers $headers -Uri $URL_DOWNLOAD
            $releaseVersion,$releaseBuild = $release.computer.Windows.version.Split('-')
            $releaseUrl = $release.computer.Windows.releases.url
            $releaseChecksum = $release.computer.Windows.releases.checksum

            if($releaseVersion -eq $null){
                Write-Warning "Version info missing in link. Please try https://plex.tv and confirm it works there before reporting this issue."
                Break
            }else{
                Write-Host "Completed" -ForegroundColor Cyan
                Write-Verbose "Plex Media Server version available $releaseVersion for download."
            }

            #Determine if installed PMS version needs update
            if([Version]$installedVersion -eq [Version]$releaseVersion){
                Write-Host "Running the latest version $installedVersion." -ForegroundColor Cyan
                if(-not $force) {Break}
            }elseif([version]$installedVersion -lt [version]$releaseVersion){
                Write-Host "New version $releaseVersion Available!!!" -ForegroundColor Cyan
            }else{
                Write-Host "Running version ($installedVersion) later than available Plex Media Server Update version ($releaseVersion)." -ForegroundColor Cyan
                if(-not $force) {Break}
            }

            #Check if Update already downloaded and has valid checksum
            #Locate Plex AppData Folder
            If($(Get-ItemProperty "HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server" -Name "LocalAppDataPath" | Select -ExpandProperty LocalAppDataPath -OutVariable LocalAppDataPath )){
                Write-Host "Checking custom local application data path ($LocalAppDataPath) for Updates" -ForegroundColor Cyan
            }Else{
                $LocalAppDataPath = "$Env:SystemDrive\Users\$UserName\AppData\Local"
                Write-Host "Checking default local application data path ($LocalAppDataPath) for Updates" -ForegroundColor Cyan
            }
            if((Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe") -and `
            ((Get-FileHash "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe"-ALgorithm SHA1).Hash -ieq $releaseChecksum)){
                Write-Host "Latest available Update already downloaded." -ForegroundColor Cyan
            }else{
                #create destination directory if not present
                if(-Not (Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild")){New-Item "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild" -ItemType directory | Out-Null}
                if(Test-Path -Path "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe"){
                    Write-Host "Already downloaded Update failed Checksum, attempting to download again..." -ForegroundColor Cyan -NoNewline
                }else{
                    Write-Host "Downloading Plex Media Server for Windows ($releaseVersion-$releaseBuild)..." -ForegroundColor Cyan -NoNewline
                }
                if([int](Invoke-WebRequest -Headers $headers -Uri $releaseUrl -OutFile "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -PassThru -OutVariable response).StatusCode -eq 200){
                    Write-Host "Completed" -ForegroundColor Cyan
                    Write-Verbose "WebRequest result $([int]$response.StatusCode)"
                }else{
                    Write-Host "ERROR OCCURRED!!!" -ForegroundColor Red
                    Write-Error "Error occured downloading Update. Status Description $([string]$response.StatusDescription) Statuscode: $([int]$response.StatusCode)"
                    Break
                }
            }

            #Check if Server in use...PlexTranscoder Process Running
            if(Get-Process -Name 'PlexTranscoder','PlexNewTranscoder' -ErrorAction SilentlyContinue){
                Write-Host "Server is currently being used by one or more users, skipping update. Please run again later" -ForegroundColor Red
                break
            }else{
                Write-Verbose "Plex Media Server is not in use."
            }

            #Stop Plex Media Server Service (PlexService)
            If(Get-Service PlexService -ErrorAction SilentlyContinue){
                Write-Host "Stopping Plex Media Server Service (PlexService)..." -ForegroundColor Cyan -NoNewline
                While ($(Get-Service PlexService).Status -eq "Running"){
                    Get-Service PlexService | Stop-Service -Force -WarningAction SilentlyContinue
                }
                Write-Host "Completed" -ForegroundColor Cyan
            }Else{
                Write-Warning "Plex Media Server Service (PlexService) not installed on $Env:COMPUTERNAME!"
            }

            #Stop all Plex Media Server related processes
            if(Get-Process -Name 'Plex Media Server','Plex Media Scanner','Plex Tuner Service','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue){
                Write-Host "Stopping Plex Media Server Processes." -ForegroundColor Cyan -NoNewline
                    while(Get-Process -Name 'Plex Media Server','Plex Media Scanner','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue -OutVariable PMSProcesses){
                        $PMSProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                        Write-Host "." -ForegroundColor Cyan -NoNewline
                    }
                Write-Host "Completed" -ForegroundColor Cyan
            }

            #Start Silent install of PMS
            # /install | /repair | /uninstall | /layout - installs, repairs, uninstalls or creates a compelte local copy of bundle in directory. Install is the default
            # /passive | /quiet - displays minimal UI with no prompts or display no UI and no prompts. By default UI and all prompts are displayed.
            Write-Host "Updating Plex Media Server..." -ForegroundColor Cyan -NoNewline
            $Process = Start-Process -FilePath "$LocalAppDataPath\Plex Media Server\Updates\$releaseVersion-$releaseBuild\Plex-Media-Server-$releaseVersion-$releaseBuild.exe" -ArgumentList "/install /quiet /norestart" -PassThru
            While(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
                Start-Sleep -Seconds 4
                Write-Host "." -ForegroundColor Cyan -NoNewline
            }
            if($Process.ExitCode -eq 0){
                Write-Host "Completed" -ForegroundColor Cyan
                Write-Host "Plex Media Server Updated Successfully to ersion $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.FileVersion)" -ForegroundColor Cyan
            }elseif($Process.ExitCode -eq 3010 ){
                Write-Host "Completed" -ForegroundColor Cyan
                Write-Host "Plex Media Server Updated Successfully to version $($(Get-ItemProperty -Path $PMSExeFile).VersionInfo.FileVersion). A Restart of the computer is required." -ForegroundColor Cyan
            }else{
                Write-Host "ERROR OCCURRED" -ForegroundColor Red
                Write-Error "An error occurred during the PMS Update (Exit code was $($Process.ExitCode))."
                Break
            }

            #cleanup after install
            if($(Get-ItemProperty "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Plex Media Server" -ErrorAction SilentlyContinue)){
                Remove-ItemProperty "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Run\" -Name "Plex Media Server" -Force
            }
            If ($(Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Plex Media Server" -ErrorAction SilentlyContinue)) {
                Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Plex Media Server" -Force
            }

            #Restart PlexService
            While($(Get-Service PlexService).Status -eq "Stopped"){
                Write-Host "Starting Plex Media Server Service (PlexService)..." -ForegroundColor Cyan -NoNewline
                Get-Service PlexService | Start-Service
            }
            Write-Host "Completed" -ForegroundColor Cyan

        }Catch{
            Write-Warning "Error occurred: $_"
        }
    }
    end{
        if($EmailNotify){
            $msg = "Plex Media Server was upgraded on computer $env:COMPUTERNAME.`r`nNew Version: $($(Get-ItemProperty `
                -Path $PMSExeFile).VersionInfo.ProductVersion)`rOld Version: $installedVersion-$installedBuild"

            if(Send-ToEmail -SmtpFrom $SmtpFrom -SmtpTo $SmtpTo -Subject "Plex Media Server Upgraded on $env:COMPUTERNAME" `
                -Body $msg `
                -SmtpUser $SmtpUser -SmtpPassword $SmtpPassword -SmtpServer $SmtpServer -SmtpPort $SmtpPort -EnableSSL $EnableSSL){
                Write-Host "Email notification sent." -ForegroundColor Cyan
            }else{
                Write-Warning "Error sending email notification sent."
            }
        }
    }
}

function Get-PlexToken ([string]$PlexLogin, [string]$Password) {
    
    if($PlexLogin -eq ""){
        $PlexLogin=Read-Host -Prompt "Enter Plex.tv Email or ID"
    }
    if($Password -eq ""){
        $SecurePassword=Read-Host -Prompt "Enter Plex.tv password" -AsSecureString
        $Password=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))
    }

    $URL_LOGIN='https://plex.tv/users/sign_in.json'

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("X-Plex-Client-Identifier", '4a745ae7-1839-e44e-1e42-aebfa578c865')
    $headers.Add("X-Plex-Product", 'Plex SSO')
    $postParams= @{
        'user[login]'="$PlexLogin"
	    'user[password]'="$Password"
	    'user[remember_me]'=0
    }

    try {
        Invoke-RestMethod -Uri $URL_LOGIN -Headers $headers -Method Post -Body $postParams -OutVariable response | Out-Null
    } catch {
        $return=$_.Exception
    }

    if($response){
        Write-Host "Plex Authentication Token found for $($response.user.title)($($response.user.username))" -ForegroundColor Cyan
        Return $response.user.authToken
    }else{
        Write-Host "Unable to get Plex Token. " -ForegroundColor Cyan -NoNewline
        Write-Host "HTTP ERROR StatusDescription:" $return.Response.StatusDescription "(StatusCode:" $return.Response.StatusCode.value__ ")"
        switch($return.Response.StatusCode.value__){
            401{Write-Host "Username and/or password incorrect."}
            201{Write-Host "Failed to log in, debug information:."}
            else{Write-Error "Unknown shouldn't be here"}
        }
    }

}

function Get-PlexServer ($PlexServerHost, $PlexToken){
    Invoke-RestMethod -Uri "http://$PlexServerHost:32400/?X-Plex-Token=$PlexToken" -OutVariable response
    return $response
}

function Send-ToEmail([string]$SmtpFrom, [string]$SmtpTo, [string]$Subject, [string]$Body, [string]$attachmentpath, [string]$SmtpUser, [string]$SmtpPassword, [string]$SmtpServer, [string]$SmtpPort, [boolean]$EnableSSL, [boolean]$IsBodyHtml){

    $message = new-object Net.Mail.MailMessage;
    $message.From = "$SmtpFrom";
    $message.To.Add($SmtpTo);
    $message.Subject = $Subject;
    if($IsBodyHtml){$message.IsBodyHtml = $true;}
    $message.Body = $Body;
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
        return $false
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
        $VerbosePreference = 'Continue' 
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
