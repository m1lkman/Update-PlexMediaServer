<#
.Synopsis
   Updates systems that use both Plex Media Server and Plex Server Service.
.DESCRIPTION
   Use this script to update systems that have Plex Media Server and use the Plex Server service.
.EXAMPLE
   Update-PMSInstall
.EXAMPLE
   Update-PMSInstall -UserName JDoe
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PMSInstall}
.EXAMPLE
   Invoke-Command -ComputerName Server1 -Credential Administrator -ScriptBlock ${function:Update-PMSInstall -UserName JDoe} 
#>
Function Update-PMSInstall{
    [CmdletBinding()]
    Param (
    [Parameter(ValueFromPipelineByPropertyName=$true, Position=0)]
    # Change this to the user name you run Plex Media Server under, or use the parameter and enter a value.
    $UserName = "$env:USERNAME"
    )

    Try{
        New-PSDrive HKLM -PSProvider Registry -Root Registry::HKEY_LOCAL_MACHINE | Out-Null
        New-PSDrive HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        #Get User SID
        $UserSID = (New-Object System.Security.Principal.NTAccount("$env:DomainName", "$UserName")).Translate([System.Security.Principal.SecurityIdentifier]).Value

        #Locate Plex Media Server.exe
        do{
            if(Get-ItemProperty "$(Get-ItemProperty "HKLM:\Software\Wow6432Node\Plex, Inc.\Plex Media Server" -Name "InstallFolder" -ErrorAction SilentlyContinue | Select -ExpandProperty InstallFolder -OutVariable InstallFolder)\Plex Media Server.exe" -OutVariable PMSFile -ErrorAction SilentlyContinue){
                Break
            }elseif(Get-ItemProperty "$(Get-ItemProperty "HKLM:\Software\Plex, Inc.\Plex Media Server" -Name "InstallFolder" -ErrorAction SilentlyContinue | Select -ExpandProperty InstallFolder -OutVariable InstallFolder)\Plex Media Server.exe" -OutVariable PMSFile -ErrorAction SilentlyContinue){
                Break
            }elseif(Get-ItemProperty "$(Get-ItemProperty "HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server" -Name "InstallFolder" -ErrorAction SilentlyContinue | Select -ExpandProperty InstallFolder -OutVariable InstallFolder)\Plex Media Server.exe" -OutVariable PMSFile -ErrorAction SilentlyContinue){
                Break
            }elseif(Get-ItemProperty "$env:ProgramFiles\Plex\Plex Media Server\Plex Media Server.exe" -OutVariable PMSFile -ErrorAction SilentlyContinue){
                Break
            }elseif(Get-ItemProperty "${env:ProgramFiles(x86)}\Plex\Plex Media Server\Plex Media Server.exe" -OutVariable PMSFile -ErrorAction SilentlyContinue){
                Break
            }
        }until($PMSFile -ne "")
        if($PMSFile -eq ""){
            Write-Output "Unable to find PMS Installed"
            Break
        }else{
            Write-Output "Found PMS ($PMSFile) Version $($PMSFile.VersionInfo.FileVersion)"
        }

        #Locate Plex AppData Folder
        If($(Get-ItemProperty "HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server" -Name "LocalAppDataPath" | Select -ExpandProperty LocalAppDataPath -OutVariable LocalAppDataPath )){
#            $LocalAppDataPath = $(Get-ItemProperty "HKU:\$UserSID\Software\Plex, Inc.\Plex Media Server" -Name "LocalAppDataPath").LocalAppDataPath
            Write-Output "Checking custom local application data path ($LocalAppDataPath) for PMS Updates"
        }Else{
            $LocalAppDataPath = "$Env:SystemDrive\Users\$UserName\AppData\Local"
            Write-Output "Checking default local application data path ($LocalAppDataPath) for PMS Updates"
        }

        #Find Latest Update file available based on Creation Time
        If(Get-ChildItem "$LocalAppDataPath\Plex Media Server\Updates" -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue | Sort creationtime | Select -expand fullname -Last 1 -OutVariable PMSInstaller){
            $PMSInstaller = Get-ItemProperty $PMSInstaller
        }Else{
            Write-Warning "There are no PMS Update Files in $LocalAppDataPath\Plex Media Server\Update - Check the username $UserName or Update Availability!"
            Break
        }
        Write-Output "Found PMS Update file ($PMSInstaller) Version $($PMSInstaller.VersionInfo.FileVersion)"

        #Determine if Update file is newer build than currently installed PMS
        if([Version][System.Diagnostics.FileVersionInfo]::GetVersionInfo($PMSInstaller).FileVersion -gt [Version][System.Diagnostics.FileVersionInfo]::GetVersionInfo($PMSFile.VersionInfo.FileName).FileVersion){
            Write-Output "PMS Update Available!!! Installed PMS Version ($($PMSFile.VersionInfo.FileVersion)) is less than available PMS Update file version ($($PMSInstaller.VersionInfo.FileVersion))."
        }elseif([Version][System.Diagnostics.FileVersionInfo]::GetVersionInfo($PMSInstaller).FileVersion -eq [Version][System.Diagnostics.FileVersionInfo]::GetVersionInfo($PMSFile.VersionInfo.FileName).FileVersion){
            Write-Output "PMS is Current!!! Installed PMS version ($($PMSFile.VersionInfo.FileVersion)) is equal to available PMS Update file version ($($PMSInstaller.VersionInfo.FileVersion)). Verify you've downloaded updates via Plex Web and try again!"
            Break
        }else{
            Write-Output "Currently installed PMS version ($($PMSFile.VersionInfo.FileVersion)) is greater than the latest PMS Update file version ($($PMSInstaller.VersionInfo.FileVersion)). Verify you've downloaded updates via Plex Web and try again!"
            Break
        }

        #Stop PMS as a Service (PlexService)
        If(Get-Service PlexService -ErrorAction SilentlyContinue){
            While ($(Get-Service PlexService).Status -eq "Running"){
                Get-Service PlexService | Stop-Service -Force -Verbose
            }
        }Else{
            Write-Warning "There is no such Service named PlexService on $Env:COMPUTERNAME!"
            Break
        }
        #Stop all related processes
        Get-Process -Name 'Plex Media Server','Plex Media Scanner','PlexDlnaServer','PlexNewTranscoder','PlexScriptHost','PlexTranscoder' -ErrorAction SilentlyContinue | Stop-Process -Force -Verbose -ErrorAction SilentlyContinue

        #colorful banner
        Do{
            [enum]::GetValues([System.ConsoleColor]) | Where-Object {$_ -ne 'Black'} | ForEach-Object{
                Write-Host 'Updating Plex Media Server...' -ForegroundColor $_
                Start-Sleep -Seconds 1
                Clear-Host
            }
        }

        #Start Silent install of PMS
        While(Start-Process -FilePath "$PMSInstaller" -ArgumentList "/install /passive /norestart" -Wait)

        #cleanup after install
        If($(Get-ItemProperty "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Plex Media Server" -ErrorAction SilentlyContinue)){
            Remove-ItemProperty "HKU:\$UserSID\Software\Microsoft\Windows\CurrentVersion\Run\" -Name "Plex Media Server" -Force -Verbose
        }

        #Restart PlexService
        While($(Get-Service PlexService).Status -eq "Stopped"){
            Get-Service PlexService | Start-Service -Verbose
        }
    }Catch{
        Write-Warning "Error occurred: $_"
    }
}
