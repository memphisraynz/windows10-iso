function Remove-FileLock {
    param (
        [Parameter(Mandatory=$true)]
        [string]$LockFile
    )
    
    $HandleEXE = "C:\ProgramData\SysInternals\handle64.exe"
    $DownloadLink = "https://live.sysinternals.com/handle64.exe"

    #Create Directory
    $Split = $HandleEXE.Split("\\")
    New-Item -Path $(([string]$split[0..($Split.count-2)]) -replace(" ","\")) -ItemType Directory -Force | Out-Null

    #Download File
    (New-Object System.Net.WebClient).DownloadFile($DownloadLink, $HandleEXE)

    & $HandleEXE -NoBanner $LockFile | Where-Object { $_ -match 'pid' } | ForEach-Object {
        $ProcessID = ($_ -split '\s+')[2]
        $LockID = $(($_ -split '\s+')[5]) -replace ':', ''
    }

    if (-not $ProcessID -and -not $LockID) {
        Write-Verbose "No lock on file $LockFile" -Verbose
    } else {
        Write-Verbose "Attempting to remove lock on file $LockFile" -Verbose
        & $HandleEXE -c $LockID -p $ProcessID -y
    }
}

function CleanPreviousUpdate {
    $ErrorActionPreference = 'SilentlyContinue'

    stop-service wuauserv
    Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse -Force
    start-service wuauserv

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Provisioning.old") {
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning.old" -Recurse -Force
    }
    Rename-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning" -NewName "Provisioning.old" | Out-Null
    if (Test-Path "C:\Windows\Provisioning.old") {
        takeown /F "C:\Windows\Provisioning.old\*" /R /A
        icacls "C:\Windows\Provisioning.old\*.*" /T /grant administrators:F
        Remove-Item -Path "C:\Windows\Provisioning.old" -Recurse -Force
    }
    Rename-Item -Path "C:\Windows\Provisioning" -NewName "Provisioning.old" | Out-Null
    Rename-Item -Path 'C:\$WINDOWS.~BT' -NewName '$WINDOWS.~BT.old' | Out-Null

    Dism /cleanup-Wim
}

function Get-Win10ISOLink {
    <#
    .SYNOPSIS
        This function generates a fresh download link for a Windows 10 ISO
    .NOTES
        Version:        1.6
        Author:         Andy Escolastico
        Creation Date:  10/11/2019
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] 
        [ValidateSet("64-bit", "32-bit")]
        [String] $Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture,
        [Parameter(Mandatory=$false)] 
        [ValidateSet("fr-dz", "es-ar", "en-au", "nl-be", "fr-be", "es-bo", "bs-ba", "pt-br", "en-ca", "fr-ca", "cs-cz", "es-cl", "es-co", "es-cr", "sr-latn-me", "en-cy", "da-dk", "de-de", "es-ec", "et-ee", "en-eg", "es-sv", "es-es", "fr-fr", "es-gt", "en-gulf", "es-hn", "en-hk", "hr-hr", "en-in", "id-id", "en-ie", "is-is", "it-it", "en-jo", "lv-lv", "en-lb", "lt-lt", "hu-hu", "en-my", "en-mt", "es-mx", "fr-ma", "nl-nl", "en-nz", "es-ni", "en-ng", "nb-no", "de-at", "en-pk", "es-pa", "es-py", "es-pe", "en-ph", "pl-pl", "pt-pt", "es-pr", "es-do", "ro-md", "ro-ro", "en-sa", "de-ch", "en-sg", "sl-si", "sk-sk", "en-za", "sr-latn-rs", "en-lk", "fr-ch", "fi-fi", "sv-se", "fr-tn", "tr-tr", "en-gb", "en-us", "es-uy", "es-ve", "vi-vn", "el-gr", "ru-by", "bg-bg", "ru-kz", "ru-ru", "uk-ua", "he-il", "ar-iq", "ar-sa", "ar-ly", "ar-eg", "ar-gulf", "th-th", "ko-kr", "zh-cn", "zh-tw", "ja-jp", "zh-hk")]
        [String] $Locale = (Get-WinSystemLocale).Name,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Arabic", "Brazilian Portuguese", "Bulgarian", "Chinese (Simplified)", "Chinese (Traditional)", "Croatian", "Czech", "Danish", "Dutch", "English", "English International", "Estonian", "Finnish", "French", "French Canadian", "German", "Greek", "Hebrew", "Hungarian", "Italian", "Japanese", "Korean", "Latvian", "Lithuanian", "Norwegian", "Polish", "Portuguese", "Romanian", "Russian", "Serbian Latin", "Slovak", "Slovenian", "Spanish", "Spanish (Mexico)", "Swedish", "Thai", "Turkish", "Ukrainian")]
        [String] $Language = "English",
        [Parameter(Mandatory=$false)]
        [String] $Version = "2009"
    )
    
    # prefered architecture
    if ($Architecture -eq "64-bit"){ $archID = "x64" } else { $archID = "x32" }
    
    # prefered prodID
    if ($Version -eq "Latest") {
        # grabs latest id
        $response = Invoke-WebRequest -UserAgent $userAgent -WebSession $session -Uri "https://www.microsoft.com/$Locale/software-download/windows10ISO" -UseBasicParsing
        $prodID = ([regex]::Match((($response).RawContent), 'product-info-content.*option value="(.*)">Windows 10')).captures.groups[1].value
    } else{
        # uses hard-coded id
        $WindowsVersions = @{
            "2009"  = 1882
            "2004"  = 1626
            "1909"  = 1429
            "1903"  = 1384
        }
        $prodID = $WindowsVersions[$Version]
    } 

    # variables you might not want to change (unless msft changes their schema)
    $pgeIDs = @("a8f8f489-4c7f-463a-9ca6-5cff94d8d041", "cfa9e580-a81e-4a4b-a846-7b21bf4e2e5b")
    $actIDs = @("getskuinformationbyproductedition", "getproductdownloadlinksbysku")
    $hstParam = "www.microsoft.com"
    $segParam = "software-download"
    $sdvParam = "2"
    $verID = "Windows10ISO"

    # used to spoof a non-windows web request
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362"

    # used to maintain session in subsequent requests
    $sessionID = [GUID]::NewGuid()

    # builds session request url 
    $uri = "https://www.microsoft.com/" + $Locale + "/api/controls/contentinclude/html"
    $uri += "?pageId=" + $pgeIDs[0]
    $uri += "&host=" + $hstParam
    $uri += "&segments=" + $segParam + "," + $verID
    $uri += "&query="
    $uri += "&action=" + $actIDs[0]
    $uri += "&sessionId=" + $sessionID
    $uri += "&productEditionId=" + $prodID
    $uri += "&sdvParam=" + $sdvParam

    # requests user session
    $response = Invoke-WebRequest -UserAgent $userAgent -WebSession $session -Uri $uri -UseBasicParsing

    # prefered skuid
    if ($Version = "Latest") {
        # grabs latest id
        $skuIDs = (($response.RawContent) -replace "&quot;" -replace '</div><script language=.*' -replace  '</select></div>.*' -split '<option value="' -replace '">.*' -replace '{' -replace '}'| Select-String -pattern 'id:') -replace 'id:' -replace 'language:' -replace '\s' | ConvertFrom-String -PropertyNames SkuID, Language -Delimiter ','
        $skuID = $skuIDs | Where-Object {$_.Language -eq "$Language"} | Select-Object -ExpandProperty SkuID
    }
    else{
        # uses hard-coded id
        $skuID = "9029"
    } 

    # builds link request url
    $uri = "https://www.microsoft.com/" + $Locale + "/api/controls/contentinclude/html"
    $uri += "?pageId=" + $pgeIDs[1]
    $uri += "&host=" + $hstParam
    $uri += "&segments=" + $segParam + "," + $verID
    $uri += "&query="
    $uri += "&action=" + $actIDs[1]
    $uri += "&sessionId=" + $sessionID
    $uri += "&skuId=" + $skuID
    $uri += "&lang=" + $Language
    $uri += "&sdvParam=" + $sdvParam

    # requests link data
    $response = Invoke-WebRequest -UserAgent $userAgent -WebSession $session -Uri $uri -UseBasicParsing

    # parses response data 
    $raw = ($response.Links).href
    $clean = $raw.Replace('amp;','')

    # stores download link
    $dlLink = $clean | Where-Object {$_ -like "*$archID*"}

    # outputs download link
    Write-Output $dlLink
}

function Start-Win10ISODownload {
    param (
        [String] $Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture,
        [String] $Version = "2009",
        $DownloadPath
    )

    Write-Verbose "Attempting to generate a $Architecture windows 10 iso download link" -Verbose
    try {
        $DownloadLink = Get-Win10ISOLink -Architecture $Architecture -Version $Version
    }
    catch {
        throw "Failed to generate windows 10 iso download link."
    }
    
    Write-Verbose "Attempting to download windows 10 iso to '$DownloadPath'" -Verbose
    try {
        $Split = $DownloadPath.Split("\\")
        New-Item -Path $(([string]$split[0..($Split.count-2)]) -replace(" ","\")) -ItemType Directory -Force | Out-Null
        
        if (Test-Path -Path $DownloadPath) {
            $ISO = Get-Item $DownloadPath
            If ($ISO.Length -ne $((Invoke-WebRequest $DownloadLink -Method Head -UseBasicParsing).Headers.'Content-Length')) {
                Remove-Item $DownloadPath -Force
                (New-Object System.Net.WebClient).DownloadFile($DownloadLink, "$DownloadPath")
            }
        } else {
            (New-Object System.Net.WebClient).DownloadFile($DownloadLink, "$DownloadPath")
        }
    }
    catch {
        throw "Failed to download ISO at path specified."
    }
}

function Start-Win10UpgradeISO {
    <#
    .SYNOPSIS
        Downloads the latest Windows 10 ISO, mounts it, and runs it silently.
    .NOTES
        Version:        1.1
        Author:         Andy Escolastico
        Creation Date:  02/11/2020
        
        Version 1.0 (2020-02-11)
        Version 1.1 (2020-06-03) - Added handling for case where drive letter was not mounted.                
        Version 1.2 (2020-06-03) - Added ISO download functionality
    #>
    [CmdletBinding()]
    param (
        #THIS FLAG DOES NOT WORK FOR THIS FUNCTION
        [Parameter(Mandatory=$false)] 
        [Boolean] $Reboot = $true,
        [Parameter(Mandatory=$false)] 
        [ValidateSet("64-bit", "32-bit")]
        [String] $Architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture,
        [Parameter(Mandatory=$false)] 
        [String] [String] $DLPath = (Get-Location).Path + "\" +"Win10_" + $Architecture + ".iso",
        [Parameter(Mandatory=$false)] 
        [String] $LogPath = $((Split-Path $DLPath) + "\Win10_Upgrade.log"),
        [Parameter(Mandatory=$false)]
        [String] $Version = "2009",
        [switch] $DynamicUpdates
    )
    
    Write-Verbose "Cleaning up any previous Windows 10 updates" -Verbose
    CleanPreviousUpdate
    
    Write-Verbose "Attempting to download windows 10 iso to '$DLPath'" -Verbose
    try {
        Start-Win10ISODownload -Version $Version -DownloadPath $DLPath
    }
    catch {
        throw "Failed to Download Windows 10 iso."
    }
    
    $ISOPath = $DLPath
    $ISOMounted = Get-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue
    
    if (Test-Path $ISOPath) {
        if ($ISOMounted.Attached -eq $true) {
            $DriveLetter = (Get-DiskImage -ImagePath $ISOPath | Get-Volume).DriveLetter
        } else {
            Remove-FileLock -LockFile $ISOPath
            Start-Sleep -Seconds 10
            Mount-DiskImage -ImagePath $ISOPath | Out-Null
            #Start-Sleep -Seconds 5
            
            $timeout = New-TimeSpan -Minutes 1
            $stopwatch = [diagnostics.stopwatch]::StartNew()
            do {
                $DriveLetter = (Get-DiskImage -ImagePath $ISOPath -ErrorAction SilentlyContinue | Get-Volume).DriveLetter
                #Close explorer popup
                $locationurl = 'file:///' + $driveletter + ':/'
                $shell = New-Object -ComObject Shell.Application
                $window = $shell.Windows() | Where-Object {$_.LocationURL -eq $locationurl}
                if ($window) {
                    $window.Quit()
                }
                #Sleep and try again
                Start-Sleep -Seconds 1
            } until ($DriveLetter -or $stopwatch.elapsed -gt $timeout)
        }
    } else {
        throw "ISO could not be found under $($ISOPath)."
    }
    
    Write-Warning "The Upgrade will commence shortly. Your PC will be rebooted soon. Please save any work you do not want to lose."
    
    if ($DynamicUpdates -eq $true) {
        $DynamicUpdate = "enable"
    } else {
        $DynamicUpdate = "disable"
    }

    if ($DriveLetter) {
        if ($Reboot -eq $true){
            Write-Output "$($DriveLetter):\setup.exe /auto upgrade /migratedrivers all /showoobe none /compat ignorewarning /dynamicupdate $DynamicUpdate /copylogs $LogPath"
            Invoke-Expression "$($DriveLetter):\setup.exe /auto upgrade /migratedrivers all /showoobe none /compat ignorewarning /dynamicupdate $DynamicUpdate /copylogs $LogPath"
        } else{
            Invoke-Expression "$($DriveLetter):\setup.exe /auto upgrade /migratedrivers all /showoobe none /noreboot /compat ignorewarning /dynamicupdate $DynamicUpdate /copylogs $LogPath"
        }    
    } else {
        throw "ISO could not be mounted on this system."
    }

}
New-Alias -Name "Start-Win10FeatureUpdate" -Value "Start-Win10UpgradeISO" -ea 0

function Start-Win10UpgradeWUA {
    <#
    .SYNOPSIS
        This function downloads the Windows update assistant tool and runs it silently.
    .NOTES
        Version:        1.0
        Author:         Andy Escolastico
        Creation Date:  05/10/2020
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] 
        [Boolean] $Reboot = $true,
        #THIS FLAG DOES NOT WORK FOR THIS FUNCTION
        [Parameter(Mandatory=$false)] 
        [String] $DLPath = (Get-Location).Path,
        [Parameter(Mandatory=$false)] 
        [String] $LogPath = "$DLPath\Log"
    )
    if(!(Test-Path -Path $DLPath)){$null = New-Item -ItemType directory -Path $DLPath -Force}   
    if(!(Test-Path -Path $LogPath)){$null = New-Item -ItemType directory -Path $LogPath -Force}      
    $DLLink = "https://go.microsoft.com/fwlink/?LinkID=799445"
    $PackagePath = "$DLPath\Win10_WUA.exe"
    $LogPath = "$LogPath\Win10_WUA.log"
    (New-Object System.Net.WebClient).DownloadFile($DLLink, "$PackagePath")
    Write-Host "The Upgrade will commence shortly. Your PC will be rebooted. Please save any work you do not want to lose."
    if ($Reboot -eq $true){
        Invoke-Expression "$PackagePath /copylogs $LogPath /auto upgrade /dynamicupdate /compat ignorewarning enable /skipeula /quietinstall"
    } else{
        Invoke-Expression "$PackagePath /NoReboot /NoRestartUI /NoRestart /copylogs $LogPath /auto upgrade /dynamicupdate /compat ignorewarning enable /skipeula /quietinstall"
    }
}

function Start-Win10UpgradeCAB{
    <#
    .SYNOPSIS
        This function downloads the feature enablement package cab file and runs it silently using dism.exe.
    .NOTES
        Version:        1.0
        Author:         Andy Escolastico
        Creation Date:  06/11/2020
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)] 
        [ValidateSet("1909")]
        [String] $Version = "1909",
        [Parameter(Mandatory=$false)] 
        [Boolean] $Reboot = $true,
        [Parameter(Mandatory=$false)]
        [String] $DLPath = (Get-Location).Path,
        [Parameter(Mandatory=$false)] 
        [String] $LogPath = (Get-Location).Path
    )
    if(!(Test-Path -Path $DLPath)){$null = New-Item -ItemType directory -Path $DLPath -Force}   
    if(!(Test-Path -Path $LogPath)){$null = New-Item -ItemType directory -Path $LogPath -Force}    
    if($Version -eq "1909"){
        $DLLink = 'http://b1.download.windowsupdate.com/d/upgr/2019/11/windows10.0-kb4517245-x64_4250e1db7bc9468236c967c2c15f04b755b3d3a9.cab'
    }
    $PackagePath = "$DLPath\Win10_CAB.cab"
    $LogPath = "$LogPath\Win10_CAB.log"
    (New-Object System.Net.WebClient).DownloadFile($DLLink, "$PackagePath")
    if ($Reboot -eq $true){
        Invoke-Expression "DISM.exe /Online /Add-Package /Quiet /PackagePath:$PackagePath /LogPath:$LogPath"
    } else{
        Invoke-Expression "DISM.exe /Online /Add-Package /Quiet /NoRestart /PackagePath:$PackagePath /LogPath:$LogPath"
    }
}
