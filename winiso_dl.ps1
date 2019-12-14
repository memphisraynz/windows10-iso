function Get-Win10ISOLink {
    <#
    .SYNOPSIS
        This script generates a fresh download link for a windows iso
    .INPUTS
        Prefered Architecture 
    .OUTPUTS
        Windows 10 ISO download link    
    .NOTES
        Version:        1.0
        Author:         Andy Escolastico
        Creation Date:  10/11/2019
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)] 
        [ValidateSet("64bit", "32bit")]
        [String] $Architecture 
    )
    
    # variables you might want to change
    $lang = "English"
    $locID = "en-US"
    $verID = "Windows10ISO"
    $skuID = "8829"
    $prodID = "1384"

    # prefered architecture
    if ($Architecture -eq "64bit"){ $archID = "IsoX64" } else { $archID = "IsoX86" }

    # variables you might not want to change (unless msft changes their schema)
    $pgeIDs = @("a8f8f489-4c7f-463a-9ca6-5cff94d8d041", "cfa9e580-a81e-4a4b-a846-7b21bf4e2e5b")
    $actIDs = @("getskuinformationbyproductedition", "getproductdownloadlinksbysku")
    $hstParam = "www.microsoft.com"
    $segParam = "software-download"
    $sdvParam = "2"

    # used to spoof a non-windows web request
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362"

    # used to maintain session in subsequent requests
    $sessionID = [GUID]::NewGuid()

    # builds session request url 
    $uri = "https://www.microsoft.com/" + $locID + "/api/controls/contentinclude/html"
    $uri += "?pageId=" + $pgeIDs[0]
    $uri += "&host=" + $hstParam
    $uri += "&segments=" + $segParam + "," + $verID
    $uri += "&query="
    $uri += "&action=" + $actIDs[0]
    $uri += "&sessionId=" + $sessionID
    $uri += "&productEditionId=" + $prodID
    $uri += "&sdvParam=" + $sdvParam

    # requests user session
    $null = Invoke-WebRequest -UserAgent $userAgent -WebSession $session $uri

    # builds link request url
    $uri = "https://www.microsoft.com/" + $locID + "/api/controls/contentinclude/html"
    $uri += "?pageId=" + $pgeIDs[1]
    $uri += "&host=" + $hstParam
    $uri += "&segments=" + $segParam + "," + $verID
    $uri += "&query="
    $uri += "&action=" + $actIDs[1]
    $uri += "&sessionId=" + $sessionID
    $uri += "&skuId=" + $skuID
    $uri += "&lang=" + $lang
    $uri += "&sdvParam=" + $sdvParam

    # requests link data
    $response = Invoke-WebRequest -UserAgent $userAgent -WebSession $session $uri

    # parses response data 
    $raw = ($response.AllElements | Where-Object {$_.tagname -eq "input"}).value
    $json = $raw.Replace(',"DownloadType": IsoX64',',"DownloadType": "IsoX64"')
    $json = $json.Replace(',"DownloadType": IsoX86',',"DownloadType": "IsoX86"')
    $objs = $json | ConvertFrom-Json
    $objs | Foreach-Object {$_.Uri = ($_.Uri).Replace('amp;','')}

    # stores download link
    $dlLink = $objs | Where-Object {$_.DownloadType -eq $archID} | Select-Object -ExpandProperty Uri

    # outputs download link
    Write-Output $dlLink
}
