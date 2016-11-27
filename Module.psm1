<#
    Avanade.KuduTools
#>

#region Helpers

function ConvertCredentialToBasicAuth
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [pscredential[]]
        $Credential
    )
    begin 
    {

    }
    
    process 
    {
        foreach ($item in $Credential)
        {
            $AuthInfo="$($item.UserName):$($item.GetNetworkCredential().Password)"
            $BasicCredential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthInfo))
            Write-Output $BasicCredential
        }
    }
    
    end 
    {

    }
}

function GetKuduResult
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $Uri,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }    
    $KuduResult=Invoke-RestMethod -Uri $Uri -Headers $Headers -ContentType 'application/json' -ErrorAction Stop
    return $KuduResult
}

function PostKuduResult
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Body,
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $Uri,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }    
    $KuduResult=Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/json' -Method Post -ErrorAction Stop
    return $KuduResult
}

function PostKuduFile
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $Path,
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $Uri,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }    
    Invoke-RestMethod -Uri $Uri -Headers $Headers -InFile $Path -ContentType "multipart/form-data" -Method Post -UserAgent "powershell/avanade" -ErrorAction Stop    
}

#endregion

function ConvertTo-KuduConnection 
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Uri[]]
        $Uri
    )
    begin
    {
    }
    process
    {
        foreach ($item in $Uri) 
        {
            $UserName=$item.UserInfo.Split(':')|Select-Object -First 1
            $Password=$item.UserInfo.Split(':')|Select-Object -Last 1
            $KuduConnection=New-Object PSObject -Property @{
                ScmEndpoint=[Uri]"$($item.Scheme)://$($item.Host)";
                Credential=New-Object pscredential($UserName,($Password|ConvertTo-SecureString -AsPlainText -Force));
            }
            Write-Output $KuduConnection
        }
    }
    end
    {
    }
}

function Get-KuduProcess 
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken,         
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [int[]]
        $Id,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Name        
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/processes"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken    
    }
    if ($Id -ne $null)
    {
        foreach ($i in $Id)
        {
            $SpecificProcess=$KuduResult | Where-Object {$_.id -EQ $i} | Select-Object -First 1
            if ($SpecificProcess -ne $null) {
                Write-Output $SpecificProcess
            }
        }
    }
    elseif ($Name -ne $null)
    {
        foreach ($n in $Name)
        {
            $SpecificProcess=$KuduResult | Where-Object {$_.name -EQ $n} | Select-Object -First 1
            if ($SpecificProcess -ne $null) {
                Write-Output $SpecificProcess
            }
        }
    }
    else
    {
        Write-Output $KuduResult
    }
}

function Get-KuduProcessMinidump
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken,         
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [int[]]
        $Id
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    foreach ($item in $Id)
    {
        $KuduUriBld.Path="api/processes/$item"
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

function Get-KuduRuntimeVersions
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/diagnostics/runtime"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
        return GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    return GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
}

function Get-KuduSourceControlInfo
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/scm/info"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        return GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    return GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
}

function Get-KuduEnvironment
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/environment"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
        return GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    return GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
}

function Get-KuduSetting
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Name,       
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/enviroment"
    if ($Name -ne $null)
    {
        foreach ($item in $Name)
        {
            $KuduUriBld.Path="api/enviroment/$item"
            if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
                $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
            }
            else
            {
                $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
            }
            Write-Output $KuduResult            
        }
    }
    else
    {
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else
        {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

function Get-KuduDeployment
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Id,       
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/deployments"
    if($Id -ne $null)
    {
        foreach ($item in $Id)
        {
            $KuduUriBld.Path="api/deployments/$item"
            if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
                $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
            }
            else {
                $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
            }
            Write-Output $KuduResult
        }
    }
    else
    {
        $KuduUriBld.Path="api/deployments"
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

function Get-KuduDeploymentLog
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Id,       
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    foreach ($item in $Id) {
        $KuduUriBld.Path="api/deployments/$item/log"
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

function Get-KuduDiagnosticSetting
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Name,       
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/diagnostics/settings"
    if ($Name -ne $null)
    {
        foreach ($item in $Name)
        {
            $KuduUriBld.Path="api/diagnostics/settings/$item"
            if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
                $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
            }
            else {
                $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
            }
            Write-Output $KuduResult            
        }
    }
    else
    {
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

function Get-KuduRecentLog
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [ValidateRange(1,1000)]
        [int]
        $Top,       
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/logs/recent"
    if ($Top -gt 0) {
        $KuduUriBld.Query="top=$Top"
    }
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
}

function Get-KuduWebJob
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $Triggered,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $Continuous,               
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    if ($Triggered.IsPresent) {
        $KuduUriBld.Path="api/triggeredwebjobs"
    }
    elseif ($Continuous.IsPresent) {
        $KuduUriBld.Path="api/continuouswebjobs"
    }
    else {
        $KuduUriBld.Path="api/webjobs"
    }    
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
}

function Save-KuduDump
{
    [CmdletBinding()]
    param
    (   
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Destination=$env:TEMP,             
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    if ((Test-Path -Path $Destination) -eq $false) {
        throw "$Destination does not exist."
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/dump"
    $FileName="$($KuduUriBld.Host)-$(Get-Date -Format "hh_mm_ss-dd_MM_yyyy")-dump.zip"
    $OutFile=Join-Path $Destination $FileName
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }
    $Result=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -OutFile $OutFile -UseBasicParsing -ErrorAction Stop  
}

function Invoke-KuduCommand
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Command,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Directory='SystemDrive/Windows/System32',             
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/command"
    $CommandToRun=New-Object PSObject -Property @{
        command=$Command;
        dir=$Directory;
    }    
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        return PostKuduResult -Uri $KuduUriBld.Uri -Credential $Credential -Body ($CommandToRun|ConvertTo-Json)
    }
    return PostKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken -Body ($CommandToRun|ConvertTo-Json)
}

function Get-KuduVfsChildItem
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Path='/',
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $Recurse,             
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $AccessToken  
    )
    $VfsItems=@()
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/vfs/$($Path.TrimEnd('/'))/"
    try 
    {
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        if ($KuduResult -ne $null -and $Recurse.IsPresent)
        {
            foreach ($item in $KuduResult)
            {
                $VfsItems+=$item
                if ($item.mime -in "inode/directory","inode/shortcut")
                {
                    $ItemUri=New-Object System.Uri($item.href.ToLower())
                    $SubPath=$ItemUri.AbsolutePath.Replace("/api/vfs/",[String]::Empty)
                    if ($SubPath -ne "systemdrive/") {
                        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
                            $VfsItems+=Get-KuduVfsChildItem -Path $SubPath -ScmEndpoint $ScmEndpoint -Credential $Credential -Recurse
                        }
                        else {
                            $VfsItems+=Get-KuduVfsChildItem -Path $SubPath -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken -Recurse
                        }
                    }
                }
            }            
        }
        else
        {
            $VfsItems=$KuduResult    
        }
    }
    catch [System.Exception] {
        Write-Warning "[Get-KuduVfsChildItem] $ScmEndpoint $_"
    }
    return $VfsItems
}

function Copy-KuduVfsItem
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Path,        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Destination,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $Recurse,             
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $ScmEndpoint,     
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $AccessToken  
    )
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/vfs/$($Destination.TrimEnd('/'))/"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        PostKuduFile -Path $Path -Uri $KuduUriBld.Uri -Credential $Credential  
    }
    else {
        PostKuduFile -Path $Path -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    
}