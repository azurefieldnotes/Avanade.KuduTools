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
    Write-Verbose "ParameterSetName=$($PSCmdlet.ParameterSetName)"
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
    Write-Verbose "ParameterSetName=$($PSCmdlet.ParameterSetName)"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }    
    $KuduResult=Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/json' -Method Post -ErrorAction Stop
    return $KuduResult
}

function DeleteKuduResult
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
    Write-Verbose "ParameterSetName=$($PSCmdlet.ParameterSetName)"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }    
    $KuduResult=Invoke-RestMethod -Uri $Uri -Headers $Headers -ContentType 'application/json' -Method Delete -ErrorAction Stop
    return $KuduResult
}

function UploadKuduFile
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
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('GET','PUT','POST')]
        [string]
        $Method='POST',              
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $AccessToken  
    )
    Write-Verbose "ParameterSetName=$($PSCmdlet.ParameterSetName)"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }    
    Invoke-RestMethod -Uri $Uri -Headers $Headers -InFile $Path -ContentType "multipart/form-data" -Method $Method -UserAgent "powershell/avanade" -ErrorAction Stop    
}

function SaveKuduFile
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $OutFile,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('GET','PUT','POST')]
        [string]
        $Method='GET',  
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
    Write-Verbose "ParameterSetName=$($PSCmdlet.ParameterSetName)"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        $Headers=@{Authorization="Basic $($Credential|ConvertCredentialToBasicAuth)"}
    }
    else {
        $Headers=@{Authorization="Bearer $AccessToken"}
    }
    $Result=Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method -OutFile $OutFile -UseBasicParsing -ErrorAction Stop
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
    #region Process Results
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
    #endregion
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
        
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
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

function Clear-KuduSourceControlRepository
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
    $KuduUriBld.Path="api/scm/clean"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        PostKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        PostKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
}

function Remove-KuduSourceControlRepository
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
    $KuduUriBld.Path="api/scm"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        DeleteKuduResult -Uri $KuduUriBld.Path -Credential $Credential
    }
    else {
        DeleteKuduResult -Uri $KuduUriBld.Path -AccessToken $AccessToken
    }   
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
        
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=GetKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
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
    foreach ($item in $Id)
    {
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
        SaveKuduFile -Uri $KuduUriBld.Uri -OutFile $OutFile -Credential $Credential -Method GET
    }
    else {
        SaveKuduFile -Uri $KuduUriBld.Uri -OutFile $OutFile -AccessToken $AccessToken -Method GET
    }  
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
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential')
    {
        $KuduResult=PostKuduResult -Uri $KuduUriBld.Uri -Credential $Credential -Body ($CommandToRun|ConvertTo-Json)
    }
    else 
    {
        $KuduResult=PostKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken -Body ($CommandToRun|ConvertTo-Json)
    }
    Write-Output $KuduResult
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
                Write-Output $item
                if ($item.mime -in "inode/directory","inode/shortcut")
                {
                    $ItemUri=New-Object System.Uri($item.href.ToLower())
                    $SubPath=$ItemUri.AbsolutePath.Replace("/api/vfs/",[String]::Empty)
                    if ($SubPath -ne "systemdrive/") {
                        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
                            $VfsResult=Get-KuduVfsChildItem -Path $SubPath -ScmEndpoint $ScmEndpoint -Credential $Credential -Recurse
                        }
                        else {
                            $VfsResult=Get-KuduVfsChildItem -Path $SubPath -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken -Recurse
                        }
                        if ($VfsResult -ne $null) {
                            Write-Output $VfsResult
                        }
                    }
                }
            }            
        }
        else
        {
            Write-Output $KuduResult    
        }
    }
    catch [System.Exception] {
        Write-Warning "[Get-KuduVfsChildItem] $ScmEndpoint $_"
    }
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
        UploadKuduFile -Path $Path -Uri $KuduUriBld.Uri -Credential $Credential -Method POST  
    }
    else {
        UploadKuduFile -Path $Path -Uri $KuduUriBld.Uri -AccessToken $AccessToken -Method POST
    }
    
}

function Compress-KuduPath
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string[]]
        $Path,
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [String]
        $Destination,             
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
    $KuduBriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
    $OutFile=Join-Path $Destination "$($KuduUriBld.Host)-$($Path.Replace("/","_")).zip"
    foreach ($item in $Path)
    {
        $KuduBriBld.Path="api/zip/$($item.TrimEnd('/'))/"
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
            SaveKuduFile -OutFile $OutFile -Uri $KuduBriBld.Uri -Method GET -Credential $Credential
        }
        else {
            SaveKuduFile -OutFile $OutFile -Uri $KuduBriBld.Uri -Method GET -AccessToken $AccessToken
        }
    }
}

function Expand-KuduVfsZipFile
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
        [String]
        $Destination,             
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
    $KuduBriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
    $KuduBriBld.Path="api/zip/$($Path.TrimEnd('/'))"
    if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        UploadKuduFile -Path $Path -Uri $KuduBriBld.Uri -Method PUT -Credential $Credential
    }
    else {
        UploadKuduFile -Path $Path -Uri $KuduBriBld.Uri -Method PUT -AccessToken $AccessToken
    }    
}