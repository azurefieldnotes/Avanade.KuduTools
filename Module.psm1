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

function InvokeKuduResult
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Body,
        [Parameter(Mandatory=$true,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [uri]
        $Uri,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [ValidateSet('GET','PUT','POST','DELETE')]
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
    if ([String]::IsNullOrEmpty($Body) -eq $false) {
        $KuduResult=Invoke-RestMethod -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/json' -Method $Method -ErrorAction Stop
    }
    else {
        $KuduResult=Invoke-RestMethod -Uri $Uri -Headers $Headers -ContentType 'application/json' -Method $Method -ErrorAction Stop
    }
    if ($KuduResult -ne $null) {
        Write-Output $KuduResult
    }
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

<#
    .SYNOPSIS
        Converts a publishing Uri to a Kudu credential
    .PARAMETER Uri
        The publishing Uri from the Azure Website resource
#>
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

<#
    .SYNOPSIS
        Returns process details for the Website
    .PARAMETER Id
        The process id
    .PARAMETER Name
        The process name
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        $KuduResult=InvokeKuduResult -Method GET -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=InvokeKuduResult -Method GET -Uri $KuduUriBld.Uri -AccessToken $AccessToken    
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

<#
    .SYNOPSIS
        Returns a mini dump for the specified process
    .PARAMETER Id
        The process id
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        
            $KuduResult=InvokeKuduResult -Method GET -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=InvokeKuduResult -Method GET -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

<#
    .SYNOPSIS
        Returns a list of the runtime versions
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        
        $KuduResult=InvokeKuduResult -Method GET -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=InvokeKuduResult -Method GET -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
}

<#
    .SYNOPSIS
        Returns source control info for the Website
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
}

<#
    .SYNOPSIS
        Clears the Website's associated source control repository
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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

<#
    .SYNOPSIS
        Removes the Website's associated source control repository    
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        InvokeKuduResult -Method Delete -Uri $KuduUriBld.Path -Credential $Credential
    }
    else {
        InvokeKuduResult -Method Delete -Uri $KuduUriBld.Path -AccessToken $AccessToken
    }
}

<#
    .SYNOPSIS
        Returns the current Kudu runtime environment details
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
}

<#
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
                $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
            }
            else
            {
                $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
            }
            Write-Output $KuduResult            
        }
    }
    else
    {
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else
        {
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

<#
    .SYNOPSIS
        Retrieves the Website deployments
    .PARAMETER Id
        The deployment id
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        
                $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
            }
            else {
                $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
            }
            Write-Output $KuduResult
        }
    }
    else
    {
        $KuduUriBld.Path="api/deployments"
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

<#
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
function Start-KuduDeployment
{
    [CmdletBinding()]
    param
    (        
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [string]
        $Id,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $Clean,
        [Parameter(Mandatory=$false,ParameterSetName='ByCredential',ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$false,ParameterSetName='ByToken',ValueFromPipelineByPropertyName=$true)]
        [Switch]
        $CheckOut,                       
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
    if ([String]::IsNullOrEmpty($Id) -eq $false) {
        $KuduUriBld.Path="api/deployments/$Id"
    }
    else {
        $KuduUriBld.Path="api/deployments/$Id"
    }
    if ($Clean.IsPresent -or $CheckOut.IsPresent) {
        $PayloadProps=@{}
        if ($Clean.IsPresent) {
            $PayloadProps.Add('clean',$true)
        }
        if ($CheckOut.IsPresent) {
            $PayloadProps.Add('needFileUpdate',$true)
        }
        $Payload=New-Object PSObject -Property $PayloadProps
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
            InvokeKuduResult -Method PUT -Uri $KuduUriBld.Uri -Body ($Payload|ConvertTo-Json) -Credential $Credential
        }
        else {
            InvokeKuduResult -Method PUT -Uri $KuduUriBld.Uri -Body ($Payload|ConvertTo-Json) -AccessToken $AccessToken
        }
    }
    else {
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
            InvokeKuduResult -Method PUT -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            InvokeKuduResult -Method PUT -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }        
    }
    
}

<#
    .SYNOPSIS
        Retrieves a deployment log for the specified deployment id
    .PARAMETER Id
        The deployment id
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

<#
    .SYNOPSIS
        Retrieves the specified diagnostic setting value
    .PARAMETER Name
        The diagnostic setting name
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        
                $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
            }
            else {
                $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
            }
            Write-Output $KuduResult            
        }
    }
    else
    {
        if ($PSCmdlet.ParameterSetName -eq 'ByCredential') {
        
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
        }
        Write-Output $KuduResult
    }
}

<#
    .SYNOPSIS
        Returns the recent log entries for the Website
    .PARAMETER Top
        Limits the results to the specified count
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
}

<#
    .SYNOPSIS
        Returns the list of web jobs
    .PARAMETER Triggered
        Return the triggered web jobs
    .PARAMETER Continuous
        Return the continuous web jobs        
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
    }
    else {
        $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
    }
    Write-Output $KuduResult
}

<#
    .SYNOPSIS
        Downloads a Kudu summary dump
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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

<#
    .SYNOPSIS
        Invokes the specified command on the Web server
    .PARAMETER Command
        The command to execute
    .PARAMETER Directory
        The starting directory for the command
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
        $KuduResult=InvokeKuduResult -Uri $KuduUriBld.Uri -AccessToken $AccessToken -Body ($CommandToRun|ConvertTo-Json)
    }
    Write-Output $KuduResult
}

<#
    .SYNOPSIS
        Enumerates the child items within the specified VFS path
    .PARAMETER Path
        The path to evaluate
    .PARAMETER Recurse
        Whether to recurse the current path
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -Credential $Credential
        }
        else {
            $KuduResult=InvokeKuduResult -Method Get -Uri $KuduUriBld.Uri -AccessToken $AccessToken
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

<#
    .SYNOPSIS
        Downloads the specified VFS item
    .PARAMETER Path
        The VFS path to download
    .PARAMETER Destination
        The destination path for the downloaded file
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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

<#
    .SYNOPSIS
        Downloads the specified VFS path as a zip file
    .PARAMETER Path
        The VFS path to download
    .PARAMETER Destination
        The destination path for the downloaded file
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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

<#
    .SYNOPSIS
        Expands a zip file to the Kudu VFS
    .PARAMETER Path
        The path to the zip file to upload and expand
    .PARAMETER Destination
        The VFS destination path to extract the zip
    .PARAMETER ScmEndpoint
        The Azure Website SCM Endpoint
    .PARAMETER Credential
        The Kudu Website publishing credential
    .PARAMETER AccessToken
        An appropriate OAuth Bearer token
#>
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