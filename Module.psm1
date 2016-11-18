<#
    Avanade.KuduTools
#>

Function GetKuduHeaders
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (   
        [Parameter(Mandatory=$true,ParameterSetName='AAD',ValueFromPipeline=$true)]
        [System.String[]]
        $AccessToken,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential       
    )

    BEGIN
    {

    }
    PROCESS
    {
        if ($PSCmdlet.ParameterSetName -eq 'AAD') {
            foreach ($token in $AccessToken) {
                $AadHeader=@{'Authorization'="Bearer $AccessToken"}
                Write-Output $AadHeader
            }
            
        }
        else {
            if ($PSCmdlet.ParameterSetName -eq 'PublishingCredential') {
                foreach ($cred in $PublishingCredential) {
                    $PublishingUsername+=$PublishingCredential.properties.publishingUserName
                    $PublishingSecret+=$PublishingCredential.properties.publishingPassword
                }
            }
            for ($i = 0; $i -lt $PublishingUsername.Count; $i++) {
                $AuthInfo="$($PublishingUsername[$i]):$($PublishingSecret[$i])"
                $BasicCredential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthInfo))
                $BasicHeader=@{'Authorization'="Basic $BasicCredential"}
                Write-Output $BasicHeader
            }
        }
    }
    END
    {

    }
}

Function GetKuduUri
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential
    )
    BEGIN
    {

    }
    PROCESS
    {
        foreach ($item in $PublishingCredential) {
            [Uri]$PcUriBld=$PublishingCredential.properties.scmUri
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host)/$($PcUriBld.PathAndQuery)")
            Write-Output $ScmEndpoint            
        }
    }
    END
    {

    }
}

Function GetKuduConnection
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (   
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,        
        [Parameter(Mandatory=$true,ParameterSetName='AAD',ValueFromPipeline=$true)]
        [System.String[]]
        $AccessToken,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential       
    )
    BEGIN
    {
        $HeaderCollection=@()   
    }
    PROCESS
    {
        if ($PSCmdlet.ParameterSetName -eq 'AAD') {
            if ($ScmEndpoint.Count -ne $AccessToken.Count) {
                throw "The parameters are not congruent"    
            }
            foreach ($tok in $AccessToken) {
                $HeaderCollection+=@{Authorization="Bearer $tok"}
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'basic') {
            if (($ScmEndpoint.Count -ne $PublishingUsername.Count) `
                -or ($ScmEndpoint.Count -ne $PublishingSecret.Count)) {
                    throw "The parameters are not congruent"
            }
            for ($i = 0; $i -lt $ScmEndpoint.Count; $i++) {
                $AuthInfo="$($PublishingUsername[$i]):$($PublishingSecret[$i])"
                $BasicCredential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthInfo))
                $HeaderCollection+=@{'Authorization'="Basic $BasicCredential"}                    
            }
        }
        else {
            foreach ($item in $PublishingCredential) {
                $AuthInfo="$($item.properties.publishingUserName):$($item.properties.publishingPassword)"
                $BasicCredential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthInfo))
                $HeaderCollection+=@{'Authorization'="Basic $BasicCredential"}
                [Uri]$PcUriBld=$item.properties.scmUri
                $ScmEndpoint+=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host)/$($PcUriBld.PathAndQuery)")                                        
            }
        }
        for ($i = 0; $i -lt $ScmEndpoint.Count; $i++) {
            $KuduConn=New-Object psobject -Property @{
                Headers=$HeaderCollection[$i];
                ScmEndpoint=$ScmEndpoint[$i];
            }
            Write-Output $KuduConn
        }
    }
    END
    {

    }
}

#Processes
#api/processes
Function Get-KuduProcess
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD',ValueFromPipeline=$true)]
        [System.String[]]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential,        
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.Int32[]]
        $ProcessId,
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.String[]]
        $ProcessName
    )

    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections) {
            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path+="/api/processes"
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType "application/json" -ErrorAction Stop
                if ($ProcessId.Count -gt 0) {
                    foreach ($pid in $ProcessId) {
                        if ($pid -gt 0) {
                            $SpecificProcess=$KuduResult | Where-Object {$_.id -EQ $pid} | Select-Object -First 1
                            if ($SpecificProcess -ne $null) {
                                Write-Output $SpecificProcess
                            }
                        }
                    }
                }
                elseif($ProcessName.Count -gt 0){
                    foreach ($pName in $ProcessName) {
                        if ([String]::IsNullOrEmpty($pName) -eq $false) {
                            $SpecificProcess=$KuduResult | Where-Object {$_.name -EQ $pName}
                            if ($SpecificProcess -ne $null) {
                                Write-Output $SpecificProcess
                            }
                        }
                    }
                }
                else {
                    Write-Output $KuduResult
                }
            }
            catch [System.Exception]
            {
                Write-Warning "$($KuduConnection.ScmEndpoint) $_"
            }
        }
    }
    END
    {

    }
}

#api/processes


#api/diagnostics/runtime
Function Get-KuduRuntimeVersions
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD',ValueFromPipeline=$true)]
        [System.String[]]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential       
    )

    switch ($PSCmdlet.ParameterSetName) {
        'basic' { 
            $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
        }
        'AAD' {
            $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
        }
        'PublishingCredential' {
            $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
        }
    }

    foreach ($KuduConnection in $KuduConnections)
    {
        try
        {
            $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
            $KuduUriBld.Path="api/diagnostics/runtime"
            $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType "application/json" -ErrorAction Stop
            Write-Output $KuduResult
        }
        catch [System.Exception]
        {
            Write-Warning "$($KuduConnection.ScmEndpoint) $_"
        }
    }

}

#/api/scm/info
Function Get-KuduSourceControlInfo
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD',ValueFromPipeline=$true)]
        [System.String[]]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential       
    )

    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections) {

            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="api/scm/info"
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType "application/json" -ErrorAction Stop
                Write-Output $KuduResult
            }
            catch [System.Exception]
            {
                Write-Warning "$($KuduConnection.ScmEndpoint) $_"
            }
        }
    }
    END
    {

    }
}

#api/environment
Function Get-KuduEnvironment
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential       
    )
    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections) {

            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="api/environment"
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType "application/json" -ErrorAction Stop
                Write-Output $KuduResult
            }
            catch [System.Exception]
            {
                Write-Warning "$($KuduConnection.ScmEndpoint) $_"
            }
        }
    }
    END
    {

    }
}

#api/settings
Function Get-KuduSetting
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.String]
        $Setting,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,    
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential  
    )
    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections) {

            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="/api/settings"
                if ([String]::IsNullOrEmpty($Setting) -eq $false) {
                    $KuduUriBld.Path+="/$Setting"
                }
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType "application/json" -ErrorAction Stop
                Write-Output $KuduResult
            }
            catch [System.Exception]
            {
                Write-Warning "$($KuduConnection.ScmEndpoint) $_"
            }
        }
    }
    END
    {

    }
}

#api/deployments
Function Get-KuduDeployment
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential',ValueFromPipeline=$false)]
        [System.String]
        $DeploymentId,        
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,    
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken
    )
    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {           
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {           
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections)
        {
            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="api/deployments"
                if ([String]::IsNullOrEmpty($DeploymentId) -eq $false) {
                    $KuduUriBld.Path="api/deployments/$($DeploymentId)" 
                }
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType "application/json" -ErrorAction Stop
                Write-Output $KuduResult             
            }
            catch [System.Exception]
            {
                Write-Warning "$($KuduUriBld.Uri) $_"
            }            
        }
    }
    END
    {

    }
}

#VFS
#/api/vfs
Function Get-KuduVfsChildItem
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri]
        $ScmEndpoint,
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.String]
        $Path,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String]
        $PublishingSecret,        
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential,
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [Switch]
        $Recurse
    )

    if ($PSCmdlet.ParameterSetName -eq 'basic') {
        $Headers=GetKuduHeaders -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'AAD') {
        $Headers=GetKuduHeaders -AccessToken $AccessToken
    }
    elseif ($PSCmdlet.ParameterSetName -eq "PublishingCredential") {
        [Uri]$PcUriBld=$PublishingCredential.properties.scmUri
        $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
        $Headers=GetKuduHeaders -PublishingCredential $PublishingCredential
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/vfs/"
    if([String]::IsNullOrEmpty($Path) -eq $false)
    {
        $KuduUriBld.Path+="$Path"
    }
    try
    {
        $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
        if($Recurse.IsPresent) {
            foreach ($item in $KuduResult)
            {
                if($item.mime -in "inode/directory","inode/shortcut") {
                    $Uri=New-Object System.Uri($item.href.ToLower())
                    $SubPath=$Uri.AbsolutePath.Replace("/api/vfs/",[String]::Empty)
                    if($SubPath -ne "systemdrive/") {
                        switch ($PSCmdlet.ParameterSetName)
                        {
                            "AAD" {
                                $DirResult=Get-KuduWebsiteVfsChildItem -ScmEndpoint $ScmEndpoint -Path $SubPath `
                                    -AccessToken $AccessToken -Recurse -ErrorAction 'Continue'
                            }
                            "basic" {
                                $DirResult=Get-KuduWebsiteVfsChildItem -ScmEndpoint $ScmEndpoint -Path $SubPath `
                                    -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret `
                                    -Recurse -ErrorAction 'Continue'
                            }
                            "PublishingCredential" {
                                $DirResult=Get-KuduWebsiteVfsChildItem -Path $SubPath -PublishingCredential $PublishingCredential `
                                    -Recurse -ErrorAction 'Continue'
                            }
                        }
                        if($DirResult -ne $null) {
                            Write-Output $DirResult
                        }
                    }
                    else {
                        Write-Warning "The SystemDrive alias is skipped as it is redundant."
                    }
                }
                Write-Output $item
            }
        }
        else {
            Write-Output $KuduResult
        }
    }
    catch
    {
        Write-Warning $_.Message
    }
}
#/api/vfs
Function Copy-KuduItem
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri]
        $ScmEndpoint,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String]
        $PublishingSecret,                
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential')]
        [System.Object]
        $PublishingCredential,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential')]
        [System.IO.String[]]
        $Path,
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.String]
        $Destination
    )

    BEGIN
    {
        if ($PSCmdlet.ParameterSetName -eq 'basic') {
            $Headers=GetKuduHeaders -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'AAD') {
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
        elseif ($PSCmdlet.ParameterSetName -eq "PublishingCredential") {
            [Uri]$PcUriBld=$PublishingCredential.properties.scmUri
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -PublishingCredential $PublishingCredential
        }
        $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
        $UserAgent = "powershell/avanade"
        if([String]::IsNullOrEmpty($Destination)) {
            $KuduBriBld.Path="api/vfs/"
        }
        else {
            $KuduBriBld.Path="api/vfs/$($Destination.TrimEnd('/'))/"
        }
    }
    PROCESS
    {
        foreach ($item in $path)
        {
            Write-Verbose "Uploading $item to $($KuduBriBld.Uri)"
            Invoke-RestMethod -Uri $KuduBriBld.Uri -Headers $Headers -Method Put -InFile $item -UserAgent $UserAgent -ContentType "multipart/form-data"
        }
    }
    END
    {

    }
}

#Zip
#api/zip
<#
Function Compress-KuduPath
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri]
        $ScmEndpoint,  
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential')]
        [System.Object]
        $PublishingCredential,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential')]
        [System.String[]]
        $Path,
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.String]
        $Destination
    )

    BEGIN
    {
        switch ($PSCmdlet.ParameterSetName) {
            "PublishingCredential" {
                $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
                $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
                $Headers=GetKuduHeaders -AccessToken $AccessToken
            }
        }
        $KuduBriBld=New-Object System.UriBuilder($ScmEndpoint)
        $KuduBriBld.Path="api/zip/$($Path.TrimEnd('/'))"
    }
    PROCESS
    {
        foreach ($item in $path)
        {

        }
    }
    END
    {

    }
}
#>

#Execute Command
#api/command
Function Invoke-KuduCommand
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential')]
        [System.String]
        $Command,
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.String]
        $Directory='SystemDrive/Windows/System32',        
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential 
    )
    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections) {
            try 
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="api/command"
                $CommandToRun=New-Object PSObject -Property @{
                    command=$Command;
                    dir=$Directory;
                }    
                $CmdResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -Method Post -Body $CommandToRun -ContentType 'application/json'
                Write-Output $CmdResult                
            }
            catch [System.Exception] {
                Write-Warning "$($KuduConnection.ScmEndpoint) $_"
            }
        }
    }
    END
    {

    }
}

#Diagnostics
#/api/dump
Function Get-KuduDump
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [System.String]
        $Destination=$env:TEMP,
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,    
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken      
    )

    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections)
        {
            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="api/dump"
                if ((Test-Path -Path $Destination) -eq $false) {
                    New-Item -Path (Split-Path $Destination -Parent) -Name (Split-Path $Destination -Parent) -Force|Out-Null
                }
                $FileName="$($KuduUriBld.Host)-$(Get-Date -Format "hh_mm_ss-dd_MM_yyyy").zip"
                $OutFile=Join-Path $Destination $FileName
                $Result=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -OutFile $OutFile -UseBasicParsing -ErrorAction Stop                
            }
            catch [System.Exception]
            {
                
            }
        }
    }
    END
    {

    }
}

#Diagnostics/Settings
#api/diagnostics/settings
Function Get-KuduDiagnosticSetting
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (     
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [System.String]
        $Setting,
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,    
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken            
    )
    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections)
        {
            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="api/diagnostics/settings"
                if([String]::IsNullOrEmpty($Setting) -eq $false)
                {
                    $KuduUriBld.Path="api/diagnostics/settings/$Setting"
                }
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType "application/json" -ErrorAction Stop
                if($KuduResult -ne $null)
                {
                    Write-Output $KuduResult
                }               
            }
            catch [System.Exception]
            {
                
            }   
        }
    }
    END
    {

    }
}

#Logs
#/api/logs/recent
Function Get-KuduRecentLog
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [ValidateRange(1,1000)]
        [System.Int32]
        $Top, 
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,    
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken    
    )
    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections)
        {
            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                $KuduUriBld.Path="api/logs/recent"
                if ($Top -gt 0) {
                    $KuduUriBld.Query="top=$Top"
                }
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType 'application/json' -ErrorAction Stop
                if($KuduResult -ne $null)
                {
                    Write-Output $KuduResult
                }
            }
            catch [System.Exception]
            {
                Write-Warning "$KuduConnection.ScmEndpoint $_"
            }
        }
    }
    END
    {

    }
}

#Webjobs
Function Get-KuduWebJob
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [Switch]
        $Triggered,
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [Switch]
        $Continuous,
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object[]]
        $PublishingCredential,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri[]]
        $ScmEndpoint,    
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String[]]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String[]]
        $AccessToken   
    )
    BEGIN
    {

    }
    PROCESS
    {
        switch ($PSCmdlet.ParameterSetName) {
            'basic' { 
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -PublishingUsername $PublishingUsername -PublishingSecret $PublishingSecret
            }
            'AAD' {
                $KuduConnections=GetKuduConnection -ScmEndpoint $ScmEndpoint -AccessToken $AccessToken
            }
            'PublishingCredential' {
                $KuduConnections=GetKuduConnection -PublishingCredential $PublishingCredential
            }
        }
        foreach ($KuduConnection in $KuduConnections)
        {
            try
            {
                $KuduUriBld=New-Object System.UriBuilder($KuduConnection.ScmEndpoint)
                if ($Triggered.IsPresent) {
                    $KuduUriBld.Path="api/triggeredwebjobs"
                }
                elseif ($Continuous.IsPresent) {
                    $KuduUriBld.Path="api/continuouswebjobs"
                }
                else {
                    $KuduUriBld.Path="api/webjobs"
                }
                $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $KuduConnection.Headers -ContentType 'application/json' -ErrorAction Stop
                if($KuduResult -ne $null -and $KuduResult.Count -gt 0)
                {
                    Write-Output $KuduResult
                }
            }
            catch [System.Exception]
            {
                Write-Warning "$KuduConnection.ScmEndpoint $_"
            }
        }
    }
    END
    {

    }
}