<#
    Avanade.KuduTools
#>

Function GetKuduHeaders
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (   
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String]
        $AccessToken,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String]
        $PublishingUsername,
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [System.String]
        $PublishingSecret,           
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential')]
        [System.Object]
        $PublishingCredential       
    )
    $Headers=@{}
    if ($PSCmdlet.ParameterSetName -eq 'AAD') {
        #Use the access token
        $Headers.Add('Authorization',"Bearer $AccessToken")
    }
    else {
        if ($PSCmdlet.ParameterSetName -eq 'PublishingCredential') {
            $PublishingUsername=$PublishingCredential.properties.publishingUserName
            $PublishingSecret=$PublishingCredential.properties.publishingPassword
        }
        $AuthInfo="$($PublishingUsername):$($PublishingSecret)"
        $BasicCredential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($AuthInfo))        
        $Headers.Add('Authorization',"Basic $BasicCredential")
    }

    return $Headers     
}

Function Get-KuduProcessList
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
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential    
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }

    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path+="/api/processes"
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
    Write-Output $KuduResult
}

Function Get-KuduProcessMiniDump
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
        [System.Int32]
        $ProcessId,
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
        $PublishingCredential   
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }

    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path+="api/processes"
    if([String]::IsNullOrEmpty($FilePath) -eq $false) {
        $KuduUriBld.Path+="/$ProcessId"
        $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
        Write-Output $KuduResult
    }
    else {
        $ProcessList=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
        foreach ($item in $ProcessList)
        {
            $KuduUriBld.Path="/api/processes/$($item.id)"
            $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
            Write-Output $KuduResult
        }
    }
}

Function Get-KuduRuntimeVersions
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
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential       
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path+="/api/diagnostics/runtime"
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
    return $KuduResult
}

Function Get-KuduEnvironment
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
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential       
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path+="/api/environment"
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
    return $KuduResult
}

Function Get-KuduSetting
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
        $Setting,
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
        $PublishingCredential       
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path+="/api/settings"
    if ([String]::IsNullOrEmpty($Setting) -eq $false) {
        $KuduUriBld.Path+="/$Setting"
    }
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
    return $KuduResult
}

Function Get-KuduDeployment
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
        $DeploymentId,        
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential       
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path+="api/deployments"
    if([String]::IsNullOrEmpty($DeploymentId) -eq $false)
    {
        $KuduUriBld.Path+="/$DeploymentId"
    }
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
    Write-Output $KuduResult

}

Function Get-KuduSourceControlInfo
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
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential       
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path+="/api/scm/info"
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
    return $KuduResult

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

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
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
        switch ($PSCmdlet.ParameterSetName) {
            "PublishingCredential" {
                $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
                $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
                $Headers=GetKuduHeaders -AccessToken $AccessToken
            }
        }
        $UserAgent = "powershell/avanade"
        $KuduBriBld=New-Object System.UriBuilder($ScmEndpoint)
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

#Execute Command
#api/command
Function Invoke-KuduCommand
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri]
        $ScmEndpoint,
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
        $PublishingCredential
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $CommandToRun=New-Object PSObject -Property @{
        command=$Command;
        dir=$Directory;
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/command"
    $CmdResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -Method Post -Body $CommandToRun -ContentType 'application/json'
    Write-Output $CmdResult
}

#Diagnostics
#/api/dump
Function Get-KuduDump
{
    [CmdletBinding(DefaultParameterSetName='AAD')]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName='basic')]
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.Uri]
        $ScmEndpoint,
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [System.String]
        $Destination=$env:TEMP,
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]        
        [System.String]
        $FileName='dump.zip',        
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential       
    )
    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/dump"
    if (Test-Path -Path $Destination -eq $false) {
        New-Item -Path (Split-Path $Destination -Parent) -Name (Split-Path $Destination -Parent) -Force|Out-Null
    }
    $OutFile=Join-Path $Destination $FileName
    $Result=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -OutFile $OutFile -UseBasicParsing
}

#Diagnostics/Settings
#api/diagnostics/settings
Function Get-KuduDiagnosticSetting
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
        $Setting,        
        [Parameter(Mandatory=$true,ParameterSetName='AAD')]
        [System.String]
        $AccessToken,      
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential       
    )

    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/diagnostics/settings"
    if([String]::IsNullOrEmpty($DeploymentId) -eq $false)
    {
        $KuduUriBld.Path+="/$Setting"
    }
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType "application/json"
    Write-Output $KuduResult
}

#Logs
#/api/logs/recent
Get-KuduRecentLog
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
        [Parameter(Mandatory=$false,ParameterSetName='basic')]
        [Parameter(Mandatory=$false,ParameterSetName='AAD')]
        [Parameter(Mandatory=$false,ParameterSetName='PublishingCredential')]
        [ValidateRange(1,1000)]
        [System.Int32]
        $Top, 
        [Parameter(Mandatory=$true,ParameterSetName='PublishingCredential',ValueFromPipeline=$true)]
        [System.Object]
        $PublishingCredential       
    )
    switch ($PSCmdlet.ParameterSetName) {
        "PublishingCredential" {
            $PcUriBld=New-Object System.Uri($PublishingCredential.properties.scmUri)
            $ScmEndpoint=New-Object System.Uri("$($PcUriBld.Scheme)://$($PcUriBld.Host):$($PcUriBld.PathAndQuery)")
            $Headers=GetKuduHeaders -AccessToken $AccessToken
        }
    }
    $KuduUriBld=New-Object System.UriBuilder($ScmEndpoint)
    $KuduUriBld.Path="api/logs/recent"
    if ($Top -gt 0) {
        $KuduUriBld.Query="top=$Top"
    }
    $KuduResult=Invoke-RestMethod -Uri $KuduUriBld.Uri -Headers $Headers -ContentType 'application/json'
    Write-Output $KuduResult
}

#Webjobs