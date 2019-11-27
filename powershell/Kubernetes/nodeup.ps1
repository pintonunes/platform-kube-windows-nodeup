[CmdletBinding()]
param (
    [parameter()]
    [string]$AWSRegion = 'eu-west-1'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Constants
$script:installDir = "$env:ALLUSERSPROFILE\Kubernetes"

# ---- Helper Functions ---- #
function DownloadFile([string]$Url, [string]$Destination)
{
    $secureProtocols = @()
    $insecureProtocols = @([System.Net.SecurityProtocolType]::SystemDefault, [System.Net.SecurityProtocolType]::Ssl3)
    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType]))
    {
        if ($insecureProtocols -notcontains $protocol)
        {
            $secureProtocols += $protocol
        }
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols

    try
    {
        (New-Object System.Net.WebClient).DownloadFile($Url, $Destination)
    }
    catch
    {
        Write-Error "ERROR: Failed to download $Url"
        throw $_
    }
}

function DownloadKopsConfigStoreFile([string]$KopsConfigBase, [string]$KopsFile , [string]$Destination)
{
    $s3Bucket = $kopsConfigBase.Split('/')[-2]
    $s3Item = "$($kopsConfigBase.Split('/')[-1])/$KopsFile"
    try
    {
        Read-S3Object -BucketName $s3Bucket -Key $s3Item -File $Destination -Region $AWSRegion | Out-Null
    }
    catch
    {
        Write-Output "ERROR: Cannot get file $s3Item from bucket $s3Bucket"
        throw $_
    }
}

function GetDefaultInterface()
{
    $interface = ( Get-NetIPConfiguration | Where-Object -FilterScript { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected" })

    if ((-not $interface) -or ($interface.Count -ne 1))
    {
        throw 'Cannot get default interface..! Exiting...'
    }
    return $interface
}

function NewKubeConfigFromKopsState([string]$KopsConfigBase, [string]$KubeUser, [string]$KubeApi, [string]$KubeCAPublicData, [string]$Destination)
{
    DownloadKopsConfigStoreFile -KopsConfigBase $KopsConfigBase -KopsFile "pki/private/$KubeUser/keyset.yaml" -Destination "$env:TEMP\kops\$KubeUser-keyset.yaml"
    $kubeKeysetData = Get-Content -Path "$env:TEMP\kops\$KubeUser-keyset.yaml" | ConvertFrom-Yaml

    $kubeConfig = @{
        "apiVersion"      = "v1";
        "clusters"        = @(
            @{
                "cluster" = @{
                    "certificate-authority-data" = $KubeCAPublicData;
                    "server"                     = "https://$KubeApi";
                };
                "name"    = "local";
            }
        );
        "contexts"        = @(
            @{
                "context" = @{
                    "cluster" = "local";
                    "user"    = "$KubeUser";
                };
                "name"    = "service-account-context";
            }
        )
        "current-context" = "service-account-context";
        "kind"            = "Config";
        "users"           = @(
            @{
                "name" = "$KubeUser";
                "user" = @{
                    "client-certificate-data" = $kubeKeysetData.publicMaterial;
                    "client-key-data"         = $kubeKeysetData.privateMaterial;
                };
            }
        );
    }

    ConvertTo-Yaml $kubeConfig | Set-Content -Path $Destination
}

function GetTokenForServiceAccount([string]$KubeCtlPath, [string]$KubeConfig, [string]$Namespace, [string]$ServiceAccount)
{
    $kubeSecrets = ( & $KubeCtlPath get secrets --kubeconfig=`"$KubeConfig`" --namespace $Namespace -ojson | ConvertFrom-Json )
    if ($LASTEXITCODE -ne 0)
    {
        Write-Output 'ERROR: Running kubectl'
        throw 'Error running kubectl'
    }

    $kubeSecret = $kubeSecrets.items | Where-Object -FilterScript { $_.metadata.annotations.'kubernetes.io/service-account.name' -eq $ServiceAccount }
    if (-not $kubeSecret.data.token)
    {
        Write-Output "ERROR: Cant find token for service account $ServiceAccount in namespace $Namespace"
        throw "Cant find token for service account $ServiceAccount in namespace $Namespace"
    }

    return $kubeSecret.data.token
}

function NewKubeConfigFromToken([string]$KubeUser, [string]$KubeUserToken, [string]$KubeApi, [string]$KubeCAPublicData, [string]$Destination)
{
    $kubeConfig = @{
        "apiVersion"      = "v1";
        "clusters"        = @(
            @{
                "cluster" = @{
                    "certificate-authority-data" = $KubeCAPublicData;
                    "server"                     = "https://$KubeApi";
                };
                "name"    = "local";
            }
        );
        "contexts"        = @(
            @{
                "context" = @{
                    "cluster" = "local";
                    "user"    = "$KubeUser";
                };
                "name"    = "service-account-context";
            }
        )
        "current-context" = "service-account-context";
        "kind"            = "Config";
        "users"           = @(
            @{
                "name" = "$KubeUser";
                "user" = @{
                    "token" = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($KubeUserToken)); ;
                };
            }
        );
    }

    ConvertTo-Yaml $kubeConfig | Set-Content -Path $Destination
}

function UpdateCNIConfig([string]$KubeClusterCIDR, [string]$KubeDnsServiceIP, [string]$KubeServiceCIDR, [string]$Destination)
{
    $configuration = @{
        "cniVersion" = "0.2.0"
        "name"       = "vxlan0"
        "type"       = "flannel"
        "delegate"   = @{
            "type"     = "win-overlay"
            "dns"      = @{
                "Nameservers" = @(
                    "$KubeDnsServiceIP"
                )
                "Search"      = @(
                    "cluster.local"
                )
            }
            "policies" = @(
                @{
                    "Name"  = "EndpointPolicy"
                    "Value" = @{
                        "Type"          = "OutBoundNAT"
                        "ExceptionList" = @(
                            $KubeClusterCIDR,
                            $KubeServiceCIDR
                        )
                    }
                },
                @{
                    "Name"  = "EndpointPolicy"
                    "Value" = @{
                        "Type"              = "ROUTE"
                        "DestinationPrefix" = $KubeServiceCidr
                        "NeedEncap"         = $true
                    }
                }
            )
        }
    }
    Set-Content -Path $Destination -Value (ConvertTo-Json $Configuration -Depth 20)
}

function UpdateNetConfiguration([string]$KubeClusterCIDR, [string]$Destination)
{
    $configuration = @{
        "Network" = "$KubeClusterCIDR"
        "Backend" = @{
            "name" = "vxlan0"
            "type" = "vxlan"
        }
    }
    Set-Content -Path $Destination -Value (ConvertTo-Json $Configuration -Depth 20)
}

function InstallNSSMService([string]$NSSMPath, [string]$Name, [string]$Path, [string]$LogPath, [string]$DependsOn, [string]$EnvironmentVars, [string]$Arguments)
{
    $commands = @(
        "install $Name $Path",
        "set $Name AppStderr $LogPath",
        "set $Name DependOnService $DependsOn",
        "set $Name AppEnvironmentExtra $EnvironmentVars",
        "set $Name AppParameters $Arguments"
    )

    foreach ($command in $commands)
    {
        Invoke-Expression -Command "& $NSSMPath\nssm.exe $command" | Out-Null
        if ($LASTEXITCODE -ne 0)
        {
            Write-Output "ERROR: Installing service $Name"
            throw "ERROR: Installing service $Name"
        }
    }
}

function WaitForNetwork([string]$NetworkName, [int]$waitTimeSeconds = 60)
{
    $startTime = Get-Date

    # Wait till the network is available
    while ($true)
    {
        $timeElapsed = $(Get-Date) - $startTime
        if ($($timeElapsed).TotalSeconds -ge $waitTimeSeconds)
        {
            throw "Fail to create the network[($NetworkName)] in $waitTimeSeconds seconds"
        }
        if (Get-HnsNetwork | Where-Object  -FilterScript { $_.Name -eq $NetworkName.ToLower() })
        {
            break;
        }
        Write-Output "Waiting for the Network ($NetworkName) to be created by flanneld"
        Start-Sleep 5
    }
}

function GetSourceVip([string]$NetworkName, [string]$CniPath)
{
    $hnsNetwork = Get-HnsNetwork | Where-Object -FilterScript { $_.Name -EQ $NetworkName.ToLower() }
    $subnet = $hnsNetwork.Subnets[0].AddressPrefix

    $ipamConfig = @"
        {"cniVersion": "0.2.0", "name": "$NetworkName", "ipam":{"type":"host-local","ranges":[[{"subnet":"$subnet"}]],"dataDir":"/var/lib/cni/networks"}}
"@
    $env:CNI_COMMAND="ADD"
    $env:CNI_CONTAINERID="dummy"
    $env:CNI_NETNS="dummy"
    $env:CNI_IFNAME="dummy"
    $env:CNI_PATH=$CniPath #path to host-local.exe

    $sourceVip = ($ipamConfig |  & $CniPath\host-local.exe | ConvertFrom-Json).ip4.ip.Split("/")[0]

    Remove-Item env:CNI_COMMAND
    Remove-Item env:CNI_CONTAINERID
    Remove-Item env:CNI_NETNS
    Remove-Item env:CNI_IFNAME
    Remove-Item env:CNI_PATH

    return $sourceVip
}

# ---- Routine Functions ---- #
function CreateFolderStructure()
{
    $folders = @(
        "$installDir",
        "$installDir\kconfigs",
        "$installDir\kconfigs\issued",
        "$installDir\logs",
        "$installDir\cni",
        "$installDir\cni\bin",
        "$installDir\cni\configs",
        "$env:TEMP\kops",
        "$env:SystemDrive\etc\kube-flannel"
    )

    foreach ($folder in $folders)
    {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }
}

function InstallPreReqs()
{
    Write-Output 'Checking if docker is installed'
    if (-not (Get-Command -Name 'docker' -ErrorAction SilentlyContinue))
    {
        throw "Cant find Docker!!"
    }

    Write-Output 'Checking if powershell module powershell-yam is installed'
    if (-not (Get-Module powershell-yaml -ListAvailable))
    {
        Write-Output 'Module powershell-yam is not installed. Installing...'
        Install-Module -Name powershell-yaml -Force | Out-Null
    }
}

function InstallBinaries()
{
    Write-Output 'Downloading flannel'
    DownloadFile -Url "https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe" -Destination "$installDir\flanneld.exe"

    Write-Output 'Downloading CNI Binaries'
    DownloadFile -Url "https://github.com/containernetworking/plugins/releases/download/v0.8.2/cni-plugins-windows-amd64-v0.8.2.tgz" -Destination "$env:Temp/kops/cni-plugins-windows-amd64-v0.8.2.tgz"
    & cmd /c tar -zxvf $env:Temp/kops/cni-plugins-windows-amd64-v0.8.2.tgz -C $installDir/cni/bin '2>&1' | Out-Null
    if (!$?)
    {
        Write-Output 'Error decompressing CNI binaries'
        throw 'Error decompressing CNI binaries'
    }

    Write-Output 'Downloading Kubernetes Binaries'
    DownloadFile -Url "https://dl.k8s.io/v$kubeVersion/kubernetes-node-windows-amd64.tar.gz" -Destination "$env:Temp/kops/kubernetes-node-windows-amd64.tar.gz"
    New-Item -Path "$env:Temp/kops/kubernetes" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    & cmd /c tar -zxvf $env:Temp/kops/kubernetes-node-windows-amd64.tar.gz -C $env:Temp/kops/kubernetes '2>&1' | Out-Null
    if (!$?)
    {
        Write-Output 'Error decompressing kubernetes binaries'
        throw 'Error decompressing kubernetes binaries'
    }
    Move-Item -Path "$env:Temp/kops/kubernetes/kubernetes/node/bin/*.exe" -Destination $installDir -Force

    Write-Output 'Downloading Microsoft SDN PowerShell module'
    DownloadFile -Url "https://raw.githubusercontent.com/Microsoft/SDN/master/Kubernetes/windows/hns.psm1" -Destination "$installDir/hns.psm1"

    Write-Output 'Downloading NSSM service manager'
    DownloadFile -Url "https://nssm.cc/release/nssm-2.23.zip" -Destination "$env:Temp\kops\nssm.zip"
    Expand-Archive "$env:Temp\kops\nssm.zip" -DestinationPath "$env:Temp\kops" -Force
    Copy-Item "$env:Temp\kops\nssm-2.23\win64\nssm.exe" -Destination $installDir -Force
}

function PrepareNetwork()
{
    if (-not (Get-NetFirewallRule -Name OverlayTraffic4789UDP -ErrorAction SilentlyContinue))
    {
        Write-Output 'Creating firewall rule for VXLAN'
        New-NetFirewallRule -Name OverlayTraffic4789UDP -Description "Overlay network traffic UDP" -Action Allow -LocalPort 4789 -Enabled True -DisplayName "Overlay Traffic 4789 UDP" -Protocol UDP | Out-Null
    }
    else
    {
        Write-Output 'Firewall rule for VXLAN already exists'
    }

    if (-not (Get-NetFirewallRule -Name KubeletAllow10250 -ErrorAction SilentlyContinue))
    {
        Write-Output 'Creating firewall rule for kubelet'
        New-NetFirewallRule -Name KubeletAllow10250 -Description "Kubelet Allow 10250" -Action Allow -LocalPort 10250 -Enabled True -DisplayName "KubeletAllow10250" -Protocol TCP | Out-Null
    }
    else
    {
        Write-Output 'Firewall rule for kubelet already exists'
    }

    if ( -not (Get-HnsNetwork | Where-Object -FilterScript { $_.Name -eq 'External' }))
    {
        Write-Output 'Creating External network'
        New-HNSNetwork -Type 'overlay' -AddressPrefix "192.168.255.0/30" -Gateway "192.168.255.1" -Name "External" -AdapterName $((GetDefaultInterface).InterfaceAlias) -SubnetPolicies @(@{Type = "VSID"; VSID = 9999; }) | Out-Null
        Write-Output "Re-Adding the route to the meta-data AWS service"
        route add 169.254.169.254 MASK 255.255.255.255 0.0.0.0 | Out-Null
    }
    else
    {
        Write-Output 'External network already exists... Skipping...'
    }
}

function GetKubeletArgs()
{
    $args = @(
        "$installDir\kubelet.exe",
        '--windows-service',
        '--v=6',
        '--cgroups-per-qos=false',
        '--enforce-node-allocatable=""',
        '--pod-infra-container-image=mcr.microsoft.com/k8s/core/pause:1.2.0',
        "--kubeconfig=$installDir\kconfigs\kubelet",
        '--cloud-provider=aws',
        "--hostname-override=$ec2LocalHostname",
        "--log-dir=$installDir\logs",
        '--logtostderr=false',
        '--network-plugin=cni',
        "--cni-bin-dir=$installDir\cni\bin",
        "--cni-conf-dir=$installDir\cni\configs"
    )
    return $args

    # "$kubeletBinPath --windows-service --v=6 --log-dir=$logDir --cert-dir=$env:SYSTEMDRIVE\var\lib\kubelet\pki --cni-bin-dir=$CniDir --cni-conf-dir=$CniConf --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --hostname-override=$(hostname) --pod-infra-container-image=$Global:PauseImage --enable-debugging-handlers  --cgroups-per-qos=false --enforce-node-allocatable=`"`" --logtostderr=false --network-plugin=cni --resolv-conf=`"`" --cluster-dns=`"$KubeDnsServiceIp`" --cluster-domain=cluster.local --feature-gates=$KubeletFeatureGates"
    #    "--hostname-override=$ec2LocalHostname"
    #    '--v=6'
    #    '--pod-infra-container-image=mcr.microsoft.com/k8s/core/pause:1.2.0'
    #    #'--resolv-conf=\"\"',
    #    #'--allow-privileged=true',
    #    #'--enable-debugging-handlers', # Comment for Config
    #    "--cluster-dns=`"$KubeDnsServiceIp`"",
    #    '--cluster-domain=cluster.local',
    #    #'--hairpin-mode=promiscuous-bridge', # Comment for Config
    #    '--image-pull-progress-deadline=20m'
    #    '--cgroups-per-qos=false'
    #    "--log-dir=$installDir/logs"
    #    '--logtostderr=false'
    #    "--enforce-node-allocatable=`"`""
    #    '--network-plugin=cni'
    #    "--cni-bin-dir=$installDir\cni\bin"
    #    "--cni-bin-dir=$installDir\cni\configs"
    #    "--node-ip=$NodeIp"
    #    "--cert-dir=$env:SYSTEMDRIVE\var\lib\kubelet\pki"
    #    "--config=$env:SYSTEMDRIVE\var\lib\kubelet\config.yaml"
    #    "--kubeconfig=$env:SYSTEMDRIVE\etc\kubernetes\kubelet.conf"
    #    #"--bootstrap-kubeconfig=$env:SYSTEMDRIVE\etc\kubernetes\bootstrap-kubelet.conf"
}

function GetFlannelArgs()
{
    $args = @(
        '--kube-subnet-mgr=1',
        '--ip-masq=1',
        "--kubeconfig-file=$installDir\kconfigs\flannel",
        "--iface=$(((GetDefaultInterface).IPv4Address).IPAddress)"
    )
    return $args
}

function GetKubeProxyArgs()
{
    $args = @(
        "$installDir\kube-proxy.exe",
        "--hostname-override=$ec2LocalHostname"
        '--v=6'
        '--proxy-mode=kernelspace'
        "--kubeconfig=$installDir\kconfigs\kube-proxy",
        '--network-name=vxlan0'
        "--cluster-cidr=$kubeClusterCidr"
        "--log-dir=$installDir\logs",
        '--logtostderr=false'
        '--windows-service',
        '--feature-gates="WinOverlay=true"',
        "--source-vip=$sourceVip"
    )
    return $args
}

function CleanNode()
{
    if (Get-Service -Name 'kube-proxy' -ErrorAction SilentlyContinue)
    {
        Write-Output 'Stopping and removing kube-proxy service'
        Stop-Service -Name 'kube-proxy' -Force
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='kube-proxy'"
        $service.delete() | Out-Null
    }

    if (Get-Service -Name 'kubelet' -ErrorAction SilentlyContinue)
    {
        Write-Output 'Stopping and removing kubelet service'
        Stop-Service -Name 'kubelet' -Force
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='kubelet'"
        $service.delete() | Out-Null
    }

    if (Get-Service -Name 'flanneld' -ErrorAction SilentlyContinue)
    {
        Write-Output 'Stopping and removing flanneld service'
        Stop-Service -Name 'flanneld' -Force
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='flanneld'"
        $service.delete() | Out-Null
    }

    $folders = @(
        "$env:TEMP\kops",
        "$installDir",
        "$env:SystemDrive\etc",
        "$env:SystemDrive\run",
        "$env:SystemDrive\usr",
        "$env:SystemDrive\var"
    )
    foreach ($folder in $folders)
    {
        if (Test-Path -Path $folder)
        {
            Remove-Item -Path $folder -Recurse -Force
        }
    }
}

# *****************************  Main **************************** #
Write-Output 'Starting Node ....'

#region init
Write-Output '------  Init ------'

Write-Output 'Cleaning node services, files and folder'
CleanNode

Write-Output 'Creating folder structure'
CreateFolderStructure

Write-Output 'Checking and installing pre-reqs'
InstallPreReqs

Import-Module -Name powershell-yaml
#endregion init

#region get ec2 config
Write-Output '------  Retrieving EC2 information from metadata service ------'
$ec2MetadataUri = 'http://169.254.169.254/latest'
try
{
    $ec2InstanceId = (Invoke-RestMethod "$ec2MetadataUri/meta-data/instance-id").ToString()
    $ec2AvailabilityZone = (Invoke-RestMethod "$ec2MetadataUri/meta-data/placement/availability-zone").ToString()
    $ec2Region = $ec2AvailabilityZone.Substring(0, $ec2AvailabilityZone.Length - 1)
    $ec2LocalHostname = (Invoke-RestMethod "$ec2MetadataUri/meta-data/local-hostname").ToString()
    $ec2UserData = (Invoke-RestMethod "$ec2MetadataUri/user-data").ToString()
}
catch
{
    Write-Output 'ERROR: Retrieving ec2 instance metadata'
    throw $_
}

Write-Output "EC2 Instance ID: $ec2InstanceId"
Write-Output "EC2 Availability Zone: $ec2AvailabilityZone"
Write-Output "EC2 Region: $ec2Region"
Write-Output "EC2 Local Hostname: $ec2LocalHostname"
#endregion

#region get kube config
Write-Output '------  Getting kube cluster information from KOPS S3 config store ------'
$kopsConfigBaseMatches = $ec2UserData.Split([Environment]::NewLine) | ForEach-Object -Process { Select-String -InputObject $_ -Pattern "^ConfigBase: s3://(?<bucket>[^/]+)/(?<prefix>.+)$" }
$kopsConfigBase = 's3://' + $kopsConfigBaseMatches.Matches.Groups[1] + '/' + $kopsConfigBaseMatches.Matches.Groups[2]
Write-Output "KOPS ConfigBase: $kopsConfigBase"
Write-Output "Downloading cluster.spec file"
DownloadKopsConfigStoreFile -KopsConfigBase $kopsConfigBase -KopsFile 'cluster.spec' -Destination "$env:TEMP\kops\cluster.spec"
$kopsClusterSpec = Get-Content -Path "$env:TEMP\kops\cluster.spec" | ConvertFrom-Yaml -ErrorAction SilentlyContinue

$kubeClusterCidr = $kopsClusterSpec.clusterCidr | Sort-Object -Unique
$kubeClusterDns = $kopsClusterSpec.clusterDNS | Sort-Object -Unique
$kubeClusterInternalApi = $kopsClusterSpec.masterInternalName | Sort-Object -Unique
$kubeDnsDomain = $kopsClusterSpec.clusterDnsDomain | Sort-Object -Unique
$kubeNonMasqueradeCidr = $kopsClusterSpec.nonMasqueradeCIDR | Sort-Object -Unique
$kubeServiceCidr = $kopsClusterSpec.serviceClusterIPRange | Sort-Object -Unique
$kubeVersion = $kopsClusterSpec.kubernetesVersion | Sort-Object -Unique

Write-Output "KUBE Cluster Cidr: $kubeClusterCidr"
Write-Output "KUBE DNS Server: $kubeClusterDns"
Write-Output "KUBE API: $kubeClusterInternalApi"
Write-Output "KUBE Domain: $kubeDnsDomain"
Write-Output "KUBE Non-Masquerade Cidr: $kubeNonMasqueradeCidr"
Write-Output "KUBE Service Cidr: $kubeServiceCidr"
Write-Output "KUBE Version: $kubeVersion"
#endregion

#region install binaries
Write-Output '------  Install Binaries ------'
Write-Output "Installing kubernetes binaries for version: $kubeVersion"
InstallBinaries
Import-Module $installDir\hns.psm1 -WarningAction SilentlyContinue
#endregion

#region generate kube config files
Write-Output '------  Generating kube config files ------'
Write-Output 'Getting certificate authority certificate'
DownloadKopsConfigStoreFile -KopsConfigBase $kopsConfigBase -KopsFile 'pki/issued/ca/keyset.yaml' -Destination "$env:TEMP\kops\ca-keyset.yaml"
$kubeCAPublicData = (Get-Content -Path "$env:TEMP\kops\ca-keyset.yaml" | ConvertFrom-Yaml).publicMaterial
try
{
    $caCertData = [System.Convert]::FromBase64String($kubeCAPublicData)
}
catch
{
    Write-Output 'ERROR: Converting CA keyset to CA certificate'
    throw $_
}
Set-Content -Path "$installDir/kconfigs/issued/ca.crt" -Value $caCertData -Encoding Byte

Write-Output 'Generating kubeconfig for kubelet'
NewKubeConfigFromKopsState -KopsConfigBase $kopsConfigBase -KubeUser 'kubelet' -KubeApi $kubeClusterInternalApi -KubeCAPublicData $kubeCAPublicData -Destination "$installDir/kconfigs/kubelet"

Write-Output 'Generating kubeconfig for kube-proxy'
NewKubeConfigFromKopsState -KopsConfigBase $kopsConfigBase -KubeUser 'kube-proxy' -KubeApi $kubeClusterInternalApi -KubeCAPublicData $kubeCAPublicData -Destination "$installDir/kconfigs/kube-proxy"

Write-Output 'Generating kubeconfig for flannel'
NewKubeConfigFromToken -KubeUser 'flannel' -KubeUserToken $(GetTokenForServiceAccount -KubeCtlPath "$installDir\kubectl.exe" -KubeConfig "$installDir\kconfigs\kubelet" -Namespace 'kube-system' -ServiceAccount 'flannel') -KubeApi $kubeClusterInternalApi -KubeCAPublicData $kubeCAPublicData -Destination "$installDir/kconfigs/flannel"
#endregion

Write-Output '------  Configuring Network ------'
Write-Output 'Preparing HNS network and configure firewall rules'
PrepareNetwork
Write-Output 'Generating a new cni.conf file for kubelet'
UpdateCNIConfig -KubeClusterCIDR $kubeClusterCidr -KubeDnsServiceIP $kubeClusterDns -KubeServiceCIDR $kubeServiceCidr -Destination "$installDir\cni\configs\cni.conf"
Write-Output 'Generating a new net-conf.json file for flannel'
UpdateNetConfiguration -KubeClusterCIDR $kubeClusterCidr -Destination "$env:SystemDrive\etc\kube-flannel\net-conf.json"

Write-Output '------  Start Kubelet and Flannel ------'
Write-Output 'Installing and starting the kubelet service'
New-Service -Name 'kubelet' -StartupType Automatic -DependsOn "docker" -BinaryPathName $($(GetKubeletArgs) -join ' ') | Start-Service
Write-Output 'Installing and starting the flanneld service'
InstallNSSMService -NSSMPath $installDir -Name 'flanneld' -Path "$installDir\flanneld.exe" -LogPath "$installDir\Logs\flannel.log" -DependsOn 'kubelet' -EnvironmentVars "NODE_NAME=$ec2LocalHostname" -Arguments (GetFlannelArgs)
Start-Service -Name 'flanneld'

Write-Output '------  Checking network ------'
Write-Output 'Check if network was already created by flannel'
WaitForNetwork -NetworkName 'vxlan0' -WaitTimeSeconds 60
Write-Output 'Getting source vip'
$sourceVip = GetSourceVip -NetworkName 'vxlan0' -CniPath "$installDir\cni\bin"
Write-Output "Found source vip: $sourceVip"

Write-Output '------  Start Kube-Proxy ------'
New-Service -Name 'kube-proxy' -StartupType Automatic -BinaryPathName $($(GetKubeProxyArgs) -join ' ') | Start-Service

Write-Output 'Node initialized!!!!'
