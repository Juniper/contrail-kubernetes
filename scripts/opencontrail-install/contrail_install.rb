#!/usr/bin/env ruby

require 'optparse'
require 'ostruct'

# Use this script to install and provision contrail nodes.
# sudo ruby $PWD/contrail-kubernetes/scripts/opencontrail-install/contrail_install.rb

@opt = OpenStruct.new

def parse_options
    @opt.fix_docker_issue = false
    @opt.intf = "eth0"
    @opt.role = "controller"
    @opt.setup_kubernetes = false
    @opt.controller_host = "localhost"
    @opt.controller_ip = ""
    @opt.private_net = "10.0.0.0/16"
    @opt.portal_net = "10.254.0.0/16"
    @opt.public_net = "10.1.0.0/16"
    @opt.user = "ubuntu"
    @opt.password = "ubuntu"
    @opt.setup_ssh = false
    @opt.ssh_key = "/home/#{@opt.user}/.ssh/contrail_rsa"
    @opt.contrail_install = true
    @opt.provision_vgw = false

    if File.directory? "/vagrant" then
        @opt.intf = "eth1"
        @opt.user = "vagrant"
        @opt.portal_net = "10.247.0.0/16"
    end

    opt_parser = OptionParser.new { |o|
        o.banner = "Usage: #{$0} [options]"
        o.on("-b", "--public-net #{@opt.public_net}",
             "Public network subnet value") { |net|
            @opt.public_net = net
        }
        o.on("-c", "--controller-name #{@opt.controller_host}",
             "Name of the contrail controller host") { |controller|
            @opt.controller_host = controller
        }
        o.on("-f", "--[no-]fix-docker-fs-issue", "#{@opt.fix_docker_issue}",
             "Fix/work-around docker fs device mapper issue") { |f|
             @opt.fix_docker_issue = f
        }
        o.on("-g", "--[no-]provision-vgw", "#{@opt.provision_vgw}",
             "Provision vgw interface") { |f|
             @opt.provision_vgw = f
        }
        o.on("-i", "--controller-ip #{@opt.controller_ip}",
             "IP of the contrail controller host") { |ip|
            @opt.controller_ip = ip
        }
        o.on("-I", "--intf #{@opt.intf}", "data interface name") { |i|
            @opt.intf = i
        }
        o.on("-k", "--[no-]kubernetes-setup", "[#{@opt.setup_kubernetes}",
             "Setup kubernetes plugin") { |kubernetes|
             @opt.setup_kubernetes = kubernetes
        }
        o.on("-l", "--portal-net #{@opt.portal_net}",
             "Portal network subnet value") { |net|
            @opt.portal_net = net
        }
        o.on("-p", "--private-net #{@opt.private_net}",
             "Private network subnet value") { |net|
            @opt.private_net = net
        }
        o.on("-r", "--role #{@opt.role}", "Configuration role") { |role|
            @opt.role = role
        }
        o.on("-s", "--[no-]ssh-setup", "[#{@opt.setup_ssh}",
             "Setup ssh configuration") { |setup|
             @opt.setup_ssh = setup
        }
        o.on("-t", "--[no-]contrail-install", "[#{@opt.contrail_install}",
             "Install and provision contrail software") { |contrail_install|
             @opt.contrail_install = contrail_install
        }
        o.on("-u", "--user #{@opt.user}", "Guest user name") { |user|
            @opt.user = user
        }
        o.on("-w", "--password #{@opt.password}", "Guest user passwd") { |user|
            @opt.password = password
        }
        o.on("-y", "--ssh-key #{@opt.ssh_key}",
             "ssh key for user #{@opt.user} #{@opt.ssh_key}") { |key|
            @opt.ssh_key = ssh_key
        }
    }
    opt_parser.parse!(ARGV)
end

# Parse command line options.
parse_options

@ws="#{File.dirname($0)}"
require "#{@ws}/util"

# Find platform OS
sh(%{\grep -i "ubuntu 14" /etc/issue 2>&1 > /dev/null}, true)
@platform = $?.to_i == 0 ? "ubuntu1404" : "fedora20"
require "#{@ws}/#{@platform}/install"
@utils = @platform =~ /fedora/ ?  "/opt/contrail/utils" :
                                  "/usr/share/contrail-utils"

# Update ssh configuration
def setup_ssh
    return unless @opt.setup_ssh
    conf=<<EOF
UserKnownHostsFile=/dev/null
StrictHostKeyChecking=no
LogLevel=QUIET
EOF
    sh("mkdir -p /root/.ssh")
    File.open("/root/.ssh/config", "a") { |fp| fp.puts(conf) }
    sh("chmod 600 /root/.ssh/config")

    # Add ssh config to ~@opt.user also.
    sh("mkdir -p /home/#{@opt.user}/.ssh")
    File.open("/home/#{@opt.user}/.ssh/config", "a") { |fp| fp.puts(conf) }
    sh("chmod 600 /home/#{@opt.user}/.ssh/config")
    sh("chown #{@opt.user}.#{@opt.user} /home/#{@opt.user}/.ssh/config")
    sh("chown #{@opt.user}.#{@opt.user} /home/#{@opt.user}/.ssh/.")
end

def resolve_controller_host_name
    return if !@opt.controller_ip.empty?
    begin
        @opt.controller_ip = IPSocket.getaddress(@opt.controller_host)
    rescue
        # Check in /etc/hosts
        @opt.controller_ip =
            sh(%{grep #{@opt.controller_host} /etc/hosts | awk '{print $1}'})
    end
    error "Cannot resolve controller #{@opt.controller_host}" \
        if @opt.controller_ip.empty?
end

# Do initial setup
def initial_setup
    STDOUT.sync = true
    raise 'Must run with superuser privilages' unless Process.uid == 0

    @control_node_introspect_port =
        @opt.controller_host == "aurora" ? 9083 : "8083"
    setup_ssh

    sh("service hostname restart", true) if @platform !~ /fedora/
    resolve_controller_host_name

    # Make sure that localhost resolves to 127.0.0.1
    sh(%{\grep -q "127\.0\.0\.1.*localhost" /etc/hosts}, true)
    sh("echo 127.0.0.1 localhost >> /etc/hosts") if $?.to_i != 0

    Dir.chdir("#{@ws}")
    sh("mkdir -p /var/crashes", true)
end

def update_controller_etc_hosts
    # Update /etc/hosts with the IP address
    @controller_ip, mask, gw, prefix_len = get_intf_ip(@opt.intf)

    rip = sh("\grep #{@opt.controller_host} /etc/hosts | awk '{print $1}'", true)
    return if rip != "127.0.0.1" and !rip.empty?

    # If @opt.controller_host resolves to 127.0.0.1, take it out of /etc/hosts
    sh("sed -i '/127.0.0.1 #{@opt.controller_host}/d' /etc/hosts") \
        if rip == "127.0.0.1"
    sh("echo #{@controller_ip} #{@opt.controller_host} >> /etc/hosts")
end

def verify_controller
    sh("netstat -anp | \grep LISTEN | \grep -w 5672", false, 10, 3) # RabbitMQ
    sh("netstat -anp | \grep LISTEN | \grep -w 2181", false, 10, 3) # ZooKeeper
    sh("netstat -anp | \grep LISTEN | \grep -w 9160", false, 10, 3) # Cassandra
    sh("netstat -anp |\grep LISTEN | \grep -w #{@control_node_introspect_port}",
       false, 10, 3) # Control-Node
    sh("netstat -anp | \grep LISTEN | \grep -w 5998", false, 10, 3) # discovery
    sh("netstat -anp | \grep LISTEN | \grep -w 6379", false, 10, 3) # redis
    sh("netstat -anp | \grep LISTEN | \grep -w 8443", false, 10, 3) # IFMAP
    sh("netstat -anp | \grep LISTEN | \grep -w 8082", false, 10, 3) # API-Server
    sh("netstat -anp | \grep LISTEN | \grep -w 8086", false, 10, 3) # Collector
    sh("netstat -anp | \grep LISTEN | \grep -w 8087", false, 10, 3) # Schema
    sh("netstat -anp | \grep LISTEN | \grep -w 8081", false, 10, 3) # OpServer

    sh("netstat -anp | \grep LISTEN | \grep -w 8094", false, 10, 3) # DNS
    sh("netstat -anp | \grep LISTEN | \grep -w 53", false, 10, 3)   # named

    sh("netstat -anp | \grep LISTEN | \grep -w 8143", false, 10, 3) # WebUI
    sh("netstat -anp | \grep LISTEN | \grep -w 8070", false, 10, 3) # WebUI

    puts "All contrail controller components up"
end

# Fix nodemgr configs
def fix_nodemgr_config_files
    nodemgr_conf = <<EOF
[COLLECTOR]
server_list=127.0.0.1:8086
EOF
    File.open("/etc/contrail/contrail-control-nodemgr.conf", "a") { |fp|
        fp.puts nodemgr_conf
    }
    File.open("/etc/contrail/contrail-database-nodemgr.conf", "a") { |fp|
        fp.puts nodemgr_conf
    }
    File.open("/etc/contrail/contrail-analytics-nodemgr.conf", "a") { |fp|
        fp.puts nodemgr_conf
    }
    File.open("/etc/contrail/contrail-config-nodemgr.conf", "a") {|fp|
        fp.puts nodemgr_conf
    }
end

# Provision contrail-controller
def provision_contrail_controller
    update_controller_etc_hosts
    sh("ln -sf /bin/openstack-config /opt/contrail/bin/openstack-config") \
        if @platform =~ /fedora/

    if @platform =~ /fedora/ then
        sh(%{sed -i 's/Xss180k/Xss280k/' /etc/cassandra/conf/cassandra-env.sh})
        sh(%{echo "api-server:api-server" >> /etc/ifmap-server/basicauthusers.properties})
        sh(%{echo "schema-transformer:schema-transformer" >> /etc/ifmap-server/basicauthusers.properties})
        sh(%{echo "svc-monitor:svc-monitor" >> /etc/ifmap-server/basicauthusers.properties})
        sh(%{echo "control-user:control-user-passwd" >> /etc/ifmap-server/basicauthusers.properties})
        sh(%{sed -i 's/911%(process_num)01d/5998/' /etc/contrail/supervisord_config_files/contrail-discovery.ini})
        sh(%{sed -i 's/91%(process_num)02d/8082/' /etc/contrail/supervisord_config_files/contrail-api.ini})
        sh(%{sed -i 's/# port=5998/port=5998/' /etc/contrail/contrail-control.conf})
        sh(%{sed -i 's/# server=127.0.0.1/server=127.0.0.1/' /etc/contrail/contrail-control.conf})
        sh(%{sed -i 's/# port=5998/port=5998/' /etc/contrail/contrail-collector.conf})
        sh(%{sed -i 's/# server=0.0.0.0/server=127.0.0.1/' /etc/contrail/contrail-collector.conf})
        sh(%{sed -i 's/# user=control-user/user=control-user/g' /etc/contrail/contrail-control.conf})
        sh(%{sed -i 's/# password=control-user-passwd/password=control-user-passwd/' /etc/contrail/contrail-control.conf})
        sh(%{sed -i 's/Xss180k/Xss280k/' /etc/cassandra/conf/cassandra-env.sh})
    end

    # Reduce analytics cassandra db ttl
    sh(%{/opt/contrail/bin/openstack-config --set /etc/contrail/contrail-collector.conf DEFAULT analytics_data_ttl 1})

    # Fix webui config
    if !File.file? "/usr/bin/node" then
        sh("ln -sf /usr/bin/nodejs /usr/bin/node", true)
    end
    sh(%{sed -i "s/config.orchestration.Manager = 'openstack'/config.orchestration.Manager = 'none'/" /etc/contrail/config.global.js})
    sh(%{sed -i 's/8080/8070/' /etc/contrail/config.global.js})
    sh(%{echo control-node:control-node >> /etc/ifmap-server/basicauthusers.properties})

    if @platform =~ /fedora/
        fix_nodemgr_config_files
        sh("service cassandra restart")
        sh("service zookeeper restart")
        sh("service redis restart")
    else
        sh("service redis-server restart")
    end
    sh("service rabbitmq-server restart")
    sh("service supervisor-database restart") if @platform =~ /fedora/
    sh("service supervisor-control restart")
    sh("service supervisor-config restart")
    sh("service supervisor-analytics restart")

    if @platform =~ /ubuntu/
        sh("restart contrail-webui-webserver", true)
    else
        sh("service supervisor-webui restart", true)
    end

    60.times {|i| print "\rWait for #{i}/60 seconds to settle down.. "; sleep 1}
    verify_controller

    sh(%{python #{@utils}/provision_control.py --api_server_ip } +
       %{#{@controller_ip} --api_server_port 8082 --router_asn 64512 } +
       %{--host_name #{@opt.controller_host} --host_ip #{@controller_ip} } +
       %{--oper add })
end

def verify_compute
    5.times {|i| print "\rWait for #{i}/5 seconds to settle down.. "; sleep 1}
    sh("lsmod |\grep vrouter")
    sh("netstat -anp | \grep -w LISTEN | \grep -w 8085")
    sh("ping -c 3 #{@opt.controller_host}")
    sh("ping -c 3 github.com")
end

# Provision contrail-vrouter agent and vrouter kernel module
def provision_contrail_compute
    sh("ln -sf /bin/openstack-config /opt/contrail/bin/openstack-config") \
        if @platform =~ /fedora/
    ip, mask, gw, prefix_len = get_intf_ip(@opt.intf)
    create_vhost_interface(ip, mask, gw)

    if @platform =~ /fedora/ then
        ko = sh("find /usr/lib/modules/#{`uname -r`.chomp}/extra/net -name vrouter.ko")
    else
        ko="vrouter"
    end
    templ=<<EOF
LOG=/var/log/contrail.log
CONFIG=/etc/contrail/contrail-vrouter-agent.conf
prog=/usr/bin/contrail-vrouter-agent
kmod=#{ko}
pname=contrail-vrouter-agent
LIBDIR=/usr/lib64
DEVICE=vhost0
dev=#{@opt.intf}
vgw_subnet_ip=__VGW_SUBNET_IP__
vgw_intf=__VGW_INTF_LIST__
LOGFILE=--log-file=/var/log/contrail/vrouter.log
VHOST_CFG=/etc/sysconfig/network-scripts/ifcfg-vhost0
EOF
    File.open("/etc/contrail/agent_param", "w") { |fp| fp.puts templ}
    sh("touch /etc/contrail/default_pmac")

    sh("/opt/contrail/bin/openstack-config --set /etc/contrail/contrail-vrouter-agent.conf HYPERVISOR type kvm")
    sh("/opt/contrail/bin/openstack-config --set /etc/contrail/contrail-vrouter-agent.conf DISCOVERY server #{@opt.controller_ip}")
    sh("/opt/contrail/bin/openstack-config --set /etc/contrail/contrail-vrouter-agent.conf VIRTUAL-HOST-INTERFACE name vhost0")
    sh("/opt/contrail/bin/openstack-config --set /etc/contrail/contrail-vrouter-agent.conf VIRTUAL-HOST-INTERFACE ip #{ip}/#{prefix_len}")
    sh("/opt/contrail/bin/openstack-config --set /etc/contrail/contrail-vrouter-agent.conf VIRTUAL-HOST-INTERFACE gateway #{gw}")
    sh("/opt/contrail/bin/openstack-config --set /etc/contrail/contrail-vrouter-agent.conf VIRTUAL-HOST-INTERFACE physical_interface #{@opt.intf}")
    sh("/opt/contrail/bin/openstack-config --del /etc/contrail/contrail-vrouter-agent.conf VIRTUAL-HOST-INTERFACE compute_node_address")

    nodemgr_conf = <<EOF
[DISCOVERY]
server=#{@opt.controller_ip}
port=5998
[COLLECTOR]
server_list=#{@opt.controller_ip}:8086
EOF
    File.open("/etc/contrail/contrail-vrouter-nodemgr.conf", "w") {|fp| fp.puts nodemgr_conf}

    key = File.file?(@opt.ssh_key) ? "-i #{@opt.ssh_key}" : ""
    sh("sshpass -p #{@opt.password} ssh -t #{key} #{@opt.user}@#{@opt.controller_host} sudo python #{@utils}/provision_vrouter.py --host_name #{sh('hostname')} --host_ip #{ip} --api_server_ip #{@opt.controller_ip} --oper add", false, 20, 6)
    sh("sync; echo 3 > /proc/sys/vm/drop_caches") if @platform =~ /ubuntu/
    sh("service supervisor-vrouter restart")
    sh("service contrail-vrouter-agent restart")

    # Remove ip address from the interface as that is taken over by vhost0
    sh("ifdown #{@opt.intf}; ifup #{@opt.intf}", true, 1, 1, true)
    sh("ip addr flush dev #{@opt.intf}", true, 1, 1, true)

    # Restore default route
    sh("ip route add 0.0.0.0/0 via #{gw}", true, 1, 1, true)

    # Setup virtual gateway
    sh("python #{@utils}/provision_vgw_interface.py --oper create --interface vgw_public --subnets #{@opt.public_net} --routes 0.0.0.0/0 --vrf default-domain:default-project:Public:Public", false, 5, 5) if @opt.provision_vgw

    verify_compute
end

# http://www.fedora.hk/linux/yumwei/show_45.html
def fix_docker_file_system_issue
    return unless @opt.fix_docker_issue
    return if @platform !~ /ubuntu/

    sh("service docker stop", true)
    sh("mv /mnt/docker /mnt/docker.old", true)
    sh("mkdir -p /root/docker", true)
    sh("ln -sf /root/docker /mnt/docker", true)
    sh("mkdir -p /mnt/docker/devicemapper/devicemapper", true)
    sh("dd if=/dev/zero of=/mnt/docker/devicemapper/devicemapper/data bs=1G count=0 seek=250", true)
    sh("service docker restart", true)
end

def provision_contrail_compute_kubernetes
    return unless @opt.setup_kubernetes

    # Copy kubectl from kubernets-master node
    key = File.file?(@opt.ssh_key) ? "-i #{@opt.ssh_key}" : ""
    sh("sshpass -p #{@opt.password} scp #{key} #{@opt.user}@#{@opt.controller_host}:/usr/local/bin/kubectl /usr/local/bin/.")
    sh("ln -sf /usr/local/bin/kubectl /usr/bin/kubectl", true)

    Dir.chdir("#{@ws}/../opencontrail-kubelet")
    sh("python setup.py install")
    plugin = "opencontrail"
    sh("mkdir -p /usr/libexec/kubernetes/kubelet-plugins/net/exec/#{plugin}")
    path = @platform =~ /fedora/ ? "/usr/bin/opencontrail-kubelet-plugin" :
                                   "/usr/local/bin/opencontrail-kubelet-plugin"
    sh("ln -sf #{path} " +
       "/usr/libexec/kubernetes/kubelet-plugins/net/exec/#{plugin}/#{plugin}")

    # Generate default plugin configuration file
    plugin_conf = <<EOF
[DEFAULTS]
api_server = #{@opt.controller_ip}
net_mode = bridge
EOF
    File.open("/usr/libexec/kubernetes/kubelet-plugins/net/exec/#{plugin}/config", "w") { |fp|
        fp.puts plugin_conf
    }

    if @platform =~ /fedora/
        sh(%{sed -i 's/DAEMON_ARGS=" /DAEMON_ARGS=" --network_plugin=#{plugin} /' /etc/sysconfig/kubelet})
        sh("systemctl restart kubelet", true)
        sh("systemctl stop kube-proxy", true)
    else
        sh(%{sed -i 's/DAEMON_ARGS /DAEMON_ARGS --network_plugin=#{plugin} /' /etc/default/kubelet})
        sh("service kubelet restart", true)

        # Disable kube-proxy monitoring and stop the service.
        sh("mv /etc/monit/conf.d/kube-proxy /etc/monit/.", true)
        sh("monit reload", true)
        sh("service kube-proxy stop", true)
    end

    # Flush iptable nat entries
    sh("iptables -F -t nat")
end

def provision_contrail_controller_kubernetes
    return unless @opt.setup_kubernetes

    # Start kube web server in background
    # http://localhost:8001/static/app/#/dashboard/
    sh("ln -sf /usr/local/bin/kubectl /usr/bin/kubectl", true)
    sh("nohup /usr/local/bin/kubectl proxy --www=#{@ws}/build_kubernetes/www 2>&1 > /var/log/kubectl-web-proxy.log", true, 1, 1, true)

    target = @platform =~ /fedora/ ? "/root" : "/home/ubuntu"

    # Start kube-network-manager plugin daemon in background
    sh(%{nohup #{target}/contrail/kube-network-manager -- --contrail_api=#{@opt.controller_ip} --public_net="#{@opt.public_net}" --portal_net="#{@opt.portal_net}" --private_net="#{@opt.private_net}" 2>&1 > /var/log/contrail/kube-network-manager.log}, true, 1, 1, true) if @platform =~ /ubuntu/
end

def build_kube_network_manager (kubernetes_branch = "v0.20.1",
                                  contrail_branch = "master")
    return unless @opt.setup_kubernetes
    ENV["TARGET"]="#{ENV["HOME"]}/contrail"
    ENV["CONTRAIL_BRANCH"]=contrail_branch
    ENV["KUBERNETES_BRANCH"]=kubernetes_branch
    ENV["GOPATH"]="#{ENV["TARGET"]}/kubernetes/Godeps/_workspace"
    target = @platform =~ /fedora/ ? "/root" : "/home/ubuntu"

    sh("rm -rf #{ENV["TARGET"]}")
    sh("mkdir -p #{ENV["TARGET"]}")
    Dir.chdir(ENV["TARGET"])

    commands=<<EOF
wget -q -O - https://storage.googleapis.com/golang/go1.4.2.linux-amd64.tar.gz | tar -C /usr/local -zx
rm -rf /usr/bin/go
ln -sf /usr/local/go/bin/go /usr/bin/go
git clone -b #{ENV["KUBERNETES_BRANCH"]} https://github.com/googlecloudplatform/kubernetes
go get github.com/Juniper/contrail-go-api
wget -q https://raw.githubusercontent.com/Juniper/contrail-controller/#{ENV["CONTRAIL_BRANCH"]}/src/schema/vnc_cfg.xsd
wget -q https://raw.githubusercontent.com/Juniper/contrail-controller/#{ENV["CONTRAIL_BRANCH"]}/src/schema/loadbalancer.xsd || true
git clone -b #{ENV["CONTRAIL_BRANCH"]} https://github.com/Juniper/contrail-generateDS.git
./contrail-generateDS/generateDS.py -f -o $GOPATH/src/github.com/Juniper/contrail-go-api/types -g golang-api vnc_cfg.xsd 2>/dev/null
ln -sf #{target}/contrail-kubernetes ./kubernetes/Godeps/_workspace/src/github.com/Juniper/contrail-kubernetes
mkdir -p #{ENV["GOPATH"]}/src/github.com/GoogleCloudPlatform
ln -sf #{ENV["TARGET"]}/kubernetes #{ENV["GOPATH"]}/src/github.com/GoogleCloudPlatform/kubernetes
go build github.com/Juniper/contrail-kubernetes/cmd/kube-network-manager
EOF
    commands.split(/\n/).each { |cmd| sh(cmd) }
end

def main
    initial_setup
    download_contrail_software if @opt.contrail_install
    if @opt.role == "controller" or @opt.role == "all" then
        install_thirdparty_software_controller if @opt.contrail_install
        install_contrail_software_controller if @opt.contrail_install
        provision_contrail_controller if @opt.contrail_install
        build_kube_network_manager
        provision_contrail_controller_kubernetes
    end
    if @opt.role == "compute" or @opt.role == "all" then
        fix_docker_file_system_issue # Work-around docker file system issues
        install_thirdparty_software_compute if @opt.contrail_install
        install_contrail_software_compute if @opt.contrail_install
        provision_contrail_compute if @opt.contrail_install
        provision_contrail_compute_kubernetes
    end
end

main
