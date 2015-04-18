#!/usr/bin/env ruby

# Use this script to install and provision contrail nodes.
# sudo ruby $PWD/contrail-kubernetes/scripts/opencontrail-install/contrail_install.rb

raise 'Must run as root' unless Process.uid == 0

@ws="#{File.dirname($0)}"
require "#{@ws}/util"

sh("\grep aurora /etc/hostname", true)
@controller_host = $?.to_i == 0 ? "aurora" : "kubernetes-master"
@intf = "eth1"

# Find platform OS
sh(%{\grep -i "ubuntu 14" /etc/issue 2>&1 > /dev/null}, true)
@platform = $?.to_i == 0 ? "ubuntu1404" : "fedora21"

@control_node_introspect_port = @controller_host == "aurora" ? 9083 : "8083"

require "#{@ws}/#{@platform}/install"

# Update ssh configuration
def ssh_setup
    conf=<<EOF
UserKnownHostsFile=/dev/null
StrictHostKeyChecking=no
LogLevel=QUIET
EOF
    sh("mkdir -p /root/.ssh")
    File.open("/root/.ssh/config", "a") { |fp| fp.puts(conf) }
    sh("chmod 600 /root/.ssh/config")

    # Add ssh config to ~vagrant also.
    sh("mkdir -p ~vagrant/.ssh")
    File.open(File.expand_path("~vagrant/.ssh/config"), "a") { |fp|
        fp.puts(conf)
    }
    sh("chmod 600 ~vagrant/.ssh/config")
    sh("chown vagrant.vagrant ~vagrant/.ssh/config")
    sh("chown vagrant.vagrant ~vagrant/.ssh/.")
end

# Do initial setup
def initial_setup
    @resolvers = sh("\grep -w nameserver /etc/resolv.conf").split("\n")
    ssh_setup
    sh("service hostname restart", true) if @platform =~ /ubuntu/
#   @contrail_controller = IPSocket.getaddress(@controller_host)
    @contrail_controller =
        sh(%{grep #{@controller_host} /etc/hosts | awk '{print $1}'})
    error "Cannot resolve contrail-controller host" \
        if @contrail_controller.empty?
    Dir.chdir("#{@ws}")
end

def update_controller_etc_hosts
    # Update /etc/hosts with the IP address
    ip, mask, gw = get_intf_ip(@intf)
    @controller_ip = ip

    sh("\grep #{@controller_host} /etc/hosts > /dev/null", true)
    sh("echo #{ip} #{@controller_host} >> /etc/hosts") if $?.to_i != 0
end

def verify_controller
    sleep 30
    sh("netstat -anp | \grep LISTEN | \grep -w 5672") # RabbitMQ
    sh("netstat -anp | \grep LISTEN | \grep -w 2181") # ZooKeeper
    sh("netstat -anp | \grep LISTEN | \grep -w 9160") # Cassandra
    sh("netstat -anp | \grep LISTEN | \grep -w #{@control_node_introspect_port}") # Control-Node
    sh("netstat -anp | \grep LISTEN | \grep -w 5998") # discovery
    sh("netstat -anp | \grep LISTEN | \grep -w 8443") # IFMAP-Server
    sh("netstat -anp | \grep LISTEN | \grep -w 8082") # API-Server
    sh("netstat -anp | \grep LISTEN | \grep -w 8086") # Collector
    sh("netstat -anp | \grep LISTEN | \grep -w 8081") # OpServer
end

# Provision contrail-controller
def provision_contrail_controller
    update_controller_etc_hosts

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

    if @platform =~ /fedora/
        sh("service cassandra restart")
        sh("service zookeeper restart")
    end
    sh("service rabbitmq-server restart")
    sh("service supervisor-database restart")
    sh("service supervisor-control restart")
    sh("service supervisor-config restart")
    sh("service supervisor-analytics restart")

    verify_controller

    sh(%{python /opt/contrail/utils/provision_control.py --api_server_ip } +
       %{#{@controller_ip} --api_server_port 8082 --router_asn 64512 } +
       %{--host_name #{@controller_host} --host_ip #{@controller_ip} } +
       %{--oper add })
end

def verify_compute
    sleep 5
    sh("lsmod |\grep vrouter")
    sh("netstat -anp | \grep -w LISTEN | \grep -w 8085")
    sh("ping -c 3 #{@controller_host}")
    sh("ping -c 3 github.com")
end

# Provision contrail-vrouter agent and vrouter kernel module
def provision_contrail_compute
    ip, mask, gw = get_intf_ip(@intf)
    create_vhost_interface(ip, mask, gw)

    sh("sed 's/__DEVICE__/#{@intf}/' /etc/contrail/agent_param.tmpl > /etc/contrail/agent_param")
    sh("sed -i 's/# type=kvm/type=kvm/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("touch /etc/contrail/default_pmac")
    sh("sed -i 's/# name=vhost0/name=vhost0/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sed -i 's/# physical_interface=vnet0/physical_interface=#{@intf}/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sed -i 's/# server=10.204.217.52/server=#{@contrail_controller}/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sshpass -p vagrant ssh vagrant@#{@controller_host} sudo python /opt/contrail/utils/provision_vrouter.py --host_name #{sh('hostname')} --host_ip #{ip} --api_server_ip #{@contrail_controller} --oper add")
    sh("service supervisor-vrouter restart")
    sh("service contrail-vrouter-agent restart")

    # Remove ip address from the interface as that is taken over by vhost0
    sh("ifdown #{@intf}; ifup #{@intf}")
    sh("ip addr flush dev #{@intf}")

    # Restore DNS resolver
    @resolvers.each { |r|
        sh(%{sh -c "echo #{r} >> /etc/resolv.conf"})
    }
    verify_compute
end

def provision_contrail_compute_kubernetes
    Dir.chdir("#{@ws}/scripts/opencontrail-kubelet")
    sh("python setup.py install")
    plugin = "opencontrail"
    sh("mkdir -p /usr/libexec/kubernetes/kubelet-plugins/net/exec/#{plugin}")
    sh("ln -sf /usr/bin/opencontrail-kubelet-plugin " +
       "/usr/libexec/kubernetes/kubelet-plugins/net/exec/#{plugin}/#{plugin}")

    # Generate default plugin configuration file
    plugin_conf = <<EOF
[DEFAULTS]
api_server = #{@contrail_controller}
net_mode = bridge
EOF
    File.open("/usr/libexec/kubernetes/kubelet-plugins/net/exec/#{plugin}/config", "w") { |fp|
        fp.puts plugin_conf
    }

    sh(%{sed -i 's/DAEMON_ARGS=" /DAEMON_ARGS=" --network_plugin=#{plugin} /' /etc/sysconfig/kubelet})
    sh("systemctl restart kubelet")
end

def main
    initial_setup
    download_contrail_software
    if ARGV[0] == "controller" or ARGV[0] == "all" then
        install_thirdparty_software_controller
        install_contrail_software_controller
        provision_contrail_controller
    end
    if ARGV[0] == "compute" or ARGV[0] == "all" then
        install_thirdparty_software_compute
        install_contrail_software_compute
        provision_contrail_compute
        # provision_contrail_compute_kubernetes
    end
end

main
