#!/usr/bin/env ruby

# Use this script to install and provision contrail nodes.

raise 'Must run as root' unless Process.uid == 0

require 'socket'
require 'ipaddr'

@ws="#{File.dirname($0)}/../.."
@intf = "eth1"
@controller_host = "kubernetes-master"
@branch = "3.0" # master
@tag = "4100"
@pkg_tag = "#{@branch}-#{@tag}"

def sh(cmd, ignore_exit_code = false)
    puts cmd
    r = `#{cmd}`.chomp
    puts r
    exit -1 if !ignore_exit_code and $?.to_i != 0
    return r
end

def error(msg); puts msg; exit -1 end

# Update ssh configuration
def ssh_setup
    conf=<<EOF
UserKnownHostsFile=/dev/null
StrictHostKeyChecking=no
LogLevel=QUIET
EOF
    sh("mkdir -p #{ENV['HOME']}/.ssh")
    File.open("#{ENV["HOME"]}/.ssh/config", "a") { |fp| fp.puts(conf) }
    sh("chmod 600 #{ENV['HOME']}/.ssh/config")

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
    @contrail_controller = IPSocket.getaddress(@controller_host)
    error "Cannot resolve contrail-controller host" \
        if @contrail_controller.empty?
    Dir.chdir("#{@ws}")
end

# Download and extract contrail and thirdparty rpms
def download_contrail_software
    sh("wget -qO - https://github.com/rombie/opencontrail-netns/blob/master/provision/fedora/contrail-rpms.tar.xz?raw=true | tar Jx")
    sh("wget -qO - https://github.com/rombie/opencontrail-netns/blob/master/provision/fedora/thirdparty.tar.xz?raw=true | tar Jx")
end

# Install third-party software from /cs-shared/builder/cache/centoslinux70/juno
def install_thirdparty_software_controller
    sh("yum -y remove java-1.8.0-openjdk java-1.8.0-openjdk-headless")

    init_common
    sh("yum -y install supervisor supervisord python-supervisor rabbitmq-server python-kazoo python-ncclient", true)

    third_party_rpms = [
    "#{@ws}/thirdparty/authbind-2.1.1-0.x86_64.rpm",
    "#{@ws}/thirdparty/librdkafka1-0.8.5-2.0contrail0.el7.centos.x86_64.rpm",
    "#{@ws}/thirdparty/librdkafka-devel-0.8.5-2.0contrail0.el7.centos.x86_64.rpm",
    "#{@ws}/thirdparty/cassandra12-1.2.11-1.noarch.rpm",
    "#{@ws}/thirdparty/kafka-2.9.2-0.8.2.0.0contrail0.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-pycassa-1.10.0-0contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/thrift-0.9.1-12.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-thrift-0.9.1-12.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-bitarray-0.8.0-0contrail.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-jsonpickle-0.3.1-2.1.el7.noarch.rpm",
    "#{@ws}/thirdparty/xmltodict-0.7.0-0contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-amqp-1.4.5-1.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-geventhttpclient-1.0a-0contrail.el7.x86_64.rpm",
    "#{@ws}/thirdparty/consistent_hash-1.0-0contrail0.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-kafka-python-0.9.2-0contrail0.el7.noarch.rpm",
    "#{@ws}/thirdparty/redis-py-0.1-2contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/ifmap-server-0.3.2-2contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/hc-httpcore-4.1-1.jpp6.noarch.rpm",
    "#{@ws}/thirdparty/zookeeper-3.4.3-1.el6.noarch.rpm",
    "#{@ws}/thirdparty/bigtop-utils-0.6.0+243-1.cdh4.7.0.p0.17.el6.noarch.rpm",
    "#{@ws}/thirdparty/python-keystone-2014.1.3-2.el7ost.noarch.rpm",
    "#{@ws}/thirdparty/python-psutil-1.2.1-1.el7.x86_64.rpm",
    "#{@ws}/thirdparty/java-1.7.0-openjdk-1.7.0.55-2.4.7.2.el7_0.x86_64.rpm",
    "#{@ws}/thirdparty/java-1.7.0-openjdk-headless-1.7.0.55-2.4.7.2.el7_0.x86_64.rpm",
    "#{@ws}/thirdparty/log4j-1.2.17-15.el7.noarch.rpm",

    # "#{@ws}/thirdparty/python-psutil-0.6.1-3.el7.x86_64.rpm",
    # "#{@ws}/thirdparty/python-keystone-2014.2.1-1.el7.centos.noarch.rpm",
    ]
    sh("yum -y install #{third_party_rpms.join(" ")}", true)
end

# Install contrail controller software
def install_contrail_software_controller
    contrail_rpms = [
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-database-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-config-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-lib-#{@pkg_tag}0.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-control-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-analytics-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-web-controller-#{@pkg_tag}.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-web-core-#{@pkg_tag}.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-setup-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-nodemgr-#{@pkg_tag}4100.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-utils-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-dns-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-control-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-database-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-webui-#{@pkg_tag}.fc21.noarch.rpm",
    ]
    sh("yum -y install #{contrail_rpms.join(" ")}", true)

    sh("rpm2cpio #{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-openstack-database-#{@pkg_tag}.fc21.noarch.rpm | cpio -idmv")
    sh("cp etc/rc.d/init.d/zookeeper /etc/rc.d/init.d/")
    sh("rpm2cpio #{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-openstack-config-#{@pkg_tag}.fc21.noarch.rpm | cpio -idmv")
    sh("cp etc/rc.d/init.d/rabbitmq-server.initd.supervisord /etc/rc.d/init.d/")
    sh("cp -a etc/contrail/supervisord_support_service_files/ /etc/contrail/")

    sh("rpm2cpio #{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-openstack-control-#{@pkg_tag}.fc21.noarch.rpm | cpio -idmv")
    sh("cp -a etc/contrail/supervisord_support_service_files/ /etc/contrail/")
    sh("cp -a etc/contrail/supervisord_control_files/ /etc/contrail/")
    sh("cp etc/contrail/supervisord_config_files/* /etc/contrail/supervisord_config_files/")

    # XXX Install missing service files.
    sh("cp #{@ws}/contrail/controller/run/systemd/generator.late/*.service /run/systemd/generator.late/.")
end

def update_controller_etc_hosts
    # Update /etc/hosts with the IP address
    sh("\grep #{@controller_host} /etc/hosts > /dev/null", true)
    return if $?.to_i == 0
    ip, mask, gw = get_intf_ip
    sh("echo #{ip} #{@controller_host} >> /etc/hosts")
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

    sh("service cassandra start")
    sh("service zookeeper start")
    sh("service rabbitmq-server start")
    sh("service supervisor-database start")
    sh("service supervisor-control start")
    sh("service supervisor-config start")
    sh("service supervisor-analytics start")

    sleep 30
    sh("netstat -anp | \grep LISTEN | \grep -w 5672") # RabbitMQ
    sh("netstat -anp | \grep LISTEN | \grep -w 2181") # ZooKeeper
    sh("netstat -anp | \grep LISTEN | \grep -w 9160") # Cassandra
    sh("netstat -anp | \grep LISTEN | \grep -w 8083") # Control-Node
    sh("netstat -anp | \grep LISTEN | \grep -w 5998") # discovery
    sh("netstat -anp | \grep LISTEN | \grep -w 8443") # IFMAP-Server
    sh("netstat -anp | \grep LISTEN | \grep -w 8082") # API-Server
    sh("netstat -anp | \grep LISTEN | \grep -w 8086") # Collector
    sh("netstat -anp | \grep LISTEN | \grep -w 8081") # OpServer

    sh(%{python /opt/contrail/utils/provision_control.py --api_server_ip 10.245.1.2 --api_server_port 8082 --router_asn 64512 --host_name #{@controller_host} --host_ip 10.245.1.2 --oper add})
end

def init_common
    sh("yum -y install sshpass createrepo docker vim git zsh strace " +
       "tcpdump unzip", true)
end

# Install third-party software
def install_thirdparty_software_compute
    init_common
    third_party_rpms = [
    "#{@ws}/thirdparty/xmltodict-0.7.0-0contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/consistent_hash-1.0-0contrail0.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-pycassa-1.10.0-0contrail.el7.noarch.rpm ",
    ]

    sh("yum -y install #{third_party_rpms.join(" ")}", true)
    sh("systemctl restart docker")
#   sh("docker pull ubuntu")
end

# Install contrail compute software
def install_contrail_software_compute
    contrail_rpms = [
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-vrouter-api-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-utils-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-init-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-lib-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-agent-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-setup-#{@pkg_tag}.fc21.noarch.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-vrouter-common-#{@pkg_tag}.fc21.noarch.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-init-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-utils-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-nodemgr-#{@pkg_tag}.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-vrouter-common-#{@pkg_tag}.fc21.noarch.rpm",
    ]
    sh("yum -y install #{contrail_rpms.join(" ")}", true)
end

# Return interface IP address, mask and gateway information
def get_intf_ip(intf = @intf)
    prefix = sh("ip addr show dev #{@intf}|\grep -w inet | " +
                "\grep -v dynamic | awk '{print $2}'")
    error("Cannot retrieve #{@intf}'s IP address") if prefix !~ /(.*)\/(\d+)$/
    ip = $1
    mask = IPAddr.new(prefix).inspect.split("/")[1].chomp.chomp(">")
    gw = sh(%{netstat -rn |\grep "^0.0.0.0" | awk '{print $2}'})

    return ip, mask, gw
end

# Provision contrail-vrouter agent and vrouter kernel module
def provision_contrail_compute
    ip, mask, gw = get_intf_ip
    ifcfg = <<EOF
#Contrail vhost0
DEVICE=vhost0
ONBOOT=yes
BOOTPROTO=none
IPV6INIT=no
USERCTL=yes
IPADDR=#{ip}
NETMASK=#{mask}
NM_CONTROLLED=no
#NETWORK MANAGER BUG WORKAROUND
SUBCHANNELS=1,2,3
GATEWAY=#{gw}
DNS1=8.8.8.8
#DOMAIN="contrail.juniper.net. juniper.net. jnpr.net. contrail.juniper.net"
EOF
    File.open("/etc/sysconfig/network-scripts/ifcfg-vhost0", "w") { |fp|
        fp.puts(ifcfg)
    }

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
    sleep 5
    sh("lsmod |\grep vrouter")
    sh("netstat -anp | \grep -w LISTEN | \grep -w 8085")
    sh("ping -c 3 #{@controller_host}")
    sh("ping -c 3 github.com")
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

def sh_container(container_id, cmd, ignore = false)
    pid = sh(%{docker inspect -f {{.State.Pid}} #{container_id}})
    sh(%{echo #{cmd} | nsenter -n -t #{pid} sh})
end

def main
    initial_setup
    download_contrail_software
    if ARGV[0] == "controller" then
        install_thirdparty_software_controller
        install_contrail_software_controller
        provision_contrail_controller
    else # compute
        install_thirdparty_software_compute
        install_contrail_software_compute
        provision_contrail_compute
        provision_contrail_compute_kubernetes
    end
end

main
