#!/usr/bin/env ruby

@branch = "3.0" # master
@tag = "4100"
@pkg_tag = "#{@branch}-#{@tag}"

@common_packages = [
    "createrepo",
    "docker",
    "git",
    "sshpass",
    "strace",
    "tcpdump",
    "unzip",
    "vim",
]

@controller_thirdparty_packages = [
    @common_packages,
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

    "supervisor",
    "supervisord",
    "python-supervisor",
    "rabbitmq-server",
    "python-kazoo",
    "python-ncclient",
]

@controller_contrail_packages = [
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-database-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-config-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-lib-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-control-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-analytics-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-web-controller-#{@pkg_tag}.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-web-core-#{@pkg_tag}.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-setup-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-nodemgr-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-utils-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-dns-#{@pkg_tag}.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-control-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-database-#{@pkg_tag}.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-webui-#{@pkg_tag}.fc21.noarch.rpm",
]

@compute_thirdparty_packages = [
    @common_packages,
    "#{@ws}/thirdparty/xmltodict-0.7.0-0contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/consistent_hash-1.0-0contrail0.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-pycassa-1.10.0-0contrail.el7.noarch.rpm ",
]

@compute_contrail_packages = [
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

# Download and extract contrail and thirdparty rpms
def download_contrail_software
    sh("wget -qO - https://github.com/rombie/opencontrail-packages/blob/master/fedora21/contrail.tar.xz?raw=true | tar Jx")
    sh("wget -qO - https://github.com/rombie/opencontrail-packages/blob/master/fedora21/thirdparty.tar.xz?raw=true | tar Jx")
end

# Install from /cs-shared/builder/cache/centoslinux70/juno
def install_thirdparty_software_controller
    sh("yum -y remove java-1.8.0-openjdk java-1.8.0-openjdk-headless")
    sh("yum -y install #{@controller_thirdparty_packages.join(" ")}")
end

# Install contrail controller software
def install_contrail_software_controller
    sh("yum -y install #{@controller_contrail_packages.join(" ")}")

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

def create_vhost_interface(ip, mask, gw)
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
end

# Install third-party software
def install_thirdparty_software_compute
    sh("yum -y install #{@compute_thirdparty_packages.join(" ")}", true)
    sh("service docker restart")
#   sh("docker pull ubuntu")
end

# Install contrail compute software
def install_contrail_software_compute
    sh("yum -y install #{@compute_contrail_packages.join(" ")}", true)
end
