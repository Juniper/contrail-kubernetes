#!/usr/bin/env ruby

@branch = "3.0" # master
@tag = "4100"
@pkg_tag = "#{@branch}-#{@tag}"

@common_packages = [
#   "docker",
    "gdebi-core",
    "git",
    "sshpass",
    "strace",
    "tcpdump",
    "unzip",
    "vim",
]

@controller_thirdparty_packages = [
    "#{@ws}/thirdparty/python-pycassa_1.11.0-1contrail2_all.deb",
    "#{@ws}/thirdparty/python-consistent-hash_1.0-0contrail1_amd64.deb",
    "#{@ws}/thirdparty/python-backports.ssl-match-hostname_3.4.0.2-1contrail1_all.deb",
    "#{@ws}/thirdparty/python-certifi_1.0.1-1contrail1_all.deb",
    "#{@ws}/thirdparty/python-geventhttpclient_1.1.0-1contrail1_amd64.deb",
    "#{@ws}/thirdparty/python-kazoo_1.3.1-1contrail2_all.deb",
    "#{@ws}/thirdparty/python-ncclient_0.4.1-1contrail1_all.deb",
    "#{@ws}/thirdparty/python-xmltodict_0.9.0-1contrail1_all.deb",
    "#{@ws}/thirdparty/librdkafka1_0.8.5-2-0contrail0.14.04_amd64.deb",
    "#{@ws}/thirdparty/python-kafka-python_0.9.2-0contrail0_all.deb",
    "#{@ws}/thirdparty/python-redis_2.8.0-1contrail1_all.deb",
    "#{@ws}/thirdparty/cassandra_1.2.11_all.deb",
    "#{@ws}/thirdparty/kafka_2.9.2-0.8.2.0-0contrail0_amd64.deb",
]

@controller_contrail_packages = [
    "#{@ws}/build/packages/python-contrail_#{@pkg_tag}_all.deb",
    "#{@ws}/build/packages/contrail-config_#{@pkg_tag}_all.deb",
    "#{@ws}/build/packages/contrail-lib_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/packages/contrail-control_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/packages/contrail-analytics_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/debian/contrail-web-core_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/debian/contrail-web-controller_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/debian/contrail-setup_#{@pkg_tag}_all.deb",
    "#{@ws}/build/debian/contrail-nodemgr_#{@pkg_tag}_all.deb",
    "#{@ws}/build/packages/contrail-utils_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/packages/contrail-dns_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/packages/ifmap-server_0.3.2-1contrail1_all.deb",
    "#{@ws}/build/packages/ifmap-python-client_0.1-2_all.deb",

    "#{@ws}/build/debian/contrail-openstack-control_#{@pkg_tag}_all.deb",
    "#{@ws}/build/debian/contrail-openstack-webui_#{@pkg_tag}_all.deb",
    "#{@ws}/build/debian/contrail-openstack-analytics_#{@pkg_tag}_all.deb",

     # "#{@ws}/build/debian/contrail-openstack-database_#{@pkg_tag}_all.deb",

#   "#{@ws}/build/debian/contrail-f5_3.0-4100_all.deb",
#   "#{@ws}/build/debian/contrail-openstack-config_#{@pkg_tag}_all.deb",
]

@compute_thirdparty_packages = [
    "#{@ws}/thirdparty/python-pycassa_1.11.0-1contrail2_all.deb",
    "#{@ws}/thirdparty/python-consistent-hash_1.0-0contrail1_amd64.deb",
    "#{@ws}/thirdparty/python-backports.ssl-match-hostname_3.4.0.2-1contrail1_all.deb",
    "#{@ws}/thirdparty/python-certifi_1.0.1-1contrail1_all.deb",
    "#{@ws}/thirdparty/python-geventhttpclient_1.1.0-1contrail1_amd64.deb",
    "#{@ws}/thirdparty/python-docker-py_0.6.1-dev_all.deb",
]

@compute_contrail_packages = [
    "#{@ws}/build/packages/python-contrail_#{@pkg_tag}_all.deb",
    "#{@ws}/build/packages/contrail-lib_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/debian/contrail-setup_#{@pkg_tag}_all.deb",
    "#{@ws}/build/packages/contrail-utils_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/debian/contrail-nodemgr_#{@pkg_tag}_all.deb",
    "#{@ws}/build/packages/contrail-vrouter-utils_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/packages/contrail-vrouter-dkms_3.0-4100_all.deb",
    "#{@ws}/build/packages/contrail-vrouter-agent_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/packages/python-contrail-vrouter-api_#{@pkg_tag}_all.deb",
    "#{@ws}/build/packages/python-opencontrail-vrouter-netns_#{@pkg_tag}_amd64.deb",
    "#{@ws}/build/debian/contrail-vrouter-init_#{@pkg_tag}_all.deb",
    "#{@ws}/build/debian/contrail-nova-vif_#{@pkg_tag}_all.deb",
#   "#{@ws}/build/debian/contrail-vrouter-common_#{@pkg_tag}_all.deb",

#   "#{@ws}/build/packages/contrail-vrouter-3.13.0-49-generic_#{@pkg_tag}_all.deb",
#   "#{@ws}/build/packages/python-vrouter-utils_#{@pkg_tag}_amd64.deb",
]

# Download and extract contrail and thirdparty rpms
def download_contrail_software
    sh("wget -qO - https://github.com/rombie/opencontrail-packages/blob/master/ubuntu1404/contrail.tar.xz?raw=true | tar Jx")
    sh("wget -qO - https://github.com/rombie/opencontrail-packages/blob/master/ubuntu1404/thirdparty.tar.xz?raw=true | tar Jx")
    sh("wget -qO - https://github.com/rombie/opencontrail-packages/blob/master/ubuntu1404/kubernetes.tar.xz?raw=true | tar Jx")
end

# Install from /cs-shared/builder/cache/centoslinux70/icehouse
def install_thirdparty_software_controller
    sh("apt-get -y install openjdk-7-jre rabbitmq-server zookeeperd")
    sh("apt-get -y install #{@common_packages.join(" ")}")
    @controller_thirdparty_packages.each { |pkg| sh("gdebi -n #{pkg}") }
end

# Install contrail controller software
def install_contrail_software_controller
    @controller_contrail_packages.each { |pkg| sh("gdebi -n #{pkg}") }

    sh("rm -rf /etc/init/zookeeper.conf")
    sh("dpkg -i --force-overwrite #{@ws}/build/debian/contrail-openstack-database_#{@pkg_tag}_all.deb")

    # Fix ubuntu specific issues
    sh("apt-get -y remove openjdk-6-jre", true)
    sh("apt-get -y autoremove")
    sh("ln -sf /etc/cassandra /etc/cassandra/conf")

    sh("dpkg -x #{@ws}/build/debian/contrail-openstack-config_#{@pkg_tag}_all.deb #{@ws}/build/debian/extract")
    sh("cp -a #{@ws}/build/debian/extract/etc/* /etc/")
    sh("openstack-config --set /etc/contrail/contrail-control.conf DEFAULT http_server_port #{@control_node_introspect_port}")
end

def create_vhost_interface(ip, mask, gw)
    intf = "/etc/network/interfaces"
    `\grep vhost0 #{intf} 2>&1 > /dev/null`
    return if $?.to_i == 0

    ifcfg = <<EOF

auto vhost0
iface vhost0 inet static
      address #{ip}
      netmask #{mask}

EOF
    File.open(intf, "a") { |fp| fp.puts(ifcfg) }
end

# Install third-party software from /cs-shared/builder/cache/ubuntu1404/icehouse
def install_thirdparty_software_compute
    sh("apt-get -y install #{@common_packages.join(" ")}")
    @compute_thirdparty_packages.each { |pkg| sh("gdebi -n #{pkg}") }
end

# Install contrail compute software
def install_contrail_software_compute
    @compute_contrail_packages.each { |pkg| sh("gdebi -n #{pkg}") }
    sh("apt-get -y autoremove")
    sh("sync; echo 3 > /proc/sys/vm/drop_caches")
end
