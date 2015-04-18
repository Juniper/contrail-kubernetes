#!/usr/bin/env ruby

require 'socket'
require 'ipaddr'
require 'pp'

def sh(cmd, ignore_exit_code = false)
    puts cmd
    r = `#{cmd}`.chomp
    puts r
    exit -1 if !ignore_exit_code and $?.to_i != 0
    return r
end

def error(msg); puts msg; exit -1 end

# Return interface IP address, mask and gateway information
def get_intf_ip(intf)
    prefix = sh("ip addr show dev #{intf}|\grep -w inet | " +
                "\grep -v dynamic | awk '{print $2}'")
    error("Cannot retrieve #{intf}'s IP address") if prefix !~ /(.*)\/(\d+)$/
    ip = $1
    mask = IPAddr.new(prefix).inspect.split("/")[1].chomp.chomp(">")
    gw = sh(%{netstat -rn |\grep "^0.0.0.0" | awk '{print $2}'})

    return ip, mask, gw
end

def sh_container(container_id, cmd, ignore = false)
    pid = sh(%{docker inspect -f {{.State.Pid}} #{container_id}})
    sh(%{echo #{cmd} | nsenter -n -t #{pid} sh})
end
