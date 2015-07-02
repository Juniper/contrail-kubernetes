#!/usr/bin/env ruby

require 'socket'
require 'ipaddr'
require 'pp'

def sh(cmd, ignore_exit_code = false, retry_count = 1, delay = 1, bg = false)
    puts cmd
    if bg then
        # Run command in background
        Process.detach(spawn(cmd))
        return
    end

    r = ""
    retry_count.times { |i|
        r = `#{cmd}`.chomp
        puts r
        break if $?.to_i == 0
        exit -1 if !ignore_exit_code and i == retry_count - 1
        sleep delay
        puts "#{i}/#{retry_count}: Retry: #{cmd}"
    }
    return r
end

def error(msg); puts msg; exit -1 end

# Return interface IP address, mask and gateway information
def get_intf_ip(intf)
    prefix = sh("ip addr show dev #{intf}|\grep -w inet | " +
                "\grep -v dynamic | awk '{print $2}'")
    error("Cannot retrieve #{intf}'s IP address") if prefix !~ /(.*)\/(\d+)$/
    ip = $1; prefix_len = $2
    mask = IPAddr.new(prefix).inspect.split("/")[1].chomp.chomp(">")
    gw = sh(%{netstat -rn |\grep "^0.0.0.0" | awk '{print $2}'})

    return ip, mask, gw, prefix_len
end

def sh_container(container_id, cmd, ignore = false)
    pid = sh(%{docker inspect -f {{.State.Pid}} #{container_id}})
    sh(%{echo #{cmd} | nsenter -n -t #{pid} sh})
end
