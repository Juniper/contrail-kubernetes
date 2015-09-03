{% set params = "" -%}

{% if pillar['service_private_ip_range'] is defined -%}
{% set private_net = "--private_net=" + pillar['service_private_ip_range'] -%}
{% else -%}
{% set private_net = "--private_net=10.10.0.0/16" -%}
{% endif -%}

{% if pillar['service_cluster_ip_range'] is defined -%}
{% set portal_net = "--portal_net=" + pillar['service_cluster_ip_range'] -%}
{% else -%}
{% set portal_net = "--portal_net=10.0.0.0/16" -%}
{% endif -%}

{% if pillar['opencontrail_public_subnet'] is defined -%}
{% set public_net = "--public_net=" + pillar['opencontrail_public_subnet'] -%}
{% else -%}
{% set public_net = "--public_net=10.1.0.0/16" -%}
{% endif -%}

{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name":"kube-network-manager"},
    "spec":{
        "hostNetwork": true,
        "containers":[{
            "name": "kube-network-manager",
            "image": "opencontrail/kube-network-manager",
            "command": ["/go/kube-network-manager", "--", "{{ private_net }}", "{{ portal_net }}", "{{ public_net }}"],
            "volumeMounts": [{
                    "name": "config",
                    "mountPath": "/etc/kubernetes"
            },
                {
                    "name": "logs",
                    "mountPath": "/var/log/contrail",
                    "readOnly": false
        }]
        }],
    "volumes": [{
        "name": "config",
        "hostPath": {"path": "/etc/contrail"}
    },
        {
        "name": "logs",
        "hostPath": {"path": "/var/log/contrail"}
        }]
    }
}
