node {
    checkout scm
    docker.withRegistry('https://localhost:5000:1.1') {
        def k8s_manager = docker.build('opencontrail/kube-network-manager')
        k8s_manager.push()
    }
}

