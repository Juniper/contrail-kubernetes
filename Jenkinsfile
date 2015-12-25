node {
    checkout scm
    docker.withRegistry('https://localhost:5000') {
        def origin_manager = docker.build('opencontrail/kube-network-manager:origin-1.1')
        origin_manager.push()
    }
}

