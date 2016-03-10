node {
    checkout scm
    docker.withRegistry('https://localhost:5000') {
        def image = docker.build('opencontrail/kube-network-manager')
        image.push("${env.BRANCH_NAME}")
    }
}
