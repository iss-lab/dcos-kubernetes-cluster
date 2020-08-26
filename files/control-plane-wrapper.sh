#!/bin/bash

set -e
set -m  # Turn on job control so we can receive SIGCHLD when a child exits.

# ONSIGCHLD_PIDS will contain the PIDs we want to "monitor".
ONSIGCHLD_PIDS=()
# onsigchld will execute whenever a child process exits (after we trap SIGCHLD).
function onsigchld {
    # Loop through monitored PIDs...
    for pid in ${ONSIGCHLD_PIDS[@]}
    do
        # ... and if any of them has exited...
        kill -0 ${pid} > /dev/null 2>&1 || {
            # ... reset the trap so we don't get notified multiple times...
            trap - SIGCHLD;
            # ... and kill the remaining processes.
            # NOTE: One of the processes (the one that exited) will fail to be
            # killed which will cause 'kubelet-wrapper.sh' to exit with non-zero
            # code. This is intentional and sets the 'kube-node' task as failed.
            kill -9 ${ONSIGCHLD_PIDS[*]} > /dev/null 2>&1;
        }
    done
}

# tighten up permissions
[ -d .ssl ] && chmod 600 .ssl/*.key

# dcos-commons 0.42.1 and later turn on isolation of the /tmp folder and mess with the permissions:
# https://github.com/mesosphere/dcos-commons/blob/0.56.1/sdk/scheduler/src/main/java/com/mesosphere/sdk/offer/evaluate/PodInfoBuilder.java#L575-L581
# we must manually set the permissions on the /tmp directory so that we can pass conformance:
# https://github.com/kubernetes/kubernetes/blob/v1.16.9/test/e2e/common/host_path.go#L60
chmod 1777 /tmp

# Configure write access to all available devices. This needs to
# happen before any child cgroup is created. When using a container
# image cgroup namespacing is enabled, this means we should configure
# the root cgroup because it's pointing to the correct file.
echo "a *:* rwm" > /sys/fs/cgroup/devices/devices.allow || true

# docker and the kubelet require write access to /sys/ and /proc/sys
mount -o remount,rw /sys/
mount -o remount,rw /proc/sys

#
# workaround for kmem issues
#
# when we detect that we're running in an 3.10.0 kernel we setup PATH
# to point to custom built versions of docker and the kubelet that
# don't enable kmem accounting
#
# when not running on 3.10.0 kernels the following code snippet will
# return 1 and the script will exit. we add || true to handle that
# case
KERNEL_VERSION=$((uname -r | grep ^3.10.0) || true)
if [ ! -z "${KERNEL_VERSION}" ];
then
    printf "Running dockerd and kubelet that don't enable kmem accounting\n"
    export PATH=/usr/local/rhel/:/usr/local/rhel/docker/:${PATH}
fi

# set hostname in the task to avoid using --hostname-override flag; this works
# because mesos creates a new a uts namespace for this task
hostname ${TASK_NAME}.${SERVICE_NAME}.mesos

# remount /dev to have access to host devices
mkdir -p dev
mount -t devtmpfs none dev
mount --bind dev /dev

# Containers with permission CAP_NET_RAW can spoof their IP address if
# the rp_filter kernel setting is set to ‘loose’. We disable rp_filter
# in this network namespace to prevent this and make Calico happy.
sysctl -w net.ipv4.conf.all.rp_filter=1

# SDK doesn't allow mounting host-volumes where the container-path
# starts with a / so we mount bind them here.
mkdir -p /opt/mesosphere
mount --bind opt-mesosphere /opt/mesosphere

mkdir -p /lib/modules
mount --bind lib-modules /lib/modules

if [ "${USE_AGENT_DOCKER_CERTS}" = true ];
then
    mkdir -p /etc/docker/certs.d
    mount --bind docker-certs /etc/docker/certs.d
fi

printf "Configuring task environment...\n"

[ -z "$KUBE_ALLOCATABLE_CPUS" ] && (printf "Error: KUBE_ALLOCATABLE_CPUS not set or empty!" >&2 ; exit 1)
[ -z "$KUBE_ALLOCATABLE_MEM" ] && (printf "Error: KUBE_ALLOCATABLE_MEM not set or empty!" >&2 ; exit 1)
[ -z "$KUBE_RESERVED_CPUS" ] && (printf "Error: KUBE_RESERVED_CPUS not set or empty!" >&2 ; exit 1)
[ -z "$KUBE_RESERVED_MEM" ] && (printf "Error: KUBE_RESERVED_MEM not set or empty!" >&2 ; exit 1)

# The kubelet sees all of the host resources.
# To override the resources it will advertise, we set the allocatable resources
# as follows:
#  - reserved_cpu:
#    read total cpu available
#    subtract amount configured by user
#    convert to millicores format expected by kubelet
#  - reserved_mem is calculated as follows:
#    read total system memory in Kb
#    subtract memory the user configured (in Mb)
#
SYSTEM_RESERVED_CPUS=$(lscpu | awk -v requested=$KUBE_ALLOCATABLE_CPUS -v reserved=$KUBE_RESERVED_CPUS '/^CPU\(s\)/ {print ($NF - requested - reserved) * 1000}')
SYSTEM_RESERVED_MEM=$(awk -v requested=$KUBE_ALLOCATABLE_MEM -v reserved=$KUBE_RESERVED_MEM '/MemTotal/ {print int(($2 - requested * 1000 - reserved * 1000))}' /proc/meminfo)

# We need to convert this to millicores
KUBE_RESERVED_CPUS_M=$((${KUBE_RESERVED_CPUS} * 1000))
KUBE_RESERVED_MEM_M=$((${KUBE_RESERVED_MEM} * 1000))


# use the DC/OS proxy for dockerd and the kubelet
set -o allexport
if [ "${KUBE_OVERRIDE_PROXY}" = true ];
then
    HTTP_PROXY="${KUBE_HTTP_PROXY}"
    HTTPS_PROXY="${KUBE_HTTPS_PROXY}"
    NO_PROXY="${KUBE_NO_PROXY}"
else
    # reading this file from /opt/mesosphere is a hack. Ideally these vars would be injected by mesos
    source /opt/mesosphere/etc/proxy.env
fi
set +o allexport

# After this point we no longer need access to /opt/mesosphere. We unmount
# everything to not allow access to the host.
umount /opt/mesosphere
umount opt-mesosphere

# Docker must run with a few special arguments.
DOCKER_ARGS=(
    --bridge=none
    --iptables=false
    --ip-masq=false
)

# For now, we enforce Docker storage driver to overlay2.
DOCKER_ARGS+=(
    --storage-driver=overlay2
    --storage-opt="overlay2.override_kernel_check=true"
)

# Make Docker observe the configured limit on the amount of container logs to keep.
DOCKER_ARGS+=(
    --log-driver=json-file
    --log-opt=max-size={{KUBERNETES_CONTAINER_LOGS_MAX_SIZE}}m
    --log-opt=max-file=1
)


MANIFESTS_DIR=$(pwd)/manifests/
mkdir -p ${MANIFESTS_DIR}

# concatenate the root and internal ca certificates into a
# single file so that kube-apiserver can use both certificates
# to validate client certificates. this is required because
# certificates for kube-proxy are signed by the root ca,
# while certificates for the kubelets are signed by the internal ca.
# NOTE: both certificates (but not the keys!) are public, and as
# such it is safe to concatenate them into a normal file (i.e.
# without using secrets).
cat ca-crt.pem internal-ca-crt.pem > client-ca-crt.pem

# concatenate the kube apiserver certificate and root ca certificates
# into a single file so that the kube apiserver correctly serves TLS certificates with any
# intermediate certificates.
cat kube-apiserver-crt.pem ca-crt.pem > kube-apiserver-crt-chain.pem

# setup kubelet client certs for this instance
ln -s "$(pwd)/control-plane-kubelet-$POD_INSTANCE_INDEX-crt.pem" "$(pwd)/kubelet-crt.pem"
ln -s "$(pwd)/control-plane-kubelet-$POD_INSTANCE_INDEX-key.pem" "$(pwd)/kubelet-key.pem"

{{#AUDIT_POLICY_SECRET_FILE}}
# create a directory for apiserver to store log audit data in
# https://kubernetes.io/docs/tasks/debug-application-cluster/audit/
mkdir -p var/audit
{{/AUDIT_POLICY_SECRET_FILE}}

# Kubelet must run with a few special arguments.
#
# FRAMEWORK_NAME, KUBELET_CPUS and KUBELET_MEM are framework variables
# set by the framework scheduler when processing the service spec.
KUBELET_ARGS=(
    --address=${MESOS_CONTAINER_IP}
    --anonymous-auth=false
    --authentication-token-webhook=true
    --authorization-mode=Webhook
    --cgroup-driver=cgroupfs
    --client-ca-file=ca-crt.pem
    --cluster-dns=${MESOS_CONTAINER_IP}
    --cluster-domain=${KUBERNETES_CLUSTER_DOMAIN}
    --event-burst=30
    --event-qps=0
    --eviction-hard="nodefs.available<100Mi,imagefs.available<100Mi"
    --fail-swap-on=false
    --feature-gates=${KUBELET_FEATURE_GATES}
    --healthz-bind-address=127.0.0.1
    --kube-api-burst=30
    --kube-api-qps=15
    --kube-reserved="cpu=${KUBE_RESERVED_CPUS_M}m,memory=${KUBE_RESERVED_MEM_M}Ki"
    --kubeconfig=kubelet.conf
    --max-pods=10
    --network-plugin=cni
    --node-ip=${MESOS_CONTAINER_IP}
    --node-labels=name=${TASK_NAME}.${SERVICE_NAME}.mesos,tier=kube-control-plane
    --pod-infra-container-image=${PAUSE_DOCKER_IMAGE}
    --pod-manifest-path="${MANIFESTS_DIR}"
    --pods-per-core=10
    --read-only-port=0
    --register-with-taints=node-role.kubernetes.io/master="":NoExecute
    --system-reserved="cpu=${SYSTEM_RESERVED_CPUS}m,memory=${SYSTEM_RESERVED_MEM}Ki"
    --tls-cipher-suites="TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256"
    --tls-cert-file=$(pwd)/kubelet-crt.pem
    --tls-private-key-file=$(pwd)/kubelet-key.pem
)

# Trap SIGCHLD as late as possible to avoid as many useless notifications as possible.
trap 'onsigchld' SIGCHLD

printf "Starting docker...\n"

# workaround for a portworx issue; remove any immutable bits set in folders
# before proceeding to cleanup the persistent volume
chattr -R -f -i var/ || true

# Since the persistent volume "var" may have been previously used by the same
# task, we need to make sure it's empty before proceeding.
rm -rf var/*

# make /var/lib/docker point to the volume configured by the operator
mkdir -p /var/lib/docker
mount --bind var /var/lib/docker

dockerd ${DOCKER_ARGS[@]} &

DOCKERD_PID=$!
# Add DOCKERD_PID to the array of monitored PIDs.
ONSIGCHLD_PIDS+=(${DOCKERD_PID})

printf "Starting kubelet...\n"

kubelet ${KUBELET_ARGS[@]} &

KUBELET_PID=$!
# Add KUBELET_PID to the array of monitored PIDs.
ONSIGCHLD_PIDS+=(${KUBELET_PID})

#
# wait for up to 4m55s (5s less than the task health check timeout) for Api
# server to be ready
#
# copy yaml files into the manifests/ directory (cannot symlink, kubelet won't
# like it)
cp kube-apiserver.yml local-dns-dispatcher.yml ${MANIFESTS_DIR}
APISERVER_PODNAME=kube-apiserver-${TASK_NAME}.${SERVICE_NAME}.mesos

# Since Kubernetes 1.15, the kubelet's "--node-labels" flag can't be used to label nodes with keys that include certain prefixes.
# The sanctioned way to do it is through the Kubernetes API.
# Hence, we use kubectl to label the node, looping until successful (as the Kubernetes API may not be up when this code is reached, or the targeted "Node" resource may not exist yet).
RETRY_INTERVAL=5
until kubectl --kubeconfig admin.conf label nodes --overwrite ${TASK_NAME}.${SERVICE_NAME}.mesos node-role.kubernetes.io/master=
do
    echo "Failed to label node (retrying after ${RETRY_INTERVAL}s)..." && sleep ${RETRY_INTERVAL}
done

# don't leak the admin conf
rm -f admin.conf
{{#HTTP_BASED_TLS_PROVISIONING}}
rm -f admin-crt.pem
rm -f admin-key.pem
{{/HTTP_BASED_TLS_PROVISIONING}}
{{^HTTP_BASED_TLS_PROVISIONING}}
umount admin-crt.pem
umount admin-key.pem
{{/HTTP_BASED_TLS_PROVISIONING}}

# start the rest of the control plane that require the apiserver to be up; copy
# yaml files into the manifests/ directory (cannot symlink, kubelet won't like
# it)
cp kube-controller-manager.yml kube-scheduler.yml kube-proxy.yml ${MANIFESTS_DIR}

# Wait for all child processes to exit.
wait
