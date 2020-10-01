function wait_for_external_ip() {
    IP_REGEX="^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"
    TIME_WAITED=0
    TIMEOUT=300
    POLL=5
    IP_ADDRESS=''
    get_external_ip
    while [[ ! $IP_ADDRESS =~ $IP_REGEX ]]
    do
        sleep $POLL
        TIME_WAITED=$(($TIME_WAITED+$POLL))
        if [[ $TIME_WAITED = $TIMEOUT ]]
        then
            echo "External IP Timed out" 1>&2
            exit 1
        fi
        get_external_ip
    done
    echo $IP_ADDRESS
}

function get_external_ip() {
    IP_ADDRESS=$(kubectl get svc attested-tls-service --template="{{range .status.loadBalancer.ingress}}{{.ip}}{{end}}")
}

wait_for_external_ip
