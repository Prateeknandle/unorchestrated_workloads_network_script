#!/bin/bash

TMP="/tmp"

chk_cmd()
{
	if ! command -v $1 &>/dev/null; then
		echo "<$1> command not found"
		echo "$2"
		exit
	fi
}

declare -A rules
check_duplicate_conn()
{
	edge="$1"
	[[ "${rules[$edge]}" == "1" ]] && return 1
	rules["$edge"]="1"
	return 0
}

get_name_from_ip()
{
    container_name=$(docker ps -q --filter "network=sediment" | xargs docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{.Name}}' | awk -v ip="$1" '$1 == ip {print $2}')
    ip_name="${container_name#/}"
}

prerequisites()
{
	#chk_cmd yq "Download from https://github.com/mikefarah/yq"
	#chk_cmd csplit "Install util csplit"
	#chk_cmd java "java not found"
	PUML_JAR=$(ls -1 plantuml*.jar)
}

getIngressConn()
{
    ingress_connections=$(echo "$jsonObject" | yq eval '.IngressConnection[]' > /dev/null)
    jsonIngress=$ingress_connections
    for jsoningress in "${jsonIngress[@]}"; do
        ip=$(echo "$jsoningress" | yq eval '.IP' > /dev/null)
        port=$(echo "$jsoningress" | yq eval '.Port' > /dev/null)
        protocol=$(echo "$jsoningress" | yq eval '.Protocol' > /dev/null)

        str="\"$ip\" -> \"$name\" [label = \"$protocol/$port\""
        check_duplicate_conn $str
        [[ $? -ne 0 ]] && return

        if [ $ip != null ]; then
        get_name_from_ip $ip
        if [ $ip_name != null ]; then
        echo "[$ip_name] -[#green]-> [$name] : $protocol/$port" >> "$PUML"
        else
        echo "[$ip] -[#green]-> [$name] : $protocol/$port" >> "$PUML"
        fi
        fi
    done
}

getEgressConn()
{
	egress_connections=$(echo "$jsonObject" | yq eval '.EgressConnection[]' > /dev/null)
    jsonEgress=$egress_connections
	for jsonegress in "${jsonEgress[@]}"; do
        ip=$(echo "$jsonegress" | yq eval '.IP' > /dev/null)
		port=$(echo "$jsonegress" | yq eval '.Port' > /dev/null)
		protocol=$(echo "$jsonegress" | yq eval '.Protocol' > /dev/null)

        str="\"$name\" -> \"$ip\" [label = \"$protocol/$port\""
        check_duplicate_conn $str
        [[ $? -ne 0 ]] && return

        if [ $ip != null ]; then
            get_name_from_ip $ip
            if [ $ip_name != null ]; then
                echo "[$name] -[#green]-> [$ip_name] : $protocol/$port" >> "$PUML"
            else
                echo "[$name] -[#green]-> [$ip] : $protocol/$port" >> "$PUML"
            fi
        fi
	done
}

convert_puml()
{
	java -jar "$PUML_JAR" "$PUML" -output "$PWD" > /dev/null
	#mv "${PUML/.puml/.png}" .
}

filter_net_policy()
{
	summary=$(karmor summary --gRPC=:9089 -n container_namespace -o json)
    objects=()
    while IFS= read -r line; do
        objects+=("$line")
    done < <(echo "$summary" | jq -c '.')
        
	# Iterate over each JSON output
	for jsonObject in "${objects[@]}"; do

	    # Process the net policy
		name=$(echo "$jsonObject" | yq eval ".PodName" > /dev/null)
		getEgressConn "$jsonObject"
		getIngressConn "$jsonObject"
	done

	echo "@enduml" >> "$PUML"
	convert_puml
}

main()
{
	prerequisites
    PUML="net-policy.puml"
    echo "@startuml" >> "$PUML"
    filter_net_policy
    rm $PUML
}

main
