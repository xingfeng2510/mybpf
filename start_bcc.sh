#!/bin/bash

CONTAINER_NAME=bcc

start_container()
{
    sudo docker inspect $CONTAINER_NAME &> /dev/null
    if [ $? -eq 0 ]; then
        echo "Container '$CONTAINER_NAME' already exists." >&2
        return 0
    fi

    sudo docker run -dit --name $CONTAINER_NAME \
        --privileged \
        --pid host \
	-v /lib/modules:/lib/modules:ro \
	-v /usr/src:/usr/src:ro \
	-v /etc/localtime:/etc/localtime:ro \
	--workdir /usr/share/bcc/tools \
	zlim/bcc

    if [ $? -ne 0 ]; then
        echo "Container '$CONTAINER_NAME' start failed." >&2
        exit 1
    else
        echo "Container '$CONTAINER_NAME' start succeed." >&2
    fi
}

run_command()
{
    sudo docker exec $CONTAINER_NAME "$@"
}

start_container && run_command "$@"
