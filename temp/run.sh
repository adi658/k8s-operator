#!/bin/sh

function build {
    docker build -t cronjob:latest $@ .
}

function up {
    docker run $@ \
        --name cronjob \
        -d \
        -v $(pwd)/task.py:/app/task.py \
        cronjob:latest
}

function down {
    docker rm -f -v cronjob
}

function log {
    docker logs cronjob $@
}

function sh {
    docker exec $@ -it cronjob bash
}

function main {
    Command=$1
    shift
    case "${Command}" in
        build)  build $@ ;;
        up)     up $@ ;;
        down)   down $@ ;;
        log)    log $@ ;;
        sh)     sh $@ ;;
        *)      echo "Usage: $0 {build|up|down|log|sh}" ;;
    esac
}

main $@
