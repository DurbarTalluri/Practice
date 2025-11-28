#!/bin/sh

IS_K8S_INSTALLATION=""
BOOLEAN_FALSE="false"

Func() {
    echo "Func"
    if [ $IS_K8S_INSTALLATION = $BOOLEAN_FALSE ]; then
        echo "YESS!!"
    fi
}

Func
