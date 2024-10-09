#!/bin/sh
exec >>./test.log 2>&1
echo "STARTED"
echo "ARGS: $0 $@"
