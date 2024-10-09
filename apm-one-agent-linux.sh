#!/bin/sh
exec >>./test.log 2>&1
echo "ARGS: $@"
