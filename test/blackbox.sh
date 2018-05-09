#!/bin/sh 

 # Get absolute path to the working dir
SCRIPT=$(readlink -f "$0")
SPATH=$(dirname "$SCRIPT")
DRIVER=$SPATH/../driverprogram

mkdir -p bb_actual
    
eval $DRIVER $1 > bb_actual/$2
exit $?