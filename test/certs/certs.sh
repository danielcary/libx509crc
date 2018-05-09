#!/bin/bash 

 # Get absolute path to the working dir
SCRIPT=$(readlink -f "$0")
SPATH=$(dirname "$SCRIPT")
CAPATH=$SPATH/root/ca
IMPATH=$CAPATH/intermediate

# http://ocsp-res.libx509crc.test:49200 http://localhost:49200
# http://crl.libx509crc.test:49201 http://localhost:49201
# https://libx509crc.test:49202  https://localhost:49202

if [ "$1" == "setup" ]; then

    # create the directory for the root CA
    mkdir $SPATH/root
    mkdir $SPATH/root/ca
    mkdir $CAPATH/certs $CAPATH/crl $CAPATH/newcerts $CAPATH/private

    # create initial files
    touch $CAPATH/index.txt
    touch $CAPATH/index.txt.attr
    echo 1000 > $CAPATH/serial
    cp $SPATH/root-openssl.cnf $CAPATH/openssl.cnf
    sed -i s+DIR+$CAPATH+g $CAPATH/openssl.cnf

    # generate root key
    openssl genrsa -out $CAPATH/private/ca.key.pem 2048

    # create the root cert
    openssl req \
        -config $CAPATH/openssl.cnf \
        -key $CAPATH/private/ca.key.pem \
        -new -x509 -days 730 -sha256 -extensions v3_ca \
        -out $CAPATH/certs/ca.cert.pem

    # Copy the root cert with the name as the hash of the file
    cp $CAPATH/certs/ca.cert.pem $CAPATH/certs/$(openssl x509 -noout -hash -in $CAPATH/certs/ca.cert.pem).0

    ### Create intermediate pair

    # setup intermediate dir
    mkdir $IMPATH
    mkdir $IMPATH/certs $IMPATH/crl $IMPATH/csr $IMPATH/newcerts $IMPATH/private

    # setup files
    touch $IMPATH/index.txt
    touch $IMPATH/index.txt.attr
    echo 1000 > $IMPATH/serial
    echo 1000 > $IMPATH/crlnumber
    cp $SPATH/intermediate-openssl.cnf $IMPATH/openssl.cnf
    cp $SPATH/intermediate-openssl-muststaple.cnf $IMPATH/openssl-muststaple.cnf
    cp $SPATH/intermediate-openssl-noocsp.cnf $IMPATH/openssl-noocsp.cnf
    cp $SPATH/intermediate-openssl-nocrl.cnf $IMPATH/openssl-nocrl.cnf
    cp $SPATH/intermediate-openssl-https.cnf $IMPATH/openssl-https.cnf
    sed -i s+DIR+$IMPATH+g $IMPATH/openssl.cnf
    sed -i s+DIR+$IMPATH+g $IMPATH/openssl-muststaple.cnf
    sed -i s+DIR+$IMPATH+g $IMPATH/openssl-noocsp.cnf
    sed -i s+DIR+$IMPATH+g $IMPATH/openssl-nocrl.cnf
    sed -i s+DIR+$IMPATH+g $IMPATH/openssl-https.cnf

    # generate key
    openssl genrsa -out $IMPATH/private/intermediate.key.pem 2048

    openssl req \
        -config $IMPATH/openssl.cnf \
        -new -sha256 \
        -key $IMPATH/private/intermediate.key.pem \
        -out $IMPATH/csr/intermediate.csr.pem

    openssl ca \
        -config $CAPATH/openssl.cnf \
        -extensions v3_intermediate_ca -batch -days 365 -notext -md sha256 \
        -in $IMPATH/csr/intermediate.csr.pem \
        -out $IMPATH/certs/intermediate.cert.pem

    # create the full chain pem
    cat $IMPATH/certs/intermediate.cert.pem $CAPATH/certs/ca.cert.pem > $IMPATH/certs/intermediate.fullchain.pem 

    ## GENERATE OCSP Certs

    # gen private key
    openssl genrsa -out $IMPATH/private/ocsp-res.libx509crc.test.key.pem 2048

    # gen csr
    openssl req \
        -config $IMPATH/openssl.cnf  \
        -new -sha256 \
        -key $IMPATH/private/ocsp-res.libx509crc.test.key.pem \
        -out $IMPATH/csr/ocsp-res.libx509crc.test.csr.pem

    # sign
    openssl ca \
        -config $IMPATH/openssl.cnf \
        -subj '/CN=ocsp-res.libx509crc.test/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US' \
        -extensions ocsp -days 365 -notext -batch -md sha256 \
        -in $IMPATH/csr/ocsp-res.libx509crc.test.csr.pem \
        -out $IMPATH/certs/ocsp-res.libx509crc.test.cert.pem

    # add servers
    $SPATH/certs.sh add
    $SPATH/certs.sh add-muststaple

    ## add-noocsp
    SERVER="noocsp.libx509crc.test"
    openssl genrsa -out $IMPATH/private/$SERVER.key.pem 2048
    openssl req \
        -config $IMPATH/openssl-noocsp.cnf  \
        -new -sha256 \
        -key $IMPATH/private/$SERVER.key.pem \
        -out $IMPATH/csr/$SERVER.csr.pem

    openssl ca \
        -config $IMPATH/openssl-noocsp.cnf \
        -subj "/CN=$SERVER/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US" \
        -extensions server_cert -batch -days 100 -notext -md sha256 \
        -in $IMPATH/csr/$SERVER.csr.pem \
        -out $IMPATH/certs/$SERVER.cert.pem

    cat $IMPATH/certs/$SERVER.cert.pem $IMPATH/certs/intermediate.fullchain.pem > $IMPATH/certs/$SERVER.fullchain.pem
    
    ## add-nocrl
    SERVER="nocrl.libx509crc.test"
    openssl genrsa -out $IMPATH/private/$SERVER.key.pem 2048
    openssl req \
        -config $IMPATH/openssl-nocrl.cnf  \
        -new -sha256 \
        -key $IMPATH/private/$SERVER.key.pem \
        -out $IMPATH/csr/$SERVER.csr.pem

    openssl ca \
        -config $IMPATH/openssl-nocrl.cnf \
        -subj "/CN=$SERVER/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US" \
        -extensions server_cert -batch -days 100 -notext -md sha256 \
        -in $IMPATH/csr/$SERVER.csr.pem \
        -out $IMPATH/certs/$SERVER.cert.pem

    cat $IMPATH/certs/$SERVER.cert.pem $IMPATH/certs/intermediate.fullchain.pem > $IMPATH/certs/$SERVER.fullchain.pem
    
    ## add-ocsp for https ocsp
    SERVER="ocsp.libx509crc.test"
    openssl genrsa -out $IMPATH/private/$SERVER.key.pem 2048
    openssl req \
        -config $IMPATH/openssl.cnf  \
        -new -sha256 \
        -key $IMPATH/private/$SERVER.key.pem \
        -out $IMPATH/csr/$SERVER.csr.pem

    openssl ca \
        -config $IMPATH/openssl.cnf \
        -subj "/CN=$SERVER/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US" \
        -extensions server_cert -batch -days 100 -notext -md sha256 \
        -in $IMPATH/csr/$SERVER.csr.pem \
        -out $IMPATH/certs/$SERVER.cert.pem

    cat $IMPATH/certs/$SERVER.cert.pem $IMPATH/certs/intermediate.fullchain.pem > $IMPATH/certs/$SERVER.fullchain.pem
    
     ## add-crl for https crl
    SERVER="crl.libx509crc.test"
    openssl genrsa -out $IMPATH/private/$SERVER.key.pem 2048
    openssl req \
        -config $IMPATH/openssl.cnf  \
        -new -sha256 \
        -key $IMPATH/private/$SERVER.key.pem \
        -out $IMPATH/csr/$SERVER.csr.pem

    openssl ca \
        -config $IMPATH/openssl.cnf \
        -subj "/CN=$SERVER/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US" \
        -extensions server_cert -batch -days 100 -notext -md sha256 \
        -in $IMPATH/csr/$SERVER.csr.pem \
        -out $IMPATH/certs/$SERVER.cert.pem

    cat $IMPATH/certs/$SERVER.cert.pem $IMPATH/certs/intermediate.fullchain.pem > $IMPATH/certs/$SERVER.fullchain.pem
    

    ## add https for testing https dist points
    SERVER="https.libx509crc.test"
    openssl genrsa -out $IMPATH/private/$SERVER.key.pem 2048
    openssl req \
        -config $IMPATH/openssl-https.cnf  \
        -new -sha256 \
        -key $IMPATH/private/$SERVER.key.pem \
        -out $IMPATH/csr/$SERVER.csr.pem

    openssl ca \
        -config $IMPATH/openssl-https.cnf \
        -subj "/CN=$SERVER/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US" \
        -extensions server_cert -batch -days 100 -notext -md sha256 \
        -in $IMPATH/csr/$SERVER.csr.pem \
        -out $IMPATH/certs/$SERVER.cert.pem

    cat $IMPATH/certs/$SERVER.cert.pem $IMPATH/certs/intermediate.fullchain.pem > $IMPATH/certs/$SERVER.fullchain.pem
    


    # gen crl
    $SPATH/certs.sh gencrl

elif [ "$1" == "add" ]; then

    if [ -z "$2" ]; then
        SERVER="libx509crc.test"
    else
        SERVER="$2"
    fi

    # gen private key
    openssl genrsa -out $IMPATH/private/$SERVER.key.pem 2048

    # gen csr
    openssl req \
        -config $IMPATH/openssl.cnf  \
        -new -sha256 \
        -key $IMPATH/private/$SERVER.key.pem \
        -out $IMPATH/csr/$SERVER.csr.pem

    openssl ca \
        -config $IMPATH/openssl.cnf \
        -subj "/CN=$SERVER/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US" \
        -extensions server_cert -batch -days 100 -notext -md sha256 \
        -in $IMPATH/csr/$SERVER.csr.pem \
        -out $IMPATH/certs/$SERVER.cert.pem

    cat $IMPATH/certs/$SERVER.cert.pem $IMPATH/certs/intermediate.fullchain.pem > $IMPATH/certs/$SERVER.fullchain.pem

elif [ "$1" == "add-muststaple" ]; then

    if [ -z "$2" ]; then
        SERVER="muststaple.libx509crc.test"
    else
        SERVER="$2"
    fi

    # gen private key
    openssl genrsa -out $IMPATH/private/$SERVER.key.pem 2048

    # gen csr
    openssl req \
        -config $IMPATH/openssl-muststaple.cnf  \
        -new -sha256 \
        -key $IMPATH/private/$SERVER.key.pem \
        -out $IMPATH/csr/$SERVER.csr.pem

    openssl ca \
        -config $IMPATH/openssl-muststaple.cnf \
        -subj "/CN=$SERVER/OU=Team 13/O=NCSU Spring 2018 CSC 492/ST=North Carolina/L=Raleigh/C=US" \
        -extensions server_cert -batch -days 100 -notext -md sha256 \
        -in $IMPATH/csr/$SERVER.csr.pem \
        -out $IMPATH/certs/$SERVER.cert.pem

    cat $IMPATH/certs/$SERVER.cert.pem $IMPATH/certs/intermediate.fullchain.pem > $IMPATH/certs/$SERVER.fullchain.pem

elif [ "$1" == "revoke" ]; then

    if [ -z "$2" ]; then
        SERVER="libx509crc.test"
    else
        SERVER="$2"
    fi

    openssl ca \
        -config $IMPATH/openssl.cnf \
        -revoke $IMPATH/certs/$SERVER.cert.pem

elif [ "$1" == "gencrl" ]; then

    ## GENERATE CRL
    openssl ca \
        -config $IMPATH/openssl.cnf -gencrl \
        -out $IMPATH/crl/intermediate.crl.pem

    # convert it to dir
    openssl crl \
        -in $IMPATH/crl/intermediate.crl.pem \
        -outform DER \
        -out $IMPATH/crl/intermediate.crl.der
        
elif [ "$1" == "clean" ]; then

    echo "cleaning"
    rm -rf $SPATH/root

elif [ "$1" == "ocsp" ]; then

    openssl ocsp \
        -index $IMPATH/index.txt \
        -CA $IMPATH/certs/intermediate.fullchain.pem \
        -rsigner $IMPATH/certs/ocsp-res.libx509crc.test.cert.pem \
        -rkey $IMPATH/private/ocsp-res.libx509crc.test.key.pem \
        -port 49200

elif [ "$1" == "crl" ]; then

    python $SPATH/crl_server.py 49201 $IMPATH/crl/intermediate.crl.der

elif [ "$1" == "run" ]; then
    
    if [ -z "$2" ]; then
        SERVER="libx509crc.test"
    else
        SERVER="$2"
    fi

    openssl s_server \
        -accept 49202 \
        -cert $IMPATH/certs/$SERVER.cert.pem \
        -key $IMPATH/private/$SERVER.key.pem \
        -www -status -CAfile $IMPATH/certs/intermediate.fullchain.pem

else

    echo "setup gencrl clean"

fi

