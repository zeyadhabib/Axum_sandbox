#! /bin/bash

openssl req -new -x509 -newkey rsa:2048 -keyout ./certs/root/root.key -out ./certs/root/root.pem -config ./certs/root/root.cnf -outform PEM -nodes
openssl req -new -newkey rsa:2048 -keyout ./certs/ca/ca.key -out ./certs/ca/ca.csr -config ./certs/ca/ca.cnf -nodes
openssl x509 -req -in ./certs/ca/ca.csr -CA ./certs/root/root.pem -CAkey ./certs/root/root.key -CAcreateserial -out ./certs/ca/ca.pem -days 365 -sha256 -extfile ./certs/ca/ca.cnf -extensions cert_ext
openssl req -new -newkey rsa:2048 -keyout ./certs/client-leaf/client-leaf.key -out ./certs/client-leaf/client-leaf.csr -config ./certs/client-leaf/leaf.cnf -nodes
openssl req -new -newkey rsa:2048 -keyout ./certs/server-leaf/server-leaf.key -out ./certs/server-leaf/server-leaf.csr -config ./certs/server-leaf/leaf.cnf -nodes
openssl x509 -req -in ./certs/client-leaf/client-leaf.csr -CA ./certs/ca/ca.pem -CAkey ./certs/ca/ca.key -CAcreateserial -out ./certs/client-leaf/client-leaf.pem -days 365 -sha256 -extfile ./certs/client-leaf/leaf.cnf -extensions req_ext
openssl x509 -req -in ./certs/server-leaf/server-leaf.csr -CA ./certs/ca/ca.pem -CAkey ./certs/ca/ca.key -CAcreateserial -out ./certs/server-leaf/server-leaf.pem -days 365 -sha256 -extfile ./certs/server-leaf/leaf.cnf -extensions req_ext
cat ./certs/client-leaf/client-leaf.pem > ./certs/client-leaf/chain.pem && cat ./certs/ca/ca.pem >> ./certs/client-leaf/chain.pem && cat ./certs/root/root.pem >> ./certs/client-leaf/chain.pem
cat ./certs/server-leaf/server-leaf.pem > ./certs/server-leaf/chain.pem && cat ./certs/ca/ca.pem >> ./certs/server-leaf/chain.pem && cat ./certs/root/root.pem >> ./certs/server-leaf/chain.pem
cat ./certs/ca/ca.pem > ./certs/chain.pem && cat ./certs/root/root.pem >> ./certs/chain.pem