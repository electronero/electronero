cd build/release/bin
tar -cvzf electronero_ubuntu64-camel.tar.gz  electronero-blockchain-import electronero-blockchain-export electronerod electronero-gen-trusted-multisig electronero-wallet-cli electronero-wallet-rpc electronero-blockchain-blackball electronero-blockchain-usage
rm -rf /var/www/html/website/dl/electronero_ubuntu64-camel.tar.gz 
cp electronero_ubuntu64-camel.tar.gz /var/www/html/website/dl/ -r -f 
rm -rf ../../../electronero_ubuntu64-camel.tar.gz 
mv electronero_ubuntu64-camel.tar.gz ../../../
./electronerod
