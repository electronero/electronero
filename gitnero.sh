git clone -b STAGENET-ETNX https://github.com/shopglobal/electronero stagenet/etnx
cd stagenet/etnx
git submodule init
git submodule update
make -j$(nproc)
echo"build stage complete"
cd ../../
sh gitpulse.sh
