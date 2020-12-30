git submodule init && git submodule update && cd coins/electronero
git submodule init && git submodule update
make -j4 && cd ../electroneropulse
git submodule init && git submodule update
make -j4 && cd ../litenero
git submodule init && git submodule update
make -j4 && cd ../goldnero
git submodule init && git submodule update
make -j4 && cd coins/crystaleum
git submodule init && git submodule update && make -j4
echo 'Electronero network compiled ETNX, ETNXP, LTNX, GLDX, CRFI successfully'
