# CMake generated Testfile for 
# Source directory: /root/_electronero/tests/hash
# Build directory: /root/_electronero/build/release/tests/hash
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(hash-fast "/root/_electronero/build/release/tests/hash/hash-tests" "fast" "/root/_electronero/tests/hash/tests-fast.txt")
add_test(hash-slow "/root/_electronero/build/release/tests/hash/hash-tests" "slow" "/root/_electronero/tests/hash/tests-slow.txt")
add_test(hash-slow-1 "/root/_electronero/build/release/tests/hash/hash-tests" "slow-1" "/root/_electronero/tests/hash/tests-slow-1.txt")
add_test(hash-tree "/root/_electronero/build/release/tests/hash/hash-tests" "tree" "/root/_electronero/tests/hash/tests-tree.txt")
add_test(hash-extra-blake "/root/_electronero/build/release/tests/hash/hash-tests" "extra-blake" "/root/_electronero/tests/hash/tests-extra-blake.txt")
add_test(hash-extra-groestl "/root/_electronero/build/release/tests/hash/hash-tests" "extra-groestl" "/root/_electronero/tests/hash/tests-extra-groestl.txt")
add_test(hash-extra-jh "/root/_electronero/build/release/tests/hash/hash-tests" "extra-jh" "/root/_electronero/tests/hash/tests-extra-jh.txt")
add_test(hash-extra-skein "/root/_electronero/build/release/tests/hash/hash-tests" "extra-skein" "/root/_electronero/tests/hash/tests-extra-skein.txt")
