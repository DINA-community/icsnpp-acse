# @TEST-EXEC: zeek -NN OSS::ACSE |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
