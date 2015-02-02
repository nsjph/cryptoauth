# Based on http://zduck.com/2014/go-project-structure-and-dependencies/

.PHONY: build doc fmt lint run test vendor_clean vendor_get vendor_update vet

# Prepend our _vendor directory to the system GOPATH
# so that import path resolution will prioritize
# our third party snapshots.
ORIGINAL_GOPATH := ${GOPATH}
export ORIGINAL_GOPATH
GOPATH := ${PWD}/_vendor:${GOPATH}
export GOPATH

default: vendor_get build install

build: 
	GOPATH=${PWD}/_vendor go build -v 

# Install package to original GOPATH
install:
	go install -v 

doc:
	godoc -http=:6060 -index

# http://golang.org/cmd/go/#hdr-Run_gofmt_on_package_sources
fmt:
	go fmt 

# https://github.com/golang/lint
# go get github.com/golang/lint/golint
lint:
	golint 

test:
	go test 

vendor_clean:
	rm -dRf ./_vendor/src

# We have to set GOPATH to just the _vendor
# directory to ensure that `go get` doesn't
# update packages in our primary GOPATH instead.
# This will happen if you already have the package
# installed in GOPATH since `go get` will use
# that existing location as the destination.
vendor_get: vendor_clean
	GOPATH=${PWD}/_vendor go get -d -u -v \
	github.com/davecgh/go-spew/spew \
	golang.org/x/crypto/curve25519 \
	golang.org/x/crypto/nacl/box \

vendor_update: vendor_get
	rm -rf `find ./_vendor/src -type d -name .git` \
	&& rm -rf `find ./_vendor/src -type d -name .hg` \
	&& rm -rf `find ./_vendor/src -type d -name .bzr` \
	&& rm -rf `find ./_vendor/src -type d -name .svn`

# http://godoc.org/code.google.com/p/go.tools/cmd/vet
# go get code.google.com/p/go.tools/cmd/vet
vet:
	go vet ./src/...
