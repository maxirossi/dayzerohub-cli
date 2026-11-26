module github.com/acme/api

go 1.22

toolchain go1.22.3

require (
	github.com/elazarl/goproxy v1.7.0
	github.com/gin-gonic/gin v1.9.1
	github.com/pkg/errors v0.9.1 // indirect
)

require golang.org/x/text v0.14.0 // indirect

replace github.com/pkg/errors => github.com/fork/errors v0.9.2
replace github.com/acme/lib => ../lib
