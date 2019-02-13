# Container is based on a preexisting image that contains the Go tools needed
# to compile and install
FROM golang:1.11-alpine AS builder

# Project URI based on repository URL
ENV PROJECT_URI=github.com/hlwong/codechallenge
ENV PROJECT_DIR=${GOPATH}/src/${PROJECT_URI}

# Create project directory
RUN mkdir -p ${PROJECT_DIR}

# Change current working directory to project directory
WORKDIR ${PROJECT_DIR}

# Copy source code to project directory
COPY . ${PROJECT_DIR}

# Compile and install code
RUN GOOS=linux GOARCH=amd64 go install ${PROJECT_URI}/...

# multistage build, use alpine image for execution environment
FROM alpine
COPY --from=builder /go/bin/codechallenge /codechallenge
# Configure the container entrypoint so that it runs the compiled program. In
# this case, we utilize the shell to enable variable substitution for the
# GOPATH variable (for more info, refer to Docker's documentation:
# https://docs.docker.com/engine/reference/builder/#shell-form-entrypoint-example)
#
# There was an issue using `sh -c` to execute the binary, since for some reason
# it wasn't allowing for additional command line arguments to be passed through
# to the container. Setting the entry point specifically to where the binary was
# installed, seemed to do the trick. The container defaults to `/go` for $GOPATH.
ENTRYPOINT ["/codechallenge"]
CMD ["henry.li.wong@gmail.com"]