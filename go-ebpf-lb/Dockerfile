FROM ubuntu:jammy as builder
RUN apt-get update
RUN apt-get install -y clang llvm libelf-dev libpcap-dev build-essential make 
RUN apt-get install -y linux-tools-common
# gcc-multilib is not currently available for ARM architectures on 
# Add /usr/include/$(shell uname -m)-linux-gnu into the include path instead. 
# See this thread for more info: https://patchwork.ozlabs.org/project/netdev/patch/20200311123421.3634-1-tklauser@distanz.ch/
RUN apt install -y gcc-multilib libbpf-dev
RUN apt-get install -y wget

# Install Go for arm64
RUN wget https://go.dev/dl/go1.21.10.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.10.linux-amd64.tar.gz

RUN export PATH=$PATH:/usr/local/go/bin

# Set Go environment variables
ENV PATH="/usr/local/go/bin:${PATH}"
ENV CGO_ENABLED=1
ENV GOARCH=amd64
RUN mkdir -p /go/src/app
WORKDIR /go/src/app
COPY . .
RUN chmod +x /usr/local/go/bin/go
RUN ls -l /usr/local/go/bin/go  # Check permissions
RUN go mod tidy
RUN go generate
RUN go build -o ebpf-lb .

FROM ubuntu:jammy
ENV IFACE=eth0
COPY --from=builder /go/src/app/ebpf-lb /usr/local/bin/ebpf-lb
RUN chmod +x /usr/local/bin/ebpf-lb
# RUN the binary
CMD ["/usr/local/bin/ebpf-lb"]