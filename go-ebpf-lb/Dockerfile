FROM ubuntu:jammy as builder
RUN apt-get update
RUN apt-get install -y clang llvm libelf-dev libpcap-dev build-essential make 
RUN apt-get install -y linux-tools-common
RUN apt-get install -y wget

# Install Go for arm64
RUN wget https://go.dev/dl/go1.21.0.linux-arm64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-arm64.tar.gz && \
    rm go1.21.0.linux-arm64.tar.gz

RUN ln -s /usr/include/asm /usr/include$(uname -m)-linux-gnu/asm
RUN ln -s /usr/include/asm /usr/include/asm-generic



# Set Go environment variables
ENV PATH="/usr/local/go/bin:${PATH}"
ENV CGO_ENABLED=1
ENV GOARCH=arm64
RUN mkdir -p /go/src/app
WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN go generate
RUN go build -o ebpf-lb .


FROM ubuntu:jammy
ENV IFACE=eth0
COPY --from=builder /go/src/app/ebpf-lb /usr/local/bin/ebpf-lb
RUN chmod +x /usr/local/bin/ebpf-lb
# RUN the binary
CMD ["/usr/local/bin/ebpf-lb"]