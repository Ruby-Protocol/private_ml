FROM rust:1.51.0

WORKDIR /home/workspace/ruby_protocol
COPY . .

RUN cargo build 

