FROM rust:latest

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libprotobuf-dev

WORKDIR /usr/src/app

COPY . .

RUN cargo build --release
