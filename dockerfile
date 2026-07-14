FROM rustlang/rust:nightly-bookworm

# Installation of libs for cryptography and work with ESP32 via Serial
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    pkg-config \
    libudev-dev \
    libfuzzer-14-dev \
    && rm -rf /var/lib/apt/lists/*

# Installation of fuzzer and sources of std lib
RUN cargo install cargo-fuzz
RUN rustup component add rust-src --toolchain nightly

WORKDIR /app

# To not rebuild everything with each start it is possible to get into bash and run fuzzer there
CMD ["/bin/bash"]