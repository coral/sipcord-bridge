# Stage 0: Shared base with build dependencies
FROM debian:trixie AS build-base

RUN apt-get update && apt-get install -y \
    cmake \
    pkg-config \
    build-essential \
    libssl-dev \
    libasound2-dev \
    uuid-dev \
    libclang-dev \
    curl \
    libopencore-amrnb-dev \
    libopencore-amrwb-dev \
    libopus-dev \
    libtiff-dev \
    libjpeg-dev \
    && rm -rf /var/lib/apt/lists/*

# Stage 1: Build pjproject C library (slow, cached unless pjsua/pjproject changes)
FROM build-base AS pjproject-builder

WORKDIR /build

COPY pjsua/pjproject/ pjproject-src/
COPY pjsua/pjproject_config.h pjproject_config.h

RUN mkdir -p pjproject-build pjproject-install && \
    cd pjproject-build && \
    cmake \
        -G "Unix Makefiles" \
        -DCMAKE_INSTALL_PREFIX=/build/pjproject-install \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DPJ_SKIP_EXPERIMENTAL_NOTICE=ON \
        -DPJ_ENABLE_TESTS=OFF \
        -DBUILD_TESTING=OFF \
        -DPJMEDIA_WITH_VIDEO=OFF \
        -DPJMEDIA_WITH_FFMPEG=OFF \
        -DPJMEDIA_WITH_LIBYUV=OFF \
        -DPJMEDIA_WITH_OPENCORE_AMRNB_CODEC=ON \
        -DPJMEDIA_WITH_OPENCORE_AMRWB_CODEC=ON \
        -DPJMEDIA_WITH_OPUS_CODEC=ON \
        -DPJLIB_WITH_SSL=openssl \
        "-DCMAKE_C_FLAGS=-include /build/pjproject_config.h" \
        "-DCMAKE_CXX_FLAGS=-include /build/pjproject_config.h" \
        ../pjproject-src && \
    cmake --build . -j$(nproc) \
        --target pjlib pjlib-util pjnath pjmedia pjmedia-audiodev \
        pjmedia-codec pjsip pjsip-simple pjsip-ua pjsua-lib pjsua2 \
        resample srtp speex g7221 gsm ilbc && \
    cmake --install . || true

# Collect all .a files into a single flat lib directory
RUN mkdir -p /build/pjproject-install/lib && \
    find /build/pjproject-build /build/pjproject-install -name '*.a' -exec cp -n {} /build/pjproject-install/lib/ \; && \
    echo "Libraries collected:" && ls /build/pjproject-install/lib/

# Collect headers from source tree (cmake --install often fails to install them).
# Also grab generated config_site.h from the build directory.
RUN mkdir -p /build/pjproject-install/include && \
    for dir in pjlib/include pjlib-util/include pjmedia/include pjnath/include pjsip/include; do \
        if [ -d "/build/pjproject-src/$dir" ]; then \
            cp -r /build/pjproject-src/$dir/* /build/pjproject-install/include/; \
        fi; \
    done && \
    find /build/pjproject-build -name 'config_site.h' -exec cp {} /build/pjproject-install/include/pj/ \; 2>/dev/null; \
    echo "Headers collected:" && ls /build/pjproject-install/include/

# Stage 2: Build Rust dependencies (cached unless Cargo.toml/lock changes)
FROM build-base AS deps-builder

# Install Rust nightly (required for portable_simd)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy pre-built pjproject from stage 1
COPY --from=pjproject-builder /build/pjproject-install /pjproject
ENV PJPROJECT_DIR=/pjproject

# Copy only what cargo needs for dependency resolution
COPY Cargo.toml Cargo.lock ./
COPY pjsua/ pjsua/
COPY sipcord-bridge/Cargo.toml sipcord-bridge/Cargo.toml

# Create dummy source files to build dependencies only
RUN mkdir -p sipcord-bridge/src && \
    echo '#![feature(portable_simd)] fn main() {}' > sipcord-bridge/src/main.rs && \
    echo '#![feature(portable_simd)]' > sipcord-bridge/src/lib.rs

RUN cargo build --release -p sipcord-bridge

# Stage 3: Build application (fast, only rebuilds when src/ changes)
FROM deps-builder AS builder

RUN rm -rf sipcord-bridge/src
COPY sipcord-bridge/src/ sipcord-bridge/src/
COPY wav/ wav/
COPY config.toml config.toml

RUN touch sipcord-bridge/src/main.rs sipcord-bridge/src/lib.rs
RUN cargo build --release -p sipcord-bridge

# Stage 4: Minimal runtime image
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libasound2 \
    libssl3 \
    libuuid1 \
    libopencore-amrnb0 \
    libopencore-amrwb0 \
    libopus0 \
    libtiff6 \
    libjpeg62-turbo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/sipcord-bridge /app/sipcord-bridge
COPY --from=builder /build/config.toml /app/config.toml
COPY --from=builder /build/wav/ /app/wav/

ENTRYPOINT ["/app/sipcord-bridge"]
