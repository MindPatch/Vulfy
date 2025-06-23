# Build stage
FROM rust:1.75 as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy dependency files
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this is cached unless Cargo.toml changes)
RUN cargo build --release && rm src/main.rs

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -r -s /bin/false -m -d /app vulfy

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/vulfy /usr/local/bin/vulfy

# Make sure the binary is executable
RUN chmod +x /usr/local/bin/vulfy

# Create necessary directories
RUN mkdir -p /app/vulfy-workspace /app/vulfy-exports && \
    chown -R vulfy:vulfy /app

# Switch to non-root user
USER vulfy

# Create a default automation config
COPY --chown=vulfy:vulfy vulfy-automation.toml /app/vulfy-automation.toml

# Expose port for potential web interface
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD vulfy --version || exit 1

# Set environment variables
ENV VULFY_WORKSPACE=/app/vulfy-workspace
ENV VULFY_CONFIG=/app/vulfy-automation.toml

# Default command
CMD ["vulfy", "--help"] 