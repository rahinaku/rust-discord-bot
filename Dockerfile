FROM rust:1.85-bookworm AS builder

WORKDIR /app

# 依存関係のキャッシュ用に先にCargo.tomlとCargo.lockをコピー
COPY Cargo.toml Cargo.lock ./

# ダミーのsrc/main.rsを作成して依存関係のみビルド
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# 実際のソースコードをコピーしてビルド
COPY src ./src
RUN touch src/main.rs && cargo build --release

# 実行用の軽量イメージ
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/api-test /app/api-test
COPY src/slash_command.json /app/slash_command.json

EXPOSE 3000

CMD ["./api-test"]
