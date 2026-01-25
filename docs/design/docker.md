# Docker 環境構築ガイド

## 概要

Dockerを使用してアプリケーションをコンテナ化し、ビルド・実行する手順を記載します。

## 前提条件

- Docker Desktop または Docker Engine がインストールされていること

```bash
# インストール確認
docker --version
```

## ファイル構成

```
.
├── Dockerfile           # マルチステージビルド用Dockerfile
├── .dockerignore        # ビルド時に除外するファイル（推奨）
└── .env                 # 環境変数ファイル
```

## ビルド手順

### 1. イメージのビルド

```bash
docker build -t api-test .
```

キャッシュを使わずにビルドする場合:

```bash
docker build --no-cache -t api-test .
```

### 2. ビルド確認

```bash
docker images | grep api-test
```

## 実行手順

### 基本的な実行

```bash
docker run -p 3000:3000 api-test
```

### 環境変数ファイルを使用

```bash
docker run -p 3000:3000 --env-file .env api-test
```

### バックグラウンドで実行

```bash
docker run -d -p 3000:3000 --env-file .env --name api-test-container api-test
```

### ログの確認

```bash
docker logs api-test-container

# リアルタイムで確認
docker logs -f api-test-container
```

### コンテナの停止・削除

```bash
# 停止
docker stop api-test-container

# 削除
docker rm api-test-container

# 停止と削除を同時に
docker rm -f api-test-container
```

## 開発時の使用

### ソースコードをマウントして実行

開発時にはソースコードをマウントし、コンテナ内でビルド・実行できます。

```bash
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  -p 3000:3000 \
  rust:1.84-bookworm \
  cargo run
```

### cargo-watch を使用したホットリロード

```bash
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  -p 3000:3000 \
  rust:1.84-bookworm \
  bash -c "cargo install cargo-watch && cargo watch -x run"
```

## .dockerignore の作成（推奨）

ビルド時間短縮とイメージサイズ削減のため、`.dockerignore` を作成します。

```
target/
.git/
.gitignore
*.md
.env
.env.*
!.env.template
```

## トラブルシューティング

### ビルドが失敗する

```bash
# Dockerのディスク容量を確認
docker system df

# 不要なイメージ・コンテナを削除
docker system prune -a
```

### ポートが既に使用されている

```bash
# 使用中のポートを確認
lsof -i :3000

# 別のポートにマッピング
docker run -p 8080:3000 api-test
```

### コンテナ内でデバッグ

```bash
# コンテナ内にシェルで入る
docker run -it --rm api-test /bin/bash

# 実行中のコンテナに入る
docker exec -it api-test-container /bin/bash
```
