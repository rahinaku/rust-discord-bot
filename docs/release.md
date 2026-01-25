# Kubernetes デプロイ設計

## Helm Chart 構成

```
chart/
├── Chart.yaml
├── values.yaml
└── templates/
    ├── namespace.yaml
    ├── deployment.yaml
    ├── service.yaml
    ├── configmap.yaml
    └── secret.yaml
```

## デプロイ手順（k3s）

### 初回デプロイ

```bash
make all
```

### 更新時

```bash
make update
```

### アンインストール

```bash
make delete
```

### 確認コマンド

```bash
make status   # Pod/Service 確認
make logs     # ログ確認
```

## Make コマンド一覧

| コマンド | 説明 |
|----------|------|
| `make build` | Docker イメージをビルド |
| `make load` | k3s にイメージをロード |
| `make deploy` | Helm でデプロイ |
| `make upgrade` | Helm でアップグレード |
| `make delete` | Helm でアンインストール |
| `make all` | ビルド + ロード + デプロイ |
| `make update` | ビルド + ロード + アップグレード |
| `make status` | ステータス確認 |
| `make logs` | ログ確認 |

## Values の変更方法

### 方法1: --set フラグで個別に指定

```bash
make deploy ARGS="--set replicaCount=3"
```

### 方法2: カスタム values ファイルを使用

`values-local.yaml` を作成:

```yaml
secret:
  DISCORD_TOKEN: "your-token-here"
  DISCORD_APP_ID: "your-app-id"
  DISCORD_PUBLIC_KEY: "your-public-key"
```

デプロイ:

```bash
helm install api-test ./chart -n api-test -f chart/values.yaml -f values-local.yaml
```

### 現在の values を確認

```bash
helm get values api-test -n api-test --all
```

## Service タイプ

| タイプ | アクセス範囲 | 用途 |
|--------|-------------|------|
| **ClusterIP** | クラスタ内部のみ | 内部サービス間通信（デフォルト） |
| **NodePort** | クラスタ外部から `<NodeIP>:<Port>` | 開発・テスト環境 |
| **LoadBalancer** | 外部ロードバランサー経由 | 本番環境での外部公開 |

### 外部からアクセスする場合

`values-local.yaml` で Service タイプを変更:

```yaml
service:
  type: NodePort
  port: 3000
```
