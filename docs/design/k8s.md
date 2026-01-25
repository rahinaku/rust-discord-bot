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

## ローカルでのデプロイ手順

### 1. Docker イメージのビルド

```bash
docker build -t api-test:latest .
```

### 2. Minikube を使用する場合

Minikube の Docker デーモンを使用してイメージをビルドする：

```bash
eval $(minikube docker-env)
docker build -t api-test:latest .
```

### 3. kind を使用する場合

ビルドしたイメージを kind クラスタにロードする：

```bash
docker build -t api-test:latest .
kind load docker-image api-test:latest
```

### 4. Helm でデプロイ

```bash
helm install api-test ./chart -n api-test
```

### 5. デプロイの確認

```bash
kubectl get pods -n api-test
kubectl get svc -n api-test
```

## Values の変更方法

### 方法1: --set フラグで個別に指定

```bash
# レプリカ数を変更
helm install api-test ./chart -n api-test --set replicaCount=3

# イメージタグを変更
helm install api-test ./chart -n api-test --set image.tag=v1.0.0

# Secret の値を設定
helm install api-test ./chart -n api-test \
  --set secret.DISCORD_TOKEN=your-token-here \
  --set secret.DISCORD_APPLICATION_ID=your-app-id

# 複数の値を同時に変更
helm install api-test ./chart -n api-test \
  --set replicaCount=2 \
  --set configMap.RUST_LOG=debug \
  --set resources.limits.memory=512Mi
```

### 方法2: カスタム values ファイルを使用

`values-local.yaml` を作成してデプロイ:

```bash
helm install api-test ./chart -n api-test -f values-local.yaml
```

### 方法3: 複数の values ファイルを組み合わせる

```bash
# 後から指定したファイルが優先される
helm install api-test ./chart -n api-test \
  -f values.yaml \
  -f values-local.yaml \
  -f values-secret.yaml
```

### アップグレード時の変更

```bash
# 既存のリリースを更新
helm upgrade api-test ./chart -n api-test --set replicaCount=3

# values ファイルを使用して更新
helm upgrade api-test ./chart -n api-test -f values-local.yaml
```

### 現在の values を確認

```bash
# デプロイ済みの values を確認
helm get values api-test -n api-test

# すべての values（デフォルト含む）を確認
helm get values api-test -n api-test --all
```
