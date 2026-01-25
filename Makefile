.PHONY: build load deploy upgrade delete logs status up down help

# 変数
IMAGE_NAME := api-test
IMAGE_TAG := latest
NAMESPACE := api-test
RELEASE_NAME := api-test
CHART_PATH := ./chart
VALUES_FILE ?=
HELM_ARGS ?=

# values ファイルが指定されていれば -f オプションを追加
ifneq ($(VALUES_FILE),)
  HELM_VALUES := -f $(VALUES_FILE)
else
  HELM_VALUES :=
endif

# Docker ビルド
build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# k3s にイメージをロード
load: build
	docker save $(IMAGE_NAME):$(IMAGE_TAG) | sudo k3s ctr images import -

# Helm インストール
deploy:
	helm install $(RELEASE_NAME) $(CHART_PATH) -n $(NAMESPACE) --create-namespace $(HELM_VALUES) $(HELM_ARGS)

# Helm アップグレード
upgrade:
	helm upgrade $(RELEASE_NAME) $(CHART_PATH) -n $(NAMESPACE) $(HELM_VALUES) $(HELM_ARGS)

# Helm アンインストール
delete:
	helm uninstall $(RELEASE_NAME) -n $(NAMESPACE)

# ビルド + ロード + デプロイ
all: load deploy

# ビルド + ロード + アップグレード
update: load upgrade

# ログ確認
logs:
	kubectl logs -f -l app=$(IMAGE_NAME) -n $(NAMESPACE)

# ステータス確認
status:
	kubectl get pods,svc -n $(NAMESPACE)

# Docker Compose 起動
up:
	docker compose up -d --build

# Docker Compose 停止
down:
	docker compose down

clog:
	docker compose logs
# ヘルプ
help:
	@echo "Usage:"
	@echo "  make build   - Docker イメージをビルド"
	@echo "  make load    - k3s にイメージをロード"
	@echo "  make deploy  - Helm でデプロイ"
	@echo "  make upgrade - Helm でアップグレード"
	@echo "  make delete  - Helm でアンインストール"
	@echo "  make all     - ビルド + ロード + デプロイ"
	@echo "  make update  - ビルド + ロード + アップグレード"
	@echo "  make logs    - ログ確認"
	@echo "  make status  - ステータス確認"
	@echo "  make up      - Docker Compose 起動"
	@echo "  make down    - Docker Compose 停止"
	@echo ""
	@echo "Options:"
	@echo "  VALUES_FILE  - values ファイルを指定"
	@echo "  HELM_ARGS    - Helm に追加の引数を渡す"
	@echo ""
	@echo "Examples:"
	@echo "  make deploy VALUES_FILE=values-local.yaml"
	@echo "  make all VALUES_FILE=values-local.yaml"
	@echo "  make deploy HELM_ARGS=\"--set replicaCount=3\""
