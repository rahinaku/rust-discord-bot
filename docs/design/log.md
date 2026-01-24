# Rustロギングガイド - tracing

## 概要

このドキュメントでは、Rustアプリケーションにおける構造化ロギングのベストプラクティスとして、`tracing` クレートの使用方法を説明します。

`tracing` は、アプリケーションの実行をトレースし、構造化されたイベントベースの診断情報を収集するためのフレームワークです。従来の `log` クレートよりも強力で、特に非同期アプリケーションに適しています。

## セットアップ

### 依存関係の追加

```toml
[dependencies]
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# オプション: JSON形式での出力が必要な場合
# tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
```

### 初期化

アプリケーションの起動時に、一度だけ初期化を行います。

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() {
    // 基本的な初期化
    tracing_subscriber::fmt::init();

    // または、環境変数で制御可能な初期化
    init_tracing();

    // アプリケーションのコード
}

/// トレーシングの初期化（推奨）
fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
```

### 環境変数での制御

```bash
# すべてのログを表示
RUST_LOG=trace cargo run

# info以上のみ表示
RUST_LOG=info cargo run

# モジュール別に制御
RUST_LOG=my_app=debug,reqwest=warn,tokio=info cargo run

# 複数のモジュールに異なるレベルを設定
RUST_LOG=my_app::domain=trace,my_app::infrastructure=debug,info cargo run
```

## ログレベルの使い分け

| レベル | 用途 | 本番環境 | 例 |
|--------|------|----------|-----|
| **error** | 重大なエラー、即座の対応が必要 | ✓ | データベース接続失敗、API呼び出し失敗 |
| **warn** | 警告、問題の可能性がある状態 | ✓ | 再試行回数が上限に近い、廃止予定の機能の使用 |
| **info** | 重要なイベント、ビジネスロジックの主要な流れ | ✓ | サーバー起動、リクエスト処理完了、重要な設定値 |
| **debug** | 開発時のデバッグ情報、詳細な処理の流れ | △ | 関数の引数、中間処理の結果 |
| **trace** | 非常に詳細な情報、すべての処理ステップ | ✗ | ループの各反復、低レベルな処理の詳細 |

## 基本的な使い方

### ログマクロ

```rust
use tracing::{trace, debug, info, warn, error};

fn process_data() {
    trace!("関数開始");
    debug!("データ処理中");
    info!("処理が完了しました");
    warn!("メモリ使用量が高くなっています");
    error!("データの読み込みに失敗しました");
}
```

### 構造化ログ

フィールドを使って構造化された情報を記録します。

```rust
use tracing::info;

fn handle_request(user_id: u64, action: &str) {
    // フィールド名 = 値 の形式で記録
    info!(
        user_id = user_id,
        action = action,
        "Processing user request"
    );

    // % を使って Display トレイトでフォーマット
    info!(
        user_id = %user_id,
        action = %action,
        "Request processed"
    );

    // ? を使って Debug トレイトでフォーマット
    info!(
        request = ?some_struct,
        "Received request"
    );
}
```

### エラー情報の記録

```rust
use tracing::error;

async fn fetch_data(url: &str) -> Result<String, reqwest::Error> {
    let response = reqwest::get(url).await;

    match response {
        Ok(resp) => {
            info!(url = %url, status = %resp.status(), "Request successful");
            resp.text().await
        }
        Err(e) => {
            error!(
                url = %url,
                error = %e,
                "Request failed"
            );
            Err(e)
        }
    }
}
```

## 高度な機能

### #[instrument] 属性

関数の呼び出しを自動的にトレースします。

```rust
use tracing::instrument;

#[instrument]
fn calculate(x: i32, y: i32) -> i32 {
    x + y
}
// 呼び出し時に自動的にログが出力される:
// TRACE calculate{x=5 y=3}: enter
// TRACE calculate{x=5 y=3}: exit, return=8

#[instrument(level = "debug")]
async fn fetch_user(user_id: u64) -> Result<User, Error> {
    // この関数の開始と終了が debug レベルで記録される
    database::get_user(user_id).await
}
```

### 機密情報のスキップ

```rust
use tracing::instrument;

// token はログに出力されない
#[instrument(skip(token))]
async fn authenticate(username: &str, token: &str) -> Result<(), Error> {
    info!("Authenticating user");
    // 処理...
    Ok(())
}

// 複数のフィールドをスキップ
#[instrument(skip(password, secret_key))]
fn secure_operation(user: &str, password: &str, secret_key: &str) -> Result<(), Error> {
    // 処理...
    Ok(())
}

// すべての引数をスキップし、特定のフィールドのみ表示
#[instrument(skip_all, fields(user_id = user.id))]
fn process_user(user: &User, config: &Config) -> Result<(), Error> {
    // user.id のみがログに記録される
    Ok(())
}
```

### カスタムフィールドの追加

```rust
use tracing::{info, instrument};

#[instrument(fields(request_id = %uuid::Uuid::new_v4()))]
async fn handle_request(data: &str) -> Result<(), Error> {
    // リクエストごとにユニークなIDが自動的に付与される
    info!("Processing request");
    Ok(())
}
```

### Span の手動管理

```rust
use tracing::{info, span, Level};

fn complex_operation() {
    let span = span!(Level::INFO, "complex_operation", operation_id = 123);
    let _enter = span.enter();

    info!("Step 1");
    // 処理...

    info!("Step 2");
    // 処理...

    // _enter がドロップされると span が終了
}

// または
fn another_operation() {
    let span = span!(Level::INFO, "another_operation");
    span.in_scope(|| {
        info!("Inside span");
        // この中の処理はすべて span に関連付けられる
    });
}
```

### 非同期処理でのトレーシング

```rust
use tracing::{info, instrument, Instrument};

#[instrument]
async fn async_operation() {
    info!("Starting async operation");

    // 非同期タスクを spawn する場合は .instrument() を使う
    let handle = tokio::spawn(
        async {
            info!("Inside spawned task");
        }.instrument(tracing::info_span!("spawned_task"))
    );

    handle.await.unwrap();
}
```

## ベストプラクティス

### 1. println! を使わない

**❌ 悪い例:**
```rust
println!("User logged in: {}", username);
println!("Error: {}", error);
```

**✅ 良い例:**
```rust
info!(username = %username, "User logged in");
error!(error = %error, "Operation failed");
```

### 2. 構造化ログを活用

**❌ 悪い例:**
```rust
info!("User {} performed action {} at {}", user_id, action, timestamp);
```

**✅ 良い例:**
```rust
info!(
    user_id = user_id,
    action = %action,
    timestamp = %timestamp,
    "User action performed"
);
```

### 3. 適切なログレベルを選択

```rust
// ❌ すべてを info にしない
info!("Loop iteration: {}", i);
info!("Variable value: {:?}", var);

// ✅ 適切なレベルを使う
trace!("Loop iteration: {}", i);
debug!(var = ?var, "Processing variable");
info!("Processing completed");
```

### 4. 機密情報をログに含めない

```rust
// ❌ 危険
info!(password = password, "User login attempt");
info!("Token: {}", api_token);

// ✅ 安全
info!(username = username, "User login attempt");
info!("Token configured, length: {}", api_token.len());
debug!("Token prefix: {}...", &api_token[..8]);
```

### 5. エラーには十分なコンテキストを含める

**❌ 悪い例:**
```rust
if let Err(e) = result {
    error!("Failed");
}
```

**✅ 良い例:**
```rust
if let Err(e) = result {
    error!(
        error = %e,
        user_id = user_id,
        operation = "fetch_data",
        "Operation failed"
    );
}
```

### 6. #[instrument] を活用

```rust
// 重要な関数には #[instrument] を付ける
#[instrument]
async fn process_payment(user_id: u64, amount: f64) -> Result<(), Error> {
    info!("Processing payment");
    // 処理...
    Ok(())
}

// 非同期関数でも同様
#[instrument(skip(db_pool))]
async fn fetch_user_data(user_id: u64, db_pool: &DbPool) -> Result<User, Error> {
    // db_pool は大きな構造体なので skip
    Ok(User::default())
}
```

### 7. 計測可能なイベントを記録

```rust
use tracing::info;

#[instrument]
async fn process_batch(items: &[Item]) -> Result<(), Error> {
    let start = std::time::Instant::now();

    // 処理...

    info!(
        items_count = items.len(),
        duration_ms = start.elapsed().as_millis(),
        "Batch processing completed"
    );

    Ok(())
}
```

## 環境別の設定

### 開発環境

```rust
fn init_tracing_dev() {
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_target(true)      // モジュール名を表示
        .with_line_number(true) // 行番号を表示
        .with_thread_ids(true)  // スレッドIDを表示
        .pretty()               // 人間が読みやすい形式
        .init();
}
```

### 本番環境

```rust
fn init_tracing_prod() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "info".to_string())
        )
        .json()  // JSON形式で出力（ログ集約システム向け）
        .init();
}
```

### 環境に応じた初期化

```rust
pub fn init_tracing() {
    if cfg!(debug_assertions) {
        // デバッグビルド
        tracing_subscriber::fmt()
            .with_env_filter("debug")
            .pretty()
            .init();
    } else {
        // リリースビルド
        tracing_subscriber::fmt()
            .with_env_filter(
                std::env::var("RUST_LOG")
                    .unwrap_or_else(|_| "info".to_string())
            )
            .json()
            .init();
    }
}
```

## ファイル出力

### 基本的なファイル出力

```rust
use std::fs::File;
use tracing_subscriber::fmt::writer::MakeWriterExt;

fn init_tracing_with_file() {
    let file = File::create("app.log")
        .expect("Unable to create log file");

    tracing_subscriber::fmt()
        .with_writer(file)
        .init();
}
```

### 標準出力とファイルの両方に出力

```rust
use std::fs::File;
use tracing_subscriber::fmt::writer::MakeWriterExt;

fn init_tracing_multi_output() {
    let file = File::create("app.log")
        .expect("Unable to create log file");

    let (non_blocking_file, _guard) = tracing_appender::non_blocking(file);

    tracing_subscriber::fmt()
        .with_writer(std::io::stdout.and(non_blocking_file))
        .init();
}
```

### ローテーション付きファイル出力

```toml
[dependencies]
tracing-appender = "0.2"
```

```rust
use tracing_appender::rolling::{RollingFileAppender, Rotation};

fn init_tracing_with_rotation() {
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,    // 日次でローテーション
        "/var/log/myapp",   // ディレクトリ
        "app.log"           // ファイル名のプレフィックス
    );

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .init();
}
```

## テスト時のロギング

### テストで出力を確認

```rust
#[cfg(test)]
mod tests {
    use tracing::info;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_with_logging() {
        info!("This will be captured");
        assert!(true);
    }
}
```

### テスト用の依存関係

```toml
[dev-dependencies]
tracing-test = "0.2"
```

## パフォーマンスの考慮事項

### 1. 無効なログレベルのオーバーヘッドは最小限

```rust
// trace が無効な場合、この処理はほとんどコストがかからない
trace!("Value: {:?}", expensive_debug_formatting());
```

### 2. 条件付きロギング

```rust
use tracing::{debug, Level};

// ログレベルが有効な場合のみ実行
if tracing::level_enabled!(Level::DEBUG) {
    let expensive_result = expensive_computation();
    debug!(result = ?expensive_result, "Computation result");
}
```

### 3. Span の再利用

```rust
use tracing::{info_span, Instrument};

// span を作成して再利用
let span = info_span!("request_handler", request_id = %request_id);

async {
    info!("Processing request");
    // 処理...
}.instrument(span).await;
```

## よくある間違いと解決策

### 1. 初期化を忘れる

**問題:**
```rust
use tracing::info;

fn main() {
    info!("Hello"); // 何も出力されない！
}
```

**解決:**
```rust
use tracing::info;

fn main() {
    tracing_subscriber::fmt::init(); // 初期化が必要
    info!("Hello"); // 出力される
}
```

### 2. 非同期タスクで span が失われる

**問題:**
```rust
#[instrument]
async fn parent() {
    tokio::spawn(async {
        info!("This loses the parent span context");
    });
}
```

**解決:**
```rust
#[instrument]
async fn parent() {
    tokio::spawn(
        async {
            info!("This preserves the span context");
        }.instrument(tracing::info_span!("child_task"))
    );
}
```

### 3. 文字列の所有権の問題

**問題:**
```rust
let owned_string = String::from("test");
info!(value = owned_string, "Log"); // owned_string が move される
println!("{}", owned_string); // エラー！
```

**解決:**
```rust
let owned_string = String::from("test");
info!(value = %owned_string, "Log"); // % を使って借用
println!("{}", owned_string); // OK
```

## まとめ

### 採用する理由

- ✅ 構造化ログで検索・分析が容易
- ✅ 非同期処理のトレーシングに優れている
- ✅ `#[instrument]` で自動的にコンテキストを追跡
- ✅ 環境変数で柔軟に制御可能
- ✅ パフォーマンスへの影響が最小限
- ✅ JSON出力でログ集約システムと統合可能

### 次のステップ

1. 既存の `println!` を `info!` / `error!` などに置き換え
2. 重要な関数に `#[instrument]` を追加
3. 機密情報がログに含まれていないか確認
4. 環境変数で適切なログレベルを設定
5. 本番環境ではJSON形式の出力を検討

### 参考リンク

- [tracing 公式ドキュメント](https://docs.rs/tracing/)
- [tracing-subscriber 公式ドキュメント](https://docs.rs/tracing-subscriber/)
- [The Rust Performance Book - Logging](https://nnethercote.github.io/perf-book/logging.html)
