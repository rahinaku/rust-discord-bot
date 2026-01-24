# スラッシュコマンド登録機能のDDD設計

## 概要

`pre_task`関数をDomain-Driven Design (DDD)の原則に従って、責務を明確に分離した設計に再構築する。

## アーキテクチャ

### レイヤー構成

```
┌─────────────────────────────────────┐
│      Presentation Layer             │
│      (lib.rs - pre_task)            │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Application Layer              │
│  (UseCase - ビジネスフロー)         │
│  - RegisterSlashCommandsUseCase     │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │                │
┌──────▼─────┐   ┌──────▼──────────┐
│   Domain   │   │ Infrastructure  │
│   Layer    │   │     Layer       │
│            │◄──┤                 │
│ - Value    │   │ - API Client    │
│   Objects  │   │ - Config        │
│ - Repository   │ - Repository    │
│   Traits   │   │   Implementation│
└────────────┘   └─────────────────┘
```

## 各層の責務

### 1. Domain層
**責務**: ビジネスロジックとドメインモデルの定義

- **Value Objects**:
  - `ApplicationId`: Discord アプリケーションIDの表現
  - `BotToken`: Botトークンの表現
  - `CommandName`: スラッシュコマンド名（Discord仕様のバリデーション付き）
  - `CommandDescription`: スラッシュコマンドの説明
  - `SlashCommandDefinition`: スラッシュコマンドの構造化された定義

- **Repository Traits**:
  - `DiscordRepository`: Discord API操作のインターフェース
  - `ConfigRepository`: 設定取得のインターフェース

- **特徴**:
  - 外部依存なし（外部システムの仕様を知らない）
  - バリデーションロジックを含む
  - 不変性を保証
  - JSONなどのシリアライズ形式に依存しない
  - Repository traitsはドメインオブジェクトの永続化を抽象化

### 2. Application層
**責務**: ユースケースの実装とビジネスフローの調整

- **UseCase**:
  - `RegisterSlashCommandsUseCase`: スラッシュコマンド登録の流れを制御

- **特徴**:
  - Domain層のRepository traitsに依存
  - 具体的な実装に依存せず、インターフェースに依存
  - テスト可能な設計

### 3. Infrastructure層
**責務**: 外部システムとの統合と技術的な実装

- **実装**:
  - `DiscordApiClient`: Discord API通信の実装
  - `EnvConfigRepository`: 環境変数とファイルからの設定読み込み

- **特徴**:
  - Domain層のRepository traitsを実装
  - 外部ライブラリ(reqwest, std::envなど)に依存
  - Discord API固有の仕様（認証ヘッダーフォーマットなど）を扱う

## ディレクトリ構成

```
src/
├── lib.rs                              # エントリーポイント
├── domain/
│   ├── mod.rs
│   ├── discord/
│   │   ├── mod.rs
│   │   ├── value_objects.rs            # Discord Value Objects定義
│   │   └── repository.rs               # DiscordRepository trait定義
│   └── config/
│       ├── mod.rs
│       └── repository.rs               # ConfigRepository trait定義
├── application/
│   ├── mod.rs
│   └── register_slash_commands.rs      # UseCase
├── infrastructure/
│   ├── mod.rs
│   ├── config.rs                       # ConfigRepository実装
│   └── discord_client.rs               # DiscordRepository実装
├── controller/
│   └── ping_handler.rs
└── middleware/
    └── discord_verify.rs
```

## 実装詳細

### Domain層の実装

#### value_objects.rs

```rust
/// Discord Application ID
#[derive(Debug, Clone)]
pub struct ApplicationId(String);

impl ApplicationId {
    pub fn new(id: String) -> Result<Self, String> {
        if id.is_empty() {
            return Err("Application ID cannot be empty".to_string());
        }
        Ok(Self(id))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// Discord Bot Token
#[derive(Debug, Clone)]
pub struct BotToken(String);

impl BotToken {
    pub fn new(token: String) -> Result<Self, String> {
        if token.is_empty() {
            return Err("Bot token cannot be empty".to_string());
        }
        Ok(Self(token))
    }

    /// トークンの値を取得
    pub fn value(&self) -> &str {
        &self.0
    }
}

/// コマンド名
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandName(String);

impl CommandName {
    pub fn new(name: String) -> Result<Self, String> {
        // Discord仕様: 1-32文字
        if name.is_empty() || name.len() > 32 {
            return Err("Command name must be 1-32 characters".to_string());
        }
        // Discord仕様: 小文字英数字、ハイフン、アンダースコアのみ
        if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
            return Err("Command name must be lowercase alphanumeric with - or _".to_string());
        }
        Ok(Self(name))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// コマンドの説明
#[derive(Debug, Clone)]
pub struct CommandDescription(String);

impl CommandDescription {
    pub fn new(description: String) -> Result<Self, String> {
        // Discord仕様: 1-100文字
        if description.is_empty() || description.len() > 100 {
            return Err("Description must be 1-100 characters".to_string());
        }
        Ok(Self(description))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// スラッシュコマンド定義
#[derive(Debug, Clone)]
pub struct SlashCommandDefinition {
    name: CommandName,
    description: CommandDescription,
}

impl SlashCommandDefinition {
    pub fn new(name: CommandName, description: CommandDescription) -> Self {
        Self { name, description }
    }

    pub fn name(&self) -> &CommandName {
        &self.name
    }

    pub fn description(&self) -> &CommandDescription {
        &self.description
    }
}
```

#### domain/discord/repository.rs

```rust
use super::{ApplicationId, BotToken, SlashCommandDefinition};
use std::future::Future;

/// Discord API操作のインターフェース
pub trait DiscordRepository {
    fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> impl Future<Output = Result<(), String>> + Send;
}
```

#### domain/discord/mod.rs

```rust
pub mod value_objects;
pub mod repository;

pub use value_objects::{
    ApplicationId,
    BotToken,
    CommandName,
    CommandDescription,
    SlashCommandDefinition,
};
pub use repository::DiscordRepository;
```

#### domain/config/repository.rs

```rust
use crate::domain::discord::{ApplicationId, BotToken, SlashCommandDefinition};

/// 設定取得のインターフェース
pub trait ConfigRepository {
    fn get_application_id(&self) -> Result<ApplicationId, String>;
    fn get_bot_token(&self) -> Result<BotToken, String>;
    fn load_slash_command_definition(&self) -> Result<SlashCommandDefinition, String>;
}
```

#### domain/config/mod.rs

```rust
pub mod repository;

pub use repository::ConfigRepository;
```

#### domain/mod.rs

```rust
pub mod discord;
pub mod config;
```

### Application層の実装

#### register_slash_commands.rs

```rust
use crate::domain::discord::{ApplicationId, BotToken, SlashCommandDefinition, DiscordRepository};
use crate::domain::config::ConfigRepository;

/// スラッシュコマンド登録ユースケース
pub struct RegisterSlashCommandsUseCase<D, C>
where
    D: DiscordRepository,
    C: ConfigRepository,
{
    discord_repo: D,
    config_repo: C,
}

impl<D, C> RegisterSlashCommandsUseCase<D, C>
where
    D: DiscordRepository,
    C: ConfigRepository,
{
    pub fn new(discord_repo: D, config_repo: C) -> Self {
        Self {
            discord_repo,
            config_repo,
        }
    }

    /// スラッシュコマンド登録を実行
    pub async fn execute(&self) -> Result<(), String> {
        // 1. 設定を取得
        let app_id = self.config_repo.get_application_id()?;
        let token = self.config_repo.get_bot_token()?;
        let commands = self.config_repo.load_slash_command_definition()?;

        println!("Application ID: {}", app_id.value());
        println!("Token configured");

        // 2. Discord APIに登録
        self.discord_repo
            .register_commands(&app_id, &token, &commands)
            .await?;

        println!("Slash commands registered successfully");
        Ok(())
    }
}
```

#### application/mod.rs

```rust
pub mod register_slash_commands;
```

### Infrastructure層の実装

#### config.rs

```rust
use crate::domain::discord::{
    ApplicationId, BotToken, CommandName, CommandDescription, SlashCommandDefinition,
};
use crate::domain::config::ConfigRepository;
use serde::Deserialize;
use std::{env, fs};

/// JSONファイルのスキーマ
#[derive(Deserialize)]
struct SlashCommandJson {
    name: String,
    description: String,
}

/// 環境変数とファイルシステムから設定を読み込む実装
pub struct EnvConfigRepository;

impl EnvConfigRepository {
    pub fn new() -> Self {
        Self
    }
}

impl ConfigRepository for EnvConfigRepository {
    fn get_application_id(&self) -> Result<ApplicationId, String> {
        let id = env::var("DISCORD_APP_ID")
            .map_err(|_| "DISCORD_APP_ID not found in environment".to_string())?;
        ApplicationId::new(id)
    }

    fn get_bot_token(&self) -> Result<BotToken, String> {
        let token = env::var("DISCORD_TOKEN")
            .map_err(|_| "DISCORD_TOKEN not found in environment".to_string())?;
        BotToken::new(token)
    }

    fn load_slash_command_definition(&self) -> Result<SlashCommandDefinition, String> {
        // JSONファイルを読み込み
        let content = fs::read_to_string("./src/slash_command.json")
            .map_err(|e| format!("Failed to read slash_command.json: {}", e))?;

        // JSONをパース
        let json: SlashCommandJson = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON: {}", e))?;

        // Domain Objectに変換（バリデーションが実行される）
        let name = CommandName::new(json.name)?;
        let description = CommandDescription::new(json.description)?;

        Ok(SlashCommandDefinition::new(name, description))
    }
}
```

#### discord_client.rs

```rust
use crate::domain::discord::{ApplicationId, BotToken, SlashCommandDefinition, DiscordRepository};
use reqwest::Client;

/// Discord API クライアントの実装
pub struct DiscordApiClient {
    client: Client,
}

impl DiscordApiClient {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl DiscordRepository for DiscordApiClient {
    async fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> Result<(), String> {
        let url = format!(
            "https://discord.com/api/v10/applications/{}/commands",
            app_id.value()
        );

        println!("Registering commands to: {}", url);

        // Discord API固有の仕様: Authorizationヘッダーは "Bot {token}" の形式
        let auth_header = format!("Bot {}", token.value());

        // Domain ObjectをDiscord API用のJSONに変換
        let json_body = serde_json::json!({
            "name": commands.name().value(),
            "description": commands.description().value(),
        });

        let response = self
            .client
            .put(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .json(&json_body)  // 構造化されたデータをJSONとしてシリアライズ
            .send()
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        println!("Response Status: {}", status);
        println!("Response Body: {}", body);

        if !status.is_success() {
            return Err(format!("Discord API returned error: {}", body));
        }

        Ok(())
    }
}
```

#### infrastructure/mod.rs

```rust
pub mod config;
pub mod discord_client;
```

### lib.rsでの統合

```rust
pub mod domain;
pub mod application;
pub mod infrastructure;
pub mod controller;
pub mod middleware;

use crate::application::register_slash_commands::RegisterSlashCommandsUseCase;
use crate::infrastructure::{
    config::EnvConfigRepository,
    discord_client::DiscordApiClient,
};

pub async fn pre_task() {
    // 依存関係を注入
    let discord_client = DiscordApiClient::new();
    let config_repo = EnvConfigRepository::new();

    // ユースケースを実行
    let use_case = RegisterSlashCommandsUseCase::new(discord_client, config_repo);

    match use_case.execute().await {
        Ok(_) => println!("Pre-task completed successfully"),
        Err(e) => eprintln!("Pre-task failed: {}", e),
    }
}
```

## 設計の利点

### 1. テスタビリティの向上
- Repository traitをモック実装に差し替えることで、外部依存なしでテスト可能
- ユースケースのロジックを単体でテスト可能

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::discord::{
        ApplicationId, BotToken, CommandName, CommandDescription,
        SlashCommandDefinition, DiscordRepository,
    };
    use crate::domain::config::ConfigRepository;

    struct MockDiscordRepository;
    struct MockConfigRepository;

    impl DiscordRepository for MockDiscordRepository {
        async fn register_commands(
            &self,
            _app_id: &ApplicationId,
            _token: &BotToken,
            _commands: &SlashCommandDefinition,
        ) -> Result<(), String> {
            Ok(()) // モック実装
        }
    }

    impl ConfigRepository for MockConfigRepository {
        fn get_application_id(&self) -> Result<ApplicationId, String> {
            ApplicationId::new("test_app_id".to_string())
        }

        fn get_bot_token(&self) -> Result<BotToken, String> {
            BotToken::new("test_token".to_string())
        }

        fn load_slash_command_definition(&self) -> Result<SlashCommandDefinition, String> {
            let name = CommandName::new("test".to_string())?;
            let desc = CommandDescription::new("Test command".to_string())?;
            Ok(SlashCommandDefinition::new(name, desc))
        }
    }

    // テストケース
    #[tokio::test]
    async fn test_register_slash_commands() {
        let discord_repo = MockDiscordRepository;
        let config_repo = MockConfigRepository;
        let use_case = RegisterSlashCommandsUseCase::new(discord_repo, config_repo);

        assert!(use_case.execute().await.is_ok());
    }
}
```

### 2. 依存関係の明確化
- 各層が何に依存しているか明確
- Domain層は外部依存ゼロ（標準ライブラリのみ）
- Application層はDomain層のtraitに依存
- Infrastructure層はDomain層のtraitを実装し、外部ライブラリに依存
- 依存関係の方向: Infrastructure → Application → Domain（逆転していない）

### 3. ビジネスロジックの保護
- Domain層に外部依存がないため、ビジネスルールが技術詳細から保護される
- Value Objectによるバリデーションで不正な値の流入を防止
- **重要**: 外部システム固有の仕様はInfrastructure層に隔離
  - Discord API固有の仕様（例: `"Bot {token}"` フォーマット）
  - JSONシリアライズ/デシリアライズ
  - これにより、外部システムの変更がDomain層に影響しない

### 4. 変更に強い設計
- Discord APIの変更: Infrastructure層のみ修正
- 設定の読み込み方法の変更: ConfigRepositoryの実装のみ修正
- ビジネスフロー変更: Application層のみ修正

### 5. 型安全性の向上
- `String`の代わりに`ApplicationId`、`BotToken`を使用
- コンパイル時に型の誤使用を検出可能
- IDEの補完が効きやすい

## 移行手順

### フェーズ1: 基盤構築
1. ディレクトリ構成を作成
   ```
   src/domain/discord/
   src/application/
   src/infrastructure/
   ```
2. Domain層を実装（Value Objects + Repository Traits）
   - Value Objects:
     - `ApplicationId`, `BotToken`
     - `CommandName`, `CommandDescription`
     - `SlashCommandDefinition`
   - Repository Traits:
     - `DiscordRepository` trait
     - `ConfigRepository` trait

### フェーズ2: レイヤー実装
3. Application層を実装（UseCase）
   - `RegisterSlashCommandsUseCase`
4. Infrastructure層を実装（Repository実装）
   - `EnvConfigRepository` (JSONからDomain Objectへの変換を含む)
   - `DiscordApiClient` (Domain ObjectからJSONへの変換を含む)

### フェーズ3: 統合とテスト
5. lib.rsのpre_taskを新しい実装に置き換え
6. テストコードを追加
   - Domain層のValue Objectのバリデーションテスト
   - UseCaseのモックテスト
7. 既存の動作確認
   - JSONファイルが正しくパースされるか
   - Discord APIへの登録が成功するか

### 注意点
- **段階的な移行**: 一度にすべてを置き換えず、段階的に進める
- **バリデーションの確認**: CommandName, CommandDescriptionのバリデーションが正しく動作するか確認
- **既存のJSONファイル**: 現在の`slash_command.json`のスキーマが新しい実装と互換性があるか確認

## 今後の拡張性

この設計により、以下の拡張が容易になります：

### 1. 複数のスラッシュコマンド登録

```rust
// domain/discord/entities.rs
pub struct SlashCommands {
    commands: Vec<SlashCommandDefinition>,
}

impl SlashCommands {
    pub fn new(commands: Vec<SlashCommandDefinition>) -> Result<Self, String> {
        if commands.is_empty() {
            return Err("At least one command is required".to_string());
        }
        // 名前の重複チェック
        let names: std::collections::HashSet<_> = commands
            .iter()
            .map(|c| c.name().value())
            .collect();
        if names.len() != commands.len() {
            return Err("Duplicate command names found".to_string());
        }
        Ok(Self { commands })
    }
}
```

### 2. コマンドオプションのサポート

```rust
// domain/discord/value_objects.rs
pub enum CommandOptionType {
    String,
    Integer,
    Boolean,
    User,
    Channel,
}

pub struct CommandOption {
    name: String,
    description: String,
    option_type: CommandOptionType,
    required: bool,
}

pub struct SlashCommandDefinition {
    name: CommandName,
    description: CommandDescription,
    options: Vec<CommandOption>,  // オプション追加
}
```

### 3. その他の拡張可能性

- コマンドの更新・削除機能の追加
- 設定の動的リロード
- キャッシュ機能の追加
- エラーハンドリングの強化
- ロギング・モニタリングの追加
- サブコマンドのサポート
- 権限設定のサポート

## 設計判断の根拠

### なぜ`BotToken.as_authorization_header()`をDomain層から削除したのか

**問題点**:
```rust
// ❌ 悪い例: Domain層がDiscord APIの仕様を知っている
impl BotToken {
    pub fn as_authorization_header(&self) -> String {
        format!("Bot {}", self.0)  // Discord API固有のフォーマット
    }
}
```

この実装には以下の問題があります：

1. **外部システムへの依存**: `"Bot {token}"` というフォーマットはDiscord APIの仕様
2. **再利用性の低下**: 他のシステム（例: Slack API）では異なるフォーマットが必要
3. **レイヤーの責務違反**: Domain層が技術詳細を知るべきではない

**解決策**:
```rust
// ✅ 良い例: Domain層は値のみを扱う
impl BotToken {
    pub fn value(&self) -> &str {
        &self.0  // 単純に値を返す
    }
}

// Infrastructure層でフォーマット
impl DiscordRepository for DiscordApiClient {
    async fn register_commands(...) -> Result<(), String> {
        // Discord API固有のフォーマットはここで行う
        let auth_header = format!("Bot {}", token.value());
        // ...
    }
}
```

**この設計の利点**:

1. **Domain層の純粋性**: `BotToken`は外部システムを知らない
2. **変更への耐性**:
   - Discord APIの認証方式が変わっても、Domain層は無影響
   - 変更はInfrastructure層のみ
3. **再利用性**:
   - `BotToken`を他のAPIクライアントでも利用可能
   - 例: Slack APIクライアントでは`format!("Bearer {}", token.value())`
4. **テスタビリティ**:
   - Domain層のテストがシンプル
   - フォーマットロジックのテストはInfrastructure層で実施

### なぜ`SlashCommandDefinition`を構造化したのか

**問題点**:
```rust
// ❌ 悪い例: 単なる文字列のラッパー
pub struct SlashCommandDefinition {
    pub json_content: String,
}
```

この実装には以下の問題があります：

1. **ドメイン概念が表現されていない**: 「スラッシュコマンド」とは何かが分からない
2. **型安全性の欠如**: 構造化されていないため、間違ったJSONでもコンパイルが通る
3. **バリデーション不足**: 空文字列チェックのみで、コマンドの妥当性を検証できない
4. **シリアライズ形式への依存**: Domain層がJSON形式に依存している

**解決策**:
```rust
// ✅ 良い例: ドメイン概念を構造化して表現
pub struct SlashCommandDefinition {
    name: CommandName,        // Discord仕様のバリデーション付き
    description: CommandDescription,
}

pub struct CommandName(String);  // 1-32文字、小文字英数字のみ
pub struct CommandDescription(String);  // 1-100文字
```

**この設計の利点**:

1. **ドメイン概念の明確化**:
   - スラッシュコマンドとは「名前」と「説明」を持つもの、と明確に定義
   - コードを読むだけで仕様が理解できる

2. **型安全性**:
   - `CommandName`と`CommandDescription`は別の型
   - 間違って入れ替えることができない（コンパイルエラー）

3. **バリデーションの集約**:
   - Discord仕様（文字数制限、使用可能文字）をValue Objectで保証
   - 不正なコマンド定義は作成時点で弾かれる

4. **シリアライズ形式からの独立**:
   - Domain層はJSONを知らない
   - JSONからの読み込みはInfrastructure層（config.rs）が担当
   - JSONへの書き込みもInfrastructure層（discord_client.rs）が担当

**データの流れ**:
```
JSONファイル
    ↓ (Infrastructure: config.rs)
Domain Object (SlashCommandDefinition)
    ↓ (Application: UseCase)
Infrastructure (discord_client.rs)
    ↓ (JSONにシリアライズ)
Discord API
```

### レイヤー間の境界を守る重要性

DDDでは、各レイヤーの責務を明確に分離することが重要です：

| レイヤー | 知っていいこと | 知ってはいけないこと |
|---------|--------------|-------------------|
| Domain | ビジネスルール、ドメイン概念、Repository traits | HTTP、JSON、外部API仕様 |
| Application | ビジネスフロー、ユースケース | 具体的な実装（DB、API） |
| Infrastructure | 技術詳細、外部システム仕様 | ビジネスロジック |

**Repository Traitsの配置について**:
- ✅ **Domain層に配置**: Repositoryはドメインオブジェクトをどのように永続化するかのインターフェース
- これにより、依存関係の方向が正しく保たれる: Infrastructure → Application → Domain
- Domain層は外部の実装詳細を知らず、純粋なビジネスロジックとその抽象化のみを含む
- ドメインごとに適切に分離: `domain/discord/` と `domain/config/` は独立したドメイン概念

**具体例**:
- ❌ Domain層で`serde_json`を使う → JSONに依存してしまう
- ✅ Infrastructure層で`serde_json`を使う → Domain Objectとの変換を担当
- ❌ Application層にRepository traitsを配置 → Infrastructure層がApplication層に依存
- ✅ Domain層にRepository traitsを配置 → Infrastructure層がDomain層に依存（正しい方向）
- ❌ `domain/discord/repository.rs`に`ConfigRepository`を配置 → スコープ違反
- ✅ `domain/config/repository.rs`に`ConfigRepository`を配置 → 適切な境界

このルールを守ることで、長期的に保守しやすいコードベースが実現できます。

## Future と Send について

### なぜ `impl Future + Send` を使うのか

Rust 1.75以降では、トレイト内で `async fn` をネイティブでサポートしていますが、public traitで使用する場合はいくつかの制約があります。

#### 問題点: `async fn` in trait の制限

```rust
// ⚠️ 警告が出る例
pub trait DiscordRepository {
    async fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> Result<(), String>;
}
```

この実装では以下の警告が出ます:
```
warning: use of `async fn` in public traits is discouraged as auto trait bounds cannot be specified
```

**理由**:
- `async fn` は暗黙的に `Future` を返しますが、`Send` などの auto trait bounds を指定できません
- マルチスレッドランタイム（Tokio など）では、`Future` が `Send` である必要があります

#### 解決策: `impl Future + Send`

```rust
// ✅ 推奨される実装
use std::future::Future;

pub trait DiscordRepository {
    fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> impl Future<Output = Result<(), String>> + Send;
}
```

### Future trait とは

`Future` は、Rustの非同期処理の基盤となるトレイトです。

```rust
pub trait Future {
    type Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output>;
}
```

- **遅延評価**: `Future` は `.await` されるまで実行されません
- **poll メカニズム**: ランタイムが `poll` を繰り返し呼び出して進行状態をチェックします
- **`async fn` の実体**: `async fn` は `Future` を実装した型を返す糖衣構文です

```rust
// この2つは同等
async fn example() -> i32 { 42 }
fn example() -> impl Future<Output = i32> { async { 42 } }
```

### Send trait とは

`Send` は、値を別のスレッド間で安全に転送できることを示すマーカートレイトです。

```rust
pub unsafe auto trait Send { }
```

#### マルチスレッド環境での重要性

Tokio などのマルチスレッドランタイムでは、タスクが複数のスレッド間で移動される可能性があります:

```rust
#[tokio::main]
async fn main() {
    tokio::spawn(async {
        // このタスクはスレッド1で開始
        some_async_operation().await;
        // .await 後、スレッド2で再開される可能性がある
        another_operation().await;
    });
}
```

`tokio::spawn` は `Future + Send` を要求します:

```rust
pub fn spawn<T>(future: T) -> JoinHandle<T::Output>
where
    T: Future + Send + 'static,
    T::Output: Send + 'static,
```

#### Send な型とそうでない型

**Send な型**:
- `String`, `Vec<T>`, `i32` など基本的な型
- `Arc<T>` (Atomic Reference Counted)
- `Mutex<T>`, `RwLock<T>`

**Send でない型**:
- `Rc<T>` (Reference Counted - スレッドセーフではない)
- `*const T`, `*mut T` (生ポインタ)

### 実装側での違い

**トレイト定義**: `impl Future + Send` を使用

```rust
pub trait DiscordRepository {
    fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> impl Future<Output = Result<(), String>> + Send;
}
```

**実装側**: `async fn` を使用可能

```rust
impl DiscordRepository for DiscordApiClient {
    async fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> Result<(), String> {
        // 非同期処理の実装
        // Send でない型（Rc など）を使うとコンパイルエラーになる
        Ok(())
    }
}
```

### この設計の利点

1. **マルチスレッド安全性**: `Send` bound により、マルチスレッド環境で安全に使用できることが保証されます
2. **コンパイル時の検証**: `Send` でない型を使用した場合、コンパイルエラーで検出されます
3. **明示的な契約**: トレイトの使用者に対して、この Future がスレッド間で移動可能であることを明示します
4. **Tokio との互換性**: `tokio::spawn` などの API と問題なく統合できます

### 代替案: `#[allow(async_fn_in_trait)]`

シンプルさを優先する場合、警告を抑制する方法もあります:

```rust
#[allow(async_fn_in_trait)]
pub trait DiscordRepository {
    async fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> Result<(), String>;
}
```

**メリット**:
- コードがシンプルで読みやすい

**デメリット**:
- `Send` bound を強制できない
- マルチスレッドランタイムで問題が起きる可能性がある
- コンパイル時の安全性が低い

**本プロジェクトでは、マルチスレッド環境での安全性を重視し、`impl Future + Send` を採用しています。**
