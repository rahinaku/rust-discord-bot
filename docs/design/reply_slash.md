# スラッシュコマンド応答処理の実装設計

## 概要

Discord のスラッシュコマンド（Application Commands）に応答する処理を追加するための設計ドキュメント。
本設計はドメイン駆動設計（DDD）の原則に基づき、レイヤードアーキテクチャを採用する。

## アーキテクチャ概要

### レイヤー構成

```
┌─────────────────────────────────────────────────────────┐
│                    Controller Layer                      │
│            （HTTP リクエスト/レスポンス処理）              │
├─────────────────────────────────────────────────────────┤
│                   Application Layer                      │
│           （ユースケース、コマンドハンドラー）             │
├─────────────────────────────────────────────────────────┤
│                     Domain Layer                         │
│      （エンティティ、値オブジェクト、ドメインサービス）     │
├─────────────────────────────────────────────────────────┤
│                  Infrastructure Layer                    │
│              （外部API連携、シリアライズ）                │
└─────────────────────────────────────────────────────────┘
```

### ディレクトリ構成

```
src/
├── domain/
│   └── discord/
│       ├── mod.rs
│       ├── entities/
│       │   ├── mod.rs
│       │   └── interaction.rs          # Interaction エンティティ
│       ├── value_objects/
│       │   ├── mod.rs
│       │   ├── interaction_id.rs       # InteractionId 値オブジェクト
│       │   ├── interaction_token.rs    # InteractionToken 値オブジェクト
│       │   ├── interaction_type.rs     # InteractionType 値オブジェクト
│       │   ├── command_name.rs         # CommandName 値オブジェクト
│       │   └── command_option.rs       # CommandOption 値オブジェクト
│       ├── services/
│       │   ├── mod.rs
│       │   └── command_executor.rs     # コマンド実行ドメインサービス
│       └── errors.rs                   # ドメインエラー
├── application/
│   ├── mod.rs
│   ├── interaction_use_case.rs         # インタラクション処理ユースケース
│   └── commands/
│       ├── mod.rs
│       ├── command_handler.rs          # コマンドハンドラートレイト
│       ├── test_command.rs             # /test コマンド
│       └── ping_command.rs             # /ping コマンド
├── infrastructure/
│   └── discord_api/
│       ├── mod.rs
│       ├── dto/
│       │   ├── mod.rs
│       │   ├── interaction_request.rs  # リクエストDTO
│       │   └── interaction_response.rs # レスポンスDTO
│       └── mappers/
│           └── interaction_mapper.rs   # DTO ⇔ Entity 変換
└── controller/
    ├── mod.rs
    └── interaction_handler.rs          # HTTPハンドラー
```

## Discord Interactions API について

### インタラクションタイプ

| type | 名前 | 説明 |
|------|------|------|
| 1 | PING | Discord からの接続確認（現在実装済み） |
| 2 | APPLICATION_COMMAND | スラッシュコマンドの実行 |
| 3 | MESSAGE_COMPONENT | ボタンやセレクトメニューの操作 |
| 4 | APPLICATION_COMMAND_AUTOCOMPLETE | コマンドのオートコンプリート |
| 5 | MODAL_SUBMIT | モーダルの送信 |

### レスポンスタイプ

| type | 名前 | 説明 |
|------|------|------|
| 1 | PONG | PING への応答 |
| 4 | CHANNEL_MESSAGE_WITH_SOURCE | メッセージで応答（入力表示あり） |
| 5 | DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE | 遅延応答（後で編集） |
| 6 | DEFERRED_UPDATE_MESSAGE | コンポーネント用の遅延応答 |
| 7 | UPDATE_MESSAGE | コンポーネントのメッセージ更新 |

### インタラクションペイロード構造

#### リクエスト（Discord → Bot）

```json
{
  "id": "インタラクションID（snowflake）",
  "type": 2,
  "token": "レスポンス送信用トークン",
  "application_id": "アプリケーションID",
  "guild_id": "サーバーID（DM の場合は null）",
  "channel_id": "チャンネルID",
  "member": {
    "user": {
      "id": "ユーザーID",
      "username": "ユーザー名",
      "discriminator": "0000"
    },
    "roles": ["role_id_1", "role_id_2"],
    "permissions": "権限ビット"
  },
  "data": {
    "id": "コマンドID",
    "name": "コマンド名",
    "options": [
      {
        "name": "オプション名",
        "type": 3,
        "value": "入力値"
      }
    ]
  }
}
```

#### レスポンス（Bot → Discord）

```json
{
  "type": 4,
  "data": {
    "content": "応答メッセージ",
    "tts": false,
    "embeds": [],
    "allowed_mentions": { "parse": [] },
    "flags": 0
  }
}
```

#### flags の値

| flags | 説明 |
|-------|------|
| 0 | 通常メッセージ |
| 64 | Ephemeral（実行者のみに表示） |

## 実装方針

### 1. Domain Layer（ドメイン層）

#### 1.1 値オブジェクト（Value Objects）

`src/domain/discord/value_objects/interaction_id.rs`:
```rust
use std::fmt;

/// インタラクションID（Discord Snowflake）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InteractionId(String);

impl InteractionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InteractionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
```

`src/domain/discord/value_objects/interaction_token.rs`:
```rust
use std::fmt;

/// インタラクショントークン（15分間有効）
#[derive(Debug, Clone)]
pub struct InteractionToken(String);

impl InteractionToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// セキュリティ上、Display ではマスクする
impl fmt::Display for InteractionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "****")
    }
}
```

`src/domain/discord/value_objects/interaction_type.rs`:
```rust
use crate::domain::discord::errors::DomainError;

/// インタラクションタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionType {
    Ping,
    ApplicationCommand,
    MessageComponent,
    ApplicationCommandAutocomplete,
    ModalSubmit,
}

impl InteractionType {
    pub fn from_i32(value: i32) -> Result<Self, DomainError> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::ApplicationCommand),
            3 => Ok(Self::MessageComponent),
            4 => Ok(Self::ApplicationCommandAutocomplete),
            5 => Ok(Self::ModalSubmit),
            _ => Err(DomainError::InvalidInteractionType(value)),
        }
    }

    pub fn as_i32(&self) -> i32 {
        match self {
            Self::Ping => 1,
            Self::ApplicationCommand => 2,
            Self::MessageComponent => 3,
            Self::ApplicationCommandAutocomplete => 4,
            Self::ModalSubmit => 5,
        }
    }

    /// コマンドデータが必須かどうか
    pub fn requires_data(&self) -> bool {
        matches!(
            self,
            Self::ApplicationCommand
                | Self::MessageComponent
                | Self::ApplicationCommandAutocomplete
                | Self::ModalSubmit
        )
    }
}
```

`src/domain/discord/value_objects/command_name.rs`:
```rust
use crate::domain::discord::errors::DomainError;

/// コマンド名（1-32文字、小文字英数字とハイフン）
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandName(String);

impl CommandName {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() || value.len() > 32 {
            return Err(DomainError::InvalidCommandName(
                "Command name must be 1-32 characters".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

`src/domain/discord/value_objects/command_option.rs`:
```rust
/// コマンドオプション
#[derive(Debug, Clone)]
pub struct CommandOption {
    name: String,
    option_type: i32,
    value: Option<serde_json::Value>,
}

impl CommandOption {
    pub fn new(name: String, option_type: i32, value: Option<serde_json::Value>) -> Self {
        Self {
            name,
            option_type,
            value,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn option_type(&self) -> i32 {
        self.option_type
    }

    pub fn value(&self) -> Option<&serde_json::Value> {
        self.value.as_ref()
    }

    /// 文字列値を取得
    pub fn as_string(&self) -> Option<&str> {
        self.value.as_ref()?.as_str()
    }

    /// 整数値を取得
    pub fn as_i64(&self) -> Option<i64> {
        self.value.as_ref()?.as_i64()
    }
}
```

#### 1.2 エンティティ（Entities）

`src/domain/discord/entities/interaction.rs`:
```rust
use crate::domain::discord::{
    errors::DomainError,
    value_objects::{
        CommandName, CommandOption, InteractionId, InteractionToken, InteractionType,
    },
};

/// インタラクションコマンドデータ
#[derive(Debug, Clone)]
pub struct InteractionData {
    id: String,
    name: CommandName,
    options: Vec<CommandOption>,
}

impl InteractionData {
    pub fn new(
        id: String,
        name: CommandName,
        options: Vec<CommandOption>,
    ) -> Self {
        Self { id, name, options }
    }

    pub fn command_name(&self) -> &CommandName {
        &self.name
    }

    pub fn options(&self) -> &[CommandOption] {
        &self.options
    }

    /// 指定した名前のオプションを取得
    pub fn get_option(&self, name: &str) -> Option<&CommandOption> {
        self.options.iter().find(|o| o.name() == name)
    }
}

/// インタラクション集約ルート
#[derive(Debug)]
pub struct Interaction {
    id: InteractionId,
    interaction_type: InteractionType,
    token: InteractionToken,
    application_id: Option<String>,
    guild_id: Option<String>,
    channel_id: Option<String>,
    data: Option<InteractionData>,
}

impl Interaction {
    /// 新しいインタラクションを生成（不変条件を検証）
    pub fn new(
        id: InteractionId,
        interaction_type: InteractionType,
        token: InteractionToken,
        application_id: Option<String>,
        guild_id: Option<String>,
        channel_id: Option<String>,
        data: Option<InteractionData>,
    ) -> Result<Self, DomainError> {
        let interaction = Self {
            id,
            interaction_type,
            token,
            application_id,
            guild_id,
            channel_id,
            data,
        };
        interaction.validate()?;
        Ok(interaction)
    }

    /// 集約の不変条件を検証
    fn validate(&self) -> Result<(), DomainError> {
        // APPLICATION_COMMAND などはデータが必須
        if self.interaction_type.requires_data() && self.data.is_none() {
            return Err(DomainError::MissingInteractionData(
                self.interaction_type.as_i32(),
            ));
        }
        Ok(())
    }

    pub fn id(&self) -> &InteractionId {
        &self.id
    }

    pub fn interaction_type(&self) -> InteractionType {
        self.interaction_type
    }

    pub fn token(&self) -> &InteractionToken {
        &self.token
    }

    pub fn application_id(&self) -> Option<&str> {
        self.application_id.as_deref()
    }

    pub fn guild_id(&self) -> Option<&str> {
        self.guild_id.as_deref()
    }

    pub fn channel_id(&self) -> Option<&str> {
        self.channel_id.as_deref()
    }

    pub fn data(&self) -> Option<&InteractionData> {
        self.data.as_ref()
    }

    /// PING インタラクションかどうか
    pub fn is_ping(&self) -> bool {
        self.interaction_type == InteractionType::Ping
    }

    /// スラッシュコマンドかどうか
    pub fn is_slash_command(&self) -> bool {
        self.interaction_type == InteractionType::ApplicationCommand
    }
}
```

#### 1.3 ドメインエラー

`src/domain/discord/errors.rs`:
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Invalid interaction type: {0}")]
    InvalidInteractionType(i32),

    #[error("Invalid command name: {0}")]
    InvalidCommandName(String),

    #[error("Missing interaction data for type: {0}")]
    MissingInteractionData(i32),

    #[error("Unknown command: {0}")]
    UnknownCommand(String),
}
```

#### 1.4 ドメインサービス

`src/domain/discord/services/command_executor.rs`:
```rust
use crate::domain::discord::{entities::Interaction, errors::DomainError};

/// コマンド実行結果
#[derive(Debug)]
pub struct CommandResult {
    pub content: String,
    pub ephemeral: bool,
}

impl CommandResult {
    pub fn message(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            ephemeral: false,
        }
    }

    pub fn ephemeral_message(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            ephemeral: true,
        }
    }
}

/// コマンド実行トレイト（ドメインサービス）
pub trait CommandExecutor: Send + Sync {
    fn name(&self) -> &str;
    fn execute(&self, interaction: &Interaction) -> Result<CommandResult, DomainError>;
}
```

### 2. Application Layer（アプリケーション層）

#### 2.1 コマンドハンドラー

`src/application/commands/ping_command.rs`:
```rust
use crate::domain::discord::{
    entities::Interaction,
    errors::DomainError,
    services::command_executor::{CommandExecutor, CommandResult},
};

pub struct PingCommandHandler;

impl CommandExecutor for PingCommandHandler {
    fn name(&self) -> &str {
        "ping"
    }

    fn execute(&self, _interaction: &Interaction) -> Result<CommandResult, DomainError> {
        Ok(CommandResult::message("Pong!"))
    }
}
```

`src/application/commands/test_command.rs`:
```rust
use crate::domain::discord::{
    entities::Interaction,
    errors::DomainError,
    services::command_executor::{CommandExecutor, CommandResult},
};

pub struct TestCommandHandler;

impl CommandExecutor for TestCommandHandler {
    fn name(&self) -> &str {
        "test"
    }

    fn execute(&self, _interaction: &Interaction) -> Result<CommandResult, DomainError> {
        Ok(CommandResult::message("Hello from test command!"))
    }
}
```

#### 2.2 ユースケース

`src/application/interaction_use_case.rs`:
```rust
use std::collections::HashMap;
use crate::domain::discord::{
    entities::Interaction,
    errors::DomainError,
    services::command_executor::{CommandExecutor, CommandResult},
    value_objects::InteractionType,
};

/// インタラクション処理結果
#[derive(Debug)]
pub enum InteractionResult {
    Pong,
    CommandResponse(CommandResult),
    Error(String),
}

/// インタラクション処理ユースケース
pub struct InteractionUseCase {
    commands: HashMap<String, Box<dyn CommandExecutor>>,
}

impl InteractionUseCase {
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
        }
    }

    /// コマンドハンドラーを登録
    pub fn register_command(&mut self, handler: Box<dyn CommandExecutor>) {
        self.commands.insert(handler.name().to_string(), handler);
    }

    /// インタラクションを処理
    pub fn handle(&self, interaction: &Interaction) -> InteractionResult {
        match interaction.interaction_type() {
            InteractionType::Ping => InteractionResult::Pong,

            InteractionType::ApplicationCommand => {
                self.handle_slash_command(interaction)
            }

            _ => InteractionResult::Error(format!(
                "Unsupported interaction type: {}",
                interaction.interaction_type().as_i32()
            )),
        }
    }

    fn handle_slash_command(&self, interaction: &Interaction) -> InteractionResult {
        let command_name = interaction
            .data()
            .map(|d| d.command_name().as_str())
            .unwrap_or("unknown");

        match self.commands.get(command_name) {
            Some(handler) => match handler.execute(interaction) {
                Ok(result) => InteractionResult::CommandResponse(result),
                Err(e) => InteractionResult::Error(e.to_string()),
            },
            None => InteractionResult::Error(format!("Unknown command: {}", command_name)),
        }
    }
}
```

### 3. Infrastructure Layer（インフラストラクチャ層）

#### 3.1 DTO（データ転送オブジェクト）

`src/infrastructure/discord_api/dto/interaction_request.rs`:
```rust
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CommandOptionDto {
    pub name: String,
    pub r#type: i32,
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct InteractionDataDto {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub options: Vec<CommandOptionDto>,
}

#[derive(Debug, Deserialize)]
pub struct InteractionRequestDto {
    pub id: String,
    pub r#type: i32,
    pub token: String,
    pub application_id: Option<String>,
    pub guild_id: Option<String>,
    pub channel_id: Option<String>,
    pub data: Option<InteractionDataDto>,
}
```

`src/infrastructure/discord_api/dto/interaction_response.rs`:
```rust
use serde::Serialize;

/// レスポンスタイプ
#[derive(Debug, Clone, Copy)]
pub enum ResponseType {
    Pong = 1,
    ChannelMessageWithSource = 4,
    DeferredChannelMessageWithSource = 5,
}

/// メッセージフラグ
pub mod flags {
    pub const EPHEMERAL: i32 = 64;
}

#[derive(Debug, Serialize)]
pub struct InteractionResponseDataDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct InteractionResponseDto {
    pub r#type: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<InteractionResponseDataDto>,
}

impl InteractionResponseDto {
    pub fn pong() -> Self {
        Self {
            r#type: ResponseType::Pong as i32,
            data: None,
        }
    }

    pub fn message(content: String, ephemeral: bool) -> Self {
        Self {
            r#type: ResponseType::ChannelMessageWithSource as i32,
            data: Some(InteractionResponseDataDto {
                content: Some(content),
                tts: None,
                flags: if ephemeral { Some(flags::EPHEMERAL) } else { None },
            }),
        }
    }

    pub fn error(message: String) -> Self {
        Self::message(message, true)
    }
}
```

#### 3.2 マッパー

`src/infrastructure/discord_api/mappers/interaction_mapper.rs`:
```rust
use crate::{
    application::interaction_use_case::InteractionResult,
    domain::discord::{
        entities::{Interaction, InteractionData},
        errors::DomainError,
        value_objects::{
            CommandName, CommandOption, InteractionId, InteractionToken, InteractionType,
        },
    },
    infrastructure::discord_api::dto::{
        interaction_request::InteractionRequestDto,
        interaction_response::InteractionResponseDto,
    },
};

pub struct InteractionMapper;

impl InteractionMapper {
    /// DTO からドメインエンティティへ変換
    pub fn to_domain(dto: InteractionRequestDto) -> Result<Interaction, DomainError> {
        let interaction_type = InteractionType::from_i32(dto.r#type)?;

        let data = dto
            .data
            .map(|d| {
                let name = CommandName::new(d.name)?;
                let options = d
                    .options
                    .into_iter()
                    .map(|o| CommandOption::new(o.name, o.r#type, o.value))
                    .collect();
                Ok::<_, DomainError>(InteractionData::new(d.id, name, options))
            })
            .transpose()?;

        Interaction::new(
            InteractionId::new(dto.id),
            interaction_type,
            InteractionToken::new(dto.token),
            dto.application_id,
            dto.guild_id,
            dto.channel_id,
            data,
        )
    }

    /// ユースケース結果からレスポンスDTOへ変換
    pub fn to_response(result: InteractionResult) -> InteractionResponseDto {
        match result {
            InteractionResult::Pong => InteractionResponseDto::pong(),
            InteractionResult::CommandResponse(cmd_result) => {
                InteractionResponseDto::message(cmd_result.content, cmd_result.ephemeral)
            }
            InteractionResult::Error(message) => InteractionResponseDto::error(message),
        }
    }
}
```

### 4. Controller Layer（コントローラー層）

`src/controller/interaction_handler.rs`:
```rust
use axum::{http::StatusCode, response::IntoResponse, Json};
use crate::{
    application::interaction_use_case::InteractionUseCase,
    infrastructure::discord_api::{
        dto::interaction_request::InteractionRequestDto,
        mappers::interaction_mapper::InteractionMapper,
    },
};

pub async fn interaction_handler(
    use_case: axum::extract::Extension<std::sync::Arc<InteractionUseCase>>,
    Json(dto): Json<InteractionRequestDto>,
) -> impl IntoResponse {
    // DTO → ドメインエンティティ
    let interaction = match InteractionMapper::to_domain(dto) {
        Ok(i) => i,
        Err(e) => {
            let response = InteractionMapper::to_response(
                crate::application::interaction_use_case::InteractionResult::Error(e.to_string()),
            );
            return (StatusCode::OK, Json(response));
        }
    };

    // ユースケース実行
    let result = use_case.handle(&interaction);

    // 結果 → レスポンスDTO
    let response = InteractionMapper::to_response(result);

    (StatusCode::OK, Json(response))
}
```

### 5. 依存性注入（アプリケーション起動時）

`src/main.rs` または `src/lib.rs`:
```rust
use std::sync::Arc;
use crate::application::{
    commands::{ping_command::PingCommandHandler, test_command::TestCommandHandler},
    interaction_use_case::InteractionUseCase,
};

fn setup_interaction_use_case() -> Arc<InteractionUseCase> {
    let mut use_case = InteractionUseCase::new();

    // コマンドハンドラーを登録
    use_case.register_command(Box::new(PingCommandHandler));
    use_case.register_command(Box::new(TestCommandHandler));

    Arc::new(use_case)
}
```

## 応答の制約事項

1. **3秒ルール**: 初期応答は3秒以内に返す必要がある
2. **トークン有効期限**: インタラクショントークンは15分間有効
3. **遅延応答**: 処理に時間がかかる場合は `type: 5` で遅延応答し、後から編集する

### 遅延応答の実装例

```rust
// 1. まず遅延応答を返す
let deferred = InteractionResponseDto {
    r#type: ResponseType::DeferredChannelMessageWithSource as i32,
    data: None,
};

// 2. 後から PATCH で更新
// POST https://discord.com/api/v10/webhooks/{application_id}/{interaction_token}/messages/@original
```

## テスト方針

### 単体テスト

#### ドメイン層のテスト

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interaction_type_from_i32() {
        assert_eq!(
            InteractionType::from_i32(1).unwrap(),
            InteractionType::Ping
        );
        assert_eq!(
            InteractionType::from_i32(2).unwrap(),
            InteractionType::ApplicationCommand
        );
        assert!(InteractionType::from_i32(99).is_err());
    }

    #[test]
    fn test_interaction_requires_data() {
        assert!(!InteractionType::Ping.requires_data());
        assert!(InteractionType::ApplicationCommand.requires_data());
    }

    #[test]
    fn test_interaction_validation() {
        // PING はデータなしでOK
        let ping = Interaction::new(
            InteractionId::new("123"),
            InteractionType::Ping,
            InteractionToken::new("token"),
            None, None, None, None,
        );
        assert!(ping.is_ok());

        // APPLICATION_COMMAND はデータ必須
        let command_without_data = Interaction::new(
            InteractionId::new("123"),
            InteractionType::ApplicationCommand,
            InteractionToken::new("token"),
            None, None, None, None,
        );
        assert!(command_without_data.is_err());
    }
}
```

#### アプリケーション層のテスト

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_command() {
        let handler = PingCommandHandler;
        let interaction = create_test_interaction(InteractionType::Ping, None);
        let result = handler.execute(&interaction);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().content, "Pong!");
    }

    #[test]
    fn test_use_case_handles_ping() {
        let use_case = InteractionUseCase::new();
        let interaction = create_test_interaction(InteractionType::Ping, None);

        let result = use_case.handle(&interaction);

        assert!(matches!(result, InteractionResult::Pong));
    }
}
```

## 変更が必要なファイル

1. `src/domain/discord/` - ドメインモデルの追加
2. `src/application/` - ユースケースとコマンドハンドラーの追加
3. `src/infrastructure/discord_api/` - DTOとマッパーの追加
4. `src/controller/ping_handler.rs` → `interaction_handler.rs` - リネームと拡張
5. `src/main.rs` - 依存性注入のセットアップ

## 参考リンク

- [Discord Developer Portal - Application Commands](https://discord.com/developers/docs/interactions/application-commands)
- [Discord Interactions API - Receiving and Responding](https://discord.com/developers/docs/interactions/receiving-and-responding)
- [Domain-Driven Design Reference](https://www.domainlanguage.com/ddd/reference/)
