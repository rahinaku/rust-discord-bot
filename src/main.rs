use std::env;

use api_test::get_app;
use reqwest::Client;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    // slashコマンドを登録
    let application_id = env::var("DISCORD_APP_ID").unwrap();
    let token = env::var("DISCORD_TOKEN").unwrap();
    println!("{application_id}");
    let url = format!(
        "https://discord.com/api/v10/applications/{}/commands",
        application_id
    );
    let token = format!("Bot {}", token);
    println!("{token}");
    println!("{url}");
    let client = Client::new();
    let res = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::AUTHORIZATION, token)
        .send()
        .await
        .unwrap();
    println!("{}", res.status());
    println!("{}", res.text().await.unwrap());
    // .envファイルから環境変数を読み込む

    let app = get_app();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
