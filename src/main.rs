use api_test::get_app;

#[tokio::main]
async fn main() {
    // .envファイルから環境変数を読み込む
    dotenv::dotenv().ok();

    let app = get_app();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
