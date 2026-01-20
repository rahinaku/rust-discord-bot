use api_test::{get_app, pre_task};

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    pre_task().await;

    let app = get_app();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
