use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Query {
    message: String,
}

#[get("/echo")]
async fn echo_get(q: web::Query<Query>) -> impl Responder {
    HttpResponse::Ok().body(q.message.clone())
}

#[post("/echo")]
async fn echo_post(q: web::Json<Query>) -> impl Responder {
    HttpResponse::Ok().body(q.message.clone())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting echo server at http://0.0.0.0:80");
    HttpServer::new(|| App::new().service(echo_get).service(echo_post))
        .bind(("0.0.0.0", 80))?
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_echo_get() {
        let app = test::init_service(App::new().service(echo_get)).await;
        let req = test::TestRequest::get().uri("/echo?message=hello").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        assert_eq!(body, "hello");
    }

    #[actix_web::test]
    async fn test_echo_post() {
        let app = test::init_service(App::new().service(echo_post)).await;
        let req = test::TestRequest::post().uri("/echo").set_json(&Query { message: "world".to_string() }).to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        let body = test::read_body(resp).await;
        assert_eq!(body, "world");
    }
}
