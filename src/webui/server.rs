//! Minimal blocking HTTP/1.1 server for the local console.
//!
//! Deliberately dependency-free: the console must build and run offline on
//! Kylin/Linux boxes without a package mirror, and a single-user localhost UI
//! does not need keep-alive, chunked encoding or TLS.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use super::api;
use super::AppContext;

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_CSS: &str = include_str!("assets/app.css");
const APP_JS: &str = include_str!("assets/app.js");

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    pub fn query_params(&self) -> HashMap<String, String> {
        parse_query(&self.query)
    }

    pub fn json(&self) -> Result<serde_json::Value, String> {
        if self.body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_slice(&self.body)
            .map_err(|error| format!("请求体不是合法的 JSON: {error}"))
    }
}

pub type Response = (u16, &'static str, Vec<u8>);

pub fn handle_connection(mut stream: TcpStream, ctx: Arc<AppContext>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_nodelay(true);

    let request = match read_request(&mut stream) {
        Ok(Some(request)) => request,
        Ok(None) => return,
        Err(error) => {
            let (status, ctype, body) = api::error_response(400, error);
            respond(&mut stream, status, ctype, &body);
            return;
        }
    };

    let (status, ctype, body) = route(&request, &ctx);
    respond(&mut stream, status, ctype, &body);
}

fn route(request: &Request, ctx: &AppContext) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => (
            200,
            "text/html; charset=utf-8",
            index_html(ctx).into_bytes(),
        ),
        ("GET", "/static/app.css") => (
            200,
            "text/css; charset=utf-8",
            APP_CSS
                .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
                .into_bytes(),
        ),
        ("GET", "/static/app.js") => (
            200,
            "application/javascript; charset=utf-8",
            APP_JS
                .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
                .into_bytes(),
        ),
        ("GET", "/favicon.ico") => (204, "image/x-icon", Vec::new()),
        ("GET", "/api/health") => api::ok(serde_json::json!({ "ok": true })),
        (_, path) if path.starts_with("/api/") => {
            // A per-session token stops other pages from driving this local API
            // through cross-site requests.
            if request.header("x-sentinel-token") != Some(ctx.token.as_str()) {
                return api::error_response(403, "会话令牌无效，请刷新控制台页面");
            }
            api::handle(request, ctx)
        }
        ("GET", _) => (404, "text/plain; charset=utf-8", b"Not Found".to_vec()),
        _ => api::error_response(405, "不支持的方法"),
    }
}

fn index_html(ctx: &AppContext) -> String {
    INDEX_HTML
        .replace("__TOKEN__", &ctx.token)
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__PLATFORM__", &super::platform_label())
}

fn read_request(stream: &mut TcpStream) -> Result<Option<Request>, String> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);

    let mut request_line = String::new();
    let read = reader
        .read_line(&mut request_line)
        .map_err(|error| format!("读取请求失败: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    let request_line = request_line.trim_end();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let target = parts.next().unwrap_or("/").to_string();
    if method.is_empty() {
        return Err("无法解析请求行".to_string());
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (target, String::new()),
    };

    let mut headers: HashMap<String, String> = HashMap::new();
    let mut header_bytes = request_line.len();
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| format!("读取请求头失败: {error}"))?;
        if read == 0 {
            break;
        }
        header_bytes += read;
        if header_bytes > MAX_HEADER_BYTES {
            return Err("请求头过大".to_string());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err("请求体过大".to_string());
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .map_err(|error| format!("读取请求体失败: {error}"))?;
    }

    Ok(Some(Request {
        method,
        path: percent_decode(&path),
        query,
        headers,
        body,
    }))
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

pub fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        params.insert(percent_decode(raw_key), percent_decode(raw_value));
    }
    params
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_paths_with_chinese() {
        assert_eq!(percent_decode("/%E6%A1%8C%E9%9D%A2"), "/桌面");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn parses_query_strings() {
        let params = parse_query("path=%2Ftmp&limit=20&flag");
        assert_eq!(params.get("path").map(String::as_str), Some("/tmp"));
        assert_eq!(params.get("limit").map(String::as_str), Some("20"));
        assert_eq!(params.get("flag").map(String::as_str), Some(""));
    }
}
