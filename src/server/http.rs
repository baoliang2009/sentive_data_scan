//! 服务端 HTTP 层：Web 控制台与 JSON API。
//!
//! 复用客户端控制台的「零依赖阻塞 HTTP/1.1」实现思路——服务端同样需要能在
//! 离线麒麟机器上直接跑，不想为单个控制台引入 hyper/axum 整套异步栈。

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use super::api;
use super::AppState;

const INDEX_HTML: &str = include_str!("assets/index.html");
const APP_CSS: &str = include_str!("assets/app.css");
const APP_JS: &str = include_str!("assets/app.js");

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub remote: String,
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

    /// 从 `Authorization: Bearer xxx` 或 `X-Sentinel-Token` 取令牌。
    pub fn bearer(&self) -> Option<&str> {
        if let Some(value) = self.header("authorization") {
            if let Some(token) = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
            {
                return Some(token.trim());
            }
        }
        self.header("x-sentinel-token").map(str::trim)
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        let raw = self.header("cookie")?;
        for part in raw.split(';') {
            let (key, value) = part.trim().split_once('=')?;
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
        None
    }
}

pub type Response = (u16, &'static str, Vec<u8>);

pub fn handle_connection(mut stream: TcpStream, state: Arc<AppState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_nodelay(true);

    let remote = stream
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let request = match read_request(&mut stream, remote) {
        Ok(Some(request)) => request,
        Ok(None) => return,
        Err(error) => {
            let (status, ctype, body) = api::error_response(400, error);
            respond(&mut stream, status, ctype, &body, &[]);
            return;
        }
    };

    let (status, ctype, body, cookies) = route(&request, &state);
    respond(&mut stream, status, ctype, &body, &cookies);
}

fn route(request: &Request, state: &AppState) -> (u16, &'static str, Vec<u8>, Vec<String>) {
    let mut cookies = Vec::new();
    let (status, ctype, body) = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            (200, "text/html; charset=utf-8", index_html().into_bytes())
        }
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
        ("GET", "/api/health") => api::ok(serde_json::json!({
            "ok": true,
            "service": "sentinel-server",
            "version": env!("CARGO_PKG_VERSION"),
        })),
        // 登录不需要会话；登出需要清理。
        ("POST", "/api/login") => {
            let (response, cookie) = api::login(&state.auth, request);
            if let Some(cookie) = cookie {
                cookies.push(cookie);
            }
            response
        }
        ("POST", "/api/logout") => {
            let (response, cookie) = api::logout(&state.auth, request);
            if let Some(cookie) = cookie {
                cookies.push(cookie);
            }
            response
        }
        // Agent 侧接口：只认共享 Token，不走控制台会话。
        (_, path) if path.starts_with("/api/agent/") => api::handle_agent(request, state),
        (_, path) if path.starts_with("/api/") => match api::authorize(&state.auth, request) {
            Ok(actor) => api::handle(request, state, &actor),
            Err(response) => response,
        },
        ("GET", _) => (404, "text/plain; charset=utf-8", b"Not Found".to_vec()),
        _ => api::error_response(405, "不支持的方法"),
    };
    (status, ctype, body, cookies)
}

fn index_html() -> String {
    INDEX_HTML
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__PLATFORM__", &crate::webui::platform_label())
}

fn read_request(stream: &mut TcpStream, remote: String) -> Result<Option<Request>, String> {
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
        remote,
    }))
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    cookies: &[String],
) {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n",
        body.len()
    );
    for cookie in cookies {
        head.push_str("Set-Cookie: ");
        head.push_str(cookie);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
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
    fn decodes_paths_and_queries() {
        assert_eq!(percent_decode("/%E6%A1%8C%E9%9D%A2"), "/桌面");
        assert_eq!(percent_decode("a+b"), "a b");
        let params = parse_query("user=%E5%BC%A0%E4%B8%89&limit=20&flag");
        assert_eq!(params.get("user").map(String::as_str), Some("张三"));
        assert_eq!(params.get("flag").map(String::as_str), Some(""));
    }
}
