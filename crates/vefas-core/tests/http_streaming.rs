use vefas_core::HttpProcessor;

#[test]
fn parses_response_with_content_length() {
    let mut proc = HttpProcessor::new();
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello";
    let parsed = proc.parse_http_response(response).expect("parse");
    assert_eq!(parsed.status_code, 200);
    assert_eq!(parsed.body, b"Hello");
}

#[test]
fn decodes_chunked_transfer_encoding_single_chunk() {
    let mut proc = HttpProcessor::new();
    let response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nB\r\nHello World\r\n0\r\n\r\n";
    let parsed = proc.parse_http_response(response).expect("parse");
    // Expect body to be de-chunked: "Hello World"
    assert_eq!(parsed.status_code, 200);
    // Process body via response processing
    let body = proc.process_response_body(&parsed).expect("dechunk");
    assert_eq!(body, b"Hello World");
}

#[test]
fn decodes_chunked_transfer_encoding_multiple_chunks() {
    let mut proc = HttpProcessor::new();
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
    let parsed = proc.parse_http_response(response).expect("parse");
    let body = proc.process_response_body(&parsed).expect("dechunk");
    assert_eq!(body, b"Hello World");
}
