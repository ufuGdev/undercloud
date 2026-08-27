use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use undercloud_credentials::InMemoryCredentialStore;
use undercloud_provider_cloud::{
    CloudProviderConfig, CloudProviderKind, DropboxProvider, GoogleDriveProvider, OAuthFlow,
    OAuthToken, OneDriveProvider,
};
use undercloud_storage::{GetObjectRequest, ObjectLocator, PutObjectRequest, StorageProvider};

async fn mock_server(kind: CloudProviderKind) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut request = [0_u8; 16_384];
            let size = stream.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..size]);
            let line = request.lines().next().unwrap_or_default();
            let path = line.split_whitespace().nth(1).unwrap_or_default();
            let (status, content_type, mut body) = match kind {
                CloudProviderKind::GoogleDrive if path.contains("/about") => (
                    "200 OK",
                    "application/json",
                    br#"{"storageQuota":{"usage":"4","limit":"100"}}"#.to_vec(),
                ),
                CloudProviderKind::GoogleDrive if path.contains("alt=media") => {
                    ("200 OK", "application/octet-stream", b"payload".to_vec())
                }
                CloudProviderKind::GoogleDrive if path.contains("/upload/") => {
                    ("200 OK", "application/json", br#"{"id":"id"}"#.to_vec())
                }
                CloudProviderKind::GoogleDrive if path.contains("/files") => (
                    "200 OK",
                    "application/json",
                    br#"{"files":[{"id":"id","name":"object","size":"7","etag":"e"}]}"#.to_vec(),
                ),
                CloudProviderKind::OneDrive if path.contains("$select=quota") => (
                    "200 OK",
                    "application/json",
                    br#"{"quota":{"used":4,"total":100}}"#.to_vec(),
                ),
                CloudProviderKind::OneDrive
                    if path.contains("/content") && line.starts_with("GET") =>
                {
                    ("200 OK", "application/octet-stream", b"payload".to_vec())
                }
                CloudProviderKind::OneDrive if path.contains("/children") => (
                    "200 OK",
                    "application/json",
                    br#"{"value":[{"name":"object"}]}"#.to_vec(),
                ),
                CloudProviderKind::OneDrive => (
                    "200 OK",
                    "application/json",
                    br#"{"id":"id","size":7,"eTag":"e"}"#.to_vec(),
                ),
                CloudProviderKind::Dropbox if path.contains("get_space_usage") => (
                    "200 OK",
                    "application/json",
                    br#"{"used":4,"allocation":{"allocated":100}}"#.to_vec(),
                ),
                CloudProviderKind::Dropbox if path.contains("files/download") => {
                    ("200 OK", "application/octet-stream", b"payload".to_vec())
                }
                CloudProviderKind::Dropbox if path.contains("files/upload") => {
                    ("200 OK", "application/json", br#"{"id":"id"}"#.to_vec())
                }
                CloudProviderKind::Dropbox if path.contains("files/list_folder") => (
                    "200 OK",
                    "application/json",
                    br#"{"entries":[{"name":"object"}],"has_more":false}"#.to_vec(),
                ),
                CloudProviderKind::Dropbox if path.contains("files/get_metadata") => (
                    "200 OK",
                    "application/json",
                    br#"{"size":7,"content_hash":"e"}"#.to_vec(),
                ),
                _ if line.starts_with("DELETE") => ("204 No Content", "text/plain", Vec::new()),
                _ => ("200 OK", "application/json", b"{}".to_vec()),
            };
            let partial = request
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("range:"));
            let status = if partial {
                "206 Partial Content"
            } else {
                status
            };
            let content_range = if partial {
                "Content-Range: bytes 0-2/7\r\n"
            } else {
                ""
            };
            if partial && body == b"payload" {
                body = b"pay".to_vec();
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{content_range}Connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    });
    (format!("http://{address}"), task)
}

fn config(kind: CloudProviderKind, api_base: String) -> CloudProviderConfig {
    CloudProviderConfig {
        kind,
        display_name: None,
        client_id: "test-client".to_owned(),
        credential_reference: format!("test-{}", kind.as_str()),
        oauth_profile: "test-profile".to_owned(),
        redirect_strategy: undercloud_provider_cloud::RedirectStrategy::default_for(kind),
        account_id: None,
        account_email: None,
        api_base: Some(api_base),
    }
}

async fn exercise(provider: impl StorageProvider) {
    let locator = ObjectLocator("object".to_owned());
    let body = Box::pin(std::io::Cursor::new(b"payload".to_vec()));
    provider
        .put_object(PutObjectRequest {
            locator: locator.clone(),
            body,
            expected_size: 7,
        })
        .await
        .unwrap();
    let mut stream = provider
        .get_object(GetObjectRequest {
            locator: locator.clone(),
            range: Some((0, 2)),
        })
        .await
        .unwrap();
    let mut restored = Vec::new();
    stream.read_to_end(&mut restored).await.unwrap();
    assert_eq!(restored, b"pay");
    assert_eq!(provider.list_objects(None).await.unwrap().locators.len(), 1);
    assert!(provider.quota().await.unwrap().total_bytes.is_some());
    provider.delete_object(&locator).await.unwrap();
}

#[tokio::test]
async fn google_drive_contract_uses_app_data_and_opaque_locators() {
    let (base, server) = mock_server(CloudProviderKind::GoogleDrive).await;
    let provider = GoogleDriveProvider::connect(
        config(CloudProviderKind::GoogleDrive, base),
        Arc::new(InMemoryCredentialStore::new()),
        OAuthFlow::new(),
        OAuthToken {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at_unix: None,
        },
    )
    .await
    .unwrap();
    exercise(provider).await;
    server.abort();
}

#[tokio::test]
async fn google_drive_put_sends_multipart_related_not_form_data() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel::<String>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 16_384];
        let size = stream.read(&mut request).await.unwrap_or(0);
        let _ = captured_tx.send(String::from_utf8_lossy(&request[..size]).into_owned());
        let body = br#"{"id":"new-id"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body).await;
    });
    let provider = GoogleDriveProvider::connect(
        config(CloudProviderKind::GoogleDrive, format!("http://{address}")),
        Arc::new(InMemoryCredentialStore::new()),
        OAuthFlow::new(),
        OAuthToken {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at_unix: None,
        },
    )
    .await
    .unwrap();
    provider
        .put_object(PutObjectRequest {
            locator: ObjectLocator("object".to_owned()),
            body: Box::pin(std::io::Cursor::new(b"payload".to_vec())),
            expected_size: 7,
        })
        .await
        .unwrap();
    server.await.unwrap();
    let request = captured_rx.await.unwrap().to_ascii_lowercase();
    assert!(
        request.contains("content-type: multipart/related"),
        "expected a multipart/related content-type; Drive's upload endpoint rejects multipart/form-data with 400; got:\n{request}"
    );
    assert!(!request.contains("multipart/form-data"));
}

#[tokio::test]
async fn google_drive_put_surfaces_the_rejection_body_on_4xx() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 16_384];
        let _ = stream.read(&mut request).await.unwrap_or(0);
        let body = br#"{"error":{"code":400,"message":"Invalid parents value: appDataFolder."}}"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body).await;
    });
    let provider = GoogleDriveProvider::connect(
        config(CloudProviderKind::GoogleDrive, format!("http://{address}")),
        Arc::new(InMemoryCredentialStore::new()),
        OAuthFlow::new(),
        OAuthToken {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at_unix: None,
        },
    )
    .await
    .unwrap();
    let error = provider
        .put_object(PutObjectRequest {
            locator: ObjectLocator("object".to_owned()),
            body: Box::pin(std::io::Cursor::new(b"payload".to_vec())),
            expected_size: 7,
        })
        .await
        .unwrap_err();
    server.await.unwrap();
    match error {
        undercloud_storage::ProviderError::RequestRejected { status, message } => {
            assert_eq!(status, 400);
            assert!(message.is_none());
        }
        other => panic!("expected RequestRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn google_drive_find_id_surfaces_the_rejection_body_on_4xx() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 16_384];
        let _ = stream.read(&mut request).await.unwrap_or(0);
        let body = br#"{"error":{"code":400,"message":"Invalid query on files."}}"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body).await;
    });
    let provider = GoogleDriveProvider::connect(
        config(CloudProviderKind::GoogleDrive, format!("http://{address}")),
        Arc::new(InMemoryCredentialStore::new()),
        OAuthFlow::new(),
        OAuthToken {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at_unix: None,
        },
    )
    .await
    .unwrap();
    let error = provider
        .head_object(&ObjectLocator("object".to_owned()))
        .await
        .unwrap_err();
    server.await.unwrap();
    match error {
        undercloud_storage::ProviderError::RequestRejected { status, message } => {
            assert_eq!(status, 400);
            assert!(message.is_none());
        }
        other => panic!("expected RequestRejected, got {other:?}"),
    }
}

#[tokio::test]
async fn google_drive_field_selections_never_request_the_nonexistent_v3_etag_field() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (captured_tx, captured_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut request = [0_u8; 16_384];
            let size = stream.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..size]).into_owned();
            let line = request.lines().next().unwrap_or_default().to_owned();
            let _ = captured_tx.send(line);
            let body = if request.contains("/drive/v3/files?") {
                br#"{"files":[{"id":"id","name":"object","size":"7"}]}"#.to_vec()
            } else {
                br#"{"id":"id","size":"7"}"#.to_vec()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    });
    let provider = GoogleDriveProvider::connect(
        config(CloudProviderKind::GoogleDrive, format!("http://{address}")),
        Arc::new(InMemoryCredentialStore::new()),
        OAuthFlow::new(),
        OAuthToken {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at_unix: None,
        },
    )
    .await
    .unwrap();
    provider
        .head_object(&ObjectLocator("object".to_owned()))
        .await
        .unwrap();
    server.abort();
    let mut requests = Vec::new();
    let mut rx = captured_rx;
    while let Ok(line) = rx.try_recv() {
        requests.push(line);
    }
    assert_eq!(
        requests.len(),
        2,
        "expected find_id + head requests, got {requests:?}"
    );
    for line in &requests {
        assert!(
            !line.to_ascii_lowercase().contains("etag"),
            "Drive v3 files have no `etag` field; requesting it gets the whole call rejected with 400: {line}"
        );
    }
}

#[tokio::test]
async fn onedrive_contract_uses_app_root_and_opaque_locators() {
    let (base, server) = mock_server(CloudProviderKind::OneDrive).await;
    let provider = OneDriveProvider::connect(
        config(CloudProviderKind::OneDrive, base),
        Arc::new(InMemoryCredentialStore::new()),
        OAuthFlow::new(),
        OAuthToken {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at_unix: None,
        },
    )
    .await
    .unwrap();
    exercise(provider).await;
    server.abort();
}

#[tokio::test]
async fn dropbox_contract_uses_app_folder_and_opaque_locators() {
    let (base, server) = mock_server(CloudProviderKind::Dropbox).await;
    let provider = DropboxProvider::connect(
        config(CloudProviderKind::Dropbox, base),
        Arc::new(InMemoryCredentialStore::new()),
        OAuthFlow::new(),
        OAuthToken {
            access_token: "access".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            expires_at_unix: None,
        },
    )
    .await
    .unwrap();
    exercise(provider).await;
    server.abort();
}
