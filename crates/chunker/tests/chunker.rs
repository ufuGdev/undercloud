// SPDX-License-Identifier: Apache-2.0
use std::io::Cursor;

use undercloud_chunker::{chunk_stream, ChunkerError, DEFAULT_CHUNK_SIZE};

async fn collect(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let reader = Cursor::new(data.to_vec());
    let mut rx = chunk_stream(reader, chunk_size)
        .await
        .expect("valid chunk size must be accepted");
    let mut chunks = Vec::new();
    while let Some(result) = rx.recv().await {
        chunks.push(result.unwrap());
    }
    chunks
}

#[tokio::test]
async fn zero_chunk_size_is_rejected_before_any_reading() {
    // A zero-size buffer would make every read look like end-of-stream, silently truncating the input.
    let err = chunk_stream(Cursor::new(vec![1, 2, 3]), 0).await;
    assert!(matches!(err, Err(ChunkerError::InvalidChunkSize(0))));
}

#[tokio::test]
async fn zero_byte_file_yields_no_chunks() {
    let chunks = collect(&[], 16).await;
    assert_eq!(chunks.len(), 0);
}

#[tokio::test]
async fn one_byte_file_yields_one_chunk() {
    let chunks = collect(&[42], 16).await;
    assert_eq!(chunks, vec![vec![42]]);
}

#[tokio::test]
async fn exactly_chunk_size_yields_one_chunk() {
    let data = vec![1u8; 16];
    let chunks = collect(&data, 16).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len(), 16);
}

#[tokio::test]
async fn chunk_size_minus_one_yields_one_chunk() {
    let data = vec![1u8; 15];
    let chunks = collect(&data, 16).await;
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].len(), 15);
}

#[tokio::test]
async fn chunk_size_plus_one_yields_two_chunks() {
    let data = vec![1u8; 17];
    let chunks = collect(&data, 16).await;
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].len(), 16);
    assert_eq!(chunks[1].len(), 1);
}

#[tokio::test]
async fn multiple_full_chunks_preserve_order_and_content() {
    let data: Vec<u8> = (0..64u32).flat_map(|i| (i as u8).to_be_bytes()).collect();
    let chunks = collect(&data, 16).await;
    assert_eq!(chunks.len(), 4);
    let reassembled: Vec<u8> = chunks.concat();
    assert_eq!(reassembled, data);
}

#[tokio::test]
async fn default_chunk_size_is_six_mebibytes() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 6 * 1024 * 1024);
}
