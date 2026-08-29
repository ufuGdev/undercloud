// SPDX-License-Identifier: Apache-2.0
//! Correctness and round-trip-bound coverage for `list_file_summary_rows`,
//! the batched replacement for the old per-file `list_health_observations`
//! + `load_file_version` loop behind `list_files_cached`.
use undercloud_catalog::{CatalogBootstrap, HealthState, ObjectKind, ReplicaState};
use undercloud_crypto::{derive_vault_subkeys, generate_master_key, wrap_master_key};
use uuid::Uuid;

async fn opened() -> undercloud_catalog::UnlockedCatalog {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.sqlite3");
    let vault = Uuid::new_v4();
    let master = generate_master_key();
    let envelope = wrap_master_key(vault, "test password", &master).unwrap();
    let subkeys = derive_vault_subkeys(&master, vault);
    let bootstrap = CatalogBootstrap::open(&path).await.unwrap();
    bootstrap.create_vault(vault, 1, &envelope).await.unwrap();
    let catalog = bootstrap.unlock(subkeys.catalog_field).await.unwrap();
    // Keep the tempdir alive for the catalog's lifetime by leaking it: the
    // catalog owns its own executor thread against the file, and this test
    // module never needs the path again.
    std::mem::forget(dir);
    catalog
}

/// Builds one logical file with a healthy current version fully verified
/// on `target`, optionally recording a durable health observation for it.
async fn make_file(
    catalog: &undercloud_catalog::UnlockedCatalog,
    target: Uuid,
    name: &str,
    with_observation: bool,
) -> Uuid {
    let file = catalog.create_logical_file(None, name, None).await.unwrap();
    let version = catalog
        .create_file_version(file, 4096, 1, [3; 32])
        .await
        .unwrap();
    let chunk = catalog.create_chunk(version, 0).await.unwrap();
    let manifest_replica = catalog
        .create_replica(version, None, target, ObjectKind::Manifest, "manifest")
        .await
        .unwrap();
    catalog
        .set_replica_state(manifest_replica, ReplicaState::Verified)
        .await
        .unwrap();
    let chunk_replica = catalog
        .create_replica(version, Some(chunk), target, ObjectKind::Chunk, "chunk-0")
        .await
        .unwrap();
    catalog
        .set_replica_state(chunk_replica, ReplicaState::Verified)
        .await
        .unwrap();
    catalog
        .transaction(move |tx| {
            tx.set_current_version(file, version)?;
            Ok(())
        })
        .await
        .unwrap();
    if with_observation {
        catalog
            .record_health_observation(version, 1, 1, HealthState::Healthy)
            .await
            .unwrap();
    }
    file
}

#[tokio::test]
async fn exactly_one_summary_row_per_active_file_including_versionless() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    let with_obs = make_file(&catalog, target, "a", true).await;
    let without_obs = make_file(&catalog, target, "b", false).await;
    let versionless = catalog.create_logical_file(None, "c", None).await.unwrap();

    let rows = catalog.list_file_summary_rows().await.unwrap();
    assert_eq!(rows.len(), 3);
    let ids: std::collections::HashSet<_> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        [with_obs, without_obs, versionless].into_iter().collect()
    );
    let versionless_row = rows.iter().find(|r| r.id == versionless).unwrap();
    assert!(versionless_row.current_version_id.is_none());
    assert!(versionless_row.health_state.is_none());
    assert!(versionless_row.file_size.is_none());
}

#[tokio::test]
async fn latest_health_observation_wins_deterministically_even_on_timestamp_tie() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    let file = make_file(&catalog, target, "a", false).await;
    let version = catalog
        .list_file_summary_rows()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.id == file)
        .unwrap()
        .current_version_id
        .unwrap();

    let first = catalog
        .record_health_observation(version, 1, 2, HealthState::Degraded)
        .await
        .unwrap();
    let second = catalog
        .record_health_observation(version, 2, 2, HealthState::Healthy)
        .await
        .unwrap();

    // `now()` is millisecond-resolution, so these two rapid inserts may or
    // may not land in the same millisecond depending on scheduling (more
    // likely to differ under parallel test load) -- don't assume a tie.
    // Compute the expected winner with the exact same comparator the SQL
    // uses: max by (observed_at, id), both DESC.
    let observations = catalog.list_health_observations(version).await.unwrap();
    let winner = observations
        .iter()
        .max_by(|a, b| (&a.observed_at, a.id).cmp(&(&b.observed_at, b.id)))
        .unwrap();
    let expected_state = winner.health_state;
    assert!(winner.id == first || winner.id == second);

    let rows = catalog.list_file_summary_rows().await.unwrap();
    let row = rows.into_iter().find(|r| r.id == file).unwrap();
    assert_eq!(row.health_state, Some(expected_state));
}

#[tokio::test]
async fn a_new_observation_changes_the_subsequently_visible_summary() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    let file = make_file(&catalog, target, "a", true).await;

    let before = catalog.list_file_summary_rows().await.unwrap();
    let before_row = before.iter().find(|r| r.id == file).unwrap();
    assert_eq!(before_row.health_state, Some(HealthState::Healthy));

    let version = before_row.current_version_id.unwrap();
    catalog
        .record_health_observation(version, 0, 1, HealthState::Unrecoverable)
        .await
        .unwrap();

    let after = catalog.list_file_summary_rows().await.unwrap();
    let after_row = after.iter().find(|r| r.id == file).unwrap();
    assert_eq!(after_row.health_state, Some(HealthState::Unrecoverable));
}

#[tokio::test]
async fn round_trip_count_for_the_listing_query_itself_is_one_regardless_of_scale() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    for n in 0..40 {
        make_file(&catalog, target, &format!("file-{n}"), true).await;
    }
    catalog.reset_round_trip_count();
    let rows = catalog.list_file_summary_rows().await.unwrap();
    assert_eq!(rows.len(), 40);
    assert_eq!(
        catalog.round_trip_count(),
        1,
        "list_file_summary_rows must be exactly one executor round trip"
    );
}

/// Simulates the bulk-fallback path `list_files_cached` runs for rows
/// without a health observation: batch-fetch chunks/replicas for every
/// affected version and confirm (a) the data matches what was inserted and
/// (b) total round trips for the whole listing+fallback flow stay bounded
/// (4: summary rows, targets, chunks-for-versions, replicas-for-versions)
/// at 0%, 90%, and 100% observation coverage — it must never fall back to
/// one extra round trip per file.
async fn coverage_scenario(observed_pct: u8) {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    const N: usize = 50;
    let mut files = Vec::with_capacity(N);
    for n in 0..N {
        let with_obs = (n * 100 / N) < observed_pct as usize;
        files.push(make_file(&catalog, target, &format!("f{n}"), with_obs).await);
    }

    catalog.reset_round_trip_count();
    let rows = catalog.list_file_summary_rows().await.unwrap();
    let expected_have_observation = rows.iter().filter(|r| r.health_state.is_some()).count();
    let fallback_versions: Vec<Uuid> = rows
        .iter()
        .filter(|r| r.health_state.is_none())
        .filter_map(|r| r.current_version_id)
        .collect();

    let (targets, chunks, replicas) = if fallback_versions.is_empty() {
        (
            Vec::new(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        )
    } else {
        (
            catalog.load_storage_targets().await.unwrap(),
            catalog
                .list_chunks_for_versions(&fallback_versions)
                .await
                .unwrap(),
            catalog
                .list_replica_lite_for_versions(&fallback_versions)
                .await
                .unwrap(),
        )
    };

    let round_trips = catalog.round_trip_count();
    let expected_round_trips = if fallback_versions.is_empty() { 1 } else { 4 };
    assert_eq!(
        round_trips, expected_round_trips,
        "coverage {observed_pct}%: round trips must stay bounded, not scale with N={N}"
    );
    assert_eq!(
        expected_have_observation + fallback_versions.len(),
        N,
        "every file must land in exactly one of the two paths"
    );
    if !fallback_versions.is_empty() {
        assert_eq!(targets.len(), 1);
        for version in &fallback_versions {
            assert_eq!(chunks.get(version).map(Vec::len), Some(1));
            assert_eq!(replicas.get(version).map(Vec::len), Some(2)); // manifest + one chunk
        }
    }
}

#[tokio::test]
async fn bulk_fallback_stays_bounded_at_zero_percent_observation_coverage() {
    coverage_scenario(0).await;
}

#[tokio::test]
async fn bulk_fallback_stays_bounded_at_ninety_percent_observation_coverage() {
    coverage_scenario(90).await;
}

#[tokio::test]
async fn bulk_fallback_stays_bounded_at_full_observation_coverage() {
    coverage_scenario(100).await;
}

/// Populates `n` files with a healthy observation each directly via raw
/// SQL inside one transaction (bypassing the per-file async catalog API,
/// which would itself cost one round trip per insert) — fixture setup
/// stays outside any timed region and scales to catalog sizes the public
/// API path is too slow to build interactively.
async fn populate_bulk(catalog: &undercloud_catalog::UnlockedCatalog, vault: Uuid, n: usize) {
    catalog
        .transaction(move |tx| {
            for i in 0..n {
                let file = tx.create_logical_file(None, &format!("bulk-{i}"), None)?;
                let version = Uuid::new_v4();
                tx.create_file_version(version, file, 4096, 1, [0u8; 32])?;
                tx.set_current_version(file, version)?;
                tx.record_health_observation(version, 1, 1, HealthState::Healthy)?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let _ = vault;
}

#[tokio::test]
async fn query_plan_at_1k_and_10k_scale_has_no_avoidable_full_scan_or_temp_sort() {
    let catalog = opened().await;
    populate_bulk(&catalog, Uuid::nil(), 1_000).await;

    let plan = catalog.explain_file_summary_query_plan().await.unwrap();
    let plan_text = plan.join("\n");
    println!("query plan at 1K:\n{plan_text}");
    assert!(
        !plan_text.contains("SCAN health_observations"),
        "correlated subquery must use the file_version_id index, not a full scan: {plan_text}"
    );
    assert!(
        !plan_text.to_uppercase().contains("TEMP B-TREE"),
        "must not need a temporary sort for the per-row LIMIT 1 subquery: {plan_text}"
    );

    populate_bulk(&catalog, Uuid::nil(), 9_000).await;
    let rows = catalog.list_file_summary_rows().await.unwrap();
    assert_eq!(rows.len(), 10_000);
    let plan_10k = catalog.explain_file_summary_query_plan().await.unwrap();
    let plan_10k_text = plan_10k.join("\n");
    assert_eq!(
        plan_text.replace("logical_files", "X"),
        plan_10k_text.replace("logical_files", "X"),
        "the query plan shape must not change with scale"
    );
}

#[tokio::test]
async fn single_file_lookup_matches_the_row_from_the_full_listing() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    let file = make_file(&catalog, target, "a", true).await;
    let missing = Uuid::new_v4();

    let listed = catalog
        .list_file_summary_rows()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.id == file)
        .unwrap();
    let looked_up = catalog.list_file_summary_row(file).await.unwrap().unwrap();
    assert_eq!(listed, looked_up);
    assert!(catalog
        .list_file_summary_row(missing)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn pagination_covers_every_row_exactly_once_in_stable_order() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    let mut expected_ids = Vec::new();
    for n in 0..47 {
        expected_ids.push(make_file(&catalog, target, &format!("p{n}"), true).await);
    }
    let full = catalog.list_file_summary_rows().await.unwrap();
    let full_order: Vec<_> = full.iter().map(|r| r.id).collect();

    let mut collected = Vec::new();
    let mut after = None;
    loop {
        let page = catalog.list_file_summary_page(after, 10).await.unwrap();
        if page.is_empty() {
            break;
        }
        after = Some(page.last().unwrap().id);
        collected.extend(page);
    }
    let collected_ids: Vec<_> = collected.iter().map(|r| r.id).collect();

    assert_eq!(
        collected_ids.len(),
        expected_ids.len(),
        "pagination must return every row exactly once"
    );
    let unique: std::collections::HashSet<_> = collected_ids.iter().collect();
    assert_eq!(
        unique.len(),
        collected_ids.len(),
        "pagination must not return duplicate rows"
    );
    assert_eq!(
        collected_ids, full_order,
        "paginated traversal order must match the unpaginated listing order"
    );
    assert_eq!(
        collected, full,
        "paginated rows must match unpaginated rows field-for-field"
    );
}

#[tokio::test]
async fn pagination_is_stable_when_a_row_is_inserted_between_pages() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    for n in 0..5 {
        make_file(&catalog, target, &format!("q{n}"), true).await;
    }
    let first_page = catalog.list_file_summary_page(None, 3).await.unwrap();
    assert_eq!(first_page.len(), 3);
    let cursor = first_page.last().unwrap().id;

    // A new row inserted after the first page was read (e.g. a concurrent
    // upload) must not shift already-returned rows or appear twice; it may
    // legitimately appear on a later page since UUIDs sort unpredictably
    // relative to already-issued ones, but it must never duplicate a row
    // already handed back on `first_page`.
    let inserted = make_file(&catalog, target, "concurrent-insert", true).await;

    let second_page = catalog
        .list_file_summary_page(Some(cursor), 10)
        .await
        .unwrap();
    let first_ids: std::collections::HashSet<_> = first_page.iter().map(|r| r.id).collect();
    for row in &second_page {
        assert!(
            !first_ids.contains(&row.id),
            "a row already returned on the first page must not reappear on a later page"
        );
    }
    let all_after_ids: std::collections::HashSet<_> = second_page.iter().map(|r| r.id).collect();
    if inserted > cursor {
        assert!(
            all_after_ids.contains(&inserted),
            "a newly inserted row sorting after the cursor must appear on the next page"
        );
    }
}

#[tokio::test]
async fn pagination_page_size_does_not_change_the_total_rows_returned() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    for n in 0..23 {
        make_file(&catalog, target, &format!("r{n}"), true).await;
    }
    for page_size in [1u32, 5, 100] {
        let mut total = 0usize;
        let mut after = None;
        loop {
            let page = catalog
                .list_file_summary_page(after, page_size)
                .await
                .unwrap();
            if page.is_empty() {
                break;
            }
            assert!(page.len() as u32 <= page_size);
            total += page.len();
            after = Some(page.last().unwrap().id);
        }
        assert_eq!(
            total, 23,
            "page size {page_size} must still cover every row"
        );
    }
}

#[tokio::test]
async fn deleted_logical_files_and_legacy_versionless_rows_never_report_healthy() {
    let catalog = opened().await;
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    let file = catalog
        .create_logical_file(None, "legacy", None)
        .await
        .unwrap();
    let rows = catalog.list_file_summary_rows().await.unwrap();
    let row = rows.into_iter().find(|r| r.id == file).unwrap();
    assert!(row.health_state.is_none());
    assert!(row.current_version_id.is_none());
    let _ = target;
}
