use patchriot_protocol::websites::*;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

type Fingerprints<'a> = BTreeMap<(u8, String), (&'a WebsiteResource, ResourceFingerprint)>;

fn fingerprints(snapshot: &WebsiteSnapshot) -> Result<Fingerprints<'_>, &'static str> {
    let mut result = BTreeMap::new();
    for resource in std::iter::once(&snapshot.homepage).chain(&snapshot.resources) {
        let kind = match resource.kind {
            ResourceKind::Homepage => 0,
            ResourceKind::ExternalScript => 1,
            ResourceKind::InlineScript => 2,
        };
        let fingerprint = ResourceFingerprint {
            sha256: resource.sha256.clone(),
            bytes: resource.bytes,
            content_type: resource.content_type.clone(),
            headers: resource.headers.clone(),
        };
        if result
            .insert((kind, resource.url.clone()), (resource, fingerprint))
            .is_some()
        {
            return Err("ambiguous_snapshot_resources");
        }
    }
    Ok(result)
}

fn coverage(snapshot: &WebsiteSnapshot) -> ComparisonCoverage {
    let count = |status| {
        snapshot
            .scripts
            .iter()
            .filter(|s| s.status == status)
            .count() as u16
    };
    ComparisonCoverage {
        captured_scripts: count(ScriptStatus::Collected),
        skipped_scripts: count(ScriptStatus::Skipped),
        data_only_scripts: count(ScriptStatus::DataOnly),
        script_limit_reached: snapshot.script_limit_reached,
    }
}

pub(super) fn compare(
    baseline_id: Uuid,
    current_id: Uuid,
    before: &WebsiteSnapshot,
    after: &WebsiteSnapshot,
) -> Result<WebsiteComparison, &'static str> {
    if before.schema_version != 1
        || after.schema_version != 1
        || [before, after]
            .iter()
            .any(|s| s.scripts.len() > 40 || s.resources.len() > 40)
    {
        return Err("unsupported_snapshot_format");
    }
    if before.scope != after.scope {
        return Err("comparison_scope_mismatch");
    }
    if before.finished_at > after.started_at {
        return Err("baseline_must_be_earlier");
    }
    let earlier = fingerprints(before)?;
    let later = fingerprints(after)?;
    let keys: BTreeSet<_> = earlier.keys().chain(later.keys()).collect();
    let resources = keys
        .into_iter()
        .map(|key| {
            let first = earlier.get(key);
            let second = later.get(key);
            let change = match (first, second) {
                (Some((_, a)), Some((_, b))) if a == b => ResourceChange::Unchanged,
                (Some(_), Some(_)) => ResourceChange::Changed,
                (Some(_), None) => ResourceChange::OnlyEarlier,
                (None, _) => ResourceChange::OnlyLater,
            };
            let resource = first.or(second).expect("key came from a saved resource").0;
            ResourceComparison {
                kind: resource.kind,
                url: resource.url.clone(),
                change,
                before: first.map(|(_, fingerprint)| fingerprint.clone()),
                after: second.map(|(_, fingerprint)| fingerprint.clone()),
            }
        })
        .collect();
    Ok(WebsiteComparison {
        baseline_id,
        current_id,
        baseline_finished_at: before.finished_at,
        current_finished_at: after.finished_at,
        resources,
        script_references_changed: before.scripts != after.scripts,
        baseline_coverage: coverage(before),
        current_coverage: coverage(after),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot(start: i64) -> WebsiteSnapshot {
        serde_json::from_value(json!({
            "schema_version":1,"scope":{"homepage":"https://example.com/","script_origins":[]},
            "homepage":{"kind":"homepage","url":"https://example.com/","sha256":"1".repeat(64),"bytes":8,"content_type":"text/html","headers":{},"text":"private!","collected_at":start,"connected_ip":"93.184.215.14"},
            "resources":[],"scripts":[],"script_limit_reached":false,"requests_made":1,"captured_response_bytes":8,"started_at":start,"finished_at":start+1
        })).unwrap()
    }

    fn diff(before: &WebsiteSnapshot, after: &WebsiteSnapshot) -> WebsiteComparison {
        compare(Uuid::new_v4(), Uuid::new_v4(), before, after).unwrap()
    }

    #[test]
    fn changes_ignore_capture_time_and_cdn_address_but_include_headers_and_bytes() {
        let before = snapshot(1);
        let mut after = snapshot(3);
        after.homepage.connected_ip = Some("93.184.215.15".into());
        assert_eq!(
            diff(&before, &after).resources[0].change,
            ResourceChange::Unchanged
        );
        after.homepage.headers.insert(
            "content-security-policy".into(),
            "default-src 'self'".into(),
        );
        assert_eq!(
            diff(&before, &after).resources[0].change,
            ResourceChange::Changed
        );
        after.homepage.headers.clear();
        after.homepage.sha256 = "2".repeat(64);
        let result = diff(&before, &after);
        assert_eq!(result.resources[0].change, ResourceChange::Changed);
        let encoded = serde_json::to_string(&result).unwrap();
        assert!(!encoded.contains("private!"));
        assert!(!encoded.contains("93.184.215"));
    }

    #[test]
    fn missing_capture_remains_distinct_from_removal_and_coverage_changes_survive() {
        let mut before = snapshot(1);
        let mut after = snapshot(3);
        let mut script = before.homepage.clone();
        script.kind = ResourceKind::ExternalScript;
        script.url = "https://example.com/app.js".into();
        before.resources.push(script);
        before.scripts.push(ScriptReference {
            index: 0,
            src: Some("https://example.com/app.js".into()),
            integrity: None,
            type_hint: None,
            status: ScriptStatus::Collected,
            artifact_sha256: Some("1".repeat(64)),
            reason: None,
        });
        after.scripts = before.scripts.clone();
        after.resources = before.resources.clone();
        after.scripts[0].integrity = Some("sha384-owned-test".into());
        let attributes = diff(&before, &after);
        assert!(attributes.script_references_changed);
        assert!(
            attributes
                .resources
                .iter()
                .all(|r| r.change == ResourceChange::Unchanged)
        );
        after.resources.clear();
        after.scripts[0].status = ScriptStatus::Skipped;
        after.scripts[0].reason = Some("request_failed".into());
        after.scripts[0].artifact_sha256 = None;
        after.script_limit_reached = true;
        let result = diff(&before, &after);
        assert_eq!(result.resources[1].change, ResourceChange::OnlyEarlier);
        assert_eq!(result.current_coverage.skipped_scripts, 1);
        assert!(result.current_coverage.script_limit_reached);
        assert!(result.script_references_changed);
    }

    #[test]
    fn inline_positions_are_compared_without_silently_matching_by_hash() {
        let mut before = snapshot(1);
        let mut after = snapshot(3);
        for (position, hash) in ["a", "b"].iter().enumerate() {
            let mut script = before.homepage.clone();
            script.kind = ResourceKind::InlineScript;
            script.url = format!("https://example.com/#patchriot-script-{position}");
            script.sha256 = hash.repeat(64);
            before.resources.push(script.clone());
            script.sha256 = if position == 0 { "b" } else { "a" }.repeat(64);
            after.resources.push(script);
        }
        assert!(
            diff(&before, &after).resources[1..]
                .iter()
                .all(|r| r.change == ResourceChange::Changed)
        );
        after
            .scope
            .script_origins
            .push("https://cdn.example.com".into());
        assert_eq!(
            compare(Uuid::new_v4(), Uuid::new_v4(), &before, &after).unwrap_err(),
            "comparison_scope_mismatch"
        );
        after.scope = before.scope.clone();
        after.started_at = before.started_at;
        assert_eq!(
            compare(Uuid::new_v4(), Uuid::new_v4(), &before, &after).unwrap_err(),
            "baseline_must_be_earlier"
        );
        after.started_at = 3;
        after.resources.push(after.resources[0].clone());
        assert_eq!(
            compare(Uuid::new_v4(), Uuid::new_v4(), &before, &after).unwrap_err(),
            "ambiguous_snapshot_resources"
        );
    }
}
