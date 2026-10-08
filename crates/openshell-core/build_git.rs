// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;

/// Existing version inputs, resolved by Git for ordinary and linked checkouts.
pub fn watch_paths(directory: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for name in ["HEAD", "refs", "packed-refs", "shallow"] {
        if let Some(path) = git_path(directory, &["rev-parse", "--git-path", name])
            && let Ok(path) = path.canonicalize()
        {
            paths.push(path);
        }
    }
    // A linked checkout can change its Git directory through this pointer.
    // Do not watch an ordinary .git directory recursively: it includes objects.
    if let Some(root) = git_path(directory, &["rev-parse", "--show-toplevel"]) {
        let marker = root.join(".git");
        if marker.is_file()
            && let Ok(marker) = marker.canonicalize()
        {
            paths.push(marker);
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn git_path(directory: &Path, args: &[&str]) -> Option<PathBuf> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(directory.join(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(directory: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn repository(directory: &Path) {
        std::fs::create_dir(directory).unwrap();
        git(directory, &["init", "-q"]);
        git(
            directory,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "commit.gpgSign=false",
                "commit",
                "--allow-empty",
                "-qm",
                "fixture",
            ],
        );
    }

    #[test]
    fn ordinary_repository_watches_existing_head_and_refs() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        repository(&repo);
        let paths = watch_paths(&repo);
        assert!(paths.contains(&repo.join(".git/HEAD").canonicalize().unwrap()));
        assert!(paths.contains(&repo.join(".git/refs").canonicalize().unwrap()));
        assert!(paths.iter().all(|p| p.exists()));
        assert!(!paths.contains(&repo.join(".git").canonicalize().unwrap()));
        let crate_dir = repo.join("crates/core");
        std::fs::create_dir_all(&crate_dir).unwrap();
        assert_eq!(watch_paths(&crate_dir), paths);
    }

    #[test]
    fn linked_checkout_watches_own_head_shared_refs_and_pointer() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        repository(&repo);
        let linked = temp.path().join("linked");
        git(
            &repo,
            &["worktree", "add", "-qb", "topic", linked.to_str().unwrap()],
        );
        let paths = watch_paths(&linked);
        let head = git_path(&linked, &["rev-parse", "--git-path", "HEAD"])
            .unwrap()
            .canonicalize()
            .unwrap();
        assert!(paths.contains(&head));
        assert!(!paths.contains(&repo.join(".git/HEAD").canonicalize().unwrap()));
        assert!(paths.contains(&repo.join(".git/refs").canonicalize().unwrap()));
        assert!(paths.contains(&linked.join(".git").canonicalize().unwrap()));
        assert!(paths.iter().all(|p| p.exists()));
    }

    #[test]
    fn packed_refs_are_watched_when_present() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        repository(&repo);
        git(&repo, &["-c", "tag.gpgSign=false", "tag", "v1.2.3"]);
        git(&repo, &["pack-refs", "--all", "--prune"]);
        assert!(
            watch_paths(&repo).contains(&repo.join(".git/packed-refs").canonicalize().unwrap())
        );
    }

    #[test]
    fn source_archive_does_not_watch_missing_git_files() {
        let temp = tempfile::tempdir().unwrap();
        assert!(watch_paths(temp.path()).is_empty());
    }
}
