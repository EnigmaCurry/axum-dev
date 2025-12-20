pub async fn validate_private_dir_0700(dir: &std::path::Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use anyhow::{Context, bail};
        use std::os::unix::fs::PermissionsExt;

        let meta = tokio::fs::symlink_metadata(dir)
            .await
            .with_context(|| format!("failed to stat dir '{}'", dir.display()))?;

        if meta.file_type().is_symlink() {
            bail!(
                "refusing to use symlink as TLS cache dir '{}'",
                dir.display()
            );
        }
        if !meta.file_type().is_dir() {
            bail!("TLS cache dir '{}' is not a directory", dir.display());
        }

        let mode = meta.permissions().mode() & 0o777;

        // Require *exactly* 0700 (no group/other perms at all).
        // This is the safest policy to prevent other users from swapping files.
        if mode != 0o700 {
            bail!(
                "insecure permissions on TLS cache dir '{}': mode {:o}; expected 700 (chmod 700 '{}')",
                dir.display(),
                mode,
                dir.display(),
            );
        }
    }

    #[cfg(not(unix))]
    {
        let _ = dir;
    }

    Ok(())
}

pub async fn atomic_write_file_0600(path: &std::path::Path, contents: &[u8]) -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use tokio::io::AsyncWriteExt;

    #[cfg(unix)]
    {
        let parent = path.parent().context("path must have a parent directory")?;

        let mut tmp = parent.join(format!(
            ".{}.tmp",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("tls")
        ));

        if tmp.exists() {
            tmp = parent.join(format!(
                ".{}.tmp.{}",
                path.file_name().and_then(|s| s.to_str()).unwrap_or("tls"),
                std::process::id()
            ));
        }

        let mut f = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .await
            .with_context(|| format!("failed to create temp file '{}'", tmp.display()))?;

        f.write_all(contents).await?;
        f.flush().await?;
        f.sync_all().await?;

        if let Ok(meta) = tokio::fs::symlink_metadata(path).await {
            if meta.file_type().is_symlink() {
                let _ = tokio::fs::remove_file(&tmp).await;
                bail!("refusing to overwrite symlink '{}'", path.display());
            }
        }

        tokio::fs::rename(&tmp, path).await.with_context(|| {
            format!(
                "failed to rename '{}' -> '{}'",
                tmp.display(),
                path.display()
            )
        })?;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        tokio::fs::write(path, contents)
            .await
            .with_context(|| format!("failed to write '{}'", path.display()))?;
        Ok(())
    }
}
