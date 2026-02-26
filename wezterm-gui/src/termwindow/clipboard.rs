use crate::termwindow::TermWindowNotif;
use crate::TermWindow;
use anyhow::Context;
use config::keyassignment::{ClipboardCopyDestination, ClipboardPasteSource};
use mux::pane::{CachePolicy, Pane, PaneId};
use mux::ssh::RemoteSshDomain;
use mux::Mux;
use std::sync::Arc;
use window::{Clipboard, WindowOps};
use wezterm_toast_notification::persistent_toast_notification;

impl TermWindow {
    pub fn copy_to_clipboard(&self, clipboard: ClipboardCopyDestination, text: String) {
        let clipboard = match clipboard {
            ClipboardCopyDestination::Clipboard => [Some(Clipboard::Clipboard), None],
            ClipboardCopyDestination::PrimarySelection => [Some(Clipboard::PrimarySelection), None],
            ClipboardCopyDestination::ClipboardAndPrimarySelection => [
                Some(Clipboard::Clipboard),
                Some(Clipboard::PrimarySelection),
            ],
        };
        for &c in &clipboard {
            if let Some(c) = c {
                self.window.as_ref().unwrap().set_clipboard(c, text.clone());
            }
        }
    }

    pub fn paste_from_clipboard(&mut self, pane: &Arc<dyn Pane>, clipboard: ClipboardPasteSource) {
        let pane_id = pane.pane_id();
        log::trace!(
            "paste_from_clipboard in pane {} {:?}",
            pane.pane_id(),
            clipboard
        );
        let window = self.window.as_ref().unwrap().clone();
        let clipboard = match clipboard {
            ClipboardPasteSource::Clipboard => Clipboard::Clipboard,
            ClipboardPasteSource::PrimarySelection => Clipboard::PrimarySelection,
        };
        let future = window.get_clipboard(clipboard);
        promise::spawn::spawn(async move {
            if let Ok(clip) = future.await {
                window.notify(TermWindowNotif::Apply(Box::new(move |myself| {
                    if let Some(pane) = myself
                        .pane_state(pane_id)
                        .overlay
                        .as_ref()
                        .map(|overlay| overlay.pane.clone())
                        .or_else(|| {
                            let mux = Mux::get();
                            mux.get_pane(pane_id)
                        })
                    {
                        pane.send_paste(&clip).ok();
                    }
                })));
            }
        })
        .detach();
        self.maybe_scroll_to_bottom_for_input(&pane);
    }

    pub fn paste_image_to_ssh_upload(&mut self, pane: &Arc<dyn Pane>) {
        let config = config::configuration();
        if !config.ssh_image_paste_enabled {
            log::debug!("paste_image_to_ssh_upload: disabled by config");
            return;
        }

        let pane_id = pane.pane_id();
        let domain_id = pane.domain_id();
        log::info!(
            "paste_image_to_ssh_upload: pane_id={}, domain_id={}",
            pane_id,
            domain_id
        );

        // Detect SSH target from foreground process before entering async context
        let ssh_target = detect_ssh_target_from_pane(pane);
        log::info!(
            "paste_image_to_ssh_upload: detected ssh_target={:?}",
            ssh_target
        );

        let window = self.window.as_ref().unwrap().clone();
        let future = window.get_clipboard_image_data();

        promise::spawn::spawn(async move {
            if let Err(err) =
                paste_image_to_ssh_inner(future, pane_id, domain_id, ssh_target).await
            {
                log::error!("paste_image_to_ssh: {:#}", err);
                persistent_toast_notification("Image Paste Failed", &format!("{:#}", err));
            }
        })
        .detach();

        self.maybe_scroll_to_bottom_for_input(&pane);
    }
}

/// Parsed SSH connection target detected from a running ssh process.
#[derive(Debug, Clone)]
struct SshTarget {
    /// The destination in "user@host" or "host" format
    user_host: String,
    /// Optional port from -p flag
    port: Option<u16>,
    /// Identity files from -i flags (forwarded to scp)
    identity_files: Vec<String>,
    /// Config file from -F flag (forwarded to scp)
    config_file: Option<String>,
    /// Extra -o options (forwarded to scp)
    extra_options: Vec<String>,
}

/// Detect SSH target by inspecting the foreground process in the pane.
fn detect_ssh_target_from_pane(pane: &Arc<dyn Pane>) -> Option<SshTarget> {
    let proc_info = pane.get_foreground_process_info(CachePolicy::FetchImmediate)?;
    log::info!(
        "detect_ssh_target: foreground process name='{}', pid={}, argv={:?}",
        proc_info.name,
        proc_info.pid,
        proc_info.argv
    );
    find_ssh_target_in_process_tree(&proc_info)
}

/// Recursively search process tree for an ssh process and extract the target.
fn find_ssh_target_in_process_tree(info: &procinfo::LocalProcessInfo) -> Option<SshTarget> {
    let name_lower = info.name.to_lowercase();
    if name_lower == "ssh" || name_lower == "ssh.exe" {
        if let Some(target) = parse_ssh_target_from_argv(&info.argv) {
            log::info!(
                "find_ssh_target: found ssh process pid={}, target={:?}",
                info.pid,
                target
            );
            return Some(target);
        }
    }
    for child in info.children.values() {
        if let Some(target) = find_ssh_target_in_process_tree(child) {
            return Some(target);
        }
    }
    None
}

/// Parse SSH command-line arguments to extract the destination, port,
/// and authentication-related options to forward to scp.
fn parse_ssh_target_from_argv(argv: &[String]) -> Option<SshTarget> {
    // SSH options that consume the next argument as their value
    const OPTS_WITH_ARG: &[&str] = &[
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
        "-L", "-l", "-m", "-O", "-o", "-Q", "-R", "-S", "-W", "-w",
    ];

    let mut port: Option<u16> = None;
    let mut identity_files: Vec<String> = Vec::new();
    let mut config_file: Option<String> = None;
    let mut extra_options: Vec<String> = Vec::new();
    let mut i = 1; // skip argv[0] ("ssh" / "ssh.exe")

    while i < argv.len() {
        let arg = &argv[i];
        if arg == "-p" {
            i += 1;
            if i < argv.len() {
                port = argv[i].parse().ok();
            }
        } else if arg == "-i" {
            i += 1;
            if i < argv.len() {
                identity_files.push(argv[i].clone());
            }
        } else if arg == "-F" {
            i += 1;
            if i < argv.len() {
                config_file = Some(argv[i].clone());
            }
        } else if arg == "-o" {
            i += 1;
            if i < argv.len() {
                extra_options.push(argv[i].clone());
            }
        } else if OPTS_WITH_ARG.iter().any(|opt| arg == *opt) {
            i += 1; // skip the option's argument
        } else if arg.starts_with('-') {
            // standalone flags like -v, -N, -T, etc.
        } else {
            // first non-option argument is the destination
            return Some(SshTarget {
                user_host: arg.clone(),
                port,
                identity_files,
                config_file,
                extra_options,
            });
        }
        i += 1;
    }
    None
}

/// Upload PNG data to the remote host via scp subprocess.
fn upload_via_scp(
    target: &SshTarget,
    png_data: &[u8],
    remote_path: &str,
) -> anyhow::Result<()> {
    // Save to local temp file
    let temp_dir = std::env::temp_dir();
    let local_filename = format!(
        "wezterm-paste-{}-{}.png",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );
    let local_path = temp_dir.join(&local_filename);

    log::info!(
        "upload_via_scp: writing {} bytes to temp file '{}'",
        png_data.len(),
        local_path.display()
    );
    std::fs::write(&local_path, png_data).context("Failed to write temp PNG file")?;

    let remote_dest = format!("{}:{}", target.user_host, remote_path);
    let mut cmd = std::process::Command::new("scp");
    cmd.arg("-q"); // quiet mode
    // BatchMode prevents interactive password/passphrase prompts (GUI dialogs on Windows)
    cmd.arg("-o").arg("BatchMode=yes");
    // Prevent stdin-based prompting and suppress console window on Windows
    cmd.stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    if let Some(port) = target.port {
        cmd.arg("-P").arg(port.to_string());
    }
    // Forward SSH authentication options from the running ssh process
    for identity in &target.identity_files {
        cmd.arg("-i").arg(identity);
    }
    if let Some(config) = &target.config_file {
        cmd.arg("-F").arg(config);
    }
    for opt in &target.extra_options {
        cmd.arg("-o").arg(opt);
    }
    cmd.arg(local_path.to_str().unwrap_or_default())
        .arg(&remote_dest);

    log::info!("upload_via_scp: running: {:?}", cmd);
    let output = cmd.output().context("Failed to run scp command. Is scp installed?")?;

    // Always clean up the temp file
    let _ = std::fs::remove_file(&local_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "scp failed (exit {}): {}\n\n\
             SCP opens a NEW SSH connection that requires key-based auth.\n\
             Set up SSH keys (one-time):\n\
             \n  \
             1. Generate key:  ssh-keygen -t ed25519\n  \
             2. Copy to remote: ssh-copy-id {}\n  \
             3. Verify: ssh {}  (should not ask for password)\n\
             \n\
             On Windows, also ensure ssh-agent is running:\n  \
             Get-Service ssh-agent | Set-Service -StartupType Automatic\n  \
             Start-Service ssh-agent\n  \
             ssh-add",
            output.status,
            stderr.trim(),
            target.user_host,
            target.user_host,
        );
    }

    log::info!("upload_via_scp: success");
    Ok(())
}

async fn paste_image_to_ssh_inner(
    future: promise::Future<Vec<u8>>,
    pane_id: PaneId,
    domain_id: mux::domain::DomainId,
    ssh_target: Option<SshTarget>,
) -> anyhow::Result<()> {
    log::info!(
        "paste_image_to_ssh_inner: starting, pane_id={}, domain_id={}, ssh_target={:?}",
        pane_id,
        domain_id,
        ssh_target
    );

    log::info!("paste_image_to_ssh_inner: reading clipboard image data...");
    let dib_data = future.await.context("Failed to read clipboard image")?;
    log::info!(
        "paste_image_to_ssh_inner: got {} bytes of DIB data from clipboard",
        dib_data.len()
    );

    log::info!("paste_image_to_ssh_inner: converting DIB to PNG...");
    let png_data = convert_dib_to_png(&dib_data).context("Failed to convert image to PNG")?;
    log::info!(
        "paste_image_to_ssh_inner: converted to {} bytes of PNG data",
        png_data.len()
    );

    let config = config::configuration();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let remote_path = config
        .ssh_image_paste_remote_path
        .replace("{timestamp}", &timestamp.to_string());

    // Try RemoteSshDomain SFTP first, then fall back to SCP via detected SSH process
    let mux = Mux::get();
    let domain = mux
        .get_domain(domain_id)
        .ok_or_else(|| anyhow::anyhow!("Domain not found for domain_id={}", domain_id))?;

    let domain_name = domain.domain_name().to_string();
    log::info!("paste_image_to_ssh_inner: domain_name='{}'", domain_name);

    if let Some(ssh_domain) = domain.downcast_ref::<RemoteSshDomain>() {
        // Path 1: Direct SSH domain with SFTP
        log::info!("paste_image_to_ssh_inner: using SFTP via RemoteSshDomain");
        let sftp = ssh_domain
            .sftp()
            .ok_or_else(|| anyhow::anyhow!("SSH session not connected (no active session)"))?;

        log::info!(
            "paste_image_to_ssh_inner: SFTP uploading {} bytes to '{}'",
            png_data.len(),
            remote_path
        );

        use wezterm_ssh::{OpenFileType, OpenOptions, WriteMode};
        let mut file = sftp
            .open_with_mode(
                &remote_path,
                OpenOptions {
                    read: false,
                    write: Some(WriteMode::Append),
                    mode: 0o644,
                    ty: OpenFileType::File,
                },
            )
            .await
            .map_err(|e| anyhow::anyhow!("SFTP open '{}' failed: {}", remote_path, e))?;

        use smol::io::AsyncWriteExt;
        file.write_all(&png_data)
            .await
            .context("SFTP write failed")?;
        file.close().await.context("SFTP close failed")?;
    } else if let Some(target) = ssh_target {
        // Path 2: Local pane with ssh process detected — use scp
        log::info!(
            "paste_image_to_ssh_inner: using SCP to {}",
            target.user_host
        );

        let png_clone = png_data.clone();
        let path_clone = remote_path.clone();
        let target_clone = target.clone();
        smol::unblock(move || upload_via_scp(&target_clone, &png_clone, &path_clone))
            .await
            .context("SCP upload failed")?;
    } else {
        anyhow::bail!(
            "Cannot upload image: domain '{}' is not a direct SSH session, \
             and no ssh process was detected in the current pane. \
             Please ensure you have an active SSH connection in this pane.",
            domain_name
        );
    }

    // Display the image inline using iTerm2 protocol before pasting the path
    display_image_inline(pane_id, &png_data);

    // Paste the remote path into the terminal
    let pane = mux
        .get_pane(pane_id)
        .ok_or_else(|| anyhow::anyhow!("Pane not found for pane_id={}", pane_id))?;

    pane.send_paste(&remote_path)
        .context("Failed to paste path into terminal")?;

    log::info!(
        "paste_image_to_ssh_inner: successfully uploaded clipboard image to '{}'",
        remote_path
    );

    Ok(())
}

/// Display an image as a small inline thumbnail using the iTerm2 protocol.
/// Dynamically computes cell dimensions from the image aspect ratio so the
/// thumbnail is compact and does not clutter the terminal.
fn display_image_inline(pane_id: PaneId, png_data: &[u8]) {
    use mux::MuxNotification;
    use termwiz::escape::osc::{ITermDimension, ITermFileData, ITermProprietary};
    use termwiz::escape::{Action, OperatingSystemCommand};

    let (img_w, img_h) = parse_png_dimensions(png_data).unwrap_or((800, 600));
    let (thumb_w, thumb_h) = compute_thumbnail_cells(img_w, img_h);
    log::info!(
        "display_image_inline: image {}x{} -> thumbnail {}x{} cells",
        img_w, img_h, thumb_w, thumb_h
    );

    let file_data = ITermFileData {
        name: None,
        size: Some(png_data.len()),
        width: ITermDimension::Cells(thumb_w),
        height: ITermDimension::Cells(thumb_h),
        preserve_aspect_ratio: true,
        inline: true,
        do_not_move_cursor: false,
        data: png_data.to_vec(),
    };

    let image_action = Action::OperatingSystemCommand(Box::new(
        OperatingSystemCommand::ITermProprietary(ITermProprietary::File(Box::new(file_data))),
    ));

    let mux = Mux::get();
    if let Some(pane) = mux.get_pane(pane_id) {
        // Inject image followed by a newline so the cursor lands on a clean
        // line below the thumbnail — this prevents the user from "losing"
        // the cursor inside or behind the image.
        let mut actions = vec![image_action];
        let mut parser = termwiz::escape::parser::Parser::new();
        parser.parse(b"\r\n", |action| actions.push(action));
        pane.perform_actions(actions);

        // Notify the mux so the GUI refreshes and scrolls to show the cursor.
        mux.notify(MuxNotification::PaneOutput(pane_id));
        log::info!(
            "display_image_inline: injected iTerm2 inline image for pane {}",
            pane_id
        );
    }
}

/// Parse the IHDR chunk of a PNG to extract (width, height).
fn parse_png_dimensions(data: &[u8]) -> Option<(u32, u32)> {
    // PNG layout: 8‑byte signature, then IHDR chunk:
    //   4 bytes length + 4 bytes "IHDR" + 4 bytes width + 4 bytes height …
    if data.len() < 24 {
        return None;
    }
    if &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }
    let w = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    let h = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
    Some((w, h))
}

/// Compute a compact thumbnail size in terminal cells.
///
/// Terminal cells are roughly 2× taller than wide (e.g. 8×16 px), so we
/// account for that when converting the image aspect ratio into cell counts.
fn compute_thumbnail_cells(img_w: u32, img_h: u32) -> (i64, i64) {
    const MAX_H: i64 = 6;
    const MAX_W: i64 = 40;
    const CELL_ASPECT: f64 = 2.0; // cell_height_px / cell_width_px

    let aspect = img_w as f64 / img_h.max(1) as f64;

    // Width (in cells) needed when height = MAX_H:
    //   w_cells = h_cells × CELL_ASPECT × (img_w / img_h)
    let w_at_max_h = (MAX_H as f64 * CELL_ASPECT * aspect).round() as i64;

    if w_at_max_h <= MAX_W {
        // Height‑constrained — fits within MAX_W
        (w_at_max_h.max(4), MAX_H)
    } else {
        // Width‑constrained — recalculate height
        let h = (MAX_W as f64 / (CELL_ASPECT * aspect)).round() as i64;
        (MAX_W, h.clamp(2, MAX_H))
    }
}

fn convert_dib_to_png(dib_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // DIB data from clipboard is a BITMAPINFOHEADER followed by pixel data.
    // To make it a valid BMP file, we prepend a 14-byte BITMAPFILEHEADER.
    let file_header_size: u32 = 14;
    let total_size = file_header_size as usize + dib_data.len();

    let mut bmp = Vec::with_capacity(total_size);

    // BITMAPFILEHEADER (14 bytes):
    // bfType: 'BM' signature
    bmp.extend_from_slice(b"BM");
    // bfSize: total file size
    bmp.extend_from_slice(&(total_size as u32).to_le_bytes());
    // bfReserved1 + bfReserved2
    bmp.extend_from_slice(&0u32.to_le_bytes());
    // bfOffBits: offset to pixel data
    // = 14 (file header) + biSize (from DIB header, first 4 bytes)
    // + color table size (computed from DIB header)
    let bi_size = if dib_data.len() >= 4 {
        u32::from_le_bytes([dib_data[0], dib_data[1], dib_data[2], dib_data[3]])
    } else {
        anyhow::bail!("DIB data too short");
    };

    // Compute color table size for <=8bpp images
    // BITMAPINFOHEADER: biBitCount at offset 14, biClrUsed at offset 32
    let color_table_size = if dib_data.len() >= 36 {
        let bit_count =
            u16::from_le_bytes([dib_data[14], dib_data[15]]);
        let clr_used = u32::from_le_bytes([
            dib_data[32],
            dib_data[33],
            dib_data[34],
            dib_data[35],
        ]);
        if bit_count <= 8 {
            let num_colors = if clr_used > 0 {
                clr_used
            } else {
                1u32 << bit_count
            };
            num_colors * 4 // each RGBQUAD is 4 bytes
        } else {
            0
        }
    } else {
        0
    };

    let offset_to_pixels = file_header_size + bi_size + color_table_size;
    bmp.extend_from_slice(&offset_to_pixels.to_le_bytes());

    // Append the DIB data (header + pixels)
    bmp.extend_from_slice(dib_data);

    // Decode BMP using the image crate
    let img = image::load_from_memory_with_format(&bmp, image::ImageFormat::Bmp)
        .context("Failed to decode BMP image")?;

    // Encode as PNG
    let mut png_buf = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png_buf);
    img.write_with_encoder(encoder)
        .context("Failed to encode PNG")?;

    Ok(png_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ssh_simple_user_host() {
        let argv = vec!["ssh".into(), "user@host".into()];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "user@host");
        assert_eq!(target.port, None);
    }

    #[test]
    fn test_parse_ssh_host_only() {
        let argv = vec!["ssh".into(), "myserver".into()];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "myserver");
        assert_eq!(target.port, None);
    }

    #[test]
    fn test_parse_ssh_with_port() {
        let argv = vec!["ssh".into(), "-p".into(), "2222".into(), "user@host".into()];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "user@host");
        assert_eq!(target.port, Some(2222));
    }

    #[test]
    fn test_parse_ssh_with_identity_and_verbose() {
        let argv = vec![
            "ssh.exe".into(),
            "-v".into(),
            "-i".into(),
            "~/.ssh/id_rsa".into(),
            "admin@10.0.0.1".into(),
        ];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "admin@10.0.0.1");
        assert_eq!(target.port, None);
    }

    #[test]
    fn test_parse_ssh_with_many_options() {
        let argv = vec![
            "ssh".into(),
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "-L".into(),
            "8080:localhost:80".into(),
            "-p".into(),
            "22".into(),
            "-N".into(),
            "deploy@prod.example.com".into(),
        ];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "deploy@prod.example.com");
        assert_eq!(target.port, Some(22));
    }

    #[test]
    fn test_parse_ssh_no_destination() {
        let argv = vec!["ssh".into(), "-v".into()];
        assert!(parse_ssh_target_from_argv(&argv).is_none());
    }

    #[test]
    fn test_parse_ssh_empty_argv() {
        let argv: Vec<String> = vec!["ssh".into()];
        assert!(parse_ssh_target_from_argv(&argv).is_none());
    }

    #[test]
    fn test_parse_ssh_with_identity_file() {
        let argv = vec![
            "ssh".into(),
            "-i".into(),
            "/home/user/.ssh/my_key".into(),
            "user@host".into(),
        ];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "user@host");
        assert_eq!(target.identity_files, vec!["/home/user/.ssh/my_key"]);
        assert_eq!(target.config_file, None);
        assert!(target.extra_options.is_empty());
    }

    #[test]
    fn test_parse_ssh_with_config_and_options() {
        let argv = vec![
            "ssh".into(),
            "-F".into(),
            "/etc/ssh/custom_config".into(),
            "-o".into(),
            "StrictHostKeyChecking=no".into(),
            "-o".into(),
            "UserKnownHostsFile=/dev/null".into(),
            "-i".into(),
            "~/.ssh/id_ed25519".into(),
            "-p".into(),
            "2222".into(),
            "deploy@prod.example.com".into(),
        ];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "deploy@prod.example.com");
        assert_eq!(target.port, Some(2222));
        assert_eq!(target.identity_files, vec!["~/.ssh/id_ed25519"]);
        assert_eq!(target.config_file, Some("/etc/ssh/custom_config".into()));
        assert_eq!(
            target.extra_options,
            vec!["StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null"]
        );
    }

    #[test]
    fn test_parse_ssh_multiple_identity_files() {
        let argv = vec![
            "ssh".into(),
            "-i".into(),
            "key1".into(),
            "-i".into(),
            "key2".into(),
            "host".into(),
        ];
        let target = parse_ssh_target_from_argv(&argv).unwrap();
        assert_eq!(target.user_host, "host");
        assert_eq!(target.identity_files, vec!["key1", "key2"]);
    }

    // --- PNG dimension parsing tests ---

    fn make_minimal_png_header(width: u32, height: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n"); // signature
        data.extend_from_slice(&13u32.to_be_bytes()); // IHDR data length
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[8, 2, 0, 0, 0]); // depth, color, etc.
        data
    }

    #[test]
    fn test_parse_png_dimensions_valid() {
        let data = make_minimal_png_header(1920, 1080);
        assert_eq!(parse_png_dimensions(&data), Some((1920, 1080)));
    }

    #[test]
    fn test_parse_png_dimensions_too_short() {
        assert_eq!(parse_png_dimensions(&[0; 10]), None);
    }

    #[test]
    fn test_parse_png_dimensions_bad_signature() {
        assert_eq!(parse_png_dimensions(&[0u8; 24]), None);
    }

    // --- Thumbnail cell computation tests ---

    #[test]
    fn test_thumbnail_landscape_16_9() {
        let (w, h) = compute_thumbnail_cells(1920, 1080);
        assert_eq!(h, 6);
        // 6 * 2 * (1920/1080) ≈ 21
        assert!(w >= 20 && w <= 22, "w={}", w);
    }

    #[test]
    fn test_thumbnail_square() {
        let (w, h) = compute_thumbnail_cells(800, 800);
        assert_eq!(h, 6);
        // 6 * 2 * 1 = 12
        assert_eq!(w, 12);
    }

    #[test]
    fn test_thumbnail_portrait() {
        let (w, h) = compute_thumbnail_cells(1080, 1920);
        assert_eq!(h, 6);
        // 6 * 2 * (1080/1920) ≈ 6.75 → 7, but clamped min 4
        assert!(w >= 4 && w <= 8, "w={}", w);
    }

    #[test]
    fn test_thumbnail_very_wide() {
        // Panorama — should be width-constrained
        let (w, h) = compute_thumbnail_cells(10000, 500);
        assert_eq!(w, 40);
        assert!(h >= 2 && h <= 6, "h={}", h);
    }

    #[test]
    fn test_thumbnail_very_tall() {
        // Very tall image — height-constrained, narrow width clamped to min 4
        let (w, h) = compute_thumbnail_cells(200, 4000);
        assert_eq!(h, 6);
        assert_eq!(w, 4); // clamped minimum
    }

    /// Build a minimal 32-bit BITMAPINFOHEADER (40 bytes) + pixel data for a
    /// 2x2 BGRA image. This simulates what Windows puts on the clipboard as
    /// CF_DIB.
    fn make_test_dib_32bpp(width: i32, height: i32, pixels: &[u8]) -> Vec<u8> {
        let mut dib = Vec::new();
        // BITMAPINFOHEADER (40 bytes)
        dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
        dib.extend_from_slice(&width.to_le_bytes()); // biWidth
        dib.extend_from_slice(&height.to_le_bytes()); // biHeight
        dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
        dib.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
        dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
        dib.extend_from_slice(&(pixels.len() as u32).to_le_bytes()); // biSizeImage
        dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
        dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
        assert_eq!(dib.len(), 40);
        // Pixel data
        dib.extend_from_slice(pixels);
        dib
    }

    /// Build a minimal 24-bit BITMAPINFOHEADER + pixel data.
    fn make_test_dib_24bpp(width: i32, height: i32, pixels: &[u8]) -> Vec<u8> {
        let mut dib = Vec::new();
        dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
        dib.extend_from_slice(&width.to_le_bytes()); // biWidth
        dib.extend_from_slice(&height.to_le_bytes()); // biHeight
        dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
        dib.extend_from_slice(&24u16.to_le_bytes()); // biBitCount
        dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression
        dib.extend_from_slice(&(pixels.len() as u32).to_le_bytes()); // biSizeImage
        dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
        dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
        dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant
        dib.extend_from_slice(pixels);
        dib
    }

    #[test]
    fn test_convert_dib_to_png_32bpp_2x2() {
        // 2x2 image, 32bpp BGRA, bottom-up (default BMP row order)
        // Row 0 (bottom): red, green
        // Row 1 (top): blue, white
        let pixels: Vec<u8> = vec![
            0x00, 0x00, 0xFF, 0xFF, // red (BGRA)
            0x00, 0xFF, 0x00, 0xFF, // green
            0xFF, 0x00, 0x00, 0xFF, // blue
            0xFF, 0xFF, 0xFF, 0xFF, // white
        ];
        let dib = make_test_dib_32bpp(2, 2, &pixels);
        let png_data = convert_dib_to_png(&dib).expect("should convert successfully");

        // Verify PNG signature
        assert!(png_data.len() > 8);
        assert_eq!(&png_data[..8], b"\x89PNG\r\n\x1a\n");

        // Decode the PNG back and verify dimensions
        let img = image::load_from_memory_with_format(&png_data, image::ImageFormat::Png)
            .expect("should decode PNG");
        assert_eq!(img.width(), 2);
        assert_eq!(img.height(), 2);
    }

    #[test]
    fn test_convert_dib_to_png_24bpp_1x1() {
        // 1x1 image, 24bpp BGR
        // BMP rows are padded to 4-byte boundaries: 1 pixel * 3 bytes = 3,
        // padded to 4 bytes
        let pixels: Vec<u8> = vec![0xFF, 0x00, 0x00, 0x00]; // blue + 1 pad byte
        let dib = make_test_dib_24bpp(1, 1, &pixels);
        let png_data = convert_dib_to_png(&dib).expect("should convert successfully");

        assert_eq!(&png_data[..8], b"\x89PNG\r\n\x1a\n");
        let img = image::load_from_memory_with_format(&png_data, image::ImageFormat::Png)
            .expect("should decode PNG");
        assert_eq!(img.width(), 1);
        assert_eq!(img.height(), 1);
    }

    #[test]
    fn test_convert_dib_to_png_empty_data() {
        let result = convert_dib_to_png(&[]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("DIB data too short"), "got: {}", err_msg);
    }

    #[test]
    fn test_convert_dib_to_png_truncated_header() {
        // Only 3 bytes — not enough for biSize
        let result = convert_dib_to_png(&[0x28, 0x00, 0x00]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("DIB data too short"), "got: {}", err_msg);
    }

    #[test]
    fn test_convert_dib_to_png_larger_image() {
        // 4x4 image, 32bpp — all red pixels
        let pixel = [0x00u8, 0x00, 0xFF, 0xFF]; // red in BGRA
        let pixels: Vec<u8> = pixel.iter().copied().cycle().take(4 * 4 * 4).collect();
        let dib = make_test_dib_32bpp(4, 4, &pixels);
        let png_data = convert_dib_to_png(&dib).expect("should convert successfully");

        let img = image::load_from_memory_with_format(&png_data, image::ImageFormat::Png)
            .expect("should decode PNG");
        assert_eq!(img.width(), 4);
        assert_eq!(img.height(), 4);

        // Verify the top-left pixel is red (BMP bottom-up → image flipped)
        let rgba = img.to_rgba8();
        let px = rgba.get_pixel(0, 0);
        assert_eq!(px[0], 0xFF); // R
        assert_eq!(px[1], 0x00); // G
        assert_eq!(px[2], 0x00); // B
    }
}
