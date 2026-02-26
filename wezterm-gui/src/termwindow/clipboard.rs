use crate::termwindow::TermWindowNotif;
use crate::TermWindow;
use anyhow::Context;
use config::keyassignment::{ClipboardCopyDestination, ClipboardPasteSource};
use mux::pane::{Pane, PaneId};
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
            return;
        }

        let pane_id = pane.pane_id();
        let domain_id = pane.domain_id();
        let window = self.window.as_ref().unwrap().clone();

        let future = window.get_clipboard_image_data();

        promise::spawn::spawn(async move {
            if let Err(err) = paste_image_to_ssh_inner(future, pane_id, domain_id).await {
                log::error!("paste_image_to_ssh: {:#}", err);
                persistent_toast_notification(
                    "Image Paste Failed",
                    &format!("{:#}", err),
                );
            }
        })
        .detach();

        self.maybe_scroll_to_bottom_for_input(&pane);
    }
}

async fn paste_image_to_ssh_inner(
    future: promise::Future<Vec<u8>>,
    pane_id: PaneId,
    domain_id: mux::domain::DomainId,
) -> anyhow::Result<()> {
    let dib_data = future.await.context("Failed to read clipboard image")?;

    let png_data = convert_dib_to_png(&dib_data).context("Failed to convert image to PNG")?;

    let mux = Mux::get();
    let domain = mux
        .get_domain(domain_id)
        .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

    let ssh_domain = domain
        .downcast_ref::<RemoteSshDomain>()
        .ok_or_else(|| anyhow::anyhow!("Current pane is not an SSH session"))?;

    let sftp = ssh_domain
        .sftp()
        .ok_or_else(|| anyhow::anyhow!("SSH session not connected"))?;

    let config = config::configuration();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let remote_path = config
        .ssh_image_paste_remote_path
        .replace("{timestamp}", &timestamp.to_string());

    let mut file = sftp
        .create(&remote_path)
        .await
        .map_err(|e| anyhow::anyhow!("SFTP create failed: {}", e))?;

    use smol::io::AsyncWriteExt;
    file.write_all(&png_data)
        .await
        .context("SFTP write failed")?;
    file.close()
        .await
        .context("SFTP close failed")?;

    let pane = mux
        .get_pane(pane_id)
        .ok_or_else(|| anyhow::anyhow!("Pane not found"))?;

    pane.send_paste(&remote_path)
        .context("Failed to paste path into terminal")?;

    log::info!(
        "Successfully uploaded clipboard image to {}",
        remote_path
    );

    Ok(())
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
