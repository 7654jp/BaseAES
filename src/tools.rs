/*
 *   BaseAES, a simple filesystem-like vault system with strong encryption.
 *   Copyright (C) 2026  7654jp
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use gtk4::prelude::*;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufWriter, Cursor, Read, Seek, Write};
use std::path::PathBuf;
use std::rc::Rc;
use zune_jpeg::zune_core::{bytestream, colorspace, options};
use zune_png::PngDecoder;

use crate::types::*;
use crate::vault::get_files_from_vpath;

#[derive(PartialEq, Eq)]
enum VaultReadState {
    Name,
    Index,
    Data,
}

#[inline]
pub fn hashify_sha256(data: String) -> [u8; 32] {
    Sha256::digest(data.as_bytes()).into()
}

#[inline]
pub fn hashify_sha256_ref(data: &String) -> [u8; 32] {
    Sha256::digest(data.as_bytes()).into()
}

pub fn u8_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_u8(data: &String) -> Result<Vec<u8>, std::num::ParseIntError> {
    let mut resvec: Vec<u8> = Vec::new();
    for i in (0..data.len()).step_by(2) {
        if i == data.len() - 1 {
            break;
        }
        resvec.push(u8::from_str_radix(&data[i..i + 2], 16)?);
    }
    Ok(resvec)
}

#[inline]
pub fn grid_builder(
    mtop: i32,
    mbottom: i32,
    mstart: i32,
    mend: i32,
    sprow: i32,
    spcol: i32,
) -> gtk4::builders::GridBuilder {
    gtk4::Grid::builder()
        .margin_top(mtop)
        .margin_bottom(mbottom)
        .margin_start(mstart)
        .margin_end(mend)
        .row_spacing(sprow)
        .column_spacing(spcol)
}

pub fn show_alert(parent: &impl IsA<gtk4::Window>, title: &str, message: &str) {
    let dialog = gtk4::AlertDialog::builder()
        .message(title)
        .detail(message)
        .modal(true)
        .buttons(["OK"])
        .default_button(0)
        .build();
    dialog.choose(Some(parent), gtk4::gio::Cancellable::NONE, |_| {});
}

#[inline]
pub fn get_vault_path() -> Option<String> {
    Some(get_vault_dir()? + "/master.vbase")
}

pub fn get_vault_dir() -> Option<String> {
    let rapppath = std::env::current_exe();
    if rapppath.is_err() {
        return None;
    }
    let mut apppath = rapppath.unwrap();
    apppath.pop();
    let opath = apppath.to_str();
    if opath.is_none() {
        return None;
    }
    return Some(opath.unwrap().to_string());
}

pub fn check_vault_name(
    awindow: Rc<gtk4::ApplicationWindow>,
    base_data: &String,
    vname: Rc<String>,
) -> Option<i16> {
    let mut vault_count: i16 = 0;
    for name in base_data.split(",") {
        if vault_count == 0 && name != "^BaseAES Vault Format Ver.2^" {
            show_alert(awindow.as_ref(), "Error", "The vault index is corrupted.");
            return None;
        } else if name == vname.as_ref() {
            show_alert(
                awindow.as_ref(),
                "Alert",
                "The vault name cannot be the same.",
            );
            return None;
        }
        vault_count += 1;
    }
    vault_count -= 1;
    Some(vault_count)
}

#[inline]
pub fn get_pixbuf_from_png_u8(pngraw: &[u8]) -> Option<gtk4::gdk_pixbuf::Pixbuf> {
    let rawpb = get_rpixbuf_from_png_u8(pngraw.to_vec())?;
    let rowstride = rawpb.width * if rawpb.has_alpha { 4 } else { 3 };
    Some(gtk4::gdk_pixbuf::Pixbuf::from_bytes(
        &glib::Bytes::from_owned(rawpb.data),
        gtk4::gdk_pixbuf::Colorspace::Rgb,
        rawpb.has_alpha,
        8,
        rawpb.width,
        rawpb.height,
        rowstride,
    ))
}

pub fn get_rpixbuf_from_png_u8(pngraw: Vec<u8>) -> Option<RawPixbuf> {
    let mut png_decoder = PngDecoder::new(Cursor::new(pngraw));
    png_decoder.decode_headers().ok()?;
    let png_header = match png_decoder.info() {
        Some(header) => header.to_owned(),
        None => return None,
    };
    let png_rawbuf = png_decoder.decode_raw().ok()?;
    let (img_h, img_w) = (png_header.height as i32, png_header.width as i32);
    match png_decoder.colorspace()? {
        colorspace::ColorSpace::RGB => Some(RawPixbuf::new(png_rawbuf, false, img_w, img_h)),
        colorspace::ColorSpace::RGBA => Some(RawPixbuf::new(png_rawbuf, true, img_w, img_h)),
        _ => None,
    }
}

pub fn get_rpixbuf_from_jpeg_u8(jpgraw: Vec<u8>) -> Option<RawPixbuf> {
    let jpeg_decode_options =
        options::DecoderOptions::default().jpeg_set_out_colorspace(colorspace::ColorSpace::RGBA);
    let mut jpeg_decoder = zune_jpeg::JpegDecoder::new_with_options(
        bytestream::ZCursor::new(jpgraw),
        jpeg_decode_options,
    );
    let jpeg_rawbuf = match jpeg_decoder.decode() {
        Ok(image) => image,
        Err(_) => return None,
    };
    let jpeg_info = jpeg_decoder.info()?;
    let (img_w, img_h) = (jpeg_info.width as i32, jpeg_info.height as i32);

    return Some(RawPixbuf::new(
        jpeg_rawbuf,
        true,
        img_w as i32,
        img_h as i32,
    ));
}

pub fn get_rpixbuf_from_webp_u8(webpraw: Vec<u8>) -> Option<RawPixbuf> {
    let mut webp_decoder = match image_webp::WebPDecoder::new(Cursor::new(webpraw)) {
        Ok(decoder) => decoder,
        Err(_) => return None,
    };
    let mut webp_rawbuf = vec![0u8; webp_decoder.output_buffer_size()?];
    if let Err(_) = webp_decoder.read_image(&mut webp_rawbuf) {
        return None;
    };
    let (img_w, img_h) = webp_decoder.dimensions();
    if webp_decoder.has_alpha() {
        return Some(RawPixbuf::new(
            webp_rawbuf,
            true,
            img_w as i32,
            img_h as i32,
        ));
    } else {
        return Some(RawPixbuf::new(
            webp_rawbuf,
            false,
            img_w as i32,
            img_h as i32,
        ));
    }
}

pub fn itemname_check(name: &String, ftype: &str) -> Result<(), String> {
    if name.contains("^") || name.contains(":") || name.contains("/") || name.contains("'") {
        return Err(format!(
            "{ftype} name cannot contain \"^\" or \":\" or \"/\" or \"'\" .",
        ));
    }
    if name.starts_with(" ") {
        return Err(format!("{ftype} name cannot start with ' '."));
    }
    if name.ends_with(" ") || name.ends_with(".") {
        return Err(format!("{ftype} name cannot end with ' ' or '.'."));
    }
    if name.chars().count() == 0 {
        return Err(format!("{ftype} name cannot be empty."));
    }
    return Ok(());
}

pub fn bgsf_decode_item(line: &str) -> Option<([i32; 4], &str)> {
    // @text:1/1/1/1:WhatEverThatIs.
    // @item:1/2/1/1:/path/to/whatever-item.png
    let (style_str, data) = match line.split_once(":")?.1.split_once(":") {
        Some((st, da)) => (st, da),
        None => return None,
    };
    let mut style: [i32; 4] = [0, 0, 0, 0];
    let mut style_str_sp = style_str.split("/").into_iter();
    for idx in 0..4 {
        let istr = style_str_sp.next()?;
        if let Ok(int) = i32::from_str_radix(istr, 10) {
            style[idx] = int;
        } else {
            return None;
        }
    }

    Some((style, data))
}

pub fn decode_path(
    vindex_rc: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    path_str: &str,
) -> Option<PathBuf> {
    let mut item_path = PathBuf::from("/");
    for dfname in split_vault_path(path_str) {
        let citem_path = item_path.clone();
        for (ipath, name) in &*vindex_rc.borrow() {
            let ipath = Rc::new(ipath.clone());
            if !ipath.starts_with(&citem_path) {
                continue;
            }
            // Exclude subdirectory here
            if ipath.parent().unwrap_or(&PathBuf::from("/")) != citem_path {
                continue;
            }
            if &dfname == name {
                item_path.push(ipath.as_ref());
            }
        }
        drop(citem_path);
    }
    Some(item_path)
}

fn split_vault_path(path: &str) -> Vec<String> {
    let parts = &path.split("/").collect::<Vec<&str>>()[1..];
    let mut res: Vec<String> = Vec::new();
    if parts.is_empty() {
        return res;
    }
    for (idx, pstr) in parts.iter().enumerate() {
        if pstr.is_empty() {
            continue;
        }
        if idx + 1 < parts.len() {
            res.push(pstr.to_string() + "/");
        } else {
            res.push(pstr.to_string());
        }
    }
    res
}

#[inline]
pub fn bgsf_parse_item(
    iviewer_grid: Rc<gtk4::Grid>,
    warn_label: Rc<gtk4::Label>,
    style: [i32; 4],
    path_str: &str,
    lcount: &u32,
    idcs_rc: Rc<RefCell<ImgDecodingController>>,
    vindex_rc: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata_rc: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
) -> bool {
    if let Some(dpath) = decode_path(Rc::clone(&vindex_rc), path_str) {
        let bdata_rc = vdata_rc.borrow();
        let pdata = match bdata_rc.get(&dpath) {
            Some(d) => d,
            None => {
                warn_label.set_text(&format!(
                    "{}\nWarning: The file doesn't exist at line {lcount}  ({path_str})",
                    warn_label.text()
                ));
                return true;
            }
        };
        // Predict filetype, again
        let lmime = tree_magic_mini::from_u8(pdata);

        if lmime.starts_with("text") {
            let text_viewer = gtk4::TextView::builder()
                .hexpand(true)
                .vexpand(true)
                .editable(false)
                .build();
            text_viewer.add_css_class("normal");
            text_viewer.set_wrap_mode(gtk4::WrapMode::Word);
            text_viewer
                .buffer()
                .set_text(str::from_utf8(pdata).unwrap_or(
                    "Failed to read data as text. Data is saved but we're not able to show it.",
                ));
            iviewer_grid.attach(&text_viewer, style[0], style[1] + 1, style[2], style[3]);
        } else if lmime == "image/png" || lmime == "image/jpeg" || lmime == "image/webp" {
            // Image parsing
            let image_viewer =
                Rc::new(gtk4::Picture::builder().hexpand(true).vexpand(true).build());

            idcs_rc.borrow_mut().request_decode(
                IDCSImageType::from_str_name(lmime).unwrap(),
                pdata.to_owned(),
                Rc::clone(&image_viewer),
            );
            iviewer_grid.attach(
                image_viewer.as_ref(),
                style[0],
                style[1] + 1,
                style[2],
                style[3],
            );
        } else if lmime.starts_with("image") {
            let text_viewer = gtk4::TextView::builder()
                .hexpand(true)
                .vexpand(true)
                .editable(false)
                .build();
            text_viewer.add_css_class("normal");
            text_viewer.set_wrap_mode(gtk4::WrapMode::Word);
            text_viewer
                .buffer()
                .set_text("Sorry, only PNG/JPEG/WebP Images are supported.");
            iviewer_grid.attach(&text_viewer, 1, 1, 1, 1);
        } else {
            let phlabel = gtk4::Label::new(Some(&format!("Decoded: {:?}", dpath)));
            iviewer_grid.attach(&phlabel, style[0], style[1] + 1, style[2], style[3]);
        }
    } else {
        warn_label.set_text(&format!(
            "{}\nWarning: Invalid path at line {lcount}  ({path_str})",
            warn_label.text()
        ));
    }
    false
}

pub fn generate_new_vault(
    master_plain_vname: String,
    vname: &String,
    key: &[u8; 32],
    mwindow: &impl IsA<gtk4::Window>,
) -> Option<(String, Cipher)> {
    let vault_data = format!("^{vname}\n[Index]\n[Data]\n");
    let newvault = match encrypt_aes_with_key(mwindow, vault_data.as_bytes(), key) {
        Some(v) => v,
        None => {
            return None;
        }
    };

    return Some((master_plain_vname + &format!(",{vname}"), newvault));
}

fn open_master(parent: Option<&impl IsA<gtk4::Window>>) -> Option<std::fs::File> {
    // Open file
    let ovaultpath = get_vault_path();
    if ovaultpath.is_none() && parent.is_some() {
        show_alert(
            parent.unwrap(),
            "Error",
            "Failed to detect the path to 'master.vbase'.",
        );
        return None;
    }
    let rbase_file = std::fs::File::open(&ovaultpath.unwrap());
    if rbase_file.is_err() && parent.is_some() {
        show_alert(
            parent.unwrap(),
            "Error",
            "Could not open 'master.vbase' in read_master.",
        );
        return None;
    }
    Some(rbase_file.unwrap())
}

pub fn vault_decode(
    vault_data: &String,
) -> Option<(
    String,
    BTreeMap<PathBuf, String>,
    BTreeMap<PathBuf, Vec<u8>>,
)> {
    let mut read_state = VaultReadState::Name;
    let mut vname: String = "Invalid^".to_string();
    let mut vindex: BTreeMap<PathBuf, String> = BTreeMap::new();
    let mut vdata: BTreeMap<PathBuf, Vec<u8>> = BTreeMap::new();
    for line in vault_data.split("\n") {
        if line.starts_with("^") {
            vname = line[1..].to_string();
            continue;
        } else if read_state == VaultReadState::Name && line == "[Index]" {
            read_state = VaultReadState::Index;
            continue;
        } else if read_state == VaultReadState::Index && line == "[Data]" {
            read_state = VaultReadState::Data;
            continue;
        }

        if read_state == VaultReadState::Index {
            if !line.contains(":") {
                continue;
            }
            let (dir, name) = line.split_once(":").unwrap();
            vindex.insert(PathBuf::from(dir), name.to_string());
        } else if read_state == VaultReadState::Data {
            if !line.contains(":") {
                continue;
            }
            let (dir, data) = line.split_once(":").unwrap();
            vdata.insert(PathBuf::from(dir), hex_to_u8(&data.to_string()).unwrap());
        }
    }
    if &vname == "Invalid^" {
        return None;
    }
    return Some((vname, vindex, vdata));
}

#[inline]
pub fn encrypt_aes(parent: &impl IsA<gtk4::Window>, value: &[u8]) -> Option<([u8; 12], Vec<u8>)> {
    encrypt_aes_with_key(parent, value, BASE_KEY)
}

pub fn encrypt_aes_with_key(
    parent: &impl IsA<gtk4::Window>,
    value: &[u8],
    key: &[u8; 32],
) -> Option<([u8; 12], Vec<u8>)> {
    // Encrypt default value
    let cipher = match Aes256Gcm::new_from_slice(key) {
        Ok(c) => c,
        Err(_) => {
            show_alert(
                parent,
                "Error",
                "Failed to initialize encryption. Aborting.",
            );
            return None;
        }
    };
    let mut rng = OsRng::default();
    let mut nonce_ary: [u8; 12] = Default::default();
    if let Err(_) = rng.try_fill_bytes(&mut nonce_ary) {
        show_alert(parent, "Error", "Failed to generate nonce. Aborting.");
        return None;
    };
    let nonce = Nonce::from_slice(&nonce_ary);

    let rencrypted = cipher.encrypt(nonce, value);
    if rencrypted.is_err() {
        show_alert(parent, "Error", "Failed to encrypt default data. Aborting.");
        return None;
    }
    Some((nonce_ary, rencrypted.unwrap()))
}

#[inline]
pub fn decrypt_aes(
    parent: Option<&impl IsA<gtk4::Window>>,
    ciphertext: &Vec<u8>,
    nonce_buf: [u8; 12],
    show_error: bool,
) -> Option<Vec<u8>> {
    decrypt_aes_with_key(parent, ciphertext, nonce_buf, BASE_KEY, show_error)
}

pub fn decrypt_aes_with_key(
    parent: Option<&impl IsA<gtk4::Window>>,
    ciphertext: &[u8],
    nonce_buf: [u8; 12],
    key: &[u8; 32],
    show_error: bool,
) -> Option<Vec<u8>> {
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new_from_slice(aes_key).unwrap();
    let nonce = Nonce::from_slice(&nonce_buf);
    let rbase_data = cipher.decrypt(nonce, ciphertext);
    if rbase_data.is_err() {
        if show_error == true && parent.is_some() {
            show_alert(parent.unwrap(), "Error", "Failed to decrypt provided data.");
        }
        return None;
    }
    return Some(rbase_data.unwrap());
}

pub fn master_read_vname(parent: &impl IsA<gtk4::Window>) -> Option<([u8; 17], Vec<u8>)> {
    let mut base_file = match open_master(Some(parent)) {
        Some(f) => f,
        None => {
            return None;
        }
    };

    // Read data
    let mut vname_ibuf = [0u8; 17];
    let rread_vnamed = base_file.read_exact(&mut vname_ibuf);
    if rread_vnamed.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to read 'vname-info' from 'master.vbase'.",
        );
        return None;
    }

    let vname_length: u32 = u32::from_le_bytes(vname_ibuf[13..17].try_into().unwrap());

    let mut vname_cipherbuf = vec![0u8; vname_length as usize];
    let rread_vcipher = base_file.read_exact(&mut vname_cipherbuf);
    if rread_vcipher.is_err() {
        show_alert(
            parent,
            "Error",
            "Failed to read 'vname-cipher' from 'master.vbase'.",
        );
        return None;
    }
    return Some((vname_ibuf, vname_cipherbuf));
}

pub fn master_read_vault_at(
    parent: Option<&impl IsA<gtk4::Window>>,
    index: usize,
) -> Option<Cipher> {
    let mut base_file = match open_master(parent) {
        Some(f) => f,
        None => {
            return None;
        }
    };
    let show_error = parent.is_some();
    if let Err(_) = base_file.lock() {
        if show_error {
            show_alert(
                parent.unwrap(),
                "Error",
                "Failed to acquire a lock to 'master.vbase'.\nAborting due to unreliable read.",
            );
        }
        return None;
    }

    // Read vname section and skip
    let mut vname_ibuf = [0u8; 17];
    let vname_length = match base_file.read_exact(&mut vname_ibuf) {
        Ok(_) => u32::from_le_bytes(vname_ibuf[13..17].try_into().unwrap()),
        Err(_) => {
            if show_error {
                show_alert(
                    parent.unwrap(),
                    "Error",
                    "Failed to read 'vname-info' from 'master.vbase'.",
                );
            }
            return None;
        }
    };

    if let Err(_) = base_file.seek_relative(vname_length as i64) {
        if show_error {
            show_alert(parent.unwrap(), "Error", "Failed to skip 'vname-cipher'.");
        }
        return None;
    };

    // Read vaults before index and skip
    if index > 0 {
        for _ in 0..index {
            let mut vdata_ibuf = [0u8; 16];
            let vdata_slength = match base_file.read_exact(&mut vdata_ibuf) {
                Ok(_) => u32::from_le_bytes(vdata_ibuf[12..16].try_into().unwrap()),
                Err(_) => {
                    if show_error {
                        show_alert(
                            parent.unwrap(),
                            "Error",
                            "Failed to read 'vdata-length(skip)' from 'master.vbase'.",
                        );
                    }
                    return None;
                }
            };

            if let Err(_) = base_file.seek_relative(vdata_slength as i64) {
                if show_error {
                    show_alert(
                        parent.unwrap(),
                        "Error",
                        "Failed to skip 'vdata' that is prior to the index.",
                    );
                }
                return None;
            };
        }
    }

    // Read the vault at (index)
    let mut vdata_noncebuf = [0u8; 12];
    if let Err(_) = base_file.read_exact(&mut vdata_noncebuf) {
        if show_error {
            show_alert(
                parent.unwrap(),
                "Error",
                "Failed to read 'vdata-nonce' from 'master.vbase'.",
            );
        }
        return None;
    };
    let mut vdata_lengthbuf = [0u8; 4];
    let vdata_length = match base_file.read_exact(&mut vdata_lengthbuf) {
        Ok(_) => u32::from_le_bytes(vdata_lengthbuf),
        Err(_) => {
            if show_error {
                show_alert(
                    parent.unwrap(),
                    "Error",
                    "Failed to read 'vdata-length' from 'master.vbase'.",
                );
            }
            return None;
        }
    };

    let mut vdata_cipherbuf = vec![0u8; vdata_length as usize];
    if let Err(_) = base_file.read_exact(&mut vdata_cipherbuf) {
        if show_error {
            show_alert(
                parent.unwrap(),
                "Error",
                "Failed to read 'vdata-cipher' from 'master.vbase'.",
            );
        }
        return None;
    };

    return Some((vdata_noncebuf, vdata_cipherbuf));
}

pub fn master_update_data(
    parent: &impl IsA<gtk4::Window>,
    vname: Option<(&[u8; 1], Cipher)>,
    vdata: Option<(i16, Option<&Cipher>)>,
) -> bool {
    // Open tmp and lock
    let vtmppath = match get_vault_dir() {
        Some(d) => d + "/master.vbase.tmp",
        None => {
            show_alert(
                parent,
                "Error",
                "Failed to detect the directory of 'master.vbase'.",
            );
            return false;
        }
    };
    let base_file = match fs::File::create(&vtmppath) {
        Ok(f) => f,
        Err(_) => {
            show_alert(parent, "Error", "Could not create 'master.vbase.tmp'.");
            return false;
        }
    };
    if let Err(_) = base_file.lock() {
        show_alert(
            parent,
            "Error",
            "Failed to acquire lock to 'master.vbase.tmp'.\nAborting due to unreliable file access.",
        );
    };
    let mut bfile_bufwriter = BufWriter::new(base_file);

    // Get current and lock
    let mut current_file = match open_master(Some(parent)) {
        Some(f) => f,
        None => return false,
    };
    if let Err(_) = current_file.lock() {
        show_alert(
            parent,
            "Error",
            "Failed to acquire lock to 'master.vbase'.\nAborting due to unreliable file access.",
        );
    };

    let mut written_bytes: usize = 0;

    if vname.is_some() {
        // Update vname
        let vname_new = vname.unwrap();
        written_bytes += match bfile_bufwriter.write(vname_new.0) {
            Ok(l) => l,
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to write 'vtype' to an output buffer.",
                );
                return false;
            }
        };
        written_bytes += match bfile_bufwriter.write(&vname_new.1.0) {
            Ok(l) => l,
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to write 'vname-nonce' to an output buffer.",
                );
                return false;
            }
        };
        let vnamelen_as_bytes = (vname_new.1.1.len() as u32).to_le_bytes();
        written_bytes += match bfile_bufwriter.write(&vnamelen_as_bytes) {
            Ok(l) => l,
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to write 'vname-length' to an output buffer.",
                );
                return false;
            }
        };
        written_bytes += match bfile_bufwriter.write(&vname_new.1.1) {
            Ok(l) => l,
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to write 'vname-cipher' to an output buffer.",
                );
                return false;
            }
        };
        // Skip vname on current
        if let Err(_) = current_file.seek_relative(13) {
            show_alert(parent, "Error", "Failed to skip 'vname-info'.");
            return false;
        }
        let mut cvname_buf = [0u8; 4];
        let cvname_len = match current_file.read_exact(&mut cvname_buf) {
            Ok(_) => i64::from(u32::from_le_bytes(cvname_buf)),
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to read 'vname-length' from 'master.vbase'.",
                );
                return false;
            }
        };
        if let Err(_) = current_file.seek_relative(cvname_len) {
            show_alert(
                parent,
                "Error",
                "Failed to read 'vname-cipher' to be copied.",
            );
            return false;
        };
    } else {
        // Copy vname
        let mut curr_vnameibuf = [0u8; 17];
        if let Err(_) = current_file.read_exact(&mut curr_vnameibuf) {
            show_alert(parent, "Error", "Failed to read 'vname-info' to be copied.");
            return false;
        };
        written_bytes += match bfile_bufwriter.write(&curr_vnameibuf) {
            Ok(l) => l,
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to write 'vname-info' to an output buffer.",
                );
                return false;
            }
        };
        let vname_len = u32::from_le_bytes(curr_vnameibuf[13..17].try_into().unwrap());
        let mut curr_vnamebuf = vec![0u8; vname_len as usize];
        if let Err(_) = current_file.read_exact(&mut curr_vnamebuf) {
            show_alert(
                parent,
                "Error",
                "Failed to read 'vname-cipher' to be copied.",
            );
            return false;
        };
        written_bytes += match bfile_bufwriter.write(&curr_vnamebuf) {
            Ok(l) => l,
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to write 'vname-cipher' to an output buffer.",
                );
                return false;
            }
        };
    }

    if vdata.is_some() {
        // Update vdata
        let (index, vault_data) = vdata.unwrap();
        if index == VDATA_INDEX_APPEND {
            // Copy and then append
            let mut curr_vdatabuf = Vec::new();
            if let Err(_) = current_file.read_to_end(&mut curr_vdatabuf) {
                show_alert(parent, "Error", "Failed to read 'vdata' to be copied.");
                return false;
            };
            written_bytes += match bfile_bufwriter.write(&curr_vdatabuf) {
                Ok(l) => l,
                Err(_) => {
                    show_alert(
                        parent,
                        "Error",
                        "Failed to write 'vdata' to an output buffer.",
                    );
                    return false;
                }
            };

            // Append
            written_bytes += match bfile_bufwriter.write(&vault_data.as_ref().unwrap().0) {
                Ok(l) => l,
                Err(_) => {
                    show_alert(
                        parent,
                        "Error",
                        "Failed to write 'vdata-nonce' to an output buffer.",
                    );
                    return false;
                }
            };
            written_bytes += match bfile_bufwriter
                .write(&(vault_data.as_ref().unwrap().1.len() as u32).to_le_bytes())
            {
                Ok(l) => l,
                Err(_) => {
                    show_alert(
                        parent,
                        "Error",
                        "Failed to write 'vdata-len' to an output buffer.",
                    );
                    return false;
                }
            };
            written_bytes += match bfile_bufwriter.write(&vault_data.as_ref().unwrap().1) {
                Ok(l) => l,
                Err(_) => {
                    show_alert(
                        parent,
                        "Error",
                        "Failed to write 'vdata-cipher' to an output buffer.",
                    );
                    return false;
                }
            };
        } else {
            // Edit data at (index)
            let mut lp_index: i16 = 0;
            loop {
                if lp_index == index {
                    // Skip this in current
                    if let Err(_) = current_file.seek_relative(12) {
                        show_alert(parent, "Error", "Failed to skip 'vdata-info'.");
                    }
                    let mut curr_vdatalbuf = [0u8; 4];
                    if let Err(_) = current_file.read_exact(&mut curr_vdatalbuf) {
                        show_alert(parent, "Error", "Failed to read 'vdata-length' to skip.");
                    }
                    if let Err(_) =
                        current_file.seek_relative(i64::from(u32::from_le_bytes(curr_vdatalbuf)))
                    {
                        show_alert(parent, "Error", "Failed to skip 'vdata-cipher'.");
                    }

                    if vault_data.is_none() {
                        lp_index += 1;
                        continue;
                    }
                    let new_vault = vault_data.unwrap();
                    // Override
                    written_bytes += match bfile_bufwriter.write(&new_vault.0) {
                        Ok(l) => l,
                        Err(_) => {
                            show_alert(
                                parent,
                                "Error",
                                "Failed to write 'vdata-nonce' to an output buffer.",
                            );
                            return false;
                        }
                    };
                    written_bytes +=
                        match bfile_bufwriter.write(&(new_vault.1.len() as u32).to_le_bytes()) {
                            Ok(l) => l,
                            Err(_) => {
                                show_alert(
                                    parent,
                                    "Error",
                                    "Failed to write 'vtype' to an output buffer.",
                                );
                                return false;
                            }
                        };
                    written_bytes += match bfile_bufwriter.write(&new_vault.1) {
                        Ok(l) => l,
                        Err(_) => {
                            show_alert(
                                parent,
                                "Error",
                                "Failed to write 'vtype' to an output buffer.",
                            );
                            return false;
                        }
                    };
                } else {
                    // Copy
                    let mut curr_vdataibuf = [0u8; 16];
                    if let Err(_) = current_file.read_exact(&mut curr_vdataibuf) {
                        break;
                    };
                    written_bytes += match bfile_bufwriter.write(&curr_vdataibuf) {
                        Ok(l) => l,
                        Err(_) => {
                            show_alert(
                                parent,
                                "Error",
                                "Failed to write 'vdata-info' to an output buffer.",
                            );
                            return false;
                        }
                    };

                    let vdata_len = u32::from_le_bytes(curr_vdataibuf[12..16].try_into().unwrap());
                    let mut curr_vdatabuf = vec![0u8; vdata_len as usize];
                    if let Err(_) = current_file.read_exact(&mut curr_vdatabuf) {
                        show_alert(parent, "Error", "Failed to read 'vdata-cipher'.");
                        break;
                    };
                    written_bytes += match bfile_bufwriter.write(&curr_vdatabuf) {
                        Ok(l) => l,
                        Err(_) => {
                            show_alert(
                                parent,
                                "Error",
                                "Failed to write 'vdata' to an output buffer.",
                            );
                            return false;
                        }
                    };
                }
                lp_index += 1;
            }
        }
    } else {
        // Copy vdata
        let mut curr_vdatabuf = Vec::new();
        if let Err(_) = current_file.read_to_end(&mut curr_vdatabuf) {
            show_alert(parent, "Error", "Failed to read 'vdata' to be copied.");
            return false;
        };
        written_bytes += match bfile_bufwriter.write(&curr_vdatabuf) {
            Ok(l) => l,
            Err(_) => {
                show_alert(
                    parent,
                    "Error",
                    "Failed to write 'vtype' to an output buffer.",
                );
                return false;
            }
        };
    }

    if let Err(_) = bfile_bufwriter.flush() {
        show_alert(
            parent,
            "Error",
            "Failed to write data to 'master.vbase.tmp'.",
        );
        return false;
    }

    // Copy tmp to master
    let masterpath = match get_vault_path() {
        Some(p) => p,
        None => {
            show_alert(
                parent,
                "Error",
                "Failed to find 'master.vbase'.\nTry renaming 'master.vbase.tmp' to 'master.vbase' manually.",
            );
            return true;
        }
    };
    let rcopy = std::fs::copy(&vtmppath, masterpath);
    if rcopy.is_err() {
        show_alert(
            parent,
            "Alert",
            "Failed to copy 'master.vbase.tmp' to 'master.vbase'.\nTry renaming 'master.vbase.tmp' to 'master.vbase' manually.",
        );
        return true;
    }
    if rcopy.unwrap() != written_bytes as u64 {
        show_alert(
            parent,
            "Alert",
            "Failed to copy 'master.vbase.tmp' to 'master.vbase'.\nTry renaming 'master.vbase.tmp' to 'master.vbase' manually.",
        );
        return true;
    }

    // Remove tmp
    let rdelete = std::fs::remove_file(vtmppath);
    if rdelete.is_err() {
        show_alert(
            parent,
            "Alert",
            "Failed to delete 'master.vbase.tmp'.\nTry deleteing 'master.vbase.tmp' manually.",
        );
    };
    return true;
}

pub fn delete_button_vault_list(
    vtype: &'static [u8; 1],
    pwindow: Rc<gtk4::Window>,
    vname_plain_str: String,
    capp: Rc<gtk4::Application>,
    commlabel: Rc<RefCell<gtk4::Label>>,
    commindex: Rc<RefCell<ItemContainer<i16>>>,
) -> Vec<gtk4::Button> {
    let vname_plain = Rc::new(vname_plain_str);
    let mut buttons: Vec<gtk4::Button> = Vec::new();
    let mut vault_index: i16 = 0;
    for name in vname_plain.split(",") {
        if name.contains("^") || name == "" {
            continue;
        }
        let vlist_button = gtk4::Button::with_label(&name);
        let ccapp = Rc::clone(&capp);
        let pwindow_rc = Rc::clone(&pwindow);
        let vault_index_at = vault_index.clone();
        let vault_name = Rc::new(name.to_owned());
        let vname_plain_rc = Rc::clone(&vname_plain);
        let commindex_rc = Rc::clone(&commindex);
        let commlabel_rc = Rc::clone(&commlabel);
        vlist_button.connect_clicked(move |_| {
            let masted_vdata =
                match master_read_vault_at(Some(pwindow_rc.as_ref()), vault_index_at as usize) {
                    Some(v) => v,
                    None => return,
                };
            if vtype == b"d" {
                if let Some(mast_decoded_vname) =
                    decrypt_aes(Some(pwindow_rc.as_ref()), &masted_vdata.1, masted_vdata.0, false)
                {
                    // Ask vault password
                    let pw_window = Rc::new(
                        gtk4::Window::builder()
                            .title("Confirm deletion")
                            .modal(true)
                            .build(),
                    );
                    pw_window.set_size_request(128, 80);
                    pw_window.set_application(Some(ccapp.as_ref()));

                    let vdel_grid = grid_builder(6, 6, 12, 12, 24, 12).build();

                    // Password label
                    let pw_pass_label = gtk4::Label::new(Some("Enter Vault password to confirm:"));
                    vdel_grid.attach(&pw_pass_label, 1, 1, 2, 1);
                    // Password input box
                    let vdel_pass_box = gtk4::PasswordEntry::new();
                    vdel_pass_box.set_size_request(128, 32);
                    vdel_grid.attach(&vdel_pass_box, 1, 2, 1, 1);
                    // Confirm button
                    let pw_ok_button = gtk4::Button::with_label("OK");
                    let commindex_drc = Rc::clone(&commindex_rc);
                    let commlabel_drc = Rc::clone(&commlabel_rc);
                    let vname_rc = Rc::clone(&vault_name);
                    let vname_plain_krc = Rc::clone(&vname_plain_rc);
                    let pw_window_rc = Rc::clone(&pw_window);
                    pw_ok_button.connect_clicked(move |_| {
                        // Decode
                        let vault_password =
                            Rc::new(hashify_sha256(vdel_pass_box.text().to_string()));
                        let (mast_decoded_noncer, mast_decoded_vname) = mast_decoded_vname.split_at(12);
                        let mast_decoded_nonce: [u8; 12] = mast_decoded_noncer.try_into().unwrap();

                        match decrypt_aes_with_key(
                            Some(pw_window_rc.as_ref()),
                            mast_decoded_vname,
                            mast_decoded_nonce,
                            vault_password.as_ref(),
                            false,
                        ) {
                            Some(_) => {
                                // Remove selected
                                let vname_removed =
                                    vname_plain_krc.replace(&format!(",{}", vname_rc.as_ref()), "");
                                commlabel_drc.borrow_mut().set_text(&vname_removed);
                                commindex_drc.borrow_mut().set(vault_index_at);
                                commlabel_drc
                                    .borrow_mut()
                                    .add_css_class(&format!("del_{}_{}", vname_rc.as_ref(), u8_to_hex(&mast_decoded_nonce[0..8])));
                                pw_window_rc.close();
                            }
                            None => {
                                show_alert(
                                    pw_window_rc.as_ref(),
                                    "Alert",
                                    "Vault decryption failed.\nThe password might be incorrect.",
                                );
                                return;
                            }
                        };
                    });
                    vdel_grid.attach(&pw_ok_button, 2, 2, 1, 1);

                    pw_window.set_child(Some(&vdel_grid));
                    pw_window.present();
                } else {
                    show_alert(
                        pwindow_rc.as_ref(),
                        "Error",
                        "Failed to decrypt master vault.",
                    );
                };
            } else if vtype == b"u" {
                // Password encryption
                // Ask password window
                let mpw_window = Rc::new(gtk4::Window::new());
                mpw_window.set_application(Some(ccapp.as_ref()));
                mpw_window.set_title(Some("Master password"));
                mpw_window.set_size_request(216, 84);
                mpw_window.set_resizable(false);

                let mpw_grid = grid_builder(6, 6, 12, 12, 24, 12).build();

                // Ask label
                let mpw_label = gtk4::Label::new(Some("Enter password to open master vault."));
                mpw_grid.attach(&mpw_label, 1, 1, 3, 1);
                // Input box
                let mpw_passbox = gtk4::PasswordEntry::new();
                mpw_grid.attach(&mpw_passbox, 1, 2, 2, 1);

                let mpw_ok_button = gtk4::Button::with_label("OK");

                let cccapp = Rc::clone(&ccapp);
                let pwindow_urc = Rc::clone(&pwindow_rc);
                let vname_urc = Rc::clone(&vault_name);
                let mpw_window_rc = Rc::clone(&mpw_window);
                let commindex_urc = Rc::clone(&commindex_rc);
                let commlabel_urc = Rc::clone(&commlabel_rc);
                let vname_plain_urc = Rc::clone(&vname_plain_rc);
                mpw_ok_button.connect_clicked(move |_| {
                    let master_password = Rc::new(hashify_sha256(mpw_passbox.text().to_string()));
                    if let Some(demast_vault) = decrypt_aes_with_key(
                        Some(mpw_window_rc.as_ref()),
                        &masted_vdata.1,
                        masted_vdata.0,
                        master_password.as_ref(),
                        false,
                    ) {
                        mpw_window_rc.close();
                        // Ask vault password
                        let pw_window = Rc::new(
                            gtk4::Window::builder()
                                .title("Confirm deletion")
                                .modal(true)
                                .build(),
                        );
                        pw_window.set_size_request(128, 80);
                        pw_window.set_application(Some(cccapp.as_ref()));

                        let vdel_grid = grid_builder(6, 6, 12, 12, 24, 12).build();

                        // Password label
                        let pw_pass_label = gtk4::Label::new(Some("Enter Vault password to confirm:"));
                        vdel_grid.attach(&pw_pass_label, 1, 1, 2, 1);
                        // Password input box
                        let vdel_pass_box = gtk4::PasswordEntry::new();
                        vdel_pass_box.set_size_request(128, 32);
                        vdel_grid.attach(&vdel_pass_box, 1, 2, 1, 1);
                        // Confirm button
                        let pw_ok_button = gtk4::Button::with_label("OK");

                        let vname_crc = Rc::clone(&vname_urc);
                        let pw_window_rc = Rc::clone(&pw_window);
                        let commindex_crc = Rc::clone(&commindex_urc);
                        let commlabel_crc = Rc::clone(&commlabel_urc);
                        let vname_plain_crc = Rc::clone(&vname_plain_urc);
                        pw_ok_button.connect_clicked(move |_| {
                            // Decode
                            let vault_password =
                                Rc::new(hashify_sha256(vdel_pass_box.text().to_string()));
                            let (demast_vault_nonces, demast_vault_data) = demast_vault.split_at(12);
                            let demast_vault_nonce: [u8; 12] = demast_vault_nonces.try_into().unwrap();

                            match decrypt_aes_with_key(
                                Some(pw_window_rc.as_ref()),
                                demast_vault_data,
                                demast_vault_nonce,
                                vault_password.as_ref(),
                                false,
                            ) {
                                Some(_) => {
                                    // Remove selected
                                    let vname_removed =
                                        vname_plain_crc.replace(&format!(",{}", vname_crc.as_ref()), "");
                                    commlabel_crc.borrow_mut().set_text(&vname_removed);
                                    commindex_crc.borrow_mut().set(vault_index_at);
                                    commlabel_crc
                                        .borrow_mut()
                                        .add_css_class(&format!("del_{}_{}", vname_crc.as_ref(), u8_to_hex(&demast_vault_nonce[0..8])));
                                    pw_window_rc.close();
                                }
                                None => {
                                    show_alert(
                                        pw_window_rc.as_ref(),
                                        "Alert",
                                        "Vault decryption failed.\nThe password might be incorrect.",
                                    );
                                    return;
                                }
                            };
                        });
                        vdel_grid.attach(&pw_ok_button, 2, 2, 1, 1);

                        pw_window.set_child(Some(&vdel_grid));
                        pw_window.present();
                    } else {
                        show_alert(
                            pwindow_urc.as_ref(),
                            "Error",
                            "Failed to decrypt master vault.\nThe password might be incorrect.",
                        );
                    };
                });

                mpw_grid.attach(&mpw_ok_button, 3, 2, 1, 1);

                mpw_window.set_child(Some(&mpw_grid));
                mpw_window.set_modal(true);
                mpw_window.present();
            } else {
                show_alert(
                    pwindow_rc.as_ref(),
                    "Error",
                    "Failed to parse master vault.",
                );
            }
        });
        buttons.push(vlist_button);
        vault_index += 1;
    }
    buttons
}

pub fn baseaes_setup(
    application: &gtk4::Application,
    window: Rc<gtk4::ApplicationWindow>,
    base_file: fs::File,
    vault_path: String,
) {
    // Setup window
    let setup_window = Rc::new(
        gtk4::Window::builder()
            .application(application)
            .title("BaseAES setup")
            .resizable(false)
            .modal(true)
            .build(),
    );
    setup_window.set_size_request(460, 520);

    let setup_grid = grid_builder(6, 6, 12, 12, 8, 8)
        .hexpand(true)
        .vexpand(true)
        .build();

    let setup_title = gtk4::Label::new(Some("Welcome to BaseAES!"));
    setup_title.add_css_class("big");
    setup_grid.attach(&setup_title, 1, 1, 2, 1);

    let setup_desc = gtk4::Label::new(Some(
        "BaseAES will help keep your files safe.\nRead PRECAUTIONS before start!",
    ));
    setup_grid.attach(&setup_desc, 1, 2, 2, 1);

    // Read before continue
    let setup_precautions = gtk4::ScrolledWindow::new();
    setup_precautions.set_hscrollbar_policy(gtk4::PolicyType::Never);
    setup_precautions.add_css_class("notice");
    setup_precautions.set_size_request(440, 320);
    let setup_precautions_text = gtk4::Label::builder()
        .margin_top(12)
        .margin_bottom(8)
        .margin_start(12)
        .margin_end(12)
        .wrap(true)
        .wrap_mode(gtk4::pango::WrapMode::Word)
        .build();
    setup_precautions_text.set_label(PRECAUTIONS_TEXT);
    setup_precautions_text.add_css_class("notice");
    setup_precautions.set_child(Some(&setup_precautions_text));
    setup_grid.attach(&setup_precautions, 1, 3, 2, 1);

    let setup_line = gtk4::Separator::new(gtk4::Orientation::Horizontal);
    setup_grid.attach(&setup_line, 1, 4, 2, 1);

    // Master file encryption selectors etc.
    let setup_aes_desc = gtk4::Label::new(Some("Select master file encryption:"));
    setup_grid.attach(&setup_aes_desc, 1, 5, 2, 1);

    let setup_aes_selector1r = gtk4::CheckButton::with_label("Use included key (weaker)");
    let setup_aes_selector2r = gtk4::CheckButton::with_label("Use password (recommended)");
    setup_aes_selector1r.set_group(Some(&setup_aes_selector2r));

    setup_grid.attach(&setup_aes_selector1r, 1, 6, 1, 1);
    setup_grid.attach(&setup_aes_selector2r, 1, 7, 1, 1);
    let setup_aes_selector1 = Rc::new(setup_aes_selector1r);
    let setup_aes_selector2 = Rc::new(setup_aes_selector2r);

    let setup_aes_pwbox = gtk4::PasswordEntry::new();
    setup_aes_pwbox.set_placeholder_text(Some("Enter Master password here..."));
    setup_grid.attach(&setup_aes_pwbox, 1, 8, 1, 1);

    let setup_aes_button = gtk4::Button::with_label("OK");
    let basefile = Rc::new(base_file);
    let swindow_rc = Rc::clone(&setup_window);
    let setup_aes_sel1 = Rc::clone(&setup_aes_selector1);
    let setup_aes_sel2 = Rc::clone(&setup_aes_selector2);
    setup_aes_button.connect_clicked(move |_| {
        let use_intk = setup_aes_sel1.is_active();
        if !(use_intk || setup_aes_sel2.is_active()) {
            return;
        }
        if setup_aes_sel2.is_active() && setup_aes_pwbox.text().is_empty() {
            show_alert(
                swindow_rc.as_ref(),
                "Alert",
                "Master password cannot be empty.",
            );
            return;
        }
        let key = hashify_sha256(setup_aes_pwbox.text().to_string());
        let mut bfilewriter = BufWriter::new(basefile.as_ref());
        let vnpd_const = "^BaseAES Vault Format Ver.2^".as_bytes(); // VName Plain Default
        let vname_opt = if use_intk {
            encrypt_aes(swindow_rc.as_ref(), vnpd_const)
        } else {
            encrypt_aes_with_key(swindow_rc.as_ref(), vnpd_const, &key)
        };
        let vname = match vname_opt {
            Some(vname_cipher) => vname_cipher,
            None => {
                show_alert(
                    swindow_rc.as_ref(),
                    "Error",
                    "Failed to initialize vault.\n('vname' encryption failed)",
                );
                return;
            }
        };
        if let Err(_) = bfilewriter.write(if use_intk { b"d" } else { b"u" }) {
            show_alert(
                swindow_rc.as_ref(),
                "Error",
                "Failed to write 'vtype' to the buffer.",
            );
        };
        if let Err(_) = bfilewriter.write(&vname.0) {
            show_alert(
                swindow_rc.as_ref(),
                "Error",
                "Failed to write 'vname-nonce' to the buffer.",
            );
        };
        let vname_cilen = vname.1.len() as u32;
        if let Err(_) = bfilewriter.write(&vname_cilen.to_le_bytes()) {
            show_alert(
                swindow_rc.as_ref(),
                "Error",
                "Failed to write 'vname-cipher-length' to the buffer.",
            );
        };
        if let Err(_) = bfilewriter.write(&vname.1) {
            show_alert(
                swindow_rc.as_ref(),
                "Error",
                "Failed to write 'vname-cipher' to the buffer.",
            );
        };
        if let Err(_) = bfilewriter.flush() {
            show_alert(
                swindow_rc.as_ref(),
                "Error",
                "Failed to write 'vname-cipher' to the buffer.",
            );
        }
        swindow_rc.add_css_class("init_complete");
        swindow_rc.close();
    });
    setup_grid.attach(&setup_aes_button, 2, 8, 1, 1);

    setup_window.set_child(Some(&setup_grid));
    setup_window.connect_close_request(move |swindow| {
        if !swindow.has_css_class("init_complete") {
            let _ = fs::remove_file(&vault_path);
            window.close();
        };
        glib::Propagation::Proceed
    });
    setup_window.present();
}

pub fn save_vault(
    app_rc: Rc<gtk4::Application>,
    vname: Rc<String>,
    final_string: Rc<String>,
    hash_final: [u8; 32],
    vpassword_rc: Rc<[u8; 32]>,
    vwindow_rc: Rc<gtk4::Window>,
    commlabel_rc: Rc<RefCell<gtk4::Label>>,
) {
    let save_window = Rc::new(gtk4::Window::new());
    save_window.set_application(Some(app_rc.as_ref()));
    save_window.set_title(Some("Save changes?"));
    save_window.set_default_size(180, 48);
    save_window.set_modal(true);
    let save_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

    let save_title = gtk4::Label::new(Some(&format!("Do you want to save changes in '{vname}'?")));
    save_grid.attach(&save_title, 1, 1, 3, 1);

    let save_yes_button = gtk4::Button::with_label("Save");
    save_yes_button.set_size_request(60, 32);

    let vnamerc = Rc::clone(&vname);
    let save_window_src = Rc::clone(&save_window);
    let vault_window_src = Rc::clone(&vwindow_rc);
    let vault_password_src = Rc::clone(&vpassword_rc);
    let commlabel_src = Rc::clone(&commlabel_rc);
    save_yes_button.connect_clicked(move |_| {
        let (noncev, datav) = match encrypt_aes_with_key(
            save_window_src.as_ref(),
            final_string.as_bytes(),
            vault_password_src.as_ref(),
        ) {
            Some(v) => v,
            None => return,
        };
        commlabel_src.borrow_mut().set_text(&format!(
            "{}{}",
            u8_to_hex(&noncev),
            u8_to_hex(&datav)
        ));
        commlabel_src.borrow_mut().add_css_class(&format!(
            "vwr_{}_{}", // Vault Write Request
            u8_to_hex(&hashify_sha256_ref(vnamerc.as_ref())[0..6]),
            u8_to_hex(&hash_final[0..6]),
        ));
        save_window_src.close();
        vault_window_src.add_css_class("confirm_closure");
        vault_window_src.close();
    });
    save_grid.attach(&save_yes_button, 1, 2, 1, 1);

    let save_no_button = gtk4::Button::with_label("Don't save");
    save_no_button.set_size_request(60, 32);

    let save_window_nrc = Rc::clone(&save_window);
    let vault_window_nrc = Rc::clone(&vwindow_rc);
    save_no_button.connect_clicked(move |_| {
        save_window_nrc.close();
        vault_window_nrc.add_css_class("confirm_closure");
        vault_window_nrc.close();
    });
    save_grid.attach(&save_no_button, 2, 2, 1, 1);

    let save_cancel_button = gtk4::Button::with_label("Cancel");
    save_cancel_button.set_size_request(60, 32);

    let save_window_crc = Rc::clone(&save_window);
    save_cancel_button.connect_clicked(move |_| {
        save_window_crc.close();
    });
    save_grid.attach(&save_cancel_button, 3, 2, 1, 1);

    save_window.set_child(Some(&save_grid));
    save_window.present();
}

pub fn delete_file_confirm(
    app_rc: Rc<gtk4::Application>,
    vdata_rc: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    vindex_rc: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    idcs_rc: Rc<RefCell<ImgDecodingController>>,
    vdi_window_rc: Rc<gtk4::Window>,
    vexpath_rc: Rc<RefCell<EntryWithInternalText>>,
    iviewer_rc: Rc<gtk4::ScrolledWindow>,
    vfilelist_rc: Rc<gtk4::ListBox>,
    iviewer_title_rc: Rc<RefCell<LabelWithInternalText>>,
    changed_rc: Rc<RefCell<ItemContainer<bool>>>,
    close_vdi: bool,
) {
    let mut item_title = iviewer_title_rc.borrow().get_itext().to_owned();
    if item_title.ends_with("^") {
        item_title.pop();
    }
    let ofile = item_title.split_once(":");
    if ofile.is_none() {
        show_alert(
            vdi_window_rc.as_ref(),
            "Alert",
            "No file is selected.\nSelect a file you want to delete, and try again.",
        );
        return;
    }
    let fileid = Rc::new(PathBuf::from(ofile.unwrap().0));

    let delwindow = Rc::new(gtk4::Window::new());
    delwindow.set_title(Some("Confirm deletion?"));
    delwindow.set_application(Some(app_rc.as_ref()));
    delwindow.set_size_request(240, 96);
    delwindow.set_modal(true);

    let del_grid = grid_builder(12, 12, 12, 12, 6, 12).build();

    let fileidx = vindex_rc.borrow();
    let ofilename = fileidx.get(fileid.as_ref());
    if ofilename.is_none() {
        show_alert(
            vdi_window_rc.as_ref(),
            "Error",
            "Could not find the file selected.",
        );
        return;
    };
    let del_title = gtk4::Label::new(Some(&format!(
        "Are you sure you want to delete '{}' ?",
        ofilename.unwrap()
    )));
    del_grid.attach(&del_title, 1, 1, 3, 1);

    let del_no_button = gtk4::Button::with_label("No");
    del_no_button.set_size_request(40, 28);

    // Rc suffix: _nrc
    let delwindow_nrc = Rc::clone(&delwindow);
    if close_vdi {
        let vdi_window_nrc = Rc::clone(&vdi_window_rc);
        del_no_button.connect_clicked(move |_| {
            delwindow_nrc.close();
            vdi_window_nrc.close();
        });
    } else {
        del_no_button.connect_clicked(move |_| {
            delwindow_nrc.close();
        });
    }

    del_grid.attach(&del_no_button, 1, 2, 1, 1);

    let del_yes_button = gtk4::Button::with_label("Yes");
    del_yes_button.set_size_request(40, 28);

    // Rc suffix: _yrc
    let changed_yrc = Rc::clone(&changed_rc);
    let vindex_yrc = Rc::clone(&vindex_rc);
    let vdata_yrc = Rc::clone(&vdata_rc);
    let idcs_yrc = Rc::clone(&idcs_rc);
    let app_yrc = Rc::clone(&app_rc);
    let iviewer_title_yrc = Rc::clone(&iviewer_title_rc);
    let vfilelist_yrc = Rc::clone(&vfilelist_rc);
    let vdi_window_yrc = Rc::clone(&vdi_window_rc);
    let delwindow_yrc = Rc::clone(&delwindow);
    let vexpath_yrc = Rc::clone(&vexpath_rc);
    let iviewer_yrc = Rc::clone(&iviewer_rc);
    del_yes_button.connect_clicked(move |_| {
        let ires = vindex_yrc.borrow_mut().remove(Rc::clone(&fileid).as_ref());
        let dres = vdata_yrc.borrow_mut().remove(Rc::clone(&fileid).as_ref());
        match (ires, dres) {
            (None, None) => {
                show_alert(
                    delwindow_yrc.as_ref(),
                    "Error",
                    "The selected file was not found.",
                );
            }
            (None, Some(_)) => {
                show_alert(
                    delwindow_yrc.as_ref(),
                    "Error",
                    "The file was not found on index, but deletion was successful.",
                );
            }
            (Some(_), None) => {
                show_alert(
                    delwindow_yrc.as_ref(),
                    "Error",
                    "The file was found on index, but failed to delete its data.",
                );
            }
            _ => {}
        };
        changed_yrc.borrow_mut().set(true);

        // Reload
        loop {
            let dwidget = match vfilelist_yrc.last_child() {
                Some(w) => w,
                None => break,
            };
            vfilelist_yrc.remove(&dwidget);
        }
        for button in get_files_from_vpath(
            Rc::clone(&app_yrc),
            Rc::clone(&vfilelist_yrc),
            Rc::clone(&idcs_yrc),
            Rc::clone(&vindex_yrc),
            Rc::clone(&vdata_yrc),
            PathBuf::from(vexpath_yrc.borrow().get_itext()),
            Rc::clone(&iviewer_title_yrc),
            Rc::clone(&iviewer_yrc),
            Rc::clone(&vexpath_yrc),
        ) {
            vfilelist_yrc.append(&*button);
        }

        iviewer_title_yrc
            .borrow_mut()
            .set_text("Click to open files...");
        iviewer_title_yrc.borrow_mut().set_itext(String::new());
        iviewer_yrc.set_child(None::<&gtk4::Grid>);

        delwindow_yrc.close();
        if close_vdi {
            vdi_window_yrc.close();
        }
    });

    del_grid.attach(&del_yes_button, 3, 2, 1, 1);
    delwindow.set_child(Some(&del_grid));
    delwindow.present();
}

// CBK: Common Base Key
const BASE_KEY: &[u8; 32] = b"CBK@TmV2ZXJHb25uYUdpdmVZb3VVcA==";

const PRECAUTIONS_TEXT: &str = concat!(
    "1. DATA INTEGRITY\n",
    "THIS DOES NOT GUARANTEE THAT ENCRYPTED DATA HAS NOT BEEN ALTERED. DATA TAMPERING OR CORRUPTION MAY OCCUR.\n\n",
    "2. DATA LEGALITY\n",
    "USERS ARE SOLELY RESPONSIBLE FOR VERIFYING AND ENSURING THAT THE DATA THEY COLLECT, USE, AND STORE IS LEGALLY PERMISSIBLE. THIS PROGRAM DOES NOT ASSIST WITH SUCH COMPLIANCE.\n\n",
    "3. ACCESS CONTROL\n",
    "ENCRYPTION ALONE DOESN'T GUARANTEE SECURITY. PROPER ACCESS MANAGEMENT MUST BE IMPLEMENTED.\n\n",
    "4. KEY MANAGEMENT\n",
    "SECURELY MANAGING ENCRYPTION KEYS IS CRITICALLY IMPORTANT. IF A KEY IS COMPROMISED, DATA CONFIDENTIALITY WILL BE LOST.\n\n",
    "5. DATA RECOVERY IMPOSSIBILITY\n",
    "LOSING AN ENCRYPTION KEY WILL MAKE YOUR ENCRYPTED DATA INACCESSIBLE. SINCE IT CANNOT BE RECOVERED, THIS POSES A SIGNIFICANT RISK FOR IMPORTANT DATA.\n\n",
    "6. USER AGREEMENT\n",
    "USERS MUST ACKNOWLEDGE AND ACCEPT THE RISKS ASSOCIATED WITH USING THIS PROGRAM IN ADVANCE."
);
