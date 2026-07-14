/*
 *   BaseAES, a simple filesystem-like vault system with strong encryption.
 *   Copyright (C) 2026  7654jp
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use gtk4::prelude::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;

use crate::lang;
use crate::tools::*;
use crate::types::*;

pub fn ask_vault_password_and_open(
    application: Rc<gtk4::Application>,
    vault_data: Cipher,
    vcommlabel: Rc<RefCell<gtk4::Label>>,
) {
    // Ask vault password
    let vopen_window = Rc::new(
        gtk4::Window::builder()
            .title(lang::text::unlock::VUNLOCK_TITLE)
            .modal(true)
            .build(),
    );
    vopen_window.set_application(Some(application.as_ref()));

    let vopen_grid = grid_builder(6, 6, 12, 12, 12, 12).build();

    // Password label
    let vopen_pass_label = gtk4::Label::new(Some(lang::text::home::ADD_VAULT_PW));
    vopen_grid.attach(&vopen_pass_label, 1, 1, 1, 1);
    // Password input box
    let vopen_pass_boxr = gtk4::PasswordEntry::new();
    vopen_pass_boxr.set_size_request(120, 24);
    vopen_grid.attach(&vopen_pass_boxr, 1, 2, 1, 1);
    let vopen_pass_box = Rc::new(vopen_pass_boxr);
    // Confirm button
    let vopen_ok_button = gtk4::Button::with_label("OK");
    let vopen_window_rc = Rc::clone(&vopen_window);
    vopen_ok_button.connect_clicked(move |_| {
        // Decode
        let vault_password = Rc::new(hashify_sha256(
            vopen_pass_box.text().to_string() + VAULT_SALT,
        ));
        let vault_raw = decrypt_aes_with_key(
            Some(vopen_window_rc.as_ref()),
            &vault_data.1,
            vault_data.0,
            vault_password.as_ref(),
            false,
        );
        if vault_raw.is_none() {
            show_alert(
                vopen_window_rc.as_ref(),
                lang::text::generic::ALERT,
                lang::text::unlock::VUNLOCK_DEC_FAILED,
            );
            return;
        }
        let rvault_text = String::from_utf8(vault_raw.unwrap());
        if rvault_text.is_err() {
            show_alert(
                vopen_window_rc.as_ref(),
                lang::text::generic::ERROR,
                lang::text::unlock::VUNLOCK_PARSE_FAILED,
            );
            return;
        };
        // Vault decryption is successful here
        vopen_window_rc.close();

        open_vault(
            Rc::clone(&application),
            Rc::new(rvault_text.unwrap()),
            Rc::clone(&vcommlabel),
            Rc::clone(&vault_password),
        );
    });
    vopen_grid.attach(&vopen_ok_button, 2, 2, 1, 1);

    vopen_window.set_child(Some(&vopen_grid));
    vopen_window.present();
}

pub fn ask_vault_password_and_open_async(
    application: Rc<gtk4::Application>,
    vault_data: std::sync::mpsc::Receiver<Vec<u8>>,
    vcommlabel: Rc<RefCell<gtk4::Label>>,
    selwindow_rc: Rc<gtk4::Window>,
) {
    let vdata_fetch = Rc::new(RefCell::new(Vec::<u8>::new()));

    // Ask vault password
    let vopen_window = Rc::new(
        gtk4::Window::builder()
            .title(lang::text::unlock::VUNLOCK_TITLE)
            .modal(true)
            .build(),
    );
    vopen_window.set_application(Some(application.as_ref()));

    let vopen_grid = grid_builder(6, 6, 12, 12, 12, 12).build();

    // Password label
    let vopen_pass_label = gtk4::Label::new(Some(lang::text::home::ADD_VAULT_PW));
    vopen_grid.attach(&vopen_pass_label, 1, 1, 1, 1);
    // Password input box
    let vopen_pass_boxr = gtk4::PasswordEntry::new();
    vopen_pass_boxr.set_size_request(120, 24);
    vopen_grid.attach(&vopen_pass_boxr, 1, 2, 1, 1);
    let vopen_pass_box = Rc::new(vopen_pass_boxr);
    // Confirm button
    let vopen_ok_button = gtk4::Button::with_label("OK");
    let vopen_window_rc = Rc::clone(&vopen_window);
    vopen_ok_button.connect_clicked(move |_| {
        let receive = vault_data.try_recv();
        if receive.is_ok() || !vdata_fetch.borrow().is_empty() {
            if vdata_fetch.borrow().is_empty() {
                vdata_fetch.borrow_mut().extend(receive.unwrap());
            }
            let data = vdata_fetch.borrow();
            let (nonce_s, data_s) = data.split_at(12);
            let nonce: [u8; 12] = nonce_s.try_into().unwrap();
            // Decode
            let vault_password = Rc::new(hashify_sha256(
                vopen_pass_box.text().to_string() + VAULT_SALT,
            ));
            let vault_raw = decrypt_aes_with_key(
                Some(vopen_window_rc.as_ref()),
                data_s,
                nonce,
                vault_password.as_ref(),
                false,
            );
            if vault_raw.is_none() {
                show_alert(
                    vopen_window_rc.as_ref(),
                    lang::text::generic::ALERT,
                    lang::text::unlock::VUNLOCK_DEC_FAILED,
                );
                return;
            }
            let rvault_text = String::from_utf8(vault_raw.unwrap());
            if rvault_text.is_err() {
                show_alert(
                    vopen_window_rc.as_ref(),
                    lang::text::generic::ERROR,
                    lang::text::unlock::VUNLOCK_PARSE_FAILED,
                );
                return;
            };
            // Vault decryption is successful here
            vopen_window_rc.close();
            selwindow_rc.close();

            open_vault(
                Rc::clone(&application),
                Rc::new(rvault_text.unwrap()),
                Rc::clone(&vcommlabel),
                Rc::clone(&vault_password),
            );
        } else {
            match receive.unwrap_err() {
                TryRecvError::Empty => {
                    show_alert(
                        vopen_window_rc.as_ref(),
                        lang::text::unlock::VUNLOCK_SORRY,
                        lang::text::unlock::VUNLOCK_LOAD_NOT_FINISHED,
                    );
                }
                TryRecvError::Disconnected => {
                    show_alert(
                        vopen_window_rc.as_ref(),
                        lang::text::generic::ERROR,
                        lang::text::unlock::VUNLOCK_DISCONNECTED,
                    );
                }
            }
        }
    });
    vopen_grid.attach(&vopen_ok_button, 2, 2, 1, 1);

    vopen_window.set_child(Some(&vopen_grid));
    vopen_window.present();
}

fn open_vault(
    application: Rc<gtk4::Application>,
    vault_text: Rc<String>,
    commlabel: Rc<RefCell<gtk4::Label>>,
    vault_password: Rc<[u8; 32]>,
) {
    // Take hash for checking changes
    let hash_initial = hashify_sha256_ref(vault_text.as_ref());
    // Convert to three
    let vault_data = match vault_decode(vault_text.as_ref()) {
        Some(data) => data,
        None => return,
    };
    let vname = Rc::new(vault_data.0);
    let vindex = Rc::new(RefCell::new(vault_data.1));
    let vdata = Rc::new(RefCell::new(vault_data.2));
    let changed = Rc::new(RefCell::new(ItemContainer::new(false)));

    // Image processing handler
    let idcs = Rc::new(RefCell::new(ImgDecodingController::new()));
    let (sender, receiver) = std::sync::mpsc::channel::<(u32, RawPixbuf, &str)>();
    let idcs_trc = Rc::clone(&idcs);
    // Image decoding request handler
    let handler_raw =
        glib::source::timeout_add_local(std::time::Duration::from_millis(20), move || {
            // Fetch decoding result
            if let Ok((idx, pb_raw, ityp)) = receiver.try_recv() {
                if let Some((img_rc, cgrid)) = idcs_trc.borrow_mut().image_provider.get(&idx) {
                    let rowstride = pb_raw.width * if pb_raw.has_alpha { 4 } else { 3 };
                    img_rc.set_pixbuf(Some(&gtk4::gdk_pixbuf::Pixbuf::from_bytes(
                        &glib::Bytes::from_owned(pb_raw.data),
                        gtk4::gdk_pixbuf::Colorspace::Rgb,
                        pb_raw.has_alpha,
                        8,
                        pb_raw.width,
                        pb_raw.height,
                        rowstride,
                    )));
                    img_rc
                        .add_css_class(&format!("baim_{}x{}:{ityp}", pb_raw.width, pb_raw.height));
                    cgrid.set_size_request(pb_raw.width, pb_raw.height);
                } else {
                    drop(pb_raw);
                };
                idcs_trc.borrow_mut().image_provider.remove(&idx);
                idcs_trc.borrow_mut().is_processing = false;
            }

            // Check decode request
            if !idcs_trc.borrow().is_processing {
                let oimg_kv = {
                    let idcs_trc_reader = idcs_trc.borrow();
                    match idcs_trc_reader.queue.first_key_value() {
                        Some(kv) => Some((kv.0.clone(), kv.1.clone())),
                        None => None,
                    }
                };
                if oimg_kv.is_some() {
                    let (img_id, image_raw) = oimg_kv.unwrap();
                    idcs_trc.borrow_mut().is_processing = true;

                    let ssender = sender.clone();
                    let img_data = image_raw.data.clone();
                    match image_raw.imgtype {
                        IDCSImageType::Png => {
                            std::thread::spawn(move || {
                                if let Some(rawpb) = get_rpixbuf_from_png_u8(img_data) {
                                    let _ = ssender.send((img_id, rawpb, "PNG"));
                                }
                            });
                        }
                        IDCSImageType::Jpeg => {
                            std::thread::spawn(move || {
                                if let Some(rawpb) = get_rpixbuf_from_jpeg_u8(img_data) {
                                    let _ = ssender.send((img_id, rawpb, "JPEG"));
                                }
                            });
                        }
                    }
                    idcs_trc.borrow_mut().queue.remove(&img_id);
                }
            }
            glib::ControlFlow::Continue
        });
    let handler = Rc::new(RefCell::new(Some(handler_raw)));

    // Window
    let vault_window = Rc::new(gtk4::Window::new());
    vault_window.set_application(Some(application.as_ref()));
    vault_window.set_default_size(720, 480);
    vault_window.set_title(Some(&format!("BaseAES Explorer  -  {vname}")));

    let vault_hbox = gtk4::Box::builder()
        .spacing(6)
        .hexpand(true)
        .vexpand(true)
        .build();

    // Item grid, right side of the vault window
    let item_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

    // Item name
    let item_viewer_titlei = gtk4::Label::new(Some(lang::text::explorer::EXP_ITEMNAME_PH));
    item_viewer_titlei.set_size_request(320, 48);
    item_viewer_titlei.set_hexpand(true);
    let item_viewer_titler = LabelWithInternalText::new(item_viewer_titlei);
    item_grid.attach(&*item_viewer_titler, 1, 1, 2, 1);
    let item_viewer_title = Rc::new(RefCell::new(item_viewer_titler));

    let item_grid_separator = gtk4::Separator::new(gtk4::Orientation::Horizontal);
    item_grid.attach(&item_grid_separator, 1, 2, 3, 1);

    // Item viewer (window / inner grid)
    let iviewer_windowr = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .hexpand(true)
        .vexpand(true)
        .build();
    iviewer_windowr.set_size_request(400, 400);
    item_grid.attach(&iviewer_windowr, 1, 3, 3, 1);
    let item_viewer = Rc::new(iviewer_windowr);

    // Save item button
    let item_save_button = gtk4::Button::with_label(lang::text::explorer::EXP_SAVE_ITEM);
    item_save_button.set_size_request(80, 48);
    item_save_button.set_hexpand(false);

    // Rc suffix: _ras
    let iviewer_title_ras = Rc::clone(&item_viewer_title);
    let iviewer_window_ras = Rc::clone(&item_viewer);
    let changed_ras = Rc::clone(&changed);
    let vdata_ras = Rc::clone(&vdata);
    item_save_button.connect_clicked(move |_| {
        if !iviewer_title_ras.borrow().text().ends_with("*") {
            return;
        }
        // Get item key
        let item_text = iviewer_title_ras.borrow().get_itext().to_owned();
        let item_key = PathBuf::from(item_text.split_once(":").unwrap().0);
        // Get text buffer
        let text = match get_text_from_cwin(iviewer_window_ras.as_ref()) {
            Some(t) => t,
            None => return,
        };
        vdata_ras.borrow_mut().remove(&item_key);
        vdata_ras
            .borrow_mut()
            .insert(item_key, text.as_bytes().to_owned());
        let nochanges_title = iviewer_title_ras.borrow().text().replace("  *", "");
        iviewer_title_ras.borrow_mut().set_text(&nochanges_title);
        changed_ras.borrow_mut().set(true);
    });
    item_grid.attach(&item_save_button, 3, 1, 1, 1);

    // Show file info button
    let show_finfo_button = gtk4::Button::with_label(lang::text::explorer::EXP_SHOW_FINFO);
    show_finfo_button.set_size_request(96, 48);
    show_finfo_button.set_hexpand(false);

    // Rc suffix: _rfi
    let iviewer_title_rfi = Rc::clone(&item_viewer_title);
    let iviewer_rfi = Rc::clone(&item_viewer);
    let vwindow_rfi = Rc::clone(&vault_window);
    let vdata_rfi = Rc::clone(&vdata);
    let app_rfi = Rc::clone(&application);
    show_finfo_button.connect_clicked(move |_| {
        let finfo_window = gtk4::Window::new();
        finfo_window.set_application(Some(app_rfi.as_ref()));
        finfo_window.set_title(Some(lang::text::explorer::EXP_SHOW_FINFO));
        finfo_window.set_default_size(240, 160);
        finfo_window.set_resizable(false);

        let finfo_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

        // Get item key
        let item_text = iviewer_title_rfi.borrow().get_itext().to_owned();
        if !item_text.contains(":") {
            return;
        }
        let (item_key, filename) = match item_text.split_once(":") {
            Some(info) => info,
            None => {
                show_alert(
                    vwindow_rfi.as_ref(),
                    lang::text::generic::ERROR,
                    lang::text::explorer::EXP_MOVE_FINFO_ERR,
                );
                return;
            }
        };
        let mut info = String::new();

        // Get file name
        info.push_str("File name: ");
        info.push_str(filename);
        info.push_str("\n");
        info.push_str("(Internal mgmt ID: ");
        info.push_str(item_key);
        info.push_str(")\n");

        // Get file size
        info.push_str("File size: ");
        let dtext = if let Some(d) = vdata_rfi.borrow().get(&PathBuf::from(item_key)) {
            let dlen = d.len();
            if dlen < 1024 {
                &(dlen.to_string() + " B")
            } else if dlen < 1048576 {
                &(round_below_1(dlen as f64 / 1024 as f64).to_string() + " KiB")
            } else {
                &(round_below_1(dlen as f64 / 1048576 as f64).to_string() + "MiB")
            }
        } else {
            "(Failed to retrieve)"
        };
        info.push_str(dtext);
        info.push_str("\n");

        // Get image size if showing an image
        if let Some(grid) = iviewer_rfi.child().unwrap().first_child()
            && let Some(maybe_image) = grid.first_child()
            && let Ok(image) = maybe_image.dynamic_cast::<gtk4::Picture>()
        {
            let mut size_written = false;
            for class in image.css_classes() {
                if let Some((_, meta)) = class.split_once("_") {
                    let (dim, ityp) = meta.split_once(":").unwrap();
                    info.push_str("\n Image Type: ");
                    info.push_str(ityp);

                    let (imgw, imgh) = dim.split_once("x").unwrap();
                    info.push_str("\nImage Width: ");
                    info.push_str(imgw);
                    info.push_str("px");
                    info.push_str("\nImage Height: ");
                    info.push_str(imgh);
                    info.push_str("px");
                    size_written = true;
                }
            }
            if !size_written {
                info.push_str("\nImage width: (???) px");
                info.push_str("\nImage height: (???) px");
            }
        }

        let desc_label = gtk4::Label::new(Some(&info));
        finfo_grid.attach(&desc_label, 1, 1, 1, 1);

        finfo_window.set_child(Some(&finfo_grid));
        finfo_window.set_modal(true);
        finfo_window.present();
    });
    item_grid.attach(&show_finfo_button, 1, 4, 1, 1);

    // Toggle image view mode button
    let toggle_imgview_button = Rc::new(gtk4::Button::with_label(
        lang::text::explorer::EXP_TOGGLE_IMGVIEW,
    ));
    let toggle_imgview_mode = Rc::new(RefCell::new(ItemContainer::new(ImageViewMode::ImgSize)));
    toggle_imgview_button.set_size_request(96, 48);
    toggle_imgview_button.set_hexpand(false);

    // Rc suffix: _rit
    let iviewer_rit = Rc::clone(&item_viewer);
    let imgviewmode_rit = Rc::clone(&toggle_imgview_mode);
    toggle_imgview_button.connect_clicked(move |_| {
        if let Some(view) = iviewer_rit.child()
            && let Some(should_be_view_grid) = view.first_child()
            && let Ok(view_grid) = should_be_view_grid.dynamic_cast::<gtk4::Grid>()
        {
            if let Some(maybe_image) = view_grid.first_child()
                && let Ok(image_viewer) = maybe_image.dynamic_cast::<gtk4::Picture>()
            {
                let (imgw, imgh) = |imgview: &gtk4::Picture| -> (i32, i32) {
                    for class in imgview.css_classes() {
                        if let Some((_, meta)) = class.split_once("_") {
                            let (imgw_str, imgh_str) =
                                meta.split_once(":").unwrap().0.split_once("x").unwrap();
                            return (
                                i32::from_str_radix(imgw_str, 10).unwrap_or(-1),
                                i32::from_str_radix(imgh_str, 10).unwrap_or(-1),
                            );
                        }
                    }
                    return (-1, -1);
                }(&image_viewer);
                let imgviewmode_curr = imgviewmode_rit.borrow().get().to_owned();
                match imgviewmode_curr {
                    ImageViewMode::ImgSize => {
                        imgviewmode_rit.borrow_mut().set(ImageViewMode::FitWidth);
                        view_grid.set_width_request(iviewer_rit.width() - 24);
                        view_grid.set_height_request(
                            (imgh as f32 * ((iviewer_rit.width() - 24) as f32 / imgw as f32))
                                as i32,
                        );
                    }
                    ImageViewMode::FitWidth => {
                        imgviewmode_rit.borrow_mut().set(ImageViewMode::FitHeight);
                        view_grid.set_width_request(
                            (imgw as f32 * ((iviewer_rit.height() - 24) as f32 / imgh as f32))
                                as i32,
                        );
                        view_grid.set_height_request(iviewer_rit.height() - 24);
                    }
                    ImageViewMode::FitHeight => {
                        imgviewmode_rit.borrow_mut().set(ImageViewMode::ImgSize);
                        view_grid.set_width_request(imgw);
                        view_grid.set_height_request(imgh);
                    }
                };
            }
        }
    });
    item_grid.attach(toggle_imgview_button.as_ref(), 2, 4, 1, 1);

    // Control grid, left side of the vault window
    let control_grid = grid_builder(6, 12, 12, 12, 8, 8).vexpand(true).build();

    // Path viewer
    let vexplorer_pathi = gtk4::Entry::builder().text("/").editable(false).build();
    vexplorer_pathi.add_css_class("normal");
    vexplorer_pathi.set_size_request(240, 40);
    let vexplorer_pathr = EntryWithInternalText::new(vexplorer_pathi, "/".to_owned());
    control_grid.attach(&*vexplorer_pathr, 1, 3, 2, 1);
    let vexplorer_path = Rc::new(RefCell::new(vexplorer_pathr));

    // Item list
    let vault_scroll = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .vexpand(true)
        .build();
    vault_scroll.set_size_request(240, 280);
    let vault_file_list = Rc::new(gtk4::ListBox::new());
    vault_scroll.set_child(Some(vault_file_list.as_ref()));
    control_grid.attach(&vault_scroll, 1, 4, 2, 1);

    // Add file or Import file
    let vault_add_file = gtk4::MenuButton::builder()
        .direction(gtk4::ArrowType::Down)
        .label(lang::text::explorer::EXP_NEW_FILE)
        .build();
    vault_add_file.set_size_request(80, 48);

    let vaf_popover = Rc::new(
        gtk4::Popover::builder()
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .vexpand(true)
            .halign(gtk4::Align::Start)
            .build(),
    );

    let vaf_vbox = gtk4::Box::builder()
        .spacing(6)
        .hexpand(true)
        .vexpand(true)
        .orientation(gtk4::Orientation::Vertical)
        .build();

    let vaf_createb = gtk4::Button::with_label(lang::text::explorer::EXP_CREATE_FILE);
    vaf_createb.set_size_request(96, 40);

    // Rc suffix: _rcf
    let iviewer_title_rcf = Rc::clone(&item_viewer_title);
    let vfilelist_rcf = Rc::clone(&vault_file_list);
    let vexpath_rcf = Rc::clone(&vexplorer_path);
    let iviewer_rcf = Rc::clone(&item_viewer);
    let popover_rcf = Rc::clone(&vaf_popover);
    let changed_rcf = Rc::clone(&changed);
    let app_rcf = Rc::clone(&application);
    let vindex_rcf = Rc::clone(&vindex);
    let vdata_rcf = Rc::clone(&vdata);
    let idcs_rcf = Rc::clone(&idcs);
    vaf_createb.connect_clicked(move |_| {
        popover_rcf.popdown();
        let vcf_window = Rc::new(gtk4::Window::new());
        vcf_window.set_title(Some(lang::text::explorer::EXP_CREATE_TITLE));
        vcf_window.set_application(Some(app_rcf.as_ref()));
        vcf_window.set_size_request(180, 72);
        vcf_window.set_modal(true);

        let vcf_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

        let vcf_title = gtk4::Label::new(Some(lang::text::explorer::EXP_CREATE_DESC));
        vcf_grid.attach(&vcf_title, 1, 1, 2, 1);

        let vcf_filename = gtk4::Entry::new();
        vcf_filename.set_size_request(160, 28);
        vcf_grid.attach(&vcf_filename, 1, 2, 1, 1);

        let vcf_ok_button = gtk4::Button::with_label("OK");
        vcf_ok_button.set_size_request(64, 28);

        // Rc suffix: _rcf2
        let iviewer_title_rcf2 = Rc::clone(&iviewer_title_rcf);
        let vfilelist_rcf2 = Rc::clone(&vfilelist_rcf);
        let vcf_window_rcf2 = Rc::clone(&vcf_window);
        let iviewer_rcf2 = Rc::clone(&iviewer_rcf);
        let vexpath_rcf2 = Rc::clone(&vexpath_rcf);
        let changed_rcf2 = Rc::clone(&changed_rcf);
        let vindex_rcf2 = Rc::clone(&vindex_rcf);
        let vdata_rcf2 = Rc::clone(&vdata_rcf);
        let idcs_rcf2 = Rc::clone(&idcs_rcf);
        let app_rcf2 = Rc::clone(&app_rcf);
        vcf_ok_button.connect_clicked(move |_| {
            // File name filtering
            let filename = vcf_filename.text().to_string();
            if let Err(emsg) = filename_check(&filename) {
                show_alert(vcf_window_rcf2.as_ref(), lang::text::generic::ERROR, &emsg);
                return;
            }

            // Filename duplication check
            let vpath = vexpath_rcf2.borrow().get_itext().to_owned();
            for (ipath, name) in &*vindex_rcf2.borrow() {
                if !ipath.starts_with(&vpath) {
                    continue;
                }
                // Exclude subdirectory here
                if ipath.parent().unwrap_or(&PathBuf::from("/")) != &vpath {
                    continue;
                }

                if name == &filename {
                    show_alert(
                        vcf_window_rcf2.as_ref(),
                        lang::text::generic::ALERT,
                        lang::text::tools::FILENAME_DUPLICATED,
                    );
                    return;
                }
            }

            let ipath_rc = Rc::new(vault_append_file(
                Rc::clone(&vexpath_rcf2),
                filename,
                None,
                Rc::clone(&vindex_rcf2),
                Rc::clone(&vdata_rcf2),
            ));
            changed_rcf2.borrow_mut().set(true);

            // Reload file
            loop {
                let dwidget = match vfilelist_rcf2.last_child() {
                    Some(w) => w,
                    None => break,
                };
                vfilelist_rcf2.remove(&dwidget);
            }
            for button in get_files_from_vpath(
                Rc::clone(&app_rcf2),
                Rc::clone(&vfilelist_rcf2),
                Rc::clone(&idcs_rcf2),
                Rc::clone(&vindex_rcf2),
                Rc::clone(&vdata_rcf2),
                PathBuf::from(vexpath_rcf2.borrow().get_itext()),
                Rc::clone(&iviewer_title_rcf2),
                Rc::clone(&iviewer_rcf2),
                Rc::clone(&vexpath_rcf2),
            ) {
                vfilelist_rcf2.append(&*button);
            }

            vcf_window_rcf2.close();
            open_other_file(
                Rc::clone(&app_rcf2),
                Rc::clone(&iviewer_rcf2),
                Rc::clone(&iviewer_title_rcf2),
                Rc::clone(&vindex_rcf2),
                Rc::clone(&vdata_rcf2),
                ipath_rc,
                Rc::clone(&idcs_rcf2),
            );
        });
        vcf_grid.attach(&vcf_ok_button, 2, 2, 1, 1);

        vcf_window.set_child(Some(&vcf_grid));
        vcf_window.present();
    });
    vaf_vbox.append(&vaf_createb);

    let vaf_importb = gtk4::Button::with_label(lang::text::explorer::EXP_IMPORT_FILE);
    vaf_importb.set_size_request(96, 40);

    // Rc suffix: _rif
    let iviewer_title_rif = Rc::clone(&item_viewer_title);
    let vfilelist_rif = Rc::clone(&vault_file_list);
    let vexpath_rif = Rc::clone(&vexplorer_path);
    let vwindow_rif = Rc::clone(&vault_window);
    let iviewer_rif = Rc::clone(&item_viewer);
    let popover_rif = Rc::clone(&vaf_popover);
    let changed_rif = Rc::clone(&changed);
    let app_rif = Rc::clone(&application);
    let vindex_rif = Rc::clone(&vindex);
    let vdata_rif = Rc::clone(&vdata);
    let idcs_rif = Rc::clone(&idcs);
    vaf_importb.connect_clicked(move |_| {
        popover_rif.popdown();
        let file_dialog = gtk4::FileDialog::builder()
            .modal(true)
            .title(lang::text::explorer::EXP_IMPORT_TITLE)
            .build();

        // Rc suffix: _rif2
        let changed_rif2 = Rc::clone(&changed_rif);
        let vindex_rif2 = Rc::clone(&vindex_rif);
        let vdata_rif2 = Rc::clone(&vdata_rif);
        let idcs_rif2 = Rc::clone(&idcs_rif);
        let app_rif2 = Rc::clone(&app_rif);
        let iviewer_title_rif2 = Rc::clone(&iviewer_title_rif);
        let vfilelist_rif2 = Rc::clone(&vfilelist_rif);
        let vwindow_rifp = Rc::clone(&vwindow_rif);
        let vwindow_rif2 = Rc::clone(&vwindow_rif);
        let iviewer_rif2 = Rc::clone(&iviewer_rif);
        let vexpath_rif2 = Rc::clone(&vexpath_rif);
        file_dialog.open(
            Some(vwindow_rifp.as_ref()),
            gtk4::gio::Cancellable::NONE,
            move |gfile| {
                if gfile.is_err() {
                    return;
                }
                // Get path and read as binary from fs::read
                let filepath = match urlencoding::decode(&gfile.unwrap().uri()[7..]) {
                    Ok(s) => PathBuf::from(s.into_owned()),
                    Err(_) => return,
                };
                let fdata = match fs::read(&filepath) {
                    Ok(b) => Rc::new(b),
                    Err(_) => {
                        show_alert(
                            vwindow_rif2.as_ref(),
                            lang::text::generic::ERROR,
                            lang::text::explorer::EXP_IMPORT_OPEN_ERROR,
                        );
                        return;
                    }
                };

                // File name filtering
                let ofilename = if filepath.file_name().is_none() {
                    None
                } else {
                    filepath.file_name().unwrap().to_str()
                };
                if ofilename.is_none() {
                    show_alert(
                        vwindow_rif2.as_ref(),
                        lang::text::generic::ERROR,
                        lang::text::explorer::EXP_IMPORT_NAME_INVALID,
                    );
                    return;
                };
                let mut filename = ofilename.unwrap().to_string();
                if let Err(emsg) = filename_check(&filename) {
                    show_alert(vwindow_rif2.as_ref(), lang::text::generic::ERROR, &emsg);
                    return;
                }

                // Filename duplication check
                let vpath = vexpath_rif2.borrow().get_itext().to_owned();
                let mut duplicated: bool;
                loop {
                    duplicated = false;
                    for (ipath, name) in &*vindex_rif2.borrow() {
                        if !ipath.starts_with(&vpath) {
                            continue;
                        }
                        // Exclude subdirectory here
                        if ipath.parent().unwrap_or(&PathBuf::from("/")) != &vpath {
                            continue;
                        }

                        if name == &filename {
                            duplicated = true;
                        }
                    }
                    if duplicated {
                        if filename.contains(".") {
                            let (fname, ext) = filename.split_once(".").unwrap();
                            filename = fname.to_owned()
                                + lang::text::explorer::EXP_IMPORT_DUPLICATED_NAME
                                + "."
                                + ext;
                        } else {
                            filename = filename + lang::text::explorer::EXP_IMPORT_DUPLICATED_NAME;
                        }
                    } else {
                        break;
                    }
                }

                // Append file info
                vault_append_file(
                    Rc::clone(&vexpath_rif2),
                    filename,
                    Some(fdata.as_ref()),
                    Rc::clone(&vindex_rif2),
                    Rc::clone(&vdata_rif2),
                );
                changed_rif2.borrow_mut().set(true);

                // Reload file
                loop {
                    let dwidget = match vfilelist_rif2.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    vfilelist_rif2.remove(&dwidget);
                }
                for button in get_files_from_vpath(
                    Rc::clone(&app_rif2),
                    Rc::clone(&vfilelist_rif2),
                    Rc::clone(&idcs_rif2),
                    Rc::clone(&vindex_rif2),
                    Rc::clone(&vdata_rif2),
                    PathBuf::from(vexpath_rif2.borrow().get_itext()),
                    Rc::clone(&iviewer_title_rif2),
                    Rc::clone(&iviewer_rif2),
                    Rc::clone(&vexpath_rif2),
                ) {
                    vfilelist_rif2.append(&*button);
                }
            },
        );
    });
    vaf_vbox.append(&vaf_importb);

    let vaf_b64importb = gtk4::Button::with_label(lang::text::explorer::EXP_IMPORT_BASE64);
    vaf_importb.set_size_request(96, 40);

    // Rc suffix: _rib
    let iviewer_title_rib = Rc::clone(&item_viewer_title);
    let vfilelist_rib = Rc::clone(&vault_file_list);
    let vexpath_rib = Rc::clone(&vexplorer_path);
    let iviewer_rib = Rc::clone(&item_viewer);
    let popover_rib = Rc::clone(&vaf_popover);
    let changed_rib = Rc::clone(&changed);
    let app_rib = Rc::clone(&application);
    let vindex_rib = Rc::clone(&vindex);
    let vdata_rib = Rc::clone(&vdata);
    let idcs_rib = Rc::clone(&idcs);
    vaf_b64importb.connect_clicked(move |_| {
        popover_rib.popdown();
        let b64input_window = Rc::new(gtk4::Window::new());
        b64input_window.set_application(Some(app_rib.as_ref()));
        b64input_window.set_title(Some(lang::text::explorer::EXP_IMPORT_BASE64));
        b64input_window.set_default_size(320, 64);
        b64input_window.set_modal(true);

        let b64input_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

        let b64input_fntitle = gtk4::Label::new(Some(lang::text::explorer::EXP_CREATE_DESC));
        b64input_grid.attach(&b64input_fntitle, 1, 1, 1, 1);

        let b64input_filename = gtk4::Entry::new();
        b64input_filename.set_size_request(160, 28);
        b64input_grid.attach(&b64input_filename, 2, 1, 3, 1);

        let b64input_b64title =
            gtk4::Label::new(Some(lang::text::explorer::EXP_IMPORT_BASE64_DESC));
        b64input_grid.attach(&b64input_b64title, 1, 2, 1, 1);

        let b64input_entry = gtk4::Entry::new();
        b64input_grid.attach(&b64input_entry, 1, 3, 4, 1);

        let b64input_desc = gtk4::Label::new(Some(lang::text::explorer::EXP_IMPORT_BASE64_EX));
        b64input_grid.attach(&b64input_desc, 1, 4, 3, 3);

        let b64input_okbtn = gtk4::Button::with_label("OK");

        // Rc suffix: _rib2
        let changed_rib2 = Rc::clone(&changed_rib);
        let vindex_rib2 = Rc::clone(&vindex_rib);
        let vdata_rib2 = Rc::clone(&vdata_rib);
        let idcs_rib2 = Rc::clone(&idcs_rib);
        let app_rib2 = Rc::clone(&app_rib);
        let iviewer_title_rib2 = Rc::clone(&iviewer_title_rib);
        let b64window_rib2 = Rc::clone(&b64input_window);
        let vfilelist_rib2 = Rc::clone(&vfilelist_rib);
        let iviewer_rib2 = Rc::clone(&iviewer_rib);
        let vexpath_rib2 = Rc::clone(&vexpath_rib);
        b64input_okbtn.connect_clicked(move |_| {
            let text = b64input_entry.text();
            let b64bin_res = BASE64_STANDARD.decode(if text.contains(",") {
                text.rsplit_once(",").unwrap().1
            } else {
                &text
            });
            if let Ok(b64bin) = b64bin_res {
                // File name filtering
                let filename = b64input_filename.text().to_string();
                if let Err(emsg) = filename_check(&filename) {
                    show_alert(b64window_rib2.as_ref(), lang::text::generic::ERROR, &emsg);
                    return;
                }

                // Filename duplication check
                let vpath = vexpath_rib2.borrow().get_itext().to_owned();
                for (ipath, name) in &*vindex_rib2.borrow() {
                    if !ipath.starts_with(&vpath) {
                        continue;
                    }
                    // Exclude subdirectory here
                    if ipath.parent().unwrap_or(&PathBuf::from("/")) != &vpath {
                        continue;
                    }

                    if name == &filename {
                        show_alert(
                            b64window_rib2.as_ref(),
                            lang::text::generic::ALERT,
                            lang::text::tools::FILENAME_DUPLICATED,
                        );
                        return;
                    }
                }

                // Append file info
                let ipath_rc = Rc::new(vault_append_file(
                    Rc::clone(&vexpath_rib2),
                    filename,
                    Some(&b64bin),
                    Rc::clone(&vindex_rib2),
                    Rc::clone(&vdata_rib2),
                ));
                changed_rib2.borrow_mut().set(true);
                b64window_rib2.close();

                // Reload file
                loop {
                    let dwidget = match vfilelist_rib2.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    vfilelist_rib2.remove(&dwidget);
                }
                for button in get_files_from_vpath(
                    Rc::clone(&app_rib2),
                    Rc::clone(&vfilelist_rib2),
                    Rc::clone(&idcs_rib2),
                    Rc::clone(&vindex_rib2),
                    Rc::clone(&vdata_rib2),
                    PathBuf::from(vexpath_rib2.borrow().get_itext()),
                    Rc::clone(&iviewer_title_rib2),
                    Rc::clone(&iviewer_rib2),
                    Rc::clone(&vexpath_rib2),
                ) {
                    vfilelist_rib2.append(&*button);
                }

                open_other_file(
                    Rc::clone(&app_rib2),
                    Rc::clone(&iviewer_rib2),
                    Rc::clone(&iviewer_title_rib2),
                    Rc::clone(&vindex_rib2),
                    Rc::clone(&vdata_rib2),
                    ipath_rc,
                    Rc::clone(&idcs_rib2),
                );
            } else {
                show_alert(
                    b64window_rib2.as_ref(),
                    lang::text::generic::ERROR,
                    lang::text::explorer::EXP_IMPORT_BASE64_INVALID,
                );
            }
        });
        b64input_grid.attach(&b64input_okbtn, 4, 4, 1, 1);

        b64input_window.set_child(Some(&b64input_grid));
        b64input_window.present();
    });
    vaf_vbox.append(&vaf_b64importb);

    vaf_popover.set_child(Some(&vaf_vbox));
    vault_add_file.set_popover(Some(vaf_popover.as_ref()));
    control_grid.attach(&vault_add_file, 1, 1, 1, 1);

    // Add folder
    let vault_add_folder = gtk4::Button::with_label(lang::text::explorer::EXP_NEW_FOLDER);
    vault_add_folder.set_size_request(80, 48);

    // Rc suffix: _rad
    let changed_rad = Rc::clone(&changed);
    let app_rad = Rc::clone(&application);
    let vindex_rad = Rc::clone(&vindex);
    let vdata_rad = Rc::clone(&vdata);
    let idcs_rad = Rc::clone(&idcs);
    let iviewer_title_rad = Rc::clone(&item_viewer_title);
    let vfilelist_rad = Rc::clone(&vault_file_list);
    let vexpath_rad = Rc::clone(&vexplorer_path);
    let iviewer_rad = Rc::clone(&item_viewer);
    vault_add_folder.connect_clicked(move |_| {
        let vad_window = Rc::new(gtk4::Window::new());
        vad_window.set_title(Some(lang::text::explorer::EXP_NEW_FOLDER_TITLE));
        vad_window.set_application(Some(app_rad.as_ref()));
        vad_window.set_modal(true);
        let vad_grid = grid_builder(6, 12, 12, 12, 12, 8).build();

        let vad_title = gtk4::Label::new(Some(lang::text::explorer::EXP_NEW_FOLDER_DESC));
        vad_grid.attach(&vad_title, 1, 1, 2, 1);

        let vad_dirname = gtk4::Entry::new();
        vad_dirname.set_size_request(160, 28);
        vad_grid.attach(&vad_dirname, 1, 2, 1, 1);

        let vad_ok_button = gtk4::Button::with_label("OK");
        vad_ok_button.set_size_request(64, 28);

        // Rc suffix: _rad2
        let changed_rad2 = Rc::clone(&changed_rad);
        let vindex_rad2 = Rc::clone(&vindex_rad);
        let vdata_rad2 = Rc::clone(&vdata_rad);
        let idcs_rad2 = Rc::clone(&idcs_rad);
        let app_rad2 = Rc::clone(&app_rad);
        let iviewer_title_rad2 = Rc::clone(&iviewer_title_rad);
        let vfilelist_rad2 = Rc::clone(&vfilelist_rad);
        let vad_window_rad2 = Rc::clone(&vad_window);
        let iviewer_rad2 = Rc::clone(&iviewer_rad);
        let vexpath_rad2 = Rc::clone(&vexpath_rad);
        vad_ok_button.connect_clicked(move |_| {
            // Folder name filtering
            let mut dirname = vad_dirname.text().to_string();
            if let Err(emsg) = dirname_check(&dirname) {
                show_alert(vad_window_rad2.as_ref(), lang::text::generic::ERROR, &emsg);
                return;
            }
            dirname.push_str("/");

            // Folder name duplication check
            let vpath = vexpath_rad2.borrow().get_itext().to_owned();
            for (ipath, name) in &*vindex_rad2.borrow() {
                if !(ipath.starts_with(&vpath) && name.ends_with("/")) {
                    continue;
                }
                // Exclude subdirectory here
                if ipath.parent().unwrap_or(&PathBuf::from("/")) != &vpath {
                    continue;
                }

                if name == &dirname {
                    show_alert(
                        vad_window_rad2.as_ref(),
                        lang::text::generic::ALERT,
                        lang::text::explorer::EXP_FOLDERNAME_DUPLICATED,
                    );
                    return;
                }
            }

            // Append folder info
            vault_append_folder(Rc::clone(&vexpath_rad2), dirname, Rc::clone(&vindex_rad2));
            changed_rad2.borrow_mut().set(true);

            // Reload file
            loop {
                let dwidget = match vfilelist_rad2.last_child() {
                    Some(w) => w,
                    None => break,
                };
                vfilelist_rad2.remove(&dwidget);
            }
            for button in get_files_from_vpath(
                Rc::clone(&app_rad2),
                Rc::clone(&vfilelist_rad2),
                Rc::clone(&idcs_rad2),
                Rc::clone(&vindex_rad2),
                Rc::clone(&vdata_rad2),
                PathBuf::from(vexpath_rad2.borrow().get_itext()),
                Rc::clone(&iviewer_title_rad2),
                Rc::clone(&iviewer_rad2),
                Rc::clone(&vexpath_rad2),
            ) {
                vfilelist_rad2.append(&*button);
            }

            vad_window_rad2.close();
        });
        vad_grid.attach(&vad_ok_button, 2, 2, 1, 1);

        vad_window.set_child(Some(&vad_grid));
        vad_window.present();
    });
    control_grid.attach(&vault_add_folder, 2, 1, 1, 1);

    // Rename item
    let vault_rename_item = gtk4::Button::with_label(lang::text::explorer::EXP_RENAME_ITEM);
    vault_rename_item.set_size_request(80, 48);

    // Rc suffix: _rri
    let changed_rri = Rc::clone(&changed);
    let app_rri = Rc::clone(&application);
    let vindex_rri = Rc::clone(&vindex);
    let vdata_rri = Rc::clone(&vdata);
    let idcs_rri = Rc::clone(&idcs);
    let iviewer_title_rri = Rc::clone(&item_viewer_title);
    let vfilelist_rri = Rc::clone(&vault_file_list);
    let vexpath_rri = Rc::clone(&vexplorer_path);
    let vwindow_rri = Rc::clone(&vault_window);
    let iviewer_rri = Rc::clone(&item_viewer);
    vault_rename_item.connect_clicked(move |_| {
        let viewer_id = iviewer_title_rri.borrow().get_itext().to_owned();
        let (vfileid, vtitle) = match viewer_id.split_once(":") {
            Some(viewerid_sp) => viewerid_sp,
            None => {
                show_alert(
                    vwindow_rri.as_ref(),
                    lang::text::generic::ALERT,
                    lang::text::explorer::EXP_RENAME_NOSEL,
                );
                return;
            }
        };
        let vri_window = Rc::new(gtk4::Window::new());
        vri_window.set_title(Some(lang::text::explorer::EXP_RENAME_TITLE));
        vri_window.set_application(Some(app_rri.as_ref()));
        vri_window.set_modal(true);
        let vri_grid = grid_builder(6, 12, 12, 12, 12, 8).build();

        let vri_title = gtk4::Label::new(Some(
            &(lang::text::explorer::EXP_RENAME_DESC1.to_owned()
                + vtitle
                + lang::text::explorer::EXP_RENAME_DESC2),
        ));
        vri_title.add_css_class("title");
        vri_grid.attach(&vri_title, 1, 1, 2, 1);

        let vri_nameboxr = gtk4::Entry::new();
        vri_nameboxr.buffer().set_text(vtitle);
        vri_nameboxr.set_size_request(144, 28);
        vri_grid.attach(&vri_nameboxr, 1, 2, 1, 1);
        let vri_namebox = Rc::new(vri_nameboxr);

        let vri_ok_button = gtk4::Button::with_label("OK");
        vri_ok_button.set_size_request(40, 28);

        // Rc suffix: _rri2
        let changed_rri2 = Rc::clone(&changed_rri);
        let vindex_rri2 = Rc::clone(&vindex_rri);
        let vdata_rri2 = Rc::clone(&vdata_rri);
        let idcs_rri2 = Rc::clone(&idcs_rri);
        let app_rri2 = Rc::clone(&app_rri);
        let iviewer_title_rri2 = Rc::clone(&iviewer_title_rri);
        let vfileid_rri2 = Rc::new(PathBuf::from(vfileid));
        let vri_namebox_rri2 = Rc::clone(&vri_namebox);
        let vri_window_rri2 = Rc::clone(&vri_window);
        let vexpath_rri2 = Rc::clone(&vexpath_rri);
        let iviewer_rri2 = Rc::clone(&iviewer_rri);
        let prev_name = vtitle.to_owned();
        let vfilelist_rri2 = Rc::clone(&vfilelist_rri);
        vri_ok_button.connect_clicked(move |_| {
            let newname = vri_namebox_rri2.text();

            // Filename duplication check
            let vpath = vexpath_rri2.borrow().get_itext().to_owned();
            for (ipath, name) in &*vindex_rri2.borrow() {
                if !ipath.starts_with(&vpath) {
                    continue;
                }
                // Exclude subdirectory here
                if ipath.parent().unwrap_or(&PathBuf::from("/")) != &vpath {
                    continue;
                }

                if &newname == &prev_name {
                    vri_window_rri2.close();
                    return;
                } else if name == &newname {
                    show_alert(
                        vri_window_rri2.as_ref(),
                        lang::text::generic::ALERT,
                        lang::text::tools::FILENAME_DUPLICATED,
                    );
                    return;
                }
            }

            let mut vindex_b = vindex_rri2.borrow_mut();

            let rmres = vindex_b.remove_entry(vfileid_rri2.as_ref());
            if rmres.is_none() {
                show_alert(
                    vri_window_rri2.as_ref(),
                    lang::text::generic::ERROR,
                    lang::text::explorer::EXP_RENAME_NOTFOUND,
                );
                return;
            }

            vindex_b.insert(rmres.unwrap().0, newname.to_string());
            drop(vindex_b);
            changed_rri2.borrow_mut().set(true);

            loop {
                let dwidget = match vfilelist_rri2.last_child() {
                    Some(w) => w,
                    None => break,
                };
                vfilelist_rri2.remove(&dwidget);
            }
            for button in get_files_from_vpath(
                Rc::clone(&app_rri2),
                Rc::clone(&vfilelist_rri2),
                Rc::clone(&idcs_rri2),
                Rc::clone(&vindex_rri2),
                Rc::clone(&vdata_rri2),
                PathBuf::from(vexpath_rri2.borrow().get_itext()),
                Rc::clone(&iviewer_title_rri2),
                Rc::clone(&iviewer_rri2),
                Rc::clone(&vexpath_rri2),
            ) {
                vfilelist_rri2.append(&*button);
            }

            // IText: PATH:TITLE^
            // Text: [ TITLE ] or TITLE
            let itext = iviewer_title_rri2.borrow().get_itext().to_owned();
            let curr_title = itext.split_once(":").unwrap().1;
            if iviewer_title_rri2.borrow().text().starts_with("[ ") {
                iviewer_title_rri2
                    .borrow_mut()
                    .set_text(&format!("[ {newname} ]"));
            } else {
                iviewer_title_rri2.borrow_mut().set_text(&newname);
            }
            iviewer_title_rri2
                .borrow_mut()
                .set_itext(itext.replace(curr_title, &format!("{newname}")));

            vri_window_rri2.close();
        });
        vri_grid.attach(&vri_ok_button, 2, 2, 1, 1);

        vri_window.set_child(Some(&vri_grid));
        vri_window.present();
    });
    control_grid.attach(&vault_rename_item, 1, 2, 1, 1);

    // Move, Export, Delete item or Reload
    let vault_other_ctrl = Rc::new(
        gtk4::MenuButton::builder()
            .direction(gtk4::ArrowType::Down)
            .label(lang::text::explorer::EXP_MORE_CTRL)
            .build(),
    );
    vault_other_ctrl.set_size_request(80, 48);

    let voc_popover = gtk4::Popover::builder()
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(6)
        .margin_end(6)
        .vexpand(true)
        .build();

    let voc_grid = grid_builder(6, 12, 12, 12, 8, 8).build();

    // Move item
    let voc_move_item = gtk4::Button::with_label(lang::text::explorer::EXP_MOVE_ITEM);
    voc_move_item.set_size_request(96, 40);

    // Rc suffix: _rom
    let changed_rom = Rc::clone(&changed);
    let vindex_rom = Rc::clone(&vindex);
    let vdata_rom = Rc::clone(&vdata);
    let idcs_rom = Rc::clone(&idcs);
    let app_rom = Rc::clone(&application);
    let iviewer_title_rom = Rc::clone(&item_viewer_title);
    let voc_button_rom = Rc::clone(&vault_other_ctrl);
    let vfilelist_rom = Rc::clone(&vault_file_list);
    let vexpath_rom = Rc::clone(&vexplorer_path);
    let vwindow_rom = Rc::clone(&vault_window);
    let iviewer_rom = Rc::clone(&item_viewer);
    voc_move_item.connect_clicked(move |_| {
        voc_button_rom.popdown();
        if vexpath_rom.borrow().text() == "/" {
            vault_move_file(
                Rc::clone(&app_rom),
                Rc::clone(&idcs_rom),
                Rc::clone(&changed_rom),
                Rc::clone(&vindex_rom),
                Rc::clone(&vdata_rom),
                Rc::clone(&vwindow_rom),
                Rc::clone(&vfilelist_rom),
                Rc::clone(&iviewer_rom),
                Rc::clone(&vexpath_rom),
                Rc::clone(&iviewer_title_rom),
            );
        } else if iviewer_title_rom.borrow().get_itext() == "" {
            vault_move_dir(
                Rc::clone(&app_rom),
                Rc::clone(&idcs_rom),
                Rc::clone(&changed_rom),
                Rc::clone(&vindex_rom),
                Rc::clone(&vdata_rom),
                Rc::clone(&vfilelist_rom),
                Rc::clone(&iviewer_rom),
                Rc::clone(&vexpath_rom),
                Rc::clone(&iviewer_title_rom),
            );
        } else {
            // Not sure the user wants to move file or dir
            let vmi_window = Rc::new(gtk4::Window::new());
            vmi_window.set_title(Some(lang::text::explorer::EXP_MOVE_SEL_TITLE));
            vmi_window.set_application(Some(app_rom.as_ref()));
            vmi_window.set_size_request(224, 56);
            vmi_window.set_resizable(false);
            let vmi_hbox = gtk4::Box::builder()
                .margin_top(6)
                .margin_bottom(6)
                .margin_start(6)
                .margin_end(6)
                .halign(gtk4::Align::Center)
                .orientation(gtk4::Orientation::Horizontal)
                .spacing(6)
                .build();

            let vmi_mfile = gtk4::Button::with_label(lang::text::explorer::EXP_MOVE_SEL_FILE);
            vmi_mfile.set_size_request(96, 40);

            // Rc suffix: _romsf
            let changed_romsf = Rc::clone(&changed_rom);
            let vindex_romsf = Rc::clone(&vindex_rom);
            let vdata_romsf = Rc::clone(&vdata_rom);
            let idcs_romsf = Rc::clone(&idcs_rom);
            let app_romsf = Rc::clone(&app_rom);
            let iviewer_title_romsf = Rc::clone(&iviewer_title_rom);
            let vfilelist_romsf = Rc::clone(&vfilelist_rom);
            let vmi_window_romsf = Rc::clone(&vmi_window);
            let vwindow_romsf = Rc::clone(&vwindow_rom);
            let vexpath_romsf = Rc::clone(&vexpath_rom);
            let iviewer_romsf = Rc::clone(&iviewer_rom);
            vmi_mfile.connect_clicked(move |_| {
                vmi_window_romsf.close();
                vault_move_file(
                    Rc::clone(&app_romsf),
                    Rc::clone(&idcs_romsf),
                    Rc::clone(&changed_romsf),
                    Rc::clone(&vindex_romsf),
                    Rc::clone(&vdata_romsf),
                    Rc::clone(&vwindow_romsf),
                    Rc::clone(&vfilelist_romsf),
                    Rc::clone(&iviewer_romsf),
                    Rc::clone(&vexpath_romsf),
                    Rc::clone(&iviewer_title_romsf),
                );
            });
            vmi_hbox.append(&vmi_mfile);

            let vmi_mdir = gtk4::Button::with_label(lang::text::explorer::EXP_MOVE_SEL_DIR);
            vmi_mdir.set_size_request(96, 40);

            // Rc suffix: _romsd
            let changed_romsd = Rc::clone(&changed_rom);
            let vindex_romsd = Rc::clone(&vindex_rom);
            let vdata_romsd = Rc::clone(&vdata_rom);
            let idcs_romsd = Rc::clone(&idcs_rom);
            let app_romsd = Rc::clone(&app_rom);
            let iviewer_title_romsd = Rc::clone(&iviewer_title_rom);
            let vfilelist_romsd = Rc::clone(&vfilelist_rom);
            let vmi_window_romsd = Rc::clone(&vmi_window);
            let vexpath_romsd = Rc::clone(&vexpath_rom);
            let iviewer_romsd = Rc::clone(&iviewer_rom);
            vmi_mdir.connect_clicked(move |_| {
                vmi_window_romsd.close();
                vault_move_dir(
                    Rc::clone(&app_romsd),
                    Rc::clone(&idcs_romsd),
                    Rc::clone(&changed_romsd),
                    Rc::clone(&vindex_romsd),
                    Rc::clone(&vdata_romsd),
                    Rc::clone(&vfilelist_romsd),
                    Rc::clone(&iviewer_romsd),
                    Rc::clone(&vexpath_romsd),
                    Rc::clone(&iviewer_title_romsd),
                );
            });
            vmi_hbox.append(&vmi_mdir);

            vmi_window.set_child(Some(&vmi_hbox));
            vmi_window.set_modal(true);
            vmi_window.present();
        }
    });
    voc_grid.attach(&voc_move_item, 1, 1, 1, 1);

    // Reload
    let voc_reload_button = gtk4::Button::with_label(lang::text::explorer::EXP_RELOAD_DIR);
    voc_reload_button.set_size_request(96, 40);

    // Rc suffix: _ror
    let app_ror = Rc::clone(&application);
    let vindex_ror = Rc::clone(&vindex);
    let vdata_ror = Rc::clone(&vdata);
    let idcs_ror = Rc::clone(&idcs);
    let iviewer_title_ror = Rc::clone(&item_viewer_title);
    let voc_button_ror = Rc::clone(&vault_other_ctrl);
    let vfilelist_ror = Rc::clone(&vault_file_list);
    let vexpath_ror = Rc::clone(&vexplorer_path);
    let iviewer_ror = Rc::clone(&item_viewer);
    voc_reload_button.connect_clicked(move |_| {
        loop {
            let dwidget = match vfilelist_ror.last_child() {
                Some(w) => w,
                None => break,
            };
            vfilelist_ror.remove(&dwidget);
        }
        for button in get_files_from_vpath(
            Rc::clone(&app_ror),
            Rc::clone(&vfilelist_ror),
            Rc::clone(&idcs_ror),
            Rc::clone(&vindex_ror),
            Rc::clone(&vdata_ror),
            PathBuf::from(vexpath_ror.borrow().get_itext()),
            Rc::clone(&iviewer_title_ror),
            Rc::clone(&iviewer_ror),
            Rc::clone(&vexpath_ror),
        ) {
            vfilelist_ror.append(&*button);
        }
        voc_button_ror.popdown();
    });
    voc_grid.attach(&voc_reload_button, 2, 1, 1, 1);

    // Export
    let voc_export_item = gtk4::Button::with_label(lang::text::explorer::EXP_EXPORT_ITEM);
    voc_export_item.set_size_request(96, 40);

    // Rc suffix: _roe
    let iviewer_title_roe = Rc::clone(&item_viewer_title);
    let voc_button_roe = Rc::clone(&vault_other_ctrl);
    let vwindow_roe = Rc::clone(&vault_window);
    let vdata_roe = Rc::clone(&vdata);
    voc_export_item.connect_clicked(move |_| {
        voc_button_roe.popdown();
        let filename = iviewer_title_roe.borrow().get_itext().to_owned();
        let (fileid_str, title) = match filename.split_once(":") {
            Some(f) => f,
            None => {
                show_alert(
                    vwindow_roe.as_ref(),
                    lang::text::generic::ERROR,
                    lang::text::explorer::EXP_EXPORT_NOSEL,
                );
                return;
            }
        };

        // File save window
        let file_dialog = gtk4::FileDialog::builder()
            .modal(true)
            .title(lang::text::explorer::EXP_EXPORT_TITLE)
            .build();
        file_dialog.set_initial_name(Some(title));

        // Rc suffix: _roes
        let vwindow_roes = Rc::clone(&vwindow_roe);
        let vdata_roes = Rc::clone(&vdata_roe);
        let fileid = PathBuf::from(fileid_str);
        file_dialog.save(
            Some(vwindow_roe.as_ref()),
            gtk4::gio::Cancellable::NONE,
            move |raw_gfile| {
                if raw_gfile.is_err() {
                    show_alert(
                        vwindow_roes.as_ref(),
                        lang::text::generic::ERROR,
                        lang::text::explorer::EXP_IMPORT_OPEN_ERROR,
                    );
                    return;
                }
                let file_path = match urlencoding::decode(&raw_gfile.unwrap().uri()[7..]) {
                    Ok(s) => s.into_owned(),
                    Err(_) => return,
                };

                let mut file = match fs::File::create(&file_path) {
                    Ok(f) => f,
                    Err(_) => {
                        show_alert(
                            vwindow_roes.as_ref(),
                            lang::text::generic::ERROR,
                            lang::text::explorer::EXP_IMPORT_OPEN_ERROR,
                        );
                        return;
                    }
                };
                // Get file data, then write all
                let voc_vdata = vdata_roes.borrow();
                let vdata = match voc_vdata.get(&fileid) {
                    Some(b) => b,
                    None => {
                        show_alert(
                            vwindow_roes.as_ref(),
                            lang::text::generic::ERROR,
                            lang::text::explorer::EXP_EXPORT_GET_DATA_FAILED,
                        );
                        return;
                    }
                };
                let wres = file.write_all(vdata);
                if wres.is_err() {
                    show_alert(
                        vwindow_roes.as_ref(),
                        lang::text::generic::ERROR,
                        lang::text::explorer::EXP_EXPORT_WRITE_FAILED,
                    );
                }
                let fres = file.flush();
                if fres.is_err() {
                    show_alert(
                        vwindow_roes.as_ref(),
                        lang::text::generic::ERROR,
                        lang::text::explorer::EXP_EXPORT_FLUSH_FAILED,
                    );
                }
            },
        );
    });
    voc_grid.attach(&voc_export_item, 1, 2, 1, 1);

    // Delete
    let voc_delete_item = gtk4::Button::with_label(lang::text::explorer::EXP_DELETE_ITEM);
    voc_delete_item.set_size_request(96, 40);

    // Rc suffix: _rod
    let app_rod = Rc::clone(&application);
    let changed_rod = Rc::clone(&changed);
    let vindex_rod = Rc::clone(&vindex);
    let vdata_rod = Rc::clone(&vdata);
    let idcs_rod = Rc::clone(&idcs);
    let iviewer_title_rod = Rc::clone(&item_viewer_title);
    let voc_button_rod = Rc::clone(&vault_other_ctrl);
    let vfilelist_rod = Rc::clone(&vault_file_list);
    let vexpath_rod = Rc::clone(&vexplorer_path);
    let vwindow_rod = Rc::clone(&vault_window);
    let iviewer_rod = Rc::clone(&item_viewer);
    voc_delete_item.connect_clicked(move |_| {
        voc_button_rod.popdown();
        if &vexpath_rod.borrow().text() == "/" {
            // Delete file, no deleting directory allowed
            delete_file_confirm(
                Rc::clone(&app_rod),
                Rc::clone(&vdata_rod),
                Rc::clone(&vindex_rod),
                Rc::clone(&idcs_rod),
                Rc::clone(&vwindow_rod),
                Rc::clone(&vexpath_rod),
                Rc::clone(&iviewer_rod),
                Rc::clone(&vfilelist_rod),
                Rc::clone(&iviewer_title_rod),
                Rc::clone(&changed_rod),
                false,
            );
        } else {
            // Delete type selector
            let vdi_window = Rc::new(gtk4::Window::new());
            vdi_window.set_title(Some(lang::text::explorer::EXP_DELETE_SEL_TITLE));
            vdi_window.set_application(Some(app_rod.as_ref()));
            vdi_window.set_size_request(224, 56);
            vdi_window.set_resizable(false);
            let vdi_hbox = gtk4::Box::builder()
                .margin_top(6)
                .margin_bottom(6)
                .margin_start(6)
                .margin_end(6)
                .halign(gtk4::Align::Center)
                .orientation(gtk4::Orientation::Horizontal)
                .spacing(6)
                .build();

            let vdi_delete_file =
                gtk4::Button::with_label(lang::text::explorer::EXP_DELETE_SEL_FILE);
            vdi_delete_file.set_size_request(96, 40);

            // Rc suffix: _rodf
            let iviewer_title_rodf = Rc::clone(&iviewer_title_rod);
            let vfilelist_rodf = Rc::clone(&vfilelist_rod);
            let iviewer_rodf = Rc::clone(&iviewer_rod);
            let vexpath_rodf = Rc::clone(&vexpath_rod);
            let vdi_window_rodf = Rc::clone(&vdi_window);
            let changed_rodf = Rc::clone(&changed_rod);
            let vindex_rodf = Rc::clone(&vindex_rod);
            let vdata_rodf = Rc::clone(&vdata_rod);
            let idcs_rodf = Rc::clone(&idcs_rod);
            let app_rodf = Rc::clone(&app_rod);
            vdi_delete_file.connect_clicked(move |_| {
                delete_file_confirm(
                    Rc::clone(&app_rodf),
                    Rc::clone(&vdata_rodf),
                    Rc::clone(&vindex_rodf),
                    Rc::clone(&idcs_rodf),
                    Rc::clone(&vdi_window_rodf),
                    Rc::clone(&vexpath_rodf),
                    Rc::clone(&iviewer_rodf),
                    Rc::clone(&vfilelist_rodf),
                    Rc::clone(&iviewer_title_rodf),
                    Rc::clone(&changed_rodf),
                    true,
                );
            });
            vdi_hbox.append(&vdi_delete_file);

            let vdi_delete_dir = gtk4::Button::with_label(lang::text::explorer::EXP_DELETE_SEL_DIR);
            vdi_delete_dir.set_size_request(96, 40);

            // Rc suffix: _rodd
            let iviewer_title_rodd = Rc::clone(&iviewer_title_rod);
            let vfilelist_rodd = Rc::clone(&vfilelist_rod);
            let iviewer_rodd = Rc::clone(&iviewer_rod);
            let vexpath_rodd = Rc::clone(&vexpath_rod);
            let changed_rodd = Rc::clone(&changed_rod);
            let vdi_window_rodd = Rc::clone(&vdi_window);
            let vwindow_rodd = Rc::clone(&vwindow_rod);
            let vindex_rodd = Rc::clone(&vindex_rod);
            let vdata_rodd = Rc::clone(&vdata_rod);
            let idcs_rodd = Rc::clone(&idcs_rod);
            let app_rodd = Rc::clone(&app_rod);
            vdi_delete_dir.connect_clicked(move |_| {
                // Delete current folder and everything inside, include subdir
                let delwindow = Rc::new(gtk4::Window::new());
                delwindow.set_title(Some(lang::text::explorer::EXP_DELETE_CONFIRM));
                delwindow.set_application(Some(app_rodd.as_ref()));
                delwindow.set_size_request(240, 96);
                delwindow.set_modal(true);

                let del_grid = grid_builder(12, 12, 12, 12, 6, 12).build();

                let currpath_str = Rc::new(vexpath_rodd.borrow().get_itext().to_owned());
                let currpath_dirname = match vindex_rodd
                    .borrow()
                    .get(&PathBuf::from(currpath_str.as_ref()))
                {
                    Some(n) => n.to_owned(),
                    None => {
                        show_alert(
                            vwindow_rodd.as_ref(),
                            lang::text::generic::ERROR,
                            lang::text::explorer::EXP_DELETE_DIR_FETCH_FAILED,
                        );
                        return;
                    }
                };

                let del_title = gtk4::Label::new(Some(
                    &(lang::text::explorer::EXP_DELETE_DIR_DESC1.to_owned()
                        + &currpath_dirname
                        + lang::text::explorer::EXP_DELETE_DIR_DESC2),
                ));
                del_grid.attach(&del_title, 1, 1, 3, 1);

                let del_no_button =
                    gtk4::Button::with_label(lang::text::explorer::EXP_DELETE_NO_BTN);
                del_no_button.set_size_request(40, 28);

                // Rc suffix: _roddn
                let vdi_window_roddn = Rc::clone(&vdi_window_rodd);
                let delwindow_roddn = Rc::clone(&delwindow);
                del_no_button.connect_clicked(move |_| {
                    delwindow_roddn.close();
                    vdi_window_roddn.close();
                });
                del_grid.attach(&del_no_button, 1, 2, 1, 1);

                let del_yes_button =
                    gtk4::Button::with_label(lang::text::explorer::EXP_DELETE_YES_BTN);
                del_yes_button.set_size_request(40, 28);

                // Rc suffix: _roddy
                let iviewer_title_roddy = Rc::clone(&iviewer_title_rodd);
                let vfilelist_roddy = Rc::clone(&vfilelist_rodd);
                let vdi_window_roddy = Rc::clone(&vdi_window_rodd);
                let delwindow_roddy = Rc::clone(&delwindow);
                let currpath_roddy = Rc::clone(&currpath_str);
                let vexpath_roddy = Rc::clone(&vexpath_rodd);
                let iviewer_roddy = Rc::clone(&iviewer_rodd);
                let changed_roddy = Rc::clone(&changed_rodd);
                let vindex_roddy = Rc::clone(&vindex_rodd);
                let vdata_roddy = Rc::clone(&vdata_rodd);
                let idcs_roddy = Rc::clone(&idcs_rodd);
                let app_roddy = Rc::clone(&app_rodd);
                del_yes_button.connect_clicked(move |_| {
                    let keys_to_remove: Vec<PathBuf> = vindex_roddy
                        .borrow()
                        .keys()
                        .filter(|path| path.starts_with(currpath_roddy.as_ref()))
                        .cloned()
                        .collect();
                    for key in keys_to_remove {
                        vindex_roddy.borrow_mut().remove(&key);
                        vdata_roddy.borrow_mut().remove(&key);
                    }
                    changed_roddy.borrow_mut().set(true);

                    // Go up
                    let mut newpath = PathBuf::from(vexpath_roddy.borrow().entry.text());
                    let newvpath = newpath.parent().unwrap().to_path_buf();
                    newpath = newvpath;
                    vexpath_roddy
                        .borrow_mut()
                        .entry
                        .set_text(newpath.to_str().unwrap_or("/<invalid>/"));
                    let mut prevpath = PathBuf::from(vexpath_roddy.borrow().get_itext());
                    prevpath.pop();
                    // Set internal path
                    vexpath_roddy
                        .borrow_mut()
                        .set_itext(prevpath.to_str().unwrap_or("/").to_string());

                    // Reload
                    loop {
                        let dwidget = match vfilelist_roddy.last_child() {
                            Some(w) => w,
                            None => break,
                        };
                        vfilelist_roddy.remove(&dwidget);
                    }
                    for button in get_files_from_vpath(
                        Rc::clone(&app_roddy),
                        Rc::clone(&vfilelist_roddy),
                        Rc::clone(&idcs_roddy),
                        Rc::clone(&vindex_roddy),
                        Rc::clone(&vdata_roddy),
                        PathBuf::from(vexpath_roddy.borrow().get_itext()),
                        Rc::clone(&iviewer_title_roddy),
                        Rc::clone(&iviewer_roddy),
                        Rc::clone(&vexpath_roddy),
                    ) {
                        vfilelist_roddy.append(&*button);
                    }

                    if iviewer_title_roddy
                        .borrow()
                        .get_itext()
                        .split_once(":")
                        .unwrap()
                        .0
                        .starts_with(currpath_roddy.as_ref())
                    {
                        iviewer_title_roddy
                            .borrow_mut()
                            .set_text(lang::text::explorer::EXP_ITEMNAME_PH);
                        iviewer_roddy.set_child(None::<&gtk4::Grid>);
                    }

                    delwindow_roddy.close();
                    vdi_window_roddy.close();
                });
                del_grid.attach(&del_yes_button, 3, 2, 1, 1);

                delwindow.set_child(Some(&del_grid));
                delwindow.present();
            });

            vdi_hbox.append(&vdi_delete_dir);

            vdi_window.set_child(Some(&vdi_hbox));
            vdi_window.present();
        }
    });
    voc_grid.attach(&voc_delete_item, 2, 2, 1, 1);

    voc_popover.set_child(Some(&voc_grid));
    vault_other_ctrl.set_popover(Some(&voc_popover));
    control_grid.attach(vault_other_ctrl.as_ref(), 2, 2, 1, 1);

    // Add items on '/'
    for button in get_files_from_vpath(
        Rc::clone(&application),
        Rc::clone(&vault_file_list),
        Rc::clone(&idcs),
        Rc::clone(&vindex),
        Rc::clone(&vdata),
        PathBuf::from("/"),
        Rc::clone(&item_viewer_title),
        Rc::clone(&item_viewer),
        Rc::clone(&vexplorer_path),
    ) {
        vault_file_list.append(&*button);
    }

    // Closing event
    let wcl_app = Rc::clone(&application);
    let changed_crc = Rc::clone(&changed);
    let handler_rc = Rc::clone(&handler);
    let iviewer_title_rc = Rc::clone(&item_viewer_title);
    let vault_password_rc = Rc::clone(&vault_password);
    let iviewer_window_rc = Rc::clone(&item_viewer);
    let vault_window_rc = Rc::clone(&vault_window);
    let commlabel_rc = Rc::clone(&commlabel);
    vault_window.connect_close_request(move |window| {
        if window.has_css_class("confirm_closure") {
            handler_rc.borrow_mut().take().unwrap().remove();
            glib::Propagation::Proceed
        } else if changed_crc.borrow().get().to_owned() {
            if iviewer_title_rc.borrow().text().ends_with("*") {
                // Do you want to save changes in ...?
                let isave_window = Rc::new(gtk4::Window::new());
                isave_window.set_application(Some(wcl_app.as_ref()));
                isave_window.set_title(Some(lang::text::explorer::EXP_CLOSURE_TITLE));
                isave_window.set_default_size(144, 64);
                isave_window.set_modal(true);
                let isave_grid = grid_builder(6, 12, 12, 12, 12, 6).build();

                let isave_title = gtk4::Label::new(Some(
                    &(lang::text::explorer::EXP_CLOSURE_DESC1.to_owned()
                        + iviewer_title_rc
                            .borrow()
                            .text()
                            .rsplit_once("  ")
                            .unwrap()
                            .0
                        + lang::text::explorer::EXP_CLOSURE_DESC2),
                ));
                isave_grid.attach(&isave_title, 1, 1, 3, 1);

                let isave_yes_button =
                    gtk4::Button::with_label(lang::text::explorer::EXP_SAVE_ITEM);
                isave_yes_button.set_size_request(36, 28);

                let iviewer_window_irc = Rc::clone(&iviewer_window_rc);
                let iviewer_title_irc = Rc::clone(&iviewer_title_rc);
                let vpassword_irc = Rc::clone(&vault_password_rc);
                let vwindow_irc = Rc::clone(&vault_window_rc);
                let isave_window_irc = Rc::clone(&isave_window);
                let commlabel_irc = Rc::clone(&commlabel_rc);
                let vindex_irc = Rc::clone(&vindex);
                let vdata_irc = Rc::clone(&vdata);
                let vname_irc = Rc::clone(&vname);
                let app_irc = Rc::clone(&wcl_app);
                isave_yes_button.connect_clicked(move |_| {
                    isave_window_irc.close();
                    if !iviewer_title_irc.borrow().text().ends_with("*") {
                        return;
                    }
                    // Get item key
                    let item_text = iviewer_title_irc.borrow().get_itext().to_owned();
                    let item_key = PathBuf::from(item_text.split_once(":").unwrap().0);
                    // Get text buffer
                    let text = match get_text_from_cwin(iviewer_window_irc.as_ref()) {
                        Some(t) => t,
                        None => return,
                    };
                    vdata_irc.borrow_mut().remove(&item_key);
                    vdata_irc
                        .borrow_mut()
                        .insert(item_key, text.as_bytes().to_owned());
                    let nochanges_title = iviewer_title_irc.borrow().text().replace("  *", "");
                    iviewer_title_irc.borrow_mut().set_text(&nochanges_title);

                    let ifinal_string = Rc::new(get_vault_full_string(
                        Rc::clone(&vname_irc),
                        Rc::clone(&vindex_irc),
                        Rc::clone(&vdata_irc),
                    ));

                    save_vault(
                        Rc::clone(&app_irc),
                        Rc::clone(&vname_irc),
                        Rc::clone(&ifinal_string),
                        hashify_sha256_ref(&ifinal_string),
                        Rc::clone(&vpassword_irc),
                        Rc::clone(&vwindow_irc),
                        Rc::clone(&commlabel_irc),
                    );
                });
                isave_grid.attach(&isave_yes_button, 1, 2, 1, 1);

                let isave_no_button =
                    gtk4::Button::with_label(lang::text::explorer::EXP_DONTSAVE_ITEM);
                isave_no_button.set_size_request(36, 28);

                let vpassword_rc = Rc::clone(&vault_password_rc);
                let isave_window_nrc = Rc::clone(&isave_window);
                let vwindow_rc = Rc::clone(&vault_window_rc);
                let commlabel_rc = Rc::clone(&commlabel_rc);
                let vindex_rc = Rc::clone(&vindex);
                let vdata_rc = Rc::clone(&vdata);
                let vname_rc = Rc::clone(&vname);
                let app_rc = Rc::clone(&wcl_app);
                isave_no_button.connect_clicked(move |_| {
                    let final_string = Rc::new(get_vault_full_string(
                        Rc::clone(&vname_rc),
                        Rc::clone(&vindex_rc),
                        Rc::clone(&vdata_rc),
                    ));
                    isave_window_nrc.close();
                    save_vault(
                        Rc::clone(&app_rc),
                        Rc::clone(&vname_rc),
                        Rc::clone(&final_string),
                        hashify_sha256_ref(final_string.as_ref()),
                        Rc::clone(&vpassword_rc),
                        Rc::clone(&vwindow_rc),
                        Rc::clone(&commlabel_rc),
                    );
                });
                isave_grid.attach(&isave_no_button, 2, 2, 1, 1);

                let isave_cancel_button =
                    gtk4::Button::with_label(lang::text::explorer::EXP_CLOSURE_CANCEL);
                isave_cancel_button.set_size_request(36, 28);

                let isave_window_crc = Rc::clone(&isave_window);
                isave_cancel_button.connect_clicked(move |_| {
                    isave_window_crc.close();
                });
                isave_grid.attach(&isave_cancel_button, 3, 2, 1, 1);

                isave_window.set_child(Some(&isave_grid));
                isave_window.present();
                return glib::Propagation::Stop;
            } else {
                let final_string = Rc::new(get_vault_full_string(
                    Rc::clone(&vname),
                    Rc::clone(&vindex),
                    Rc::clone(&vdata),
                ));
                let hash_final = hashify_sha256_ref(&final_string);

                if hash_initial != hash_final {
                    // Change detected!
                    save_vault(
                        Rc::clone(&wcl_app),
                        Rc::clone(&vname),
                        final_string,
                        hash_final,
                        Rc::clone(&vault_password_rc),
                        Rc::clone(&vault_window_rc),
                        Rc::clone(&commlabel_rc),
                    );
                    return glib::Propagation::Stop;
                } else {
                    vault_window_rc.add_css_class("confirm_closure");
                    vault_window_rc.close();
                    return glib::Propagation::Proceed;
                }
            }
        } else {
            vault_window_rc.add_css_class("confirm_closure");
            vault_window_rc.close();
            glib::Propagation::Proceed
        }
    });

    vault_hbox.append(&control_grid);
    vault_hbox.append(&item_grid);
    vault_window.set_child(Some(&vault_hbox));
    vault_window.present();
}

pub fn get_files_from_vpath(
    application: Rc<gtk4::Application>,
    file_list: Rc<gtk4::ListBox>,
    idcs: Rc<RefCell<ImgDecodingController>>,
    index: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    data: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    path: PathBuf,
    name_viewer: Rc<RefCell<LabelWithInternalText>>,
    content_viewer: Rc<gtk4::ScrolledWindow>,
    explorer_path: Rc<RefCell<EntryWithInternalText>>,
) -> Vec<ButtonWithInternalText> {
    let path = Rc::new(path);
    let mut items: Vec<ButtonWithInternalText> = Vec::new();
    if path.as_os_str() != "/" {
        let abutton = ButtonWithInternalText::with_label("../", String::new());

        let app_rc = Rc::clone(&application);
        let filelist_rc = Rc::clone(&file_list);
        let idcs_rc = Rc::clone(&idcs);
        let index_rc = Rc::clone(&index);
        let data_rc = Rc::clone(&data);
        let nviewer_rc = Rc::clone(&name_viewer);
        let cviewer_rc = Rc::clone(&content_viewer);
        let expath_rc = Rc::clone(&explorer_path);
        abutton.connect_clicked(move |_| {
            // Go up
            let mut newpath = PathBuf::from(expath_rc.borrow().entry.text());
            let newvpath = newpath.parent().unwrap().to_path_buf();
            newpath = newvpath;
            expath_rc
                .borrow_mut()
                .entry
                .set_text(newpath.to_str().unwrap_or("/<invalid>/"));
            let mut prevpath = PathBuf::from(expath_rc.borrow().get_itext());
            prevpath.pop();
            // Set internal path
            expath_rc
                .borrow_mut()
                .set_itext(prevpath.to_str().unwrap_or("/").to_string());
            loop {
                let dwidget = match filelist_rc.last_child() {
                    Some(w) => w,
                    None => break,
                };
                filelist_rc.remove(&dwidget);
            }
            for button in get_files_from_vpath(
                Rc::clone(&app_rc),
                Rc::clone(&filelist_rc),
                Rc::clone(&idcs_rc),
                Rc::clone(&index_rc),
                Rc::clone(&data_rc),
                PathBuf::from(expath_rc.borrow().get_itext()),
                Rc::clone(&nviewer_rc),
                Rc::clone(&cviewer_rc),
                Rc::clone(&expath_rc),
            ) {
                filelist_rc.append(&*button);
            }
        });

        items.push(abutton);
    }

    for (ipath, name) in &*index.borrow() {
        let name = name.clone();
        let ipath = Rc::new(ipath.clone());
        if !ipath.starts_with(path.as_ref()) {
            continue;
        }
        // Exclude subdirectory here
        if ipath.parent().unwrap_or(&PathBuf::from("/")) != path.as_ref() {
            continue;
        }

        let lbuttoni = gtk4::Button::with_label(&name);
        lbuttoni.child().unwrap().set_halign(gtk4::Align::Start);
        let lbutton = ButtonWithInternalText::new(lbuttoni, ipath.to_str().unwrap().to_string());

        if name.ends_with("/") {
            // Go down
            let data_drc = Rc::clone(&data);
            let path_drc = Rc::clone(&path);
            let index_drc = Rc::clone(&index);
            let app_drc = Rc::clone(&application);
            let idcs_drc = Rc::clone(&idcs);
            let flist_drc = Rc::clone(&file_list);
            let expath_drc = Rc::clone(&explorer_path);
            let name_viewer_drc = Rc::clone(&name_viewer);
            let content_viewer_drc = Rc::clone(&content_viewer);
            let lbtnipath = Rc::new(lbutton.get_itext().to_owned());
            lbutton.connect_clicked(move |button| {
                let dirname = button.label().unwrap();
                let mut newpath = PathBuf::from(expath_drc.borrow().entry.text());
                newpath.push(&dirname);
                expath_drc.borrow_mut().entry.set_text(
                    newpath
                        .to_str()
                        .unwrap_or(&(path_drc.to_str().unwrap().to_owned() + "<invalid>/")),
                );
                // Set internal path
                let newipath = Rc::clone(&lbtnipath);
                expath_drc.borrow_mut().set_itext_ref(newipath.as_ref());
                loop {
                    let dwidget = match flist_drc.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    flist_drc.remove(&dwidget);
                }
                for button in get_files_from_vpath(
                    Rc::clone(&app_drc),
                    Rc::clone(&flist_drc),
                    Rc::clone(&idcs_drc),
                    Rc::clone(&index_drc),
                    Rc::clone(&data_drc),
                    PathBuf::from(expath_drc.borrow().get_itext()),
                    Rc::clone(&name_viewer_drc),
                    Rc::clone(&content_viewer_drc),
                    Rc::clone(&expath_drc),
                ) {
                    flist_drc.append(&*button);
                }
            });
        } else {
            // Show file
            let app_frc = Rc::clone(&application);
            let data_frc = Rc::clone(&data);
            let index_frc = Rc::clone(&index);
            let ipath_frc = Rc::clone(&ipath);
            let idcs_frc = Rc::clone(&idcs);
            let name_viewer_frc = Rc::clone(&name_viewer);
            let content_viewer_frc = Rc::clone(&content_viewer);
            lbutton.connect_clicked(move |_| {
                let (inamep_str, fname) = match name_viewer_frc.borrow().get_itext().split_once(":")
                {
                    Some(s) => (s.0.to_owned(), s.1.to_owned()),
                    None => (String::new(), String::new()),
                };
                if inamep_str.starts_with("/")
                    && ipath_frc.as_os_str() == inamep_str.as_str()
                    && !fname.ends_with("bgsf")
                {
                    return;
                }

                // Cancel drawing for the current
                // If there're any image requesting to be shown
                if let Some(child) = content_viewer_frc.child()
                    && let Some(gchild) = child.first_child()
                {
                    for grid_child in gchild.observe_children().into_iter() {
                        if grid_child.is_err() {
                            continue;
                        }
                        if let Ok(image) = grid_child.unwrap().dynamic_cast::<gtk4::Picture>() {
                            for class in image.css_classes() {
                                if let Ok(imgid) = str::parse::<u32>(&class) {
                                    idcs_frc.borrow_mut().queue.remove(&imgid);
                                    idcs_frc.borrow_mut().image_provider.remove(&imgid);
                                }
                            }
                        }
                    }
                };

                open_other_file(
                    Rc::clone(&app_frc),
                    Rc::clone(&content_viewer_frc),
                    Rc::clone(&name_viewer_frc),
                    Rc::clone(&index_frc),
                    Rc::clone(&data_frc),
                    Rc::new(ipath_frc.display().to_string()),
                    Rc::clone(&idcs_frc),
                );
            });
        }

        items.push(lbutton);
    }
    items
}

fn get_files_from_mpath(
    application: Rc<gtk4::Application>,
    file_list: Rc<gtk4::ListBox>,
    index: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    data: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    path: PathBuf,
    explorer_path: Rc<RefCell<EntryWithInternalText>>,
) -> Vec<ButtonWithInternalText> {
    let path = Rc::new(path);
    let mut items: Vec<ButtonWithInternalText> = Vec::new();

    if path.as_os_str() != "/" {
        let abutton = ButtonWithInternalText::with_label("../", String::new());

        let app_rc = Rc::clone(&application);
        let filelist_rc = Rc::clone(&file_list);
        let index_rc = Rc::clone(&index);
        let data_rc = Rc::clone(&data);
        let expath_rc = Rc::clone(&explorer_path);
        abutton.connect_clicked(move |_| {
            // Go up
            let mut newpath = PathBuf::from(expath_rc.borrow().entry.text());
            let newvpath = newpath.parent().unwrap().to_path_buf();
            newpath = newvpath;
            expath_rc
                .borrow_mut()
                .entry
                .set_text(newpath.to_str().unwrap_or("/<invalid>/"));
            let mut prevpath = PathBuf::from(expath_rc.borrow().get_itext());
            prevpath.pop();
            // Set internal path
            expath_rc
                .borrow_mut()
                .set_itext(prevpath.to_str().unwrap_or("/").to_string());
            loop {
                let dwidget = match filelist_rc.last_child() {
                    Some(w) => w,
                    None => break,
                };
                filelist_rc.remove(&dwidget);
            }
            for button in get_files_from_mpath(
                Rc::clone(&app_rc),
                Rc::clone(&filelist_rc),
                Rc::clone(&index_rc),
                Rc::clone(&data_rc),
                PathBuf::from(expath_rc.borrow().get_itext()),
                Rc::clone(&expath_rc),
            ) {
                filelist_rc.append(&*button);
            }
        });

        items.push(abutton);
    }

    for (ipath, name) in &*index.borrow() {
        let name = name.clone();
        let ipath = Rc::new(ipath.clone());
        if !ipath.starts_with(path.as_ref()) {
            continue;
        }
        // Exclude subdirectory here
        if ipath.parent().unwrap_or(&PathBuf::from("/")) != path.as_ref() {
            continue;
        }

        let lbuttoni = gtk4::Button::with_label(&name);
        lbuttoni.child().unwrap().set_halign(gtk4::Align::Start);
        let lbutton = ButtonWithInternalText::new(lbuttoni, ipath.to_str().unwrap().to_string());
        if name.ends_with("/") {
            // Go down
            let data_drc = Rc::clone(&data);
            let path_drc = Rc::clone(&path);
            let index_drc = Rc::clone(&index);
            let app_drc = Rc::clone(&application);
            let flist_drc = Rc::clone(&file_list);
            let expath_drc = Rc::clone(&explorer_path);
            let lbtnipath = Rc::new(lbutton.get_itext().to_owned());
            lbutton.connect_clicked(move |button| {
                let dirname = button.label().unwrap();
                let mut newpath = PathBuf::from(expath_drc.borrow().entry.text());
                newpath.push(&dirname);
                expath_drc.borrow_mut().entry.set_text(
                    newpath
                        .to_str()
                        .unwrap_or(&(path_drc.to_str().unwrap().to_owned() + "<invalid>/")),
                );
                // Set internal path
                let newipath = Rc::clone(&lbtnipath);
                expath_drc.borrow_mut().set_itext_ref(newipath.as_ref());
                loop {
                    let dwidget = match flist_drc.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    flist_drc.remove(&dwidget);
                }
                for button in get_files_from_mpath(
                    Rc::clone(&app_drc),
                    Rc::clone(&flist_drc),
                    Rc::clone(&index_drc),
                    Rc::clone(&data_drc),
                    PathBuf::from(expath_drc.borrow().get_itext()),
                    Rc::clone(&expath_drc),
                ) {
                    flist_drc.append(&*button);
                }
            });
        }

        items.push(lbutton);
    }
    items
}

fn vault_move_file(
    app_rc: Rc<gtk4::Application>,
    idcs_rc: Rc<RefCell<ImgDecodingController>>,
    changed_rc: Rc<RefCell<ItemContainer<bool>>>,
    vindex_rc: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata_rc: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    vwindow_rc: Rc<gtk4::Window>,
    vfilelist_rc: Rc<gtk4::ListBox>,
    iviewer_rc: Rc<gtk4::ScrolledWindow>,
    vexpath_rc: Rc<RefCell<EntryWithInternalText>>,
    iviewer_title_rc: Rc<RefCell<LabelWithInternalText>>,
) {
    let fileinfo = iviewer_title_rc.borrow().get_itext().to_owned();
    let (fileid_str, filename) = match fileinfo.split_once(":") {
        Some((id, name)) => (id.to_owned(), name.to_owned()),
        None => {
            show_alert(
                vwindow_rc.as_ref(),
                lang::text::generic::ALERT,
                lang::text::explorer::EXP_MOVE_NOSEL,
            );
            return;
        }
    };

    let imove_window = Rc::new(gtk4::Window::new());
    imove_window.set_title(Some(lang::text::explorer::EXP_MOVE_TITLE));
    imove_window.set_application(Some(app_rc.as_ref()));
    imove_window.set_size_request(240, 400);

    let imove_grid = grid_builder(6, 12, 12, 12, 6, 6).build();
    imove_grid.set_halign(gtk4::Align::Center);

    // Path viewer
    let imove_expathi = gtk4::Entry::builder()
        .text(vexpath_rc.borrow().text())
        .editable(false)
        .build();
    imove_expathi.add_css_class("normal");
    imove_expathi.set_size_request(240, 40);
    let imove_expath = Rc::new(RefCell::new(EntryWithInternalText::new(
        imove_expathi,
        vexpath_rc.borrow().get_itext().to_owned(),
    )));
    imove_grid.attach(&**imove_expath.borrow(), 1, 1, 1, 1);

    // Move confirm button
    let imove_cfbutton = gtk4::Button::with_label(lang::text::explorer::EXP_MOVE_CONFIRM);
    imove_cfbutton.add_css_class("normal");
    imove_cfbutton.set_size_request(80, 40);

    // Rc suffix: _romi
    let changed_romi = Rc::clone(&changed_rc);
    let vindex_romi = Rc::clone(&vindex_rc);
    let vdata_romi = Rc::clone(&vdata_rc);
    let idcs_romi = Rc::clone(&idcs_rc);
    let app_romi = Rc::clone(&app_rc);
    let iviewer_title_romi = Rc::clone(&iviewer_title_rc);
    let vfilelist_romi = Rc::clone(&vfilelist_rc);
    let iviewer_romi = Rc::clone(&iviewer_rc);
    let vexpath_romi = Rc::clone(&vexpath_rc);
    let imwindow_rc = Rc::clone(&imove_window);
    let iexpath_rc = Rc::clone(&imove_expath);
    imove_cfbutton.connect_clicked(move |_| {
        let (curr_ipath, name) = match iviewer_title_romi.borrow().get_itext().split_once(":") {
            Some((cipath_s, name_s)) => (cipath_s.to_owned(), name_s.to_owned()),
            None => {
                show_alert(
                    imwindow_rc.as_ref(),
                    lang::text::generic::ERROR,
                    lang::text::explorer::EXP_MOVE_FINFO_ERR,
                );
                return;
            }
        };
        let fdata = match vdata_romi.borrow().get(&PathBuf::from(curr_ipath)) {
            Some(d) => d.to_owned(),
            None => {
                show_alert(
                    imwindow_rc.as_ref(),
                    lang::text::generic::ERROR,
                    lang::text::explorer::EXP_MOVE_FDATA_ERR,
                );
                return;
            }
        };
        let new_ipath = vault_append_file(
            Rc::clone(&iexpath_rc),
            filename.clone(),
            Some(&fdata),
            Rc::clone(&vindex_romi),
            Rc::clone(&vdata_romi),
        );
        changed_romi.borrow_mut().set(true);
        iviewer_title_romi
            .borrow_mut()
            .set_itext(new_ipath + ":" + &name);

        let fileid = PathBuf::from(&fileid_str);
        vindex_romi.borrow_mut().remove(&fileid);
        vdata_romi.borrow_mut().remove(&fileid);

        loop {
            let dwidget = match vfilelist_romi.last_child() {
                Some(w) => w,
                None => break,
            };
            vfilelist_romi.remove(&dwidget);
        }
        for button in get_files_from_vpath(
            Rc::clone(&app_romi),
            Rc::clone(&vfilelist_romi),
            Rc::clone(&idcs_romi),
            Rc::clone(&vindex_romi),
            Rc::clone(&vdata_romi),
            PathBuf::from(vexpath_romi.borrow().get_itext()),
            Rc::clone(&iviewer_title_romi),
            Rc::clone(&iviewer_romi),
            Rc::clone(&vexpath_romi),
        ) {
            vfilelist_romi.append(&*button);
        }

        imwindow_rc.close();
    });
    imove_grid.attach(&imove_cfbutton, 2, 1, 1, 1);

    // Item list
    let imove_fwindow = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .vexpand(true)
        .build();
    imove_fwindow.set_size_request(240, 280);
    let imove_fviewer = Rc::new(gtk4::ListBox::new());
    imove_fwindow.set_child(Some(imove_fviewer.as_ref()));
    imove_grid.attach(&imove_fwindow, 1, 2, 2, 1);

    for button in get_files_from_mpath(
        Rc::clone(&app_rc),
        Rc::clone(&imove_fviewer),
        Rc::clone(&vindex_rc),
        Rc::clone(&vdata_rc),
        PathBuf::from(imove_expath.borrow().get_itext()),
        Rc::clone(&imove_expath),
    ) {
        imove_fviewer.append(&*button);
    }

    imove_window.set_child(Some(&imove_grid));
    imove_window.set_modal(true);
    imove_window.present();
}

fn vault_move_dir(
    app_rc: Rc<gtk4::Application>,
    idcs_rc: Rc<RefCell<ImgDecodingController>>,
    changed_rc: Rc<RefCell<ItemContainer<bool>>>,
    vindex_rc: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata_rc: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    vfilelist_rc: Rc<gtk4::ListBox>,
    iviewer_rc: Rc<gtk4::ScrolledWindow>,
    vexpath_rc: Rc<RefCell<EntryWithInternalText>>,
    iviewer_title_rc: Rc<RefCell<LabelWithInternalText>>,
) {
    let dmove_window = Rc::new(gtk4::Window::new());
    dmove_window.set_title(Some(lang::text::explorer::EXP_MOVE_TITLE));
    dmove_window.set_application(Some(app_rc.as_ref()));
    dmove_window.set_size_request(240, 400);

    let dmove_grid = grid_builder(6, 12, 12, 12, 6, 6).build();
    dmove_grid.set_halign(gtk4::Align::Center);

    // Path viewer
    let mut parent = PathBuf::from(vexpath_rc.borrow().text());
    parent.pop();
    let dmove_expathi = gtk4::Entry::builder()
        .text(parent.display().to_string())
        .editable(false)
        .build();
    dmove_expathi.add_css_class("normal");
    dmove_expathi.set_size_request(240, 40);

    parent = PathBuf::from(vexpath_rc.borrow().get_itext());
    parent.pop();
    let dmove_expath = Rc::new(RefCell::new(EntryWithInternalText::new(
        dmove_expathi,
        parent.display().to_string(),
    )));
    dmove_grid.attach(&**dmove_expath.borrow(), 1, 1, 1, 1);

    // Move confirm button
    let dmove_cfbutton = gtk4::Button::with_label(lang::text::explorer::EXP_MOVE_CONFIRM);
    dmove_cfbutton.add_css_class("normal");
    dmove_cfbutton.set_size_request(80, 40);

    // Rc suffix: _romd
    let changed_romd = Rc::clone(&changed_rc);
    let vindex_romd = Rc::clone(&vindex_rc);
    let vdata_romd = Rc::clone(&vdata_rc);
    let idcs_romd = Rc::clone(&idcs_rc);
    let app_romd = Rc::clone(&app_rc);
    let iviewer_title_romd = Rc::clone(&iviewer_title_rc);
    let vfilelist_romd = Rc::clone(&vfilelist_rc);
    let iviewer_romd = Rc::clone(&iviewer_rc);
    let vexpath_romd = Rc::clone(&vexpath_rc);
    let dmwindow_rc = Rc::clone(&dmove_window);
    let dexpath_rc = Rc::clone(&dmove_expath);
    dmove_cfbutton.connect_clicked(move |_| {
        let from_path = vexpath_romd.borrow().get_itext().clone();
        if &from_path == dexpath_rc.borrow().get_itext() {
            dmwindow_rc.close();
            return;
        }
        let mut dirpath = vexpath_romd.borrow().text().to_string();
        dirpath.pop();
        let dirname = dirpath.rsplit_once("/").unwrap().1.to_owned() + "/";

        let new_ipath =
            vault_append_folder(Rc::clone(&dexpath_rc), dirname, Rc::clone(&vindex_romd));
        dexpath_rc.borrow_mut().set_itext(new_ipath);

        // Search for the file to copy
        // We can't actually copy it inside this loop,
        // because the loop itself requires vindex to be borrowed
        let mut copylist: Vec<(PathBuf, String)> = Vec::new();
        for (spath, sname) in &*vindex_romd.borrow() {
            if !spath.starts_with(&from_path) {
                continue;
            }
            // Exclude subdirectory here
            if spath.parent().unwrap_or(&PathBuf::from("/")) != &from_path {
                continue;
            }

            copylist.push((spath.to_owned(), sname.clone()));
        }

        // Do the actual copy
        for (ipath_str, name) in copylist {
            let ipath = PathBuf::from(ipath_str);
            let fdata = match vdata_romd.borrow().get(&ipath) {
                Some(d) => d.to_owned(),
                None => {
                    show_alert(
                        dmwindow_rc.as_ref(),
                        lang::text::generic::ERROR,
                        lang::text::explorer::EXP_MOVE_FDATA_ERR,
                    );
                    return;
                }
            };
            vault_append_file(
                Rc::clone(&dexpath_rc),
                name.clone(),
                Some(&fdata),
                Rc::clone(&vindex_romd),
                Rc::clone(&vdata_romd),
            );

            vindex_romd.borrow_mut().remove(&ipath);
            vindex_romd.borrow_mut().remove(&ipath);
        }

        // Remove the origin folder
        let mut from_pb = PathBuf::from(from_path);
        vindex_romd.borrow_mut().remove(&from_pb);
        changed_romd.borrow_mut().set(true);

        // Go up to the existing folder
        let mut showpath = PathBuf::from(vexpath_romd.borrow().text());
        showpath.pop();
        vexpath_romd
            .borrow_mut()
            .set_text(&showpath.display().to_string());
        from_pb.pop();
        vexpath_romd
            .borrow_mut()
            .set_itext(from_pb.display().to_string());

        loop {
            let dwidget = match vfilelist_romd.last_child() {
                Some(w) => w,
                None => break,
            };
            vfilelist_romd.remove(&dwidget);
        }
        for button in get_files_from_vpath(
            Rc::clone(&app_romd),
            Rc::clone(&vfilelist_romd),
            Rc::clone(&idcs_romd),
            Rc::clone(&vindex_romd),
            Rc::clone(&vdata_romd),
            from_pb,
            Rc::clone(&iviewer_title_romd),
            Rc::clone(&iviewer_romd),
            Rc::clone(&vexpath_romd),
        ) {
            vfilelist_romd.append(&*button);
        }

        dmwindow_rc.close();
    });
    dmove_grid.attach(&dmove_cfbutton, 2, 1, 1, 1);

    // Item list
    let dmove_fwindow = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .vexpand(true)
        .build();
    dmove_fwindow.set_size_request(240, 280);
    let dmove_fviewer = Rc::new(gtk4::ListBox::new());
    dmove_fwindow.set_child(Some(dmove_fviewer.as_ref()));
    dmove_grid.attach(&dmove_fwindow, 1, 2, 2, 1);

    for button in get_files_from_mpath(
        Rc::clone(&app_rc),
        Rc::clone(&dmove_fviewer),
        Rc::clone(&vindex_rc),
        Rc::clone(&vdata_rc),
        PathBuf::from(dmove_expath.borrow().get_itext()),
        Rc::clone(&dmove_expath),
    ) {
        dmove_fviewer.append(&*button);
    }

    dmove_window.set_child(Some(&dmove_grid));
    dmove_window.set_modal(true);
    dmove_window.present();
}

fn get_item_viewer_grid(
    title: &String,
    data: &Vec<u8>,
    vindex_rc: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata_rc: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    ititle_label: Rc<RefCell<LabelWithInternalText>>,
    idcs: Rc<RefCell<ImgDecodingController>>,
) -> Rc<gtk4::Grid> {
    let title_fmt = format!("[ {title} ]");
    // Predict filetype
    let fmime = tree_magic_mini::from_u8(data);

    let iviewer_grid = Rc::new(
        grid_builder(6, 12, 12, 12, 4, 4)
            .hexpand(true)
            .vexpand(true)
            .build(),
    );
    iviewer_grid.set_size_request(384, 360);

    let data_utf8 = str::from_utf8(data);
    if title.ends_with(".bgsf") && fmime == "text/plain" && data_utf8.is_ok() {
        // Show as BGSF (BaseAES Grid Styling Format) document
        //
        // BGSF Example
        // # Shows 'WhatEverThatIs' (this is a comment)
        // @text:1/1/1/1:WhatEverThatIs.
        // @item:1/2/1/1:/path/to/whatever-item.png
        // @item:2/1/2/1:/path/to/explain.txt
        //
        ititle_label.borrow_mut().label.set_text(title);
        let warn_label = Rc::new(
            gtk4::Label::builder()
                .wrap_mode(gtk4::pango::WrapMode::Word)
                .build(),
        );
        warn_label.add_css_class("warning");
        iviewer_grid.attach(warn_label.as_ref(), 1, 1, 4, 1);

        let mut lcount: u32 = 1;
        for line in data_utf8.unwrap().split("\n") {
            if line == "" || line.starts_with("#") {
                lcount += 1;
                continue;
            }
            if line.starts_with("@text:") {
                if let Some(parsed) = bgsf_decode_item(line) {
                    let label = gtk4::Label::new(Some(parsed.1));
                    iviewer_grid.attach(
                        &label,
                        parsed.0[0],
                        parsed.0[1] + 1,
                        parsed.0[2],
                        parsed.0[3],
                    );
                } else {
                    warn_label.set_text(
                        &(warn_label.text().to_string()
                            + lang::text::explorer::EXP_BGSF_STYLE_ERR
                            + &lcount.to_string()),
                    );
                }
            } else if line.starts_with("@item:") {
                if let Some((style, path_str)) = bgsf_decode_item(line) {
                    let parse_failed = bgsf_parse_item(
                        Rc::clone(&iviewer_grid),
                        Rc::clone(&warn_label),
                        style,
                        path_str,
                        &lcount,
                        Rc::clone(&idcs),
                        Rc::clone(&vindex_rc),
                        Rc::clone(&vdata_rc),
                    );
                    if parse_failed {
                        continue;
                    }
                } else {
                    warn_label.set_text(
                        &(warn_label.text().to_string()
                            + lang::text::explorer::EXP_BGSF_STYLE_ERR
                            + &lcount.to_string()),
                    );
                }
            } else {
                warn_label.set_text(
                    &(warn_label.text().to_string()
                        + lang::text::explorer::EXP_BGSF_FORMAT_ERR
                        + &lcount.to_string()),
                );
            }
            lcount += 1;
        }
    } else if fmime == "image/png" || fmime == "image/jpeg" {
        // Show as image
        ititle_label.borrow_mut().label.set_text(title);
        let image_viewer = Rc::new(
            gtk4::Picture::builder()
                .can_target(true)
                .hexpand(true)
                .vexpand(false)
                .build(),
        );

        let owneddata = data.to_owned();
        idcs.borrow_mut().request_decode(
            IDCSImageType::from_str_name(fmime).unwrap(),
            owneddata,
            Rc::clone(&image_viewer),
            Rc::clone(&iviewer_grid),
        );
        iviewer_grid.attach(image_viewer.as_ref(), 1, 1, 1, 1);
    } else if fmime.starts_with("image") {
        let text_viewer = gtk4::TextView::builder()
            .hexpand(true)
            .vexpand(true)
            .editable(false)
            .can_target(true)
            .wrap_mode(gtk4::WrapMode::Word)
            .overflow(gtk4::Overflow::Visible)
            .build();
        text_viewer.add_css_class("normal");
        text_viewer
            .buffer()
            .set_text(lang::text::explorer::EXP_BGSF_IMG_TYPE_SRY);
        iviewer_grid.attach(&text_viewer, 1, 1, 1, 1);
    } else if data_utf8.is_ok() {
        // Show as text
        ititle_label.borrow_mut().label.set_text(&title_fmt);

        let text_scroll = gtk4::ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Automatic)
            .vscrollbar_policy(gtk4::PolicyType::Automatic)
            .build();
        let text_viewer = gtk4::TextView::builder()
            .hexpand(true)
            .vexpand(true)
            .can_target(true)
            .build();
        text_viewer.add_css_class("normal");
        text_viewer.add_css_class("text_viewer");
        text_viewer.buffer().set_text(data_utf8.unwrap());

        let ititle_label_rc = Rc::clone(&ititle_label);
        text_viewer.buffer().connect_changed(move |_| {
            let item_text = ititle_label_rc.borrow().label.text().to_string();
            if !item_text.ends_with("*") {
                ititle_label_rc
                    .borrow_mut()
                    .label
                    .set_text(&(item_text + "  *"));
            }
        });
        text_scroll.set_child(Some(&text_viewer));
        iviewer_grid.attach(&text_scroll, 1, 1, 1, 1);
    } else {
        ititle_label
            .borrow_mut()
            .label
            .set_text(&(title_fmt + lang::text::explorer::EXP_CONTENT_BIN_TITLE));
        let text_viewer = gtk4::TextView::builder()
            .hexpand(true)
            .vexpand(true)
            .editable(false)
            .wrap_mode(gtk4::WrapMode::Word)
            .build();
        text_viewer.add_css_class("normal");
        text_viewer.buffer().set_text(
            &(format!("Detected MIME: {fmime}\n") + lang::text::explorer::EXP_CONTENT_BIN_DESC),
        );
        iviewer_grid.attach(&text_viewer, 1, 1, 1, 1);
    };

    Rc::clone(&iviewer_grid)
}

fn open_other_file(
    app_rc: Rc<gtk4::Application>,
    iviewer_rc: Rc<gtk4::ScrolledWindow>,
    iviewer_title_rc: Rc<RefCell<LabelWithInternalText>>,
    vindex_rc: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata_rc: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    ipath_rc: Rc<String>,
    idcs_rc: Rc<RefCell<ImgDecodingController>>,
) {
    if iviewer_title_rc.borrow().text().ends_with("*") {
        // Do you want to discard changes in ...?
        let discard_window = Rc::new(gtk4::Window::new());
        discard_window.set_application(Some(app_rc.as_ref()));
        discard_window.set_title(Some(lang::text::explorer::EXP_DISCARD_TITLE));
        discard_window.set_default_size(240, 48);
        discard_window.set_modal(true);
        let discard_vbox = gtk4::Box::builder()
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .halign(gtk4::Align::Center)
            .orientation(gtk4::Orientation::Vertical)
            .spacing(6)
            .build();

        let discard_desc = gtk4::Label::new(Some(lang::text::explorer::EXP_DISCARD_DESC));
        discard_vbox.append(&discard_desc);

        let discard_cont_btn = gtk4::Button::with_label(lang::text::explorer::EXP_DISCARD_CONT);

        let index_drc = Rc::clone(&vindex_rc);
        let data_drc = Rc::clone(&vdata_rc);
        let idcs_drc = Rc::clone(&idcs_rc);
        let ipath_drc = Rc::clone(&ipath_rc);
        let nviewer_drc = Rc::clone(&iviewer_title_rc);
        let cviewer_drc = Rc::clone(&iviewer_rc);
        let dwindow_yrc = Rc::clone(&discard_window);
        discard_cont_btn.connect_clicked(move |_| {
            let fileid = PathBuf::from(ipath_drc.as_ref());
            let title = match index_drc.borrow().get(&fileid) {
                Some(s) => s.to_owned(),
                None => return,
            };
            let data = match data_drc.borrow().get(&fileid) {
                Some(d) => d.to_owned(),
                None => return,
            };
            cviewer_drc.set_child(Some(
                get_item_viewer_grid(
                    &title,
                    &data,
                    Rc::clone(&index_drc),
                    Rc::clone(&data_drc),
                    Rc::clone(&nviewer_drc),
                    Rc::clone(&idcs_drc),
                )
                .as_ref(),
            ));

            nviewer_drc
                .borrow_mut()
                .set_itext(format!("{}:{title}", ipath_drc.as_ref()));

            dwindow_yrc.close();
        });
        discard_vbox.append(&discard_cont_btn);

        let discard_cancel_btn = gtk4::Button::with_label(lang::text::explorer::EXP_DISCARD_CANCEL);

        let dwindow_rc = Rc::clone(&discard_window);
        discard_cancel_btn.connect_clicked(move |_| {
            dwindow_rc.close();
        });
        discard_vbox.append(&discard_cancel_btn);

        discard_window.set_child(Some(&discard_vbox));
        discard_window.present();
    } else {
        let fileid = PathBuf::from(ipath_rc.as_ref());
        let title = match vindex_rc.borrow().get(&fileid) {
            Some(s) => s.to_owned(),
            None => return,
        };
        let data = match vdata_rc.borrow().get(&fileid) {
            Some(d) => d.to_owned(),
            None => return,
        };
        iviewer_rc.set_child(Some(
            get_item_viewer_grid(
                &title,
                &data,
                Rc::clone(&vindex_rc),
                Rc::clone(&vdata_rc),
                Rc::clone(&iviewer_title_rc),
                Rc::clone(&idcs_rc),
            )
            .as_ref(),
        ));

        iviewer_title_rc
            .borrow_mut()
            .set_itext(format!("{}:{title}", ipath_rc.as_ref()));
    }
}

fn vault_append_file(
    vault_path: Rc<RefCell<EntryWithInternalText>>,
    filename: String,
    fdata: Option<&Vec<u8>>,
    vindex: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
) -> String {
    // Get file id here
    // Maybe I can just save next index
    let mut fileid: u32 = 0;
    let vexpath = vault_path.borrow().get_itext().to_owned();
    loop {
        let itempath = format!("{vexpath}{}", fileid.to_string());
        if vindex.borrow().contains_key(&PathBuf::from(itempath)) {
            fileid += 1;
        } else {
            break;
        }
    }
    // Add file to index
    let file_pathcode = format!("{vexpath}{fileid}");
    vindex
        .borrow_mut()
        .insert(PathBuf::from(&file_pathcode), filename.to_string());
    // Also to data
    vdata.borrow_mut().insert(
        PathBuf::from(file_pathcode),
        fdata.unwrap_or(&Vec::new()).to_owned(),
    );
    return format!("{vexpath}{}", fileid.to_string());
}

fn vault_append_folder(
    vault_path: Rc<RefCell<EntryWithInternalText>>,
    dirname: String,
    vindex: Rc<RefCell<BTreeMap<PathBuf, String>>>,
) -> String {
    // Get folder id here
    // Maybe I can just save next index
    let mut dirid: u32 = 0;
    let vexpath = vault_path.borrow().get_itext().to_owned();
    loop {
        let itempath = format!("{vexpath}d{}", dirid.to_string());
        if vindex.borrow().contains_key(&PathBuf::from(itempath)) {
            dirid += 1;
        } else {
            break;
        }
    }
    // Add folder to index
    let dir_pathcode = format!("{vexpath}d{dirid}/");
    vindex
        .borrow_mut()
        .insert(PathBuf::from(&dir_pathcode), dirname);
    return dir_pathcode;
}

fn get_vault_full_string(
    vname: Rc<String>,
    index: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    data: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
) -> String {
    let mut buffer = String::new();
    buffer.push_str(&format!("^{vname}\n[Index]\n"));
    for (path, name) in &*index.borrow() {
        buffer.push_str(&format!("{}:{name}\n", path.to_str().unwrap()));
    }
    buffer.push_str("[Data]\n");
    for (path, data) in &*data.borrow() {
        buffer.push_str(&format!("{}:{}\n", path.to_str().unwrap(), u8_to_hex(data)));
    }
    return buffer;
}

fn get_text_from_cwin(window: &gtk4::ScrolledWindow) -> Option<glib::GString> {
    let textview: gtk4::TextView = match window
        .child()?
        .first_child()?
        .first_child()?
        .first_child()?
        .dynamic_cast()
    {
        Ok(t) => t,
        Err(_) => return None,
    };
    let bounds = textview.buffer().bounds();
    Some(textview.buffer().text(&bounds.0, &bounds.1, true))
}

#[inline]
fn round_below_1(value: f64) -> f64 {
    (value * 10 as f64).round() / 10 as f64
}
