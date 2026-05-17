/*
 *   BaseAES, a simple filesystem-like vault system with strong encryption.
 *   Copyright (C) 2026  7654jp
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use gtk4::prelude::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;

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
            .title("Unlock vault")
            .modal(true)
            .build(),
    );
    vopen_window.set_application(Some(application.as_ref()));

    let vopen_grid = grid_builder(6, 6, 12, 12, 12, 12).build();

    // Password label
    let vopen_pass_label = gtk4::Label::new(Some("Vault Password:"));
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
        let vault_password = Rc::new(hashify_sha256(vopen_pass_box.text().to_string()));
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
                "Alert",
                "Vault decryption failed.\nThe password is incorrect, or the vault is broken.",
            );
            return;
        }
        let rvault_text = String::from_utf8(vault_raw.unwrap());
        if rvault_text.is_err() {
            show_alert(
                vopen_window_rc.as_ref(),
                "Error",
                "Could not convert decrypted vault data.\nThe data may be broken.",
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
    // Ask vault password
    let vopen_window = Rc::new(
        gtk4::Window::builder()
            .title("Unlock vault")
            .modal(true)
            .build(),
    );
    vopen_window.set_application(Some(application.as_ref()));

    let vopen_grid = grid_builder(6, 6, 12, 12, 12, 12).build();

    // Password label
    let vopen_pass_label = gtk4::Label::new(Some("Vault Password:"));
    vopen_grid.attach(&vopen_pass_label, 1, 1, 1, 1);
    // Password input box
    let vopen_pass_boxr = gtk4::PasswordEntry::new();
    vopen_pass_boxr.set_size_request(120, 24);
    vopen_grid.attach(&vopen_pass_boxr, 1, 2, 1, 1);
    let vopen_pass_box = Rc::new(vopen_pass_boxr);
    // Confirm button
    let vopen_ok_button = gtk4::Button::with_label("OK");
    let vopen_window_rc = Rc::clone(&vopen_window);
    vopen_ok_button.connect_clicked(move |_| match vault_data.try_recv() {
        Ok(data) => {
            selwindow_rc.close();
            let (nonce_s, data_s) = data.split_at(12);
            let nonce: [u8; 12] = nonce_s.try_into().unwrap();
            // Decode
            let vault_password = Rc::new(hashify_sha256(vopen_pass_box.text().to_string()));
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
                    "Alert",
                    "Vault decryption failed.\nThe password is incorrect, or the vault is broken.",
                );
                return;
            }
            let rvault_text = String::from_utf8(vault_raw.unwrap());
            if rvault_text.is_err() {
                show_alert(
                    vopen_window_rc.as_ref(),
                    "Error",
                    "Could not convert decrypted vault data.\nThe data may be broken.",
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
        }
        Err(TryRecvError::Empty) => {
            show_alert(
                vopen_window_rc.as_ref(),
                "Sorry",
                "Vault data loading is not finished.\nPlease try again in a few seconds.",
            );
        }
        Err(TryRecvError::Disconnected) => {
            show_alert(
                vopen_window_rc.as_ref(),
                "Error",
                "Failed to load vault data. Close this 'Unlock vault' window and try again.",
            );
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
    let (sender, receiver) = std::sync::mpsc::channel::<(u32, RawPixbuf)>();
    let idcs_trc = Rc::clone(&idcs);
    // Image decoding request handler
    let handler_raw =
        glib::source::timeout_add_local(std::time::Duration::from_millis(20), move || {
            // Fetch decoding result
            if let Ok((idx, pb_raw)) = receiver.try_recv() {
                if let Some(img_rc) = idcs_trc.borrow_mut().image_provider.get(&idx) {
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
                                    let _ = ssender.send((img_id, rawpb));
                                }
                            });
                        }
                        IDCSImageType::Jpeg => {
                            std::thread::spawn(move || {
                                if let Some(rawpb) = get_rpixbuf_from_jpeg_u8(img_data) {
                                    let _ = ssender.send((img_id, rawpb));
                                }
                            });
                        }
                        IDCSImageType::Webp => {
                            std::thread::spawn(move || {
                                if let Some(rawpb) = get_rpixbuf_from_webp_u8(img_data) {
                                    let _ = ssender.send((img_id, rawpb));
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
    let item_viewer_titlei = gtk4::Label::new(Some("Click to open files..."));
    item_viewer_titlei.set_size_request(320, 48);
    item_viewer_titlei.set_hexpand(true);
    let item_viewer_titler = LabelWithInternalText::new(item_viewer_titlei, "".to_string());
    item_grid.attach(&*item_viewer_titler, 1, 1, 1, 1);
    let item_viewer_title = Rc::new(RefCell::new(item_viewer_titler));

    let item_grid_separator = gtk4::Separator::new(gtk4::Orientation::Horizontal);
    item_grid.attach(&item_grid_separator, 1, 2, 2, 1);

    // Item viewer (window / inner grid)
    let iviewer_windowr = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .hexpand(true)
        .vexpand(true)
        .build();
    iviewer_windowr.set_size_request(400, 400);
    item_grid.attach(&iviewer_windowr, 1, 3, 2, 1);
    let item_viewer = Rc::new(iviewer_windowr);

    // Save item button
    let item_save_button = gtk4::Button::with_label("Save");
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
    item_grid.attach(&item_save_button, 2, 1, 1, 1);

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
        .label("New file")
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

    let vaf_createb = gtk4::Button::with_label("Create file");
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
        vcf_window.set_title(Some("Create new file"));
        vcf_window.set_application(Some(app_rcf.as_ref()));
        vcf_window.set_size_request(180, 72);
        vcf_window.set_modal(true);

        let vcf_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

        let vcf_title = gtk4::Label::new(Some("Enter file name:"));
        vcf_title.add_css_class("big");
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
            if let Err(emsg) = itemname_check(&filename, "File") {
                show_alert(vcf_window_rcf2.as_ref(), "Error", &emsg);
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
                        "Alert",
                        "The filename cannot be the same.",
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

            if iviewer_title_rcf2.borrow().text().ends_with("*") {
                // Do you want to discard changes in ...?
                let title_txt = iviewer_title_rcf2.borrow().text();
                let discard_window = Rc::new(gtk4::Window::new());
                discard_window.set_application(Some(app_rcf2.as_ref()));
                discard_window.set_title(Some("Discard changes?"));
                discard_window.set_default_size(220, 48);
                discard_window.set_modal(true);
                let discard_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

                let discard_title = gtk4::Label::new(Some(&format!(
                    "Do you want to discard changes in '{}'?",
                    title_txt.rsplit_once("  ").unwrap().0
                )));
                discard_grid.attach(&discard_title, 1, 1, 3, 1);

                let discard_no_button = gtk4::Button::with_label("Cancel");
                discard_no_button.set_size_request(60, 32);

                let dwindow_nrc = Rc::clone(&discard_window);
                discard_no_button.connect_clicked(move |_| {
                    dwindow_nrc.close();
                });
                discard_grid.attach(&discard_no_button, 1, 2, 1, 1);

                let discard_yes_button = gtk4::Button::with_label("Discard");
                discard_yes_button.set_size_request(60, 32);

                let index_drc = Rc::clone(&vindex_rcf2);
                let data_drc = Rc::clone(&vdata_rcf2);
                let idcs_drc = Rc::clone(&idcs_rcf2);
                let ipath_drc = Rc::clone(&ipath_rc);
                let nviewer_drc = Rc::clone(&iviewer_title_rcf2);
                let cviewer_drc = Rc::clone(&iviewer_rcf2);
                let dwindow_yrc = Rc::clone(&discard_window);
                discard_yes_button.connect_clicked(move |_| {
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
                        .set_itext(format!("{}:{title}^", ipath_drc.as_ref()));

                    dwindow_yrc.close();
                });
                discard_grid.attach(&discard_yes_button, 3, 2, 1, 1);

                discard_window.set_child(Some(&discard_grid));
                discard_window.present();
            } else {
                let fileid = PathBuf::from(ipath_rc.as_ref());
                let title = match vindex_rcf2.borrow().get(&fileid) {
                    Some(s) => s.to_owned(),
                    None => return,
                };
                let data = match vdata_rcf2.borrow().get(&fileid) {
                    Some(d) => d.to_owned(),
                    None => return,
                };
                iviewer_rcf2.set_child(Some(
                    get_item_viewer_grid(
                        &title,
                        &data,
                        Rc::clone(&vindex_rcf2),
                        Rc::clone(&vdata_rcf2),
                        Rc::clone(&iviewer_title_rcf2),
                        Rc::clone(&idcs_rcf2),
                    )
                    .as_ref(),
                ));

                iviewer_title_rcf2
                    .borrow_mut()
                    .set_itext(format!("{}:{title}^", ipath_rc.as_ref()));
            }
        });
        vcf_grid.attach(&vcf_ok_button, 2, 2, 1, 1);

        vcf_window.set_child(Some(&vcf_grid));
        vcf_window.present();
    });
    vaf_vbox.append(&vaf_createb);

    let vaf_importb = gtk4::Button::with_label("Import file");
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
            .title("Select file to import...")
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
                            "Error",
                            "Failed to open the selected file.",
                        );
                        return;
                    }
                };

                // File name filtering
                let ofilename = filepath.file_name().unwrap().to_str();
                if ofilename.is_none() {
                    show_alert(
                        vwindow_rif2.as_ref(),
                        "Error",
                        "The name of the selected file is invalid for this app.",
                    );
                    return;
                };
                let mut filename = ofilename.unwrap().to_string();
                if let Err(emsg) = itemname_check(&filename, "File") {
                    show_alert(vwindow_rif2.as_ref(), "Error", &emsg);
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
                            let (fname, ext) = filename.rsplit_once(".").unwrap();
                            filename = format!("{fname} (Copy).{ext}");
                        } else {
                            filename = format!("{filename} (Copy)");
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

    vaf_popover.set_child(Some(&vaf_vbox));
    vault_add_file.set_popover(Some(vaf_popover.as_ref()));
    control_grid.attach(&vault_add_file, 1, 1, 1, 1);

    // Add folder
    let vault_add_folder = gtk4::Button::with_label("New folder");
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
        vad_window.set_title(Some("Add folder..."));
        vad_window.set_application(Some(app_rad.as_ref()));
        vad_window.set_modal(true);
        let vad_grid = grid_builder(6, 12, 12, 12, 12, 8).build();

        let vad_title = gtk4::Label::new(Some("Enter folder name:"));
        vad_title.add_css_class("big");
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
            if let Err(emsg) = itemname_check(&dirname, "Folder") {
                show_alert(vad_window_rad2.as_ref(), "Error", &emsg);
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
                        "Alert",
                        "The folder name cannot be the same.",
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
    let vault_rename_item = gtk4::Button::with_label("Rename");
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
        let mut viewer_id = iviewer_title_rri.borrow().get_itext().to_owned();
        if viewer_id.ends_with("^") {
            viewer_id.pop();
        }
        let (vfileid, vtitle) = match viewer_id.split_once(":") {
            Some(viewerid_sp) => viewerid_sp,
            None => {
                show_alert(
                    vwindow_rri.as_ref(),
                    "Alert",
                    "No file is selected.\nSelect a file you want to rename and try again.",
                );
                return;
            }
        };
        let vri_window = Rc::new(gtk4::Window::new());
        vri_window.set_title(Some("Rename item..."));
        vri_window.set_application(Some(app_rri.as_ref()));
        vri_window.set_modal(true);
        let vri_grid = grid_builder(6, 12, 12, 12, 12, 8).build();

        let vri_title = gtk4::Label::new(Some(&format!("Rename '{vtitle}' to:")));
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
                        "Alert",
                        "The filename cannot be the same.",
                    );
                    return;
                }
            }

            let mut vindex_b = vindex_rri2.borrow_mut();

            let rmres = vindex_b.remove_entry(vfileid_rri2.as_ref());
            if rmres.is_none() {
                show_alert(
                    vri_window_rri2.as_ref(),
                    "Error",
                    "Failed to find the selected item.",
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
                .set_itext(itext.replace(curr_title, &format!("{newname}^")));

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
            .label("More...")
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
    let voc_move_item = gtk4::Button::with_label("Move item");
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
            // Move file only
            let mut fileinfo = iviewer_title_rom.borrow().get_itext().to_owned();
            if fileinfo.ends_with("^") {
                fileinfo.pop();
            }
            let (fileid_str, filename) = match fileinfo.split_once(":") {
                Some((id, name)) => (id.to_owned(), name.to_owned()),
                None => {
                    voc_button_rom.popdown();
                    show_alert(
                        vwindow_rom.as_ref(),
                        "Alert",
                        "No file is selected.\nSelect a file you want to move and try again.",
                    );
                    return;
                }
            };

            let imove_window = Rc::new(gtk4::Window::new());
            imove_window.set_title(Some("Move to..."));
            imove_window.set_application(Some(app_rom.as_ref()));
            imove_window.set_size_request(240, 400);

            let imove_grid = grid_builder(6, 12, 12, 12, 6, 6).build();
            imove_grid.set_halign(gtk4::Align::Center);

            // Path viewer
            let imove_expathi = gtk4::Entry::builder().text("/").editable(false).build();
            imove_expathi.add_css_class("normal");
            imove_expathi.set_size_request(240, 40);
            let imove_expath = Rc::new(RefCell::new(EntryWithInternalText::new(
                imove_expathi,
                "/".to_owned(),
            )));
            imove_grid.attach(&**imove_expath.borrow(), 1, 1, 1, 1);

            // Move confirm button
            let imove_cfbutton = gtk4::Button::with_label("Move");
            imove_cfbutton.add_css_class("normal");
            imove_cfbutton.set_size_request(80, 40);

            // Rc suffix: _romi
            let changed_romi = Rc::clone(&changed_rom);
            let vindex_romi = Rc::clone(&vindex_rom);
            let vdata_romi = Rc::clone(&vdata_rom);
            let idcs_romi = Rc::clone(&idcs_rom);
            let app_romi = Rc::clone(&app_rom);
            let iviewer_title_romi = Rc::clone(&iviewer_title_rom);
            let vfilelist_romi = Rc::clone(&vfilelist_rom);
            let iviewer_romi = Rc::clone(&iviewer_rom);
            let vexpath_romi = Rc::clone(&vexpath_rom);
            let imwindow_rc = Rc::clone(&imove_window);
            let iexpath_rc = Rc::clone(&imove_expath);
            imove_cfbutton.connect_clicked(move |_| {
                let (curr_ipath, name) =
                    match iviewer_title_romi.borrow().get_itext().split_once(":") {
                        Some((cipath_s, name_s)) => (cipath_s.to_owned(), name_s.to_owned()),
                        None => {
                            show_alert(
                                imwindow_rc.as_ref(),
                                "Error",
                                "Failed to get the file information.",
                            );
                            return;
                        }
                    };
                let fdata = match vdata_romi.borrow().get(&PathBuf::from(curr_ipath)) {
                    Some(d) => d.to_owned(),
                    None => {
                        show_alert(
                            imwindow_rc.as_ref(),
                            "Error",
                            "Failed to get file data to copy.",
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
                vindex_romi.borrow_mut().remove(&fileid);

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
                Rc::clone(&app_rom),
                Rc::clone(&imove_fviewer),
                Rc::clone(&vindex_rom),
                Rc::clone(&vdata_rom),
                PathBuf::from("/"),
                Rc::clone(&imove_expath),
            ) {
                imove_fviewer.append(&*button);
            }

            imove_window.set_child(Some(&imove_grid));
            imove_window.set_modal(true);
            imove_window.present();
        } else if iviewer_title_rom.borrow().get_itext() == "" {
            // Move dir
            let dmove_window = Rc::new(gtk4::Window::new());
            dmove_window.set_title(Some("Move to..."));
            dmove_window.set_application(Some(app_rom.as_ref()));
            dmove_window.set_size_request(240, 400);

            let dmove_grid = grid_builder(6, 12, 12, 12, 6, 6).build();
            dmove_grid.set_halign(gtk4::Align::Center);

            // Path viewer
            let mut parent = PathBuf::from(vexpath_rom.borrow().text());
            parent.pop();
            let dmove_expathi = gtk4::Entry::builder()
                .text(parent.display().to_string())
                .editable(false)
                .build();
            dmove_expathi.add_css_class("normal");
            dmove_expathi.set_size_request(240, 40);

            parent = PathBuf::from(vexpath_rom.borrow().get_itext());
            parent.pop();
            let dmove_expath = Rc::new(RefCell::new(EntryWithInternalText::new(
                dmove_expathi,
                parent.display().to_string(),
            )));
            dmove_grid.attach(&**dmove_expath.borrow(), 1, 1, 1, 1);

            // Move confirm button
            let dmove_cfbutton = gtk4::Button::with_label("Move");
            dmove_cfbutton.add_css_class("normal");
            dmove_cfbutton.set_size_request(80, 40);

            // Rc suffix: _romd
            let changed_romd = Rc::clone(&changed_rom);
            let vindex_romd = Rc::clone(&vindex_rom);
            let vdata_romd = Rc::clone(&vdata_rom);
            let idcs_romd = Rc::clone(&idcs_rom);
            let app_romd = Rc::clone(&app_rom);
            let iviewer_title_romd = Rc::clone(&iviewer_title_rom);
            let vfilelist_romd = Rc::clone(&vfilelist_rom);
            let iviewer_romd = Rc::clone(&iviewer_rom);
            let vexpath_romd = Rc::clone(&vexpath_rom);
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
                                "Error",
                                "Failed to get file data to copy.",
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
                Rc::clone(&app_rom),
                Rc::clone(&dmove_fviewer),
                Rc::clone(&vindex_rom),
                Rc::clone(&vdata_rom),
                PathBuf::from(dmove_expath.borrow().get_itext()),
                Rc::clone(&dmove_expath),
            ) {
                dmove_fviewer.append(&*button);
            }

            dmove_window.set_child(Some(&dmove_grid));
            dmove_window.set_modal(true);
            dmove_window.present();
        } else {
            // Move file or dir
            let vmi_window = Rc::new(gtk4::Window::new());
            vmi_window.set_title(Some("Select what to move..."));
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

            let vmi_mfile = gtk4::Button::with_label("Move file");
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
                // Move file
                vmi_window_romsf.close();

                let mut fileinfo = iviewer_title_romsf.borrow().get_itext().to_owned();
                if fileinfo.ends_with("^") {
                    fileinfo.pop();
                }
                let (fileid_str, filename) = match fileinfo.split_once(":") {
                    Some((id, name)) => (id.to_owned(), name.to_owned()),
                    None => {
                        show_alert(
                            vwindow_romsf.as_ref(),
                            "Error",
                            "No file is selected.\nSelect a file you want to move, then try again.",
                        );
                        return;
                    }
                };

                let imove_window = Rc::new(gtk4::Window::new());
                imove_window.set_title(Some("Move to..."));
                imove_window.set_application(Some(app_romsf.as_ref()));
                imove_window.set_size_request(240, 400);

                let imove_grid = grid_builder(6, 12, 12, 12, 6, 6).build();
                imove_grid.set_halign(gtk4::Align::Center);

                // Path viewer
                let imove_expathi = gtk4::Entry::builder()
                    .text(vexpath_romsf.borrow().text())
                    .editable(false)
                    .build();
                imove_expathi.add_css_class("normal");
                imove_expathi.set_size_request(240, 40);
                let imove_expath = Rc::new(RefCell::new(EntryWithInternalText::new(
                    imove_expathi,
                    vexpath_romsf.borrow().get_itext().to_owned(),
                )));
                imove_grid.attach(&**imove_expath.borrow(), 1, 1, 1, 1);

                // Move confirm button
                let imove_cfbutton = gtk4::Button::with_label("Move");
                imove_cfbutton.add_css_class("normal");
                imove_cfbutton.set_size_request(80, 40);

                // Rc suffix: _romsfc
                let changed_romsfc = Rc::clone(&changed_romsf);
                let vindex_romsfc = Rc::clone(&vindex_romsf);
                let vdata_romsfc = Rc::clone(&vdata_romsf);
                let idcs_romsfc = Rc::clone(&idcs_romsf);
                let app_romsfc = Rc::clone(&app_romsf);
                let iviewer_title_romsfc = Rc::clone(&iviewer_title_romsf);
                let vfilelist_romsfc = Rc::clone(&vfilelist_romsf);
                let iviewer_romsfc = Rc::clone(&iviewer_romsf);
                let vexpath_romsfc = Rc::clone(&vexpath_romsf);
                let imwindow_rc = Rc::clone(&imove_window);
                let iexpath_rc = Rc::clone(&imove_expath);
                imove_cfbutton.connect_clicked(move |_| {
                    let (curr_ipath, name) =
                        match iviewer_title_romsfc.borrow().get_itext().split_once(":") {
                            Some((cipath_s, name_s)) => (cipath_s.to_owned(), name_s.to_owned()),
                            None => {
                                show_alert(
                                    imwindow_rc.as_ref(),
                                    "Error",
                                    "Failed to get the file information.",
                                );
                                return;
                            }
                        };
                    let fdata = match vdata_romsfc.borrow().get(&PathBuf::from(curr_ipath)) {
                        Some(d) => d.to_owned(),
                        None => {
                            show_alert(
                                imwindow_rc.as_ref(),
                                "Error",
                                "Failed to get file data to copy.",
                            );
                            return;
                        }
                    };
                    let new_ipath = vault_append_file(
                        Rc::clone(&iexpath_rc),
                        filename.clone(),
                        Some(&fdata),
                        Rc::clone(&vindex_romsfc),
                        Rc::clone(&vdata_romsfc),
                    );
                    changed_romsfc.borrow_mut().set(true);
                    iviewer_title_romsfc
                        .borrow_mut()
                        .set_itext(new_ipath + ":" + &name);

                    let fileid = PathBuf::from(&fileid_str);
                    vindex_romsfc.borrow_mut().remove(&fileid);
                    vindex_romsfc.borrow_mut().remove(&fileid);

                    loop {
                        let dwidget = match vfilelist_romsfc.last_child() {
                            Some(w) => w,
                            None => break,
                        };
                        vfilelist_romsfc.remove(&dwidget);
                    }
                    for button in get_files_from_vpath(
                        Rc::clone(&app_romsfc),
                        Rc::clone(&vfilelist_romsfc),
                        Rc::clone(&idcs_romsfc),
                        Rc::clone(&vindex_romsfc),
                        Rc::clone(&vdata_romsfc),
                        PathBuf::from(vexpath_romsfc.borrow().get_itext()),
                        Rc::clone(&iviewer_title_romsfc),
                        Rc::clone(&iviewer_romsfc),
                        Rc::clone(&vexpath_romsfc),
                    ) {
                        vfilelist_romsfc.append(&*button);
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
                    Rc::clone(&app_romsf),
                    Rc::clone(&imove_fviewer),
                    Rc::clone(&vindex_romsf),
                    Rc::clone(&vdata_romsf),
                    PathBuf::from(vexpath_romsf.borrow().get_itext()),
                    Rc::clone(&imove_expath),
                ) {
                    imove_fviewer.append(&*button);
                }

                imove_window.set_child(Some(&imove_grid));
                imove_window.set_modal(true);
                imove_window.present();
            });
            vmi_hbox.append(&vmi_mfile);

            let vmi_mdir = gtk4::Button::with_label("Move directory");
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

                let dmove_window = Rc::new(gtk4::Window::new());
                dmove_window.set_title(Some("Move to..."));
                dmove_window.set_application(Some(app_romsd.as_ref()));
                dmove_window.set_size_request(240, 400);

                let dmove_grid = grid_builder(6, 12, 12, 12, 6, 6).build();
                dmove_grid.set_halign(gtk4::Align::Center);

                // Path viewer
                let mut parent = PathBuf::from(vexpath_romsd.borrow().text());
                parent.pop();
                let dmove_expathi = gtk4::Entry::builder()
                    .text(parent.display().to_string())
                    .editable(false)
                    .build();
                dmove_expathi.add_css_class("normal");
                dmove_expathi.set_size_request(240, 40);

                parent = PathBuf::from(vexpath_romsd.borrow().get_itext());
                parent.pop();
                let dmove_expath = Rc::new(RefCell::new(EntryWithInternalText::new(
                    dmove_expathi,
                    parent.display().to_string(),
                )));
                dmove_grid.attach(&**dmove_expath.borrow(), 1, 1, 1, 1);

                // Move confirm button
                let dmove_cfbutton = gtk4::Button::with_label("Move");
                dmove_cfbutton.add_css_class("normal");
                dmove_cfbutton.set_size_request(80, 40);

                // Rc suffix: _romsdc
                let changed_romsdc = Rc::clone(&changed_romsd);
                let vindex_romsdc = Rc::clone(&vindex_romsd);
                let vdata_romsdc = Rc::clone(&vdata_romsd);
                let idcs_romsdc = Rc::clone(&idcs_romsd);
                let app_romsdc = Rc::clone(&app_romsd);
                let iviewer_title_romsdc = Rc::clone(&iviewer_title_romsd);
                let vfilelist_romsdc = Rc::clone(&vfilelist_romsd);
                let iviewer_romsdc = Rc::clone(&iviewer_romsd);
                let vexpath_romsdc = Rc::clone(&vexpath_romsd);
                let dmwindow_rc = Rc::clone(&dmove_window);
                let dexpath_rc = Rc::clone(&dmove_expath);
                dmove_cfbutton.connect_clicked(move |_| {
                    let from_path = vexpath_romsdc.borrow().get_itext().clone();
                    if &from_path == dexpath_rc.borrow().get_itext() {
                        dmwindow_rc.close();
                        return;
                    }
                    let mut dirpath = vexpath_romsdc.borrow().text().to_string();
                    dirpath.pop();
                    let dirname = dirpath.rsplit_once("/").unwrap().1.to_owned() + "/";

                    let new_ipath = vault_append_folder(
                        Rc::clone(&dexpath_rc),
                        dirname,
                        Rc::clone(&vindex_romsdc),
                    );
                    dexpath_rc.borrow_mut().set_itext(new_ipath);

                    // Search for the file to copy
                    // We can't actually copy it inside this loop,
                    // because the loop itself requires vindex to be borrowed
                    let mut copylist: Vec<(PathBuf, String)> = Vec::new();
                    for (spath, sname) in &*vindex_romsdc.borrow() {
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
                    for (ipath, name) in copylist {
                        let ipath = PathBuf::from(ipath);
                        let fdata = match vdata_romsdc.borrow().get(&ipath) {
                            Some(d) => d.to_owned(),
                            None => {
                                show_alert(
                                    dmwindow_rc.as_ref(),
                                    "Error",
                                    "Failed to get file data to copy.",
                                );
                                return;
                            }
                        };
                        vault_append_file(
                            Rc::clone(&dexpath_rc),
                            name.clone(),
                            Some(&fdata),
                            Rc::clone(&vindex_romsdc),
                            Rc::clone(&vdata_romsdc),
                        );

                        vindex_romsdc.borrow_mut().remove(&ipath);
                        vindex_romsdc.borrow_mut().remove(&ipath);
                    }

                    // Remove the origin folder
                    let mut from_pb = PathBuf::from(from_path);
                    vindex_romsdc.borrow_mut().remove(&from_pb);
                    changed_romsdc.borrow_mut().set(true);

                    // Go up to the existing folder
                    let mut showpath = PathBuf::from(vexpath_romsdc.borrow().text());
                    showpath.pop();
                    vexpath_romsdc
                        .borrow_mut()
                        .set_text(&showpath.display().to_string());
                    from_pb.pop();
                    vexpath_romsdc
                        .borrow_mut()
                        .set_itext(from_pb.display().to_string());

                    loop {
                        let dwidget = match vfilelist_romsdc.last_child() {
                            Some(w) => w,
                            None => break,
                        };
                        vfilelist_romsdc.remove(&dwidget);
                    }
                    for button in get_files_from_vpath(
                        Rc::clone(&app_romsdc),
                        Rc::clone(&vfilelist_romsdc),
                        Rc::clone(&idcs_romsdc),
                        Rc::clone(&vindex_romsdc),
                        Rc::clone(&vdata_romsdc),
                        from_pb,
                        Rc::clone(&iviewer_title_romsdc),
                        Rc::clone(&iviewer_romsdc),
                        Rc::clone(&vexpath_romsdc),
                    ) {
                        vfilelist_romsdc.append(&*button);
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
                    Rc::clone(&app_romsd),
                    Rc::clone(&dmove_fviewer),
                    Rc::clone(&vindex_romsd),
                    Rc::clone(&vdata_romsd),
                    PathBuf::from(dmove_expath.borrow().get_itext()),
                    Rc::clone(&dmove_expath),
                ) {
                    dmove_fviewer.append(&*button);
                }

                dmove_window.set_child(Some(&dmove_grid));
                dmove_window.set_modal(true);
                dmove_window.present();
            });
            vmi_hbox.append(&vmi_mdir);

            vmi_window.set_child(Some(&vmi_hbox));
            vmi_window.set_modal(true);
            vmi_window.present();
        }
    });
    voc_grid.attach(&voc_move_item, 1, 1, 1, 1);

    // Reload
    let voc_reload_button = gtk4::Button::with_label("Reload");
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
    let voc_export_item = gtk4::Button::with_label("Export file");
    voc_export_item.set_size_request(96, 40);

    // Rc suffix: _roe
    let iviewer_title_roe = Rc::clone(&item_viewer_title);
    let voc_button_roe = Rc::clone(&vault_other_ctrl);
    let vwindow_roe = Rc::clone(&vault_window);
    let vdata_roe = Rc::clone(&vdata);
    voc_export_item.connect_clicked(move |_| {
        voc_button_roe.popdown();
        let mut filename = iviewer_title_roe.borrow().get_itext().to_owned();
        if filename.ends_with("^") {
            filename.pop();
        }
        let (fileid_str, title) = match filename.split_once(":") {
            Some(f) => f,
            None => {
                show_alert(
                    vwindow_roe.as_ref(),
                    "Error",
                    "No file is selected.\nSelect a file you want to export, then try again.",
                );
                return;
            }
        };

        // File save window
        let file_dialog = gtk4::FileDialog::builder()
            .modal(true)
            .title("Export to...")
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
                        "Error",
                        "Failed to open the selected file.",
                    );
                    return;
                }
                let file_path = &raw_gfile.unwrap().uri()[7..];

                let mut file = match fs::File::create(&file_path) {
                    Ok(f) => f,
                    Err(_) => {
                        show_alert(
                            vwindow_roes.as_ref(),
                            "Error",
                            "Failed to open the selected file.",
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
                            "Error",
                            "Failed to get the data of the selected file.",
                        );
                        return;
                    }
                };
                let wres = file.write_all(vdata);
                if wres.is_err() {
                    show_alert(
                        vwindow_roes.as_ref(),
                        "Error",
                        "Failed to export the selected file.",
                    );
                }
                let fres = file.flush();
                if fres.is_err() {
                    show_alert(
                        vwindow_roes.as_ref(),
                        "Error",
                        "Failed to flush the output stream.",
                    );
                }
            },
        );
    });
    voc_grid.attach(&voc_export_item, 1, 2, 1, 1);

    // Delete
    let voc_delete_item = gtk4::Button::with_label("Delete item");
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
            vdi_window.set_title(Some("Select what to delete..."));
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

            let vdi_delete_file = gtk4::Button::with_label("Delete file");
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
                    true
                );
            });
            vdi_hbox.append(&vdi_delete_file);

            let vdi_delete_dir = gtk4::Button::with_label("Delete folder");
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
                delwindow.set_title(Some("Confirm deletion?"));
                delwindow.set_application(Some(app_rodd.as_ref()));
                delwindow.set_size_request(240, 96);
                delwindow.set_modal(true);

                let del_grid = grid_builder(12, 12, 12, 12, 6, 12).build();

                let currpath_str = Rc::new(vexpath_rodd.borrow().get_itext().to_owned());
                let currpath_dirname = match vindex_rodd.borrow()
                    .get(&PathBuf::from(currpath_str.as_ref()))
                {
                    Some(n) => n.to_owned(),
                    None => {
                        show_alert(vwindow_rodd.as_ref(), "Error",
                            "Failed to get the name of current folder.");
                        return;
                    }
                };


                let del_title = gtk4::Label::new(Some(&format!(
                    "Are you sure you want to delete\nthe folder '{currpath_dirname}' and everything inside ?",
                )));
                del_grid.attach(&del_title, 1, 1, 3, 1);

                let del_no_button = gtk4::Button::with_label("No");
                del_no_button.set_size_request(40, 28);

                // Rc suffix: _roddn
                let vdi_window_roddn = Rc::clone(&vdi_window_rodd);
                let delwindow_roddn = Rc::clone(&delwindow);
                del_no_button.connect_clicked(move |_| {
                    delwindow_roddn.close();
                    vdi_window_roddn.close();
                });
                del_grid.attach(&del_no_button, 1, 2, 1, 1);

                let del_yes_button = gtk4::Button::with_label("Yes");
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
                    let keys_to_remove: Vec<PathBuf> = vindex_roddy.borrow().keys()
                        .filter(|path| {path.starts_with(currpath_roddy.as_ref())}).cloned().collect();
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

                    if iviewer_title_roddy.borrow().get_itext().split_once(":").unwrap().0.starts_with(currpath_roddy.as_ref()) {
                        iviewer_title_roddy
                            .borrow_mut()
                            .set_text("Click to open files...");
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
            // Check if there're any unsaved changes
            if iviewer_title_rc.borrow().text().ends_with("*") {
                let isave_window = Rc::new(gtk4::Window::new());
                isave_window.set_application(Some(wcl_app.as_ref()));
                isave_window.set_title(Some("Save file changes?"));
                isave_window.set_default_size(180, 48);
                isave_window.set_modal(true);
                let isave_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

                let isave_title = gtk4::Label::new(Some(&format!(
                    "Do you want to save changes in {}?",
                    iviewer_title_rc
                        .borrow()
                        .text()
                        .rsplit_once("  ")
                        .unwrap()
                        .0
                )));
                isave_grid.attach(&isave_title, 1, 1, 3, 1);

                let isave_yes_button = gtk4::Button::with_label("Save");
                isave_yes_button.set_size_request(60, 32);

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

                let isave_no_button = gtk4::Button::with_label("Don't save");
                isave_no_button.set_size_request(60, 32);

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

                let isave_cancel_button = gtk4::Button::with_label("Cancel");
                isave_cancel_button.set_size_request(60, 32);

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
            let data_frc = Rc::clone(&data);
            let index_frc = Rc::clone(&index);
            let ipath_frc = Rc::clone(&ipath);
            let idcs_frc = Rc::clone(&idcs);
            let app_frc = Rc::clone(&application);
            let name_viewer_frc = Rc::clone(&name_viewer);
            let content_viewer_frc = Rc::clone(&content_viewer);
            lbutton.connect_clicked(move |_| {
                let (inamep_str, mut fname) =
                    match name_viewer_frc.borrow().get_itext().split_once(":") {
                        Some(s) => (s.0.to_owned(), s.1.to_owned()),
                        None => (String::new(), String::new()),
                    };
                if fname.ends_with("^") {
                    fname.pop();
                }
                if inamep_str.starts_with("/")
                    && ipath_frc.as_os_str() == inamep_str.as_str()
                    && !fname.ends_with("bgsf")
                {
                    return;
                }

                // Cancel drawing for the current
                // If there're any image requesting to be shown
                if let Some(child) = content_viewer_frc.child() {
                    if let Some(gchild) = child.first_child() {
                        for grid_child in gchild.observe_children().into_iter() {
                            if grid_child.is_err() {
                                continue;
                            }
                            if let Ok(image) = grid_child.unwrap().dynamic_cast::<gtk4::Image>() {
                                if image.css_classes().len() == 1 {
                                    let imgid: u32 =
                                        str::parse(&image.css_classes()[0].clone()).unwrap();
                                    idcs_frc.borrow_mut().queue.remove(&imgid);
                                    idcs_frc.borrow_mut().image_provider.remove(&imgid);
                                }
                            }
                        }
                    }
                };

                let iname = name_viewer_frc.borrow().text();
                if iname.ends_with("*") {
                    // Do you want to discard changes in ...?
                    let discard_window = Rc::new(gtk4::Window::new());
                    discard_window.set_application(Some(app_frc.as_ref()));
                    discard_window.set_title(Some("Discard changes?"));
                    discard_window.set_default_size(220, 48);
                    discard_window.set_modal(true);
                    let discard_grid = grid_builder(6, 12, 12, 12, 6, 6).build();

                    let discard_title = gtk4::Label::new(Some(&format!(
                        "Do you want to discard changes in '{}'?",
                        iname.rsplit_once("  ").unwrap().0
                    )));
                    discard_grid.attach(&discard_title, 1, 1, 3, 1);

                    let discard_no_button = gtk4::Button::with_label("Cancel");
                    discard_no_button.set_size_request(60, 32);

                    let dwindow_nrc = Rc::clone(&discard_window);
                    discard_no_button.connect_clicked(move |_| {
                        dwindow_nrc.close();
                    });
                    discard_grid.attach(&discard_no_button, 1, 2, 1, 1);

                    let discard_yes_button = gtk4::Button::with_label("Discard");
                    discard_yes_button.set_size_request(60, 32);

                    let index_drc = Rc::clone(&index_frc);
                    let data_drc = Rc::clone(&data_frc);
                    let ipath_drc = Rc::clone(&ipath);
                    let idcs_drc = Rc::clone(&idcs_frc);
                    let nviewer_drc = Rc::clone(&name_viewer_frc);
                    let cviewer_drc = Rc::clone(&content_viewer_frc);
                    let dwindow_yrc = Rc::clone(&discard_window);
                    discard_yes_button.connect_clicked(move |_| {
                        let fileid_str = ipath_drc.to_str().unwrap();
                        let fileid = PathBuf::from(&fileid_str);
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
                            .set_itext(format!("{fileid_str}:{title}^"));

                        dwindow_yrc.close();
                    });
                    discard_grid.attach(&discard_yes_button, 3, 2, 1, 1);

                    discard_window.set_child(Some(&discard_grid));
                    discard_window.present();
                } else {
                    let fileid_str = ipath.to_str().unwrap();
                    let fileid = PathBuf::from(&fileid_str);
                    let title = match index_frc.borrow().get(&fileid) {
                        Some(s) => s.to_owned(),
                        None => return,
                    };
                    let data = match data_frc.borrow().get(&fileid) {
                        Some(d) => d.to_owned(),
                        None => return,
                    };
                    content_viewer_frc.set_child(Some(
                        get_item_viewer_grid(
                            &title,
                            &data,
                            Rc::clone(&index_frc),
                            Rc::clone(&data_frc),
                            Rc::clone(&name_viewer_frc),
                            Rc::clone(&idcs_frc),
                        )
                        .as_ref(),
                    ));

                    name_viewer_frc
                        .borrow_mut()
                        .set_itext(format!("{fileid_str}:{title}^"));
                }
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
                    warn_label.set_text(&format!(
                        "{}\nWarning: Invalid styling at line {lcount} > {line}",
                        warn_label.text()
                    ));
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
                    warn_label.set_text(&format!(
                        "{}\nWarning: Invalid styling at line {lcount}  ({line})",
                        warn_label.text()
                    ));
                }
            } else {
                warn_label.set_text(&format!(
                    "{}\nWarning: invalid format at line {lcount} > {line}",
                    warn_label.text()
                ));
            }
            lcount += 1;
        }
    } else if fmime == "image/png" || fmime == "image/jpeg" || fmime == "image/webp" {
        // Show as image
        ititle_label.borrow_mut().label.set_text(title);
        let image_viewer = Rc::new(gtk4::Picture::builder().hexpand(true).vexpand(true).build());

        let owneddata = data.to_owned();
        idcs.borrow_mut().request_decode(
            IDCSImageType::from_str_name(fmime).unwrap(),
            owneddata,
            Rc::clone(&image_viewer),
        );
        iviewer_grid.attach(image_viewer.as_ref(), 1, 1, 1, 1);
    } else if fmime.starts_with("image") {
        let text_viewer = gtk4::TextView::builder()
            .hexpand(true)
            .vexpand(true)
            .editable(false)
            .wrap_mode(gtk4::WrapMode::Word)
            .build();
        text_viewer.add_css_class("normal");
        text_viewer
            .buffer()
            .set_text("Sorry, only PNG/JPEG/WebP Images are supported.");
        iviewer_grid.attach(&text_viewer, 1, 1, 1, 1);
    } else if data_utf8.is_ok() {
        // Show as text
        ititle_label.borrow_mut().label.set_text(&title_fmt);

        let text_viewer = gtk4::TextView::builder()
            .hexpand(true)
            .vexpand(true)
            .build();
        text_viewer.add_css_class("normal");
        text_viewer.buffer().set_text(data_utf8.unwrap());

        let ititle_label_rc = Rc::clone(&ititle_label);
        text_viewer.buffer().connect_changed(move |_| {
            let mut title_text = ititle_label_rc.borrow().get_itext().to_owned();
            if title_text.ends_with("^") {
                title_text.pop();
                ititle_label_rc.borrow_mut().set_itext(title_text);
            }
            let item_text = ititle_label_rc.borrow().label.text().to_string();
            if !item_text.ends_with("*") {
                ititle_label_rc
                    .borrow_mut()
                    .label
                    .set_text(&(item_text + "  *"));
            }
        });
        iviewer_grid.attach(&text_viewer, 1, 1, 1, 1);
    } else {
        ititle_label
            .borrow_mut()
            .label
            .set_text(&(title_fmt + "  :  Binary"));
        let text_viewer = gtk4::TextView::builder()
            .hexpand(true)
            .vexpand(true)
            .editable(false)
            .wrap_mode(gtk4::WrapMode::Word)
            .build();
        text_viewer.add_css_class("normal");
        text_viewer
            .buffer()
            .set_text("Editing/Viewing binary file will be implemented someday.");
        iviewer_grid.attach(&text_viewer, 1, 1, 1, 1);
    };

    Rc::clone(&iviewer_grid)
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
    let textview: gtk4::TextView =
        match window.child()?.first_child()?.first_child()?.dynamic_cast() {
            Ok(t) => t,
            Err(_) => return None,
        };
    let bounds = textview.buffer().bounds();
    Some(textview.buffer().text(&bounds.0, &bounds.1, true))
}
