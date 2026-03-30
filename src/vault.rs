use glib::clone;
use gtk4::prelude::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;

use crate::tools::*;
use crate::types::*;

pub fn ask_vault_password_and_open(
    application: Rc<gtk4::Application>,
    decoded_master_data: Rc<String>,
    vault_data: String,
    commlabel: Rc<gtk4::Label>,
) {
    // Ask vault password
    let vopen_window = gtk4::Window::builder()
        .title("Unlock vault")
        .modal(true)
        .build();
    vopen_window.set_application(Some(application.as_ref()));

    let vopen_grid = gtk4::Grid::builder()
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .row_spacing(12)
        .column_spacing(12)
        .build();

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
    vopen_ok_button.connect_clicked(clone!(
        #[weak]
        vopen_window,
        move |_| {
            // Decode
            let vault_bin = match hex_to_u8(&vault_data) {
                Ok(b) => b,
                Err(_) => {
                    show_alert(&vopen_window, "Error", "Failed to parse vault data.");
                    return;
                }
            };
            let vault_password = Rc::new(hashify_sha256(
                &vopen_pass_box.text().to_string(),
            ));
            let vault_raw = match decrypt_aes_with_key(
                &vopen_window,
                &vault_bin[12..],
                vault_bin[0..12].try_into().unwrap(),
                vault_password.as_ref(),
                false,
            ) {
                Some(bin) => bin,
                None => {
                    show_alert(&vopen_window, "Alert",
                        "Vault decryption failed.\nThe password is incorrect, or the vault is broken.");
                    return;
                },
            };
            let rvault_text = String::from_utf8(vault_raw);
            if rvault_text.is_err() {
                show_alert(&vopen_window, "Error",
                    "Could not convert decrypted vault data.\nThe data may be broken.");
                return;
            };
            // Vault decryption is successful here
            vopen_window.close();

            open_vault(
                Rc::clone(&application),
                Rc::new(rvault_text.unwrap()),
                Rc::clone(&commlabel),
                Rc::clone(&vault_password),
                Rc::clone(&decoded_master_data),
            );
        }
    ));
    vopen_grid.attach(&vopen_ok_button, 2, 2, 1, 1);

    vopen_window.set_child(Some(&vopen_grid));
    vopen_window.present();
}

fn open_vault(
    application: Rc<gtk4::Application>,
    vault_text: Rc<String>,
    commlabel: Rc<gtk4::Label>,
    vault_password: Rc<[u8; 32]>,
    decoded_master_data: Rc<String>,
) {
    // Take hash for checking changes
    eprintln!("Initial vault data:\n{vault_text}");
    let hash_initial = hashify_sha256(vault_text.as_ref());
    // Convert to three
    let vault_data = match vault_decode(vault_text.as_ref()) {
        Some(data) => data,
        None => return,
    };
    let vname = Rc::new(vault_data.0);
    let vindex = Rc::new(RefCell::new(vault_data.1));
    let vdata = Rc::new(RefCell::new(vault_data.2));

    // Window
    let vault_window = Rc::new(gtk4::Window::new());
    vault_window.set_application(Some(application.as_ref()));
    vault_window.set_default_size(720, 480);
    vault_window.set_title(Some(&format!("FileBase Explorer  -  {vname}")));

    let vault_hbox = gtk4::Box::builder()
        .spacing(6)
        .hexpand(true)
        .vexpand(true)
        .build();

    // Item grid, right side of the vault window
    let item_grid = gtk4::Grid::builder()
        .margin_top(6)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .row_spacing(6)
        .column_spacing(6)
        .build();

    // Item name
    let item_viewer_titlei = gtk4::Label::new(Some("Click to open files..."));
    item_viewer_titlei.set_size_request(320, 48);
    item_viewer_titlei.set_hexpand(true);
    let item_viewer_titler = LabelWithInternalText::new(item_viewer_titlei, "".to_string());
    item_grid.attach(&*item_viewer_titler, 1, 1, 1, 1);
    let item_viewer_title = Rc::new(RefCell::new(item_viewer_titler));

    // Save item button
    let item_save_button = gtk4::Button::with_label("Save");
    item_save_button.set_size_request(80, 48);
    item_save_button.set_hexpand(false);
    item_grid.attach(&item_save_button, 2, 1, 1, 1);

    let item_grid_separator = gtk4::Separator::new(gtk4::Orientation::Horizontal);
    item_grid.attach(&item_grid_separator, 1, 2, 2, 1);

    // Item viewer
    let iviewer_windowr = gtk4::ScrolledWindow::builder()
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .hexpand(true)
        .vexpand(true)
        .build();
    iviewer_windowr.set_size_request(400, 400);
    let iviewer_gridr = gtk4::Grid::new();
    let item_viewerr = gtk4::TextView::new();
    item_viewerr.add_css_class("normal");
    item_viewerr.set_editable(false);
    iviewer_gridr.attach(&item_viewerr, 1, 1, 1, 1);
    iviewer_windowr.set_child(Some(&iviewer_gridr));
    item_grid.attach(&iviewer_windowr, 1, 3, 2, 1);
    //let iviewer_grid = Rc::new(iviewer_gridr);
    let item_viewer = Rc::new(item_viewerr);

    // Control grid, left side of the vault window
    let control_grid = gtk4::Grid::builder()
        .margin_top(6)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .row_spacing(8)
        .column_spacing(8)
        .vexpand(true)
        .build();

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
    let vault_add_file = gtk4::Button::with_label("New file");
    vault_add_file.set_size_request(80, 48);

    // Rc suffix: _raf
    let vwindow_raf = Rc::clone(&vault_window);
    let iviewer_title_raf = Rc::clone(&item_viewer_title);
    let vfilelist_raf = Rc::clone(&vault_file_list);
    let iviewer_raf = Rc::clone(&item_viewer);
    let app_raf = Rc::clone(&application);
    let vindex_raf = Rc::clone(&vindex);
    let vexpath_raf = Rc::clone(&vexplorer_path);
    let vdata_raf = Rc::clone(&vdata);
    vault_add_file.connect_clicked(move |_| {
        // Create type selector
        let vaf_window = Rc::new(gtk4::Window::new());
        vaf_window.set_title(Some("New item..."));
        vaf_window.set_application(Some(app_raf.as_ref()));
        vaf_window.set_size_request(160, 56);
        vaf_window.set_resizable(false);

        let vaf_hbox = gtk4::Box::builder()
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .halign(gtk4::Align::Center)
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .build();

        // File from scratch
        let vaf_create_button = gtk4::Button::with_label("Create file");
        vaf_create_button.set_size_request(96, 40);

        // Rc suffix: _rafc
        let app_rafc = Rc::clone(&app_raf);
        let vwindow_rafc = Rc::clone(&vwindow_raf);
        let vaf_window_rafc = Rc::clone(&vaf_window);
        let iviewer_title_rafc = Rc::clone(&iviewer_title_raf);
        let vfilelist_rafc = Rc::clone(&vfilelist_raf);
        let iviewer_rafc = Rc::clone(&iviewer_raf);
        let vindex_rafc = Rc::clone(&vindex_raf);
        let vexpath_rafc = Rc::clone(&vexpath_raf);
        let vdata_rafc = Rc::clone(&vdata_raf);
        vaf_create_button.connect_clicked(move |_| {
            vaf_window_rafc.close();
            let vcf_window = Rc::new(gtk4::Window::new());
            vcf_window.set_title(Some("Create new file"));
            vcf_window.set_application(Some(app_rafc.as_ref()));
            vcf_window.set_size_request(180, 72);
            vcf_window.set_modal(true);

            let vcf_grid = gtk4::Grid::builder()
                .margin_top(6)
                .margin_bottom(12)
                .margin_start(12)
                .margin_end(12)
                .row_spacing(6)
                .column_spacing(6)
                .build();

            let vcf_title = gtk4::Label::new(Some("Enter file name:"));
            vcf_title.add_css_class("big");
            vcf_grid.attach(&vcf_title, 1, 1, 2, 1);

            let vcf_filename = gtk4::Entry::new();
            vcf_filename.set_size_request(160, 28);
            vcf_grid.attach(&vcf_filename, 1, 2, 1, 1);

            let vcf_ok_button = gtk4::Button::with_label("OK");
            vcf_ok_button.set_size_request(64, 28);

            // Rc suffix: _rafc2
            let vcf_window_rafc2 = Rc::clone(&vcf_window);
            let vwindow_rafc2 = Rc::clone(&vwindow_rafc);
            let iviewer_title_rafc2 = Rc::clone(&iviewer_title_rafc);
            let iviewer_rafc2 = Rc::clone(&iviewer_rafc);
            let vfilelist_rafc2 = Rc::clone(&vfilelist_rafc);
            let vexpath_rafc2 = Rc::clone(&vexpath_rafc);
            let vindex_rafc2 = Rc::clone(&vindex_rafc);
            let vdata_rafc2 = Rc::clone(&vdata_rafc);
            vcf_ok_button.connect_clicked(move |_| {
                let currpath = Rc::new(vexpath_rafc2.borrow().text().to_string());

                // File name filtering
                let filename = vcf_filename.text().to_string();
                if let Err(emsg) = itemname_check(&filename, "File") {
                    show_alert(vcf_window_rafc2.as_ref(), "Error", &emsg);
                    return;
                }

                vault_append_file(
                    Rc::clone(&vexpath_rafc2),
                    vcf_filename.text().to_string(),
                    None,
                    Rc::clone(&vindex_rafc2),
                    Rc::clone(&vdata_rafc2),
                );

                // Reload file
                loop {
                    let dwidget = match vfilelist_rafc2.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    vfilelist_rafc2.remove(&dwidget);
                }
                for button in get_current_from_vault_path(
                    Rc::clone(&vfilelist_rafc2),
                    Rc::clone(&vindex_rafc2),
                    Rc::clone(&vdata_rafc2),
                    PathBuf::from(vexpath_rafc2.borrow().get_itext()),
                    Rc::clone(&iviewer_title_rafc2),
                    Rc::clone(&iviewer_rafc2),
                    Rc::clone(&vexpath_rafc2),
                ) {
                    vfilelist_rafc2.append(&*button);
                }

                // Add '*' at title
                if let Some(title) = vwindow_rafc2.title() {
                    if !title.ends_with("*") {
                        vwindow_rafc2.set_title(Some(&(title.to_string() + "*")));
                    }
                }

                vcf_window_rafc2.close();
            });
            vcf_grid.attach(&vcf_ok_button, 2, 2, 1, 1);

            vcf_window.set_child(Some(&vcf_grid));
            vcf_window.present();
        });
        vaf_hbox.append(&vaf_create_button);

        // Import file
        let vaf_import_button = gtk4::Button::with_label("Import file");
        vaf_import_button.set_size_request(96, 40);

        // Rc suffix: _rafi
        let vaf_window_rafi = Rc::clone(&vaf_window);
        let vexpath_rafi = Rc::clone(&vexpath_raf);
        let iviewer_title_rafi = Rc::clone(&iviewer_title_raf);
        let iviewer_rafi = Rc::clone(&iviewer_raf);
        let vfilelist_rafi = Rc::clone(&vfilelist_raf);
        let vindex_rafi = Rc::clone(&vindex_raf);
        let vdata_rafi = Rc::clone(&vdata_raf);
        vaf_import_button.connect_clicked(move |_| {
            let file_dialog = gtk4::FileDialog::builder()
                .modal(true)
                .title("Select file to import...")
                .build();

            // Rc suffix: _rafi2
            let vaf_window_rafi2 = Rc::clone(&vaf_window_rafi);
            let vfilelist_rafi2 = Rc::clone(&vfilelist_rafi);
            let iviewer_title_rafi2 = Rc::clone(&iviewer_title_rafi);
            let iviewer_rafi2 = Rc::clone(&iviewer_rafi);
            let vexpath_rafi2 = Rc::clone(&vexpath_rafi);
            let vindex_rafi2 = Rc::clone(&vindex_rafi);
            let vdata_rafi2 = Rc::clone(&vdata_rafi);
            file_dialog.open(
                Some(vaf_window_rafi.as_ref()),
                gtk4::gio::Cancellable::NONE,
                move |raw_gfile| {
                    if raw_gfile.is_err() {
                        return;
                    }
                    let file_path = &raw_gfile.unwrap().uri()[7..];
                    let rfile = fs::File::open(&file_path);
                    if rfile.is_err() {
                        show_alert(
                            vaf_window_rafi2.as_ref(),
                            "Error",
                            "Failed to open the selected file.",
                        );
                        return;
                    }
                    let mut read_buf: Vec<u8> = Vec::new();
                    let read_result = rfile.unwrap().read_to_end(&mut read_buf);
                    if read_result.is_err() {
                        show_alert(
                            vaf_window_rafi2.as_ref(),
                            "Error",
                            "Failed to read from the selected file.",
                        );
                        return;
                    }
                    let filepath = PathBuf::from(file_path);
                    let rfilename = filepath.file_name();
                    if rfilename.is_none() {
                        return;
                    }
                    let vaultpath = Rc::new(vexpath_rafi2.borrow().text().to_string());

                    // File name filtering
                    let ufilename = rfilename.unwrap().to_str();
                    if ufilename.is_none() {
                        show_alert(
                            vaf_window_rafi2.as_ref(),
                            "Error",
                            "The name of the selected file is invalid for this app.",
                        );
                        return;
                    };
                    let filename = ufilename.unwrap().to_string();
                    if let Err(emsg) = itemname_check(&filename, "File") {
                        show_alert(vaf_window_rafi2.as_ref(), "Error", &emsg);
                        return;
                    }

                    // Append file info
                    vault_append_file(
                        Rc::clone(&vexpath_rafi2),
                        filename,
                        Some(read_buf),
                        Rc::clone(&vindex_rafi2),
                        Rc::clone(&vdata_rafi2),
                    );

                    // Reload file
                    loop {
                        let dwidget = match vfilelist_rafi2.last_child() {
                            Some(w) => w,
                            None => break,
                        };
                        vfilelist_rafi2.remove(&dwidget);
                    }
                    for button in get_current_from_vault_path(
                        Rc::clone(&vfilelist_rafi2),
                        Rc::clone(&vindex_rafi2),
                        Rc::clone(&vdata_rafi2),
                        PathBuf::from(vexpath_rafi2.borrow().get_itext()),
                        Rc::clone(&iviewer_title_rafi2),
                        Rc::clone(&iviewer_rafi2),
                        Rc::clone(&vexpath_rafi2),
                    ) {
                        vfilelist_rafi2.append(&*button);
                    }

                    vaf_window_rafi2.close();
                },
            );
        });
        vaf_hbox.append(&vaf_import_button);

        vaf_window.set_child(Some(&vaf_hbox));
        vaf_window.present();
    });
    control_grid.attach(&vault_add_file, 1, 1, 1, 1);

    // Add folder
    let vault_add_folder = gtk4::Button::with_label("New folder");
    vault_add_folder.set_size_request(80, 48);

    // Rc suffix: _rad
    let iviewer_title_rad = Rc::clone(&item_viewer_title);
    let vfilelist_rad = Rc::clone(&vault_file_list);
    let vwindow_rad = Rc::clone(&vault_window);
    let iviewer_rad = Rc::clone(&item_viewer);
    let app_rad = Rc::clone(&application);
    let vindex_rad = Rc::clone(&vindex);
    let vexpath_rad = Rc::clone(&vexplorer_path);
    let vdata_rad = Rc::clone(&vdata);
    vault_add_folder.connect_clicked(move |_| {
        let vad_window = Rc::new(gtk4::Window::new());
        vad_window.set_title(Some("Add folder..."));
        vad_window.set_application(Some(app_rad.as_ref()));
        vad_window.set_modal(true);
        let vad_grid = gtk4::Grid::builder()
            .margin_top(6)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .row_spacing(12)
            .column_spacing(8)
            .build();

        let vad_title = gtk4::Label::new(Some("Enter folder name:"));
        vad_title.add_css_class("big");
        vad_grid.attach(&vad_title, 1, 1, 2, 1);

        let vad_dirname = gtk4::Entry::new();
        vad_dirname.set_size_request(160, 28);
        vad_grid.attach(&vad_dirname, 1, 2, 1, 1);

        let vad_ok_button = gtk4::Button::with_label("OK");
        vad_ok_button.set_size_request(64, 28);

        // Rc suffix: _rad2
        let vad_window_rad2 = Rc::clone(&vad_window);
        let iviewer_title_rad2 = Rc::clone(&iviewer_title_rad);
        let vwindow_rad2 = Rc::clone(&vwindow_rad);
        let vfilelist_rad2 = Rc::clone(&vfilelist_rad);
        let iviewer_rad2 = Rc::clone(&iviewer_rad);
        let vindex_rad2 = Rc::clone(&vindex_rad);
        let vexpath_rad2 = Rc::clone(&vexpath_rad);
        let vdata_rad2 = Rc::clone(&vdata_rad);
        vad_ok_button.connect_clicked(move |_| {
            // Folder name filtering
            let dirname = vad_dirname.text().to_string();
            if let Err(emsg) = itemname_check(&dirname, "Folder") {
                show_alert(vad_window_rad2.as_ref(), "Error", &emsg);
                return;
            }

            // Append folder info
            vault_append_folder(
                Rc::clone(&vexpath_rad2),
                format!("{}/", dirname),
                Rc::clone(&vindex_rad2),
            );

            // Reload file
            loop {
                let dwidget = match vfilelist_rad2.last_child() {
                    Some(w) => w,
                    None => break,
                };
                vfilelist_rad2.remove(&dwidget);
            }
            for button in get_current_from_vault_path(
                Rc::clone(&vfilelist_rad2),
                Rc::clone(&vindex_rad2),
                Rc::clone(&vdata_rad2),
                PathBuf::from(vexpath_rad2.borrow().get_itext()),
                Rc::clone(&iviewer_title_rad2),
                Rc::clone(&iviewer_rad2),
                Rc::clone(&vexpath_rad2),
            ) {
                vfilelist_rad2.append(&*button);
            }

            // Add '*' at title
            if let Some(title) = vwindow_rad2.title() {
                if !title.ends_with("*") {
                    vwindow_rad2.set_title(Some(&(title.to_string() + "*")));
                }
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
    let vdata_rri = Rc::clone(&vdata);
    let vindex_rri = Rc::clone(&vindex);
    let app_rri = Rc::clone(&application);
    let vexpath_rri = Rc::clone(&vexplorer_path);
    let iviewer_title_rri = Rc::clone(&item_viewer_title);
    let iviewer_rri = Rc::clone(&item_viewer);
    let vfilelist_rri = Rc::clone(&vault_file_list);
    vault_rename_item.connect_clicked(move |_| {
        let viewer_id = iviewer_title_rri.borrow().get_itext().to_owned();
        let (vfileid, vtitle) = viewer_id.split_once(":").unwrap();
        let vri_window = Rc::new(gtk4::Window::new());
        vri_window.set_title(Some("Rename item..."));
        vri_window.set_application(Some(app_rri.as_ref()));
        vri_window.set_modal(true);
        let vri_grid = gtk4::Grid::builder()
            .margin_top(6)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .row_spacing(12)
            .column_spacing(8)
            .build();

        let vri_title = gtk4::Label::new(Some(&format!("Rename '{vtitle}' to:")));
        vri_title.add_css_class("title");
        vri_grid.attach(&vri_title, 1, 1, 2, 1);

        let vri_nameboxr = gtk4::Entry::new();
        vri_nameboxr.set_size_request(144, 28);
        vri_grid.attach(&vri_nameboxr, 1, 2, 1, 1);
        let vri_namebox = Rc::new(vri_nameboxr);

        let vri_ok_button = gtk4::Button::with_label("OK");
        vri_ok_button.set_size_request(40, 28);

        // Rc suffix: _rri2
        let vdata_rri2 = Rc::clone(&vdata_rri);
        let vindex_rri2 = Rc::clone(&vindex_rri);
        let vexpath_rri2 = Rc::clone(&vexpath_rri);
        let vri_window_rri2 = Rc::clone(&vri_window);
        let vri_namebox_rri2 = Rc::clone(&vri_namebox);
        let vfileid_rri2 = Rc::new(PathBuf::from(vfileid));
        let iviewer_rri2 = Rc::clone(&iviewer_rri);
        let iviewer_title_rri2 = Rc::clone(&iviewer_title_rri);
        let vfilelist_rri2 = Rc::clone(&vfilelist_rri);
        vri_ok_button.connect_clicked(move |_| {
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

            vindex_b.insert(rmres.unwrap().0, vri_namebox_rri2.text().to_string());
            drop(vindex_b);

            loop {
                let dwidget = match vfilelist_rri2.last_child() {
                    Some(w) => w,
                    None => break,
                };
                vfilelist_rri2.remove(&dwidget);
            }
            for button in get_current_from_vault_path(
                Rc::clone(&vfilelist_rri2),
                Rc::clone(&vindex_rri2),
                Rc::clone(&vdata_rri2),
                PathBuf::from(vexpath_rri2.borrow().get_itext()),
                Rc::clone(&iviewer_title_rri2),
                Rc::clone(&iviewer_rri2),
                Rc::clone(&vexpath_rri2),
            ) {
                vfilelist_rri2.append(&*button);
            }
            vri_window_rri2.close();
        });
        vri_grid.attach(&vri_ok_button, 2, 2, 1, 1);

        vri_window.set_child(Some(&vri_grid));
        vri_window.present();
    });
    control_grid.attach(&vault_rename_item, 1, 2, 1, 1);

    // Move, Export, Delete item or Reload
    let vault_other_ctrl = gtk4::Button::with_label("More...");
    vault_other_ctrl.set_size_request(80, 48);

    // Rc suffix: _ro
    let app_ro = Rc::clone(&application);
    let iviewer_title_ro = Rc::clone(&item_viewer_title);
    let vfilelist_ro = Rc::clone(&vault_file_list);
    let iviewer_ro = Rc::clone(&item_viewer);
    let vexpath_ro = Rc::clone(&vexplorer_path);
    let vindex_ro = Rc::clone(&vindex);
    let vdata_ro = Rc::clone(&vdata);
    vault_other_ctrl.connect_clicked(move |_| {
        // Create type selector
        let voc_window = Rc::new(gtk4::Window::new());
        voc_window.set_title(Some("More commands"));
        voc_window.set_application(Some(app_ro.as_ref()));
        voc_window.set_size_request(192, 80);
        voc_window.set_resizable(false);

        let voc_grid = gtk4::Grid::builder()
            .margin_top(6)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .row_spacing(6)
            .column_spacing(6)
            .halign(gtk4::Align::Center)
            .valign(gtk4::Align::Center)
            .build();

        // Move item
        let voc_move_item = gtk4::Button::with_label("Move item");
        voc_move_item.set_size_request(96, 40);

        let voc_window_mrc = Rc::clone(&voc_window);
        voc_move_item.connect_clicked(move |_| {
            show_alert(
                voc_window_mrc.as_ref(),
                "Sorry",
                "Move item is not supported right now.",
            );
        });
        voc_grid.attach(&voc_move_item, 1, 1, 1, 1);

        // Reload
        let voc_reload_button = gtk4::Button::with_label("Reload");
        voc_reload_button.set_size_request(96, 40);

        // Rc suffix: _ror
        let iviewer_title_ror = Rc::clone(&iviewer_title_ro);
        let vfilelist_ror = Rc::clone(&vfilelist_ro);
        let vexpath_ror = Rc::clone(&vexpath_ro);
        let voc_window_ror = Rc::clone(&voc_window);
        let iviewer_ror = Rc::clone(&iviewer_ro);
        let vindex_ror = Rc::clone(&vindex_ro);
        let vdata_ror = Rc::clone(&vdata_ro);
        voc_reload_button.connect_clicked(move |_| {
            loop {
                let dwidget = match vfilelist_ror.last_child() {
                    Some(w) => w,
                    None => break,
                };
                vfilelist_ror.remove(&dwidget);
            }
            for button in get_current_from_vault_path(
                Rc::clone(&vfilelist_ror),
                Rc::clone(&vindex_ror),
                Rc::clone(&vdata_ror),
                PathBuf::from(vexpath_ror.borrow().get_itext()),
                Rc::clone(&iviewer_title_ror),
                Rc::clone(&iviewer_ror),
                Rc::clone(&vexpath_ror),
            ) {
                vfilelist_ror.append(&*button);
            }
            voc_window_ror.close();
        });
        voc_grid.attach(&voc_reload_button, 2, 1, 1, 1);

        // Export
        let voc_export_item = gtk4::Button::with_label("Export item");
        voc_export_item.set_size_request(96, 40);

        // Rc suffix: _roe
        let iviewer_title_roe = Rc::clone(&iviewer_title_ro);
        let voc_window_roe = Rc::clone(&voc_window);
        let vdata_roe = Rc::clone(&vdata_ro);
        voc_export_item.connect_clicked(move |_| {
            let filename = iviewer_title_roe.borrow().get_itext().to_owned();
            let (fileid_str, title) = match filename.split_once(":") {
                Some(f) => f,
                None => {
                    show_alert(voc_window_roe.as_ref(), "Error",
                        "No file is selected.\nSelect a file you want to export, then try again.");
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
            let voc_window_roes = Rc::clone(&voc_window_roe);
            let vdata_roes = Rc::clone(&vdata_roe);
            let fileid = PathBuf::from(fileid_str);
            file_dialog.save(
                Some(voc_window_roe.as_ref()),
                gtk4::gio::Cancellable::NONE,
                move |raw_gfile| {
                    if raw_gfile.is_err() {
                        show_alert(
                            voc_window_roes.as_ref(),
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
                                voc_window_roes.as_ref(),
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
                                voc_window_roes.as_ref(),
                                "Error",
                                "Failed to get the data of the selected file.",
                            );
                            return;
                        }
                    };
                    let wres = file.write_all(vdata);
                    if wres.is_err() {
                        show_alert(
                            voc_window_roes.as_ref(),
                            "Error",
                            "Failed to export the selected file.",
                        );
                    }
                    let fres = file.flush();
                    if fres.is_err() {
                        show_alert(
                            voc_window_roes.as_ref(),
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
        let iviewer_title_rod = Rc::clone(&iviewer_title_ro);
        let vfilelist_rod = Rc::clone(&vfilelist_ro);
        let iviewer_rod = Rc::clone(&iviewer_ro);
        let vexpath_rod = Rc::clone(&vexpath_ro);
        let voc_window_rod = Rc::clone(&voc_window);
        let vindex_rod = Rc::clone(&vindex_ro);
        let vdata_rod = Rc::clone(&vdata_ro);
        let app_rod = Rc::clone(&app_ro);
        voc_delete_item.connect_clicked(move |_| {
            // Create type selector
            let vdi_windowr = Rc::new(gtk4::Window::new());
            vdi_windowr.set_title(Some("Select delete type"));
            vdi_windowr.set_application(Some(app_rod.as_ref()));
            vdi_windowr.set_size_request(160, 56);
            vdi_windowr.set_resizable(false);
            let vdi_window = Rc::new(vdi_windowr);
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
            let voc_window_rodf = Rc::clone(&voc_window_rod);
            let vdi_window_rodf = Rc::clone(&vdi_window);
            let vindex_rodf = Rc::clone(&vindex_rod);
            let vdata_rodf = Rc::clone(&vdata_rod);
            let app_rodf = Rc::clone(&app_rod);
            vdi_delete_file.connect_clicked(move |_| {
                let fileid = Rc::new(PathBuf::from(iviewer_title_rodf.borrow().get_itext()));

                let delwindow = Rc::new(gtk4::Window::new());
                delwindow.set_title(Some("Confirm deletion?"));
                delwindow.set_application(Some(app_rodf.as_ref()));
                delwindow.set_size_request(240, 96);
                delwindow.set_modal(true);

                let del_grid = gtk4::Grid::builder()
                    .margin_top(12)
                    .margin_bottom(12)
                    .margin_start(12)
                    .margin_end(12)
                    .row_spacing(6)
                    .column_spacing(12)
                    .build();

                let fileidx = vindex_rodf.borrow();
                let ofilename = fileidx.get(fileid.as_ref());
                if ofilename.is_none() {
                    show_alert(
                        voc_window_rodf.as_ref(),
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

                // Rc suffix: _rodfn
                let delwindow_rodfn = Rc::clone(&delwindow);
                let vdi_window_rodfn = Rc::clone(&vdi_window_rodf);
                del_no_button.connect_clicked(move |_| {
                    delwindow_rodfn.close();
                    vdi_window_rodfn.close();
                });
                del_grid.attach(&del_no_button, 1, 2, 1, 1);

                let del_yes_button = gtk4::Button::with_label("Yes");
                del_yes_button.set_size_request(40, 28);

                // Rc suffix: _rodfy
                let delwindow_rodfy = Rc::clone(&delwindow);
                let vdi_window_rodfy = Rc::clone(&vdi_window_rodf);
                let voc_window_rodfy = Rc::clone(&voc_window_rodf);
                let iviewer_title_rodfy = Rc::clone(&iviewer_title_rodf);
                let vexpath_rodfy = Rc::clone(&vexpath_rodf);
                let iviewer_rodfy = Rc::clone(&iviewer_rodf);
                let vfilelist_rodfy = Rc::clone(&vfilelist_rodf);
                let vindex_rodfy = Rc::clone(&vindex_rodf);
                let vdata_rodfy = Rc::clone(&vdata_rodf);
                del_yes_button.connect_clicked(move |_| {
                    let ires = vindex_rodfy.borrow_mut().remove(Rc::clone(&fileid).as_ref());
                    let dres = vdata_rodfy.borrow_mut().remove(Rc::clone(&fileid).as_ref());
                    match (ires, dres) {
                        (None, None) => {
                            show_alert(
                                delwindow_rodfy.as_ref(),
                                "Error",
                                "The selected file was not found.",
                            );
                        }
                        (None, Some(_)) => {
                            show_alert(
                                delwindow_rodfy.as_ref(),
                                "Error",
                                "The file was not found on index, but deletion was successful.",
                            );
                        }
                        (Some(_), None) => {
                            show_alert(
                                delwindow_rodfy.as_ref(),
                                "Error",
                                "The file was found on index, but failed to delete its data.",
                            );
                        }
                        _ => {}
                    };

                    // Reload
                    loop {
                        let dwidget = match vfilelist_rodfy.last_child() {
                            Some(w) => w,
                            None => break,
                        };
                        vfilelist_rodfy.remove(&dwidget);
                    }
                    for button in get_current_from_vault_path(
                        Rc::clone(&vfilelist_rodfy),
                        Rc::clone(&vindex_rodfy),
                        Rc::clone(&vdata_rodfy),
                        PathBuf::from(vexpath_rodfy.borrow().get_itext()),
                        Rc::clone(&iviewer_title_rodfy),
                        Rc::clone(&iviewer_rodfy),
                        Rc::clone(&vexpath_rodfy),
                    ) {
                        vfilelist_rodfy.append(&*button);
                    }
                    delwindow_rodfy.close();
                    vdi_window_rodfy.close();
                    voc_window_rodfy.close();
                });
                del_grid.attach(&del_yes_button, 3, 2, 1, 1);

                delwindow.set_child(Some(&del_grid));
                delwindow.present();
            });
            vdi_hbox.append(&vdi_delete_file);

            let vdi_delete_dir = gtk4::Button::with_label("Delete folder");
            vdi_delete_dir.set_size_request(96, 40);

            // Rc suffix: _rodd
            let iviewer_title_rodd = Rc::clone(&iviewer_title_rod);
            let vfilelist_rodd = Rc::clone(&vfilelist_rod);
            let iviewer_rodd = Rc::clone(&iviewer_rod);
            let vexpath_rodd = Rc::clone(&vexpath_rod);
            let voc_window_rodd = Rc::clone(&voc_window_rod);
            let vdi_window_rodd = Rc::clone(&vdi_window);
            let vindex_rodd = Rc::clone(&vindex_rod);
            let vdata_rodd = Rc::clone(&vdata_rod);
            let app_rodd = Rc::clone(&app_rod);
            vdi_delete_dir.connect_clicked(move |_| {
                // Delete current folder and everything inside, include subdir
                let delwindow = Rc::new(gtk4::Window::new());
                delwindow.set_title(Some("Confirm deletion?"));
                delwindow.set_application(Some(app_rodd.as_ref()));
                delwindow.set_size_request(240, 96);
                delwindow.set_modal(true);

                let del_grid = gtk4::Grid::builder()
                    .margin_top(12)
                    .margin_bottom(12)
                    .margin_start(12)
                    .margin_end(12)
                    .row_spacing(6)
                    .column_spacing(12)
                    .build();

                let currpath_str = Rc::new(vexpath_rodd.borrow().get_itext().to_owned());
                if currpath_str.as_ref() == "/" {
                    show_alert(voc_window_rodd.as_ref(), "Alert",
                        "You cannot delete the root directory.\nTry deleting files and folders one by one instead.");
                    return;
                }
                let currpath_dirname = match vindex_rodd.borrow()
                    .get(&PathBuf::from(currpath_str.as_ref()))
                {
                    Some(n) => n.to_owned(),
                    None => {
                        show_alert(voc_window_rodd.as_ref(), "Error",
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
                let delwindow_roddn = Rc::clone(&delwindow);
                let vdi_window_roddn = Rc::clone(&vdi_window_rodd);
                let voc_window_roddn = Rc::clone(&voc_window_rodd);
                del_no_button.connect_clicked(move |_| {
                    delwindow_roddn.close();
                    vdi_window_roddn.close();
                    voc_window_roddn.close();
                });
                del_grid.attach(&del_no_button, 1, 2, 1, 1);

                let del_yes_button = gtk4::Button::with_label("Yes");
                del_yes_button.set_size_request(40, 28);

                // Rc suffix: _roddy
                let delwindow_roddy = Rc::clone(&delwindow);
                let vdi_window_roddy = Rc::clone(&vdi_window_rodd);
                let voc_window_roddy = Rc::clone(&voc_window_rodd);
                let iviewer_title_roddy = Rc::clone(&iviewer_title_rodd);
                let vexpath_roddy = Rc::clone(&vexpath_rodd);
                let iviewer_roddy = Rc::clone(&iviewer_rodd);
                let vfilelist_roddy = Rc::clone(&vfilelist_rodd);
                let vindex_roddy = Rc::clone(&vindex_rodd);
                let vdata_roddy = Rc::clone(&vdata_rodd);
                let currpath_roddy = Rc::clone(&currpath_str);
                del_yes_button.connect_clicked(move |_| {
                    let keys_to_remove: Vec<PathBuf> = vindex_roddy.borrow().keys()
                        .filter(|path| {path.starts_with(currpath_roddy.as_ref())}).cloned().collect();
                    for key in keys_to_remove {
                        vindex_roddy.borrow_mut().remove(&key);
                        vdata_roddy.borrow_mut().remove(&key);
                    }

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
                    for button in get_current_from_vault_path(
                        Rc::clone(&vfilelist_roddy),
                        Rc::clone(&vindex_roddy),
                        Rc::clone(&vdata_roddy),
                        PathBuf::from(vexpath_roddy.borrow().get_itext()),
                        Rc::clone(&iviewer_title_roddy),
                        Rc::clone(&iviewer_roddy),
                        Rc::clone(&vexpath_roddy),
                    ) {
                        vfilelist_roddy.append(&*button);
                    }

                    delwindow_roddy.close();
                    vdi_window_roddy.close();
                    voc_window_roddy.close();
                });
                del_grid.attach(&del_yes_button, 3, 2, 1, 1);

                delwindow.set_child(Some(&del_grid));
                delwindow.present();
            });

            vdi_hbox.append(&vdi_delete_dir);

            vdi_window.set_child(Some(&vdi_hbox));
            vdi_window.present();
        });
        voc_grid.attach(&voc_delete_item, 2, 2, 1, 1);

        voc_window.set_child(Some(&voc_grid));
        voc_window.present();
    });
    control_grid.attach(&vault_other_ctrl, 2, 2, 1, 1);

    // Add items on '/'
    for button in get_current_from_vault_path(
        Rc::clone(&vault_file_list),
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
    let decoded_master_rc = Rc::clone(&decoded_master_data);
    let commlabel_rc = Rc::clone(&commlabel);
    let vault_password_rc = Rc::clone(&vault_password);
    let vault_window_rc = Rc::clone(&vault_window);
    vault_window.connect_close_request(move |window| {
        if window.has_css_class("confirm_closure") {
            glib::Propagation::Proceed
        } else {
            let final_string =
                get_vault_full_string(Rc::clone(&vname), Rc::clone(&vindex), Rc::clone(&vdata));
            eprintln!("Final vault data:\n{final_string}");
            let hash_final = hashify_sha256(&final_string);
            if hash_initial != hash_final {
                // Change detected!
                let save_window = Rc::new(gtk4::Window::new());
                save_window.set_application(Some(wcl_app.as_ref()));
                save_window.set_title(Some("Save changes?"));
                save_window.set_default_size(180, 48);
                save_window.set_modal(true);
                let save_grid = gtk4::Grid::builder()
                    .margin_top(6)
                    .margin_bottom(12)
                    .margin_start(12)
                    .margin_end(12)
                    .row_spacing(6)
                    .column_spacing(6)
                    .build();

                let save_title =
                    gtk4::Label::new(Some(&format!("Do you want to save changes in '{vname}'?")));
                save_grid.attach(&save_title, 1, 1, 3, 1);

                let save_yes_button = gtk4::Button::with_label("Save");
                save_yes_button.set_size_request(60, 32);

                let vnamerc = Rc::clone(&vname);
                let save_window_src = Rc::clone(&save_window);
                let vault_window_src = Rc::clone(&vault_window_rc);
                let decoded_master_src = Rc::clone(&decoded_master_rc);
                let vault_password_src = Rc::clone(&vault_password_rc);
                let commlabel_src = Rc::clone(&commlabel_rc);
                save_yes_button.connect_clicked(move |_| {
                    let (noncev, datav) = match encrypt_aes_with_key(
                        save_window_src.as_ref(),
                        &final_string,
                        vault_password_src.as_ref(),
                    ) {
                        Some(v) => v,
                        None => return,
                    };
                    let mut final_master = String::new();
                    for line in decoded_master_src.split("\n") {
                        if line.starts_with(vnamerc.as_ref()) {
                            final_master.push_str(&format!(
                                "{}:{}{}\n",
                                vnamerc.as_ref(),
                                u8_to_hex(&noncev),
                                u8_to_hex(&datav)
                            ));
                        } else if line != "" {
                            final_master.push_str(line);
                            final_master.push('\n');
                        }
                    }

                    commlabel_src.set_text(&final_master);
                    commlabel_src.add_css_class(&format!(
                        "vwr_{}_{}", // Vault Write Request
                        u8_to_hex(&hashify_sha256(&vnamerc)[0..6]),
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
                let vault_window_nrc = Rc::clone(&vault_window_rc);
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
                glib::Propagation::Stop
            } else {
                vault_window_rc.add_css_class("confirm_closure");
                vault_window_rc.close();
                glib::Propagation::Proceed
            }
        }
    });

    vault_hbox.append(&control_grid);
    vault_hbox.append(&item_grid);
    vault_window.set_child(Some(&vault_hbox));
    vault_window.present();
}

fn get_current_from_vault_path(
    file_list: Rc<gtk4::ListBox>,
    index: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    data: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
    path: PathBuf,
    name_viewer: Rc<RefCell<LabelWithInternalText>>,
    content_viewer: Rc<gtk4::TextView>,
    explorer_path: Rc<RefCell<EntryWithInternalText>>,
) -> Vec<ButtonWithInternalText> {
    let mut items: Vec<ButtonWithInternalText> = Vec::new();
    if path.as_os_str() != "/" {
        let abuttoni = gtk4::Button::with_label("../");
        let abutton = ButtonWithInternalText::new(abuttoni, String::new());

        let filelist_rc = Rc::clone(&file_list);
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
            for button in get_current_from_vault_path(
                Rc::clone(&filelist_rc),
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
        if !ipath.starts_with(&path) {
            continue;
        }
        // Exclude subdirectory here
        if ipath.parent().unwrap_or(&PathBuf::from("/")) != path {
            continue;
        }

        let lbuttoni = gtk4::Button::with_label(&name);
        let lbutton = ButtonWithInternalText::new(lbuttoni, ipath.to_str().unwrap().to_string());

        let name_viewer_rc = Rc::clone(&name_viewer);
        let content_viewer_rc = Rc::clone(&content_viewer);
        if name.ends_with("/") {
            // Go down
            let rpath = path.clone();
            let lbtnipath = Rc::new(lbutton.get_itext().to_owned());
            let expath_rc = Rc::clone(&explorer_path);
            let flist_rc = Rc::clone(&file_list);
            let index_rc = Rc::clone(&index);
            let data_rc = Rc::clone(&data);
            lbutton.connect_clicked(move |button| {
                let dirname = button.label().unwrap();
                let mut newpath = PathBuf::from(expath_rc.borrow().entry.text());
                newpath.push(&dirname);
                expath_rc.borrow_mut().entry.set_text(
                    newpath
                        .to_str()
                        .unwrap_or(&(rpath.to_str().unwrap().to_owned() + "<invalid>/")),
                );
                // Set internal path
                let newipath = Rc::clone(&lbtnipath);
                expath_rc.borrow_mut().set_itext_ref(newipath.as_ref());
                loop {
                    let dwidget = match flist_rc.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    flist_rc.remove(&dwidget);
                }

                for button in get_current_from_vault_path(
                    Rc::clone(&flist_rc),
                    Rc::clone(&index_rc),
                    Rc::clone(&data_rc),
                    PathBuf::from(newipath.as_ref()),
                    Rc::clone(&name_viewer_rc),
                    Rc::clone(&content_viewer_rc),
                    Rc::clone(&expath_rc),
                ) {
                    flist_rc.append(&*button);
                }
            });
        } else {
            // Show file
            let vindex = Rc::clone(&index);
            let vdata = Rc::clone(&data);
            lbutton.connect_clicked(move |_| {
                let fileid_str = ipath.to_str().unwrap();
                let fileid = PathBuf::from(&fileid_str);
                let vf_index = vindex.borrow();
                let vf_data = vdata.borrow();
                let data = match vf_data.get(&fileid) {
                    Some(d) => d,
                    None => return,
                };
                let title = match vf_index.get(&fileid) {
                    Some(s) => s,
                    None => return,
                };
                let data_utf8 = str::from_utf8(data);
                if data_utf8.is_ok() {
                    name_viewer_rc.borrow_mut().label.set_text(title);
                    content_viewer_rc.buffer().set_text(data_utf8.unwrap());
                } else {
                    name_viewer_rc
                        .borrow_mut()
                        .label
                        .set_text(&(title.to_owned() + " : Binary"));
                    content_viewer_rc.buffer().set_text(&u8_to_hex(data));
                }
                name_viewer_rc
                    .borrow_mut()
                    .set_itext(format!("{fileid_str}:{title}"));
                content_viewer_rc.set_editable(true);
            });
        }

        items.push(lbutton);
    }
    items
}

fn vault_append_file(
    vault_path: Rc<RefCell<EntryWithInternalText>>,
    filename: String,
    file_data: Option<Vec<u8>>,
    vindex: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    vdata: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
) {
    // Get file id here
    // Maybe I can just save next index
    let mut fileid: u16 = 0;
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
    if file_data.is_none() {
        vdata
            .borrow_mut()
            .insert(PathBuf::from(file_pathcode), Vec::new());
    } else {
        vdata
            .borrow_mut()
            .insert(PathBuf::from(file_pathcode), file_data.unwrap());
    }
}

fn vault_append_folder(
    vault_path: Rc<RefCell<EntryWithInternalText>>,
    dirname: String,
    vindex: Rc<RefCell<BTreeMap<PathBuf, String>>>,
) {
    // Get folder id here
    // Maybe I can just save next index
    let mut dirid: u16 = 0;
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
        .insert(PathBuf::from(&dir_pathcode), dirname.to_string());
}

fn get_vault_full_string(
    vname: Rc<String>,
    index: Rc<RefCell<BTreeMap<PathBuf, String>>>,
    data: Rc<RefCell<BTreeMap<PathBuf, Vec<u8>>>>,
) -> String {
    let mut index_final = String::new();
    let mut data_final = String::new();
    for (path, name) in &*index.borrow() {
        index_final.push_str(&format!("{}:{name}\n", path.to_str().unwrap()));
    }
    for (path, data) in &*data.borrow() {
        data_final.push_str(&format!("{}:{}\n", path.to_str().unwrap(), u8_to_hex(data)));
    }
    format!("^{vname}\n[Index]\n{index_final}[Data]\n{data_final}")
}
