/*
 * FileBase, a simple filesystem-like vault system with strong encryption.
 *   Copyright (C) 2026  @7654jp on GitHub
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use glib::clone;
use gtk4::gdk;
use gtk4::prelude::*;
use std::cell::RefCell;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::rc::Rc;

mod tools;
use tools::*;

fn open_vault(
    application: Rc<gtk4::Application>,
    decoded_data: String,
    commlabel: Rc<gtk4::Label>,
) {
    // Take hash for checking changes
    let hash_initial = hashify_sha256(&decoded_data);

    // Convert to three
    let vault_data = match vault_decode(decoded_data) {
        Some(data) => data,
        None => return,
    };
    let vname = Rc::new(vault_data.0);
    let vindex = Rc::new(RefCell::new(vault_data.1));
    let vdata = Rc::new(RefCell::new(vault_data.2));

    // Window
    let vault_window = Rc::new(gtk4::Window::new());
    vault_window.set_application(Some(application.as_ref()));
    vault_window.set_default_size(320, 480);
    vault_window.set_title(Some(&format!("FileBase Explorer  -  {vname}")));

    let vault_grid = gtk4::Grid::builder()
        .margin_top(6)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .row_spacing(6)
        .column_spacing(6)
        .build();

    // Path viewer
    let vault_path = gtk4::Entry::builder().text("/").build();
    vault_path.set_size_request(200, 40);
    vault_path.set_editable(false);
    vault_grid.attach(&vault_path, 1, 3, 2, 1);
    let vpathrc = Rc::new(vault_path);

    // Item list
    let vault_scroll = gtk4::ScrolledWindow::new();
    vault_scroll.set_size_request(240, 280);
    vault_scroll.set_hscrollbar_policy(gtk4::PolicyType::Never);
    let vault_file_list = Rc::new(gtk4::ListBox::new());

    // Add items on '/'
    for button in get_current_from_vault_path(
        Rc::clone(&vault_file_list),
        Rc::clone(&vindex),
        Rc::clone(&vdata),
        PathBuf::from("/"),
    ) {
        vault_file_list.append(&button);
    }
    vault_scroll.set_child(Some(&*vault_file_list));
    vault_grid.attach(&vault_scroll, 1, 4, 2, 1);

    // Item viewer
    let vault_viewer = gtk4::ScrolledWindow::new();
    vault_viewer.set_size_request(400, 400);
    vault_viewer.set_hscrollbar_policy(gtk4::PolicyType::Automatic);
    vault_viewer.set_vscrollbar_policy(gtk4::PolicyType::Automatic);
    let vvetv = gtk4::TextView::new();
    vault_viewer.set_child(Some(&vvetv));
    vault_grid.attach(&vault_viewer, 3, 1, 1, 4);

    let vault_add_file = gtk4::Button::new();
    vault_add_file.set_size_request(120, 48);
    let vaf_label = gtk4::Label::new(Some("New file"));
    vault_add_file.set_child(Some(&vaf_label));
    let af_app = Rc::clone(&application);
    let vnf_index = Rc::clone(&vindex);
    let vnf_data = Rc::clone(&vdata);
    vault_add_file.connect_clicked(move |_| {
        // Create type selector
        let vaf_window = Rc::new(gtk4::Window::new());
        vaf_window.set_title(Some("New item..."));
        vaf_window.set_application(Some(af_app.as_ref()));
        vaf_window.set_size_request(240, 56);
        vaf_window.set_modal(true);

        let vaf_hbox = gtk4::Box::builder()
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .orientation(gtk4::Orientation::Horizontal)
            .spacing(6)
            .build();

        // File from scratch
        let vaf_create_button = gtk4::Button::new();
        vaf_create_button.set_size_request(100, 40);
        let vaf_create_label = gtk4::Label::new(Some("Create file"));
        vaf_create_button.set_child(Some(&vaf_create_label));

        let nf_app = Rc::clone(&af_app);
        let va_window = Rc::clone(&vaf_window);
        let vpathcrc = Rc::clone(&vpathrc);
        let vfile_list = Rc::clone(&vault_file_list);
        let vaf_index = Rc::clone(&vnf_index);
        let vaf_data = Rc::clone(&vnf_data);
        vaf_create_button.connect_clicked(move |_| {
            va_window.close();
            let vcf_window = Rc::new(gtk4::Window::new());
            vcf_window.set_title(Some("Enter file name"));
            vcf_window.set_application(Some(nf_app.as_ref()));
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

            let vcf_title = gtk4::Label::new(Some("New file..."));
            vcf_title.add_css_class("big");
            vcf_grid.attach(&vcf_title, 1, 1, 2, 1);

            let vcf_filename = gtk4::Entry::new();
            vcf_filename.set_size_request(160, 48);
            vcf_grid.attach(&vcf_filename, 1, 2, 1, 1);

            let vcf_ok_button = gtk4::Button::new();
            vcf_ok_button.set_size_request(64, 48);
            let vcf_ok_label = gtk4::Label::new(Some("OK"));
            vcf_ok_button.set_child(Some(&vcf_ok_label));

            let vcwindow = Rc::clone(&vcf_window);
            let vcf_file_list = Rc::clone(&vfile_list);
            let vpathorc = Rc::clone(&vpathcrc);
            let vcf_index = Rc::clone(&vaf_index);
            let vcf_data = Rc::clone(&vaf_data);
            vcf_ok_button.connect_clicked(move |_| {
                let filepath = Rc::new(vpathorc.text().to_string());

                // Filename filtering
                let filename = vcf_filename.text().to_string();
                if filename.contains("^") || filename.contains(":") {
                    show_alert(
                        vcwindow.as_ref(),
                        "Alert",
                        "File name cannot contain '^' or ':'.",
                    );
                    return;
                }
                if filename.starts_with(" ") {
                    show_alert(
                        vcwindow.as_ref(),
                        "Alert",
                        "File name cannot start with ' '.",
                    );
                    return;
                }
                if filename.ends_with(" ") || filename.ends_with(".") {
                    show_alert(
                        vcwindow.as_ref(),
                        "Alert",
                        "File name cannot end with ' ' or '.'.",
                    );
                    return;
                }
                if filename.chars().count() == 0 {
                    show_alert(vcwindow.as_ref(), "Alert", "File name cannot be empty.");
                    return;
                }

                vault_data_append(
                    Rc::clone(&filepath),
                    vcf_filename.text().to_string(),
                    None,
                    Rc::clone(&vcf_index),
                    Rc::clone(&vcf_data),
                );
                // Reload file
                loop {
                    let dwidget = match vcf_file_list.last_child() {
                        Some(w) => w,
                        None => break,
                    };
                    vcf_file_list.remove(&dwidget);
                }
                for button in get_current_from_vault_path(
                    Rc::clone(&vcf_file_list),
                    Rc::clone(&vcf_index),
                    Rc::clone(&vcf_data),
                    PathBuf::from(filepath.to_string()),
                ) {
                    vcf_file_list.append(&button);
                }

                // Close window
                vcwindow.close();
            });
            vcf_grid.attach(&vcf_ok_button, 2, 2, 1, 1);

            vcf_window.set_child(Some(&vcf_grid));
            vcf_window.present();
        });
        vaf_hbox.append(&vaf_create_button);

        // Import file
        let vaf_import_button = gtk4::Button::new();
        vaf_import_button.set_size_request(100, 40);
        let vaf_import_label = gtk4::Label::new(Some("Import file"));
        vaf_import_button.set_child(Some(&vaf_import_label));

        let vif_window = Rc::clone(&vaf_window);
        let vpatharc = Rc::clone(&vpathrc);
        let vfile_list = Rc::clone(&vault_file_list);
        let vif_index = Rc::clone(&vnf_index);
        let vif_data = Rc::clone(&vnf_data);
        vaf_import_button.connect_clicked(move |_| {
            let file_dialog = gtk4::FileDialog::builder()
                .modal(true)
                .title("Select file to import...")
                .build();

            let vid_window = Rc::clone(&vif_window);
            let vic_window = Rc::clone(&vif_window);
            let vcf_file_list = Rc::clone(&vfile_list);
            let vpathorc = Rc::clone(&vpatharc);
            let vcf_index = Rc::clone(&vif_index);
            let vcf_data = Rc::clone(&vif_data);
            file_dialog.open(
                Some(vid_window.as_ref()),
                gtk4::gio::Cancellable::NONE,
                move |raw_gfile| {
                    if raw_gfile.is_err() {
                        return;
                    }
                    let file_path = &raw_gfile.unwrap().uri()[7..];
                    let rfile = fs::File::open(&file_path);
                    if rfile.is_err() {
                        show_alert(
                            vic_window.as_ref(),
                            "Error",
                            "Failed to open selected file.\n",
                        );
                        return;
                    }
                    let mut read_buf: Vec<u8> = Vec::new();
                    let read_result = rfile.unwrap().read_to_end(&mut read_buf);
                    if read_result.is_err() {
                        show_alert(
                            vic_window.as_ref(),
                            "Error",
                            "Failed to read from selected file.",
                        );
                        return;
                    }
                    let filepath = PathBuf::from(file_path);
                    let rfilename = filepath.file_name();
                    if rfilename.is_none() {
                        return;
                    }
                    let vaultpath = Rc::new(vpathorc.text().to_string());

                    // Filename filtering
                    let filename = rfilename.unwrap().to_str().unwrap().to_string();
                    if filename.contains("^") || filename.contains(":") {
                        show_alert(
                            vic_window.as_ref(),
                            "Alert",
                            "File name cannot contain '^' or ':'.",
                        );
                        return;
                    }
                    if filename.starts_with(" ") {
                        show_alert(
                            vic_window.as_ref(),
                            "Alert",
                            "File name cannot start with ' '.",
                        );
                        return;
                    }
                    if filename.ends_with(" ") || filename.ends_with(".") {
                        show_alert(
                            vic_window.as_ref(),
                            "Alert",
                            "File name cannot end with ' ' or '.'.",
                        );
                        return;
                    }
                    if filename.chars().count() == 0 {
                        show_alert(vic_window.as_ref(), "Alert", "File name cannot be empty.");
                        return;
                    }
                    vault_data_append(
                        Rc::clone(&vaultpath),
                        filename,
                        Some(read_buf),
                        Rc::clone(&vcf_index),
                        Rc::clone(&vcf_data),
                    );
                    // Reload file
                    loop {
                        let dwidget = match vcf_file_list.last_child() {
                            Some(w) => w,
                            None => break,
                        };
                        vcf_file_list.remove(&dwidget);
                    }
                    for button in get_current_from_vault_path(
                        Rc::clone(&vcf_file_list),
                        Rc::clone(&vcf_index),
                        Rc::clone(&vcf_data),
                        PathBuf::from(Rc::clone(&vaultpath).to_string()),
                    ) {
                        vcf_file_list.append(&button);
                    }

                    vic_window.close();
                },
            );
        });
        vaf_hbox.append(&vaf_import_button);

        vaf_window.set_child(Some(&vaf_hbox));
        vaf_window.present();
    });
    vault_grid.attach(&vault_add_file, 1, 1, 1, 1);

    let vault_add_folder = gtk4::Button::new();
    vault_add_folder.set_size_request(120, 48);
    let vad_label = gtk4::Label::new(Some("New folder"));
    vault_add_folder.set_child(Some(&vad_label));
    vault_grid.attach(&vault_add_folder, 2, 1, 1, 1);

    let vault_rename_item = gtk4::Button::new();
    vault_rename_item.set_size_request(80, 48);
    let vri_label = gtk4::Label::new(Some("Rename"));
    vault_rename_item.set_child(Some(&vri_label));
    vault_grid.attach(&vault_rename_item, 1, 2, 1, 1);

    let vault_other_ctrl = gtk4::Button::new();
    vault_other_ctrl.set_size_request(80, 48);
    let voc_label = gtk4::Label::new(Some("More.."));
    vault_other_ctrl.set_child(Some(&voc_label));

    let oc_app = Rc::clone(&application);
    vault_other_ctrl.connect_clicked(move |_| {
        // Create type selector
        let voc_window = Rc::new(gtk4::Window::new());
        voc_window.set_title(Some("More controls"));
        voc_window.set_application(Some(oc_app.as_ref()));
        voc_window.set_size_request(240, 96);
        voc_window.set_modal(true);

        let voc_grid = gtk4::Grid::builder()
            .margin_top(6)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .row_spacing(6)
            .column_spacing(6)
            .build();

        let voc_move_item = gtk4::Button::new();
        voc_move_item.set_size_request(96, 40);
        let voc_move_label = gtk4::Label::new(Some("Move item"));
        voc_move_item.set_child(Some(&voc_move_label));
        voc_grid.attach(&voc_move_item, 1, 1, 1, 1);

        let voc_reload_button = gtk4::Button::new();
        voc_reload_button.set_size_request(96, 40);
        let voc_reload_label = gtk4::Label::new(Some("Reload"));
        voc_reload_button.set_child(Some(&voc_reload_label));
        voc_grid.attach(&voc_reload_button, 2, 1, 1, 1);

        let voc_export_item = gtk4::Button::new();
        voc_export_item.set_size_request(96, 40);
        let voc_export_label = gtk4::Label::new(Some("Export item"));
        voc_export_item.set_child(Some(&voc_export_label));
        voc_grid.attach(&voc_export_item, 1, 2, 1, 1);

        let voc_delete_item = gtk4::Button::new();
        voc_delete_item.set_size_request(96, 40);
        let voc_delete_label = gtk4::Label::new(Some("Delete item"));
        voc_delete_item.set_child(Some(&voc_delete_label));
        voc_grid.attach(&voc_delete_item, 2, 2, 1, 1);

        voc_window.set_child(Some(&voc_grid));
        voc_window.present();
    });
    vault_grid.attach(&vault_other_ctrl, 2, 2, 1, 1);

    let wcl_app = Rc::clone(&application);
    let commlabel_rc = Rc::clone(&commlabel);
    let vault_window_rc = Rc::clone(&vault_window);
    vault_window.connect_close_request(move |window| {
        if window.has_css_class("confirm_closure") {
            glib::Propagation::Proceed
        } else {
            let mut index_final = String::new();
            let mut data_final = String::new();
            for (path, name) in &*vindex.borrow() {
                index_final.push_str(&format!("{}:{name}\n", path.to_str().unwrap()));
            }
            for (path, data) in &*vdata.borrow() {
                data_final.push_str(&format!("{path}:{}\n", u8_to_hex(data)));
            }
            let final_string = format!("^{vname}\n[Index]\n{index_final}[Data]\n{data_final}\n");
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

                let save_yes_button = gtk4::Button::new();
                save_yes_button.set_size_request(60, 32);
                let save_yes_label = gtk4::Label::new(Some("Save"));
                save_yes_button.set_child(Some(&save_yes_label));

                let vnamerc = Rc::clone(&vname);
                let save_window_src = Rc::clone(&save_window);
                let vault_window_src = Rc::clone(&vault_window_rc);
                let commlabel_src = Rc::clone(&commlabel_rc);
                save_yes_button.connect_clicked(move |_| {
                    commlabel_src.set_text(&final_string);
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

                let save_no_button = gtk4::Button::new();
                save_no_button.set_size_request(60, 32);
                let save_no_label = gtk4::Label::new(Some("Don't save"));
                save_no_button.set_child(Some(&save_no_label));

                let save_window_nrc = Rc::clone(&save_window);
                let vault_window_nrc = Rc::clone(&vault_window_rc);
                save_no_button.connect_clicked(move |_| {
                    save_window_nrc.close();
                    vault_window_nrc.add_css_class("confirm_closure");
                    vault_window_nrc.close();
                });
                save_grid.attach(&save_no_button, 2, 2, 1, 1);

                let save_cancel_button = gtk4::Button::new();
                save_cancel_button.set_size_request(60, 32);
                let save_cancel_label = gtk4::Label::new(Some("Cancel"));
                save_cancel_button.set_child(Some(&save_cancel_label));

                let save_window_crc = Rc::clone(&save_window);
                save_cancel_button.connect_clicked(move |_| {
                    save_window_crc.add_css_class("confirm_closure");
                    save_window_crc.close();
                });
                save_grid.attach(&save_cancel_button, 3, 2, 1, 1);

                save_window.set_child(Some(&save_grid));
                save_window.present();
            }
            glib::Propagation::Stop
        }
    });

    vault_window.set_child(Some(&vault_grid));
    vault_window.present();
}

fn open_main(application: &gtk4::Application) {
    // Main window
    let window = Rc::new(gtk4::ApplicationWindow::new(application));
    window.set_title(Some("FileBase"));
    window.set_default_size(400, 180);
    window.set_resizable(false);

    // Main grid
    let grid = gtk4::Grid::builder()
        .margin_top(6)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .row_spacing(24)
        .column_spacing(12)
        .build();

    // title label
    let title_label = gtk4::Label::new(None);
    title_label.set_markup("<b>FileBase Vault Manager</b>");
    title_label.add_css_class("big");
    grid.attach(&title_label, 1, 1, 3, 1);

    // Enable CSS
    let display = gdk::Display::default().expect("Error: Could not get default display.");
    let provider = gtk4::CssProvider::new();
    provider.load_from_data(include_str!("fstyle.css"));
    gtk4::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // Add vault button
    let add_button = gtk4::Button::new();
    add_button.set_size_request(120, 96);
    // Inside Add button
    let abbox = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    let abimg = gtk4::Image::new();
    abimg.set_size_request(48, 48);
    abimg.set_from_pixbuf(Some(&get_pixbuf_with_embedded_image(include_bytes!(
        "images/add.png"
    ))));
    abbox.append(&abimg);
    let ablabel = gtk4::Label::new(Some("Add new vault"));
    abbox.append(&ablabel);
    add_button.set_child(Some(&abbox));
    // Inline function
    let awindow = Rc::clone(&window);
    add_button.connect_clicked(clone!(
        #[weak]
        application,
        move |_| {
            // Create window and box
            let nv_window = gtk4::Window::new();
            nv_window.set_application(Some(&application));
            nv_window.set_title(Some("Add new vault..."));
            let nv_grid = gtk4::Grid::builder()
                .margin_top(8)
                .margin_bottom(8)
                .margin_start(8)
                .margin_end(8)
                .row_spacing(8)
                .column_spacing(8)
                .build();

            // Name label
            let nv_name_label = gtk4::Label::new(Some("Vault Name:"));
            nv_grid.attach(&nv_name_label, 1, 1, 2, 1);
            // Name input box
            let nv_name_box = gtk4::Entry::new();
            nv_name_box.set_size_request(120, 24);
            nv_grid.attach(&nv_name_box, 3, 1, 2, 1);
            // Password label
            let nv_pass_label = gtk4::Label::new(Some("Vault Password:"));
            nv_grid.attach(&nv_pass_label, 1, 2, 2, 1);
            // Password input box
            let nv_pass_box = gtk4::PasswordEntry::new();
            nv_pass_box.set_size_request(120, 24);
            nv_grid.attach(&nv_pass_box, 3, 2, 2, 1);

            let nv_ok_button = gtk4::Button::with_label("OK");
            let aawindow = Rc::clone(&awindow);
            nv_ok_button.connect_clicked(clone!(
                #[weak]
                application,
                #[weak]
                nv_window,
                #[weak]
                nv_pass_box,
                move |_| {
                    // Filter vault name
                    let vname = nv_name_box.text().to_string();
                    if vname.contains("^") || vname.contains(":") {
                        show_alert(&nv_window, "Error", "Vault name cannot contain '^' or ':'.");
                        return;
                    }
                    // Get master data
                    let omaster_data = read_master(&nv_window);
                    nv_window.close();
                    if omaster_data.is_none() {
                        return;
                    }
                    let comm_label = Rc::new(gtk4::Label::new(None));
                    // Save after user edited data inside vault
                    comm_label.connect_css_classes_notify(|label| {
                        eprint!(
                            "[Debug] main.rs:625\nValue returned in main:\n{}",
                            label.text().to_string()
                        );
                    });
                    let (vtype, nonce_buf, base_cipher) = omaster_data.unwrap();
                    // Decrypt master
                    if &vtype == b"d" {
                        // Default encryption
                        let obase_data =
                            decrypt_aes(aawindow.as_ref(), &base_cipher, nonce_buf, true);
                        if obase_data.is_none() {
                            return;
                        }
                        let sbase_data = String::from_utf8(obase_data.unwrap());
                        if sbase_data.is_err() {
                            show_alert(
                                aawindow.as_ref(),
                                "Error",
                                "Could not parse vault data as string.",
                            );
                            return;
                        }
                        let base_data = sbase_data.unwrap();
                        // Vault name validation
                        for line in base_data.split("\n") {
                            if line.starts_with("^") || line.len() == 0 {
                                continue;
                            }
                            let vline = line.split_once(":");
                            if vline.is_none() {
                                show_alert(
                                    aawindow.as_ref(),
                                    "Error",
                                    "Failed to parse vault data. The vault may be broken.",
                                );
                                return;
                            }
                            if vline.unwrap().0 == vname {
                                show_alert(
                                    aawindow.as_ref(),
                                    "Alert",
                                    "You cannot use a same vault name.",
                                );
                                return;
                            }
                        }
                        let oadded_str = add_vault(
                            base_data,
                            vname.clone(),
                            nv_pass_box.text().to_string(),
                            aawindow.as_ref(),
                        );
                        if oadded_str.is_none() {
                            return;
                        }
                        let (added_master, vault_data) = oadded_str.unwrap();
                        // Save
                        let oadded_master = encrypt_aes(aawindow.as_ref(), &added_master);
                        if oadded_master.is_none() {
                            return;
                        }
                        let added_master = oadded_master.unwrap();
                        write_master(aawindow.as_ref(), b"d", added_master.0, added_master.1);
                        open_vault(Rc::new(application), vault_data, comm_label);
                    } else if &vtype == b"u" {
                        // Password encryption
                        // Ask password window
                        let pw_window = gtk4::Window::new();
                        pw_window.set_application(Some(&application));
                        pw_window.set_title(Some("Master password"));

                        // Ask password grid
                        let pw_grid = gtk4::Grid::builder()
                            .margin_top(6)
                            .margin_bottom(6)
                            .margin_start(12)
                            .margin_end(12)
                            .row_spacing(8)
                            .column_spacing(8)
                            .build();
                        // Ask label
                        let pw_label =
                            gtk4::Label::new(Some("Enter password to open master vault."));
                        pw_grid.attach(&pw_label, 1, 1, 3, 1);
                        // Input box
                        let pw_box = gtk4::PasswordEntry::new();
                        pw_grid.attach(&pw_box, 1, 2, 2, 1);

                        let pw_ok_button = gtk4::Button::with_label("OK");
                        let aapprc = Rc::new(application);
                        let commlabel_rc = Rc::clone(&comm_label);
                        let aaawindow = Rc::clone(&aawindow);
                        pw_ok_button.connect_clicked(clone!(
                            #[weak]
                            pw_window,
                            move |_| {
                                let obase_data = decrypt_aes_with_key(
                                    &pw_window,
                                    &base_cipher,
                                    nonce_buf,
                                    &hashify_sha256(&pw_box.text().to_string()),
                                    false,
                                );
                                if obase_data.is_none() {
                                    show_alert(
                                        &pw_window,
                                        "Error",
                                        "Failed to decrypt master vault.",
                                    );
                                    return;
                                }
                                pw_window.close();
                                let sbase_data = String::from_utf8(obase_data.unwrap());
                                if sbase_data.is_err() {
                                    show_alert(
                                        aaawindow.as_ref(),
                                        "Error",
                                        "Could not parse vault data as string.",
                                    );
                                    return;
                                }
                                let base_data = sbase_data.unwrap();
                                // Vault name validation
                                for line in base_data.split("\n") {
                                    if line.starts_with("^") || line.len() == 0 {
                                        continue;
                                    }
                                    let vline = line.split_once(":");
                                    if vline.is_none() {
                                        show_alert(
                                            aaawindow.as_ref(),
                                            "Error",
                                            "Failed to parse vault data. The vault may be broken.",
                                        );
                                        return;
                                    }
                                    if vline.unwrap().0 == vname {
                                        show_alert(
                                            aaawindow.as_ref(),
                                            "Alert",
                                            "You cannot use a same vault name.",
                                        );
                                        return;
                                    }
                                }
                                let (added_master, vault_data) = match add_vault(
                                    base_data,
                                    vname.clone(),
                                    nv_pass_box.text().to_string(),
                                    aaawindow.as_ref(),
                                ) {
                                    Some(added) => added,
                                    None => return,
                                };
                                // Save
                                let added_master = match encrypt_aes_with_key(
                                    aaawindow.as_ref(),
                                    &added_master,
                                    &hashify_sha256(&pw_box.text().to_string()),
                                ) {
                                    Some(v) => v,
                                    None => return,
                                };
                                write_master(
                                    aaawindow.as_ref(),
                                    b"u",
                                    added_master.0,
                                    added_master.1,
                                );
                                open_vault(
                                    Rc::clone(&aapprc),
                                    vault_data,
                                    Rc::clone(&commlabel_rc),
                                );
                            }
                        ));
                        pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                        pw_window.set_child(Some(&pw_grid));
                        pw_window.set_modal(true);
                        pw_window.present();
                    } else {
                        show_alert(aawindow.as_ref(), "Error", "Could not parse vault data.");
                        return;
                    }
                }
            ));
            nv_grid.attach(&nv_ok_button, 4, 3, 1, 1);

            nv_window.set_child(Some(&nv_grid));
            nv_window.set_modal(true);
            nv_window.present();
        }
    ));
    grid.attach(&add_button, 1, 2, 1, 1);

    // Open vault button
    let open_button = gtk4::Button::new();
    open_button.set_size_request(120, 96);
    // Inside Open button
    let obbox = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    let obimg = gtk4::Image::new();
    obimg.set_size_request(48, 48);
    obimg.set_from_pixbuf(Some(&get_pixbuf_with_embedded_image(include_bytes!(
        "images/open.png"
    ))));
    obbox.append(&obimg);
    let oblabel = gtk4::Label::new(Some("Open vault"));
    obbox.append(&oblabel);
    open_button.set_child(Some(&obbox));
    // Inline function
    let owindow = Rc::clone(&window);
    open_button.connect_clicked(clone!(
        #[weak]
        application,
        move |_| {
            let selwindow = gtk4::Window::new();
            selwindow.set_application(Some(&application));
            selwindow.set_title(Some("Select vault..."));
            selwindow.set_size_request(320, 240);
            selwindow.set_modal(true);

            let selvbox = gtk4::Box::builder()
                .orientation(gtk4::Orientation::Vertical)
                .spacing(8)
                .margin_start(12)
                .margin_end(12)
                .build();

            let seltitle = gtk4::Label::new(Some("Select vault to open:"));
            seltitle.add_css_class("big");
            selvbox.append(&seltitle);

            // Show vault list widget family
            let selscroll = gtk4::ScrolledWindow::new();
            selscroll.set_size_request(180, 200);
            selscroll.set_hscrollbar_policy(gtk4::PolicyType::Never);
            let sellist = gtk4::ListBox::new();
            selscroll.set_child(Some(&sellist));
            selvbox.append(&selscroll);

            selwindow.set_child(Some(&selvbox));

            let omaster_data = read_master(&selwindow);
            if omaster_data.is_none() {
                return;
            }
            let (vtype, nonce_buf, base_cipher) = omaster_data.unwrap();
            let oapprc = Rc::new(application);
            // Decrypt master
            if &vtype == b"d" {
                // Default encryption
                let obase_data = decrypt_aes(&selwindow, &base_cipher, nonce_buf, false);
                if obase_data.is_none() {
                    show_alert(&selwindow, "Error", "Failed to decrypt master vault.");
                    return;
                }
                let base_string = match String::from_utf8(obase_data.unwrap()) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let hidden_comm_label2r = gtk4::Label::new(None);
                // Save after user edited data inside vault
                hidden_comm_label2r.connect_css_classes_notify(|label| {
                    eprint!("[Debug] main.rs:889\nValue returned in main:\n{}", label.text().to_string());
                });
                let hidden_comm_label2 = Rc::new(hidden_comm_label2r);

                for line in base_string.split("\n") {
                    if line.starts_with("^") {
                        continue;
                    }
                    if let Some((mvname, mvhex)) = line.split_once(":") {
                        let vlist_button = gtk4::Button::new();
                        let vlist_label = gtk4::Label::new(Some(mvname));
                        vlist_button.set_child(Some(&vlist_label));
                        let mvdata = mvhex.to_string();
                        let oapplrc = Rc::clone(&oapprc);
                        vlist_button.connect_clicked(clone!(
                            #[strong]
                            mvdata,
                            #[strong]
                            hidden_comm_label2,
                            #[weak]
                            selwindow,
                            move |_| {
                                // Ask vault password
                                let vopen_window = gtk4::Window::builder()
                                    .title("Unlock vault")
                                    .modal(true)
                                    .build();
                                let oappwinrc = Rc::clone(&oapplrc);
                                vopen_window.set_application(Some(oappwinrc.as_ref()));

                                let vopen_grid = gtk4::Grid::builder()
                                    .margin_top(6)
                                    .margin_bottom(6)
                                    .margin_start(12)
                                    .margin_end(12)
                                    .row_spacing(12)
                                    .column_spacing(12)
                                    .build();

                                // Password label
                                let vopen_pass_label =
                                    gtk4::Label::new(Some("Vault Password:"));
                                vopen_grid.attach(&vopen_pass_label, 1, 1, 1, 1);
                                // Password input box
                                let vopen_pass_box = gtk4::PasswordEntry::new();
                                vopen_pass_box.set_size_request(120, 24);
                                vopen_grid.attach(&vopen_pass_box, 1, 2, 1, 1);
                                // Confirm button
                                let vopen_ok_button = gtk4::Button::new();
                                let vopen_ok_label = gtk4::Label::new(Some("OK"));
                                vopen_ok_button.set_child(Some(&vopen_ok_label));
                                let oapplorc = Rc::clone(&oapplrc);
                                vopen_ok_button.connect_clicked(clone!(
                                    #[weak]
                                    vopen_window,
                                    #[weak]
                                    hidden_comm_label2,
                                    #[strong]
                                    mvdata,
                                    move |_| {
                                        // Decode
                                        let mvdata_l = mvdata.clone();
                                        let bindata = hex_to_u8(&mvdata_l).unwrap();
                                        let vault_raw = match decrypt_aes_with_key(
                                            &vopen_window,
                                            &bindata[12..],
                                            bindata[0..12].try_into().unwrap(),
                                            &hashify_sha256(
                                                &vopen_pass_box.text().to_string(),
                                            ),
                                            false,
                                        ) {
                                            Some(bin) => bin,
                                            None => {
                                                show_alert(&vopen_window, "Alert", "Vault decryption failed.\nThe password is incorrect, or the vault is broken.");
                                                return;
                                            },
                                        };
                                        let rvault_text = String::from_utf8(vault_raw);
                                        if rvault_text.is_err() {
                                            show_alert(&vopen_window, "Error",
                                                "Could not convert decrypted vault data.\nThe data may be broken.");
                                            return;
                                        };
                                        vopen_window.close();
                                        selwindow.close();
                                        open_vault(
                                            Rc::clone(&oapplorc),
                                            rvault_text.unwrap(),
                                            hidden_comm_label2,
                                        );
                                    }
                                ));
                                vopen_grid.attach(&vopen_ok_button, 2, 2, 1, 1);

                                vopen_window.set_child(Some(&vopen_grid));
                                vopen_window.present();
                            }
                        ));
                        sellist.append(&vlist_button);
                    }
                }
                selwindow.present();
            } else if &vtype == b"u" {
                // Password encryption
                // Ask password window
                let pw_window = gtk4::Window::new();
                pw_window.set_application(Some(oapprc.as_ref()));
                pw_window.set_title(Some("Master password"));

                // Ask password grid
                let pw_grid = gtk4::Grid::builder()
                    .margin_top(6)
                    .margin_bottom(6)
                    .margin_start(12)
                    .margin_end(12)
                    .row_spacing(8)
                    .column_spacing(8)
                    .build();

                // Ask label
                let pw_label = gtk4::Label::new(Some("Enter password to open master vault."));
                pw_grid.attach(&pw_label, 1, 1, 3, 1);
                // Input box
                let pw_boxr = gtk4::PasswordEntry::new();
                pw_grid.attach(&pw_boxr, 1, 2, 2, 1);
                let pw_box = Rc::new(pw_boxr);

                let pw_ok_button = gtk4::Button::with_label("OK");

                let oowindow = Rc::clone(&owindow);
                pw_ok_button.connect_clicked(clone!(
                    #[weak]
                    pw_window,
                    #[weak]
                    selwindow,
                    move |_| {
                        let obase_data = decrypt_aes_with_key(
                            &pw_window,
                            &base_cipher,
                            nonce_buf,
                            &hashify_sha256(&pw_box.text().to_string()),
                            false,
                        );
                        if obase_data.is_none() {
                            show_alert(&pw_window, "Error", "Failed to decrypt master vault.");
                            return;
                        }
                        pw_window.close();
                        let base_string = match String::from_utf8(obase_data.unwrap()) {
                            Ok(s) => s,
                            Err(_) => return,
                        };
                        let comm_labelr = gtk4::Label::new(None);
                        // Save after user edited data inside vault
                        let ooowindow = Rc::clone(&oowindow);
                        let opw_box = Rc::clone(&pw_box);
                        comm_labelr.connect_css_classes_notify(move |label| {
                            let edited_vault = label.text().to_string();
                            let opt_encrypt = encrypt_aes_with_key(ooowindow.as_ref(), &edited_vault, &hashify_sha256(&opw_box.text().to_string()));
                            if opt_encrypt.is_none() {
                                show_alert(ooowindow.as_ref(), "Error", "Failed to encrypt changed vault.");
                                return;
                            };
                            let (nonce, data) = opt_encrypt.unwrap();
                            write_master(ooowindow.as_ref(), b"u", nonce, data);
                        });
                        let comm_label = Rc::new(comm_labelr);

                        for line in base_string.split("\n") {
                            if line.starts_with("^") {
                                continue;
                            }
                            if let Some((mvname, mvhex)) = line.split_once(":") {
                                let vlist_button = gtk4::Button::new();
                                let vlist_label = gtk4::Label::new(Some(mvname));
                                vlist_button.set_child(Some(&vlist_label));
                                let mvdata = Rc::new(mvhex.to_string());
                                let oapplrc = Rc::clone(&oapprc);
                                let commlabel_l = Rc::clone(&comm_label);
                                vlist_button.connect_clicked(clone!(
                                    #[weak]
                                    selwindow,
                                    move |_| {
                                        // Ask vault password
                                        let vopen_window = gtk4::Window::builder()
                                            .title("Unlock vault")
                                            .modal(true)
                                            .build();
                                        let oappwinrc = Rc::clone(&oapplrc);
                                        vopen_window.set_application(Some(oappwinrc.as_ref()));

                                        let vopen_grid = gtk4::Grid::builder()
                                            .margin_top(6)
                                            .margin_bottom(6)
                                            .margin_start(12)
                                            .margin_end(12)
                                            .row_spacing(24)
                                            .column_spacing(12)
                                            .build();

                                        // Password label
                                        let vopen_pass_label =
                                            gtk4::Label::new(Some("Vault Password:"));
                                        vopen_grid.attach(&vopen_pass_label, 1, 1, 1, 1);
                                        // Password input box
                                        let vopen_pass_box = gtk4::PasswordEntry::new();
                                        vopen_pass_box.set_size_request(120, 24);
                                        vopen_grid.attach(&vopen_pass_box, 1, 2, 1, 1);
                                        // Confirm button
                                        let vopen_ok_button = gtk4::Button::new();
                                        let vopen_ok_label = gtk4::Label::new(Some("OK"));
                                        vopen_ok_button.set_child(Some(&vopen_ok_label));
                                        let oapplorc = Rc::clone(&oapplrc);
                                        let mvdatarc = Rc::clone(&mvdata);
                                        let commlabelrc = Rc::clone(&commlabel_l);
                                        vopen_ok_button.connect_clicked(clone!(
                                            #[weak]
                                            vopen_window,
                                            move |_| {
                                                // Decode
                                                let bindata = hex_to_u8(&mvdatarc).unwrap();
                                                let vault_raw = match decrypt_aes_with_key(
                                                    &vopen_window,
                                                    &bindata[12..],
                                                    bindata[0..12].try_into().unwrap(),
                                                    &hashify_sha256(
                                                        &vopen_pass_box.text().to_string(),
                                                    ),
                                                    false,
                                                ) {
                                                    Some(bin) => bin,
                                                    None => {
                                                        show_alert(&vopen_window, "Alert", "Vault decryption failed.\nThe password is incorrect, or the vault is broken.");
                                                        return;
                                                    },
                                                };
                                                let rvault_text = String::from_utf8(vault_raw);
                                                if rvault_text.is_err() {
                                                    show_alert(&vopen_window, "Error",
                                                        "Could not convert decrypted vault data.\nThe data may be broken.");
                                                    return;
                                                };
                                                vopen_window.close();
                                                selwindow.close();
                                                open_vault(
                                                    Rc::clone(&oapplorc),
                                                    rvault_text.unwrap(),
                                                    Rc::clone(&commlabelrc),
                                                );
                                            }
                                        ));
                                        vopen_grid.attach(&vopen_ok_button, 2, 2, 1, 1);

                                        vopen_window.set_child(Some(&vopen_grid));
                                        vopen_window.present();
                                    }
                                ));
                                sellist.append(&vlist_button);
                            }
                        }
                    }
                ));
                pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                pw_window.set_child(Some(&pw_grid));
                pw_window.set_modal(true);
                selwindow.present();
                pw_window.present();
            } else {
                show_alert(&selwindow, "Error", "Could not parse vault data.");
                return;
            }
        }
    ));
    grid.attach(&open_button, 2, 2, 1, 1);

    // Delete vault button
    let delete_button = gtk4::Button::new();
    delete_button.set_size_request(120, 96);
    // Inside Delete button
    let dbbox = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
    let dbimg = gtk4::Image::new();
    dbimg.set_size_request(48, 48);
    dbimg.set_from_pixbuf(Some(&get_pixbuf_with_embedded_image(include_bytes!(
        "images/delete.png"
    ))));
    dbbox.append(&dbimg);
    let dblabel = gtk4::Label::new(Some("Delete vault"));
    dbbox.append(&dblabel);
    delete_button.set_child(Some(&dbbox));
    // Inline function
    let dwindow = Rc::clone(&window);
    delete_button.connect_clicked(clone!(
        #[weak]
        application,
        move |_| {
            let selwindow = gtk4::Window::new();
            selwindow.set_application(Some(&application));
            selwindow.set_title(Some("Select vault..."));
            selwindow.set_size_request(320, 240);
            selwindow.set_modal(true);

            let selvbox = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
            selvbox.set_margin_start(12);
            selvbox.set_margin_end(12);

            let seltitle = gtk4::Label::new(Some("Select vault to delete:"));
            seltitle.add_css_class("big");
            selvbox.append(&seltitle);

            // Show vault list widget family
            let selscroll = gtk4::ScrolledWindow::new();
            selscroll.set_size_request(180, 200);
            selscroll.set_hscrollbar_policy(gtk4::PolicyType::Never);
            let sellist = gtk4::ListBox::new();
            selscroll.set_child(Some(&sellist));
            selvbox.append(&selscroll);
            selwindow.set_child(Some(&selvbox));

            let omaster_data = read_master(&selwindow);
            if omaster_data.is_none() {
                return;
            }
            let (vtype, nonce_buf, base_cipher) = omaster_data.unwrap();
            // Decrypt master
            if &vtype == b"d" {
                // Default encryption
                let obase_data = decrypt_aes(&selwindow, &base_cipher, nonce_buf, true);
                if obase_data.is_none() {
                    return;
                }
                let rbase_string = String::from_utf8(obase_data.unwrap());
                if rbase_string.is_err() {
                    show_alert(
                        &selwindow,
                        "Error",
                        "Failed to parse master vault to string.",
                    );
                    return;
                }

                let hidden_comm_label = gtk4::Label::new(None);
                let ddwindow = Rc::clone(&dwindow);
                hidden_comm_label.connect_css_classes_notify(clone!(
                    #[weak]
                    selwindow,
                    move |label| {
                        let newbase = label.text().to_string();
                        let obase_cipher = encrypt_aes(&selwindow, &newbase);
                        if obase_cipher.is_none() {
                            return;
                        }
                        let (nonced, based) = obase_cipher.unwrap();
                        write_master(&selwindow, b"d", nonced, based);
                        selwindow.close();
                        show_alert(
                            ddwindow.as_ref(),
                            "Vault deletion complete",
                            "Deletion command was issued for the selected vault.",
                        );
                    }
                ));
                for button in delete_button_vault_list(
                    Rc::new(rbase_string.unwrap()),
                    &application,
                    Rc::new(hidden_comm_label),
                ) {
                    sellist.append(&button);
                }
                selwindow.present();
            } else if &vtype == b"u" {
                // Password encryption
                // Ask password window
                let pw_window = gtk4::Window::new();
                pw_window.set_application(Some(&application));
                pw_window.set_title(Some("Master password"));

                // Ask password grid
                let pw_grid = gtk4::Grid::builder()
                    .margin_top(6)
                    .margin_bottom(6)
                    .margin_start(12)
                    .margin_end(12)
                    .row_spacing(8)
                    .column_spacing(8)
                    .build();
                // Ask label
                let pw_label = gtk4::Label::new(Some("Enter password to open master vault."));
                pw_grid.attach(&pw_label, 1, 1, 3, 1);
                // Input box
                let pw_box = gtk4::PasswordEntry::new();
                pw_grid.attach(&pw_box, 1, 2, 2, 1);

                let pw_ok_button = gtk4::Button::with_label("OK");
                pw_ok_button.connect_clicked(clone!(
                    #[weak]
                    pw_box,
                    #[weak]
                    pw_window,
                    #[weak]
                    selwindow,
                    #[weak]
                    application,
                    move |_| {
                        let obase_data = decrypt_aes_with_key(
                            &pw_window,
                            &base_cipher,
                            nonce_buf,
                            &hashify_sha256(&pw_box.text().to_string()),
                            false,
                        );
                        if obase_data.is_none() {
                            show_alert(&pw_window, "Error", "Failed to decrypt master vault.");
                            return;
                        }
                        pw_window.close();

                        let rbase_string = String::from_utf8(obase_data.unwrap());
                        if rbase_string.is_err() {
                            show_alert(
                                &selwindow,
                                "Error",
                                "Failed to parse master vault to string.",
                            );
                            return;
                        }

                        // A hidden label to communicate
                        let pw_base_hlabel = gtk4::Label::new(None);
                        pw_base_hlabel.connect_css_classes_notify(clone!(
                            #[weak]
                            selwindow,
                            move |label| {
                                let newbase = label.text().to_string();
                                let obase_cipher = encrypt_aes_with_key(
                                    &selwindow,
                                    &newbase,
                                    &hashify_sha256(&pw_box.text().to_string()),
                                );
                                if obase_cipher.is_none() {
                                    return;
                                }
                                let (nonced, based) = obase_cipher.unwrap();
                                write_master(&selwindow, b"u", nonced, based);
                                show_alert(
                                    &selwindow,
                                    "Vault deletion complete",
                                    "Deletion command was issued for the selected vault.",
                                );
                            }
                        ));

                        for button in delete_button_vault_list(
                            Rc::new(rbase_string.unwrap()),
                            &application,
                            Rc::new(pw_base_hlabel),
                        ) {
                            sellist.append(&button);
                        }
                        selwindow.present();
                    }
                ));
                pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                pw_window.set_child(Some(&pw_grid));
                pw_window.set_modal(true);
                pw_window.present();
            } else {
                show_alert(&selwindow, "Error", "Could not parse vault data.");
                return;
            }
        }
    ));
    grid.attach(&delete_button, 3, 2, 1, 1);

    window.set_child(Some(&grid));
    window.present();

    // Check if this is fresh
    // Get path
    let ovaultpath = get_vault_path();
    if ovaultpath.is_none() {
        show_alert(
            window.as_ref(),
            "Error",
            "Failed to detect the path to 'master.vbase'.",
        );
    }
    // Try to create new file, true if new
    let rbase_file = fs::File::create_new(ovaultpath.as_ref().unwrap());
    if rbase_file.is_ok() {
        // Fresh install, do some setup
        filebase_setup(
            &application,
            Rc::clone(&window),
            rbase_file.unwrap(),
            ovaultpath.unwrap(),
        );
    }
}

fn main() {
    let application = gtk4::Application::new(
        Some("local.net.jp7654.filebase"),
        gtk4::gio::ApplicationFlags::HANDLES_OPEN,
    );
    application.connect_activate(open_main);
    application.run();
}
