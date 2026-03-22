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
use std::fs;
use std::rc::Rc;

mod tools;
use tools::*;

fn open_vault(application: Rc<gtk4::Application>, decoded_data: String, commlabel: gtk4::Label) {
    // Convert to three
    let vault_data = match vault_decode(decoded_data) {
        Some(data) => data,
        None => return,
    };
    let vname = vault_data.0;
    //let vindex = vault_data.1;
    //let vdata = vault_data.2;

    // Window
    let vault_window = gtk4::Window::new();
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

    // Item list
    let vault_scroll = gtk4::ScrolledWindow::new();
    vault_scroll.set_size_request(240, 280);
    vault_scroll.set_hscrollbar_policy(gtk4::PolicyType::Never);
    let vault_file_list = Rc::new(gtk4::ListBox::new());
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
    vault_grid.attach(&vault_other_ctrl, 2, 2, 1, 1);

    vault_window.connect_close_request(move |_| {
        commlabel.set_text("str");
        commlabel.add_css_class(&format!(
            "notify_{}",
            u8_to_hex(&hashify_sha256(&vname)[0..6]),
        ));
        glib::Propagation::Proceed
    });

    vault_window.set_child(Some(&vault_grid));
    vault_window.present();
}

fn open_main(application: &gtk4::Application) {
    // Main window
    let windowr = gtk4::ApplicationWindow::new(application);
    windowr.set_title(Some("FileBase"));
    windowr.set_default_size(400, 180);
    windowr.set_resizable(false);
    let window = Rc::new(windowr);

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
    add_button.connect_clicked(clone!(
        #[weak]
        application,
        #[weak]
        window,
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
            nv_ok_button.connect_clicked(clone!(
                #[weak]
                window,
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
                        show_alert(&*window, "Error", "Vault name cannot contain '^' or ':'.");
                        return;
                    }
                    // Get master data
                    let omaster_data = read_master(&nv_window);
                    nv_window.close();
                    if omaster_data.is_none() {
                        return;
                    }
                    let hidden_comm_label = gtk4::Label::new(None);
                    // Save after user edited data inside vault
                    hidden_comm_label.connect_css_classes_notify(|label| {
                        let edited_vault = label.text().to_string();
                        eprintln!("[Debug] main.rs:223\nValue returned in main:\n{edited_vault}");
                    });
                    let (vtype, nonce_buf, base_cipher) = omaster_data.unwrap();
                    // Decrypt master
                    if &vtype == b"d" {
                        // Default encryption
                        let obase_data = decrypt_aes(&*window, &base_cipher, nonce_buf, true);
                        if obase_data.is_none() {
                            return;
                        }
                        let oadded_str = add_vault(
                            obase_data.unwrap(),
                            vname.clone(),
                            nv_pass_box.text().to_string(),
                            &*window,
                        );
                        if oadded_str.is_none() {
                            return;
                        }
                        let (added_master, vault_data) = oadded_str.unwrap();
                        // Save
                        let oadded_master = encrypt_aes(&*window, &added_master);
                        if oadded_master.is_none() {
                            return;
                        }
                        let added_master = oadded_master.unwrap();
                        write_master(&*window, b"d", added_master.0, added_master.1);
                        open_vault(Rc::new(application), vault_data, hidden_comm_label);
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
                        pw_ok_button.connect_clicked(clone!(
                            #[weak]
                            pw_window,
                            #[weak]
                            hidden_comm_label,
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
                                let (added_master, vault_data) = match add_vault(
                                    obase_data.unwrap(),
                                    vname.clone(),
                                    nv_pass_box.text().to_string(),
                                    &*window,
                                ) {
                                    Some(added) => added,
                                    None => return,
                                };
                                // Save
                                let added_master = match encrypt_aes_with_key(
                                    &*window,
                                    &added_master,
                                    &hashify_sha256(&pw_box.text().to_string()),
                                ) {
                                    Some(v) => v,
                                    None => return,
                                };
                                write_master(&*window, b"u", added_master.0, added_master.1);
                                open_vault(Rc::clone(&aapprc), vault_data, hidden_comm_label);
                            }
                        ));
                        pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                        pw_window.set_child(Some(&pw_grid));
                        pw_window.set_modal(true);
                        pw_window.present();
                    } else {
                        show_alert(&*window, "Error", "Could not parse vault data.");
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
                let hidden_comm_label2 = gtk4::Label::new(None);
                // Save after user edited data inside vault
                hidden_comm_label2.connect_css_classes_notify(|label| {
                    let edited_vault = label.text().to_string();
                    eprintln!("[Debug] main.rs:410\nValue returned in main:\n{edited_vault}");
                });

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
                                            true,
                                        ) {
                                            Some(bin) => bin,
                                            None => return,
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
                        let hidden_comm_label2 = gtk4::Label::new(None);
                        // Save after user edited data inside vault
                        let ooowindow = Rc::clone(&oowindow);
                        let opw_box = Rc::clone(&pw_box);
                        hidden_comm_label2.connect_css_classes_notify(move |label| {
                            let edited_vault = label.text().to_string();
                            let opt_encrypt = encrypt_aes_with_key(&*ooowindow, &edited_vault, &hashify_sha256(&opw_box.text().to_string()));
                            if opt_encrypt.is_none() {
                                show_alert(&*ooowindow, "Error", "Failed to encrypt changed vault.");
                                return;
                            };
                            let (nonce, data) = opt_encrypt.unwrap();
                            write_master(&*ooowindow, b"u", nonce, data);
                        });

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
                                                    true,
                                                ) {
                                                    Some(bin) => bin,
                                                    None => return,
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
            &*window,
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
