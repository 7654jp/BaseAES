/*
 *   FileBase, a simple filesystem-like vault system with strong encryption.
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
use std::io::Write;
use std::rc::Rc;

mod tools;
use tools::*;

fn open_vault(application: &gtk4::Application, decoded_data: String, commlabel: gtk4::Label) {
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
    vault_window.set_application(Some(application));
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

    let vault_add_file = gtk4::Button::new();
    vault_add_file.set_size_request(120, 48);
    let vaf_label = gtk4::Label::new(Some("New file"));
    vault_add_file.set_child(Some(&vaf_label));
    vault_grid.attach(&vault_add_file, 1, 1, 3, 1);

    let vault_add_folder = gtk4::Button::new();
    vault_add_folder.set_size_request(120, 48);
    let vad_label = gtk4::Label::new(Some("New folder"));
    vault_add_folder.set_child(Some(&vad_label));
    vault_grid.attach(&vault_add_folder, 4, 1, 3, 1);

    let vault_rename_item = gtk4::Button::new();
    vault_rename_item.set_size_request(80, 48);
    let vri_label = gtk4::Label::new(Some("Rename"));
    vault_rename_item.set_child(Some(&vri_label));
    vault_grid.attach(&vault_rename_item, 1, 2, 2, 1);

    let vault_export_item = gtk4::Button::new();
    vault_export_item.set_size_request(80, 48);
    let vei_label = gtk4::Label::new(Some("Export"));
    vault_export_item.set_child(Some(&vei_label));
    vault_grid.attach(&vault_export_item, 3, 2, 2, 1);

    let vault_delete_item = gtk4::Button::new();
    vault_delete_item.set_size_request(80, 48);
    let vdi_label = gtk4::Label::new(Some("Delete"));
    vault_delete_item.set_child(Some(&vdi_label));
    vault_grid.attach(&vault_delete_item, 5, 2, 2, 1);

    // Path viewer
    let vault_path = gtk4::Entry::builder().text("/").build();
    vault_path.set_size_request(200, 40);
    vault_path.set_editable(false);
    vault_grid.attach(&vault_path, 1, 3, 6, 1);

    // Item list
    let vault_scroll = gtk4::ScrolledWindow::new();
    vault_scroll.set_size_request(240, 280);
    vault_scroll.set_hscrollbar_policy(gtk4::PolicyType::Never);
    let vault_file_list = Rc::new(gtk4::ListBox::new());
    vault_scroll.set_child(Some(&*vault_file_list));
    vault_grid.attach(&vault_scroll, 1, 4, 6, 1);

    // Item viewer
    let vault_viewer = gtk4::ScrolledWindow::new();
    vault_viewer.set_size_request(400, 400);
    vault_viewer.set_hscrollbar_policy(gtk4::PolicyType::Automatic);
    vault_viewer.set_vscrollbar_policy(gtk4::PolicyType::Automatic);
    let vvetv = gtk4::TextView::new();
    vault_viewer.set_child(Some(&vvetv));
    vault_grid.attach(&vault_viewer, 7, 1, 1, 4);

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
    let window = gtk4::ApplicationWindow::new(application);
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
            let nv_name_box = gtk4::Text::new();
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
                        show_alert(&window, "Error", "Vault name cannot contain '^' or ':'.");
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
                        eprintln!("{}", label.text().to_string());
                    });
                    let (vtype, nonce_buf, base_cipher) = omaster_data.unwrap();
                    // Decrypt master
                    if &vtype == b"d" {
                        // Default encryption
                        let obase_data = decrypt_aes(&window, &base_cipher, nonce_buf, true);
                        if obase_data.is_none() {
                            return;
                        }
                        let oadded_str = add_vault(
                            obase_data.unwrap(),
                            vname.clone(),
                            nv_pass_box.text().to_string(),
                            &window,
                        );
                        if oadded_str.is_none() {
                            return;
                        }
                        let (added_master, vault_data) = oadded_str.unwrap();
                        // Save
                        let oadded_master = encrypt_aes(&window, &added_master);
                        if oadded_master.is_none() {
                            return;
                        }
                        let added_master = oadded_master.unwrap();
                        write_master(&window, b"d", added_master.0, added_master.1);
                        open_vault(&application, vault_data, hidden_comm_label);
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
                        pw_ok_button.connect_clicked(clone!(
                            #[weak]
                            application,
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
                                    &window,
                                ) {
                                    Some(added) => added,
                                    None => return,
                                };
                                // Save
                                let added_master = match encrypt_aes_with_key(
                                    &window,
                                    &added_master,
                                    &hashify_sha256(&pw_box.text().to_string()),
                                ) {
                                    Some(v) => v,
                                    None => return,
                                };
                                write_master(&window, b"u", added_master.0, added_master.1);
                                open_vault(&application, vault_data, hidden_comm_label);
                            }
                        ));
                        pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                        pw_window.set_child(Some(&pw_grid));
                        pw_window.set_modal(true);
                        pw_window.present();
                    } else {
                        show_alert(&window, "Error", "Could not parse vault data.");
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
            // Decrypt master
            if &vtype == b"d" {
                // Default encryption
                let obase_data = decrypt_aes(&selwindow, &base_cipher, nonce_buf, false);
                if obase_data.is_none() {
                    show_alert(&selwindow, "Error", "Failed to decrypt master vault.");
                    return;
                }
                let rbase_string = String::from_utf8(obase_data.unwrap());
                if rbase_string.is_err() {
                   return;
                }
                let base_string = rbase_string.unwrap();
                let hidden_comm_label2 = gtk4::Label::new(None);
                // Save after user edited data inside vault
                hidden_comm_label2.connect_css_classes_notify(|label| {
                    eprintln!("{}", label.text().to_string());
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
                        vlist_button.connect_clicked(clone!(
                            #[weak]
                            application,
                            #[weak]
                            selwindow,
                            #[strong]
                            mvdata,
                            #[strong]
                            hidden_comm_label2,
                            move |_| {
                                // Ask vault password
                                let vopen_window = gtk4::Window::builder()
                                    .title("Unlock vault")
                                    .modal(true)
                                    .build();
                                vopen_window.set_application(Some(&application));

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
                                vopen_ok_button.connect_clicked(clone!(
                                    #[weak]
                                    application,
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
                                            &application,
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
                        hidden_comm_label2.connect_css_classes_notify(move |label| {
                            eprintln!("{}", label.text().to_string());
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
                                vlist_button.connect_clicked(clone!(
                                    #[weak]
                                    application,
                                    #[weak]
                                    selwindow,
                                    #[strong]
                                    mvdata,
                                    #[strong]
                                    hidden_comm_label2,
                                    move |_| {
                                        // Ask vault password
                                        let vopen_window = gtk4::Window::builder()
                                            .title("Unlock vault")
                                            .modal(true)
                                            .build();
                                        vopen_window.set_application(Some(&application));

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
                                        vopen_ok_button.connect_clicked(clone!(
                                            #[weak]
                                            application,
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
                                                    &application,
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
                hidden_comm_label.connect_css_classes_notify(move |label| {
                    eprint!("Deleted:\n{}", label.text().to_string());
                });
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
                        pw_base_hlabel.connect_css_classes_notify(move |label| {
                            eprint!("Deleted vault:\n{}", label.text().to_string());
                        });

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
            &window,
            "Error",
            "Failed to detect the path to 'master.vbase'.",
        );
    }
    // Try to create new file, true if new
    let rbase_file = fs::File::create_new(ovaultpath.as_ref().unwrap());
    if rbase_file.is_ok() {
        // Fresh install
        // Setup window
        let setup_window = gtk4::Window::builder()
            .application(application)
            .title("FileBase setup")
            .resizable(false)
            .modal(true)
            .build();
        setup_window.set_size_request(400, 480);

        let setup_grid = gtk4::Grid::builder()
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .row_spacing(8)
            .column_spacing(8)
            .build();

        let setup_title = gtk4::Label::new(Some("Welcome to FileBase!"));
        setup_title.add_css_class("big");
        setup_grid.attach(&setup_title, 1, 1, 2, 1);

        let setup_desc = gtk4::Label::new(Some(
            "FileBase will help keep your files safe.\nRead PRECAUTIONS before start!",
        ));
        setup_grid.attach(&setup_desc, 1, 2, 2, 1);

        // Read before continue
        let setup_precautions = gtk4::ScrolledWindow::new();
        setup_precautions.add_css_class("notice");
        setup_precautions.set_size_request(320, 280);
        let setup_precautions_text = gtk4::Label::new(Some(PRECAUTIONS_TXT));
        setup_precautions.set_child(Some(&setup_precautions_text));
        setup_grid.attach(&setup_precautions, 1, 3, 2, 1);

        // Master file encryption selectors etc.
        let setup_aes_desc = gtk4::Label::new(Some("Select master file encryption:"));
        setup_grid.attach(&setup_aes_desc, 1, 4, 2, 1);

        let setup_aes_selector1 = gtk4::CheckButton::new();
        let setup_aes_label1 = gtk4::Label::new(Some("Use default"));
        setup_aes_selector1.set_child(Some(&setup_aes_label1));

        let setup_aes_selector2 = gtk4::CheckButton::new();
        let setup_aes_label2 = gtk4::Label::new(Some("Use password (extra safety)"));
        setup_aes_selector2.set_child(Some(&setup_aes_label2));
        setup_aes_selector1.set_group(Some(&setup_aes_selector2));

        setup_grid.attach(&setup_aes_selector1, 1, 5, 1, 1);
        setup_grid.attach(&setup_aes_selector2, 2, 5, 1, 1);

        let setup_aes_pwbox = gtk4::PasswordEntry::new();
        setup_grid.attach(&setup_aes_pwbox, 2, 6, 1, 1);

        let setup_aes_button = gtk4::Button::new();
        let setup_aes_button_label = gtk4::Label::new(Some("OK"));
        setup_aes_button.set_child(Some(&setup_aes_button_label));
        let masterfile = RefCell::new(rbase_file.unwrap());
        let selectors = (setup_aes_selector1.clone(), setup_aes_selector2.clone());
        setup_aes_button.connect_clicked(clone!(
            #[weak]
            setup_window,
            move |_| {
                let default_encrypt = selectors.0.is_active();
                if default_encrypt || selectors.1.is_active() {
                    // Use default encryption
                    let oencrypted = if default_encrypt {
                        encrypt_aes(&setup_window, "^FileBase All-in-One vault Ver.1^\n")
                    } else {
                        encrypt_aes_with_key(
                            &setup_window,
                            "^FileBase All-in-One vault Ver.1^\n",
                            &hashify_sha256(&setup_aes_pwbox.text().to_string()),
                        )
                    };
                    if oencrypted.is_none() {
                        return;
                    }
                    let (nonced, valued) = oencrypted.unwrap();
                    let mut mfile = masterfile.borrow_mut();

                    let rtwrite = mfile.write(if default_encrypt { b"d" } else { b"u" });
                    if rtwrite.is_err() {
                        show_alert(
                            &setup_window,
                            "Error",
                            "Could not write encrypt type to master vault.",
                        );
                        return;
                    }
                    let rnwrite = mfile.write_all(&nonced);
                    if rnwrite.is_err() {
                        show_alert(
                            &setup_window,
                            "Error",
                            "Could not write nonce to master vault.",
                        );
                        return;
                    }
                    let rdwrite = mfile.write_all(&valued);
                    if rdwrite.is_err() {
                        show_alert(
                            &setup_window,
                            "Error",
                            "Could not write default value to master vault.",
                        );
                        return;
                    }
                    setup_window.close();
                }
            }
        ));
        setup_grid.attach(&setup_aes_button, 2, 7, 1, 1);

        setup_window.set_child(Some(&setup_grid));
        setup_window.connect_close_request(clone!(
            #[strong]
            ovaultpath,
            move |_| {
                if !(setup_aes_selector1.is_active() || setup_aes_selector2.is_active()) {
                    let _ = fs::remove_file(ovaultpath.as_ref().unwrap());
                    window.close();
                }
                glib::Propagation::Proceed
            }
        ));
        setup_window.present();
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
