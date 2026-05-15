/*
 *   BaseAES, a simple filesystem-like vault system with strong encryption.
 *   Copyright (C) 2026  7654jp
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
use std::rc::Rc;

mod tools;
use tools::*;

use crate::types::*;
mod types;
mod vault;

fn open_main(application: &gtk4::Application) {
    // Main window
    let window = Rc::new(gtk4::ApplicationWindow::new(application));
    window.set_title(Some("BaseAES"));
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
    title_label.set_markup("<b>BaseAES Vault Manager</b>");
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
    let abimg =
        gtk4::Image::from_pixbuf(get_pixbuf_from_png_u8(include_bytes!("images/add.png")).as_ref());
    abimg.set_size_request(48, 48);
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
            let nv_passbox_rc = Rc::new(nv_pass_box);
            nv_ok_button.connect_clicked(clone!(
                #[weak]
                application,
                #[weak]
                nv_window,
                move |_| {
                    // Filter vault name
                    let vname = Rc::new(nv_name_box.text().to_string());
                    if vname.contains("^") || vname.contains(",") {
                        show_alert(
                            &nv_window,
                            "Error",
                            "Vault name cannot contain  ' ^ '  or  ' , '  .",
                        );
                        return;
                    }
                    nv_window.close();
                    // Get master data
                    let mvname = match master_read_vname(&nv_window) {
                        Some(d) => d,
                        None => return,
                    };
                    let mvname_info = Rc::new(mvname.0);
                    let mvname_cipher = Rc::new(mvname.1);
                    let vcomm_label = Rc::new(RefCell::new(gtk4::Label::new(None)));
                    let vcomm_index: Rc<RefCell<ItemContainer<i16>>> =
                        Rc::new(RefCell::new(ItemContainer::new(-1)));

                    // Decrypt master
                    if &[mvname_info[0]] == b"d" {
                        // Default encryption
                        let mvname_nonce = mvname_info[1..13].try_into().unwrap();
                        let vname_plain_opt = decrypt_aes(
                            Some(aawindow.as_ref()),
                            &mvname_cipher,
                            mvname_nonce,
                            true,
                        );
                        if vname_plain_opt.is_none() {
                            return;
                        }
                        let vname_plain_str_opt = String::from_utf8(vname_plain_opt.unwrap());
                        if vname_plain_str_opt.is_err() {
                            show_alert(
                                aawindow.as_ref(),
                                "Error",
                                "Could not parse 'vname' as string.",
                            );
                            return;
                        };
                        let vname_plain_str = vname_plain_str_opt.unwrap();

                        let mut vault_count: i16 = 0;
                        // Vault name validation check
                        if vname_plain_str.contains(",") {
                            if let Some(vc) = check_vault_name(
                                Rc::clone(&aawindow),
                                &vname_plain_str,
                                Rc::clone(&vname),
                            ) {
                                vault_count = vc;
                            } else {
                                return;
                            }
                        }
                        vcomm_index.borrow_mut().set(vault_count);

                        // Given:
                        // (edited full vname) and (password encrypted vdata)
                        let (added_full_vname, diff_vdata) = match generate_new_vault(
                            vname_plain_str,
                            Rc::clone(&vname).as_ref(),
                            &hashify_sha256(nv_passbox_rc.text().to_string()),
                            aawindow.as_ref(),
                        ) {
                            Some((vname, vdata)) => (vname, vdata),
                            None => {
                                show_alert(
                                    aawindow.as_ref(),
                                    "Error",
                                    "Failed to generate the new vault.",
                                );
                                return;
                            }
                        };
                        let mut diffvdata_buf = Vec::new();
                        diffvdata_buf.extend_from_slice(&diff_vdata.0);
                        diffvdata_buf.extend_from_slice(&diff_vdata.1);

                        // Save new data
                        // Get encrypted vname related data
                        let new_vname_cipher =
                            match encrypt_aes(aawindow.as_ref(), added_full_vname.as_bytes()) {
                                Some(b) => b,
                                None => {
                                    show_alert(
                                        aawindow.as_ref(),
                                        "Error",
                                        "Failed to encrypt 'full-vname'.",
                                    );
                                    return;
                                }
                            };

                        let master_diff_vdata = match encrypt_aes(aawindow.as_ref(), &diffvdata_buf)
                        {
                            Some(b) => b,
                            None => return,
                        };

                        master_update_data(
                            aawindow.as_ref(),
                            Some((b"d", new_vname_cipher)),
                            Some((VDATA_INDEX_APPEND, Some(&master_diff_vdata))),
                        );

                        // Save after user edited data inside vault
                        let aaawindow = Rc::clone(&aawindow);
                        vcomm_label
                            .borrow_mut()
                            .connect_css_classes_notify(move |label| {
                                if let Some(edited_vdata) = encrypt_aes(
                                    aaawindow.as_ref(),
                                    &hex_to_u8(&label.text().to_string()).unwrap(),
                                ) {
                                    master_update_data(
                                        aaawindow.as_ref(),
                                        None,
                                        Some((vault_count, Some(&edited_vdata))),
                                    );
                                } else {
                                    show_alert(
                                        aaawindow.as_ref(),
                                        "Error",
                                        "Failed to encrypt master vault.",
                                    );
                                }
                            });
                        vault::ask_vault_password_and_open(
                            Rc::new(application),
                            diff_vdata,
                            vcomm_label,
                        );
                    } else if &[mvname_info[0]] == b"u" {
                        // Password encryption
                        // Ask password window
                        let pw_window = gtk4::Window::new();
                        pw_window.set_application(Some(&application));
                        pw_window.set_title(Some("Master password"));
                        pw_window.set_size_request(216, 84);
                        pw_window.set_resizable(false);

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
                        let aaawindow = Rc::clone(&aawindow);
                        let vcommindex = Rc::clone(&vcomm_index);
                        let vcommlabel = Rc::clone(&vcomm_label);
                        let nv_pass_rc = Rc::clone(&nv_passbox_rc);
                        pw_ok_button.connect_clicked(clone!(
                            #[weak]
                            pw_window,
                            move |_| {
                                let user_key = Rc::new(hashify_sha256(pw_box.text().to_string()));
                                let vname_plain_opt = decrypt_aes_with_key(
                                    Some(&pw_window),
                                    mvname_cipher.as_ref(),
                                    mvname_info[1..13].try_into().unwrap(),
                                    user_key.as_ref(),
                                    false,
                                );
                                if vname_plain_opt.is_none() {
                                    show_alert(
                                        &pw_window,
                                        "Error",
                                        "Failed to decrypt master vault.",
                                    );
                                    return;
                                }
                                pw_window.close();
                                let sbase_data = String::from_utf8(vname_plain_opt.unwrap());
                                if sbase_data.is_err() {
                                    show_alert(
                                        aaawindow.as_ref(),
                                        "Error",
                                        "Could not parse 'vname' as string.",
                                    );
                                    return;
                                }
                                let base_data = sbase_data.unwrap();

                                let mut vault_count: i16 = 0;
                                // Vault name validation check
                                if base_data.contains(",") {
                                    if let Some(vc) = check_vault_name(
                                        Rc::clone(&aaawindow),
                                        &base_data,
                                        Rc::clone(&vname),
                                    ) {
                                        vault_count = vc;
                                    } else {
                                        return;
                                    }
                                }
                                vcommindex.borrow_mut().set(vault_count);

                                // Given:
                                // (edited full vname) and (password encrypted vdata)
                                let (added_full_vname, diff_vdata) = match generate_new_vault(
                                    base_data,
                                    Rc::clone(&vname).as_ref(),
                                    &hashify_sha256(nv_pass_rc.text().to_string()),
                                    aaawindow.as_ref(),
                                ) {
                                    Some((vname, vdata)) => (vname, vdata),
                                    None => {
                                        show_alert(
                                            aaawindow.as_ref(),
                                            "Error",
                                            "Failed to generate the new vault.",
                                        );
                                        return;
                                    }
                                };
                                let mut diffvdata_buf = Vec::new();
                                diffvdata_buf.extend_from_slice(&diff_vdata.0);
                                diffvdata_buf.extend_from_slice(&diff_vdata.1);

                                // Save new data
                                // Get encrypted vname related data
                                let new_vname_cipher = match encrypt_aes_with_key(
                                    aaawindow.as_ref(),
                                    added_full_vname.as_bytes(),
                                    user_key.as_ref(),
                                ) {
                                    Some(b) => b,
                                    None => {
                                        show_alert(
                                            aaawindow.as_ref(),
                                            "Error",
                                            "Failed to encrypt 'full-vname'.",
                                        );
                                        return;
                                    }
                                };

                                let master_diff_vdata =
                                    match encrypt_aes(aaawindow.as_ref(), &diffvdata_buf) {
                                        Some(b) => b,
                                        None => return,
                                    };

                                master_update_data(
                                    aaawindow.as_ref(),
                                    Some((b"u", new_vname_cipher)),
                                    Some((VDATA_INDEX_APPEND, Some(&master_diff_vdata))),
                                );

                                // Save after user edited data inside vault
                                let userkey_rc = Rc::clone(&user_key);
                                let aaaawindow = Rc::clone(&aaawindow);
                                vcommlabel
                                    .borrow_mut()
                                    .connect_css_classes_notify(move |label| {
                                        if let Some(encrypted_master) = encrypt_aes_with_key(
                                            aaaawindow.as_ref(),
                                            &hex_to_u8(&label.text().to_string()).unwrap(),
                                            userkey_rc.as_ref(),
                                        ) {
                                            master_update_data(
                                                aaaawindow.as_ref(),
                                                None,
                                                Some((vault_count, Some(&encrypted_master))),
                                            );
                                        } else {
                                            show_alert(
                                                aaaawindow.as_ref(),
                                                "Error",
                                                "Failed to encrypt master vault.",
                                            );
                                        }
                                    });
                                vault::ask_vault_password_and_open(
                                    Rc::clone(&aapprc),
                                    diff_vdata,
                                    Rc::clone(&vcommlabel),
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
    let obimg = gtk4::Image::from_pixbuf(
        get_pixbuf_from_png_u8(include_bytes!("images/open.png")).as_ref(),
    );
    obimg.set_size_request(48, 48);
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
            let selwindow = Rc::new(gtk4::Window::new());
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

            let (vname_info, vname_cipher) = match master_read_vname(selwindow.as_ref()) {
                Some(vndata) => vndata,
                None => return,
            };
            let vcomm_label = Rc::new(RefCell::new(gtk4::Label::new(None)));
            let vcomm_index: Rc<RefCell<ItemContainer<i16>>> =
                Rc::new(RefCell::new(ItemContainer::new(-1)));

            let oapprc = Rc::new(application);
            // Decrypt master
            if &[vname_info[0]] == b"d" {
                // Default encryption
                let vname_opt = decrypt_aes(
                    Some(selwindow.as_ref()),
                    &vname_cipher,
                    vname_info[1..13].try_into().unwrap(),
                    false,
                );
                if vname_opt.is_none() {
                    show_alert(selwindow.as_ref(), "Error", "Failed to decrypt 'vname'.");
                    return;
                }
                let vname_str_res = String::from_utf8(vname_opt.unwrap());
                if vname_str_res.is_err() {
                    return;
                }
                let vname_str = Rc::new(vname_str_res.unwrap());
                // Save after user edited data inside vault
                let oowindow = Rc::clone(&owindow);
                let vcindex_drc = Rc::clone(&vcomm_index);
                vcomm_label
                    .borrow_mut()
                    .connect_css_classes_notify(move |label| {
                        if let Some(encrypted_master) = encrypt_aes(
                            oowindow.as_ref(),
                            &hex_to_u8(&label.text().to_string()).unwrap(),
                        ) {
                            master_update_data(
                                oowindow.as_ref(),
                                None,
                                Some((*vcindex_drc.borrow().get(), Some(&encrypted_master))),
                            );
                        } else {
                            show_alert(
                                oowindow.as_ref(),
                                "Error",
                                "Failed to encrypt master vault.",
                            );
                        }
                    });

                let mut vault_count: i16 = 0;
                for name in vname_str.split(",") {
                    if name.contains("^") || name == "" {
                        continue;
                    }
                    let vlist_button = gtk4::Button::with_label(name);
                    let oapplrc = Rc::clone(&oapprc);
                    let vcount_at = vault_count.clone();
                    let selwindow_rc = Rc::clone(&selwindow);
                    let vcommlabel = Rc::clone(&vcomm_label);
                    let vcommindex = Rc::clone(&vcomm_index);
                    vlist_button.connect_clicked(move |_| {
                        vcommindex.borrow_mut().set(vcount_at);
                        let (v_sender, v_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
                        std::thread::spawn(move || {
                            let vault_opt =
                                master_read_vault_at(None::<&gtk4::Window>, vcount_at as usize);
                            if vault_opt.is_none() {
                                return;
                            }
                            let (vault_nonce, vault_data) = vault_opt.unwrap();
                            if let Some(demast_vault) =
                                decrypt_aes(None::<&gtk4::Window>, &vault_data, vault_nonce, true)
                            {
                                let _ = v_sender.send(demast_vault);
                            } else {
                                drop(v_sender);
                            }
                        });

                        vault::ask_vault_password_and_open_async(
                            Rc::clone(&oapplrc),
                            v_receiver,
                            Rc::clone(&vcommlabel),
                            Rc::clone(&selwindow_rc),
                        );
                    });
                    sellist.append(&vlist_button);
                    vault_count += 1;
                }
                selwindow.present();
            } else if &[vname_info[0]] == b"u" {
                // Password encryption
                // Ask password window
                let pw_window = gtk4::Window::new();
                pw_window.set_application(Some(oapprc.as_ref()));
                pw_window.set_title(Some("Master password"));
                pw_window.set_size_request(216, 84);
                pw_window.set_resizable(false);

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
                let selwindow_rc = Rc::clone(&selwindow);
                pw_ok_button.connect_clicked(clone!(
                    #[weak]
                    pw_window,
                    move |_| {
                        let mast_key = Rc::new(hashify_sha256(pw_box.text().to_string()));
                        let vname_opt = decrypt_aes_with_key(
                            Some(&pw_window),
                            &vname_cipher,
                            vname_info[1..13].try_into().unwrap(),
                            &mast_key,
                            false,
                        );
                        if vname_opt.is_none() {
                            show_alert(&pw_window, "Error", "Failed to decrypt 'vname'.");
                            return;
                        }
                        pw_window.close();
                        let vname_str_res = String::from_utf8(vname_opt.unwrap());
                        if vname_str_res.is_err() {
                            return;
                        }
                        let vname_str = Rc::new(vname_str_res.unwrap());

                        // Save after user edited data inside vault
                        let ooowindow = Rc::clone(&oowindow);
                        let mkey_rc = Rc::clone(&mast_key);
                        let vcindex_urc = Rc::clone(&vcomm_index);
                        vcomm_label
                            .borrow_mut()
                            .connect_css_classes_notify(move |label| {
                                if let Some(encrypted_master) = encrypt_aes_with_key(
                                    ooowindow.as_ref(),
                                    &hex_to_u8(&label.text().to_string()).unwrap(),
                                    mkey_rc.as_ref(),
                                ) {
                                    master_update_data(
                                        ooowindow.as_ref(),
                                        None,
                                        Some((
                                            *vcindex_urc.borrow().get(),
                                            Some(&encrypted_master),
                                        )),
                                    );
                                } else {
                                    show_alert(
                                        ooowindow.as_ref(),
                                        "Error",
                                        "Failed to encrypt master vault.",
                                    );
                                }
                            });

                        let mut vault_count: i16 = 0;
                        for name in vname_str.split(",") {
                            if name.contains("^") || name == "" {
                                continue;
                            }
                            let vlist_button = gtk4::Button::with_label(name);
                            let oapplrc = Rc::clone(&oapprc);
                            let vcount_at = vault_count.clone();
                            let mkey_lrc = Rc::clone(&mast_key);
                            let selwindow_rc = Rc::clone(&selwindow);
                            let vcommindex = Rc::clone(&vcomm_index);
                            let vcommlabel = Rc::clone(&vcomm_label);
                            vlist_button.connect_clicked(move |_| {
                                vcommindex.borrow_mut().set(vcount_at);
                                let mkey_raw = mkey_lrc.as_ref().to_owned();
                                let (v_sender, v_receiver) = std::sync::mpsc::channel::<Vec<u8>>();
                                std::thread::spawn(move || {
                                    let vault_opt = master_read_vault_at(
                                        None::<&gtk4::Window>,
                                        vcount_at as usize,
                                    );
                                    if vault_opt.is_none() {
                                        return;
                                    }
                                    let (vault_nonce, vault_data) = vault_opt.unwrap();
                                    if let Some(demast_vault) = decrypt_aes_with_key(
                                        None::<&gtk4::Window>,
                                        &vault_data,
                                        vault_nonce,
                                        &mkey_raw,
                                        true,
                                    ) {
                                        let _ = v_sender.send(demast_vault);
                                    } else {
                                        drop(v_sender);
                                    }
                                });
                                selwindow_rc.close();
                                vault::ask_vault_password_and_open_async(
                                    Rc::clone(&oapplrc),
                                    v_receiver,
                                    Rc::clone(&vcommlabel),
                                    Rc::clone(&selwindow_rc),
                                );
                            });
                            sellist.append(&vlist_button);
                            vault_count += 1;
                        }
                        selwindow_rc.present();
                    }
                ));
                pw_grid.attach(&pw_ok_button, 3, 2, 1, 1);

                pw_window.set_child(Some(&pw_grid));
                pw_window.present();
            } else {
                show_alert(selwindow.as_ref(), "Error", "Could not parse vault data.");
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
    let dbimg = gtk4::Image::from_pixbuf(
        get_pixbuf_from_png_u8(include_bytes!("images/delete.png")).as_ref(),
    );
    dbimg.set_size_request(48, 48);
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
            let selwindow = Rc::new(gtk4::Window::new());
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

            let (vname_info, vname_cipher) = match master_read_vname(selwindow.as_ref()) {
                Some((vn_info, vn_cipher)) => (vn_info, vn_cipher),
                None => return,
            };

            // Decrypt master
            if &[vname_info[0]] == b"d" {
                // Default encryption
                let vname_data_opt = decrypt_aes(
                    Some(selwindow.as_ref()),
                    &vname_cipher,
                    vname_info[1..13].try_into().unwrap(),
                    true,
                );
                if vname_data_opt.is_none() {
                    return;
                }
                let vname_str_res = String::from_utf8(vname_data_opt.unwrap());
                if vname_str_res.is_err() {
                    show_alert(
                        selwindow.as_ref(),
                        "Error",
                        "Failed to parse 'vname' as string.",
                    );
                    return;
                }

                let ddwindow = Rc::clone(&dwindow);
                let vcomm_label = Rc::new(RefCell::new(gtk4::Label::new(None)));
                let vcomm_index: Rc<RefCell<ItemContainer<i16>>> =
                    Rc::new(RefCell::new(ItemContainer::new(-1)));

                let vcommindex = Rc::clone(&vcomm_index);
                let selwindow_rc = Rc::clone(&selwindow);
                vcomm_label
                    .borrow_mut()
                    .connect_css_classes_notify(move |label| {
                        // Update vname
                        let vname_cipher_opt =
                            encrypt_aes(selwindow_rc.as_ref(), &label.text().as_bytes());
                        if vname_cipher_opt.is_none() {
                            return;
                        }
                        // Update vdata
                        let vault_index = *vcommindex.borrow().get();
                        master_update_data(
                            selwindow_rc.as_ref(),
                            Some((b"d", vname_cipher_opt.unwrap())),
                            Some((vault_index, None)),
                        );
                        selwindow_rc.close();
                        show_alert(
                            ddwindow.as_ref(),
                            "Vault deletion complete",
                            "Deletion command was issued for the selected vault.",
                        );
                    });

                for button in delete_button_vault_list(
                    b"d",
                    Rc::clone(&selwindow),
                    vname_str_res.unwrap(),
                    Rc::new(application),
                    Rc::clone(&vcomm_label),
                    Rc::clone(&vcomm_index),
                ) {
                    sellist.append(&button);
                }
                selwindow.present();
            } else if &[vname_info[0]] == b"u" {
                // Password encryption
                // Ask password window
                let pw_window = Rc::new(gtk4::Window::new());
                pw_window.set_application(Some(&application));
                pw_window.set_title(Some("Master password"));
                pw_window.set_size_request(216, 84);
                pw_window.set_resizable(false);

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
                let ddwindow = Rc::clone(&dwindow);
                let pwwindow_rc = Rc::clone(&pw_window);
                let selwindow_rc = Rc::clone(&selwindow);
                pw_ok_button.connect_clicked(clone!(
                    #[weak]
                    pw_box,
                    #[weak]
                    application,
                    move |_| {
                        let master_pw = Rc::new(hashify_sha256(pw_box.text().to_string()));
                        let vname_data_opt = decrypt_aes_with_key(
                            Some(pwwindow_rc.as_ref()),
                            &vname_cipher,
                            vname_info[1..13].try_into().unwrap(),
                            master_pw.as_ref(),
                            false,
                        );
                        if vname_data_opt.is_none() {
                            show_alert(
                                pwwindow_rc.as_ref(),
                                "Error",
                                "Failed to decrypt 'vname' .",
                            );
                            return;
                        }
                        pwwindow_rc.close();

                        let vname_str_res = String::from_utf8(vname_data_opt.unwrap());
                        if vname_str_res.is_err() {
                            show_alert(
                                selwindow_rc.as_ref(),
                                "Error",
                                "Failed to parse 'vname' as string.",
                            );
                            return;
                        }

                        let dddwindow = Rc::clone(&ddwindow);
                        let vcomm_label = Rc::new(RefCell::new(gtk4::Label::new(None)));
                        let vcomm_index: Rc<RefCell<ItemContainer<i16>>> =
                            Rc::new(RefCell::new(ItemContainer::new(-1)));

                        let masterpw_rc = Rc::clone(&master_pw);
                        let vcommindex = Rc::clone(&vcomm_index);
                        let selwindow_drc = Rc::clone(&selwindow_rc);
                        vcomm_label
                            .borrow_mut()
                            .connect_css_classes_notify(move |label| {
                                // Update vname
                                let vname_cipher_opt = encrypt_aes_with_key(
                                    selwindow_drc.as_ref(),
                                    &label.text().as_bytes(),
                                    masterpw_rc.as_ref(),
                                );
                                if vname_cipher_opt.is_none() {
                                    return;
                                }
                                // Update vdata
                                let label_ivalue = *vcommindex.borrow().get();
                                master_update_data(
                                    selwindow_drc.as_ref(),
                                    Some((b"u", vname_cipher_opt.unwrap())),
                                    Some((label_ivalue, None)),
                                );
                                selwindow_drc.close();
                                show_alert(
                                    dddwindow.as_ref(),
                                    "Vault deletion complete",
                                    "Deletion command was issued for the selected vault.",
                                );
                            });

                        for button in delete_button_vault_list(
                            b"u",
                            Rc::clone(&pwwindow_rc),
                            vname_str_res.unwrap(),
                            Rc::new(application),
                            Rc::clone(&vcomm_label),
                            Rc::clone(&vcomm_index),
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
                show_alert(selwindow.as_ref(), "Error", "Could not parse vault data.");
                return;
            }
        }
    ));
    grid.attach(&delete_button, 3, 2, 1, 1);

    window.set_child(Some(&grid));
    window.present();

    // Check if this is fresh
    // Get path
    if let Some(vaultpath) = get_vault_path() {
        // Try to create new file, true if new
        if let Ok(file) = fs::File::create_new(&vaultpath) {
            // Fresh install, do some setup
            baseaes_setup(&application, Rc::clone(&window), file, vaultpath);
        };
    } else {
        show_alert(
            window.as_ref(),
            "Error",
            "Failed to detect the path to 'master.vbase'.",
        );
    };
}

fn main() {
    println!(
        "\n==========\nTHIS IS A DEBUG VERSION, NOT INTENDED FOR RELEASE.\nREMOVE ALL 'eprintln' BEFORE RELEASE.\nTHIS VERSION STILL CONTAINS BUGS. CONTACT DEVELOPER IF YOU SAW THIS.\n==========\n"
    );
    let application = gtk4::Application::new(
        Some("local.net.jp7654.baseaes"),
        gtk4::gio::ApplicationFlags::HANDLES_OPEN,
    );
    application.connect_activate(open_main);
    application.run();
}
