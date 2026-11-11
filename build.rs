fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/steampin.ico");
        res.set("ProductName", "SteamPin");
        res.set("FileDescription", "SteamPin - keeps Steam working where it's blocked");
        res.set("CompanyName", "CratusGod");
        res.set("LegalCopyright", "Copyright (c) 2026 CratusGod");
        res.set_manifest(include_str!("assets/app.manifest"));
        res.compile().expect("resource compile failed");
    }
    println!("cargo:rerun-if-changed=assets/steampin.ico");
    println!("cargo:rerun-if-changed=assets/app.manifest");
    println!("cargo:rerun-if-changed=vendor/zapret");
}
