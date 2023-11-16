//! Connecting to NKU's WiFi in Rust
//!
//! Remember to set SSID, USERNAME, PASSWORD via envionment variables.
//!
//! Obtained by merging:
//! - https://github.com/esp-rs/esp-idf-svc/blob/master/examples/http_request.rs
//! - https://github.com/esp-rs/esp-idf-svc/blob/master/examples/tls.rs

use embedded_svc::{
    http::{client::Client as HttpClient, Method},
    utils::io,
    wifi::{AuthMethod, ClientConfiguration, Configuration},
};

use esp_idf_svc::hal::prelude::Peripherals;
use esp_idf_svc::http::client::EspHttpConnection;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};
use esp_idf_svc::{eventloop::EspSystemEventLoop, nvs::EspDefaultNvsPartition};

use esp_idf_sys::{
    esp_wifi_sta_wpa2_ent_enable, esp_wifi_sta_wpa2_ent_set_password,
    esp_wifi_sta_wpa2_ent_set_username,
};

use log::{error, info};

const SSID: &str = env!("SSID");
const USERNAME: &str = env!("USERNAME");
const PASSWORD: &str = env!("PASSWORD");

fn main() -> anyhow::Result<()> {
    esp_idf_svc::sys::link_patches();
    EspLogger::initialize_default();

    // The '?' means "if this function returns an error, return that error from the current function".
    // You can think of it like exceptions in C++/Java.
    let peripherals = Peripherals::take()?;
    let sys_loop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;
    // `::take()` refers to the singleton design pattern:
    // https://docs.rust-embedded.org/book/peripherals/singletons.html

    // We choose BlockingWifi as opposed to AsyncWifi for simpler control flow
    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(peripherals.modem, sys_loop.clone(), Some(nvs))?,
        sys_loop,
    )?; 

    connect_wifi(&mut wifi).map_err(|details| {
        error!("failed to connect to wifi: {}", details);
        details
    })?;

    let ip_info = wifi.wifi()
        .sta_netif() // returns the EspNetif abstraction in client mode
        .get_ip_info()?;
    info!("Wifi DHCP info: {:?}", ip_info);

    let mut client = HttpClient::wrap(EspHttpConnection::new(&Default::default())?);

    get_request(&mut client)?;

    info!("END - SUCCESS!!");

    Ok(())
}

/// Set up wifi for basic WPA2 Enterprise connections
fn connect_wifi(wifi: &mut BlockingWifi<EspWifi<'static>>) -> anyhow::Result<()> {
    unsafe {
        esp_wifi_sta_wpa2_ent_set_username(USERNAME.as_ptr(), USERNAME.len().try_into().unwrap()); // username, NOT EMAIL
        esp_wifi_sta_wpa2_ent_set_password(PASSWORD.as_ptr(), PASSWORD.len().try_into().unwrap()); // set password
        esp_wifi_sta_wpa2_ent_enable(); // Enable WPA2 Enterprise authentication on the ESP32
    }

    let wifi_configuration: Configuration = Configuration::Client(ClientConfiguration {
        ssid: SSID.into(),
        password: PASSWORD.into(),
        auth_method: AuthMethod::WPA2Enterprise,
        bssid: None,
        channel: None,
    });

    wifi.set_configuration(&wifi_configuration)?;

    wifi.start()?;
    info!("Wifi started");

    wifi.connect()?;
    info!("Wifi connected");

    wifi.wait_netif_up()?;
    info!("Wifi netif up");

    Ok(())
}

/// Send an HTTP GET request to ifconfig.net
fn get_request(client: &mut HttpClient<EspHttpConnection>) -> anyhow::Result<()> {
    // Prepare headers and URL
    let headers = [("accept", "text/plain")];
    let url = "http://ifconfig.net/";

    // Send request
    //
    // Note: If you don't want to pass in any headers, you can also use `client.get(url, headers)`.
    let request = client.request(Method::Get, url, &headers)?;
    info!("-> GET {}", url);
    let mut response = request.submit()?;

    // Process response
    let status = response.status();
    info!("<- {}", status);
    let mut buf = [0u8; 1024];
    let bytes_read = io::try_read_full(&mut response, &mut buf).map_err(|e| e.0)?;
    info!("Read {} bytes", bytes_read);
    match std::str::from_utf8(&buf[0..bytes_read]) {
        Ok(body_string) => info!(
            "Response body (truncated to {} bytes): {:?}",
            buf.len(),
            body_string
        ),
        Err(e) => error!("Error decoding response body: {}", e),
    };

    // Drain the remaining response bytes
    while response.read(&mut buf)? > 0 {}

    Ok(())
}
