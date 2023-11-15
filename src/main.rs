//! Blinks the internal led (GPIO pin 2)
//! built for ESP32
//! modified from https://github.com/esp-rs/esp-idf-hal/blob/master/examples/blinky.rs
//! by Zack Sargent

use esp_idf_hal::delay::FreeRtos;
use esp_idf_hal::gpio::*;
use esp_idf_hal::peripherals::Peripherals;

fn main() -> anyhow::Result<()> {
    /* setup - runs once on board start */
    // It is necessary to call this function once. Otherwise some patches to the runtime
    // implemented by esp-idf-sys might not link properly. See https://github.com/esp-rs/esp-idf-template/issues/71
    esp_idf_hal::sys::link_patches();

    esp_idf_svc::log::EspLogger::initialize_default(); // initalize logger

    // The `?` at the end of the following lines means:
    // "If this function returns an error, stop the main function and return that error."
    // It's like throwing an exception.

    let peripherals = Peripherals::take()?; // get list of peripherals
    let mut led = PinDriver::output(peripherals.pins.gpio2)?; // take the GPIO pin 2 as an output device

    log::info!("Connected! Blinking..");

    /* loop - equivalent to a `while(true)` loop in C++ */
    loop {
        led.set_high()?;
        FreeRtos::delay_ms(1000);

        led.set_low()?;
        FreeRtos::delay_ms(1000);
    }
}

// run with `cargo run` or `cargo espflash flash --port <SERIAL>`
