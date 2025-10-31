// #[cfg(feature = "debug")]
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        println!("[*] {}", format!($($arg)*));
    };

    ([ $prefix:expr ] $($arg:tt)*) => {
        println!("[{}] {}", $prefix, format!($($arg)*));
    };
}

// #[cfg(not(feature = "debug"))]
// #[macro_export]
// macro_rules! log {
// ($($arg:tt)*) => {};
// }
