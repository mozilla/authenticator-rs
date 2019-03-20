extern crate simple_logger;

mod common;

#[test]
fn it_adds_two() {
    common::setup();
    assert_eq!(4, 2 + 2);
}
