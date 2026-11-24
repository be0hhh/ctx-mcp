//! Cx unit tests. The test target compiles the production modules and attaches their private tests here.
#![allow(dead_code)]

#[path = "../src/hooks.rs"]
mod hooks;
#[path = "../src/json.rs"]
mod json;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/search_render.rs"]
mod search_render;
#[path = "../src/security.rs"]
mod security;
mod store {
    include!("../src/store.rs");
    mod cache_tests {
        include!("unit/store.rs");
    }
}

mod broker {
    include!("../src/broker.rs");
    mod memo_tests {
        include!("unit/broker.rs");
    }
}

mod capsule {
    include!("../src/capsule.rs");
    mod tests {
        include!("unit/capsule.rs");
    }
}

mod engine {
    include!("../src/engine.rs");
    mod search_tests {
        include!("unit/engine.rs");
    }
}

mod protocol {
    include!("../src/protocol.rs");
    mod transport_tests {
        include!("unit/protocol.rs");
    }
}

mod simd {
    include!("../src/simd.rs");
    mod tests {
        include!("unit/simd.rs");
    }
}
