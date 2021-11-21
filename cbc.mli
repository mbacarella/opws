type state = { mutable prev_v : bytes }

val init : bytes -> state
val encrypt : state -> (bytes -> bytes) -> bytes -> bytes
val decrypt : state -> (bytes -> bytes) -> bytes -> bytes
