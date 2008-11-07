type state =
    {
      mutable prev_v: string;
    }

val encrypt : state -> (string -> string) -> string -> string
val decrypt : state -> (string -> string) -> string -> string
