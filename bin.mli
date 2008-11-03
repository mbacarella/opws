
val unpack_le : int -> string -> int
val unpack8_le  : string -> int
val unpack16_le : string -> int
val unpack32_le : string -> int

val pack64 : Int64.t -> Buffer.t
val pack32 : Int32.t -> Buffer.t
val pack16 : Int32.t -> Buffer.t
val pack8 : Int32.t -> Buffer.t
