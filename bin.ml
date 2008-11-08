
let chr x = char_of_int x
let ord c = int_of_char c
let ord32 c = Int32.of_int (ord c)

let and32 x n = Int32.logand x n
let xor32 x y = Int32.logxor x y
let or32 x y = Int32.logor x y
let right32 x n = Int32.shift_right_logical x n
let left32 x n = Int32.shift_left x n
let ror32 x n = or32 (right32 x n)  (left32 x (32-n))
let rol32 x n = or32  (left32 x n) (right32 x (32-n))
let add32 x y = Int32.add x y
let not32 x = Int32.lognot x

let add64 x y = Int64.add x y
let and64 x n = Int64.logand x n
let xor64 x y = Int64.logxor x y
let or64 x y = Int64.logor x y
let right64 x n = Int64.shift_right_logical x n
let left64 x n = Int64.shift_left x n
let ror64 x n = or64 (right64 x n)  (left64 x (64-n))
let rol64 x n = or64  (left64 x n) (right64 x (64-n))

let int64eq x y = (Int64.compare x y) = 0
let int64true x = (int64eq x 0L) = false

let to_int32 x = (Int32.of_int (int_of_char x))
let xor4_32 a b c d = (xor32 a (xor32 b (xor32 c d)))

(* unpacks little-endian *)
let unpack_le n s =
  let x = ref 0 in
  let n' = (n/8) in
    for i = 0 to (n'-1) do
      x := (!x lor (ord s.[i]) lsl (i*8))
    done;
    !x

let unpack8_le = unpack_le 8
let unpack16_le = unpack_le 16
let unpack24_le = unpack_le 24
let unpack32_le = unpack_le 32

let unpack32_be_int32 a b c d =
  or32 (left32 d 24) (or32 (left32 c 16) (or32 (left32 b 8) a))

(* packs big-endian *)
let pack64 x = 
  let b = Buffer.create 8 in 
    for i = 0 to 7 do
      let shft = (7-i)*8 in
        Buffer.add_char b (char_of_int (Int64.to_int (Int64.logand (Int64.shift_right x shft) 0xFFL)));
    done;
    b

let pack x n = 
  if (n mod 8) = 0 then
    let n' = n/8 in
    let b = Buffer.create n' in 
      for i = 0 to n'-1 do
        let shft = ((n'-1)-i)*8 in
          Buffer.add_char b (char_of_int (Int32.to_int (Int32.logand (Int32.shift_right x shft) 0xFFl)));
      done;
      b
  else
    raise (Invalid_argument ("pack: " ^ (string_of_int n) ^ " is not a multiple of 8"))

let pack32 x = pack x 32
let pack16 x = pack x 16
let pack8 x = pack x 8

let hexstring a = 
  let rec loop i =
    if i = String.length a then
      ""
    else
	(Printf.sprintf "%02x" (ord a.[i])) ^ (loop (i+1))
  in
  loop 0

