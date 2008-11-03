
let ord = int_of_char

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
