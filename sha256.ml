(* An implementation of the SHA-256 hash function in OCaml
   Copyright (C) 2008 Michael Bacarella <mbac@panix.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

   SHA256 as specified here:
   http://en.wikipedia.org/wiki/SHA256
*)

open Bin

let rotate x n = or32 (right32 x n) (left32 x (32 - n))
let shift x n = right32 x n
let ch x y z = xor32 (and32 x y) (and32 (not32 x) z)
let maj x y z = xor32 (and32 x y) (xor32 (and32 x z) (and32 y z))
let sum0 x = xor32 (rotate x 2) (xor32 (rotate x 13) (rotate x 22))
let sum1 x = xor32 (rotate x 6) (xor32 (rotate x 11) (rotate x 25))
let rh00 x = xor32 (rotate x 7) (xor32 (rotate x 18) (shift x 3))
let rh01 x = xor32 (rotate x 17) (xor32 (rotate x 19) (shift x 10))

type ctx =
  { mutable total_length : Int64.t;
    mutable h : Int32.t array
  }

(* packs big-endian *)
let pack64 x =
  let b = Buffer.create 8 in
  for i = 0 to 7 do
    let shft = (7 - i) * 8 in
    Buffer.add_char b (char_of_int (Int64.to_int (Int64.logand (Int64.shift_right x shft) 0xFFL)))
  done;
  b

let pack x n =
  if n mod 8 = 0
  then (
    let n' = n / 8 in
    let b = Buffer.create n' in
    for i = 0 to n' - 1 do
      let shft = (n' - 1 - i) * 8 in
      Buffer.add_char b (char_of_int (Int32.to_int (Int32.logand (Int32.shift_right x shft) 0xFFl)))
    done;
    b)
  else raise (Invalid_argument ("pack: " ^ string_of_int n ^ " is not a multiple of 8"))

let pack32 x = pack x 32

let as_bytes bits =
  match bits mod 8 with
  | 0 -> bits / 8
  | _ -> failwith "as_bytes: bits must be multiple of 8"

let as_bits bytes = bytes * 8
let bs_in_bits = 512
let bs_in_bytes = as_bytes 512

let k =
  [| 0x428a2f98l;
     0x71374491l;
     0xb5c0fbcfl;
     0xe9b5dba5l;
     0x3956c25bl;
     0x59f111f1l;
     0x923f82a4l;
     0xab1c5ed5l;
     0xd807aa98l;
     0x12835b01l;
     0x243185bel;
     0x550c7dc3l;
     0x72be5d74l;
     0x80deb1fel;
     0x9bdc06a7l;
     0xc19bf174l;
     0xe49b69c1l;
     0xefbe4786l;
     0x0fc19dc6l;
     0x240ca1ccl;
     0x2de92c6fl;
     0x4a7484aal;
     0x5cb0a9dcl;
     0x76f988dal;
     0x983e5152l;
     0xa831c66dl;
     0xb00327c8l;
     0xbf597fc7l;
     0xc6e00bf3l;
     0xd5a79147l;
     0x06ca6351l;
     0x14292967l;
     0x27b70a85l;
     0x2e1b2138l;
     0x4d2c6dfcl;
     0x53380d13l;
     0x650a7354l;
     0x766a0abbl;
     0x81c2c92el;
     0x92722c85l;
     0xa2bfe8a1l;
     0xa81a664bl;
     0xc24b8b70l;
     0xc76c51a3l;
     0xd192e819l;
     0xd6990624l;
     0xf40e3585l;
     0x106aa070l;
     0x19a4c116l;
     0x1e376c08l;
     0x2748774cl;
     0x34b0bcb5l;
     0x391c0cb3l;
     0x4ed8aa4al;
     0x5b9cca4fl;
     0x682e6ff3l;
     0x748f82eel;
     0x78a5636fl;
     0x84c87814l;
     0x8cc70208l;
     0x90befffal;
     0xa4506cebl;
     0xbef9a3f7l;
     0xc67178f2l
  |]

let init () =
  { total_length = 0L;
    h =
      [| 0x6a09e667l;
         0xbb67ae85l;
         0x3c6ef372l;
         0xa54ff53al;
         0x510e527fl;
         0x9b05688cl;
         0x1f83d9abl;
         0x5be0cd19l
      |]
  }

let rec range i j = if i > j then [] else i :: range (i + 1) j

let update ctx message =
  let sha = ctx.h in
  let message_bits = as_bits (Buffer.length message) in
  if message_bits <> bs_in_bits
  then failwith ("update: message must be 512 bits; got " ^ string_of_int message_bits ^ " bits")
  else (
    let mm i = Buffer.nth message i in
    let w = Array.make bs_in_bytes 0l in
    for t = 0 to 15 do
      w.(t)
        <- or32
             (left32 (to_int32 (mm (t * 4))) 24)
             (or32
                (left32 (to_int32 (mm ((t * 4) + 1))) 16)
                (or32 (left32 (to_int32 (mm ((t * 4) + 2))) 8) (to_int32 (mm ((t * 4) + 3)))))
    done;
    for t = 16 to 63 do
      w.(t) <- add32 (add32 (rh01 w.(t - 2)) w.(t - 7)) (add32 (rh00 w.(t - 15)) w.(t - 16))
    done;
    let rec hround (a, b, c, d, e, f, g, h) = function
      | 64 ->
        [| add32 sha.(0) a;
           add32 sha.(1) b;
           add32 sha.(2) c;
           add32 sha.(3) d;
           add32 sha.(4) e;
           add32 sha.(5) f;
           add32 sha.(6) g;
           add32 sha.(7) h
        |]
      | t ->
        let t0 = add32 (add32 h (sum1 e)) (add32 (ch e f g) (add32 k.(t) w.(t))) in
        let t1 = add32 (sum0 a) (maj a b c) in
        hround (add32 t0 t1, a, b, c, add32 d t0, e, f, g) (t + 1)
    in
    ctx.h <- hround (sha.(0), sha.(1), sha.(2), sha.(3), sha.(4), sha.(5), sha.(6), sha.(7)) 0;
    ctx.total_length <- add64 ctx.total_length (Int64.of_int message_bits))

let sub_buf b pos len =
  let s = Buffer.sub b pos len in
  let b' = Buffer.create (String.length s) in
  Buffer.add_string b' s;
  b'

let hexdigits64 m =
  let rec hexdigits_inner hx i =
    match i with
    | 64 -> hx
    | _ -> hexdigits_inner (hx ^ Printf.sprintf "%02x" (int_of_char (Buffer.nth m i))) (i + 1)
  in
  hexdigits_inner "" 0

let pack_sha256 ctx =
  let h = ctx.h in
  let sha256 = Buffer.create (as_bytes 256) in
  let rec pack_sha256_inner = function
    | 8 -> sha256
    | i ->
      Buffer.add_buffer sha256 (pack32 h.(i));
      pack_sha256_inner (i + 1)
  in
  pack_sha256_inner 0

let final ctx message =
  let original_length = as_bits (Buffer.length message) in
  if original_length > bs_in_bits
  then
    failwith
      ("error: final: must be called with message smaller than 512 bits;"
      ^ "  got "
      ^ string_of_int original_length
      ^ " bits")
  else (
    let pad_blocks = if original_length mod bs_in_bits < 448 then 1 else 2 in
    ctx.total_length <- add64 ctx.total_length (Int64.of_int original_length);
    Buffer.add_char message '\x80';
    let pad_start = as_bits (Buffer.length message) in
    let message_length = ((original_length / bs_in_bits) + pad_blocks) * bs_in_bits in
    (* appending k bits of 0 (where message_length-64 is our k) *)
    for i = as_bytes pad_start to as_bytes (message_length - as_bytes 64) - 8 do
      Buffer.add_char message '\x00'
    done;
    Buffer.add_buffer message (pack64 ctx.total_length);
    let new_length = as_bits (Buffer.length message) in
    if new_length = 1024
    then (
      update ctx (sub_buf message 0 bs_in_bytes);
      update ctx (sub_buf message bs_in_bytes bs_in_bytes))
    else if new_length = 512
    then update ctx message
    else failwith ("error: final: unexpected length " ^ string_of_int new_length))

let digest message =
  let message_length = as_bits (Buffer.length message) in
  let ctx = init () in
  let total_blocks = message_length / bs_in_bits in
  let last_block_pos = total_blocks * bs_in_bytes in
  let last_block_len = as_bytes message_length - last_block_pos in
  for blockno = 0 to total_blocks - 1 do
    update ctx (sub_buf message (blockno * bs_in_bytes) bs_in_bytes)
  done;
  final ctx (sub_buf message last_block_pos last_block_len);
  pack_sha256 ctx

let hexdigits m =
  let rec hexdigits_inner hx = function
    | 32 -> hx
    | i -> hexdigits_inner (hx ^ Printf.sprintf "%02x" (int_of_char (Buffer.nth m i))) (i + 1)
  in
  hexdigits_inner "" 0

let hexdigest s =
  let b = Buffer.create (String.length s) in
  Buffer.add_string b s;
  hexdigits (digest b)

let test () =
  let rec run_tests = function
    | [] -> ()
    | (msg, sum) :: tests ->
      let result = hexdigest msg in
      if result = sum
      then Printf.printf "ok: sha256('%s') = '%s'\n" msg sum
      else Printf.printf "FAIL: sha256('%s') != '%s'; got '%s'\n" msg sum result;
      run_tests tests
  in
  run_tests
    [ "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      "def", "cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34";
      "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
      ( "The quick brown fox jumps over the lazy dog",
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" );
      ( "The quick brown fox jumps over the lazy cog",
        "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be" );
      "abcabcabc", "76b99ab4be8521d78b19bcff7d1078aabeb477bd134f404094c92cd39f051c3e";
      ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34" );
      ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" );
      ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0" );
      ( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "6bc3b8eaea5380e522ff7df7736989b5e3fff569ba75003be63a8e7ab9c8123e" )
    ]

(* let () = test () *)
