(* Binary data manipulation routines
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
*)


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

(* packs big-endian *)
let pack64 x = 
  let b = Buffer.create 8 in 
    for i = 0 to 7 do
      let shft = (7-i)*8 in
        Buffer.add_char b (chr (Int64.to_int (Int64.logand (Int64.shift_right x shft) 0xFFL)));
    done;
    b

let pack x n = 
  if (n mod 8) = 0 then
    let n' = n/8 in
    let b = Buffer.create n' in 
      for i = 0 to n'-1 do
        let shft = ((n'-1)-i)*8 in
          Buffer.add_char b (chr (Int32.to_int (and32 (right32 x shft) 0xFFl)));
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

